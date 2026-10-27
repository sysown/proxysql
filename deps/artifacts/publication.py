"""Promote verified same-run candidates from reviewed history, one key at a time.

The caller supplies a fresh trusted checkout and serializes publication jobs by
the complete dependency fingerprint. Candidate payloads are data, never code.
"""
import hashlib
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from bundles import extract_verified, verify_archive
from identity import (FLAGS, load_json, unique_object, validate_entry)
import store


HELPERS = ('identity.py', 'bundles.py', 'manage.py', 'prepare.bash')
IDENTITY_FIELDS = {'format_version', 'dependency', 'eligible', 'version',
                   'source_sha256', 'recipe_sha256', 'verifier_sha256', 'helper',
                   'settings', 'flags', 'custom_paths', 'toolchain'}


def _git(root, *arguments):
    result = subprocess.run(['git', '-C', str(root)] + list(arguments),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=120)
    if result.returncode:
        raise ValueError('reviewed source Git verification failed: ' +
                         result.stderr.decode(errors='replace').strip())
    return result.stdout


def _reviewed(root, commit):
    if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('reviewed source requires a complete commit SHA')
    if _git(root, 'rev-parse', '--verify', commit + '^{commit}').decode().strip() != commit:
        raise ValueError('reviewed source does not identify a commit')
    _git(root, 'merge-base', '--is-ancestor', commit, 'refs/remotes/origin/v3.0')


def _trusted_source(source_sha, repo_root, environ):
    if environ.get('GITHUB_REPOSITORY') != store.REPOSITORY:
        raise ValueError('global publication requires the canonical source repository')
    event = environ.get('GITHUB_EVENT_NAME')
    if event == 'workflow_run':
        path = environ.get('GITHUB_EVENT_PATH')
        if not path:
            raise ValueError('workflow_run publication requires its event payload')
        payload = load_json(path)
        run = payload.get('workflow_run') if isinstance(payload, dict) else None
        if (not isinstance(run, dict) or not isinstance(run.get('head_repository'), dict) or
                run.get('event') != 'push' or run.get('head_branch') != 'v3.0' or
                run.get('head_sha') != source_sha or
                run.get('head_repository', {}).get('full_name') != store.REPOSITORY):
            raise ValueError('producer must be a protected source-repository push')
    elif event in ('push', 'workflow_dispatch'):
        if environ.get('GITHUB_REF') != 'refs/heads/v3.0':
            raise ValueError('publication requires protected v3.0 history')
        if event == 'push' and environ.get('GITHUB_SHA') != source_sha:
            raise ValueError('publication source does not match the protected push')
    else:
        raise ValueError('this event cannot publish global dependency artifacts')
    _reviewed(repo_root, source_sha)


def _assignment(text, name):
    match = re.search(r'^' + re.escape(name) + r'\s*[:?]?=\s*(.*?)\s*$',
                      text.replace('\\\n', ' '), re.M)
    if match is None:
        raise ValueError('reviewed source lacks dependency version: ' + name)
    return match.group(1)


@lru_cache(maxsize=128)
def _source_digest(repo_root, source_sha, archive_path):
    # Git objects are immutable. Reuse digests across profile candidates rather
    # than buffering the same vendored archive once for every configuration.
    return hashlib.sha256(_git(repo_root, 'show', source_sha + ':' + archive_path)).hexdigest()


def _focused_identity(identity, source_sha, repo_root):
    """Bind candidate source facts to Git objects, never the working directory."""
    dependency = identity['dependency']
    directory = 'duckdb' if dependency == 'duckdb' else 'libssl'
    recipe_path = 'deps/' + directory + '/build.mk'
    recipe = _git(repo_root, 'show', source_sha + ':' + recipe_path)
    version_data = recipe if dependency == 'duckdb' else _git(
        repo_root, 'show', source_sha + ':common_mk/openssl_flags.mk')
    version = _assignment(version_data.decode(), dependency.upper() + '_VERSION')
    if identity['version'] != version:
        raise ValueError('candidate version does not match reviewed source')
    archive_name = dependency + '-' + version + '.tar.gz'
    archive_path = 'deps/' + directory + '/' + archive_name
    checksum = _git(repo_root, 'show', source_sha + ':' + archive_path + '.sha256').decode().split()
    if (len(checksum) != 2 or checksum[1].lstrip('*') != archive_name or
            not re.fullmatch(r'[0-9a-fA-F]{64}', checksum[0])):
        raise ValueError('reviewed source checksum metadata is invalid')
    actual = _source_digest(repo_root, source_sha, archive_path)
    if actual != checksum[0].lower() or actual != identity['source_sha256']:
        raise ValueError('candidate source checksum does not match reviewed source')
    expected = {
        'recipe_sha256': hashlib.sha256(recipe).hexdigest(),
        'verifier_sha256': hashlib.sha256(_git(
            repo_root, 'show', source_sha + ':deps/' + directory + '/verify-source.bash')).hexdigest()}
    for name, digest in expected.items():
        if identity[name] != digest:
            raise ValueError('candidate ' + name + ' does not match reviewed source')
    helper = {name: hashlib.sha256(_git(
        repo_root, 'show', source_sha + ':deps/artifacts/' + name)).hexdigest()
              for name in HELPERS}
    if identity['helper'] != helper:
        raise ValueError('candidate helpers do not match reviewed source')


def _entry(entry, source_sha, repo_root, dependency=None, key=None):
    validate_entry(entry)
    identity = entry['identity']
    if set(identity) != IDENTITY_FIELDS:
        raise ValueError('incomplete or unsupported candidate identity schema')
    if (not isinstance(identity['helper'], dict) or set(identity['helper']) != set(HELPERS) or
            not isinstance(identity['flags'], dict) or set(identity['flags']) != set(FLAGS) or
            not all(isinstance(v, str) for v in identity['flags'].values()) or
            not isinstance(identity['settings'], list) or
            not all(isinstance(v, str) for v in identity['settings']) or
            not isinstance(identity['custom_paths'], dict) or
            set(identity['custom_paths']) != {'CPATH', 'CPLUS_INCLUDE_PATH', 'C_INCLUDE_PATH', 'LIBRARY_PATH'} or
            not all(isinstance(v, str) for v in identity['custom_paths'].values())):
        raise ValueError('incomplete candidate build configuration')
    toolchain = identity['toolchain']
    if not isinstance(toolchain, dict):
        raise ValueError('invalid candidate toolchain')
    fields = {'os', 'arch', 'cc', 'cxx', 'runtime'}
    if toolchain.get('os') == 'Linux':
        fields.update(('distro', 'libc'))
        for name in ('distro', 'libc'):
            values = toolchain.get(name)
            if (not isinstance(values, list) or len(values) != 2 or
                    not all(isinstance(v, str) and v for v in values)):
                raise ValueError('incomplete candidate toolchain platform')
    elif toolchain.get('os') == 'Darwin':
        fields.update(('sdk', 'deployment_target'))
        if (not isinstance(toolchain.get('sdk'), str) or not toolchain['sdk'] or
                not isinstance(toolchain.get('deployment_target'), str)):
            raise ValueError('incomplete candidate toolchain SDK')
    else:
        raise ValueError('unsupported candidate toolchain platform')
    if (set(toolchain) != fields or not isinstance(toolchain['arch'], str) or
            not toolchain['arch'] or not isinstance(toolchain['runtime'], str) or
            not re.fullmatch(r'[0-9a-f]{64}', toolchain['runtime'])):
        raise ValueError('incomplete candidate toolchain facts')
    for name in ('cc', 'cxx'):
        compiler = toolchain[name]
        if (not isinstance(compiler, dict) or set(compiler) != {'command', 'version', 'target', 'macros'} or
                not isinstance(compiler['command'], list) or not compiler['command'] or
                not all(isinstance(v, str) and v for v in compiler['command']) or
                not all(isinstance(compiler[v], str) and compiler[v] for v in ('version', 'target')) or
                not isinstance(compiler['macros'], str) or
                not re.fullmatch(r'[0-9a-f]{64}', compiler['macros'])):
            raise ValueError('incomplete candidate toolchain compiler')
    if dependency is not None and entry['dependency'] != dependency:
        raise ValueError('candidate dependency does not match publication request')
    if key is not None and entry['fingerprint'] != key:
        raise ValueError('candidate fingerprint does not match publication request')
    if entry['url'] != store.asset_url(entry['dependency'], entry['fingerprint'], 'bundle.tar.gz'):
        raise ValueError('candidate download URL is not canonical')
    _focused_identity(identity, source_sha, repo_root)
    provenance = entry['provenance'].get('commit')
    _reviewed(repo_root, provenance)
    if provenance != source_sha:
        _focused_identity(identity, provenance, repo_root)
    return entry


def _archive(archive, entry):
    if Path(archive).is_symlink():
        raise ValueError('candidate bundle must be a regular file')
    verify_archive(archive, entry)
    with tempfile.TemporaryDirectory(prefix='dependency-publication-check-') as temporary:
        extract_verified(archive, entry, Path(temporary))


def _candidate(directory, source_sha, repo_root, dependency=None, key=None):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('candidate must be an immediate artifact directory')
    metadata = directory / 'entry.json'
    if metadata.is_symlink() or not metadata.is_file():
        raise ValueError('candidate entry.json must be a regular file')
    entry = _entry(load_json(metadata), source_sha, repo_root, dependency, key)
    _archive(directory / 'bundle.tar.gz', entry)
    return entry


def publication_matrix(inputdir, source_sha, repo_root, environ):
    _trusted_source(source_sha, repo_root, environ)
    attempt = environ.get('GITHUB_RUN_ATTEMPT', '')
    if not re.fullmatch(r'[1-9][0-9]*', attempt):
        raise ValueError('publication requires the current run attempt')
    prefix = 'dependency-candidate-a' + attempt + '-'
    selected, seen = [], set()
    for directory in sorted(Path(inputdir).iterdir()):
        if not directory.name.startswith(prefix):
            continue
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', directory.name):
            raise ValueError('unsafe candidate artifact name')
        entry = _candidate(directory, source_sha, repo_root)
        pair = entry['dependency'], entry['fingerprint']
        if pair not in seen:
            seen.add(pair)
            selected.append(dict(dependency=pair[0], fingerprint=pair[1], artifact=directory.name))
    return {'include': selected}


def _gh(arguments, environ, check=True):
    environment = dict(os.environ)
    environment.update(environ)
    result = subprocess.run(['gh'] + arguments, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=600)
    if check and result.returncode:
        raise ValueError('dependency release operation failed: ' + result.stderr.strip())
    return result


def _release(tag, repository, environ):
    # REST releases/tags only sees published releases. The CLI uses GraphQL
    # here so a newly created draft, or an interrupted draft, is also visible.
    result = _gh(['release', 'view', tag, '--repo', repository,
                  '--json', 'isDraft,tagName'], environ, check=False)
    if result.returncode:
        if result.stderr.strip() == 'release not found':
            return None
        raise ValueError('cannot inspect dependency release: ' + result.stderr.strip())
    if len(result.stdout.encode()) > store.MAX_ENTRY:
        raise ValueError('dependency release API metadata exceeds size limit')
    release = json.loads(result.stdout, object_pairs_hook=unique_object)
    if (not isinstance(release, dict) or type(release.get('isDraft')) is not bool or
            release.get('tagName') != tag):
        raise ValueError('invalid dependency release API metadata')
    return {'draft': release['isDraft'], 'tag_name': release['tagName']}


def _published_winner(entry, source_sha, repo_root, environ):
    for attempt in range(3):
        try:
            winner = store.remote_entry(entry['dependency'], entry['identity'], environ)
            if winner is None:
                raise store.Unavailable('published dependency metadata is not yet available')
            _entry(winner, source_sha, repo_root, entry['dependency'], entry['fingerprint'])
            with tempfile.TemporaryDirectory(prefix='dependency-release-check-') as temporary:
                archive = Path(temporary) / 'bundle.tar.gz'
                url = store.asset_url(entry['dependency'], entry['fingerprint'], 'bundle.tar.gz')
                with urlopen(url, timeout=30) as response, archive.open('wb') as output:
                    if not response.geturl().startswith('https://'):
                        raise ValueError('dependency bundle redirected away from HTTPS')
                    received = 0
                    while True:
                        block = response.read(1024 * 1024)
                        if not block:
                            break
                        received += len(block)
                        if received > winner['size']:
                            raise ValueError('published dependency exceeds declared size')
                        output.write(block)
                _archive(archive, winner)
            return winner
        except (store.Unavailable, HTTPError, URLError, TimeoutError, socket.timeout, ConnectionError):
            if attempt == 2:
                raise
            time.sleep(1)


def publish_candidate(inputdir, dependency, fingerprint, source_sha, repo_root, repository, environ):
    _trusted_source(source_sha, repo_root, environ)
    if repository != store.REPOSITORY:
        raise ValueError('global publication requires the canonical destination repository')
    key = fingerprint
    tag = store.release_tag(dependency, key)
    directory = Path(inputdir)
    entry = _candidate(directory, source_sha, repo_root, dependency, key)
    release = _release(tag, repository, environ)
    if release is None:
        created = _gh(['release', 'create', tag, '--repo', repository, '--target', source_sha,
                       '--draft', '--prerelease', '--latest=false', '--title', tag,
                       '--notes', 'Automatically verified dependency bundle for ' + key + '.'],
                      environ, check=False)
        for attempt in range(3):
            release = _release(tag, repository, environ)
            if release is not None:
                break
            if attempt < 2:
                time.sleep(1)
        if release is None:
            raise ValueError('dependency release creation failed: ' + created.stderr.strip())
    if not release['draft']:
        _published_winner(entry, source_sha, repo_root, environ)
        return dict(dependency=dependency, fingerprint=key, status='existing')
    # Per-key workflow concurrency owns this draft. Recheck before replacing
    # draft assets, including after a competing tag creator won the race.
    release = _release(tag, repository, environ)
    if release is None:
        raise ValueError('dependency draft disappeared before publication')
    if not release['draft']:
        _published_winner(entry, source_sha, repo_root, environ)
        return dict(dependency=dependency, fingerprint=key, status='existing')
    _gh(['release', 'upload', tag, '--repo', repository,
         str(directory / 'entry.json'), str(directory / 'bundle.tar.gz'), '--clobber'], environ)
    _gh(['release', 'edit', tag, '--repo', repository,
         '--draft=false', '--prerelease', '--latest=false'], environ)
    _published_winner(entry, source_sha, repo_root, environ)
    return dict(dependency=dependency, fingerprint=key, status='published')
