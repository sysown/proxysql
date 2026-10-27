#!/usr/bin/env python3
"""Build explicit profiles and publish complete, immutable dependency batches."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from bundles import extract_verified, verify_archive
from identity import (DEPENDENCIES, FORMAT_VERSION, configuration, digest_file,
                      load_json, load_registry, validate_entry)
import store

ROOT = Path(__file__).resolve().parents[2]


def profiles():
    data = load_json(ROOT / 'deps/artifacts/profiles.json')
    if data.get('format_version') != FORMAT_VERSION:
        raise ValueError('unsupported profile schema')
    result, seen = data['profiles'], set()
    for item in result:
        if item['profile'] in seen or item['arch'] not in ('amd64', 'arm64'):
            raise ValueError('duplicate profile or unsupported architecture')
        if item['system'] == 'Linux':
            if (item['arch'] == 'arm64') != item['runner'].endswith('-arm') or not item['service']:
                raise ValueError('profile architecture/runner mismatch')
        elif (item['system'], item['arch'], item['runner']) != ('Darwin', 'arm64', 'macos-14'):
            raise ValueError('unsupported native profile')
        seen.add(item['profile'])
    return result


def build_matrix(group, dependency):
    if dependency not in DEPENDENCIES + ('both',):
        raise ValueError('unknown dependency')
    selected = [item for item in profiles() if group in
                ('all', item['group'], item['profile'], 'linux' if item['system'] == 'Linux' else 'macos')]
    if not selected:
        raise ValueError('unknown profile group: ' + group)
    dependencies = DEPENDENCIES if dependency == 'both' else (dependency,)
    return {'include': [dict(profile, dependency=dep) for profile in selected for dep in dependencies]}


def merge_entries(directory, base=None):
    directory = Path(directory)
    entries = []
    seen = set()
    observed = set()
    for path in sorted(directory.glob('*.entry.json')):
        entry = validate_entry(load_json(path))
        key = (entry['dependency'], entry['fingerprint'])
        if key in seen:
            raise ValueError('duplicate dependency artifact in batch')
        seen.add(key)
        name = Path(urlsplit(entry['url']).path).name
        if not re.fullmatch(r'[A-Za-z0-9._-]+[.]tar[.]gz', name):
            raise ValueError('invalid release archive filename')
        verify_archive(directory / name, entry)
        pair = (entry['provenance'].get('profile'), entry['dependency'])
        if pair in observed:
            raise ValueError('duplicate build profile in batch')
        observed.add(pair)
        entries.append(entry)
    if not entries:
        raise ValueError('empty dependency publication batch')
    expected_path = directory / 'expected-matrix.json'
    if expected_path.exists():
        expected = {(item['profile'], item['dependency']) for item in load_json(expected_path)['include']}
        if expected != observed:
            raise ValueError('dependency batch does not match selected matrix')
    if base is not None:
        for entry in load_registry(base)['artifacts']:
            key = (entry['dependency'], entry['fingerprint'])
            if key in seen:
                raise ValueError('duplicate artifact already registered; retain or explicitly remove the old entry')
            seen.add(key)
            entries.append(entry)
    return {'format_version': FORMAT_VERSION, 'artifacts': entries}


def run(args, timeout=60):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=timeout)
    if result.returncode:
        raise ValueError('command failed: ' + ' '.join(args) + '\n' + result.stderr)
    return result.stdout.strip()


def register_entries(candidate, registry_path):
    registry_path = Path(registry_path)
    existing = load_registry(registry_path)
    incoming = load_registry(candidate)
    keys = {(entry['dependency'], entry['fingerprint']) for entry in existing['artifacts']}
    for entry in incoming['artifacts']:
        if (entry['dependency'], entry['fingerprint']) in keys:
            raise ValueError('artifact already registered; retain or explicitly remove the old entry')
    existing['artifacts'].extend(incoming['artifacts'])
    temporary = registry_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(existing, indent=2, sort_keys=True) + '\n')
    os.replace(temporary, registry_path)


def publish_batch(directory, repository, tag, expected_source_sha):
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or
            not re.fullmatch(r'dependency-artifacts-v1-[0-9]+-[0-9]+', tag)):
        raise ValueError('invalid dependency repository/tag')
    directory = Path(directory)
    if not (directory / 'expected-matrix.json').is_file():
        raise ValueError('publication requires expected-matrix.json')
    registry = merge_entries(directory)
    prefix = 'https://github.com/' + repository + '/releases/download/' + tag + '/'
    if any(entry['url'] != prefix + Path(urlsplit(entry['url']).path).name
           for entry in registry['artifacts']):
        raise ValueError('artifact URL does not match publication repository/tag')
    commits = {entry['provenance'].get('commit') for entry in registry['artifacts']}
    if len(commits) != 1 or not re.fullmatch(r'[0-9a-f]{40}', next(iter(commits)) or ''):
        raise ValueError('batch must come from one source commit')
    if commits != {expected_source_sha}:
        raise ValueError('batch does not match planned source commit')
    existing = subprocess.run(['gh', 'api', 'repos/' + repository + '/releases/tags/' + tag],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
    if existing.returncode == 0:
        raise ValueError('dependency release already exists; assets are never replaced')
    if '404' not in existing.stderr:
        raise ValueError('unable to check release availability: ' + existing.stderr)
    lock = directory / 'lock-entries.json'
    lock.write_text(json.dumps(registry, indent=2, sort_keys=True) + '\n')
    run(['gh', 'release', 'create', tag, '--repo', repository, '--target', next(iter(commits)),
         '--draft', '--prerelease', '--latest=false', '--title', tag,
         '--notes', 'Verified pinned DuckDB/OpenSSL dependency builds. Import lock-entries.json to enable reuse.'])
    assets = [str(directory / Path(urlsplit(entry['url']).path).name) for entry in registry['artifacts']]
    run(['gh', 'release', 'upload', tag, '--repo', repository] + assets + [str(lock)], timeout=600)
    run(['gh', 'release', 'edit', tag, '--repo', repository, '--draft=false', '--prerelease', '--latest=false'])


def reviewed_source(root, source_sha, environ):
    if (environ.get('GITHUB_REPOSITORY') != store.REPOSITORY or
            environ.get('GITHUB_EVENT_NAME') not in ('push', 'workflow_dispatch') or
            environ.get('GITHUB_REF') != 'refs/heads/v3.0' or
            not re.fullmatch(r'[0-9a-f]{40}', source_sha) or
            (environ.get('GITHUB_EVENT_NAME') == 'push' and environ.get('GITHUB_SHA') != source_sha)):
        raise ValueError('global publication requires reviewed protected-branch source')
    if run(['git', '-C', str(root), 'rev-parse', 'HEAD']) != source_sha:
        raise ValueError('reviewed source checkout does not match planned source')
    run(['git', '-C', str(root), 'merge-base', '--is-ancestor', source_sha,
         'refs/remotes/origin/v3.0'])


def candidate_entry(directory, source_root, dependency=None, key=None):
    directory, source_root = Path(directory), Path(source_root)
    if directory.is_symlink() or any((directory / name).is_symlink()
                                    for name in ('entry.json', 'bundle.tar.gz')):
        raise ValueError('candidate files must be regular files')
    entry = validate_entry(load_json(directory / 'entry.json'))
    identity = entry['identity']
    dep, fingerprint = entry['dependency'], entry['fingerprint']
    if ((dependency is not None and dep != dependency) or (key is not None and fingerprint != key) or
            entry['url'] != store.asset_url(dep, fingerprint, 'bundle.tar.gz')):
        raise ValueError('candidate does not match canonical publication key/URL')
    conf = configuration(dep, source_root)
    checksum = Path(str(conf['archive']) + '.sha256').read_text().split()
    actual = digest_file(conf['archive'])
    expected = dict(version=conf['version'], source_sha256=actual,
                    recipe_sha256=digest_file(conf['recipe']),
                    verifier_sha256=digest_file(conf['archive'].parent / 'verify-source.bash'),
                    helper={name: digest_file(source_root / 'deps/artifacts' / name)
                            for name in ('identity.py', 'bundles.py', 'manage.py', 'prepare.bash')})
    if (checksum != [actual, conf['archive'].name] or
            any(identity.get(name) != value for name, value in expected.items())):
        raise ValueError('candidate inputs do not match reviewed source')
    provenance = entry['provenance'].get('commit', '')
    if not re.fullmatch(r'[0-9a-f]{40}', provenance):
        raise ValueError('candidate requires reviewed producer provenance')
    run(['git', '-C', str(source_root), 'merge-base', '--is-ancestor', provenance,
         'refs/remotes/origin/v3.0'])
    verify_archive(directory / 'bundle.tar.gz', entry)
    with tempfile.TemporaryDirectory(prefix='dependency-check-') as temporary:
        extract_verified(directory / 'bundle.tar.gz', entry, Path(temporary))
    return entry


def publication_matrix(inputdir, source_sha, source_root, environ):
    reviewed_source(source_root, source_sha, environ)
    attempt = environ.get('GITHUB_RUN_ATTEMPT', '')
    if not re.fullmatch(r'[1-9][0-9]*', attempt):
        raise ValueError('publication requires the current run attempt')
    result, seen = [], set()
    for directory in sorted(Path(inputdir).glob('dependency-candidate-a' + attempt + '-*')):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', directory.name):
            raise ValueError('invalid candidate artifact name')
        entry = candidate_entry(directory, source_root)
        pair = entry['dependency'], entry['fingerprint']
        if pair not in seen:
            seen.add(pair)
            result.append(dict(dependency=pair[0], fingerprint=pair[1], artifact=directory.name))
    return {'include': result}


def release_state(tag, repository):
    # gh release view sees drafts; the REST releases/tags endpoint does not.
    result = subprocess.run(['gh', 'release', 'view', tag, '--repo', repository,
                             '--json', 'isDraft,tagName'], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
    if result.returncode:
        if result.stderr.strip() == 'release not found':
            return None
        raise ValueError('cannot inspect dependency release: ' + result.stderr)
    state = json.loads(result.stdout)
    if type(state.get('isDraft')) is not bool or state.get('tagName') != tag:
        raise ValueError('invalid dependency release metadata')
    return state


def publish_candidate(inputdir, dependency, fingerprint, source_sha, source_root, repository, environ):
    reviewed_source(source_root, source_sha, environ)
    if repository != store.REPOSITORY:
        raise ValueError('global publication requires the canonical destination')
    entry = candidate_entry(inputdir, source_root, dependency, fingerprint)
    tag = store.release_tag(dependency, fingerprint)
    state = release_state(tag, repository)
    if state is None:
        try:
            run(['gh', 'release', 'create', tag, '--repo', repository, '--target', source_sha,
                 '--draft', '--prerelease', '--latest=false', '--title', tag,
                 '--notes', 'Verified dependency bundle for ' + fingerprint + '.'])
        except ValueError:
            if release_state(tag, repository) is None:
                raise
        state = release_state(tag, repository)
    if state is None:
        raise ValueError('dependency release creation was not visible')
    status = 'existing'
    if state['isDraft']:
        # Workflow concurrency serializes this dependency + fingerprint only.
        run(['gh', 'release', 'upload', tag, '--repo', repository,
             str(Path(inputdir) / 'entry.json'), str(Path(inputdir) / 'bundle.tar.gz'), '--clobber'], timeout=600)
        run(['gh', 'release', 'edit', tag, '--repo', repository,
             '--draft=false', '--prerelease', '--latest=false'])
        status = 'published'
    winner = store.remote_entry(dependency, entry['identity'], environ)
    if winner is None:
        raise ValueError('published dependency metadata is unavailable')
    with tempfile.TemporaryDirectory(prefix='dependency-winner-') as temporary:
        directory = Path(temporary)
        (directory / 'entry.json').write_text(json.dumps(winner))
        run(['gh', 'release', 'download', tag, '--repo', repository,
             '--pattern', 'bundle.tar.gz', '--dir', temporary], timeout=600)
        candidate_entry(directory, source_root, dependency, fingerprint)
    return dict(dependency=dependency, fingerprint=fingerprint, status=status)


def build_profile(profile_name, dependency, output, repository, tag):
    matches = [item for item in profiles() if item['profile'] == profile_name]
    if len(matches) != 1 or dependency not in DEPENDENCIES:
        raise ValueError('unknown dependency build profile')
    profile = matches[0]
    machine = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if machine != profile['arch'] or platform.system() != ('Linux' if profile['service'] else 'Darwin'):
        raise ValueError('build profile does not match runner OS/architecture')
    output = Path(output).resolve()
    relative = output.relative_to(ROOT)
    output.mkdir(parents=True, exist_ok=True)
    if profile['service']:
        services = json.loads(run(['docker', 'compose', 'config', '--format', 'json']))['services']
        image = services[profile['service']]['image']
        run(['docker', 'pull', '--platform', 'linux/' + profile['arch'], image], timeout=600)
        digest = run(['docker', 'image', 'inspect', '--format', '{{index .RepoDigests 0}}', image])
        command = ['docker', 'run', '--rm', '--platform', 'linux/' + profile['arch'],
                   '--entrypoint', '/bin/bash', '-v', str(ROOT) + ':/opt/proxysql',
                   '-e', 'DEPS_ARTIFACT_IMAGE=' + digest, '-e', 'GITHUB_RUN_ID',
                   '-e', 'DEPS_BUILD_JOBS=' + os.environ.get('DEPS_BUILD_JOBS', '2'), image,
                   '/opt/proxysql/deps/artifacts/build.bash', profile_name, dependency,
                   '/opt/proxysql/' + relative.as_posix(), repository, tag]
    else:
        command = ['bash', str(ROOT / 'deps/artifacts/build.bash'), profile_name, dependency,
                   str(output), repository, tag]
    subprocess.check_call(command, timeout=5400)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command')
    matrix = sub.add_parser('matrix')
    matrix.add_argument('--group', required=True)
    matrix.add_argument('--dependency', choices=DEPENDENCIES + ('both',), required=True)
    merge = sub.add_parser('merge')
    merge.add_argument('--input', type=Path, required=True)
    merge.add_argument('--output', type=Path, required=True)
    merge.add_argument('--base', type=Path)
    publish = sub.add_parser('publish')
    publish.add_argument('--input', type=Path, required=True)
    publish.add_argument('--repository', required=True)
    publish.add_argument('--tag', required=True)
    publish.add_argument('--source-sha', required=True)
    build = sub.add_parser('build')
    build.add_argument('--profile', required=True)
    build.add_argument('--dependency', choices=DEPENDENCIES, required=True)
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--repository', required=True)
    build.add_argument('--tag', required=True)
    register = sub.add_parser('register')
    register.add_argument('--entries', type=Path, required=True)
    register.add_argument('--registry', type=Path, required=True)
    for command in ('plan-candidates', 'publish-candidate'):
        candidate = sub.add_parser(command)
        candidate.add_argument('--input', type=Path, required=True)
        candidate.add_argument('--source-root', type=Path, required=True)
        candidate.add_argument('--source-sha', required=True)
        if command == 'plan-candidates':
            candidate.add_argument('--github-output', type=Path)
        else:
            candidate.add_argument('--dependency', choices=DEPENDENCIES, required=True)
            candidate.add_argument('--fingerprint', required=True)
            candidate.add_argument('--repository', default=store.REPOSITORY)
    args = parser.parse_args()
    if args.command == 'matrix':
        print(json.dumps(build_matrix(args.group, args.dependency), separators=(',', ':')))
    elif args.command == 'merge':
        args.output.write_text(json.dumps(merge_entries(args.input, args.base), indent=2, sort_keys=True) + '\n')
    elif args.command == 'publish':
        publish_batch(args.input, args.repository, args.tag, args.source_sha)
    elif args.command == 'plan-candidates':
        result = publication_matrix(args.input, args.source_sha, args.source_root, os.environ)
        encoded = json.dumps(result, separators=(',', ':'))
        if args.github_output:
            with args.github_output.open('a') as output:
                output.write('matrix=' + encoded + '\ncount=' + str(len(result['include'])) + '\n')
        print(encoded)
    elif args.command == 'publish-candidate':
        print(json.dumps(publish_candidate(args.input, args.dependency, args.fingerprint,
                         args.source_sha, args.source_root, args.repository, os.environ)))
    elif args.command == 'build':
        build_profile(args.profile, args.dependency, args.output, args.repository, args.tag)
    elif args.command == 'register':
        register_entries(args.entries, args.registry)
    else:
        parser.error('a subcommand is required')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        sys.exit(1)
