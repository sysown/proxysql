"""Exact-identity bundle storage; release URLs never depend on a core branch."""
from contextlib import contextmanager
import fcntl
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from bundles import create_bundle, verify_archive
from identity import (DEPENDENCIES, fingerprint, load_json, unique_object,
                      validate_entry)

REPOSITORY = 'sysown/proxysql'
MAX_ENTRY = 4 * 1024 * 1024


class Unavailable(ValueError):
    """An absent or unavailable store may fall back to a source build."""


def cache_root(root, environ):
    return Path(environ.get('DEPS_ARTIFACT_CACHE_DIR') or
                str(Path(root) / '.cache/dependency-artifacts')).resolve()


def release_tag(dependency, key):
    if dependency not in DEPENDENCIES or not re.fullmatch(r'[0-9a-f]{64}', key):
        raise ValueError('invalid dependency cache key')
    return 'dependency-artifact-v1-' + dependency + '-' + key


def asset_url(dependency, key, asset):
    if asset not in ('entry.json', 'bundle.tar.gz'):
        raise ValueError('invalid dependency asset')
    return ('https://github.com/' + REPOSITORY + '/releases/download/' +
            release_tag(dependency, key) + '/' + asset)


def entry_url(dependency, key):
    return asset_url(dependency, key, 'entry.json')


def cache_directory(cache, *parts, create=False):
    # The selected root may intentionally resolve outside the checkout. All
    # components below that root must be directories, never cached symlinks.
    directory = Path(cache).resolve()
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    for part in parts:
        directory = directory / part
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise ValueError('dependency cache must contain regular files and directories')
        if create:
            directory.mkdir(exist_ok=True)
    return directory


def bundle_directory(cache, dependency, key):
    release_tag(dependency, key)
    return cache_directory(cache, 'bundles', dependency) / key


@contextmanager
def key_lock(cache, dependency, key):
    release_tag(dependency, key)
    directory = cache_directory(cache, 'locks', create=True)
    path = directory / (dependency + '-' + key + '.lock')
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('dependency cache must contain regular files and directories')
    with path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        os.set_inheritable(lock.fileno(), True)
        yield


def checked_entry(entry, dependency, identity, remote=False):
    validate_entry(entry)
    key = fingerprint(identity)
    if (entry['dependency'] != dependency or entry['fingerprint'] != key or
            entry['identity'] != identity):
        raise ValueError('dependency cache identity mismatch')
    if remote and entry['url'] != asset_url(dependency, key, 'bundle.tar.gz'):
        raise ValueError('dependency bundle URL does not match its signature')
    return entry


def local_entry(cache, dependency, identity):
    directory = bundle_directory(cache, dependency, fingerprint(identity))
    if (directory.is_symlink() or (directory.exists() and not directory.is_dir()) or
            any((directory / name).is_symlink()
                for name in ('entry.json', 'bundle.tar.gz'))):
        raise ValueError('dependency cache must contain regular files and directories')
    if not (directory / 'entry.json').is_file() or not (directory / 'bundle.tar.gz').is_file():
        return None
    entry = checked_entry(load_json(directory / 'entry.json'), dependency, identity)
    verify_archive(directory / 'bundle.tar.gz', entry)
    return entry, directory / 'bundle.tar.gz'


def remote_entry(dependency, identity, environ=None):
    url = entry_url(dependency, fingerprint(identity))
    try:
        with urlopen(url, timeout=30) as response:
            if not response.geturl().startswith('https://'):
                raise ValueError('dependency metadata redirected away from HTTPS')
            data = response.read(MAX_ENTRY + 1)
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise Unavailable('dependency metadata unavailable: ' + str(exc)) from exc
    except (URLError, TimeoutError, socket.timeout, ConnectionError,
            ssl.SSLError, HTTPException) as exc:
        raise Unavailable('dependency metadata unavailable: ' + str(exc)) from exc
    if len(data) > MAX_ENTRY:
        raise ValueError('dependency metadata exceeds size limit')
    return checked_entry(json.loads(data, object_pairs_hook=unique_object),
                         dependency, identity, remote=True)


def source_provenance(root, environ):
    try:
        result = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=30)
        commit = result.stdout.strip() if result.returncode == 0 else ''
    except (OSError, subprocess.SubprocessError):
        commit = ''
    return dict(commit=commit, run=environ.get('DEPS_ARTIFACT_RUN_ID', environ.get('GITHUB_RUN_ID', '')),
                image=environ.get('DEPS_ARTIFACT_IMAGE', ''),
                profile=environ.get('DEPS_ARTIFACT_PROFILE', ''))


def save_local(cache, dependency, identity, tree=None, root=None, environ=None,
               archive=None, entry=None, repair=False):
    """Caller holds key_lock; publish the complete pair by one directory rename."""
    try:
        existing = local_entry(cache, dependency, identity)
    except ValueError:
        # Explicit source mode may repair corrupt regular cached data using
        # independently validated source outputs. Automatic consumers still
        # fail integrity checks; neither path follows cached symlinks.
        directory = bundle_directory(cache, dependency, fingerprint(identity))
        if (not repair or directory.is_symlink() or
                (directory.exists() and not directory.is_dir() and not directory.is_file()) or
                any((directory / name).is_symlink() for name in ('entry.json', 'bundle.tar.gz'))):
            raise
        existing = None
    if existing is not None:
        return existing
    key = fingerprint(identity)
    destination = bundle_directory(cache, dependency, key)
    cache_directory(cache, 'bundles', dependency, create=True)
    destination.parent.chmod(0o755)
    destination.parent.parent.chmod(0o755)
    stage = Path(tempfile.mkdtemp(prefix='.bundle-stage-', dir=str(destination.parent)))
    try:
        target = stage / 'bundle.tar.gz'
        if archive is None:
            entry = create_bundle(dependency, tree, identity, target)
            entry.update(url=asset_url(dependency, key, 'bundle.tar.gz'),
                         provenance=source_provenance(root, environ or {}))
        else:
            checked_entry(entry, dependency, identity)
            verify_archive(archive, entry)
            shutil.copyfile(str(archive), str(target))
        checked_entry(entry, dependency, identity)
        (stage / 'entry.json').write_text(json.dumps(entry, sort_keys=True) + '\n')
        for path in stage.iterdir():
            path.chmod(0o644)
        stage.chmod(0o755)
        if destination.exists():
            # Incomplete entries are never hits; discard only this exact key.
            if destination.is_symlink():
                raise ValueError('dependency cache must contain regular files and directories')
            if destination.is_dir():
                shutil.rmtree(str(destination))
            elif repair and destination.is_file():
                destination.unlink()
            else:
                raise ValueError('dependency cache must contain regular files and directories')
        os.replace(str(stage), str(destination))
        return entry, destination / 'bundle.tar.gz'
    finally:
        if stage.exists():
            shutil.rmtree(str(stage))
