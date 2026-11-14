"""Local bundle pairs and exact public release URLs for dependency identities."""
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
from identity import DEPENDENCIES, fingerprint, load_json, unique_object, validate_entry

REPOSITORY = 'sysown/proxysql'


class Unavailable(ValueError):
    """An absent or unavailable store may fall back to a source build."""


def cache_root(root, environ=None):
    return Path(root) / '.cache/dependency-artifacts'


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


def bundle_directory(cache, dependency, key):
    release_tag(dependency, key)
    directory = Path(cache)
    for part in ('bundles', dependency, key):
        directory = directory / part
        if directory.is_symlink() or (part != key and directory.exists() and not directory.is_dir()):
            raise ValueError('dependency cache must contain regular files and directories')
    return directory


def checked_entry(entry, dependency, identity, remote=False):
    validate_entry(entry)
    key = fingerprint(identity)
    if entry['dependency'] != dependency or entry['identity'] != identity or entry['fingerprint'] != key:
        raise ValueError('dependency cache identity mismatch')
    if remote and entry['url'] != asset_url(dependency, key, 'bundle.tar.gz'):
        raise ValueError('dependency bundle URL does not match its signature')
    return entry


def local_entry(cache, dependency, identity):
    directory = bundle_directory(cache, dependency, fingerprint(identity))
    if directory.exists() and not directory.is_dir():
        raise ValueError('dependency cache must contain regular files and directories')
    paths = [directory / name for name in ('entry.json', 'bundle.tar.gz')]
    if any(path.is_symlink() or (path.exists() and not path.is_file()) for path in paths):
        raise ValueError('dependency cache must contain regular files and directories')
    if not all(path.is_file() for path in paths):
        return None
    entry = checked_entry(load_json(paths[0]), dependency, identity)
    verify_archive(paths[1], entry)
    return entry, paths[1]


def remote_entry(dependency, identity, environ=None):
    try:
        with urlopen(entry_url(dependency, fingerprint(identity)), timeout=30) as response:
            if not response.geturl().startswith('https://'):
                raise ValueError('dependency metadata redirected away from HTTPS')
            data = response.read(4 * 1024 * 1024 + 1)
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise Unavailable('dependency metadata unavailable: ' + str(exc)) from exc
    except (URLError, TimeoutError, socket.timeout, ConnectionError, ssl.SSLError, HTTPException) as exc:
        raise Unavailable('dependency metadata unavailable: ' + str(exc)) from exc
    if len(data) > 4 * 1024 * 1024:
        raise ValueError('dependency metadata exceeds size limit')
    return checked_entry(json.loads(data, object_pairs_hook=unique_object), dependency, identity, remote=True)


def source_provenance(root, environ):
    try:
        commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                                         stderr=subprocess.DEVNULL, universal_newlines=True, timeout=30).strip()
    except (OSError, subprocess.SubprocessError):
        commit = ''
    return dict(commit=commit, run=environ.get('DEPS_ARTIFACT_RUN_ID', environ.get('GITHUB_RUN_ID', '')),
                image=environ.get('DEPS_ARTIFACT_IMAGE', ''), profile=environ.get('DEPS_ARTIFACT_PROFILE', ''))


def save_local(cache, dependency, identity, tree=None, root=None, environ=None,
               archive=None, entry=None, repair=False):
    """Caller holds the checkout's dependency lock; stage a complete pair."""
    key = fingerprint(identity)
    destination = bundle_directory(cache, dependency, key)
    # Source mode may repair regular cached data, but never cached symlinks.
    if repair and destination.is_file() and not destination.is_symlink():
        destination.unlink()
    try:
        existing = local_entry(cache, dependency, identity)
    except ValueError:
        if not repair or any(p.is_symlink() or not p.is_file() for p in destination.iterdir()):
            raise
        existing = None
    if existing is not None:
        return existing
    destination.parent.mkdir(parents=True, exist_ok=True)
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
            shutil.rmtree(str(destination))
        os.replace(str(stage), str(destination))
        return entry, destination / 'bundle.tar.gz'
    finally:
        if stage.exists():
            shutil.rmtree(str(stage))
