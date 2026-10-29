#!/usr/bin/env python3
"""Prepare pinned dependencies, or package them for a publication batch."""
import argparse
import fcntl
import json
from http.client import HTTPException
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile

import store
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from bundles import (collect_payload, create_bundle, restore_bundle, safe_path,
                     validate_tree, verify_archive)
from identity import (DEPENDENCIES, FORMAT_VERSION, build_identity, configuration,
                      fingerprint, load_json, load_registry, validate_entry, ToolchainUnavailable)


Unavailable = store.Unavailable


def report(dependency, message):
    print('[deps/' + dependency + '] ' + message, file=sys.stderr, flush=True)


def download_artifact(entry, cache):
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / (entry['sha256'] + '.tar.gz')
    if target.exists():
        verify_archive(target, entry)
        return target
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=str(cache), prefix='.download-', delete=False) as output:
            temporary = Path(output.name)
            try:
                with urlopen(entry['url'], timeout=30) as response:
                    if not response.geturl().startswith('https://'):
                        raise ValueError('artifact download redirected away from HTTPS')
                    received = 0
                    while True:
                        data = response.read(1024 * 1024)
                        if not data:
                            break
                        received += len(data)
                        if received > entry['size']:
                            raise ValueError('dependency archive exceeds registered size')
                        output.write(data)
                    if received < entry['size']:
                        raise Unavailable('artifact download ended before registered size')
            except (HTTPError, URLError, TimeoutError, socket.timeout, ConnectionError,
                    ssl.SSLError, HTTPException) as exc:
                raise Unavailable('artifact download unavailable: ' + str(exc)) from exc
        verify_archive(temporary, entry)
        os.replace(temporary, target)
        return target
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def write_metadata(dependency, tree, metadata):
    metadata['outputs'] = collect_payload(dependency, tree, metadata.get('version'))
    target = tree / '.proxysql-dependency.json'
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps(metadata, sort_keys=True) + '\n')
    os.replace(temporary, target)
    (tree / '.proxysql-origin').write_text(metadata['origin'] + '\n')
    (tree / '.proxysql-build-complete').touch()


def prepare_dependency(dependency, root, mode, environ):
    if mode not in ('auto', 'source', 'prebuilt'):
        raise ValueError('DEPS_MODE must be auto, source, or prebuilt')
    root = Path(root).resolve()
    conf = configuration(dependency, root)
    cache = root / '.cache/dependency-artifacts'
    cache.mkdir(parents=True, exist_ok=True)
    with (cache / (dependency + '.lock')).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        os.set_inheritable(lock.fileno(), True)
        try:
            identity = build_identity(dependency, root, environ)
        except ToolchainUnavailable as exc:
            if mode == 'prebuilt':
                raise
            report(dependency, mode + ': ' + str(exc) + '; using source escape hatch')
            before = (conf['tree'] / '.proxysql-source-complete')
            previous = before.stat().st_mtime_ns if before.exists() else None
            subprocess.check_call(['bash', str(root / 'deps/artifacts/prepare.bash'),
                                   dependency, str(root), mode, '--locked'],
                                  env=dict(environ), close_fds=False)
            return dict(origin='source', fingerprint=None,
                        changed=previous != before.stat().st_mtime_ns)
        key = fingerprint(identity)
        entry, archive = None, None
        if mode != 'source' and identity['eligible']:
            local = store.local_entry(cache, dependency, identity)
            if local is not None:
                entry, archive = local
            else:
                # Migration only: an old registry may supply an already published
                # bundle. New entries are discovered and saved without editing it.
                registry_path = root / 'deps/artifacts/lock.json'
                if registry_path.is_file():
                    registry = load_registry(registry_path)
                    entry = next((item for item in registry['artifacts']
                                  if item['dependency'] == dependency and item['fingerprint'] == key), None)
        tree = conf['tree']
        old = None
        if (tree / '.proxysql-dependency.json').is_file():
            try:
                old = load_json(tree / '.proxysql-dependency.json')
                validate_tree(dependency, tree, conf['version'])
                if not isinstance(old, dict) or not isinstance(old.get('outputs'), list) or not old['outputs']:
                    raise ValueError('missing prepared-output manifest')
                for relative in old['outputs']:
                    path = tree / safe_path(relative)
                    if not path.is_file() or path.is_symlink():
                        raise ValueError('missing prepared dependency output: ' + relative)
            except (ValueError, OSError):
                old = None
        accepted_source = (isinstance(old, dict) and old.get('fingerprint') == key and
                           old.get('origin') == 'source' and mode != 'prebuilt' and
                           (tree / '.proxysql-build-complete').is_file())
        if (mode != 'source' and identity['eligible'] and entry is None and
                not accepted_source and environ.get('DEPS_ARTIFACT_REMOTE', '1') != '0'):
            try:
                entry = store.remote_entry(dependency, identity, environ)
            except Unavailable as exc:
                if mode == 'prebuilt':
                    raise
                report(dependency, 'auto: ' + str(exc) + '; building source')
        if (isinstance(old, dict) and old.get('fingerprint') == key and
                old.get('origin') in ('source', 'prebuilt') and
                (tree / '.proxysql-build-complete').is_file()):
            origin = old['origin']
            if ((origin == 'source' and mode != 'prebuilt') or
                    (origin == 'prebuilt' and mode != 'source' and entry is not None and
                     old.get('archive_sha256') == entry['sha256'])):
                if identity['eligible']:
                    store.save_local(cache, dependency, identity, tree=tree, root=root, environ=environ,
                                     repair=(mode == 'source'))
                report(dependency, mode + ': already prepared from ' + origin + ' (' + key[:12] + ')')
                return dict(origin=origin, fingerprint=key, changed=False)
        if entry is not None and identity['eligible']:
            try:
                archive = archive or download_artifact(entry, cache)
            except Unavailable as exc:
                if mode == 'prebuilt':
                    raise
                report(dependency, 'auto: ' + str(exc) + '; building source')
            else:
                restore_bundle(archive, entry, tree)
                store.save_local(cache, dependency, identity, archive=archive, entry=entry)
                write_metadata(dependency, tree, dict(origin='prebuilt', fingerprint=key,
                               version=conf['version'], archive_sha256=entry['sha256']))
                report(dependency, mode + ': restored verified artifact ' + key[:12])
                return dict(origin='prebuilt', fingerprint=key, changed=True)
        elif mode == 'prebuilt':
            raise Unavailable(dependency + ': no compatible artifact (' + key[:12] + ')')
        else:
            report(dependency, mode + ': no compatible artifact; building vendored source ' + key[:12])
        # Keep Make's jobserver descriptors and dependency lock through compilation.
        if tree.exists():
            shutil.rmtree(str(tree))
        environment = dict(environ)
        environment['DEPS_MODE'] = 'source'
        make = environment.get('MAKE', 'make')
        result = subprocess.run([make, '--no-print-directory', '-C', str(root / 'deps'),
                                 'dependency-source-' + dependency], env=environment,
                                close_fds=False)
        if result.returncode:
            raise ValueError(dependency + ' source build failed')
        validate_tree(dependency, tree, conf['version'])
        if build_identity(dependency, root, environ) != identity:
            raise ValueError('dependency inputs changed during compilation')
        write_metadata(dependency, tree, dict(origin='source', fingerprint=key, version=conf['version']))
        if identity['eligible']:
            store.save_local(cache, dependency, identity, tree=tree, root=root, environ=environ,
                             repair=(mode == 'source'))
            report(dependency, 'saved reusable bundle ' + key[:12])
        report(dependency, mode + ': source build complete ' + key[:12])
        return dict(origin='source', fingerprint=key, changed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('identity', 'prepare', 'package'))
    parser.add_argument('--dependency', required=True, choices=DEPENDENCIES)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--mode', default=os.environ.get('DEPS_MODE', 'auto'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--url', help='Exact future HTTPS release asset URL (package)')
    args = parser.parse_args()
    if args.command == 'prepare':
        result = prepare_dependency(args.dependency, args.root, args.mode, dict(os.environ))
    else:
        identity = build_identity(args.dependency, args.root, dict(os.environ))
        result = dict(identity=identity, fingerprint=fingerprint(identity))
        if args.command == 'package':
            if args.output is None or args.url is None:
                parser.error('package requires --output and --url')
            tree = configuration(args.dependency, args.root)['tree']
            accepted = load_json(tree / '.proxysql-dependency.json')
            if accepted.get('fingerprint') != fingerprint(identity):
                raise ValueError('dependency inputs changed; prepare before packaging')
            result = create_bundle(args.dependency, tree, identity, args.output)
            commit = subprocess.check_output(['git', '-C', str(args.root), 'rev-parse', 'HEAD'],
                                             universal_newlines=True).strip()
            result.update(url=args.url, provenance=dict(commit=commit,
                          image=os.environ.get('DEPS_ARTIFACT_IMAGE', ''),
                          run=os.environ.get('GITHUB_RUN_ID', '')))
            validate_entry(result)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
