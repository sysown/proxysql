#!/usr/bin/env python3
"""CI adapters for exact dependency keys, preparation and automatic publication."""
import argparse
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys

from identity import (DEPENDENCIES, ToolchainUnavailable, build_identity,
                      configuration, fingerprint)
from manage import prepare_dependency
import store


ROOT = Path(__file__).resolve().parents[2]


def selected_dependencies(environ):
    requested = environ.get('DEPS_ARTIFACT_DEPENDENCIES', '').split()
    if not requested:
        requested = ['openssl'] + (['duckdb'] if environ.get('PROXYSQL40') == '1' else [])
    if len(set(requested)) != len(requested) or any(d not in DEPENDENCIES for d in requested):
        raise ValueError('invalid requested dependency set')
    return requested


def dependency_keys(root, environ):
    root = Path(root).resolve()
    result = {}
    for dependency in selected_dependencies(environ):
        row = dict(eligible=False, fingerprint='', key='', path='')
        try:
            identity = build_identity(dependency, root, environ)
        except ToolchainUnavailable as exc:
            row['reason'] = str(exc)
        else:
            key = fingerprint(identity)
            row['fingerprint'] = key
            expected_cache = (root / '.cache/dependency-artifacts').resolve()
            if identity['eligible'] and store.cache_root(root, environ) == expected_cache:
                row.update(eligible=True, key='proxysql-deps-v1-' + dependency + '-' + key,
                           path='.cache/dependency-artifacts/bundles/' + dependency + '/' + key)
        result[dependency] = row
    return result


def prepare_dependencies(root, environ):
    results = {}
    for dependency in selected_dependencies(environ):
        result = prepare_dependency(dependency, root, environ.get('DEPS_MODE', 'auto'), environ)
        if result['fingerprint'] is not None:
            identity = build_identity(dependency, root, environ)
            if identity['eligible']:
                tree = configuration(dependency, root)['tree']
                # Execute only in the read-only build job; publication never
                # executes a candidate library or scripts from its archive.
                cache = store.cache_root(root, environ)
                try:
                    subprocess.check_call(['bash', str(Path(root) / 'test/infra/control/dependency-artifacts-smoke.bash'),
                                           dependency, str(tree)], env=dict(environ))
                except (OSError, subprocess.SubprocessError):
                    # Failed runtime validation must not leave a local bundle
                    # available for later reuse, caching or publication.
                    with store.key_lock(cache, dependency, fingerprint(identity)):
                        if store.local_entry(cache, dependency, identity) is not None:
                            shutil.rmtree(str(store.bundle_directory(cache, dependency, fingerprint(identity))))
                    raise
                cached = store.local_entry(cache, dependency, identity)
                if cached is None:
                    raise ValueError('successful dependency preparation did not persist a bundle')
        results[dependency] = result
    return results


def write_keys(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, sort_keys=True) + '\n')
    temporary.chmod(0o644)
    os.replace(str(temporary), str(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('keys', 'prepare', 'publication-matrix', 'publish'))
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--source-sha')
    parser.add_argument('--dependency', choices=DEPENDENCIES)
    parser.add_argument('--fingerprint')
    parser.add_argument('--repository', default=store.REPOSITORY)
    parser.add_argument('--github-output', type=Path)
    args = parser.parse_args()
    environ = dict(os.environ)
    if args.command == 'keys':
        result = dependency_keys(args.root, environ)
        destination = environ.get('DEPS_ARTIFACT_KEYS_FILE')
        if destination:
            write_keys(destination, result)
    elif args.command == 'prepare':
        # Recursive Make runs '+' recipes even under -n. Never compile or write
        # caches when a caller is only inspecting the graph.
        flags = environ.get('MAKEFLAGS', '').split(' ', 1)[0]
        if not flags.startswith('--') and 'n' in flags:
            print('[deps] dry run: prepare automatic dependency cache')
            return 0
        result = prepare_dependencies(args.root, environ)
    else:
        if args.input is None or args.source_sha is None:
            parser.error('publication requires --input and --source-sha')
        from publication import publication_matrix, publish_candidate
        if args.command == 'publication-matrix':
            result = publication_matrix(args.input, args.source_sha, args.root, environ)
            if args.github_output:
                with args.github_output.open('a') as output:
                    output.write('matrix=' + json.dumps(result, separators=(',', ':')) + '\n')
                    output.write('count=' + str(len(result['include'])) + '\n')
        else:
            if args.dependency is None or args.fingerprint is None:
                parser.error('publish requires --dependency and --fingerprint')
            result = publish_candidate(args.input, args.dependency, args.fingerprint,
                                       args.source_sha, args.root, args.repository, environ)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
