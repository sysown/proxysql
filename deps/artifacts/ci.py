#!/usr/bin/env python3
"""Expose dependency cache keys and prepare verified bundles for CI."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from identity import DEPENDENCIES, ToolchainUnavailable, build_identity, configuration, fingerprint
from manage import prepare_dependency
import store


def dependency_keys(root, environ):
    requested = environ.get('DEPS_ARTIFACT_DEPENDENCIES', '').split()
    dependencies = requested or ['openssl'] + (['duckdb'] if environ.get('PROXYSQL40') == '1' else [])
    if len(set(dependencies)) != len(dependencies) or any(d not in DEPENDENCIES for d in dependencies):
        raise ValueError('invalid requested dependency set')
    result = {}
    for dependency in dependencies:
        row = dict(eligible=False, fingerprint='', key='', path='')
        try:
            identity = build_identity(dependency, root, environ)
        except ToolchainUnavailable as exc:
            row['reason'] = str(exc)
        else:
            key = fingerprint(identity)
            row['fingerprint'] = key
            if identity['eligible']:
                row.update(eligible=True, key='proxysql-deps-v1-' + dependency + '-' + key,
                           path='.cache/dependency-artifacts/bundles/' + dependency + '/' + key)
        result[dependency] = row
    return result


def prepare_dependencies(root, environ):
    result = {}
    for dependency, row in dependency_keys(root, environ).items():
        result[dependency] = prepare_dependency(dependency, root, environ.get('DEPS_MODE', 'auto'), environ)
        if row['eligible']:
            directory = store.bundle_directory(store.cache_root(root), dependency, row['fingerprint'])
            try:
                subprocess.check_call(['bash', str(Path(root) / 'test/infra/control/dependency-artifacts-smoke.bash'),
                                       dependency, str(configuration(dependency, root)['tree'])], env=dict(environ))
            except (OSError, subprocess.SubprocessError):
                shutil.rmtree(str(directory), ignore_errors=True)
                raise
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('keys', 'prepare'))
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    environ = dict(os.environ)
    flags = environ.get('MAKEFLAGS', '').split(' ', 1)[0]
    if args.command == 'prepare' and not flags.startswith('--') and 'n' in flags:
        print('[deps] dry run: prepare automatic dependency cache')
        return
    result = dependency_keys(args.root, environ) if args.command == 'keys' else prepare_dependencies(args.root, environ)
    if args.command == 'keys' and environ.get('DEPS_ARTIFACT_KEYS_FILE'):
        path = Path(environ['DEPS_ARTIFACT_KEYS_FILE'])
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(result, sort_keys=True) + '\n')
        os.replace(str(temporary), str(path))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
