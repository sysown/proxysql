#!/usr/bin/env python3
"""Prepare exact dependency bundles in the product's actual build container."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

DEPENDENCIES = ('openssl', 'duckdb')


def emit(**values):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        for name, value in values.items():
            value = str(value)
            if '\n' in value or '\r' in value:
                raise ValueError('invalid action output')
            output.write(name + '=' + value + '\n')


def source_directory(value):
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    source = (workspace / value).resolve()
    source.relative_to(workspace)
    if not source.is_dir():
        raise ValueError('product source directory does not exist')
    return source


def selected_dependencies(args):
    dependencies = args.dependencies.split() if args.dependencies else (
        list(DEPENDENCIES) if args.tier == 'v40' else ['openssl'])
    if len(set(dependencies)) != len(dependencies) or any(d not in DEPENDENCIES for d in dependencies):
        raise ValueError('dependencies must be openssl and/or duckdb')
    return dependencies


def load_keys(source, selected):
    path = source / '.cache/dependency-artifacts/ci-keys.json'
    if path.stat().st_size > 1024 * 1024:
        raise ValueError('oversized dependency keys')
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or any(d not in DEPENDENCIES for d in data):
        raise ValueError('invalid dependency keys')
    result = {}
    for dependency in selected:
        item = data.get(dependency)
        if not isinstance(item, dict):
            raise ValueError('missing dependency key: ' + dependency)
        if item.get('eligible') is not True:
            if item.get('key') or item.get('path'):
                raise ValueError('ineligible dependency advertised a cache key')
            continue
        fingerprint = item.get('fingerprint', '')
        if not isinstance(fingerprint, str) or not re.fullmatch('[0-9a-f]{64}', fingerprint):
            raise ValueError('invalid dependency fingerprint')
        key = 'proxysql-deps-v1-' + dependency + '-' + fingerprint
        relative = '.cache/dependency-artifacts/bundles/' + dependency + '/' + fingerprint
        if item.get('key') != key or item.get('path') != relative:
            raise ValueError('dependency key/path does not match fingerprint')
        destination = source / relative
        if destination.resolve() != destination:
            raise ValueError('dependency cache path must not traverse symlinks')
        result[dependency] = (key, destination, fingerprint)
    return result


def docker_environment():
    # Compose files are product inputs. Never offer them host credentials or
    # Actions service tokens through environment interpolation/passthrough.
    return {name: value for name, value in os.environ.items()
            if not name.startswith(('GITHUB_', 'ACTIONS_', 'AWS_', 'AZURE_', 'GOOGLE_', 'SSH_'))
            and not any(word in name.upper() for word in ('TOKEN', 'SECRET', 'PASSWORD', 'CREDENTIAL', '_KEY', 'AUTH', 'COOKIE', 'SESSION'))}


def run_container(args, source, target, dependencies):
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]*', args.service):
        raise ValueError('invalid compose service')
    environment = {
        'PROXYSQL40': '1' if args.tier == 'v40' else '0',
        'PROXYSQL31': '1' if args.tier == 'v31' else '0',
        'WITHASAN': '1' if args.sanitizer == 'asan' else '0',
        'TEST_WITHASAN': '1' if args.sanitizer == 'asan' else '0',
        'WITHTSAN': '1' if args.sanitizer == 'tsan' else '0',
        'WITHGCOV': '1' if args.coverage == 'true' else '0',
        'DEPS_MODE': 'auto',
        'DEPS_ARTIFACT_DEPENDENCIES': ' '.join(dependencies),
        'DEPS_ARTIFACT_KEYS_FILE': '/opt/proxysql/.cache/dependency-artifacts/ci-keys.json',
        'DEPS_ARTIFACT_UID': str(os.getuid()), 'DEPS_ARTIFACT_GID': str(os.getgid()),
    }
    command = ['docker', 'compose', 'run', '--rm', '--no-deps', '-T', '--entrypoint', '/bin/bash']
    for name, value in environment.items():
        command += ['-e', name + '=' + value]
    script = ('set -euo pipefail; cd /opt/proxysql; '
              'export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/proxysql; '
              'status=0; make --no-print-directory -C deps ' + target + ' || status=$?; '
              'chown -R "$DEPS_ARTIFACT_UID:$DEPS_ARTIFACT_GID" .cache/dependency-artifacts; '
              'exit "$status"')
    command += [args.service, '-lc', script]
    subprocess.run(command, cwd=source, env=docker_environment(), check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('keys', 'prepare'))
    parser.add_argument('--source-path', required=True)
    parser.add_argument('--service', default='ubuntu24_dbg_build')
    parser.add_argument('--tier', choices=('v30', 'v31', 'v40'), default='v40')
    parser.add_argument('--sanitizer', choices=('none', 'asan', 'tsan'), default='none')
    parser.add_argument('--coverage', choices=('false', 'true'), default='false')
    parser.add_argument('--dependencies', default='')
    args = parser.parse_args()
    source = source_directory(args.source_path)
    selected = selected_dependencies(args)
    if args.command == 'keys':
        if not (source / 'deps/artifacts/ci.py').is_file():
            print('::notice::Product predates dependency cache API; continuing the regular build')
            emit(enabled='false')
            return
        cache = source / '.cache/dependency-artifacts'
        cache.mkdir(parents=True, exist_ok=True)
        (cache / 'ci-keys.json').unlink(missing_ok=True)
        run_container(args, source, 'dependency-artifact-keys', selected)
        keys = load_keys(source, selected)
        emit(enabled='true', **{'selected-' + d: 'true' for d in selected})
        for dependency, (key, path, _) in keys.items():
            # Keep cache path strings stable across hosted/self-hosted workspace roots.
            relative = path.relative_to(Path(os.environ['GITHUB_WORKSPACE']).resolve())
            emit(**{dependency + '-key': key, dependency + '-path': relative.as_posix()})
        return
    dependency = os.environ['CACHE_DEPENDENCY']
    if dependency not in selected:
        raise ValueError('dependency was not selected')
    keys = load_keys(source, selected)
    # Ineligible dependencies still prepare from source and run their smoke check.
    if dependency in keys:
        key, path, fingerprint = keys[dependency]
        exact = (os.environ.get('CACHE_HIT') == 'true' and
                 os.environ.get('CACHE_MATCHED_KEY') == key and
                 os.environ.get('CACHE_REQUESTED_KEY') == key)
        if not exact and path.exists():
            shutil.rmtree(path)
    run_container(args, source, 'dependency-artifact-prepare', [dependency])
    if dependency in keys:
        for name in ('entry.json', 'bundle.tar.gz'):
            file = path / name
            if file.is_symlink() or not file.is_file() or not file.stat().st_size:
                raise ValueError('missing prepared bundle output: ' + name)
        entry = json.loads((path / 'entry.json').read_text())
        if entry.get('dependency') != dependency or entry.get('fingerprint') != fingerprint:
            raise ValueError('prepared bundle identity does not match requested cache key')
        emit(ready='true')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit('Dependency cache failed: ' + str(error))
