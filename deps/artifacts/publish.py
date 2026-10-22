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
from urllib.parse import urlsplit

from bundles import verify_archive
from identity import DEPENDENCIES, FORMAT_VERSION, load_json, load_registry, validate_entry

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


def run(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True)
    if result.returncode:
        raise ValueError('command failed: ' + ' '.join(args) + '\n' + result.stderr)
    return result.stdout.strip()


def publish_batch(directory, repository, tag):
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or
            not re.fullmatch(r'dependency-artifacts-v1-[0-9]+-[0-9]+', tag)):
        raise ValueError('invalid dependency repository/tag')
    directory = Path(directory)
    registry = merge_entries(directory)
    prefix = 'https://github.com/' + repository + '/releases/download/' + tag + '/'
    if any(not entry['url'].startswith(prefix) for entry in registry['artifacts']):
        raise ValueError('artifact URL does not match publication repository/tag')
    commits = {entry['provenance'].get('commit') for entry in registry['artifacts']}
    if len(commits) != 1 or not re.fullmatch(r'[0-9a-f]{40}', next(iter(commits)) or ''):
        raise ValueError('batch must come from one source commit')
    existing = subprocess.run(['gh', 'api', 'repos/' + repository + '/releases/tags/' + tag],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
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
    run(['gh', 'release', 'upload', tag, '--repo', repository] + assets + [str(lock)])
    run(['gh', 'release', 'edit', tag, '--repo', repository, '--draft=false', '--prerelease', '--latest=false'])


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
        run(['docker', 'pull', '--platform', 'linux/' + profile['arch'], image])
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
    subprocess.check_call(command)


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
    build = sub.add_parser('build')
    build.add_argument('--profile', required=True)
    build.add_argument('--dependency', choices=DEPENDENCIES, required=True)
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--repository', required=True)
    build.add_argument('--tag', required=True)
    args = parser.parse_args()
    if args.command == 'matrix':
        print(json.dumps(build_matrix(args.group, args.dependency), separators=(',', ':')))
    elif args.command == 'merge':
        args.output.write_text(json.dumps(merge_entries(args.input, args.base), indent=2, sort_keys=True) + '\n')
    elif args.command == 'publish':
        publish_batch(args.input, args.repository, args.tag)
    elif args.command == 'build':
        build_profile(args.profile, args.dependency, args.output, args.repository, args.tag)
    else:
        parser.error('a subcommand is required')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        sys.exit(1)
