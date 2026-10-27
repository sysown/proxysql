#!/usr/bin/env python3
"""Save MySQL GR deployment evidence before its containers are removed."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import socket
import subprocess
import time


PROCESS_SNAPSHOT = r'''
for dir in /proc/[0-9]*; do
  read -r name < "$dir/comm" 2>/dev/null || continue
  case "$name" in
    mysqld*|dbdeployer)
      printf '\n=== %s (%s) ===\n' "$dir" "$name"
      for file in cmdline status io wchan; do
        printf '\n--- %s ---\n' "$file"
        tr '\000' ' ' < "$dir/$file" 2>/dev/null || true
      done
      ;;
  esac
done
'''


def collect(infra_id, output):
    output.mkdir(parents=True, exist_ok=True)
    records = []
    deadline = time.monotonic() + 120

    def command(args, destination=None, merge_stderr=False):
        record = dict(command=args, time=datetime.now(timezone.utc).isoformat())
        records.append(record)
        if destination is not None:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b'')
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('collection deadline reached')
            result = subprocess.run(['docker', *args], stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
                                    timeout=min(15, remaining))
            record.update(returncode=result.returncode,
                          stderr=(result.stderr or b'').decode(errors='replace'))
            if destination is not None:
                destination.write_bytes(result.stdout)
            return result.stdout.decode(errors='replace') if result.returncode == 0 else ''
        except (OSError, subprocess.TimeoutExpired, TimeoutError) as error:
            record['error'] = str(error)
            if isinstance(error, subprocess.TimeoutExpired) and destination is not None:
                destination.write_bytes(error.output or b'')
            return ''

    host = ['time: ' + datetime.now(timezone.utc).isoformat(), 'host: ' + socket.gethostname()]
    for name in ('loadavg', 'meminfo', 'stat', 'diskstats', 'pressure/cpu', 'pressure/io', 'pressure/memory'):
        try:
            host += ['\n=== /proc/' + name + ' ===', (Path('/proc') / name).read_text()]
        except OSError as error:
            host.append(str(error))
    (output / 'host.txt').write_text('\n'.join(host))

    rows = command(['ps', '-a', '--filter', 'label=com.docker.compose.project',
                    '--format', '{{.ID}} {{.Label "com.docker.compose.project"}}'])
    for row in rows.splitlines():
        fields = row.split()
        if len(fields) != 2:
            continue
        container, project = fields
        if not (project.startswith('infra-dbdeployer-mysql') and project.endswith('-' + infra_id)):
            continue
        if not re.fullmatch('[0-9a-f]+', container):
            continue
        folder = output / container
        folder.mkdir(exist_ok=True)
        (folder / 'project.txt').write_text(project + '\n')
        # Docker returns the container's stderr on its own stderr stream.
        # Both streams belong in the saved deployment log.
        command(['logs', '--timestamps', container], folder / 'deployment.log', merge_stderr=True)
        deployment = (folder / 'deployment.log').read_text(errors='replace')
        state = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
                 '"state":{{json .State}},"memory_limit":{{json .HostConfig.Memory}},'
                 '"nano_cpus":{{json .HostConfig.NanoCpus}}}')
        command(['inspect', '--format', state, container], folder / 'state.json')
        command(['top', container, '-eo', 'pid,ppid,stat,etime,time,pcpu,pmem,wchan:32,args'], folder / 'processes.txt')
        command(['stats', '--no-stream', '--format', '{{json .}}', container], folder / 'stats.json')
        command(['exec', container, 'sh', '-c', PROCESS_SNAPSHOT], folder / 'process-io.txt')

        # dbdeployer's operation logs live here; never copy sandbox data trees.
        logs = folder / 'root/sandboxes'
        logs.mkdir(parents=True, exist_ok=True)
        command(['cp', container + ':/root/sandboxes/logs', str(logs / 'logs')])
        listing = command(['exec', container, 'find', '/root/sandboxes', '-maxdepth', '5',
                           '-type', 'f', '(', '-name', '*.err', '-o', '-name', 'my.sandbox.cnf',
                           '-o', '-name', 'init_db', ')', '-print'])
        paths = set(listing.splitlines())
        if not paths:
            # docker exec cannot inspect an exited container. Its logged version
            # gives the standard three-node GR paths, which docker cp still reads.
            versions = re.findall(r'Using MySQL version:\s*([0-9]+\.[0-9]+\.[0-9]+)', deployment)
            for version in set(versions):
                base = '/root/sandboxes/group_sp_msb_' + version.replace('.', '_')
                for node in ('node1', 'node2', 'node3'):
                    paths.update(base + '/' + node + '/' + name
                                 for name in ('data/msandbox.err', 'my.sandbox.cnf', 'init_db'))
        for name in sorted(paths):
            path = PurePosixPath(name)
            if ('..' in path.parts or not path.is_relative_to('/root/sandboxes')
                    or not (path.name.endswith('.err') or path.name in ('my.sandbox.cnf', 'init_db'))):
                continue
            destination = folder / path.relative_to('/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            command(['cp', container + ':' + str(path), str(destination)])

    (output / 'collection.json').write_text(json.dumps(records, indent=2) + '\n')
    failures = sum(record.get('returncode', 1) != 0 for record in records)
    print(f'MySQL deployment diagnostics saved to {output} ({failures} unavailable probes; see collection.json)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--infra-id', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    collect(args.infra_id, args.output)


if __name__ == '__main__':
    main()
