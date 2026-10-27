#!/usr/bin/env python3
"""Preserve job infrastructure evidence before teardown, regardless of service type."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import socket
import subprocess
import tarfile
import tempfile
import threading
import time

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_FILES = 512
LOG_ROOTS = ('/var/log', '/var/logs', '/root/sandboxes/logs', '/home/pguser/sandboxes/logs')
FIND_ROOTS = ('/root/sandboxes', '/home/pguser/sandboxes', '/var/lib/mysql',
              '/var/lib/postgresql/data/log', '/var/lib/proxysql', '/tmp')
CONFIG_NAMES = ('init_db', 'my.sandbox.cnf', 'postgresql.conf', 'pg_hba.conf', 'logfile')
INSPECT = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
           '"state":{{json .State}},"mounts":{{json .Mounts}},'
           '"networks":{{json .NetworkSettings.Networks}},'
           '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
           '"memory_limit":{{json .HostConfig.Memory}},"nano_cpus":{{json .HostConfig.NanoCpus}}}')
PROCESS_SNAPSHOT = r'''
count=0
for dir in /proc/[0-9]*; do
  [ -r "$dir/comm" ] || continue
  count=$((count+1)); [ "$count" -le 128 ] || break
  printf '\n=== %s ===\n' "$dir"
  for file in comm status io wchan; do
    printf '\n--- %s ---\n' "$file"
    cat "$dir/$file" 2>/dev/null || true
  done
done
'''


def selected_containers(states, infra_id, workspace, all_containers=False):
    """Select job ownership first, then include its project/network peers."""
    owned, projects, networks = set(), set(), set()
    for state in states:
        project = state.get('project') or ''
        names = set(state.get('networks') or {})
        mounted = any(m.get('Source') and Path(m['Source']).resolve().is_relative_to(workspace)
                      for m in state.get('mounts') or [])
        named = infra_id and (project.endswith('-' + infra_id)
                               or infra_id + '_backend' in names
                               or state.get('name', '').lstrip('/') == 'proxysql.' + infra_id)
        if all_containers or mounted or named:
            owned.add(state['id'])
    changed = True
    while changed:
        changed = False
        for state in states:
            project = state.get('project') or ''
            names = set(state.get('networks') or {}) - {'host', 'none', 'bridge'}
            if state['id'] in owned or (project and project in projects) or names & networks:
                if state['id'] not in owned:
                    owned.add(state['id']); changed = True
                project_count = len(projects)
                projects.update([project] if project else [])
                changed |= len(projects) != project_count
                before = len(networks)
                networks.update(names)
                changed |= len(networks) != before
    return [state for state in states if state['id'] in owned]


def wanted_file(path):
    return path.name.endswith(('.err', '.log', '.out', '.conf')) or path.name in CONFIG_NAMES


def stopped_sandbox_paths(deployment, project):
    paths = set()
    for kind, version in re.findall(r'Using (MySQL|MariaDB|PostgreSQL) version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', deployment):
        if kind == 'PostgreSQL':
            major, minor = map(int, version.split('.')[:2])
            bases = ['/home/pguser/sandboxes/postgresql_repl_' + str(15000 + major*100 + minor)]
            nodes = ('primary', 'replica1', 'replica2')
        else:
            version = version.replace('.', '_')
            topology = ('group_sp_msb' if re.match(r'^infra-dbdeployer-mysql\d+-gr(?:-|$)', project)
                        else 'galera_msb' if re.match(r'^infra-dbdeployer-mariadb\d+-galera(?:-|$)', project)
                        else 'msb' if re.match(r'^infra-dbdeployer-mysql\d+-single(?:-|$)', project) else 'rsandbox')
            bases = ['/root/sandboxes/' + topology + '_' + version]
            nodes = ('',) if topology == 'msb' else ('node1', 'node2', 'node3') if topology != 'rsandbox' else ('master', 'node1', 'node2')
        for base in bases:
            for node in nodes:
                for name in ('data/msandbox.err', 'my.sandbox.cnf', 'init_db', 'postgresql.log', 'logfile', 'data/postgresql.conf', 'data/pg_hba.conf'):
                    paths.add(str(PurePosixPath(base) / node / name))
    return paths


def collect(infra_id, output, workspace=None, all_containers=False, host_log_root=None,
            container_ids=None, docker_command=None, timeout=120):
    output.mkdir(parents=True, exist_ok=True)
    workspace = Path(workspace or os.environ.get('GITHUB_WORKSPACE', os.getcwd())).resolve()
    records = []
    deadline = time.monotonic() + timeout
    existing = [p for p in output.rglob('*') if p.is_file() and not p.is_symlink()]
    copied = sum(p.stat().st_size for p in existing)
    files = len(existing)
    docker_command = docker_command or [os.environ.get('CI_INFRA_REAL_DOCKER', 'docker')]

    def command(args, destination=None, merge_stderr=False, max_time=10):
        nonlocal copied, files
        record = dict(command=args, time=datetime.now(timezone.utc).isoformat())
        records.append(record)
        if destination is not None:
            if copied >= MAX_TOTAL_BYTES:
                record['error'] = 'diagnostic byte budget reached'
                return ''
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists(): copied -= destination.stat().st_size
            destination.write_bytes(b'')
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('collection deadline reached')
            if destination is not None:
                # Stream directly to disk. The child cannot grow a diagnostic
                # file beyond the cap, even for a single enormous log line.
                def limit_output():
                    cap = min(MAX_FILE_BYTES, max(0, MAX_TOTAL_BYTES-copied))
                    resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))
                with destination.open('wb') as target:
                    result = subprocess.run([*docker_command, *args], stdout=target,
                        stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
                        timeout=min(max_time, remaining), preexec_fn=limit_output)
                data = destination.read_text(errors='replace')
                copied += destination.stat().st_size; files += 1
            else:
                result = subprocess.run([*docker_command, *args], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=min(max_time, remaining))
                data = result.stdout.decode(errors='replace')
            record.update(returncode=result.returncode, stderr=(result.stderr or b'').decode(errors='replace'))
            # find may report absent optional roots while returning useful paths.
            return data
        except (OSError, subprocess.TimeoutExpired, TimeoutError) as error:
            record['error'] = str(error)
            if isinstance(error, subprocess.TimeoutExpired) and destination is not None and error.output:
                destination.write_bytes(error.output[:MAX_FILE_BYTES])
            return ''

    def copy_log_path(container, name, folder):
        """Stream selected log paths from running or exited containers; no tar on disk."""
        nonlocal copied, files
        if time.monotonic() >= deadline or copied >= MAX_TOTAL_BYTES or files >= MAX_FILES:
            return
        args = ['cp', container + ':' + name, '-']
        record = dict(command=args, time=datetime.now(timezone.utc).isoformat())
        records.append(record)
        process = None
        timer = None
        try:
            with tempfile.TemporaryFile() as errors:
                process = subprocess.Popen([*docker_command, *args], stdout=subprocess.PIPE, stderr=errors)
                timer = threading.Timer(min(10, max(.01, deadline-time.monotonic())), process.kill)
                timer.start()
                with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                    for member in archive:
                        path = PurePosixPath(member.name)
                        if not member.isfile() or path.is_absolute() or '..' in path.parts:
                            continue
                        if not path.parts or path.parts[0] != PurePosixPath(name).name:
                            continue
                        size = min(member.size, MAX_FILE_BYTES, MAX_TOTAL_BYTES-copied)
                        stream = archive.extractfile(member)
                        payload = stream.read(size)
                        target = folder / PurePosixPath(name).parent.relative_to('/') / path
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(payload)
                        copied += len(payload); files += 1
                        if size < member.size or copied >= MAX_TOTAL_BYTES or files >= MAX_FILES:
                            record['truncated'] = True
                            break
                if record.get('truncated') and process.poll() is None:
                    process.kill()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                errors.seek(0)
                record.update(returncode=process.returncode, stderr=errors.read(4096).decode(errors='replace'))
        except (OSError, tarfile.TarError, EOFError) as error:
            record['error'] = str(error)
        finally:
            if timer:
                timer.cancel()
            if process:
                if process.poll() is None: process.kill()
                process.wait()
                if process.stdout: process.stdout.close()

    host = ['time: ' + datetime.now(timezone.utc).isoformat(), 'host: ' + socket.gethostname()]
    for name in ('loadavg', 'meminfo', 'stat', 'diskstats', 'pressure/cpu', 'pressure/io', 'pressure/memory'):
        try: host += ['\n=== /proc/' + name + ' ===', (Path('/proc') / name).read_text()]
        except OSError as error: host.append(str(error))
    (output / 'host.txt').write_text('\n'.join(host))
    ids = container_ids if container_ids is not None else command(['ps', '-aq']).split()
    ids = [value for value in ids if re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]*', value)]
    states = []
    if ids:
        for row in command(['inspect', '--format', INSPECT, *ids]).splitlines():
            try:
                state = json.loads(row)
                if isinstance(state, dict) and re.fullmatch('[0-9a-f]+', state.get('id', '')):
                    states.append(state)
            except (ValueError, TypeError):
                continue
    owned = selected_containers(states, infra_id, workspace, all_containers)
    # Save every service's stdout/state first; one slow file probe must not
    # consume the time budget before other containers' primary evidence exists.
    log_budget = min(3, max(.05, (deadline-time.monotonic())*.4/max(1,len(owned))))
    for state in owned:
        container = state['id']; folder = output / container; folder.mkdir(exist_ok=True)
        (folder / 'state.json').write_text(json.dumps(state, indent=2) + '\n')
        (folder / 'project.txt').write_text((state.get('project') or '') + '\n')
        command(['logs', '--timestamps', '--tail', '20000', container], folder / 'deployment.log',
                merge_stderr=True, max_time=log_budget)
    for state in owned:
        container = state['id']; folder = output / container
        if state.get('state',{}).get('Status') not in (None,'running'):
            continue
        command(['top', container, '-eo', 'pid,ppid,stat,etime,time,pcpu,pmem,wchan:32,args'], folder / 'processes.txt')
        command(['stats', '--no-stream', '--format', '{{json .}}', container], folder / 'stats.json')
        command(['exec', container, 'sh', '-c', PROCESS_SNAPSHOT], folder / 'process-io.txt')
    for state in owned:
        container = state['id']; folder = output / container
        for name in LOG_ROOTS:
            copy_log_path(container, name, folder)
        listing = command(['exec', container, 'find', *FIND_ROOTS, '-maxdepth', '6', '-type', 'f',
                           '(', '-name', '*.err', '-o', '-name', '*.log', '-o', '-name', '*.out',
                           '-o', '-name', 'my.sandbox.cnf', '-o', '-name', 'init_db', '-o', '-name', 'logfile', ')', '-print'])
        paths = set(listing.splitlines())
        if not paths:
            log = folder/'deployment.log'
            paths = stopped_sandbox_paths(log.read_text(errors='replace') if log.exists() else '', state.get('project') or '')
        for name in sorted(paths):
            path = PurePosixPath(name)
            if '..' in path.parts or not wanted_file(path) or not any(path.is_relative_to(root) for root in FIND_ROOTS):
                continue
            if any(path.is_relative_to(root) for root in LOG_ROOTS):
                continue
            copy_log_path(container, str(path), folder)
    if host_log_root:
        root = Path(host_log_root).expanduser()
        seen = 0
        for parent, dirs, names in os.walk(root):
            if len(Path(parent).relative_to(root).parts) >= 6: dirs[:] = []
            for name in names:
                seen += 1
                source = Path(parent)/name
                if seen > 5000 or copied >= MAX_TOTAL_BYTES or files >= MAX_FILES: break
                if not source.is_symlink() and wanted_file(source):
                    try:
                        with source.open('rb') as stream: payload = stream.read(min(MAX_FILE_BYTES, MAX_TOTAL_BYTES-copied))
                        target = output/'host-sandboxes'/source.relative_to(root)
                        target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(payload)
                        copied += len(payload); files += 1
                    except OSError as error: records.append(dict(path=str(source), error=str(error)))
            if seen > 5000 or copied >= MAX_TOTAL_BYTES or files >= MAX_FILES: break
    history = output / 'collection.json'
    if history.is_file():
        try: records = json.loads(history.read_text()) + records
        except (ValueError, TypeError): pass
    history.write_text(json.dumps(records[-5000:], indent=2) + '\n')
    failures = sum(record.get('returncode', 1) != 0 for record in records)
    print(f'Infrastructure diagnostics saved to {output}: {len(owned)} containers, {files} log files, {copied} bytes; {failures} unavailable probes (see collection.json)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--infra-id', default='')
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--all-containers', action='store_true', help='Only for an isolated job runner')
    parser.add_argument('--host-log-root', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    collect(args.infra_id, args.output, args.workspace, args.all_containers, args.host_log_root)


if __name__ == '__main__':
    main()
