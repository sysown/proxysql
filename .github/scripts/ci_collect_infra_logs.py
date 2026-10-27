#!/usr/bin/env python3
"""Preserve job infrastructure evidence before teardown, regardless of service type."""
import argparse
from contextlib import ExitStack
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
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
LOG_ROOTS = ('/var/log', '/var/logs', '/root/sandboxes/logs', '/home/pguser/sandboxes/logs')
FIND_ROOTS = ('/root/sandboxes', '/home/pguser/sandboxes', '/var/lib/mysql',
              '/var/lib/postgresql/data/log', '/var/lib/proxysql',
              '/tmp')  # NOSONAR S5443: read-only container log discovery; no host files created here.
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


def diagnostic_root(output):
    root = Path(os.environ.get('RUNNER_TEMP') or tempfile.gettempdir()).resolve()
    output = Path(output).resolve()
    if output == root or not output.is_relative_to(root):
        raise ValueError('diagnostics output must be a directory under runner temp')
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    return output


class FileBudget:
    """Account for every payload write, including partial subprocess output."""
    def __init__(self, root):
        self.root = root
        self.history = root / 'collection.json'
        if self.history.is_symlink():
            raise ValueError('diagnostic manifest must not be a symbolic link')
        existing = [p for p in root.rglob('*') if p.is_file() and not p.is_symlink()]
        if not self.history.exists():
            if len(existing) >= MAX_FILES:
                raise ValueError('no file slot available for diagnostic manifest')
            self.history.touch()
            existing.append(self.history)
        self.files = len(existing)
        # The manifest has its own per-file bound and reserved file slot so
        # exhausted payload budgets can still explain omitted diagnostics.
        self.bytes = sum(p.stat().st_size for p in existing if p != self.history)

    def capacity(self, destination):
        if destination.is_symlink() or not destination.resolve().is_relative_to(self.root):
            raise ValueError('diagnostic destination escapes its output directory')
        exists = destination.exists()
        old = destination.stat().st_size if exists else 0
        capacity = min(MAX_FILE_BYTES, MAX_TOTAL_BYTES-self.bytes+old)
        if capacity <= 0 or (not exists and self.files >= MAX_FILES):
            return 0
        return capacity

    def claim(self, destination):
        capacity = self.capacity(destination)
        if not capacity:
            return 0
        exists = destination.exists()
        old = destination.stat().st_size if exists else 0
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b'')
        self.bytes -= old
        self.files += int(not exists)
        return capacity

    def account(self, destination, capacity):
        size = min(destination.stat().st_size, capacity)
        with destination.open('r+b') as stream:
            stream.truncate(size)
        self.bytes += size

    def save(self, destination, payload):
        capacity = self.claim(destination)
        if not capacity:
            return False
        destination.write_bytes(payload[:capacity])
        self.account(destination, capacity)
        return True

    def manifest(self, records):
        try:
            previous = json.loads(self.history.read_text())
        except (ValueError, OSError):
            previous = []
        if not isinstance(previous, list):
            previous = []
        records = (previous + records)[-5000:]
        payload = json.dumps(records, indent=2).encode()
        while len(payload) > MAX_FILE_BYTES and len(records) > 1:
            records = records[len(records)//2:]
            records[-1]['manifest_truncated'] = True
            records[-1]['truncated'] = True
            payload = json.dumps(records, indent=2).encode()
        if len(payload) > MAX_FILE_BYTES:
            payload = b'[{"error":"diagnostic manifest exceeded its size limit"}]'
        self.history.write_bytes(payload)


class ArchiveInputLimit(OSError):
    pass


class ArchiveReader:
    """Bound archive input as well as saved output when skipping large logs."""
    def __init__(self, stream, remaining):
        self.stream = stream
        self.remaining = remaining

    def read(self, size=-1):
        if self.remaining[0] <= 0:
            raise ArchiveInputLimit('diagnostic archive input limit reached')
        size = self.remaining[0] if size < 0 else min(size, self.remaining[0])
        data = self.stream.read(size)
        self.remaining[0] -= len(data)
        return data


def inspect_states(ids, command, keep_going):
    """Inspect bounded batches and retry truncated or partly unavailable batches."""
    states = {}

    def batch(values):
        if not values or not keep_going():
            return
        parsed = 0
        for row in command(['inspect', '--format', INSPECT, *values]).splitlines():
            try:
                state = json.loads(row)
                if isinstance(state, dict) and re.fullmatch('[0-9a-f]+', state.get('id', '')):
                    states[state['id']] = state
                    parsed += 1
            except (ValueError, TypeError):
                continue
        if parsed < len(values) and len(values) > 1:
            half = len(values)//2
            batch(values[:half])
            batch(values[half:])

    for start in range(0, len(ids), 16):
        if not keep_going():
            break
        batch(ids[start:start+16])
    return list(states.values())


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
    output = diagnostic_root(output)
    workspace = Path(workspace or os.environ.get('GITHUB_WORKSPACE', os.getcwd())).resolve()
    records = []
    deadline = time.monotonic() + timeout
    budget = FileBudget(output)
    archive_remaining = [MAX_ARCHIVE_BYTES]
    docker_command = docker_command or [os.environ.get('CI_INFRA_REAL_DOCKER', 'docker')]

    def command(args, destination=None, merge_stderr=False, max_time=10):
        record = {'command': args, 'time': datetime.now(timezone.utc).isoformat()}
        records.append(record)
        capacity = budget.claim(destination) if destination is not None else MAX_CAPTURE_BYTES
        if not capacity:
            record['error'] = 'diagnostic byte or file budget reached'
            return ''
        data = b''
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('collection deadline reached')
            def limit_output():
                resource.setrlimit(resource.RLIMIT_FSIZE, (capacity, capacity))
            with ExitStack() as stack:
                target = stack.enter_context(destination.open('w+b') if destination is not None else tempfile.TemporaryFile())
                errors = None if merge_stderr else stack.enter_context(tempfile.TemporaryFile())
                try:
                    result = subprocess.run([*docker_command, *args], stdout=target,
                        stderr=subprocess.STDOUT if merge_stderr else errors,
                        timeout=min(max_time, remaining), preexec_fn=limit_output)
                    record['returncode'] = result.returncode
                except (OSError, subprocess.TimeoutExpired) as error:
                    record['error'] = str(error)
                    if isinstance(error, subprocess.TimeoutExpired) and error.output and target.tell() == 0:
                        target.write(error.output[:capacity])
                finally:
                    target.flush(); target.seek(0)
                    data = target.read(capacity)
                    if errors:
                        errors.seek(0)
                        record['stderr'] = errors.read(4096).decode(errors='replace')
                    if len(data) == capacity:
                        record['truncated'] = True
        except OSError as error:
            record['error'] = str(error)
        finally:
            if destination is not None:
                budget.account(destination, capacity)
        # Even a failed find can return useful paths from existing roots.
        return data.decode(errors='replace')

    def copy_log_path(container, name, folder):
        """Stream selected log paths from running or exited containers; no tar on disk."""
        if time.monotonic() >= deadline or archive_remaining[0] <= 0:
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
                with tarfile.open(fileobj=ArchiveReader(process.stdout, archive_remaining), mode='r|') as archive:
                    for member in archive:
                        path = PurePosixPath(member.name)
                        if not member.isfile() or path.is_absolute() or '..' in path.parts:
                            continue
                        if not path.parts or path.parts[0] != PurePosixPath(name).name:
                            continue
                        target = folder / PurePosixPath(name).parent.relative_to('/') / path
                        capacity = budget.capacity(target)
                        if not capacity:
                            record['truncated'] = True
                            continue
                        size = min(member.size, capacity)
                        stream = archive.extractfile(member)
                        payload = stream.read(size)
                        budget.save(target, payload)
                        if size < member.size:
                            record['truncated'] = True
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                errors.seek(0)
                record.update(returncode=process.returncode, stderr=errors.read(4096).decode(errors='replace'))
        except (OSError, tarfile.TarError, EOFError) as error:
            record['error'] = str(error)
            if isinstance(error, ArchiveInputLimit):
                record['truncated'] = True
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
    budget.save(output / 'host.txt', '\n'.join(host).encode())
    ids = container_ids if container_ids is not None else command(['ps', '-aq']).split()
    ids = [value for value in ids if re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]*', value)]
    states = inspect_states(ids, command, lambda: time.monotonic() < deadline)
    owned = selected_containers(states, infra_id, workspace, all_containers)
    # Save every service's stdout/state first; one slow file probe must not
    # consume the time budget before other containers' primary evidence exists.
    log_budget = min(3, max(.05, (deadline-time.monotonic())*.4/max(1,len(owned))))
    for state in owned:
        container = state['id']; folder = output / container; folder.mkdir(exist_ok=True)
        budget.save(folder / 'state.json', (json.dumps(state, indent=2) + '\n').encode())
        budget.save(folder / 'project.txt', ((state.get('project') or '') + '\n').encode())
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
                           '(', '-name', '*.err', '-o', '-name', '*.log', '-o', '-name', '*.out', '-o', '-name', '*.conf',
                           '-o', '-name', 'my.sandbox.cnf', '-o', '-name', 'init_db', '-o', '-name', 'logfile', ')', '-print'])
        paths = set(listing.splitlines()[:MAX_FILES])
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
                if seen > 5000 or time.monotonic() >= deadline: break
                if not source.is_symlink() and wanted_file(source):
                    try:
                        target = output/'host-sandboxes'/source.relative_to(root)
                        capacity = budget.capacity(target)
                        if not capacity: continue
                        source_size = source.stat().st_size
                        with source.open('rb') as stream: payload = stream.read(capacity)
                        budget.save(target, payload)
                        if len(payload) < source_size:
                            records.append({'path':str(source),'returncode':0,'truncated':True,
                                            'saved_bytes':len(payload),'source_bytes':source_size})
                    except OSError as error: records.append(dict(path=str(source), error=str(error)))
            if seen > 5000 or time.monotonic() >= deadline: break
    records.append({'kind': 'limits', 'returncode': 0, 'payload_bytes': budget.bytes,
                    'files': budget.files, 'archive_bytes': MAX_ARCHIVE_BYTES-archive_remaining[0]})
    budget.manifest(records)
    failures = sum(record.get('returncode', 1) != 0 for record in records)
    print(f'Infrastructure diagnostics saved to {output}: {len(owned)} containers, {budget.files} diagnostic files, {budget.bytes} payload bytes; {failures} unavailable probes (see collection.json)')


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
