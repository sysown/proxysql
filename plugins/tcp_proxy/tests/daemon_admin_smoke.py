#!/usr/bin/env python3
"""Small real-daemon smoke harness for the native tcp_proxy plugin.
All datadirs, configs, loopback ports, backends and child processes are
task-owned and cleaned up with bounded waits.  Uses Python 3 stdlib and the
installed mysql CLI only.
"""
import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
HOST, ADMIN_USER, ADMIN_PASS = "127.0.0.1", "smoke", "smoke"
DEFAULT_SETTINGS = "1\t2\t10000\t16384\t5000\t30000"
SOURCE_PROTOCOL = "MYSQL"
SOURCE_HOSTGROUP = 10
TCP_HOSTGROUP = 1
# Four-table plugin metrics retain relay/listener/rule families only.  The
# deleted standalone server/health families must be absent.
METRIC_FAMILIES = {
    "proxysql_tcp_active_connections", "proxysql_tcp_accepted_total",
    "proxysql_tcp_rejected_total", "proxysql_tcp_connect_errors_total",
    "proxysql_tcp_matched_total",
    "proxysql_tcp_bytes_client_to_server_total",
    "proxysql_tcp_bytes_server_to_client_total",
    "proxysql_tcp_generation", "proxysql_tcp_running",
    "proxysql_tcp_retired_connections",
}

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def free_port():
    s = socket.socket()
    try:
        s.bind((HOST, 0))
        return s.getsockname()[1]
    finally:
        s.close()

def sql_lit(value):
    return "'" + str(value).replace("'", "''") + "'"

def clip(value, limit=600):
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "...<clipped>"

class Case:
    def __init__(self, name, evidence_dir):
        self.name, self.evidence_dir = name, evidence_dir
        self.checks, self.failures, self.daemons = [], [], []
    def check(self, name, ok, detail=""):
        self.checks.append({"name": name, "ok": bool(ok), "detail": clip(detail)})
        if not ok:
            self.failures.append(f"{name}: {clip(detail)}")
        return bool(ok)
    def must(self, name, ok, detail=""):
        if not self.check(name, ok, detail):
            raise RuntimeError(f"{name}: {clip(detail)}")
    def result(self):
        return {"name": self.name, "status": "PASS" if not self.failures else "FAIL",
                "checks": self.checks, "failures": self.failures,
                "evidence_dir": self.evidence_dir,
                "daemons": [d.record() for d in self.daemons]}

class Mysql:
    def __init__(self, binary, port):
        self.binary, self.port = binary, port
    def run(self, sql, timeout=10):
        argv = [self.binary, "--no-defaults", "--ssl-mode=DISABLED", "--protocol=TCP",
                "--batch", "--raw", "--skip-column-names", "--connect-timeout=3",
                "-h", HOST, "-P", str(self.port), "-u", ADMIN_USER,
                f"-p{ADMIN_PASS}", "-e", sql]
        return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout)
    def value(self, sql, timeout=10):
        cp = self.run(sql, timeout)
        if cp.returncode != 0:
            raise RuntimeError(f"mysql failed rc={cp.returncode}: {clip(cp.stderr)}")
        return cp.stdout.strip()

class Daemon:
    def __init__(self, host, plugin, mysql, run_dir, name, initial=True,
                 mysql_workers=False, no_start=False):
        self.host, self.plugin, self.mysql_binary = host, plugin, mysql
        self.datadir = os.path.join(run_dir, name)
        self.name, self.initial = name, initial
        self.mysql_workers, self.no_start = mysql_workers, no_start
        self.admin_port, self.worker_port = free_port(), free_port()
        self.config_path = os.path.join(self.datadir, "proxysql.cfg")
        self.log_path = os.path.join(self.datadir, "daemon.log")
        self.proc, self.argv = None, None
        self.admin = Mysql(mysql, self.admin_port)
    def write_config(self):
        os.makedirs(self.datadir, exist_ok=True)
        cfg = (f'datadir="{self.datadir}"\n'
               'admin_variables={admin_credentials="%s:%s";mysql_ifaces="%s:%d";'
               'pgsql_ifaces="";web_enabled=false;restapi_enabled=false;}\n'
               'mysql_variables={threads=1;interfaces="%s:%d";}\n'
               'pgsql_variables={threads=1;interfaces="";}\n') % (
            ADMIN_USER, ADMIN_PASS, HOST, self.admin_port, HOST, self.worker_port)
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(cfg)
    def build_argv(self):
        argv = [self.host, "-f", "-M", "-e"]
        if self.initial:
            argv.append("--initial")
        if self.no_start:
            argv.append("--no-start")
        argv += ["-c", self.config_path, "-D", self.datadir, "--no-version-check",
                 "--mysql-workers=" + ("true" if self.mysql_workers else "false"),
                 "--pgsql-workers=false", "--mysql-admin=true", "--pgsql-admin=false",
                 "--mysql-monitor=false", "--pgsql-monitor=false",
                 "--load-plugin", self.plugin]
        return argv
    def start(self):
        self.write_config()
        self.argv = self.build_argv()
        log = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen(self.argv, stdout=log, stderr=subprocess.STDOUT,
                                          start_new_session=True)
        finally:
            log.close()
        self.wait_admin()
    def start_expect_refusal(self, timeout=20):
        """Start without Admin success expectation and require bounded refusal.

        The caller must have set ``initial=False``.  No SQL is sent.  A daemon
        that stays alive is task-owned cleanup and the observation reports a
        timeout so the case cannot false-pass.
        """
        if self.initial:
            raise RuntimeError("expected-refusal start requires initial=False")
        self.write_config()
        self.argv = self.build_argv()
        started = time.monotonic()
        log_offset = (os.path.getsize(self.log_path)
                      if os.path.exists(self.log_path) else 0)
        log = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen(self.argv, stdout=log, stderr=subprocess.STDOUT,
                                          start_new_session=True)
        finally:
            log.close()
        timed_out = False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        else:
            timed_out = True
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        segment = b""
        try:
            with open(self.log_path, "rb") as handle:
                handle.seek(log_offset)
                segment = handle.read()
        except OSError:
            pass
        log_segment = segment.decode("utf-8", "replace")
        return {
            "argv": list(self.argv),
            "config": self.config_path,
            "log": self.log_path,
            "log_offset": log_offset,
            "log_segment": log_segment,
            "log_tail": clip(log_segment[-8000:]),
            "returncode": self.proc.poll(),
            "timed_out": timed_out,
            "duration_s": round(time.monotonic() - started, 3),
            "admin_port": self.admin_port,
            "worker_port": self.worker_port,
        }
    def wait_admin(self, timeout=15):
        deadline, last = time.monotonic() + timeout, ""
        while time.monotonic() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(f"daemon exited rc={self.proc.returncode}; log={self.log_path}")
            try:
                cp = self.admin.run("SELECT 1", timeout=3)
                if cp.returncode == 0 and cp.stdout.strip() == "1":
                    return
                last = cp.stderr
            except (OSError, subprocess.SubprocessError) as exc:
                last = str(exc)
            time.sleep(0.1)
        raise RuntimeError(f"admin not ready on {self.admin_port}: {clip(last)}; log={self.log_path}")
    def query(self, sql, timeout=10):
        return self.admin.run(sql, timeout)
    def value(self, sql, timeout=10):
        return self.admin.value(sql, timeout)
    def wait_echo(self, port, payload, timeout=8):
        deadline, last = time.monotonic() + timeout, ""
        while time.monotonic() < deadline:
            try:
                got = roundtrip(port, payload, timeout=2)
                if got == payload:
                    return
                last = f"echo mismatch got={clip(got)!r}"
            except (OSError, socket.timeout, RuntimeError) as exc:
                last = str(exc)
            time.sleep(0.05)
        raise RuntimeError(f"route not admitted on {port}: {clip(last)}")
    def wait_exit(self, timeout):
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self.proc.terminate()
            try:
                rc = self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                rc = self.proc.wait(timeout=5)
            raise TimeoutError(f"daemon missed {timeout}s exit deadline; cleanup rc={rc}") from exc
    def shutdown_slow(self, timeout=20):
        if not self.proc or self.proc.poll() is not None:
            return self.proc.returncode if self.proc else None
        try:
            command = self.admin.run("PROXYSQL SHUTDOWN SLOW", timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            self.proc.terminate()
            self.wait_exit(5)
            raise RuntimeError(f"slow shutdown command failed: {exc}") from exc
        # A successful shutdown can close the SQL connection before mysql
        # receives a reply. Other client errors do not prove shutdown ran.
        if command.returncode and not any(
                f"ERROR {code}" in command.stderr for code in (2006, 2013)):
            self.proc.terminate()
            self.wait_exit(5)
            raise RuntimeError(f"slow shutdown command rejected: {clip(command.stderr)}")
        return self.wait_exit(timeout)
    def stop_fast(self, timeout=10):
        if not self.proc or self.proc.poll() is not None:
            return self.proc.returncode if self.proc else None
        self.proc.terminate()
        return self.wait_exit(timeout)
    def close(self):
        if self.proc and self.proc.poll() is None:
            self.shutdown_slow()
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=5)
    def record(self):
        return {"name": self.name, "argv": self.argv, "config": self.config_path,
                "log": self.log_path, "admin_port": self.admin_port,
                "worker_port": self.worker_port,
                "returncode": self.proc.poll() if self.proc else None}

class EchoBackend:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.stopping = threading.Event()
        self.lock, self.conns, self.threads = threading.Lock(), set(), []
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()
    def _accept(self):
        while not self.stopping.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(0.5)
            with self.lock:
                self.conns.add(conn)
            t = threading.Thread(target=self._echo, args=(conn,), daemon=True)
            self.threads.append(t)
            t.start()
    def _echo(self, conn):
        try:
            while not self.stopping.is_set():
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    try:
                        conn.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            with self.lock:
                self.conns.discard(conn)
            try:
                conn.close()
            except OSError:
                pass
    def close(self):
        self.stopping.set()
        try:
            self.sock.close()
        except OSError:
            pass
        with self.lock:
            conns = list(self.conns)
        for conn in conns:
            for action in (lambda: conn.shutdown(socket.SHUT_RDWR), conn.close):
                try:
                    action()
                except OSError:
                    pass
        self.thread.join(timeout=2)
        for t in list(self.threads):
            t.join(timeout=1)

def recv_exact(sock, size):
    out = bytearray()
    while len(out) < size:
        chunk = sock.recv(size - len(out))
        if not chunk:
            raise RuntimeError(f"EOF after {len(out)}/{size} bytes")
        out.extend(chunk)
    return bytes(out)

def roundtrip(port, payload, timeout=5):
    with socket.create_connection((HOST, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        out = bytearray()
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return bytes(out)
            out.extend(chunk)

def rejected(port, timeout=2):
    try:
        with socket.create_connection((HOST, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"smoke-probe")
            data = sock.recv(64)
            # Any application byte proves forwarding, including a partial
            # TCP chunk. Silence alone does not establish rejection.
            return (not data, "closed without application data" if not data
                    else f"application data received={clip(data)!r}")
    except ConnectionError as exc:
        return True, f"connection refused/reset: {clip(exc)}"
    except OSError as exc:
        return False, f"rejection not established: {clip(exc)}"

def can_connect(port, timeout=1):
    try:
        sock = socket.create_connection((HOST, port), timeout=timeout)
        sock.close()
        return True
    except OSError:
        return False

def open_flow(port, payload, timeout=5):
    sock = socket.create_connection((HOST, port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(payload)
    if recv_exact(sock, len(payload)) != payload:
        sock.close()
        raise RuntimeError("initial echo mismatch")
    return sock

def wait_closed(sock, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            data = sock.recv(64)
        except socket.timeout:
            return False, "no EOF/reset before deadline"
        except OSError as exc:
            return True, f"connection closed: {clip(exc)}"
        if not data:
            return True, "EOF observed"
    return False, "no EOF/reset before deadline"

def exec_sqls(d, statements):
    for sql in statements:
        cp = d.query(sql)
        if cp.returncode != 0:
            raise RuntimeError(f"SQL failed: {sql}: {clip(cp.stderr)}")

def insert_listener(listener_id, port, hostgroup=1, comment="smoke"):
    return ("INSERT INTO tcp_listeners(listener_id,active,bind_address,bind_port,"
            "default_hostgroup,max_connections,connect_timeout_ms,idle_timeout_ms,"
            f"max_connect_attempts,comment) VALUES({listener_id},1,'{HOST}',{port},"
            f"{hostgroup},10000,2000,60000,3,{sql_lit(comment)})")

def set_listeners(d, ports, hostgroup=1):
    exec_sqls(d, ["DELETE FROM tcp_listeners"] +
              [insert_listener(i, p, hostgroup) for i, p in enumerate(ports, 1)])

def route_sql(backend_port, listener_port, comment="smoke", hostgroup=TCP_HOSTGROUP,
              source_hostgroup=SOURCE_HOSTGROUP, listener_id=1):
    """Four-table mapped route: source servers first, then mandatory mapping.

    The static tcp_servers table no longer exists.  The TCP hostgroup names the
    existing MySQL source hostgroup; that HGM owns endpoint selection/health.
    """
    c = sql_lit(comment)
    return ["DELETE FROM tcp_routing_rules", "DELETE FROM tcp_listeners",
            "DELETE FROM tcp_hostgroups", "DELETE FROM mysql_servers",
            "DELETE FROM mysql_replication_hostgroups",
            "INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,weight,"
            f"max_connections,comment) VALUES({source_hostgroup},'{HOST}',"
            f"{backend_port},'ONLINE',1,1000,{c})",
            "LOAD MYSQL SERVERS TO RUNTIME",
            "INSERT INTO tcp_hostgroups(hostgroup_id,source_protocol,source_hostgroup,"
            f"comment) VALUES({hostgroup},{sql_lit(SOURCE_PROTOCOL)},"
            f"{source_hostgroup},{c})",
            insert_listener(listener_id, listener_port, hostgroup, comment)]

def configure_route(d, backend_port, listener_port, comment="smoke"):
    exec_sqls(d, route_sql(backend_port, listener_port, comment))
    load(d, True)

def load(d, expect_ok):
    cp = d.query("LOAD TCP CONFIG TO RUNTIME", timeout=15)
    if expect_ok and cp.returncode != 0:
        raise RuntimeError(f"LOAD failed: {clip(cp.stderr)}")
    return cp

def generation(d):
    return int(d.value("SELECT generation FROM runtime_tcp_status"))

def metric_families(text):
    help_counts, type_counts, samples = {}, {}, {}
    for line in text.splitlines():
        parts = line.split()
        if line.startswith("# HELP ") and len(parts) >= 3 and parts[2].startswith("proxysql_tcp_"):
            help_counts[parts[2]] = help_counts.get(parts[2], 0) + 1
        elif line.startswith("# TYPE ") and len(parts) >= 3 and parts[2].startswith("proxysql_tcp_"):
            type_counts[parts[2]] = type_counts.get(parts[2], 0) + 1
        elif line.startswith("proxysql_tcp_") and "{" in line:
            name, rest = line.split("{", 1)
            samples.setdefault(name, []).append(rest.rsplit("}", 1)[0])
    return help_counts, type_counts, samples

def wait_metrics(d, timeout=5):
    """Wait for the sampler after configuring a listener/server/rule fixture."""
    deadline, text = time.monotonic() + timeout, ""
    while time.monotonic() < deadline:
        text = d.value("SHOW PROMETHEUS METRICS")
        if set(metric_families(text)[0]) == METRIC_FAMILIES:
            return text
        time.sleep(0.05)
    return text

def check_metrics(case, label, text):
    help_counts, type_counts, samples = metric_families(text)
    names = set(help_counts)
    case.check(f"{label}: expected families", names == METRIC_FAMILIES,
               f"missing={sorted(METRIC_FAMILIES - names)} extra={sorted(names - METRIC_FAMILIES)}")
    dups = [n for n, c in help_counts.items() if c != 1]
    dups += [n for n, c in type_counts.items() if c != 1]
    case.check(f"{label}: one HELP/TYPE per family", not dups, str(dups))
    label_dups = {n: len(v) - len(set(v)) for n, v in samples.items() if len(v) != len(set(v))}
    case.check(f"{label}: no duplicate sample labels", not label_dups, str(label_dups))
    return names

def case_basic(ctx):
    case = Case("basic", os.path.join(ctx.run_dir, "basic"))
    os.makedirs(case.evidence_dir, exist_ok=True)
    d = Daemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, "basic")
    case.daemons.append(d)
    backend = None
    try:
        d.start()
        cols = "id,worker_threads,max_connections,buffer_size,shutdown_timeout_ms,half_close_timeout_ms"
        case.check("tcp_settings defaults", d.value(f"SELECT {cols} FROM tcp_settings") == DEFAULT_SETTINGS,
                   d.value(f"SELECT {cols} FROM tcp_settings"))
        status = d.value("SELECT state,running,generation FROM runtime_tcp_status")
        case.check("runtime status running generation1", status == "running\t1\t1", status)
        for removed in ("tcp_servers", "tcp_hostgroup_mappings",
                        "runtime_tcp_servers", "runtime_tcp_hostgroup_mappings",
                        "stats_tcp_servers"):
            cp = d.query(f"SELECT count(*) FROM {removed}")
            case.check(f"removed schema absent: {removed}", cp.returncode != 0,
                       clip(cp.stderr))
        mapping = d.value("SELECT source_protocol,source_hostgroup FROM tcp_hostgroups")
        case.check("no implicit mapping before configuration", mapping == "", mapping)
        metrics = wait_metrics(d)
        case.check("metrics prefix proxysql_tcp_", "# HELP proxysql_tcp_" in metrics,
                   clip(metrics[:400]))
        backend = EchoBackend()
        port = free_port()
        configure_route(d, backend.port, port, "basic")
        payload = bytes(range(256)) * 129 + b"\x00\xffsmoke\x00"
        d.wait_echo(port, payload, timeout=10)
        case.check("binary roundtrip and EOF", True, f"{len(payload)} bytes over {port}")
        case.check("runtime generation advanced", generation(d) >= 2, str(generation(d)))
        row = d.value("SELECT listener_id,bind_port,default_hostgroup FROM runtime_tcp_listeners")
        case.check("runtime listener active", row == f"1\t{port}\t{TCP_HOSTGROUP}", row)
        case.check("four-table source namespace",
                   d.value("SELECT source_protocol,source_hostgroup FROM tcp_hostgroups "
                           f"WHERE hostgroup_id={TCP_HOSTGROUP}")
                   == f"{SOURCE_PROTOCOL}\t{SOURCE_HOSTGROUP}", "")
    finally:
        if backend:
            backend.close()
        d.close()
    return case

def source_runtime_value(d, column, port):
    return d.value(f"SELECT {column} FROM runtime_mysql_servers "
                   f"WHERE hostgroup_id={SOURCE_HOSTGROUP} AND hostname='{HOST}' "
                   f"AND port={port}")

def load_mysql(d, expect_ok=True):
    cp = d.query("LOAD MYSQL SERVERS TO RUNTIME", timeout=15)
    if expect_ok and cp.returncode != 0:
        raise RuntimeError(f"LOAD MYSQL SERVERS failed: {clip(cp.stderr)}")
    return cp

def case_reload(ctx):
    case = Case("reload", os.path.join(ctx.run_dir, "reload"))
    os.makedirs(case.evidence_dir, exist_ok=True)
    d = Daemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, "reload")
    case.daemons.append(d)
    backend, flow = None, None
    try:
        d.start()
        backend = EchoBackend()
        port = free_port()
        configure_route(d, backend.port, port, "reload")
        d.wait_echo(port, b"reload-initial\x00\xff")
        gen0 = generation(d)
        # A memory edit that was not loaded into the source HGM is invisible.
        cp = d.query(f"UPDATE mysql_servers SET port=1 "
                     f"WHERE hostgroup_id={SOURCE_HOSTGROUP} AND hostname='{HOST}'")
        case.must("memory source port edit succeeds", cp.returncode == 0, clip(cp.stderr))
        row = source_runtime_value(d, "port", backend.port)
        case.check("memory server edit alone leaves source runtime untouched",
                   row == str(backend.port), row)
        case.check("memory edit alone leaves TCP generation", generation(d) == gen0,
                   f"{gen0}->{generation(d)}")
        # Restore the editable source port before any status update addresses it.
        cp = d.query(f"UPDATE mysql_servers SET port={backend.port} "
                     f"WHERE hostgroup_id={SOURCE_HOSTGROUP} AND hostname='{HOST}'")
        case.must("memory source port restored", cp.returncode == 0, clip(cp.stderr))
        case.check("restored editable port matches runtime target",
                   d.value("SELECT port FROM mysql_servers "
                           f"WHERE hostgroup_id={SOURCE_HOSTGROUP} AND hostname='{HOST}'")
                   == str(backend.port), "")
        # Dangling TCP listener reference is the four-table load failure.
        cp = d.query("UPDATE tcp_listeners SET default_hostgroup=99 WHERE listener_id=1")
        case.must("dangling listener edit succeeds", cp.returncode == 0, clip(cp.stderr))
        bad = load(d, False)
        case.check("dangling listener reference LOAD fails", bad.returncode != 0,
                   clip(bad.stderr))
        case.check("failed LOAD preserves generation", generation(d) == gen0,
                   f"{gen0}->{generation(d)}")
        d.wait_echo(port, b"after-failed-load")
        case.check("failed LOAD preserves working route", True, "")
        cp = d.query(f"UPDATE tcp_listeners SET default_hostgroup={TCP_HOSTGROUP} "
                     "WHERE listener_id=1")
        case.must("listener reference restored", cp.returncode == 0, clip(cp.stderr))
        load(d, True)
        gen_native = generation(d)
        case.check("successful recovery LOAD advances generation", gen_native > gen0,
                   f"{gen0}->{gen_native}")
        flow = open_flow(port, b"established-before-soft")
        cp = d.query(f"UPDATE mysql_servers SET status='OFFLINE_SOFT' "
                     f"WHERE hostgroup_id={SOURCE_HOSTGROUP} AND port={backend.port}")
        case.must("soft status update targets restored source port",
                  cp.returncode == 0, clip(cp.stderr))
        case.check("soft status update changed the expected row",
                   d.value("SELECT status FROM mysql_servers "
                           f"WHERE hostgroup_id={SOURCE_HOSTGROUP} AND port={backend.port}")
                   == "OFFLINE_SOFT", "")
        load_mysql(d)
        case.check("soft offline applies without a TCP LOAD", generation(d) == gen_native,
                   f"{gen_native}->{generation(d)}")
        flow.sendall(b"still-alive")
        case.check("soft offline preserves established flow",
                   recv_exact(flow, len(b"still-alive")) == b"still-alive", "")
        ok, why = rejected(port)
        case.check("soft offline rejects new admission", ok, why)
        cp = d.query(f"UPDATE mysql_servers SET status='OFFLINE_HARD' "
                     f"WHERE hostgroup_id={SOURCE_HOSTGROUP} AND port={backend.port}")
        case.must("hard status update targets restored source port",
                  cp.returncode == 0, clip(cp.stderr))
        load_mysql(d)
        case.check("hard offline applies without a TCP LOAD",
                   generation(d) == gen_native, f"{gen_native}->{generation(d)}")
        ok, why = wait_closed(flow, timeout=6)
        case.check("hard offline closes established flow", ok, why)
        flow.close()
        flow = None
        ok, why = rejected(port)
        case.check("hard offline rejects new admission", ok, why)
        cp = d.query(f"UPDATE mysql_servers SET status='ONLINE' "
                     f"WHERE hostgroup_id={SOURCE_HOSTGROUP} AND port={backend.port}")
        case.must("ONLINE recovery update targets restored source port",
                  cp.returncode == 0, clip(cp.stderr))
        load_mysql(d)
        d.wait_echo(port, b"restored\x00route")
        case.check("restored ONLINE route forwards", True, "")
        case.check("native status recovery preserves current TCP generation",
                   generation(d) == gen_native, f"{gen_native}->{generation(d)}")
    finally:
        if flow:
            flow.close()
        if backend:
            backend.close()
        d.close()
    return case

def case_persistence(ctx):
    case = Case("persistence", os.path.join(ctx.run_dir, "persistence"))
    os.makedirs(case.evidence_dir, exist_ok=True)
    d = Daemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, "persistence")
    case.daemons.append(d)
    backend = None
    try:
        d.start()
        backend = EchoBackend()
        port = free_port()
        comment = "o'brien; \"quoted\";\tline1\nline2\\end"
        exec_sqls(d, route_sql(backend.port, port, comment))
        exec_sqls(d, ["INSERT INTO tcp_routing_rules(rule_id,active,listener_id,source_cidr,"
                      f"action,destination_hostgroup,comment) VALUES(1,1,1,NULL,'ROUTE',"
                      f"{TCP_HOSTGROUP},{sql_lit(comment)})"])
        load(d, True)
        d.wait_echo(port, b"persist\x00\x01\xfe" * 40)
        cp = d.query("SAVE TCP CONFIG TO DISK", timeout=15)
        case.must("SAVE TCP CONFIG TO DISK succeeds", cp.returncode == 0, clip(cp.stderr))
        cp = d.query("SAVE MYSQL SERVERS TO DISK", timeout=15)
        case.must("SAVE MYSQL SERVERS TO DISK succeeds", cp.returncode == 0, clip(cp.stderr))
        expected_hex = comment.encode().hex().upper()
        for table, where in (("tcp_hostgroups", f"hostgroup_id={TCP_HOSTGROUP}"),
                             ("tcp_listeners", "listener_id=1"),
                             ("tcp_routing_rules", "rule_id=1")):
            got = d.value(f"SELECT hex(comment) FROM {table} WHERE {where}")
            case.check(f"quoted comment {table}", got == expected_hex, f"{got} != {expected_hex}")
        exec_sqls(d, ["UPDATE tcp_settings SET worker_threads=3",
                      "UPDATE tcp_hostgroups SET source_hostgroup=99, comment='mutated' "
                      f"WHERE hostgroup_id={TCP_HOSTGROUP}",
                      "UPDATE tcp_listeners SET bind_port=1 WHERE listener_id=1",
                      "DELETE FROM tcp_routing_rules"])
        cp = d.query("LOAD TCP CONFIG FROM DISK", timeout=15)
        case.must("LOAD TCP CONFIG FROM DISK succeeds", cp.returncode == 0, clip(cp.stderr))
        cp = d.query("LOAD MYSQL SERVERS FROM DISK", timeout=15)
        case.must("LOAD MYSQL SERVERS FROM DISK succeeds", cp.returncode == 0,
                  clip(cp.stderr))
        load_mysql(d)
        rows = (d.value("SELECT worker_threads FROM tcp_settings"),
                d.value("SELECT source_protocol,source_hostgroup FROM tcp_hostgroups "
                        f"WHERE hostgroup_id={TCP_HOSTGROUP}"),
                d.value("SELECT bind_port FROM tcp_listeners WHERE listener_id=1"),
                d.value("SELECT count(*) FROM tcp_routing_rules"))
        case.check("all four tables restored from disk",
                   rows == ("2", f"{SOURCE_PROTOCOL}\t{SOURCE_HOSTGROUP}",
                            str(port), "1"), str(rows))
        case.check("mapping quoted comment restored",
                   d.value("SELECT hex(comment) FROM tcp_hostgroups "
                           f"WHERE hostgroup_id={TCP_HOSTGROUP}") == expected_hex, "")
        case.check("routing rule quoted comment restored",
                   d.value("SELECT hex(comment) FROM tcp_routing_rules WHERE rule_id=1")
                   == expected_hex, "")
        rc = d.shutdown_slow()
        case.check("slow shutdown before restart exits 0", rc == 0, str(rc))
        d.initial = False
        d.start()
        load_mysql(d)
        d.wait_echo(port, b"after-restart\x00")
        case.check("restart same datadir restores mapped route", True, "")
        row = d.value("SELECT bind_port FROM runtime_tcp_listeners WHERE listener_id=1")
        case.check("restart runtime listener restored", row == str(port), row)
    finally:
        if backend:
            backend.close()
        d.close()
    return case

def case_lifecycle(ctx):
    case = Case("lifecycle", os.path.join(ctx.run_dir, "lifecycle"))
    os.makedirs(case.evidence_dir, exist_ok=True)
    d = Daemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, "lifecycle")
    fast = Daemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, "sigterm")
    case.daemons.extend([d, fast])
    backend = None
    try:
        d.start()
        backend = EchoBackend()
        port = free_port()
        configure_route(d, backend.port, port, "lifecycle")
        d.query("INSERT INTO tcp_routing_rules(rule_id,active,listener_id,source_cidr,"
                "action,destination_hostgroup,comment) VALUES(1,1,1,NULL,'ROUTE',1,'lifecycle')")
        load(d, True)
        payload = b"lifecycle\x00route"
        d.wait_echo(port, payload)
        cp = d.query("SAVE TCP CONFIG TO DISK", timeout=15)
        case.must("lifecycle SAVE TO DISK succeeds", cp.returncode == 0, clip(cp.stderr))
        cp = d.query("SAVE MYSQL SERVERS TO DISK", timeout=15)
        case.must("lifecycle SAVE MYSQL SERVERS TO DISK succeeds",
                  cp.returncode == 0, clip(cp.stderr))
        case.check("lifecycle preparation slow shutdown exits 0", d.shutdown_slow() == 0, "")
        d.initial, d.no_start = False, True
        d.start()
        case.check("--no-start exposes tcp schema",
                   d.value("SELECT count(*) FROM tcp_settings") == "1", "")
        load_mysql(d)
        case.check("--no-start has no TCP listener", not can_connect(port), f"port {port} listening")
        cp = d.query("PROXYSQL START", timeout=15)
        case.must("PROXYSQL START succeeds", cp.returncode == 0, clip(cp.stderr))
        d.wait_echo(port, payload)
        case.check("START activates saved route", True, "")
        before = check_metrics(case, "after START", wait_metrics(d))
        cp = d.query("PROXYSQL STOP", timeout=10)
        case.check("PROXYSQL STOP accepted", cp.returncode in (0, 1), f"rc={cp.returncode}")
        d.wait_admin(timeout=20)
        case.check("STOP leaves no TCP listener", not can_connect(port), f"port {port} listening")
        cp = d.query("PROXYSQL START", timeout=15)
        case.must("second PROXYSQL START succeeds", cp.returncode == 0, clip(cp.stderr))
        d.wait_echo(port, b"after-stop-start")
        after = check_metrics(case, "after STOP/START", wait_metrics(d))
        case.check("metric families neither lost nor duplicated", before == after,
                   f"before={sorted(before)} after={sorted(after)}")
        case.check("lifecycle slow shutdown exits 0", d.shutdown_slow() == 0, "")
        fast.start()
        fast_port = free_port()
        configure_route(fast, backend.port, fast_port, "sigterm")
        fast.wait_echo(fast_port, b"fast-exit")
        fast_rc = fast.stop_fast()
        case.check("fast SIGTERM daemon exits 0", fast_rc == 0,
                   f"observed exit={fast_rc}")
        for sql in ("PROXYSQL SHUTDOWN", "PROXYSQL KILL"):
            name = "fast-sql-" + sql.split()[-1].lower()
            sql_daemon = Daemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, name)
            case.daemons.append(sql_daemon)
            try:
                sql_daemon.start()
                sql_port = free_port()
                configure_route(sql_daemon, backend.port, sql_port, name)
                exec_sqls(sql_daemon, [
                    "INSERT INTO tcp_routing_rules(rule_id,active,listener_id,source_cidr,"
                    "action,destination_hostgroup,comment) "
                    "VALUES(1,1,1,NULL,'ROUTE',1,'fast-exit')"])
                load(sql_daemon, True)
                sql_daemon.wait_echo(sql_port, b"fast-sql-exit")
                # Keep the sampler active before exit from the Admin thread.
                check_metrics(case, name, wait_metrics(sql_daemon))
                cp = sql_daemon.query(sql, timeout=5)
                case.must(sql + " accepted", cp.returncode == 0 or any(
                    f"ERROR {code}" in cp.stderr for code in (2006, 2013)), clip(cp.stderr))
                case.check(sql + " exits 0 within deadline",
                           sql_daemon.wait_exit(10) == 0, "")
            finally:
                sql_daemon.close()
    finally:
        if backend:
            backend.close()
        d.close()
        fast.close()
    return case

def case_collision(ctx):
    case = Case("collision", os.path.join(ctx.run_dir, "collision"))
    os.makedirs(case.evidence_dir, exist_ok=True)
    d = Daemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, "collision-disabled-worker")
    enabled = Daemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, "collision-enabled-worker",
                     mysql_workers=True)
    case.daemons.extend([d, enabled])
    backend, occupied = None, None
    try:
        d.start()
        backend = EchoBackend()
        port = free_port()
        configure_route(d, backend.port, port, "collision")
        d.wait_echo(port, b"active-route")
        gen0 = generation(d)
        set_listeners(d, [port, d.admin_port])
        bad = load(d, False)
        case.check("Admin listener port rejects candidate", bad.returncode != 0, clip(bad.stderr))
        case.check("Admin collision preserves generation", generation(d) == gen0,
                   f"{gen0}->{generation(d)}")
        d.wait_echo(port, b"active-after-admin-collision")
        case.check("Admin collision preserves active route", True, "")
        set_listeners(d, [port, d.worker_port])
        load(d, True)
        d.wait_echo(d.worker_port, b"disabled-worker-port-reuse")
        case.check("disabled native worker port is reusable", True, str(d.worker_port))
        occupied = socket.socket()
        occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        occupied.bind((HOST, 0))
        occupied.listen(4)
        occupied_port = occupied.getsockname()[1]
        gen0 = generation(d)
        set_listeners(d, [port, d.worker_port, occupied_port])
        bad = load(d, False)
        case.check("externally occupied port rejects candidate", bad.returncode != 0, clip(bad.stderr))
        case.check("external collision preserves generation", generation(d) == gen0,
                   f"{gen0}->{generation(d)}")
        d.wait_echo(port, b"active-after-external-collision")
        case.check("external collision preserves active route", True, "")
        occupied.close()
        occupied = None
        enabled.start()
        enabled_port = free_port()
        configure_route(enabled, backend.port, enabled_port, "collision-enabled")
        enabled.wait_echo(enabled_port, b"enabled-active")
        gen0 = generation(enabled)
        set_listeners(enabled, [enabled_port, enabled.worker_port])
        bad = load(enabled, False)
        case.check("enabled native worker port rejects candidate", bad.returncode != 0,
                   clip(bad.stderr))
        case.check("enabled worker collision preserves generation", generation(enabled) == gen0,
                   f"{gen0}->{generation(enabled)}")
        enabled.wait_echo(enabled_port, b"enabled-active-survives")
        case.check("enabled worker collision preserves route", True, "")
    finally:
        if occupied:
            occupied.close()
        if backend:
            backend.close()
        d.close()
        enabled.close()
    return case
CASES = {"basic": case_basic, "reload": case_reload, "persistence": case_persistence,
         "lifecycle": case_lifecycle, "collision": case_collision}

class Context:
    def __init__(self, args, run_dir):
        self.args, self.run_dir = args, run_dir
        self.host, self.plugin, self.mysql = args.proxysql, args.plugin_copy, args.mysql

def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--proxysql", required=True, help="absolute path to v4 host binary")
    p.add_argument("--plugin", required=True, help="absolute path to immutable plugin DSO")
    p.add_argument("--mysql", default=shutil.which("mysql") or "/usr/bin/mysql")
    p.add_argument("--case", action="append", default=[],
                   help="basic|reload|persistence|lifecycle|collision|all; repeat or comma list")
    p.add_argument("--output-json", default="")
    return p.parse_args(argv)

def selected_cases(raw):
    names = []
    for item in raw or ["all"]:
        names.extend(x.strip() for x in item.split(",") if x.strip())
    if "all" in names:
        return list(CASES)
    unknown = [n for n in names if n not in CASES]
    if unknown:
        raise SystemExit(f"unknown case(s): {', '.join(unknown)}")
    return names

def main(argv=None):
    args = parse_args(argv)
    args.proxysql = os.path.abspath(args.proxysql)
    args.plugin = os.path.abspath(args.plugin)
    args.mysql = os.path.abspath(args.mysql)
    for label, path in (("host", args.proxysql), ("plugin", args.plugin), ("mysql", args.mysql)):
        if not os.path.isfile(path):
            raise SystemExit(f"{label} not found: {path}")
    if not os.path.isabs(args.plugin):
        raise SystemExit("--plugin must be absolute")
    os.makedirs("/tmp/native-tcp-proxy", exist_ok=True)
    run_dir = os.path.join("/tmp/native-tcp-proxy", "daemon-smoke-" +
                           datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}")
    os.makedirs(run_dir, exist_ok=False)
    sha_before = sha256_file(args.plugin)
    args.plugin_copy = os.path.join(run_dir, "proxysql_tcp_proxy.snapshot.so")
    shutil.copyfile(args.plugin, args.plugin_copy)
    os.chmod(args.plugin_copy, 0o500)
    sha_copy, sha_after = sha256_file(args.plugin_copy), sha256_file(args.plugin)
    if not sha_before == sha_copy == sha_after:
        raise SystemExit(f"plugin changed while snapshotting: {sha_before}/{sha_copy}/{sha_after}")
    script = os.path.abspath(__file__)
    result = {"timestamp": datetime.now(timezone.utc).isoformat(), "script": script,
              "script_sha256": sha256_file(script), "host": args.proxysql,
              "host_sha256": sha256_file(args.proxysql), "plugin_source": args.plugin,
              "plugin_source_sha256": sha_before, "plugin_copy": args.plugin_copy,
              "plugin_copy_sha256": sha_copy, "argv": argv if argv is not None else sys.argv[1:],
              "run_dir": run_dir, "cases": {}, "failures": [], "skips": []}
    ctx, exit_code = Context(args, run_dir), 0
    for name in selected_cases(args.case):
        started = time.monotonic()
        try:
            item = CASES[name](ctx).result()
        except Exception as exc:
            item = {"name": name, "status": "FAIL", "checks": [],
                    "failures": [f"{type(exc).__name__}: {clip(exc)}", traceback.format_exc()],
                    "evidence_dir": os.path.join(run_dir, name), "daemons": []}
        item["duration_s"] = round(time.monotonic() - started, 3)
        result["cases"][name] = item
        if item["status"] != "PASS":
            exit_code = 1
            result["failures"].append({"case": name, "failures": item["failures"]})
        print(f"[{item['status']}] {name} ({item['duration_s']}s)", flush=True)
        for failure in item["failures"]:
            print(f"  {failure}", flush=True)
    result["exit_code"] = exit_code
    out_path = args.output_json or os.path.join(run_dir, "result.json")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"result: {out_path}", flush=True)
    return exit_code
if __name__ == "__main__":
    sys.exit(main())
