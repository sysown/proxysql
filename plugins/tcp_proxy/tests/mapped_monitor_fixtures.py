#!/usr/bin/env python3
"""Task-owned fixtures for mapped TCP hostgroup tests.

Contents:
  * ``MappedDaemon`` -- the admin-smoke daemon with an option to leave the real
    MySQL/PostgreSQL monitors enabled.
  * ``configure_mapped`` -- normal protocol servers + mandatory mapped
    tcp_hostgroups row + listener, loaded in the required order.
  * ``MysqlFixture`` -- a throw-away ``mysqld --initialize-insecure`` datadir on
    a loopback ephemeral port with a generated local fixture user.
  * ``PgWireFixture`` -- a controlled PostgreSQL wire endpoint for monitor role
    tests.  It is explicitly a simulated backend: only the small libpq
    startup/auth/empty-query/read_only subset plus raw byte echo is implemented.

Everything is loopback-only, task-owned and cleaned up with bounded waits.  No
production service, real credential or project source is touched.
"""

from __future__ import annotations

import os
import secrets
import select
import shutil
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

from daemon_admin_smoke import ADMIN_PASS, ADMIN_USER, HOST, Daemon, exec_sqls, free_port, sql_lit

PROTOCOLS = {
    "MYSQL": {
        "servers": "mysql_servers",
        "runtime": "runtime_mysql_servers",
        "stats": "stats_mysql_connection_pool",
        "load": "LOAD MYSQL SERVERS TO RUNTIME",
        "variables": "MYSQL",
    },
    "PGSQL": {
        "servers": "pgsql_servers",
        "runtime": "runtime_pgsql_servers",
        "stats": "stats_pgsql_connection_pool",
        "load": "LOAD PGSQL SERVERS TO RUNTIME",
        "variables": "PGSQL",
    },
}


class FixtureBlocked(RuntimeError):
    """A required fixture/environment condition is unavailable."""


def wait_until(predicate, timeout, description, interval=0.05):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
        except FixtureBlocked:
            raise
        except Exception as exc:  # noqa: BLE001 - caller owns the final error
            last = exc
            value = None
        if value:
            return value
        time.sleep(interval)
    raise FixtureBlocked(f"{description} not observed within {timeout}s (last={last})")


class MappedDaemon(Daemon):
    """Admin-smoke daemon that can start with real monitors enabled."""

    def __init__(self, *args, monitors=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.monitors = monitors

    def start(self):
        if not self.monitors:
            return super().start()
        os.makedirs(self.datadir, exist_ok=True)
        cfg = (
            f'datadir="{self.datadir}"\n'
            'admin_variables={admin_credentials="%s:%s";mysql_ifaces="%s:%d";'
            'pgsql_ifaces="";web_enabled=false;restapi_enabled=false;}\n'
            'mysql_variables={threads=1;interfaces="%s:%d";}\n'
            'pgsql_variables={threads=1;interfaces="";}\n'
        ) % (
            ADMIN_USER, ADMIN_PASS, HOST, self.admin_port, HOST, self.worker_port,
        )
        with open(self.config_path, "w", encoding="utf-8") as handle:
            handle.write(cfg)
        argv = [self.host, "-f", "-e"]
        if self.initial:
            argv.append("--initial")
        if self.no_start:
            argv.append("--no-start")
        argv += [
            "-c", self.config_path, "-D", self.datadir, "--no-version-check",
            "--mysql-workers=" + ("true" if self.mysql_workers else "false"),
            "--pgsql-workers=false", "--mysql-admin=true", "--pgsql-admin=false",
            "--mysql-monitor=true", "--pgsql-monitor=true",
            "--load-plugin", self.plugin,
        ]
        self.argv = argv
        log = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen(
                argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        finally:
            log.close()
        self.wait_admin()


FOUR_TABLE_SCHEMA = (
    "tcp_settings", "tcp_hostgroups", "tcp_listeners", "tcp_routing_rules")
RUNTIME_SCHEMA = (
    "runtime_tcp_settings", "runtime_tcp_hostgroups", "runtime_tcp_listeners",
    "runtime_tcp_routing_rules", "runtime_tcp_status")
REMOVED_SCHEMA = (
    "tcp_servers", "tcp_hostgroup_mappings", "runtime_tcp_servers",
    "runtime_tcp_hostgroup_mappings", "stats_tcp_servers",
    "stats_tcp_hostgroup_mappings")


def require_mapping_schema(d):
    """Require exactly the four-table mapped schema or raise BLOCKED.

    This validates observable production Admin SQL.  It never substitutes a
    successful check for a daemon lifecycle assertion.
    """
    for table in FOUR_TABLE_SCHEMA + RUNTIME_SCHEMA:
        cp = d.query(f"SELECT count(*) FROM {table}")
        if cp.returncode != 0:
            raise FixtureBlocked(
                f"four-table TCP schema unavailable ({table}): {cp.stderr.strip()[:300]}")
    for table in REMOVED_SCHEMA:
        cp = d.query(f"SELECT count(*) FROM {table}")
        if cp.returncode == 0:
            raise FixtureBlocked(
                f"unexpected TCP table is present: {table}; "
                "this is not the four-table artifact")
    return "tcp_hostgroups"


def validate_source_namespaces(d):
    """Return mapping rows and verify MYSQL/PGSQL namespace separation."""
    cp = d.query("SELECT hostgroup_id,source_protocol,source_hostgroup "
                 "FROM tcp_hostgroups ORDER BY hostgroup_id")
    if cp.returncode != 0:
        raise FixtureBlocked(
            f"tcp_hostgroups mapping query failed: {cp.stderr.strip()[:300]}")
    rows = []
    for line in cp.stdout.splitlines():
        if not line:
            continue
        hostgroup, protocol, source = line.split("\t")
        if protocol not in PROTOCOLS:
            raise FixtureBlocked(f"invalid source_protocol {protocol!r} in tcp_hostgroups")
        if int(source) < 0:
            raise FixtureBlocked(f"negative source_hostgroup {source} in tcp_hostgroups")
        rows.append({"hostgroup_id": int(hostgroup), "source_protocol": protocol,
                     "source_hostgroup": int(source)})
    return rows


def clear_tcp_config(d):
    require_mapping_schema(d)
    statements = [
        "DELETE FROM tcp_routing_rules",
        "DELETE FROM tcp_listeners",
        "DELETE FROM tcp_hostgroups",
    ]
    exec_sqls(d, statements)
    return statements


def configure_mapped(d, protocol, source_hostgroup, tcp_hostgroup, listener_port,
                     servers, mapping_comment="mapped smoke", listener_comment="mapped smoke",
                     listener_overrides=None):
    """Configure protocol servers first, then mapping/listener and LOAD TCP.

    ``servers`` items are dicts with hostname/port and optional status, weight,
    max_connections and comment.  The source protocol tables hold all backend
    rows; the mapped TCP hostgroup has no local server inventory.
    """
    meta = PROTOCOLS[protocol]
    listener = {
        "max_connections": 10000,
        "connect_timeout_ms": 2000,
        "idle_timeout_ms": 60000,
        "max_connect_attempts": 3,
    }
    listener.update(listener_overrides or {})
    statements = clear_tcp_config(d)
    delete_sql = f"DELETE FROM {meta['servers']}"
    exec_sqls(d, [delete_sql])
    statements.append(delete_sql)
    for index, server in enumerate(servers, 1):
        values = {
            "hostname": server.get("hostname", HOST),
            "port": server["port"],
            "status": server.get("status", "ONLINE"),
            "weight": server.get("weight", 1),
            "max_connections": server.get("max_connections", 1000),
            "comment": server.get("comment", f"mapped-{index}"),
        }
        insert_sql = (
            f"INSERT INTO {meta['servers']}(hostgroup_id,hostname,port,status,weight,"
            f"max_connections,comment) VALUES({source_hostgroup},'{values['hostname']}',"
            f"{values['port']},{sql_lit(values['status'])},{values['weight']},"
            f"{values['max_connections']},{sql_lit(values['comment'])})"
        )
        exec_sqls(d, [insert_sql])
        statements.append(insert_sql)
    exec_sqls(d, [meta["load"]])
    statements.append(meta["load"])
    tcp_sql = [
        "INSERT INTO tcp_hostgroups(hostgroup_id,source_protocol,source_hostgroup,"
        f"comment) VALUES({tcp_hostgroup},{sql_lit(protocol)},{source_hostgroup},"
        f"{sql_lit(mapping_comment)})",
        "INSERT INTO tcp_listeners(listener_id,active,bind_address,bind_port,"
        "default_hostgroup,max_connections,connect_timeout_ms,idle_timeout_ms,"
        "max_connect_attempts,comment) "
        f"VALUES(1,1,'{HOST}',{listener_port},{tcp_hostgroup},"
        f"{listener['max_connections']},{listener['connect_timeout_ms']},"
        f"{listener['idle_timeout_ms']},{listener['max_connect_attempts']},"
        f"{sql_lit(listener_comment)})",
    ]
    exec_sqls(d, tcp_sql)
    exec_sqls(d, ["LOAD TCP CONFIG TO RUNTIME"])
    statements.extend(tcp_sql + ["LOAD TCP CONFIG TO RUNTIME"])
    return {
        "protocol": protocol,
        "source_hostgroup": source_hostgroup,
        "tcp_hostgroup": tcp_hostgroup,
        "listener_port": listener_port,
        "servers": servers,
        "mapping_comment": mapping_comment,
        "sql": statements,
    }


def set_monitor_variables(d, protocol, username, password):
    prefix = "mysql" if protocol == "MYSQL" else "pgsql"
    values = {
        "monitor_enabled": "true",
        "monitor_username": sql_lit(username),
        "monitor_password": sql_lit(password),
        "monitor_connect_interval": "100",
        "monitor_connect_timeout": "500",
        "monitor_ping_interval": "100",
        "monitor_ping_timeout": "500",
        "monitor_read_only_interval": "100",
        "monitor_read_only_timeout": "500",
        "monitor_replication_lag_interval": "10000",
        "monitor_replication_lag_timeout": "1000",
    }
    for name, value in values.items():
        cp = d.query(f"SET {prefix}-{name}={value}")
        if cp.returncode != 0:
            raise FixtureBlocked(
                f"monitor variable {prefix}-{name} unavailable: {cp.stderr.strip()[:300]}")
    exec_sqls(d, [f"LOAD {prefix.upper()} VARIABLES TO RUNTIME"])


class MysqlFixture:
    """Fresh task-owned mysqld datadir plus a generated local fixture user."""

    def __init__(self, directory, client_binary):
        self.directory = Path(directory)
        self.client_binary = client_binary
        self.mysqld = shutil.which("mysqld")
        self.datadir = self.directory / "datadir"
        self.socket_path = self.directory / "mysqld.sock"
        self.pid_path = self.directory / "mysqld.pid"
        self.log_path = self.directory / "mysqld.log"
        self.port = 0
        self.username = "tcpfixture"
        self.password = secrets.token_hex(12)
        self.proc = None
        self.argv = []

    @classmethod
    def create(cls, directory, client_binary):
        fixture = cls(directory, client_binary)
        try:
            fixture.start()
        except BaseException:
            fixture.close()
            raise
        return fixture

    def _run(self, argv, timeout=30, check=True):
        cp = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout)
        if check and cp.returncode != 0:
            raise FixtureBlocked(
                f"command failed ({argv[0]} rc={cp.returncode}): "
                f"{cp.stderr.strip()[-600:]}")
        return cp

    def _root_sql(self, sql, timeout=20, check=True):
        return self._run([
            self.client_binary, "--no-defaults", "--protocol=SOCKET",
            f"--socket={self.socket_path}", "-uroot", "--batch", "--raw",
            "--skip-column-names", "-e", sql,
        ], timeout=timeout, check=check)

    def start(self):
        if not self.mysqld:
            raise FixtureBlocked("mysqld not found in PATH; real MySQL monitor fixture unavailable")
        if not self.client_binary or not os.path.isfile(self.client_binary):
            raise FixtureBlocked(f"mysql client not found: {self.client_binary}")
        self.directory.mkdir(parents=True, exist_ok=True)
        init = self._run([
            self.mysqld, "--no-defaults", "--initialize-insecure",
            f"--datadir={self.datadir}", f"--log-error={self.log_path}",
        ], timeout=120, check=False)
        if init.returncode != 0:
            raise FixtureBlocked(
                "mysqld --initialize-insecure failed (unsupported MariaDB or "
                f"permissions): {init.stderr.strip()[-600:]}")
        self.port = free_port()
        version = self._run([self.mysqld, "--version"], check=False).stdout.lower()
        argv = [
            self.mysqld, "--no-defaults", f"--datadir={self.datadir}",
            f"--port={self.port}", f"--bind-address={HOST}",
            f"--socket={self.socket_path}", f"--pid-file={self.pid_path}",
            f"--log-error={self.log_path}", "--skip-log-bin", "--skip-name-resolve",
            "--innodb-buffer-pool-size=32M", "--innodb-flush-log-at-trx-commit=2",
        ]
        if "mariadb" not in version:
            argv.append("--mysqlx=0")
        self.argv = argv
        log = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen(
                argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        finally:
            log.close()
        wait_until(self._ready, 40, f"mysqld fixture ready on {HOST}:{self.port}")
        self._create_user()

    def _ready(self):
        if self.proc and self.proc.poll() is not None:
            raise FixtureBlocked(
                f"mysqld exited rc={self.proc.returncode}; log={self.log_path}")
        try:
            cp = self._root_sql("SELECT 1", timeout=3)
        except FixtureBlocked:
            return False
        return cp.returncode == 0 and cp.stdout.strip() == "1"

    def _create_user(self):
        users = [f"'{self.username}'@'127.0.0.1'", f"'{self.username}'@'localhost'"]
        made = False
        # Prefer native password when the server still ships the plugin; fall
        # back to the server default for MySQL 8.4+/MariaDB variants.
        for auth in (" WITH mysql_native_password", ""):
            statements = []
            for user in users:
                statements.append(
                    f"CREATE USER IF NOT EXISTS {user} IDENTIFIED{auth} BY {sql_lit(self.password)}")
                statements.append(
                    f"GRANT ALL PRIVILEGES ON *.* TO {user} WITH GRANT OPTION")
            cp = self._root_sql("; ".join(statements) + "; FLUSH PRIVILEGES", check=False)
            if cp.returncode == 0:
                made = True
                break
        if not made:
            raise FixtureBlocked("could not create the task-owned MySQL fixture user")
        self.set_read_only(False)

    def sql(self, statement, timeout=20):
        argv = [
            self.client_binary, "--no-defaults", "--ssl-mode=DISABLED",
            "--get-server-public-key",
            "--protocol=TCP", "--batch", "--raw", "--skip-column-names",
            "--connect-timeout=3", "-h", HOST, "-P", str(self.port),
            "-u", self.username, f"-p{self.password}", "-e", statement,
        ]
        return self._run(argv, timeout=timeout)

    def set_read_only(self, enabled):
        value = "1" if enabled else "0"
        cp = self._root_sql(f"SET GLOBAL read_only={value}")
        if cp.returncode != 0:
            raise FixtureBlocked(f"SET GLOBAL read_only={value} failed: {cp.stderr.strip()}")
        return value

    def record(self):
        return {
            "kind": "real-mysql-fixture",
            "datadir": str(self.datadir),
            "port": self.port,
            "socket": str(self.socket_path),
            "log": str(self.log_path),
            "argv": self.argv,
            "username": self.username,
            "password": "<task-generated; not recorded>",
        }

    def close(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            try:
                self._root_sql("SHUTDOWN", timeout=10, check=False)
            except (FixtureBlocked, OSError, subprocess.SubprocessError):
                pass
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)


class PgWireFixture:
    """Controlled PostgreSQL wire endpoint (SIMULATED backend).

    Implements libpq Startup/AuthenticationOk, empty-query ping, a one-column
    ``pg_is_in_recovery()`` answer, a numeric answer for other queries, and raw
    byte echo for clients that do not start with a valid PostgreSQL startup
    frame.  It is a protocol fixture, never a real PostgreSQL server.
    """

    def __init__(self, host=HOST):
        self.host = host
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._recovery = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, 0))
        self._sock.listen(32)
        self._sock.settimeout(0.2)
        self.port = int(self._sock.getsockname()[1])
        self.accepted = 0
        self.pg_connections = 0
        self.raw_connections = 0
        self.bytes_echoed = 0
        self._conns: set[socket.socket] = set()
        self._threads: list[threading.Thread] = []
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        try:
            self._thread.start()
        except BaseException:
            self._sock.close()
            raise

    def set_recovery(self, enabled):
        with self._lock:
            self._recovery = bool(enabled)
        return 1 if enabled else 0

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(10.0)
            with self._lock:
                self.accepted += 1
                self._conns.add(conn)
                thread = threading.Thread(target=self._handle, args=(conn,), daemon=True)
                self._threads.append(thread)
            thread.start()

    @staticmethod
    def _recv_exact(conn, size):
        data = bytearray()
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise EOFError("peer closed")
            data.extend(chunk)
        return bytes(data)

    @staticmethod
    def _peek_header(conn, timeout=0.25):
        """Wait briefly for a complete 8-byte frame without consuming it."""
        deadline = time.monotonic() + timeout
        data = b""
        while True:
            data = conn.recv(8, socket.MSG_PEEK)
            if not data:
                return b""
            if len(data) >= 8:
                return data
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return data
            readable, _, _ = select.select([conn], [], [], remaining)
            if not readable:
                return data

    def _handle(self, conn):
        try:
            conn.settimeout(10.0)
            first = self._peek_header(conn)
            if len(first) >= 8:
                length, code = struct.unpack("!ii", first)
                if 8 <= length <= 10000 and code in (196608, 80877103, 80877104):
                    self._handle_pg(conn, length, code)
                    return
            self._handle_raw(conn, first)
        except (OSError, EOFError, ValueError):
            pass
        finally:
            with self._lock:
                self._conns.discard(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _handle_raw(self, conn, initial):
        with self._lock:
            self.raw_connections += 1
        if initial:
            consumed = self._recv_exact(conn, len(initial))
            conn.sendall(consumed)
            with self._lock:
                self.bytes_echoed += len(consumed)
        while not self._stop.is_set():
            data = conn.recv(65536)
            if not data:
                return
            conn.sendall(data)
            with self._lock:
                self.bytes_echoed += len(data)

    def _handle_pg(self, conn, length, code):
        with self._lock:
            self.pg_connections += 1
        self._recv_exact(conn, 8)  # length + protocol code peeked by _handle
        while code in (80877103, 80877104):
            conn.sendall(b"N")
            header = self._recv_exact(conn, 4)
            length = struct.unpack("!i", header)[0]
            code = struct.unpack("!i", self._recv_exact(conn, 4))[0]
        self._recv_exact(conn, max(0, length - 8))  # StartupMessage key/value tail
        conn.sendall(
            b"R" + struct.pack("!ii", 8, 0)
            + self._param_status("server_version", "15.0")
            + self._param_status("client_encoding", "UTF8")
            + b"K" + struct.pack("!iii", 12, 1234, 5678)
            + b"Z" + struct.pack("!i", 5) + b"I"
        )
        while not self._stop.is_set():
            msg_type = self._recv_exact(conn, 1)
            msg_len = struct.unpack("!i", self._recv_exact(conn, 4))[0]
            payload = self._recv_exact(conn, max(0, msg_len - 4))
            if msg_type == b"X":
                return
            if msg_type == b"Q":
                query = payload.rstrip(b"\x00").decode("utf-8", "replace")
                if not query.strip():
                    conn.sendall(b"I" + struct.pack("!i", 4))
                elif "pg_is_in_recovery" in query:
                    with self._lock:
                        value = b"t" if self._recovery else b"f"
                    conn.sendall(self._bool_row(value, "pg_is_in_recovery"))
                else:
                    conn.sendall(self._text_row(b"0"))
                conn.sendall(b"Z" + struct.pack("!i", 5) + b"I")
            elif msg_type == b"S":
                conn.sendall(b"Z" + struct.pack("!i", 5) + b"I")

    @staticmethod
    def _param_status(name, value):
        body = name.encode() + b"\x00" + value.encode() + b"\x00"
        return b"S" + struct.pack("!i", len(body) + 4) + body

    @staticmethod
    def _bool_row(value, name):
        row_desc_body = (
            struct.pack("!h", 1) + name.encode() + b"\x00"
            + struct.pack("!ihihih", 0, 0, 16, 1, -1, 0)
        )
        data_body = struct.pack("!h", 1) + struct.pack("!i", 1) + value
        command = b"SELECT 1\x00"
        return (
            b"T" + struct.pack("!i", len(row_desc_body) + 4) + row_desc_body
            + b"D" + struct.pack("!i", len(data_body) + 4) + data_body
            + b"C" + struct.pack("!i", len(command) + 4) + command
        )

    @staticmethod
    def _text_row(value):
        row_desc_body = (
            struct.pack("!h", 1) + b"?column?\x00"
            + struct.pack("!ihihih", 0, 0, 23, 4, -1, 0)
        )
        data_body = struct.pack("!h", 1) + struct.pack("!i", len(value)) + value
        command = b"SELECT 1\x00"
        return (
            b"T" + struct.pack("!i", len(row_desc_body) + 4) + row_desc_body
            + b"D" + struct.pack("!i", len(data_body) + 4) + data_body
            + b"C" + struct.pack("!i", len(command) + 4) + command
        )

    def record(self):
        return {
            "kind": "simulated-pgsql-wire-fixture",
            "label": "controlled PostgreSQL wire endpoint, not a real server",
            "port": self.port,
            "accepted": self.accepted,
            "pg_connections": self.pg_connections,
            "raw_connections": self.raw_connections,
            "bytes_echoed": self.bytes_echoed,
        }

    def close(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        with self._lock:
            conns = list(self._conns)
            self._conns.clear()
            threads = list(self._threads)
            accept_thread = self._thread
        for conn in conns:
            for action in (lambda: conn.shutdown(socket.SHUT_RDWR), conn.close):
                try:
                    action()
                except OSError:
                    pass
        deadline = time.monotonic() + 3.0
        if accept_thread is not None and accept_thread.is_alive():
            accept_thread.join(timeout=max(0.0, deadline - time.monotonic()))
        for thread in threads:
            if thread is not None and thread.is_alive():
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
