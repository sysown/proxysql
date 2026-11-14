#!/usr/bin/env python3
"""Native mapped-TCP versus permanent SQL fast-forward benchmark.

This runner owns only orchestration: task-owned MySQL/PostgreSQL fixtures,
fresh matching ProxySQL daemons, protocol/configuration evidence, process and
HGM accounting, and report generation.  All measured connections, SQL text,
result verification and timing live in fast_forward_bench_client.cpp.

Safety:
  * every process, datadir, port, config and log is task-owned below /tmp;
  * passwords exist only in mode-0600 config/defaults files, never argv;
  * no existing database, service, credentials or unrelated process is used;
  * no subprocess is left unbounded and cleanup targets only owned PIDs.

Subcommands:
  selfcheck   build/preflight, negative credential/payload/timeout and FF
              proof-refusal checks against real task-owned servers
  smoke       tiny (explicitly labelled) direct/native/FF smoke for MySQL and
              PostgreSQL; writes raw proof and JSON/Markdown under /tmp
  measure     full design workload; refused unless measurement-ready.json
              exists, so smoke review must happen first

The full measured command is documented in README.fast-forward.md and the
worker checkpoint.  Defaults are the approved design workload; --smoke-profile
and the smoke subcommand override only to tiny values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import queue
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

HOST = "127.0.0.1"
REPO_ROOT = Path(__file__).resolve().parents[3]
TESTS_DIR = Path(__file__).resolve().parent
DEFAULT_WORK_DIR = Path("/tmp/tcp-ff-benchmark")
DEFAULT_HOST = REPO_ROOT / "src/proxysql"
DEFAULT_PLUGIN = REPO_ROOT / "plugins/tcp_proxy/proxysql_tcp_proxy.so"
DEFAULT_CLIENT = DEFAULT_WORK_DIR / "fast_forward_bench_client"
DEFAULT_MYSQL = Path(shutil.which("mysql") or "/usr/bin/mysql")
DEFAULT_MYSQLD = Path(shutil.which("mysqld") or "/usr/sbin/mysqld")
DEFAULT_PG_BIN = Path("/usr/lib/postgresql/16/bin")
DEFAULT_DEPS = REPO_ROOT / "deps"

PROTOCOLS = {"mysql": "MYSQL", "pgsql": "PGSQL"}
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
SENSITIVE_VALUES: set[str] = set()

SQL_DELETE_TCP = [
    "DELETE FROM tcp_routing_rules",
    "DELETE FROM tcp_listeners",
    "DELETE FROM tcp_hostgroups",
]


class RunnerError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def host_info() -> dict:
    uname = platform.uname()
    cpu_model = ""
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    mem_total_kb = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                mem_total_kb = int(line.split()[1])
                break
    except (OSError, ValueError, IndexError):
        pass
    return {
        "node": uname.node,
        "system": uname.system,
        "release": uname.release,
        "machine": uname.machine,
        "processor": uname.processor,
        "cpu_model": cpu_model,
        "cpu_count": os.cpu_count(),
        "mem_total_kb": mem_total_kb,
        "uid": os.getuid(),
        "python": sys.version.splitlines()[0],
    }


def source_provenance() -> dict:
    refs = [REPO_ROOT / "src/main.cpp", REPO_ROOT / "include/ProxySQL_Plugin.h",
            TESTS_DIR / "../src/engine.cpp"]
    result = {}
    for path in refs:
        if path.is_file():
            result[str(path)] = {"sha256": sha256_file(path),
                                  "bytes": path.stat().st_size}
    return result


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clip(value: Any, limit: int = 1200) -> str:
    text = redact(str(value))
    return text if len(text) <= limit else text[:limit] + "...<clipped>"


def redact(value: Any) -> str:
    text = str(value)
    for secret in SENSITIVE_VALUES:
        if secret:
            text = text.replace(secret, "<redacted>")
    text = re.sub(r"(?i)(password\s*[=:]\s*)([^\s,;]+)", r"\1<redacted>", text)
    return text


def sql_lit(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def wait_port(port: int, timeout: float = 10.0, description: str = "port") -> None:
    deadline = time.monotonic() + timeout
    last: Optional[str] = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return
        except OSError as exc:
            last = str(exc)
            time.sleep(0.05)
    raise RunnerError(f"{description} {HOST}:{port} not ready: {last}")


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    finally:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def run_process(argv: list[str], *, timeout: float, input_text: Optional[str] = None,
                env: Optional[dict[str, str]] = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv, input=input_text, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout,
            env=env, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RunnerError(
            f"command timed out after {timeout}s: {Path(argv[0]).name}: {clip(exc)}"
        ) from exc


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def terminate_pid(pid: Optional[int], timeout: float = 5.0,
                  expected_text: Optional[str] = None) -> dict:
    """Terminate exactly one known task-owned PID; never a process group."""
    if not pid or not process_alive(pid):
        return {"pid": pid, "already_exited": True}
    if expected_text:
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(
                "utf-8", "replace")
        except OSError:
            cmdline = ""
        if expected_text not in cmdline:
            return {"pid": pid, "refused": True, "cmdline": clip(cmdline)}
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        return {"pid": pid, "signal_error": clip(exc)}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not process_alive(pid):
            return {"pid": pid, "terminated": True}
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if not process_alive(pid):
            return {"pid": pid, "killed": True}
        time.sleep(0.05)
    return {"pid": pid, "still_alive": True}


def proc_fd_count(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return -1


def proc_thread_count(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Threads:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return -1


def proc_rss_kb(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return -1


def proc_cpu_ticks(pid: int) -> Optional[int]:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    if ")" not in raw:
        return None
    fields = raw[raw.rfind(")") + 2:].split()
    try:
        return int(fields[11]) + int(fields[12])
    except (IndexError, ValueError):
        return None


def clock_ticks_per_second() -> int:
    try:
        return int(os.sysconf("SC_CLK_TCK"))
    except (ValueError, OSError):
        return 100


def snapshot_process(pid: Optional[int]) -> Optional[dict]:
    if not pid or not process_alive(pid):
        return None
    return {
        "pid": pid,
        "at_monotonic_ns": time.monotonic_ns(),
        "cpu_ticks": proc_cpu_ticks(pid),
        "rss_kb": proc_rss_kb(pid),
        "fds": proc_fd_count(pid),
        "threads": proc_thread_count(pid),
    }


def resource_delta(before: Optional[dict], after: Optional[dict]) -> Optional[dict]:
    if not before or not after:
        return None
    elapsed = max(0.0, (after["at_monotonic_ns"] - before["at_monotonic_ns"]) / 1e9)
    cpu_delta = None
    cpu_percent = None
    if before.get("cpu_ticks") is not None and after.get("cpu_ticks") is not None:
        cpu_delta = after["cpu_ticks"] - before["cpu_ticks"]
        if elapsed > 0:
            cpu_percent = (cpu_delta / clock_ticks_per_second()) / elapsed * 100.0
    return {
        "elapsed_s": round(elapsed, 6),
        "cpu_ticks_delta": cpu_delta,
        "cpu_percent": None if cpu_percent is None else round(cpu_percent, 3),
        "rss_kb_before": before.get("rss_kb"),
        "rss_kb_after": after.get("rss_kb"),
        "rss_kb_endpoint_max": max(before.get("rss_kb", -1), after.get("rss_kb", -1)),
        "fds_before": before.get("fds"),
        "fds_after": after.get("fds"),
        "fds_endpoint_max": max(before.get("fds", -1), after.get("fds", -1)),
        "threads_before": before.get("threads"),
        "threads_after": after.get("threads"),
        "threads_endpoint_max": max(before.get("threads", -1), after.get("threads", -1)),
    }


class ProcessSampler:
    def __init__(self, pid: int, interval: float = 0.05):
        self.pid = pid
        self.interval = interval
        self.samples: list[dict] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> "ProcessSampler":
        self._thread.start()
        return self

    def _loop(self) -> None:
        while not self._stop.is_set():
            sample = snapshot_process(self.pid)
            if sample:
                self.samples.append(sample)
            self._stop.wait(self.interval)

    def stop(self) -> dict:
        self._stop.set()
        self._thread.join(timeout=2)
        sample = snapshot_process(self.pid)
        if sample:
            self.samples.append(sample)
        if not self.samples:
            return {"pid": self.pid, "samples": 0}
        first, last = self.samples[0], self.samples[-1]
        base = resource_delta(first, last) or {}
        return {
            "pid": self.pid,
            "samples": len(self.samples),
            "elapsed_s": base.get("elapsed_s"),
            "cpu_percent": base.get("cpu_percent"),
            "rss_kb_peak": max(item.get("rss_kb", -1) for item in self.samples),
            "fds_peak": max(item.get("fds", -1) for item in self.samples),
            "threads_peak": max(item.get("threads", -1) for item in self.samples),
        }


def deterministic_payload(size: int) -> bytes:
    return bytes(ALPHABET[index % len(ALPHABET)] for index in range(size))


def fnv1a64(data: bytes) -> str:
    value = 1469598103934665603
    for byte in data:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}"


def percentile(values: list[float], fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def numeric(values: list[Any]) -> list[float]:
    result: list[float] = []
    for value in values:
        if value is None:
            continue
        try:
            result.append(float(value))
        except (TypeError, ValueError):
            pass
    return result


def summary(values: list[Any]) -> dict:
    values_f = numeric(values)
    if not values_f:
        return {"n": 0, "median": None, "min": None, "max": None}
    return {
        "n": len(values_f),
        "median": statistics.median(values_f),
        "min": min(values_f),
        "max": max(values_f),
    }


# ---------------------------------------------------------------------------
# Task-owned real database fixtures
# ---------------------------------------------------------------------------


class MysqlFixture:
    kind = "real-mysql"

    def __init__(self, directory: Path, mysql_binary: Path, mysqld_binary: Path):
        self.directory = directory
        self.mysql_binary = mysql_binary
        self.mysqld_binary = mysqld_binary
        self.datadir = directory / "datadir"
        self.socket_path = directory / "mysqld.sock"
        self.pid_path = directory / "mysqld.pid"
        self.log_path = directory / "mysqld.log"
        self.root_cnf = directory / "root.cnf"
        self.client_cnf = directory / "client.cnf"
        self.port = 0
        self.database = "ffbench"
        self.username = "ffbench"
        self.password = ""
        self.proc: Optional[subprocess.Popen] = None
        self.argv: list[str] = []
        self.auth_plugin = ""
        self.version = ""

    def _base(self, cnf: Path) -> list[str]:
        return [
            str(self.mysql_binary), f"--defaults-extra-file={cnf}",
            "--batch", "--raw", "--skip-column-names", "--connect-timeout=3",
        ]

    def _root_sql(self, statement: str, timeout: float = 10.0,
                  check: bool = True) -> subprocess.CompletedProcess:
        cp = run_process(self._base(self.root_cnf) + ["-e", statement], timeout=timeout)
        if check and cp.returncode != 0:
            raise RunnerError(f"mysqld root SQL failed: {clip(cp.stderr)}")
        return cp

    def _root_input(self, sql: str, timeout: float = 20.0) -> subprocess.CompletedProcess:
        cp = run_process(self._base(self.root_cnf), timeout=timeout, input_text=sql)
        if cp.returncode != 0:
            raise RunnerError(f"mysqld root SQL input failed: {clip(cp.stderr)}")
        return cp

    def start(self) -> "MysqlFixture":
        if not self.mysqld_binary.is_file():
            raise RunnerError(f"mysqld not found: {self.mysqld_binary}")
        if not self.mysql_binary.is_file():
            raise RunnerError(f"mysql client not found: {self.mysql_binary}")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.password = os.urandom(18).hex()
        SENSITIVE_VALUES.add(self.password)
        write_private(self.root_cnf, (
            "[client]\nuser=root\nprotocol=SOCKET\n"
            f"socket={self.socket_path}\n"
        ))
        version_cp = run_process([str(self.mysqld_binary), "--version"], timeout=10)
        self.version = (version_cp.stdout or version_cp.stderr).strip()
        init = run_process([
            str(self.mysqld_binary), "--no-defaults", "--initialize-insecure",
            f"--datadir={self.datadir}", f"--log-error={self.log_path}",
        ], timeout=180)
        if init.returncode != 0:
            raise RunnerError(f"mysqld --initialize-insecure failed: {clip(init.stderr)}")
        self.port = free_port()
        argv = [
            str(self.mysqld_binary), "--no-defaults", f"--datadir={self.datadir}",
            f"--port={self.port}", f"--bind-address={HOST}",
            f"--socket={self.socket_path}", f"--pid-file={self.pid_path}",
            f"--log-error={self.log_path}", "--skip-log-bin", "--skip-name-resolve",
            "--max-connections=500", "--max-allowed-packet=32M",
            "--innodb-buffer-pool-size=128M", "--innodb-flush-log-at-trx-commit=2",
            "--mysqlx=0",
        ]
        self.argv = argv
        log = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen(
                argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        finally:
            log.close()
        self._wait_ready()
        self._create_user_and_database()
        write_private(self.client_cnf, (
            "[client]\n"
            f"user={self.username}\npassword={self.password}\n"
            f"host={HOST}\nport={self.port}\nprotocol=TCP\nssl-mode=DISABLED\n"
            f"database={self.database}\n"
        ))
        return self

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 60
        last = ""
        while time.monotonic() < deadline:
            if self.proc and self.proc.poll() is not None:
                tail = ""
                try:
                    tail = self.log_path.read_text(errors="replace")[-3000:]
                except OSError:
                    pass
                raise RunnerError(
                    f"mysqld exited rc={self.proc.returncode}: {clip(tail)}")
            try:
                cp = self._root_sql("SELECT 1", timeout=3, check=False)
                if cp.returncode == 0 and cp.stdout.strip() == "1":
                    return
                last = cp.stderr
            except RunnerError as exc:
                last = str(exc)
            time.sleep(0.1)
        raise RunnerError(f"mysqld did not become ready: {clip(last)}")

    def _create_user_and_database(self) -> None:
        users = [f"'{self.username}'@'{HOST}'", f"'{self.username}'@'localhost'"]
        last_error = ""
        for auth in (" WITH mysql_native_password", ""):
            statements = [f"CREATE DATABASE IF NOT EXISTS {self.database}"]
            for user in users:
                statements.append(f"DROP USER IF EXISTS {user}")
            for user in users:
                statements.append(
                    f"CREATE USER {user} IDENTIFIED{auth} BY {sql_lit(self.password)}")
                statements.append(
                    f"GRANT ALL PRIVILEGES ON {self.database}.* TO {user}")
            statements.append("FLUSH PRIVILEGES")
            cp = run_process(self._base(self.root_cnf), timeout=30,
                             input_text=";\n".join(statements) + ";\n")
            if cp.returncode == 0:
                break
            last_error = cp.stderr
        else:
            raise RunnerError(f"MySQL fixture user creation failed: {clip(last_error)}")
        plugin = self._root_sql(
            "SELECT plugin FROM mysql.user WHERE user="
            f"{sql_lit(self.username)} LIMIT 1", timeout=10)
        self.auth_plugin = plugin.stdout.strip()

    def client_config(self, path: Path, port: int) -> Path:
        write_private(path, (
            "protocol=mysql\n"
            f"host={HOST}\nport={port}\nuser={self.username}\n"
            f"password={self.password}\ndatabase={self.database}\n"
        ))
        return path

    def record(self) -> dict:
        return {
            "kind": self.kind,
            "version": self.version,
            "auth_plugin": self.auth_plugin,
            "datadir": str(self.datadir),
            "port": self.port,
            "socket": str(self.socket_path),
            "log": str(self.log_path),
            "pid": self.proc.pid if self.proc else None,
            "argv": self.argv,
            "password": "<generated; not recorded>",
        }

    def stop(self) -> dict:
        cleanup: dict[str, Any] = {}
        if self.proc and self.proc.poll() is None:
            try:
                self._root_sql("SHUTDOWN", timeout=10, check=False)
            except Exception as exc:  # noqa: BLE001 - cleanup records the error
                cleanup["shutdown_command_error"] = clip(exc)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                cleanup["terminate"] = terminate_pid(self.proc.pid, expected_text=str(self.datadir))
        cleanup["returncode"] = self.proc.returncode if self.proc else None
        return cleanup


class PgFixture:
    kind = "real-postgresql"

    def __init__(self, directory: Path, pg_bin: Path):
        self.directory = directory
        self.pg_bin = pg_bin
        self.datadir = directory / "datadir"
        self.socket_dir = directory / "socket"
        self.log_path = directory / "postgres.log"
        self.port = 0
        self.database = "ffbench"
        self.username = "ffbench"
        self.password = ""
        self.postmaster_pid: Optional[int] = None
        self.version = ""
        self.password_is_md5 = False

    def _psql_local(self, sql: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
        argv = [
            str(self.pg_bin / "psql"), "-X", "-q", "-t", "-A",
            "-v", "ON_ERROR_STOP=1", "-h", str(self.socket_dir),
            "-p", str(self.port), "-U", "postgres", "-d", "postgres",
        ]
        cp = run_process(argv, timeout=timeout, input_text=sql)
        if cp.returncode != 0:
            raise RunnerError(f"psql local SQL failed: {clip(cp.stderr)}")
        return cp

    def start(self) -> "PgFixture":
        for name in ("initdb", "pg_ctl", "postgres", "psql"):
            if not (self.pg_bin / name).is_file():
                raise RunnerError(f"missing PostgreSQL tool: {self.pg_bin / name}")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.socket_dir.mkdir(parents=True, exist_ok=True)
        self.password = os.urandom(18).hex()
        SENSITIVE_VALUES.add(self.password)
        version_cp = run_process([str(self.pg_bin / "postgres"), "--version"], timeout=10)
        self.version = (version_cp.stdout or version_cp.stderr).strip()
        init = run_process([
            str(self.pg_bin / "initdb"), "-D", str(self.datadir), "--no-sync",
            "--encoding=UTF8", "--locale=C", "--auth-local=trust",
            "--auth-host=md5", "-U", "postgres",
        ], timeout=120)
        if init.returncode != 0:
            raise RunnerError(f"initdb failed: {clip(init.stderr)}")
        self.port = free_port()
        with open(self.datadir / "postgresql.conf", "a", encoding="utf-8") as handle:
            handle.write(
                "\n# tcp fast-forward benchmark fixture\n"
                f"listen_addresses = '{HOST}'\n"
                f"port = {self.port}\n"
                f"unix_socket_directories = '{self.socket_dir}'\n"
                "ssl = off\n"
                "password_encryption = 'md5'\n"
                "max_connections = 300\n"
                "fsync = off\n"
                "synchronous_commit = off\n"
                "full_page_writes = off\n"
            )
        argv = [
            str(self.pg_bin / "pg_ctl"), "-D", str(self.datadir),
            "-l", str(self.log_path), "-w", "-t", "60", "start",
        ]
        cp = run_process(argv, timeout=90)
        if cp.returncode != 0:
            raise RunnerError(f"pg_ctl start failed: {clip(cp.stderr)}")
        pid_file = self.datadir / "postmaster.pid"
        try:
            self.postmaster_pid = int(pid_file.read_text().splitlines()[0])
        except (OSError, ValueError, IndexError):
            self.postmaster_pid = None
        cp = self._psql_local(
            "SET password_encryption='md5';\n"
            f"CREATE ROLE {self.username} LOGIN PASSWORD {sql_lit(self.password)};\n"
            f"CREATE DATABASE {self.database} OWNER {self.username};\n"
        )
        del cp
        check = self._psql_local(
            "SELECT (rolpassword LIKE 'md5%')::text FROM pg_authid "
            f"WHERE rolname={sql_lit(self.username)};")
        self.password_is_md5 = check.stdout.strip() in ("t", "true")
        if not self.password_is_md5:
            raise RunnerError("PostgreSQL benchmark role is not MD5-encrypted")
        host_check = run_process([
            str(self.pg_bin / "psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-h", HOST, "-p", str(self.port), "-U", self.username,
            "-d", self.database, "-c", "SELECT 1",
        ], timeout=20, env={**os.environ, "PGPASSWORD": self.password})
        if host_check.returncode != 0:
            raise RunnerError(f"PostgreSQL host MD5 auth failed: {clip(host_check.stderr)}")
        return self

    def client_config(self, path: Path, port: int) -> Path:
        write_private(path, (
            "protocol=pgsql\n"
            f"host={HOST}\nport={port}\nuser={self.username}\n"
            f"password={self.password}\ndatabase={self.database}\n"
        ))
        return path

    def record(self) -> dict:
        return {
            "kind": self.kind,
            "version": self.version,
            "host_auth": "md5",
            "role_password_md5": self.password_is_md5,
            "datadir": str(self.datadir),
            "port": self.port,
            "socket_dir": str(self.socket_dir),
            "log": str(self.log_path),
            "pid": self.postmaster_pid,
            "password": "<generated; not recorded>",
        }

    def stop(self) -> dict:
        cleanup: dict[str, Any] = {}
        cp = run_process([
            str(self.pg_bin / "pg_ctl"), "-D", str(self.datadir),
            "-m", "fast", "-w", "-t", "30", "stop",
        ], timeout=45)
        cleanup["pg_ctl_returncode"] = cp.returncode
        if cp.returncode != 0:
            cleanup["pg_ctl_error"] = clip(cp.stderr)
            if self.postmaster_pid:
                cleanup["terminate"] = terminate_pid(
                    self.postmaster_pid, expected_text=str(self.datadir))
        return cleanup


# ---------------------------------------------------------------------------
# Admin and matching ProxySQL daemon
# ---------------------------------------------------------------------------


class Admin:
    def __init__(self, mysql_binary: Path, defaults_file: Path):
        self.mysql_binary = mysql_binary
        self.defaults_file = defaults_file

    def _base(self, vertical: bool = False) -> list[str]:
        argv = [
            str(self.mysql_binary), f"--defaults-extra-file={self.defaults_file}",
            "--batch", "--raw", "--skip-column-names", "--connect-timeout=3",
        ]
        if vertical:
            argv.append("--vertical")
        return argv

    def run(self, sql: str, timeout: float = 15.0,
            vertical: bool = False) -> subprocess.CompletedProcess:
        return run_process(self._base(vertical), timeout=timeout, input_text=sql)

    def value(self, sql: str, timeout: float = 15.0) -> str:
        cp = self.run(sql, timeout)
        if cp.returncode != 0:
            raise RunnerError(f"Admin query failed: {clip(cp.stderr)}")
        return cp.stdout.strip()

    def require(self, sql: str, timeout: float = 15.0) -> str:
        value = self.value(sql, timeout)
        if value == "":
            raise RunnerError("Admin query returned no row")
        return value


class ProxyDaemon:
    def __init__(self, host: Path, plugin: Path, protocol: str, mysql_binary: Path,
                 run_dir: Path, name: str):
        self.host = host
        self.plugin_source = plugin
        self.protocol = protocol
        self.mysql_binary = mysql_binary
        self.run_dir = run_dir / name
        self.datadir = self.run_dir / "datadir"
        self.config_path = self.run_dir / "proxysql.cfg"
        self.admin_cnf = self.run_dir / "admin.cnf"
        self.log_path = self.run_dir / "daemon.log"
        self.admin_port = free_port()
        self.sql_port = free_port()
        self.tcp_port = free_port()
        self.admin_password = os.urandom(18).hex()
        SENSITIVE_VALUES.add(self.admin_password)
        self.admin_user = "ffbench_admin"
        self.plugin_snapshot = self.run_dir / "proxysql_tcp_proxy.snapshot.so"
        self.proc: Optional[subprocess.Popen] = None
        self.argv: list[str] = []
        self.config_evidence: dict[str, Any] = {}
        self.source_hostgroup = 101 if protocol == "mysql" else 201
        self.tcp_hostgroup = 1 if protocol == "mysql" else 2
        self.admin: Optional[Admin] = None

    def start(self, fixture: MysqlFixture | PgFixture) -> "ProxyDaemon":
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.datadir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.plugin_source, self.plugin_snapshot)
        os.chmod(self.plugin_snapshot, 0o500)
        if sha256_file(self.plugin_snapshot) != sha256_file(self.plugin_source):
            raise RunnerError("plugin changed while creating run snapshot")
        mysql_workers = self.protocol == "mysql"
        if mysql_workers:
            mysql_cfg = (
                f'mysql_variables={{threads=2;interfaces="{HOST}:{self.sql_port}";'
                'have_ssl=false;}\n')
            pgsql_cfg = 'pgsql_variables={threads=1;interfaces="";}\n'
        else:
            mysql_cfg = 'mysql_variables={threads=1;interfaces="";}\n'
            pgsql_cfg = (
                f'pgsql_variables={{threads=2;interfaces="{HOST}:{self.sql_port}";'
                'have_ssl=false;}\n')
        cfg = (
            f'datadir="{self.datadir}"\n'
            'admin_variables={admin_credentials="%s:%s";mysql_ifaces="%s:%d";'
            'pgsql_ifaces="";web_enabled=false;restapi_enabled=false;}\n'
            '%s%s'
        ) % (self.admin_user, self.admin_password, HOST, self.admin_port,
             mysql_cfg, pgsql_cfg)
        write_private(self.config_path, cfg)
        write_private(self.admin_cnf, (
            "[client]\n"
            f"user={self.admin_user}\npassword={self.admin_password}\n"
            f"host={HOST}\nport={self.admin_port}\nprotocol=TCP\nssl-mode=DISABLED\n"
        ))
        self.admin = Admin(self.mysql_binary, self.admin_cnf)
        argv = [
            str(self.host), "-f", "-M", "-e", "--initial",
            "-c", str(self.config_path), "-D", str(self.datadir),
            "--no-version-check",
            "--mysql-workers=" + ("true" if mysql_workers else "false"),
            "--pgsql-workers=" + ("false" if mysql_workers else "true"),
            "--mysql-admin=true", "--pgsql-admin=false",
            "--mysql-monitor=false", "--pgsql-monitor=false",
            "--load-plugin", str(self.plugin_snapshot),
        ]
        self.argv = argv
        log = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen(
                argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        finally:
            log.close()
        self._wait_admin()
        self._configure(fixture)
        return self

    def _wait_admin(self) -> None:
        deadline = time.monotonic() + 30
        last = ""
        assert self.admin is not None
        while time.monotonic() < deadline:
            if self.proc and self.proc.poll() is not None:
                tail = ""
                try:
                    tail = self.log_path.read_text(errors="replace")[-5000:]
                except OSError:
                    pass
                raise RunnerError(
                    f"ProxySQL exited rc={self.proc.returncode}: {clip(tail)}")
            try:
                cp = self.admin.run("SELECT 1", timeout=3)
                if cp.returncode == 0 and cp.stdout.strip() == "1":
                    return
                last = cp.stderr
            except RunnerError as exc:
                last = str(exc)
            time.sleep(0.1)
        raise RunnerError(f"ProxySQL Admin not ready: {clip(last)}")

    def _configure(self, fixture: MysqlFixture | PgFixture) -> None:
        assert self.admin is not None
        proto = PROTOCOLS[self.protocol]
        server_table = "mysql_servers" if self.protocol == "mysql" else "pgsql_servers"
        user_table = "mysql_users" if self.protocol == "mysql" else "pgsql_users"
        runtime_user = "runtime_mysql_users" if self.protocol == "mysql" else "runtime_pgsql_users"
        runtime_server = "runtime_mysql_servers" if self.protocol == "mysql" else "runtime_pgsql_servers"
        load_servers = f"LOAD {proto} SERVERS TO RUNTIME"
        load_users = f"LOAD {proto} USERS TO RUNTIME"
        load_variables = f"LOAD {proto} VARIABLES TO RUNTIME"
        statements: list[str] = ["INSERT OR IGNORE INTO tcp_settings(id) VALUES(1)",
                                 "UPDATE tcp_settings SET worker_threads=2"]
        statements += SQL_DELETE_TCP
        statements += [f"DELETE FROM {server_table}",
                       f"DELETE FROM {user_table}"]
        statements += ["DELETE FROM mysql_query_rules", "DELETE FROM pgsql_query_rules"]
        statements.append(
            f"INSERT INTO {server_table}(hostgroup_id,hostname,port,status,weight,"
            "compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,"
            "comment) VALUES("
            f"{self.source_hostgroup},{sql_lit(HOST)},{fixture.port},'ONLINE',1,0,"
            f"1000,0,0,0,{sql_lit('tcp-fast-forward-benchmark')})")
        if self.protocol == "mysql":
            statements.append(
                "INSERT INTO mysql_users(username,password,active,use_ssl,"
                "default_hostgroup,default_schema,schema_locked,transaction_persistent,"
                "fast_forward,backend,frontend,max_connections,attributes,comment) VALUES("
                f"{sql_lit(fixture.username)},{sql_lit(fixture.password)},1,0,"
                f"{self.source_hostgroup},{sql_lit(fixture.database)},0,1,1,1,1,1000,'',"
                f"{sql_lit('tcp-fast-forward-benchmark')})")
        else:
            statements.append(
                "INSERT INTO pgsql_users(username,password,active,use_ssl,"
                "default_hostgroup,transaction_persistent,fast_forward,backend,frontend,"
                "max_connections,attributes,comment) VALUES("
                f"{sql_lit(fixture.username)},{sql_lit(fixture.password)},1,0,"
                f"{self.source_hostgroup},1,1,1,1,1000,'',"
                f"{sql_lit('tcp-fast-forward-benchmark')})")
        statements += [load_servers, load_users]
        if self.protocol == "mysql":
            statements += [
                "SET mysql-multiplexing=false",
                "SET mysql-query_cache_size_MB=0",
                "SET mysql-have_ssl=false",
                "SET mysql-show_processlist_extended=2",
            ]
        else:
            statements += [
                "SET pgsql-query_cache_size_MB=0",
                "SET pgsql-have_ssl=false",
                "SET pgsql-show_processlist_extended=2",
                "SET pgsql-authentication_method=2",
            ]
        statements.append(load_variables)
        statements += [
            "INSERT INTO tcp_hostgroups(hostgroup_id,source_protocol,source_hostgroup,"
            f"comment) VALUES({self.tcp_hostgroup},{sql_lit(proto)},"
            f"{self.source_hostgroup},{sql_lit('tcp-fast-forward-benchmark')})",
            "INSERT INTO tcp_listeners(listener_id,active,bind_address,bind_port,"
            "default_hostgroup,max_connections,connect_timeout_ms,idle_timeout_ms,"
            "max_connect_attempts,comment) VALUES("
            f"1,1,{sql_lit(HOST)},{self.tcp_port},{self.tcp_hostgroup},20000,2000,"
            f"60000,3,{sql_lit('tcp-fast-forward-benchmark')})",
            "LOAD TCP CONFIG TO RUNTIME",
        ]
        cp = self.admin.run(";\n".join(statements) + ";\n", timeout=40)
        if cp.returncode != 0:
            raise RunnerError(f"ProxySQL benchmark configuration failed: {clip(cp.stderr)}")
        self._wait_listeners()
        self._capture_config(proto, runtime_user, runtime_server)

    def _wait_listeners(self) -> None:
        wait_port(self.sql_port, timeout=15, description="SQL listener")
        wait_port(self.tcp_port, timeout=15, description="mapped TCP listener")

    def _capture_config(self, proto: str, runtime_user: str,
                        runtime_server: str) -> None:
        assert self.admin is not None
        user_columns = (
            "username,active,use_ssl,default_hostgroup,transaction_persistent,"
            "fast_forward,backend,frontend,max_connections"
        )
        server_columns = (
            "hostgroup_id,hostname,port,status,weight,compression,max_connections,"
            "use_ssl,max_latency_ms"
        )
        threading_value = self.admin.require(
            f"SELECT variable_value FROM runtime_global_variables "
            f"WHERE variable_name={sql_lit(proto.lower() + '-threads')}")
        extended_value = self.admin.require(
            "SELECT variable_value FROM runtime_global_variables "
            f"WHERE variable_name={sql_lit(proto.lower() + '-show_processlist_extended')}")
        auth_method = None
        if self.protocol == "pgsql":
            auth_method = self.admin.require(
                "SELECT variable_value FROM runtime_global_variables "
                "WHERE variable_name='pgsql-authentication_method'")
        user_row = self.admin.require(
            f"SELECT {user_columns} FROM {runtime_user} "
            f"WHERE username={sql_lit('ffbench')} AND frontend=1")
        server_row = self.admin.require(
            f"SELECT {server_columns} FROM {runtime_server} "
            f"WHERE hostgroup_id={self.source_hostgroup}")
        tcp_settings = self.admin.require(
            "SELECT worker_threads,max_connections,buffer_size,shutdown_timeout_ms,"
            "half_close_timeout_ms FROM runtime_tcp_settings")
        tcp_mapping = self.admin.require(
            "SELECT hostgroup_id,source_protocol,source_hostgroup FROM "
            f"runtime_tcp_hostgroups WHERE hostgroup_id={self.tcp_hostgroup}")
        tcp_listener = self.admin.require(
            "SELECT active,bind_address,default_hostgroup,max_connections,"
            "connect_timeout_ms,idle_timeout_ms,max_connect_attempts "
            f"FROM runtime_tcp_listeners WHERE listener_id=1")
        tcp_status = self.admin.require(
            "SELECT state,running,last_error FROM runtime_tcp_status WHERE id=1")
        query_rules = self.admin.require(
            "SELECT (SELECT count(*) FROM mysql_query_rules)+(SELECT count(*) FROM pgsql_query_rules)")
        user_parts = user_row.split("\t")
        if len(user_parts) < 9:
            raise RunnerError(f"unexpected runtime user row: {clip(user_row)}")
        if user_parts[1] != "1" or user_parts[3] != str(self.source_hostgroup):
            raise RunnerError(f"runtime user is not active in the source hostgroup: {clip(user_row)}")
        if user_parts[5] != "1":
            raise RunnerError(f"runtime user fast_forward is not 1: {clip(user_row)}")
        if user_parts[7] != "1":
            raise RunnerError(f"runtime user frontend is not 1: {clip(user_row)}")
        server_parts = server_row.split("\t")
        if len(server_parts) < 9:
            raise RunnerError(f"unexpected runtime server row: {clip(server_row)}")
        if server_parts[7] != "0":
            raise RunnerError(f"source use_ssl is not 0: {clip(server_row)}")
        if threading_value != "2":
            raise RunnerError(f"SQL worker threads expected 2, got {threading_value}")
        if tcp_settings.split("\t")[0] != "2":
            raise RunnerError(f"TCP worker threads expected 2, got {clip(tcp_settings)}")
        status_parts = tcp_status.split("\t")
        if len(status_parts) < 2 or status_parts[1] != "1":
            raise RunnerError(f"TCP engine not running: {clip(tcp_status)}")
        self.config_evidence = {
            "protocol": proto,
            "worker_argv": {
                "mysql_workers": "--mysql-workers=true" in self.argv,
                "pgsql_workers": "--pgsql-workers=true" in self.argv,
            },
            "sql_threads": threading_value,
            "show_processlist_extended": extended_value,
            "pgsql_authentication_method": auth_method,
            "source_hostgroup": self.source_hostgroup,
            "tcp_hostgroup": self.tcp_hostgroup,
            "user_row": user_row,
            "server_row": server_row,
            "tcp_settings": tcp_settings,
            "tcp_mapping": tcp_mapping,
            "tcp_listener_without_port": tcp_listener,
            "tcp_status": tcp_status,
            "query_rule_count": query_rules,
            "sql_listener_port": self.sql_port,
            "tcp_listener_port": self.tcp_port,
            "runtime_server_use_ssl_zero": server_parts[7] == "0",
            "runtime_user_fast_forward_one": user_parts[5] == "1",
        }

    def equivalence_core(self) -> dict:
        evidence = dict(self.config_evidence)
        for key in ("sql_listener_port", "tcp_listener_port"):
            evidence.pop(key, None)
        return evidence

    def value(self, sql: str, timeout: float = 15.0) -> str:
        assert self.admin is not None
        return self.admin.value(sql, timeout)

    def query(self, sql: str, timeout: float = 15.0,
              vertical: bool = False) -> subprocess.CompletedProcess:
        assert self.admin is not None
        return self.admin.run(sql, timeout, vertical=vertical)

    def hgm_stats(self, protocol: str, hostgroup: int, fixture_port: int) -> dict:
        table = ("stats_mysql_connection_pool" if protocol == "mysql"
                 else "stats_pgsql_connection_pool")
        text = self.value(
            "SELECT COALESCE(SUM(ConnUsed),0),COALESCE(SUM(ConnFree),0),"
            "COALESCE(SUM(ConnOK),0),COALESCE(SUM(ConnERR),0),"
            "COALESCE(MAX(MaxConnUsed),0),COALESCE(SUM(Bytes_data_sent),0),"
            "COALESCE(SUM(Bytes_data_recv),0) "
            f"FROM {table} WHERE hostgroup={hostgroup} "
            f"AND srv_host={sql_lit(HOST)} AND srv_port={fixture_port}")
        parts = text.split("\t")
        if len(parts) != 7:
            raise RunnerError(f"unexpected HGM aggregate: {clip(text)}")
        names = ("ConnUsed", "ConnFree", "ConnOK", "ConnERR", "MaxConnUsed",
                 "Bytes_data_sent", "Bytes_data_recv")
        return {name: int(value) for name, value in zip(names, parts)}

    def wait_hgm_idle(self, protocol: str, hostgroup: int, fixture_port: int,
                      timeout: float = 10.0) -> dict:
        deadline = time.monotonic() + timeout
        last: Optional[dict] = None
        while time.monotonic() < deadline:
            last = self.hgm_stats(protocol, hostgroup, fixture_port)
            if last["ConnUsed"] == 0 and last["ConnFree"] == 0:
                return last
            time.sleep(0.05)
        raise RunnerError(f"HGM did not drain to ConnUsed=0 ConnFree=0: {last}")

    def tcp_stats(self) -> dict:
        text = self.value(
            "SELECT active_connections,accepted_total,rejected_total,connect_errors,"
            "bytes_client_to_server,bytes_server_to_client "
            "FROM stats_tcp_listeners WHERE listener_id=1")
        parts = text.split("\t")
        if len(parts) != 6:
            raise RunnerError(f"unexpected TCP listener stats: {clip(text)}")
        names = ("active_connections", "accepted_total", "rejected_total",
                 "connect_errors", "bytes_client_to_server", "bytes_server_to_client")
        return {name: int(value) for name, value in zip(names, parts)}

    def record(self) -> dict:
        return {
            "name": self.run_dir.name,
            "argv": self.argv,
            "config": str(self.config_path),
            "log": str(self.log_path),
            "datadir": str(self.datadir),
            "admin_port": self.admin_port,
            "sql_port": self.sql_port,
            "tcp_port": self.tcp_port,
            "pid": self.proc.pid if self.proc else None,
            "returncode": self.proc.poll() if self.proc else None,
            "plugin_snapshot": str(self.plugin_snapshot),
            "plugin_snapshot_sha256": sha256_file(self.plugin_snapshot)
            if self.plugin_snapshot.exists() else None,
        }

    def close(self) -> dict:
        cleanup: dict[str, Any] = {}
        if self.proc and self.proc.poll() is None:
            try:
                assert self.admin is not None
                cp = self.admin.run("PROXYSQL SHUTDOWN SLOW", timeout=8)
                cleanup["shutdown_returncode"] = cp.returncode
                if cp.returncode != 0:
                    cleanup["shutdown_stderr"] = clip(cp.stderr)
            except Exception as exc:  # noqa: BLE001 - cleanup records error
                cleanup["shutdown_error"] = clip(exc)
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                cleanup["terminate"] = terminate_pid(
                    self.proc.pid, expected_text=str(self.plugin_snapshot))
        cleanup["returncode"] = self.proc.returncode if self.proc else None
        return cleanup


# ---------------------------------------------------------------------------
# Native client wrapper
# ---------------------------------------------------------------------------


class ClientInvocation:
    def __init__(self, returncode: int, stdout: str, stderr: str, resources: dict,
                 duration_s: float, command: list[str], config_path: Path):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.resources = resources
        self.duration_s = duration_s
        self.command = command
        self.config_path = config_path
        self.json = parse_json_output(stdout)

    def record(self) -> dict:
        return {
            "returncode": self.returncode,
            "duration_s": round(self.duration_s, 6),
            "command": self.command,
            "config_path": str(self.config_path),
            "stdout_tail": clip(self.stdout[-4000:]),
            "stderr_tail": clip(self.stderr[-4000:]),
            "resources": self.resources,
            "json": self.json,
        }


def parse_json_output(stdout: str) -> Optional[dict]:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            continue
    return None


class BenchClient:
    def __init__(self, binary: Path):
        self.binary = binary
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RunnerError(f"native benchmark client missing/executable: {binary}")

    def invoke(self, fixture: MysqlFixture | PgFixture, port: int, mode: str,
               config_path: Path, *, payload_bytes: int = 64, warmups: int = 0,
               samples: int = 0, clients: int = 1, duration_seconds: float = 0.0,
               timeout_ms: int = 2000, corrupt_expectation: bool = False,
               negative_timeout: bool = False, timeout: float = 90.0,
               prepare_config: bool = True,
               inject_late_error_ms: int = 0,
               negative_timeout_completes: bool = False,
               workload: str = "literal") -> ClientInvocation:
        if prepare_config:
            fixture.client_config(config_path, port)
        command = [
            str(self.binary), "--config", str(config_path), "--mode", mode,
            "--payload-bytes", str(payload_bytes), "--warmups", str(warmups),
            "--samples", str(samples), "--clients", str(clients),
            "--duration-seconds", str(duration_seconds),
            "--timeout-ms", str(timeout_ms), "--workload", workload,
        ]
        if corrupt_expectation:
            command.append("--corrupt-expectation")
        if negative_timeout:
            command.append("--negative-timeout-test")
        if inject_late_error_ms:
            command.extend(["--inject-late-error-ms", str(inject_late_error_ms)])
        if negative_timeout_completes:
            command.append("--negative-timeout-completes")
        started = time.monotonic()
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        sampler = ProcessSampler(proc.pid).start()
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=5)
            sampler.stop()
            raise RunnerError(
                f"native client {mode} exceeded {timeout}s: {clip(stderr[-2000:])}")
        resources = sampler.stop()
        return ClientInvocation(proc.returncode, stdout, stderr, resources,
                                time.monotonic() - started, command, config_path)

    def verify(self, fixture: MysqlFixture | PgFixture, port: int,
               config_path: Path, *, payload_bytes: int = 64,
               workload: str = "literal") -> dict:
        invocation = self.invoke(fixture, port, "verify", config_path,
                                 payload_bytes=payload_bytes, workload=workload)
        require_client_ok(invocation, "verify")
        check_tls_and_compression(fixture, invocation.json)
        return invocation.json

    def phase(self, fixture: MysqlFixture | PgFixture, port: int, mode: str,
              config_path: Path, **kwargs: Any) -> dict:
        invocation = self.invoke(fixture, port, mode, config_path, **kwargs)
        require_client_ok(invocation, mode)
        result = invocation.json or {}
        check_tls_and_compression(fixture, result)
        return {"result": result, "invocation": invocation.record()}


def require_client_ok(invocation: ClientInvocation, label: str) -> None:
    data = invocation.json or {}
    if invocation.returncode != 0 or not data.get("ok"):
        detail = data.get("error") or invocation.stderr or invocation.stdout
        raise RunnerError(f"native client {label} failed rc={invocation.returncode}: "
                          f"{clip(detail)}")
    if data.get("error"):
        raise RunnerError(f"native client {label} reported error: {clip(data['error'])}")
    for thread in data.get("threads", []):
        if thread.get("error"):
            raise RunnerError(f"native client {label} thread error: {clip(thread['error'])}")


def check_tls_and_compression(fixture: MysqlFixture | PgFixture, data: dict) -> None:
    values = [data]
    values.extend(data.get("threads", []))
    for item in values:
        if item.get("tls_used"):
            raise RunnerError(f"TLS unexpectedly used for {fixture.kind}: {clip(item)}")
        if item.get("ssl_cipher"):
            raise RunnerError(f"non-empty TLS cipher for {fixture.kind}: {clip(item)}")
        if isinstance(fixture, MysqlFixture) and item.get("compression"):
            raise RunnerError(f"MySQL compression unexpectedly negotiated: {clip(item)}")
        if item.get("tcp_nodelay") != 1:
            raise RunnerError(f"TCP_NODELAY observation is not 1: {clip(item)}")
        if item.get("gssenc_in_use"):
            raise RunnerError(f"GSS encryption unexpectedly used: {clip(item)}")
    if isinstance(fixture, PgFixture) and data.get("ssl_in_use"):
        raise RunnerError("PostgreSQL PQsslInUse unexpectedly true")


class HoldSession:
    def __init__(self, binary: Path, config_path: Path,
                 workload: str = "literal", payload_bytes: int = 64):
        self.binary = binary
        self.config_path = config_path
        self.command = [
            str(binary), "--config", str(config_path), "--mode", "hold",
            "--payload-bytes", str(payload_bytes), "--hold-seconds", "30",
            "--timeout-ms", "2000", "--workload", workload,
        ]
        self.proc = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        self.sampler = ProcessSampler(self.proc.pid).start()
        self.lines: queue.Queue[str] = queue.Queue()
        self.stderr_lines: list[str] = []
        self._stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put("")

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self.stderr_lines.append(line)

    def wait_ready(self, timeout: float = 15.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.01, deadline - time.monotonic())
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty:
                break
            if not line:
                break
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if data.get("ready"):
                return data
        stderr = "".join(self.stderr_lines)
        raise RunnerError(
            f"hold client did not become ready rc={self.proc.poll()}: {clip(stderr)}")

    def close(self) -> dict:
        if self.proc.stdin and not self.proc.stdin.closed:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            terminate_pid(self.proc.pid, expected_text=str(self.binary))
        resources = self.sampler.stop()
        self._stdout_thread.join(timeout=2)
        self._stderr_thread.join(timeout=2)
        return {
            "returncode": self.proc.returncode,
            "pid": self.proc.pid,
            "resources": resources,
            "stderr_tail": clip("".join(self.stderr_lines)[-2000:]),
        }


# ---------------------------------------------------------------------------
# Fast-forward proof
# ---------------------------------------------------------------------------


def _field(proof: dict, name: str) -> Any:
    fields = proof.get("processlist_fields")
    return fields.get(name) if isinstance(fields, dict) else None


def validate_ff_proof(protocol: str, proof: dict,
                      expected_hostgroup: Optional[int] = None) -> list[str]:
    """Validate live FF evidence; a missing PG fast_forward key is expected."""
    errors: list[str] = []
    runtime = proof.get("runtime_row") or {}
    if str(runtime.get("active", "")) != "1":
        errors.append("runtime frontend active is not 1")
    if str(runtime.get("fast_forward", "")) != "1":
        errors.append("runtime frontend fast_forward is not 1")
    if str(runtime.get("frontend", "")) != "1":
        errors.append("runtime frontend flag is not 1")
    expected = expected_hostgroup
    if expected is None:
        expected = proof.get("expected_hostgroup")
    if expected is not None and str(runtime.get("default_hostgroup", "")) != str(expected):
        errors.append("runtime frontend default_hostgroup is not the expected source hostgroup")
    if proof.get("match_count") != 1:
        errors.append("processlist match count is not exactly 1")
    if protocol == "mysql":
        if _field(proof, "command") != "Fast forward":
            errors.append("processlist command is not 'Fast forward'")
        value = proof.get("fast_forward")
        if str(value).lower() not in ("1", "true"):
            errors.append("extended_info.$.fast_forward is not 1/true")
    else:
        if _field(proof, "command") != "Fast forward":
            errors.append("processlist command is not 'Fast forward'")
        if str(proof.get("status")) != "22":
            errors.append("extended_info.$.status is not 22 (FAST_FORWARD)")
        value = proof.get("fast_forward")
        if value is not None and str(value).lower() != "null":
            errors.append("unexpected PostgreSQL fast_forward JSON key")
    cli_port = str(proof.get("cli_port") or "")
    if not cli_port.isdigit():
        errors.append("client TCP port is absent or non-numeric")
    elif str(_field(proof, "cli_port") or "") != cli_port:
        errors.append("processlist cli_port does not match the held client socket")
    return errors


def _proof_row(daemon: ProxyDaemon, sql: str, timeout: float = 8.0) -> dict:
    cp = daemon.query(sql, timeout)
    if cp.returncode != 0:
        return {}
    text = cp.stdout.rstrip("\n")
    if not text:
        return {}
    values = text.split("\t")
    return {"values": values, "raw": text}


def collect_ff_proof(daemon: ProxyDaemon, protocol: str, fixture_port: int,
                     cli_port: str, expected_hostgroup: int,
                     evidence_dir: Path) -> dict:
    user = "ffbench"
    if not str(cli_port).isdigit():
        raise RunnerError(f"held client did not report a numeric TCP port: {cli_port!r}")
    deadline = time.monotonic() + 8.0
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        if protocol == "mysql":
            columns = (
                "SessionID,user,db,cli_host,cli_port,hostgroup,srv_host,srv_port,command"
            )
            from_table = "stats_mysql_processlist"
            ff_sql = ("SELECT COALESCE(json_extract(extended_info,'$.fast_forward'),'') "
                      f"FROM {from_table} WHERE user={sql_lit(user)} "
                      f"AND cli_host={sql_lit(HOST)} AND cli_port={int(cli_port)}")
            status_sql = ("SELECT COALESCE(json_extract(extended_info,'$.status'),'') "
                          f"FROM {from_table} WHERE user={sql_lit(user)} "
                          f"AND cli_host={sql_lit(HOST)} AND cli_port={int(cli_port)}")
            raw_sql = f"SELECT extended_info FROM {from_table} WHERE user={sql_lit(user)} " \
                      f"AND cli_host={sql_lit(HOST)} AND cli_port={int(cli_port)}"
        else:
            columns = (
                "SessionID,user,database,cli_host,cli_port,hostgroup,srv_host,srv_port,"
                "backend_pid,backend_state,command"
            )
            from_table = "stats_pgsql_processlist"
            ff_sql = ("SELECT COALESCE(json_extract(extended_info,'$.fast_forward'),'NULL') "
                      f"FROM {from_table} WHERE user={sql_lit(user)} "
                      f"AND cli_host={sql_lit(HOST)} AND cli_port={int(cli_port)}")
            status_sql = ("SELECT COALESCE(json_extract(extended_info,'$.status'),'') "
                          f"FROM {from_table} WHERE user={sql_lit(user)} "
                          f"AND cli_host={sql_lit(HOST)} AND cli_port={int(cli_port)}")
            raw_sql = f"SELECT extended_info FROM {from_table} WHERE user={sql_lit(user)} " \
                      f"AND cli_host={sql_lit(HOST)} AND cli_port={int(cli_port)}"
        field_names = columns.split(",")
        match_count_text = daemon.value(
            f"SELECT COUNT(*) FROM {from_table} WHERE user={sql_lit(user)} "
            f"AND cli_host={sql_lit(HOST)} AND cli_port={int(cli_port)}")
        match_count = int(match_count_text) if match_count_text.isdigit() else -1
        row = _proof_row(
            daemon,
            f"SELECT {columns} FROM {from_table} WHERE user={sql_lit(user)} "
            f"AND cli_host={sql_lit(HOST)} AND cli_port={int(cli_port)}")
        if not row:
            time.sleep(0.1)
            continue
        fields = dict(zip(field_names, row["values"]))
        ff_value = daemon.value(ff_sql)
        status_value = daemon.value(status_sql)
        raw_extended = daemon.query(raw_sql).stdout.rstrip("\n")
        runtime_columns = (
            "username,active,frontend,backend,default_hostgroup,fast_forward"
        )
        runtime_table = ("runtime_mysql_users" if protocol == "mysql"
                         else "runtime_pgsql_users")
        runtime_raw = daemon.value(
            f"SELECT {runtime_columns} FROM {runtime_table} "
            f"WHERE username={sql_lit(user)} AND frontend=1")
        runtime_values = runtime_raw.split("\t") if runtime_raw else []
        runtime_row = dict(zip(runtime_columns.split(","), runtime_values))
        vertical = daemon.query(
            f"SELECT {columns},extended_info FROM {from_table} "
            f"WHERE user={sql_lit(user)} AND cli_host={sql_lit(HOST)} "
            f"AND cli_port={int(cli_port)}",
            vertical=True).stdout
        proof = {
            "protocol": protocol,
            "cli_port": cli_port,
            "cli_host": HOST,
            "expected_hostgroup": expected_hostgroup,
            "match_count": match_count,
            "processlist_fields": fields,
            "fast_forward": ff_value,
            "status": status_value,
            "extended_info_raw": raw_extended,
            "processlist_raw_row": row["raw"],
            "processlist_vertical_raw": vertical,
            "runtime_row_raw": runtime_raw,
            "runtime_row": runtime_row,
            "from_table": from_table,
            "collected_utc": utc_now(),
        }
        last = proof
        errors = validate_ff_proof(protocol, proof, expected_hostgroup)
        proof["errors"] = errors
        proof["ok"] = not errors
        if not errors:
            break
        time.sleep(0.1)
    proof = last or {
        "protocol": protocol,
        "cli_port": cli_port,
        "cli_host": HOST,
        "expected_hostgroup": expected_hostgroup,
        "match_count": 0,
        "collected_utc": utc_now(),
        "ok": False,
        "errors": ["no matching live processlist row"],
        "processlist_fields": {},
    }
    evidence_dir.mkdir(parents=True, exist_ok=True)
    proof_path = evidence_dir / f"{protocol}-ff-proof.json"
    proof_path.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
    proof["evidence_file"] = str(proof_path)
    if not proof.get("ok"):
        raise RunnerError(
            f"active {protocol} fast-forward proof failed ({proof_path}): "
            f"{'; '.join(proof.get('errors', []))}")
    return proof


def collect_native_proof(daemon: ProxyDaemon, protocol: str, fixture_port: int,
                         cli_port: str, baseline_tcp: dict, baseline_hgm: dict,
                         evidence_dir: Path) -> dict:
    """Prove a held native query through active plugin + pinned HGM backend."""
    assert daemon.admin is not None
    if not str(cli_port).isdigit():
        raise RunnerError(f"native held client did not report a numeric TCP port: {cli_port!r}")
    status = daemon.value("SELECT state,running,last_error FROM runtime_tcp_status WHERE id=1")
    listener = daemon.value(
        "SELECT listener_id,active,bind_address,bind_port,default_hostgroup "
        "FROM runtime_tcp_listeners WHERE listener_id=1")
    current_tcp = daemon.tcp_stats()
    current_hgm = daemon.hgm_stats(protocol, daemon.source_hostgroup, fixture_port)
    tcp_delta = wire_delta(baseline_tcp, current_tcp)
    hgm_lifecycle = hgm_delta(baseline_hgm, current_hgm)
    sql_table = ("stats_mysql_processlist" if protocol == "mysql"
                 else "stats_pgsql_processlist")
    sql_row_count_text = daemon.value(
        f"SELECT COUNT(*) FROM {sql_table} WHERE cli_host={sql_lit(HOST)} "
        f"AND cli_port={int(cli_port)}")
    sql_row_count = int(sql_row_count_text) if sql_row_count_text.isdigit() else -1
    status_parts = status.split("\t")
    errors: list[str] = []
    if len(status_parts) < 2 or status_parts[1] != "1":
        errors.append("plugin runtime is not running")
    if current_tcp.get("active_connections", 0) <= 0:
        errors.append("plugin active_connections is not >0 while the native socket is held")
    if tcp_delta.get("accepted_total", 0) <= 0:
        errors.append("plugin accepted_total did not advance for the held native socket")
    if tcp_delta.get("bytes_client_to_server", 0) <= 0:
        errors.append("plugin client-to-server proxied bytes are not >0")
    if tcp_delta.get("bytes_server_to_client", 0) <= 0:
        errors.append("plugin server-to-client proxied bytes are not >0")
    if tcp_delta.get("connect_errors", 0) != 0 or tcp_delta.get("rejected_total", 0) != 0:
        errors.append("plugin connect_errors/rejected_total advanced")
    if current_hgm.get("ConnUsed", 0) <= 0:
        errors.append("HGM ConnUsed is not >0 while the native socket is held")
    if hgm_lifecycle.get("ConnERR", 0) != 0:
        errors.append("HGM ConnERR advanced during the native hold")
    if sql_row_count != 0:
        errors.append("native held local TCP port unexpectedly has a frontend SQL processlist row")
    proof = {
        "protocol": protocol,
        "cli_port": cli_port,
        "cli_host": HOST,
        "held_sql_completed": True,
        "runtime_status_raw": status,
        "runtime_listener_raw": listener,
        "listener_stats_baseline": baseline_tcp,
        "listener_stats_held": current_tcp,
        "listener_delta": tcp_delta,
        "hgm_baseline": baseline_hgm,
        "hgm_held": current_hgm,
        "hgm_delta": hgm_lifecycle,
        "frontend_sql_processlist_match_count": sql_row_count,
        "frontend_sql_processlist_table": sql_table,
        "errors": errors,
        "ok": not errors,
        "collected_utc": utc_now(),
        "note": (
            "Held successful ordinary SELECT on the native listener; no SQL frontend "
            "processlist row for this client TCP port. Plugin active/accepted/proxied "
            "bytes and HGM ConnUsed prove the live mapped backend stream."
        ),
    }
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / f"{protocol}-native-proof.json"
    path.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
    proof["evidence_file"] = str(path)
    if errors:
        raise RunnerError(
            f"active {protocol} native proof failed ({path}): {'; '.join(errors)}")
    return proof


def config_fingerprint(daemon: Any) -> dict:
    return daemon.equivalence_core()


def assert_equivalent(protocol: str, native: Any, ff: Any) -> None:
    left = config_fingerprint(native)
    right = config_fingerprint(ff)
    if left != right:
        differing = [key for key in sorted(set(left) | set(right))
                     if left.get(key) != right.get(key)]
        raise RunnerError(f"{protocol} native/FF configuration differs: {differing}")


def hgm_delta(before: dict, after: dict) -> dict:
    delta = {
        name: int(after[name]) - int(before[name])
        for name in ("ConnUsed", "ConnFree", "ConnOK", "ConnERR",
                     "Bytes_data_sent", "Bytes_data_recv")
    }
    delta["MaxConnUsed_after"] = int(after.get("MaxConnUsed", 0))
    return delta


def wire_delta(before: dict, after: dict) -> dict:
    return {name: int(after[name]) - int(before[name]) for name in before}


class Experiment:
    def __init__(self, args: argparse.Namespace, profile: str):
        self.args = args
        self.profile = profile
        self.work_dir = Path(args.work_dir).resolve()
        self.work_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.run_dir = self.work_dir / f"{profile}-{stamp}-{os.getpid()}"
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.client = BenchClient(Path(args.client))
        self.fixtures: list[Any] = []
        self.daemons: list[ProxyDaemon] = []
        self.manifest = self.freeze_manifest()
        self.errors: list[dict] = []

    def freeze_manifest(self) -> dict:
        host = Path(self.args.proxysql).resolve()
        plugin = Path(self.args.plugin).resolve()
        for label, path in (("host", host), ("plugin", plugin)):
            if not path.is_file():
                raise RunnerError(f"{label} not found: {path}")
        inputs = [
            host, plugin, Path(self.args.client),
            Path(__file__), TESTS_DIR / "fast_forward_bench_client.cpp",
            TESTS_DIR / "Makefile.fast-forward",
            TESTS_DIR / "README.fast-forward.md",
            Path(self.args.mysql), Path(self.args.mysqld),
            Path(self.args.pg_bin) / "initdb", Path(self.args.pg_bin) / "pg_ctl",
            Path(self.args.pg_bin) / "postgres", Path(self.args.pg_bin) / "psql",
            Path(self.args.deps) / "mariadb-client-library/mariadb_client/include/mysql.h",
            Path(self.args.deps) / "mariadb-client-library/mariadb_client/libmariadb/libmariadbclient.a",
            Path(self.args.deps) / "postgresql/postgresql/src/interfaces/libpq/libpq-fe.h",
            Path("/lib/x86_64-linux-gnu/libpq.so.5"),
            Path("/lib/x86_64-linux-gnu/libssl.so.3"),
            Path("/lib/x86_64-linux-gnu/libcrypto.so.3"),
            Path("/lib/x86_64-linux-gnu/libz.so.1"),
        ]
        missing = [str(path) for path in inputs if not path.is_file()]
        if missing:
            raise RunnerError(f"freeze inputs missing: {missing}")
        artifacts = {
            str(path): {"sha256": sha256_file(path), "bytes": path.stat().st_size}
            for path in inputs
        }
        gxx = shutil.which("g++") or "g++"
        version = run_process([gxx, "--version"], timeout=10).stdout.splitlines()
        client_versions_cp = run_process([str(self.args.client), "--versions"], timeout=10)
        if client_versions_cp.returncode != 0:
            raise RunnerError(f"client --versions failed: {clip(client_versions_cp.stderr)}")
        try:
            client_versions = json.loads(client_versions_cp.stdout)
        except json.JSONDecodeError as exc:
            raise RunnerError(f"client --versions output invalid: {exc}") from exc
        ldd_cp = run_process(["ldd", str(self.args.client)], timeout=10)
        manifest = {
            "kind": "fast-forward-benchmark-frozen-manifest",
            "created_utc": utc_now(),
            "profile": self.profile,
            "repo_root": str(REPO_ROOT),
            "host": {"path": str(host), "sha256": artifacts[str(host)]["sha256"]},
            "plugin": {"path": str(plugin), "sha256": artifacts[str(plugin)]["sha256"]},
            "client": {"path": str(self.args.client),
                       "sha256": sha256_file(self.args.client),
                       "library_versions": client_versions,
                       "ldd": ldd_cp.stdout.splitlines()},
            "artifacts": artifacts,
            "compiler": version[:2],
            "build": {
                "command": (
                    "make -f plugins/tcp_proxy/tests/Makefile.fast-forward "
                    f"DEPS_PATH={self.args.deps} OUT_DIR={self.work_dir}"
                ),
                "cxx": gxx,
                "cxxflags": "-std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Werror -pthread",
                "cppflags": (
                    f"-I{self.args.deps}/mariadb-client-library/mariadb_client/include "
                    f"-I{self.args.deps}/postgresql/postgresql/src/interfaces/libpq "
                    f"-I{self.args.deps}/postgresql/postgresql/src/include"
                ),
                "ldlibs": (
                    f"{self.args.deps}/mariadb-client-library/mariadb_client/"
                    "libmariadb/libmariadbclient.a /lib/x86_64-linux-gnu/libpq.so.5 "
                    "-lssl -lcrypto -lz -ldl -lm -lresolv -pthread"
                ),
            },
            "host_info": host_info(),
            "source_provenance": source_provenance(),
        }
        path = self.run_dir / "frozen-manifest.json"
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        manifest["path"] = str(path)
        return manifest

    def verify_frozen(self) -> None:
        for path_text, item in self.manifest["artifacts"].items():
            path = Path(path_text)
            if not path.is_file() or sha256_file(path) != item["sha256"]:
                raise RunnerError(f"frozen input changed during run: {path}")

    def cleanup(self) -> dict:
        result: dict[str, Any] = {"daemons": [], "fixtures": []}
        for daemon in reversed(self.daemons):
            result["daemons"].append(daemon.close())
        self.daemons.clear()
        for fixture in reversed(self.fixtures):
            result["fixtures"].append(fixture.stop())
        self.fixtures.clear()
        leftover = []
        for daemon in result["daemons"]:
            if daemon.get("still_alive"):
                leftover.append(daemon)
        result["owned_processes_still_alive"] = leftover
        return result


def phase_resources(proxy: Optional[ProxyDaemon], fixture: Any,
                    before_proxy: Optional[dict], after_proxy: Optional[dict],
                    before_db: Optional[dict], after_db: Optional[dict]) -> dict:
    db_pid = (fixture.postmaster_pid if isinstance(fixture, PgFixture)
              else (fixture.proc.pid if getattr(fixture, "proc", None) else None))
    db_scope = ("PostgreSQL postmaster PID only; forked query backend CPU is not "
                "included" if isinstance(fixture, PgFixture)
                else "whole mysqld process")
    return {
        "proxy": {
            "pid": proxy.proc.pid if proxy and proxy.proc else None,
            "scope": "whole ProxySQL daemon process",
            "delta": resource_delta(before_proxy, after_proxy),
        },
        "database": {
            "pid": db_pid,
            "scope": db_scope,
            "delta": resource_delta(before_db, after_db),
        },
        "client": {
            "scope": "native client live-sampled /proc estimate at 50 ms; "
                     "startup/exit ticks can be missed",
        },
    }


def run_client_phase(experiment: Experiment, trial_dir: Path, fixture: Any,
                     protocol: str, port: int, path: str, phase_name: str,
                     mode: str, proxy: Optional[ProxyDaemon], **kwargs: Any) -> dict:
    phase_dir = trial_dir / phase_name
    phase_dir.mkdir(parents=True, exist_ok=True)
    proxy_before = snapshot_process(proxy.proc.pid if proxy and proxy.proc else None)
    db_pid = (fixture.postmaster_pid if isinstance(fixture, PgFixture)
              else (fixture.proc.pid if fixture.proc else None))
    db_before = snapshot_process(db_pid)
    hgm_before = None
    wire_before = None
    if proxy:
        proxy.wait_hgm_idle(protocol, proxy.source_hostgroup, fixture.port)
        hgm_before = proxy.hgm_stats(protocol, proxy.source_hostgroup, fixture.port)
        if path == "native":
            wire_before = proxy.tcp_stats()
    invoke = experiment.client.invoke(
        fixture, port, mode, phase_dir / "client.conf", **kwargs)
    require_client_ok(invoke, f"{protocol}/{path}/{phase_name}")
    result = invoke.json or {}
    check_tls_and_compression(fixture, result)
    proxy_after = snapshot_process(proxy.proc.pid if proxy and proxy.proc else None)
    db_after = snapshot_process(db_pid)
    hgm_after = None
    wire_after = None
    drained = None
    hgm_lifecycle = None
    tcp_delta = None
    zero_error_checks: dict[str, Any] = {}
    if proxy:
        hgm_after = proxy.hgm_stats(protocol, proxy.source_hostgroup, fixture.port)
        if path == "native":
            wire_after = proxy.tcp_stats()
        hgm_lifecycle = hgm_delta(hgm_before, hgm_after)
        if hgm_lifecycle["ConnERR"] != 0:
            raise RunnerError(
                f"{protocol}/{path}/{phase_name}: HGM ConnERR advanced by "
                f"{hgm_lifecycle['ConnERR']}")
        if hgm_lifecycle["ConnOK"] <= 0:
            raise RunnerError(
                f"{protocol}/{path}/{phase_name}: HGM ConnOK did not advance")
        zero_error_checks["hgm_conn_err_delta_zero"] = True
        zero_error_checks["hgm_conn_ok_advanced"] = True
        if path == "native":
            tcp_delta = wire_delta(wire_before, wire_after)
            if tcp_delta["connect_errors"] != 0:
                raise RunnerError(
                    f"{protocol}/native/{phase_name}: plugin connect_errors advanced")
            if tcp_delta["rejected_total"] != 0:
                raise RunnerError(
                    f"{protocol}/native/{phase_name}: plugin rejected_total advanced")
            if tcp_delta["accepted_total"] <= 0:
                raise RunnerError(
                    f"{protocol}/native/{phase_name}: plugin accepted_total did not advance")
            zero_error_checks["plugin_connect_errors_delta_zero"] = True
            zero_error_checks["plugin_rejected_delta_zero"] = True
            zero_error_checks["plugin_accepted_advanced"] = True
        drained = proxy.wait_hgm_idle(protocol, proxy.source_hostgroup, fixture.port)
        zero_error_checks["hgm_drained_used_free_zero"] = True
    phase = {
        "phase": phase_name,
        "mode": mode,
        "native_result": result,
        "client_invocation": invoke.record(),
        "resources": {
            **phase_resources(
                proxy, fixture, proxy_before, proxy_after, db_before, db_after),
            "client": {
                "scope": "native client live-sampled /proc estimate at 50 ms; "
                         "startup/exit ticks can be missed",
                "sampled": invoke.resources,
            },
        },
        "zero_error_checks": zero_error_checks,
        "hgm_before": hgm_before,
        "hgm_after": hgm_after,
        "hgm_delta": hgm_lifecycle,
        "hgm_drained": drained,
        "wire_before": wire_before,
        "wire_after": wire_after,
        "wire_delta": tcp_delta,
        "wire_scope": (
            "mapped-TCP listener application/relay wire counters; separate from "
            "application payload in native_result"
            if path == "native" else
            ("HGM backend bytes only; excludes frontend/auth/SQL framing; separate "
             "from application payload in native_result" if proxy else "not proxied")
        ),
    }
    (phase_dir / "phase.json").write_text(
        json.dumps(phase, indent=2, sort_keys=True) + "\n")
    return phase


def trial_directory(run_dir: Path, protocol: str, round_index: int, path: str) -> Path:
    """Return a unique per-round/path directory (3 rounds must never collide)."""
    return run_dir / protocol / f"round-{round_index:03d}" / path


def run_trial(experiment: Experiment, protocol: str, fixture: Any, path: str,
              *, round_index: int, clients: int, warmups: int, samples: int,
              phase_seconds: float, timeout_ms: int, workload: str) -> dict:
    trial_root = trial_directory(experiment.run_dir, protocol, round_index, path)
    trial_root.mkdir(parents=True, exist_ok=False)
    daemon: Optional[ProxyDaemon] = None
    proxy_cleanup: Optional[dict] = None
    started = time.monotonic()
    try:
        if path == "direct":
            port = fixture.port
            endpoint_kind = "direct-database"
        else:
            daemon = ProxyDaemon(
                Path(experiment.args.proxysql), Path(experiment.args.plugin),
                protocol, Path(experiment.args.mysql), trial_root, "proxy")
            experiment.daemons.append(daemon)
            daemon.start(fixture)
            port = daemon.tcp_port if path == "native" else daemon.sql_port
            endpoint_kind = "mapped-tcp-listener" if path == "native" else "sql-listener"
        verify = experiment.client.verify(
            fixture, port, trial_root / "verify.conf", workload=workload)
        ff_proof = None
        hold_record = None
        native_proof = None
        if path in ("ff", "native"):
            assert daemon is not None
            baseline_tcp = None
            baseline_hgm = None
            if path == "native":
                daemon.wait_hgm_idle(protocol, daemon.source_hostgroup, fixture.port)
                baseline_tcp = daemon.tcp_stats()
                baseline_hgm = daemon.hgm_stats(
                    protocol, daemon.source_hostgroup, fixture.port)
            config_path = trial_root / "hold.conf"
            fixture.client_config(config_path, port)
            holder = HoldSession(Path(experiment.args.client), config_path,
                                 workload=workload,
                                 payload_bytes=1 if workload == "select1" else 64)
            try:
                ready = holder.wait_ready(timeout=20)
                if ready.get("tls_used") or ready.get("ssl_cipher"):
                    raise RunnerError("hold client unexpectedly used TLS")
                if ready.get("tcp_nodelay") != 1:
                    raise RunnerError("hold client did not observe TCP_NODELAY=1")
                local_port = str(ready.get("local_port", ""))
                if path == "ff":
                    ff_proof = collect_ff_proof(
                        daemon, protocol, fixture.port, local_port,
                        daemon.source_hostgroup, trial_root / "proof")
                    ff_proof["hold_ready"] = ready
                else:
                    native_proof = collect_native_proof(
                        daemon, protocol, fixture.port, local_port,
                        baseline_tcp, baseline_hgm, trial_root / "proof")
                    native_proof["hold_ready"] = ready
            finally:
                hold_record = holder.close()
                if path == "native" and native_proof is not None:
                    native_proof["hgm_after_hold"] = daemon.wait_hgm_idle(
                        protocol, daemon.source_hostgroup, fixture.port)

        rtt_key = "rtt_select1" if workload == "select1" else "rtt64"
        rtt = run_client_phase(
            experiment, trial_root, fixture, protocol, port, path, rtt_key, "rtt",
            daemon, payload_bytes=1 if workload == "select1" else 64,
            warmups=warmups, samples=samples, clients=clients,
            timeout_ms=timeout_ms, timeout=120, workload=workload)
        connections = run_client_phase(
            experiment, trial_root, fixture, protocol, port, path, "connections",
            "connections", daemon, clients=clients, duration_seconds=phase_seconds,
            timeout_ms=timeout_ms, timeout=120, workload=workload)
        phases = {"rtt_select1" if workload == "select1" else "rtt64": rtt,
                  "connections": connections}
        if workload == "select1":
            phases["select1_qps"] = run_client_phase(
                experiment, trial_root, fixture, protocol, port, path, "select1_qps",
                "throughput", daemon, payload_bytes=1, warmups=warmups,
                clients=clients, duration_seconds=phase_seconds,
                timeout_ms=timeout_ms, timeout=120, workload=workload)
        else:
            phases["throughput64k"] = run_client_phase(
                experiment, trial_root, fixture, protocol, port, path,
                "throughput64k", "throughput", daemon, payload_bytes=65536,
                warmups=warmups, clients=clients, duration_seconds=phase_seconds,
                timeout_ms=timeout_ms, timeout=120, workload=workload)
            phases["throughput1m"] = run_client_phase(
                experiment, trial_root, fixture, protocol, port, path,
                "throughput1m", "throughput", daemon, payload_bytes=1048576,
                warmups=warmups, clients=clients, duration_seconds=phase_seconds,
                timeout_ms=timeout_ms, timeout=180, workload=workload)
        trial = {
            "path": path,
            "protocol": protocol,
            "workload": workload,
            "profile": experiment.profile,
            "endpoint": {"host": HOST, "port": port, "kind": endpoint_kind},
            "verify": verify,
            "ff_proof": ff_proof,
            "ff_hold": hold_record,
            "native_proof": native_proof,
            "daemon": daemon.record() if daemon else None,
            "daemon_config": daemon.config_evidence if daemon else None,
            "phases": phases,
            "duration_s": round(time.monotonic() - started, 3),
            "collected_utc": utc_now(),
        }
        (trial_root / "trial.json").write_text(
            json.dumps(trial, indent=2, sort_keys=True) + "\n")
        return trial
    finally:
        if daemon:
            proxy_cleanup = daemon.close()
            if proxy_cleanup:
                (trial_root / f"cleanup-{daemon.run_dir.name}.json").write_text(
                    json.dumps(proxy_cleanup, indent=2, sort_keys=True) + "\n")


def run_protocol(experiment: Experiment, protocol: str, fixture: Any,
                 *, clients: int, warmups: int, samples: int, phase_seconds: float,
                 timeout_ms: int, rounds: int, workload: str) -> dict:
    orders = [
        ["direct", "native", "ff"],
        ["native", "ff", "direct"],
        ["ff", "direct", "native"],
    ]
    trials_by_round: list[dict] = []
    all_trials: dict[str, list[dict]] = {"direct": [], "native": [], "ff": []}
    for round_index in range(rounds):
        order = orders[round_index % len(orders)]
        round_record = {"round": round_index + 1, "order": order, "trials": {}}
        for path in order:
            trial = run_trial(
                experiment, protocol, fixture, path, round_index=round_index,
                clients=clients, warmups=warmups, samples=samples,
                phase_seconds=phase_seconds, timeout_ms=timeout_ms,
                workload=workload)
            trial["round"] = round_index + 1
            trial["order_index"] = order.index(path)
            round_record["trials"][path] = trial
            all_trials[path].append(trial)
        native_trials = [item for item in all_trials["native"]
                         if item["daemon_config"]]
        ff_trials = [item for item in all_trials["ff"] if item["daemon_config"]]
        if native_trials and ff_trials:
            # Compare the most recent pair; configuration is frozen at run start.
            assert_equivalent(protocol,
                              _DaemonView(native_trials[-1]["daemon_config"]),
                              _DaemonView(ff_trials[-1]["daemon_config"]))
        trials_by_round.append(round_record)
    return {
        "protocol": protocol,
        "fixture": fixture.record(),
        "rounds": trials_by_round,
        "summary": summarize_trials(all_trials, workload),
    }


class _DaemonView:
    """Small adapter so assert_equivalent also works from persisted evidence."""

    def __init__(self, evidence: dict):
        self._evidence = evidence

    def equivalence_core(self) -> dict:
        result = dict(self._evidence)
        result.pop("sql_listener_port", None)
        result.pop("tcp_listener_port", None)
        return result


def trial_metric(trial: dict, phase: str, field: str) -> Any:
    return trial.get("phases", {}).get(phase, {}).get("native_result", {}).get(field)


def summarize_trials(all_trials: dict[str, list[dict]], workload: str) -> dict:
    result: dict[str, Any] = {}
    rtt_key = "rtt_select1" if workload == "select1" else "rtt64"
    for path, trials in all_trials.items():
        item = {
            "rtt_p50_ns": summary([trial_metric(t, rtt_key, "p50_ns") for t in trials]),
            "rtt_p95_ns": summary([trial_metric(t, rtt_key, "p95_ns") for t in trials]),
            "rtt_p99_ns": summary([trial_metric(t, rtt_key, "p99_ns") for t in trials]),
            "connections_per_s": summary(
                [trial_metric(t, "connections", "connections_per_s") for t in trials]),
            "trials": len(trials),
        }
        if workload == "select1":
            item["select1_qps"] = summary(
                [trial_metric(t, "select1_qps", "queries_per_s") for t in trials])
        else:
            item["throughput64k_qps"] = summary(
                [trial_metric(t, "throughput64k", "queries_per_s") for t in trials])
            item["throughput64k_mib_s"] = summary(
                [trial_metric(t, "throughput64k", "application_response_mib_per_s")
                 for t in trials])
            item["throughput1m_qps"] = summary(
                [trial_metric(t, "throughput1m", "queries_per_s") for t in trials])
            item["throughput1m_mib_s"] = summary(
                [trial_metric(t, "throughput1m", "application_response_mib_per_s")
                 for t in trials])
        result[path] = item
    return result


def render_select1_markdown(report: dict) -> str:
    title = ("Tiny smoke: SELECT 1 native mapped TCP vs permanent SQL fast-forward"
             if report.get("profile") == "smoke"
             else "SELECT 1 native mapped TCP vs permanent SQL fast-forward")
    manifest = report.get("manifest") or {}
    workload = report.get("workload") or {}
    lines = [f"# {title}", "", f"Status: **{report.get('status', 'unknown')}**",
             "", f"Generated: `{report.get('generated_utc')}`", "",
             f"Workload: `{workload.get('workload')}`; exact SQL `{workload.get('sql')}`; "
             f"expected result `{workload.get('expected_result')}`.", "",
             f"Tiny smoke: {workload.get('smoke_label') or 'no'}",
             "", "## Workload geometry", "",
             f"- Rounds: {workload.get('rounds')}; clients: {workload.get('clients')}; "
             f"warmups/client: {workload.get('warmups_per_client')}; "
             f"SELECT 1 RTT samples/client: {workload.get('rtt_samples_per_client')}.",
             f"- Requested phase duration: {workload.get('phase_seconds')} s; phases: "
             f"`{workload.get('phase_keys')}`; timeout: {workload.get('timeout_ms')} ms.",
             f"- Order rotation: `{workload.get('order_rotation')}`.", "",
             "## Provenance", ""]
    for key in ("host", "plugin", "client"):
        item = manifest.get(key) or {}
        lines.append(f"- {key}: `{item.get('path')}` sha256 `{item.get('sha256')}`")
    build = manifest.get("build") or {}
    lines += ["", f"- Build flags: `{build.get('cxxflags')}`; include flags: `{build.get('cppflags')}`",
              f"- Link inputs: `{build.get('ldlibs')}`",
              f"- Client library versions: `{manifest.get('client', {}).get('library_versions')}`",
              f"- Host: `{manifest.get('host_info')}`", "",
              "## Per-round exact SELECT 1 results", "",
              "| Proto | Round | Path | RTT p50/p95/p99 (us) | Connections/s | SELECT1 QPS | requested/actual s |",
              "|---|---:|---|---|---:|---:|---|"]
    def fmt(value, scale=1.0, digits=1):
        return "" if value is None else f"{float(value) / scale:.{digits}f}"
    for protocol, proto in report.get("protocols", {}).items():
        for rr in proto.get("rounds", []):
            for path in ("direct", "native", "ff"):
                t = rr.get("trials", {}).get(path)
                if not t:
                    continue
                rtt = t.get("phases", {}).get("rtt_select1", {}).get("native_result", {})
                conn = t.get("phases", {}).get("connections", {}).get("native_result", {})
                qps = t.get("phases", {}).get("select1_qps", {}).get("native_result", {})
                rtt_text = "/".join(fmt(rtt.get(k), 1000.0) for k in
                                    ("p50_ns", "p95_ns", "p99_ns"))
                lines.append(
                    f"| {protocol} | {rr.get('round')} | {path} | {rtt_text} | "
                    f"{fmt(conn.get('connections_per_s'))} | {fmt(qps.get('queries_per_s'))} | "
                    f"{fmt(conn.get('requested_duration_s'), 1, 2)}/"
                    f"{fmt(conn.get('actual_elapsed_s'), 1, 2)} |")
    lines += ["", "## Median and range across rounds", "",
              "| Proto | Path | RTT p50 us | RTT p95 us | RTT p99 us | Connections/s | SELECT1 QPS |",
              "|---|---|---:|---:|---:|---:|---:|"]
    def med_range(data, name, scale=1.0):
        item = data.get(name) or {}
        if item.get("median") is None:
            return ""
        return (f"{float(item['median']) / scale:.1f} "
                f"[{float(item['min']) / scale:.1f}-{float(item['max']) / scale:.1f}]")
    for protocol, proto in report.get("protocols", {}).items():
        for path in ("direct", "native", "ff"):
            data = proto.get("summary", {}).get(path, {})
            lines.append(
                f"| {protocol} | {path} | {med_range(data, 'rtt_p50_ns', 1000)} | "
                f"{med_range(data, 'rtt_p95_ns', 1000)} | "
                f"{med_range(data, 'rtt_p99_ns', 1000)} | "
                f"{med_range(data, 'connections_per_s')} | "
                f"{med_range(data, 'select1_qps')} |")
    lines += ["", "## Configuration/auth/TLS evidence", ""]
    for protocol, proto in report.get("protocols", {}).items():
        fixture = proto.get("fixture") or {}
        lines.append(f"- {protocol} fixture: `{fixture.get('kind')}` "
                     f"{fixture.get('version')} auth=`{fixture.get('auth_plugin') or fixture.get('host_auth')}`.")
        for rr in proto.get("rounds", []):
            for path in ("native", "ff"):
                t = rr.get("trials", {}).get(path)
                if not t:
                    continue
                cfg = t.get("daemon_config") or {}
                v = t.get("verify") or {}
                lines.append(
                    f"- {protocol} round {rr.get('round')} {path}: exact_sql=`{v.get('sql')}` "
                    f"expected=`{v.get('expected_result')}` sql_threads=`{cfg.get('sql_threads')}` "
                    f"tcp_workers=`{cfg.get('tcp_settings')}` tls=`{v.get('tls_used')}` "
                    f"gss=`{v.get('gssenc_in_use')}` tcp_nodelay=`{v.get('tcp_nodelay')}`.")
    lines += ["", "## Application result and wire counters", "",
              "The result value is one byte; SQL text is eight bytes per query. The legacy "
              "application_request_bytes counter counts the one-byte constant value and is "
              "not the SQL request size. HGM/TCP counters include framing/auth.", "",
              "| Proto | Round | Path | Phase | Queries/cycles | App response bytes | HGM sent/recv | TCP wire c2s/s2c |",
              "|---|---:|---|---|---:|---:|---|---|"]
    for protocol, proto in report.get("protocols", {}).items():
        for rr in proto.get("rounds", []):
            for path in ("direct", "native", "ff"):
                t = rr.get("trials", {}).get(path)
                if not t:
                    continue
                for phase_name in ("rtt_select1", "connections", "select1_qps"):
                    phase = t.get("phases", {}).get(phase_name, {})
                    r = phase.get("native_result") or {}
                    hgm = phase.get("hgm_delta") or {}
                    wire = phase.get("wire_delta") or {}
                    if phase_name == "rtt_select1":
                        ops = sum(len(th.get("samples_ns", [])) for th in r.get("threads", []))
                        app = ops
                    elif phase_name == "connections":
                        ops = r.get("cycles")
                        app = (ops or 0) * 1
                    else:
                        ops = r.get("queries")
                        app = r.get("application_response_bytes")
                    lines.append(
                        f"| {protocol} | {rr.get('round')} | {path} | {phase_name} | {ops} | "
                        f"{app} | {hgm.get('Bytes_data_sent')}/{hgm.get('Bytes_data_recv')} | "
                        f"{wire.get('bytes_client_to_server')}/{wire.get('bytes_server_to_client')} |")
    lines += ["", "## Active proof", ""]
    for protocol, proto in report.get("protocols", {}).items():
        for rr in proto.get("rounds", []):
            ff = rr.get("trials", {}).get("ff")
            if ff and ff.get("ff_proof"):
                pr = ff["ff_proof"]
                lines.append(
                    f"- {protocol} round {rr.get('round')} FF: `{pr.get('evidence_file')}`; "
                    f"command `{_field(pr, 'command')}`; cli_port `{pr.get('cli_port')}`; "
                    f"runtime active/fast_forward "
                    f"`{pr.get('runtime_row', {}).get('active')}/"
                    f"{pr.get('runtime_row', {}).get('fast_forward')}`; status `{pr.get('status')}`.")
            native = rr.get("trials", {}).get("native")
            if native and native.get("native_proof"):
                np = native["native_proof"]
                lines.append(
                    f"- {protocol} round {rr.get('round')} native: `{np.get('evidence_file')}`; "
                    f"SQL processlist matches `{np.get('frontend_sql_processlist_match_count')}`; "
                    f"plugin active `{np.get('listener_stats_held', {}).get('active_connections')}`; "
                    f"HGM ConnUsed `{np.get('hgm_held', {}).get('ConnUsed')}`.")
    lines += ["", "## Resource scopes and limitations", "",
              "- Proxy CPU/RSS/fds/threads cover the whole daemon PID; database CPU is the "
              "whole mysqld PID or PostgreSQL postmaster PID only (forked backend CPU excluded).",
              "- Client CPU is a live-sampled estimate and can miss startup/exit ticks.",
              "- PostgreSQL fast-forward HGM byte counters are zero on this host; raw application "
              "results and native plugin wire counters remain separate.",
              "- No wire relay capacity, general SQL capacity or causal claim is made.", ""]
    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    if (report.get("workload") or {}).get("workload") == "select1":
        return render_select1_markdown(report)
    title = ("Tiny smoke: native mapped TCP vs permanent SQL fast-forward"
             if report.get("profile") == "smoke"
             else "Native mapped TCP vs permanent SQL fast-forward")
    manifest = report.get("manifest") or {}
    workload = report.get("workload") or {}
    lines = [f"# {title}", "", f"Status: **{report.get('status', 'unknown')}**",
             "", f"Generated: `{report.get('generated_utc')}`", "",
             f"Profile: `{report.get('profile')}`", "",
             "This report is generated from real task-owned MySQL and PostgreSQL "
             "servers and immutable benchmarked binaries. The smoke profile is "
             "not a measurement and must not be interpreted as benchmark results.",
             "", "## Workload", "",
             f"- Rounds: {workload.get('rounds')}; clients: {workload.get('clients')}; "
             f"warmups/client: {workload.get('warmups_per_client')}; "
             f"RTT samples/client: {workload.get('rtt_samples_per_client')}.",
             f"- Requested phase duration: {workload.get('phase_seconds')} s; "
             f"throughput payloads: {workload.get('throughput_payload_bytes')} bytes.",
             f"- Order rotation: `{workload.get('order_rotation')}`.",
             f"- Smoke label: {workload.get('smoke_label') or 'none (measured profile)'}.",
             "", "## Provenance", ""]
    for key in ("host", "plugin", "client"):
        item = manifest.get(key) or {}
        lines.append(f"- {key}: `{item.get('path')}` sha256 `{item.get('sha256')}`")
    build = manifest.get("build") or {}
    if build:
        lines += ["", "Build/library evidence:", "",
                  f"- Compiler: `{build.get('cxx')}` {manifest.get('compiler')}",
                  f"- Flags: `{build.get('cxxflags')}`",
                  f"- Include flags: `{build.get('cppflags')}`",
                  f"- Link inputs: `{build.get('ldlibs')}`",
                  f"- Linked client library versions: `{manifest.get('client', {}).get('library_versions')}`",
                  f"- Host: `{manifest.get('host_info')}`"]
    provenance = manifest.get("source_provenance") or {}
    if provenance:
        lines += ["", "Source/host provenance references:", ""]
        for path, item in sorted(provenance.items()):
            lines.append(f"- `{path}` sha256 `{item.get('sha256')}`")
    lines += ["", "## Per-trial values (all rounds)", "",
              "| Proto | Round | Path | RTT p50/p95/p99 (us) | Conn/s | 64K q/s | 64K MiB/s | "
              "1M q/s | 1M MiB/s | requested/actual s |",
              "|---|---:|---|---|---:|---:|---:|---:|---:|---|"]
    def fmt(value, scale=1.0, digits=3):
        if value is None:
            return ""
        return f"{float(value) / scale:.{digits}f}"
    for protocol, proto in report.get("protocols", {}).items():
        for round_record in proto.get("rounds", []):
            for path in ("direct", "native", "ff"):
                trial = round_record.get("trials", {}).get(path)
                if not trial:
                    continue
                phases = trial.get("phases", {})
                rtt = phases.get("rtt64", {}).get("native_result", {})
                conn = phases.get("connections", {}).get("native_result", {})
                small = phases.get("throughput64k", {}).get("native_result", {})
                large = phases.get("throughput1m", {}).get("native_result", {})
                rtt_text = "/".join(fmt(rtt.get(k), 1000.0, 1)
                                    for k in ("p50_ns", "p95_ns", "p99_ns"))
                lines.append(
                    f"| {protocol} | {round_record.get('round')} | {path} | "
                    f"{rtt_text} | {fmt(conn.get('connections_per_s'), 1, 1)} | "
                    f"{fmt(small.get('queries_per_s'), 1, 1)} | "
                    f"{fmt(small.get('application_response_mib_per_s'))} | "
                    f"{fmt(large.get('queries_per_s'), 1, 1)} | "
                    f"{fmt(large.get('application_response_mib_per_s'))} | "
                    f"{fmt(conn.get('requested_duration_s'), 1, 2)}/"
                    f"{fmt(conn.get('actual_elapsed_s'), 1, 2)} |")
    lines += ["", "## Median and range across rounds", "",
              "| Proto | Path | RTT p50 us | RTT p95 us | RTT p99 us | Conn/s | "
              "64K q/s | 64K MiB/s | 1M q/s | 1M MiB/s |",
              "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    def med_range(data, name, scale=1.0):
        item = data.get(name) or {}
        if item.get("median") is None:
            return ""
        return (f"{float(item['median']) / scale:.1f} "
                f"[{float(item['min']) / scale:.1f}-{float(item['max']) / scale:.1f}]")
    for protocol, proto in report.get("protocols", {}).items():
        for path in ("direct", "native", "ff"):
            data = proto.get("summary", {}).get(path, {})
            lines.append(
                f"| {protocol} | {path} | {med_range(data, 'rtt_p50_ns', 1000)} | "
                f"{med_range(data, 'rtt_p95_ns', 1000)} | "
                f"{med_range(data, 'rtt_p99_ns', 1000)} | "
                f"{med_range(data, 'connections_per_s')} | "
                f"{med_range(data, 'throughput64k_qps')} | "
                f"{med_range(data, 'throughput64k_mib_s')} | "
                f"{med_range(data, 'throughput1m_qps')} | "
                f"{med_range(data, 'throughput1m_mib_s')} |")
    lines += ["", "## Configuration/auth/TLS evidence", ""]
    for protocol, proto in report.get("protocols", {}).items():
        fixture = proto.get("fixture") or {}
        lines.append(f"- {protocol} fixture: `{fixture.get('kind')}` "
                     f"{fixture.get('version')} auth=`{fixture.get('auth_plugin') or fixture.get('host_auth')}`.")
        for round_record in proto.get("rounds", []):
            for path in ("native", "ff"):
                trial = round_record.get("trials", {}).get(path)
                if not trial:
                    continue
                cfg = trial.get("daemon_config") or {}
                verify = trial.get("verify") or {}
                lines.append(
                    f"- {protocol} round {round_record.get('round')} {path}: "
                    f"sql_threads=`{cfg.get('sql_threads')}` tcp_workers=`{cfg.get('tcp_settings')}` "
                    f"user=`{cfg.get('user_row')}` source=`{cfg.get('server_row')}` "
                    f"pgsql_auth=`{cfg.get('pgsql_authentication_method')}` "
                    f"tls=`{verify.get('tls_used')}` ssl_cipher=`{verify.get('ssl_cipher')}` "
                    f"gss=`{verify.get('gssenc_in_use')}` tcp_nodelay=`{verify.get('tcp_nodelay')}`.")
    lines += ["", "## Wire counters versus application payload", "",
              "Application bytes below come from verified native-client queries. HGM/TCP "
              "wire counters include authentication, SQL text and protocol framing and "
              "are never expected to equal payload bytes. Native paths expose plugin TCP "
              "and HGM counters; this immutable host exposes zero HGM byte counters for "
              "fast-forward sessions, so those zeros are recorded rather than substituted.", "",
              "| Proto | Round | Path | Phase | App response bytes | HGM sent/recv delta | TCP wire c2s/s2c delta |",
              "|---|---:|---|---|---:|---|---|"]
    for protocol, proto in report.get("protocols", {}).items():
        for round_record in proto.get("rounds", []):
            for path in ("direct", "native", "ff"):
                trial = round_record.get("trials", {}).get(path)
                if not trial:
                    continue
                for phase_name in ("rtt64", "connections", "throughput64k", "throughput1m"):
                    phase = trial.get("phases", {}).get(phase_name, {})
                    result = phase.get("native_result") or {}
                    hgm = phase.get("hgm_delta") or {}
                    wire = phase.get("wire_delta") or {}
                    app = (result.get("application_response_bytes") or
                           (int(result.get("samples_per_client", 0)) *
                            int(result.get("clients", 0)) * 64 if phase_name == "rtt64" else
                            (int(result.get("cycles", 0)) * 64 if phase_name == "connections" else 0)))
                    lines.append(
                        f"| {protocol} | {round_record.get('round')} | {path} | {phase_name} | "
                        f"{app} | {hgm.get('Bytes_data_sent')}/{hgm.get('Bytes_data_recv')} | "
                        f"{wire.get('bytes_client_to_server')}/{wire.get('bytes_server_to_client')} |")
    lines += ["", "## Active proof", ""]
    for protocol, proto in report.get("protocols", {}).items():
        for round_record in proto.get("rounds", []):
            ff = round_record.get("trials", {}).get("ff")
            if ff and ff.get("ff_proof"):
                proof = ff["ff_proof"]
                lines.append(
                    f"- {protocol} round {round_record['round']} FF: "
                    f"`{proof.get('evidence_file')}`; command "
                    f"`{_field(proof, 'command')}`; cli_port "
                    f"`{proof.get('cli_port')}`; runtime fast_forward "
                    f"`{proof.get('runtime_row', {}).get('fast_forward')}`; "
                    f"status `{proof.get('status')}`.")
            native = round_record.get("trials", {}).get("native")
            if native and native.get("native_proof"):
                np = native["native_proof"]
                lines.append(
                    f"- {protocol} round {round_record['round']} native: "
                    f"`{np.get('evidence_file')}`; held cli_port `{np.get('cli_port')}`; "
                    f"SQL processlist matches `{np.get('frontend_sql_processlist_match_count')}`; "
                    f"plugin active `{np.get('listener_stats_held', {}).get('active_connections')}`; "
                    f"HGM ConnUsed `{np.get('hgm_held', {}).get('ConnUsed')}`.")
    lines += ["", "## Resource summary", "",
              "| Proto | Round | Path | Proxy CPU% | Proxy RSS KB | Proxy fd/thread | "
              "DB CPU% | DB RSS KB | Client CPU% | Client RSS KB |",
              "|---|---:|---|---:|---:|---|---:|---:|---:|---:|"]
    for protocol, proto in report.get("protocols", {}).items():
        for round_record in proto.get("rounds", []):
            for path in ("direct", "native", "ff"):
                trial = round_record.get("trials", {}).get(path)
                if not trial:
                    continue
                phase_values = [trial.get("phases", {}).get(name, {}) for name in
                                ("rtt64", "connections", "throughput64k", "throughput1m")]
                proxy_deltas = [p.get("resources", {}).get("proxy", {}).get("delta") or {}
                                for p in phase_values]
                db_deltas = [p.get("resources", {}).get("database", {}).get("delta") or {}
                             for p in phase_values]
                client_samples = [p.get("resources", {}).get("client", {}).get("sampled") or {}
                                  for p in phase_values]
                proxy_cpu = [v.get("cpu_percent") for v in proxy_deltas
                             if v.get("cpu_percent") is not None]
                db_cpu = [v.get("cpu_percent") for v in db_deltas
                          if v.get("cpu_percent") is not None]
                client_cpu = [v.get("cpu_percent") for v in client_samples
                              if v.get("cpu_percent") is not None]
                def stat(values, reducer=statistics.median, digits=1):
                    return "" if not values else f"{reducer(values):.{digits}f}"
                lines.append(
                    f"| {protocol} | {round_record.get('round')} | {path} | "
                    f"{stat(proxy_cpu)} | {max([v.get('rss_kb_endpoint_max', -1) for v in proxy_deltas] or [-1])} | "
                    f"{max([v.get('fds_endpoint_max', -1) for v in proxy_deltas] or [-1])}/"
                    f"{max([v.get('threads_endpoint_max', -1) for v in proxy_deltas] or [-1])} | "
                    f"{stat(db_cpu)} | {max([v.get('rss_kb_endpoint_max', -1) for v in db_deltas] or [-1])} | "
                    f"{stat(client_cpu)} | {max([v.get('rss_kb_peak', -1) for v in client_samples] or [-1])} |")
    lines += ["", "## Resource scopes and limitations", "",
              "- Proxy resources cover the whole ProxySQL daemon PID; database resources "
              "cover the whole mysqld PID or PostgreSQL postmaster PID only, so PostgreSQL "
              "forked backend CPU is not included.",
              "- Client CPU is a bounded live-sampled estimate (50 ms) and can miss "
              "startup/exit ticks. RSS/fd/thread endpoint maxima are named explicitly.",
              "- Byte equality to application payload is not required or used for HGM/TCP "
              "wire counters.",
              "- No winner or production-capacity claim is made from these workloads.", ""]
    return "\n".join(lines)


def write_report(experiment: Experiment, report: dict, stem: str) -> tuple[Path, Path]:
    json_path = experiment.run_dir / f"{stem}.json"
    md_path = experiment.run_dir / f"{stem}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    md_path.write_text(render_markdown(report) + "\n")
    return json_path, md_path


def run_experiment(args: argparse.Namespace, *, smoke: bool) -> int:
    profile = "smoke" if smoke else "measure"
    if not smoke:
        marker = Path(args.measurement_ready)
        if not marker.is_file():
            raise RunnerError(
                f"refusing full measurement: {marker} is absent; review smoke proof "
                "and obtain quiet-window approval first")
        try:
            marker_data = json.loads(marker.read_text())
            if marker_data.get("ready") is False:
                raise RunnerError(f"measurement marker is not ready: {marker}")
        except json.JSONDecodeError as exc:
            raise RunnerError(f"invalid measurement marker {marker}: {exc}") from exc

    configured = argparse.Namespace(**vars(args))
    if not smoke and configured.workload == "select1":
        if configured.warmups == 20:
            configured.warmups = 100
        if configured.phase_seconds == 2.0:
            configured.phase_seconds = 5.0
    if smoke:
        configured.clients = min(args.clients, 2)
        configured.warmups = min(args.warmups, 2)
        configured.samples = min(args.samples, 5)
        configured.phase_seconds = min(args.phase_seconds, 0.5)
        configured.rounds = 1
    experiment = Experiment(configured, profile)
    report: dict[str, Any] = {
        "kind": "tcp-fast-forward-comparison",
        "schema": 1,
        "status": "SMOKE" if smoke else "MEASURED",
        "profile": profile,
        "generated_utc": utc_now(),
        "work_dir": str(experiment.work_dir),
        "run_dir": str(experiment.run_dir),
        "workload_name": configured.workload,
        "sql": "SELECT 1" if configured.workload == "select1" else None,
        "expected_result": "1" if configured.workload == "select1" else None,
        "manifest": experiment.manifest,
        "workload": {
            "rounds": configured.rounds,
            "clients": configured.clients,
            "warmups_per_client": configured.warmups,
            "rtt_samples_per_client": configured.samples,
            "workload": configured.workload,
            "sql": "SELECT 1" if configured.workload == "select1" else None,
            "expected_result": "1" if configured.workload == "select1" else None,
            "rtt_payload_bytes": 1 if configured.workload == "select1" else 64,
            "phase_seconds": configured.phase_seconds,
            "throughput_payload_bytes": ([] if configured.workload == "select1"
                                         else [65536, 1048576]),
            "phase_keys": (["rtt_select1", "connections", "select1_qps"]
                           if configured.workload == "select1"
                           else ["rtt64", "connections", "throughput64k", "throughput1m"]),
            "timeout_ms": configured.timeout_ms,
            "order_rotation": [
                ["direct", "native", "ff"],
                ["native", "ff", "direct"],
                ["ff", "direct", "native"],
            ][:configured.rounds],
            "smoke_label": (
                ("TINY SMOKE ONLY: one round, two clients, two warmups, five "
                 "SELECT 1 RTT samples, 0.5s phases; never a measurement")
                if smoke and configured.workload == "select1" else
                ("TINY SMOKE ONLY: one round, two clients, two warmups, five RTT "
                 "samples, 0.5s phases; never a measurement" if smoke else None)),
        },
        "protocols": {},
        "errors": [],
        "cleanup": None,
    }
    try:
        fixtures_dir = experiment.run_dir / "fixtures"
        mysql_fixture = MysqlFixture(
            fixtures_dir / "mysql", Path(configured.mysql), Path(configured.mysqld))
        experiment.fixtures.append(mysql_fixture)
        mysql_fixture.start()
        pg_fixture = PgFixture(fixtures_dir / "pgsql", Path(configured.pg_bin))
        experiment.fixtures.append(pg_fixture)
        pg_fixture.start()
        report["fixtures"] = {
            "mysql": mysql_fixture.record(),
            "pgsql": pg_fixture.record(),
        }
        for protocol, fixture in (("mysql", mysql_fixture), ("pgsql", pg_fixture)):
            report["protocols"][protocol] = run_protocol(
                experiment, protocol, fixture, clients=configured.clients,
                warmups=configured.warmups, samples=configured.samples,
                phase_seconds=configured.phase_seconds,
                timeout_ms=configured.timeout_ms, rounds=configured.rounds,
                workload=configured.workload)
        experiment.verify_frozen()
        report["status"] = "SMOKE-PASS" if smoke else "MEASURED"
    except Exception as exc:  # noqa: BLE001 - report the real blocker
        report["status"] = "SMOKE-FAIL" if smoke else "MEASURE-FAIL"
        report["errors"].append({
            "type": type(exc).__name__,
            "message": clip(exc),
            "traceback": redact(traceback.format_exc()),
        })
    finally:
        report["cleanup"] = experiment.cleanup()
        json_path, md_path = write_report(
            experiment, report, "smoke" if smoke else "measurement")
        report["json_report"] = str(json_path)
        report["markdown_report"] = str(md_path)
        # Rewrite after adding report paths.
        json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        md_path.write_text(render_markdown(report) + "\n")
    print(f"report: {report.get('json_report')}")
    print(f"markdown: {report.get('markdown_report')}")
    if report["errors"]:
        for error in report["errors"]:
            print(f"ERROR: {error['type']}: {error['message']}", file=sys.stderr)
        return 1
    print(f"status: {report['status']}")
    return 0


# ---------------------------------------------------------------------------
# Selfcheck: real negative credential/payload/timeout plus FF-proof refusal
# ---------------------------------------------------------------------------


def proof_fixture(protocol: str, *, command: str = "Fast forward",
                  fast_forward: str = "1", status: str = "22",
                  cli_port: str = "41000", runtime_flag: str = "1",
                  runtime_active: str = "1", hostgroup: str = "101",
                  expected_hostgroup: str = "101",
                  processlist_port: Optional[str] = None,
                  match_count: int = 1) -> dict:
    fields = {"cli_port": processlist_port if processlist_port is not None else cli_port,
              "command": command}
    return {
        "protocol": protocol,
        "cli_port": cli_port,
        "expected_hostgroup": int(expected_hostgroup),
        "match_count": match_count,
        "processlist_fields": fields,
        "fast_forward": fast_forward,
        "status": status,
        "runtime_row": {"active": runtime_active, "fast_forward": runtime_flag,
                        "frontend": "1", "default_hostgroup": hostgroup},
    }


def run_selfcheck(args: argparse.Namespace) -> int:
    checks: list[dict] = []
    work_dir = Path(args.work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    client = BenchClient(Path(args.client))
    fixtures: list[Any] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": clip(detail)})

    try:
        check("host executable", Path(args.proxysql).is_file() and os.access(args.proxysql, os.X_OK),
              args.proxysql)
        check("plugin present", Path(args.plugin).is_file(),
              args.plugin)
        help_cp = run_process([str(args.client), "--help"], timeout=10)
        check("native client --help", help_cp.returncode == 0 and "Modes:" in help_cp.stdout,
              help_cp.stdout[:200])
        check("client executable", Path(args.client).is_file() and os.access(args.client, os.X_OK),
              args.client)

        mysql_positive = proof_fixture("mysql")
        check("FF refusal: MySQL positive proof", validate_ff_proof("mysql", mysql_positive) == [],
              str(validate_ff_proof("mysql", mysql_positive)))
        mysql_wrong_command = proof_fixture("mysql", command="Query")
        check("FF refusal: MySQL non-FF command rejected",
              bool(validate_ff_proof("mysql", mysql_wrong_command)))
        mysql_wrong_flag = proof_fixture("mysql", fast_forward="0")
        check("FF refusal: MySQL fast_forward=0 rejected",
              bool(validate_ff_proof("mysql", mysql_wrong_flag)))
        pg_positive = proof_fixture("pgsql", fast_forward=None)
        check("FF refusal: PostgreSQL status22 positive (missing JSON key expected)",
              validate_ff_proof("pgsql", pg_positive) == [],
              str(validate_ff_proof("pgsql", pg_positive)))
        pg_wrong_status = proof_fixture("pgsql", fast_forward=None, status="21")
        check("FF refusal: PostgreSQL status21 rejected",
              bool(validate_ff_proof("pgsql", pg_wrong_status)))
        missing_port = proof_fixture("mysql", cli_port="")
        check("FF refusal: missing client port rejected",
              bool(validate_ff_proof("mysql", missing_port)))
        wrong_port = proof_fixture("mysql", processlist_port="41001")
        check("FF refusal: wrong processlist cli_port rejected",
              bool(validate_ff_proof("mysql", wrong_port)))
        wrong_hg = proof_fixture("mysql", hostgroup="999", expected_hostgroup="101")
        check("FF refusal: wrong runtime hostgroup rejected",
              bool(validate_ff_proof("mysql", wrong_hg)))
        wrong_active = proof_fixture("mysql", runtime_active="0")
        check("FF refusal: inactive runtime frontend rejected",
              bool(validate_ff_proof("mysql", wrong_active)))
        duplicate = proof_fixture("mysql", match_count=2)
        check("FF refusal: non-unique processlist match rejected",
              bool(validate_ff_proof("mysql", duplicate)))

        round_root = work_dir / f"selfcheck-{os.getpid()}" / "round-dirs"
        round_dirs = []
        for round_index in range(3):
            for path in ("direct", "native", "ff"):
                directory = trial_directory(round_root, "mysql", round_index, path)
                directory.mkdir(parents=True, exist_ok=True)
                (directory / "sentinel.txt").write_text(
                    f"{round_index}:{path}\n")
                round_dirs.append(directory)
        unique_round_dirs = len(set(round_dirs)) == 9 and all(
            (directory / "sentinel.txt").is_file() for directory in round_dirs)
        check("three-round trial directories are unique", unique_round_dirs,
              str([str(path) for path in round_dirs]))

        fixtures_dir = work_dir / f"selfcheck-{os.getpid()}" / "fixtures"
        mysql_fixture = MysqlFixture(
            fixtures_dir / "mysql", Path(args.mysql), Path(args.mysqld))
        fixtures.append(mysql_fixture)
        mysql_fixture.start()
        pg_fixture = PgFixture(fixtures_dir / "pgsql", Path(args.pg_bin))
        fixtures.append(pg_fixture)
        pg_fixture.start()
        for protocol, fixture in (("mysql", mysql_fixture), ("pgsql", pg_fixture)):
            valid_dir = work_dir / f"selfcheck-{os.getpid()}" / protocol
            valid_dir.mkdir(parents=True, exist_ok=True)
            valid = client.invoke(fixture, fixture.port, "verify",
                                  valid_dir / "valid.conf", payload_bytes=64,
                                  workload=args.workload)
            check(f"{protocol} positive direct verify",
                  valid.returncode == 0 and bool(valid.json and valid.json.get("ok")),
                  valid.stdout + valid.stderr)
            if valid.json:
                check(f"{protocol} observed TLS off",
                      not valid.json.get("tls_used") and not valid.json.get("ssl_cipher"),
                      json.dumps(valid.json))
                if args.workload == "select1":
                    check(f"{protocol} exact SELECT 1 workload evidence",
                          valid.json.get("workload") == "select1"
                          and valid.json.get("sql") == "SELECT 1"
                          and valid.json.get("expected_result") == "1"
                          and valid.json.get("payload_bytes") == 1,
                          json.dumps(valid.json))
            bad_conf = valid_dir / "bad.conf"
            fixture.client_config(bad_conf, fixture.port)
            text = bad_conf.read_text().replace("\n", "\n")
            # Change only the generated password value.
            lines = []
            for line in text.splitlines():
                if line.startswith("password="):
                    lines.append("password=wrong-" + line.split("=", 1)[1])
                else:
                    lines.append(line)
            write_private(bad_conf, "\n".join(lines) + "\n")
            bad = client.invoke(fixture, fixture.port, "verify",
                                valid_dir / "bad.conf", payload_bytes=64,
                                prepare_config=False, workload=args.workload)
            check(f"{protocol} wrong credentials rejected",
                  bad.returncode != 0 and not (bad.json or {}).get("ok"),
                  bad.stdout + bad.stderr)
            wrong = client.invoke(fixture, fixture.port, "verify",
                                  valid_dir / "wrong-payload.conf", payload_bytes=64,
                                  corrupt_expectation=True, workload=args.workload)
            check(f"{protocol} wrong payload rejected",
                  wrong.returncode != 0 and "mismatch" in (wrong.stdout + wrong.stderr).lower(),
                  wrong.stdout + wrong.stderr)
            timeout = client.invoke(
                fixture, fixture.port, "negative-timeout",
                valid_dir / "timeout.conf", payload_bytes=64, timeout_ms=200,
                negative_timeout=True, timeout=10, workload=args.workload)
            timeout_json = timeout.json or {}
            timeout_ok = (
                timeout.returncode == 0 and bool(timeout_json.get("timed_out"))
                and isinstance(timeout_json.get("elapsed_ms"), int)
                and 50 <= timeout_json["elapsed_ms"] <= timeout_json.get("timeout_bound_ms", 0)
                and timeout.duration_s < 4.5)
            check(f"{protocol} slow-query timeout specifically propagated",
                  timeout_ok, timeout.stdout + timeout.stderr)
            completed = client.invoke(
                fixture, fixture.port, "negative-timeout",
                valid_dir / "timeout-completed.conf", payload_bytes=64,
                timeout_ms=1000, negative_timeout=True,
                negative_timeout_completes=True, timeout=10,
                workload=args.workload)
            completed_json = completed.json or {}
            check(f"{protocol} completed/mismatched payload not counted as timeout",
                  completed.returncode != 0 and not completed_json.get("timed_out")
                  and "mismatch" in (completed.stdout + completed.stderr).lower(),
                  completed.stdout + completed.stderr)

            timing_payload = 1 if args.workload == "select1" else 4096
            timing = client.invoke(
                fixture, fixture.port, "throughput",
                valid_dir / "timing.conf", payload_bytes=timing_payload, warmups=1,
                clients=1, duration_seconds=0.25, timeout_ms=2000, timeout=20,
                workload=args.workload)
            timing_json = timing.json or {}
            actual = timing_json.get("actual_elapsed_s")
            queries = timing_json.get("queries")
            qps = timing_json.get("queries_per_s")
            arithmetic_ok = (
                timing.returncode == 0 and bool(timing_json.get("ok"))
                and isinstance(actual, (int, float)) and actual >= 0.25
                and isinstance(queries, int) and queries > 0
                and timing_json.get("application_response_bytes") == queries * timing_payload
                and timing_json.get("application_request_bytes") == queries * timing_payload
                and isinstance(qps, (int, float))
                and abs(qps - (queries / actual)) <= max(0.11, qps * 1e-5)
                and timing_json.get("tcp_nodelay") == 1
                and timing_json.get("gssenc_in_use") is False
                and not timing_json.get("error"))
            if args.workload == "select1":
                arithmetic_ok = arithmetic_ok and (
                    timing_json.get("workload") == "select1"
                    and timing_json.get("sql") == "SELECT 1"
                    and timing_json.get("expected_result") == "1")
            check(f"{protocol} measured elapsed/rate/application-byte arithmetic and zero-error",
                  arithmetic_ok, timing.stdout + timing.stderr)
            late = client.invoke(
                fixture, fixture.port, "connections",
                valid_dir / "late-error.conf", payload_bytes=64, clients=1,
                duration_seconds=0.2, timeout_ms=1000, timeout=10,
                inject_late_error_ms=350, workload=args.workload)
            check(f"{protocol} late worker error after requested deadline is not suppressed",
                  late.returncode != 0 and "injected late error" in
                  (late.stdout + late.stderr),
                  late.stdout + late.stderr)
    except Exception as exc:  # noqa: BLE001 - selfcheck reports the blocker
        checks.append({"name": "selfcheck execution", "ok": False,
                       "detail": clip(f"{type(exc).__name__}: {exc}"),
                       "traceback": redact(traceback.format_exc())})
    finally:
        cleanup: list[dict] = []
        for fixture in reversed(fixtures):
            try:
                cleanup.append(fixture.stop())
            except Exception as exc:  # noqa: BLE001
                cleanup.append({"error": clip(exc)})
    result = {
        "kind": "fast-forward-benchmark-selfcheck",
        "utc": utc_now(),
        "duration_s": round(time.monotonic() - started, 3),
        "workload": args.workload,
        "host_sha256": sha256_file(Path(args.proxysql)),
        "plugin_sha256": sha256_file(Path(args.plugin)),
        "client_sha256": sha256_file(Path(args.client)),
        "checks": checks,
        "cleanup": cleanup,
        "ok": all(item["ok"] for item in checks) and bool(checks),
    }
    path = work_dir / "selfcheck.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    result["path"] = str(path)
    for item in checks:
        print(("PASS " if item["ok"] else "FAIL ") + item["name"] +
              ("" if item["ok"] else ": " + item["detail"]))
    print(f"selfcheck: {path}")
    return 0 if result["ok"] else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def common_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--proxysql", default=str(DEFAULT_HOST),
                        help="immutable ProxySQL host binary")
    parser.add_argument("--plugin", default=str(DEFAULT_PLUGIN),
                        help="immutable tcp_proxy release DSO")
    parser.add_argument("--client", default=str(DEFAULT_CLIENT),
                        help="native fast_forward_bench_client binary")
    parser.add_argument("--mysql", default=str(DEFAULT_MYSQL),
                        help="system mysql CLI for Admin and fixture setup")
    parser.add_argument("--mysqld", default=str(DEFAULT_MYSQLD),
                        help="task-owned mysqld binary")
    parser.add_argument("--pg-bin", default=str(DEFAULT_PG_BIN),
                        help="PostgreSQL 16 bin directory")
    parser.add_argument("--deps", default=str(DEFAULT_DEPS),
                        help="read-only donor dependency root")
    parser.add_argument("--work-dir", default=str(DEFAULT_WORK_DIR),
                        help="task-owned scratch root")
    parser.add_argument("--workload", choices=("literal", "select1"),
                        default="literal",
                        help="literal default, or exact SELECT 1 workload")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Native mapped TCP vs permanent SQL fast-forward benchmark")
    sub = parser.add_subparsers(dest="command", required=True)

    selfcheck = sub.add_parser("selfcheck", help="negative/preflight checks")
    common_parser(selfcheck)

    smoke = sub.add_parser("smoke", help="tiny direct/native/FF smoke for both protocols")
    common_parser(smoke)
    add_workload_args(smoke)

    measure = sub.add_parser("measure", help="full design workload (marker required)")
    common_parser(measure)
    add_workload_args(measure)
    measure.add_argument("--measurement-ready",
                         default=str(DEFAULT_WORK_DIR / "measurement-ready.json"),
                         help="quiet-window approval marker")
    return parser


def add_workload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--warmups", type=int, default=20)
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--phase-seconds", type=float, default=2.0)
    parser.add_argument("--timeout-ms", type=int, default=2000)


def validate_args(args: argparse.Namespace) -> None:
    if getattr(args, "rounds", 1) < 1:
        raise RunnerError("--rounds must be >=1")
    if getattr(args, "clients", 1) < 1:
        raise RunnerError("--clients must be >=1")
    if getattr(args, "samples", 0) < 0 or getattr(args, "warmups", 0) < 0:
        raise RunnerError("sample/warmup counts must be >=0")
    if getattr(args, "phase_seconds", 1.0) <= 0:
        raise RunnerError("--phase-seconds must be >0")
    if hasattr(args, "timeout_ms") and args.timeout_ms < 100:
        raise RunnerError("--timeout-ms must be >=100")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_args(args)
        if args.command == "selfcheck":
            return run_selfcheck(args)
        if args.command == "smoke":
            return run_experiment(args, smoke=True)
        if args.command == "measure":
            return run_experiment(args, smoke=False)
        parser.error("unknown command")
    except RunnerError as exc:
        print(f"ERROR: {clip(exc)}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
