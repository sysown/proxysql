#!/usr/bin/env python3
"""Bounded STOP/START regressions against private daemons, without backends.

Usage: python3 test/infra/control/test_module_lifecycle.py [path/to/proxysql]
Requires Linux, Python 3, and the mysql and psql command-line clients. Each case owns its process,
loopback ports and temporary datadir; no running ProxySQL service is touched.
"""

import concurrent.futures
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[3]
BINARY = Path(os.environ.get("PROXYSQL_TEST_BINARY", REPO / "src/proxysql")).resolve()
if len(sys.argv) > 1 and not sys.argv[1].startswith("-") and not sys.argv[1].startswith("Lifecycle."):
    BINARY = Path(sys.argv.pop(1)).resolve()

DIAG_MARKER = "# VERSION_LIFETIME "
DIAG_VERSION_LIFETIME_ENV = "PROXYSQL_DIAG_VERSION_LIFETIME"
# Fixture-local opt-in for these private lifecycle daemons only: absent means
# "1" (enabled), explicit "1" is enabled, and an explicit "0" (or any other
# explicit non-"1" value, including empty) stays off. main.cpp keeps its own
# global default of off for daemons that do not receive this fixture env.
_DIAG_SETTING = os.environ.get(DIAG_VERSION_LIFETIME_ENV)
DIAG_ENABLED = _DIAG_SETTING is None or _DIAG_SETTING == "1"
DIAG_OPT_IN = DIAG_ENABLED
DIAG_MAX_BYTES = 256 * 1024
DIAG_MAX_LINES = 2000


def daemon_environment():
    """Inherited environment plus the effective flag; never rewrites proxy/ASAN vars."""
    environment = os.environ.copy()
    environment.setdefault(DIAG_VERSION_LIFETIME_ENV, "1")
    return environment


def emit_proxy_env_presence():
    """Print proxy env *names and presence only*, once, never their values."""
    names = ("http_proxy", "https_proxy", "all_proxy", "no_proxy",
             "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
    presence = " ".join(f"{name}={'present' if name in os.environ else 'absent'}" for name in names)
    print(f"{DIAG_MARKER}ENV {presence}", flush=True)


class Daemon:
    def __init__(self, no_start=False, extra_args=(), config_prefix="", no_monitor=True, monitor_enabled=False,
                 threads=(1, 1)):
        self.closed = False
        self.temporary = tempfile.TemporaryDirectory(prefix="proxysql-lifecycle-")
        self.directory = Path(self.temporary.name)
        # Reserve distinct ports together so one allocation cannot repeat another.
        reservations = [socket.socket() for _ in range(4)]
        try:
            for reservation in reservations:
                reservation.bind(("127.0.0.1", 0))
            self.admin, self.pgadmin, self.mysql, self.pgsql = [s.getsockname()[1] for s in reservations]
            config = self.directory / "proxysql.cfg"
            config.write_text(
                config_prefix + '\nplugins=();set_thread_name=true;\n'
                'admin_variables={admin_credentials="admin:admin";'
                f'mysql_ifaces="127.0.0.1:{self.admin}";pgsql_ifaces="127.0.0.1:{self.pgadmin}";'
                'refresh_interval=100;web_enabled=false;}\n'
                f'mysql_variables={{threads={threads[0]};interfaces="127.0.0.1:{self.mysql}";monitor_enabled={str(monitor_enabled).lower()};}}\n'
                f'pgsql_variables={{threads={threads[1]};interfaces="127.0.0.1:{self.pgsql}";monitor_enabled={str(monitor_enabled).lower()};}}\n'
            )
            fixtures = REPO / "test/tap/tests/test_cluster_sync_config/test_cluster_sync_nomonitor"
            for name in ("proxysql-ca.pem", "proxysql-cert.pem", "proxysql-key.pem"):
                shutil.copyfile(fixtures / name, self.directory / name)
        finally:
            for reservation in reservations:
                reservation.close()
        self.stops = 0
        self.marker_offset = 0
        self.log = (self.directory / "daemon.log").open("w+")
        args = [str(BINARY), "-f", "-c", str(config), "-D", str(self.directory)]
        if no_monitor:
            args.append("-M")
        if no_start:
            args.append("--no-start")
        self.args = args
        self.process = subprocess.Popen(self.args + list(extra_args), stdout=self.log, stderr=self.log,
                                        env=daemon_environment())

    def restart(self, extra_args=()):
        """Relaunch the same datadir, retaining saved configuration and ports."""
        self.shutdown()
        self.stops = 0
        self.extract_markers()
        self.log.seek(0)
        self.log.truncate()
        self.marker_offset = 0
        self.process = subprocess.Popen(self.args + list(extra_args), stdout=self.log, stderr=self.log,
                                        env=daemon_environment())

    def output(self):
        self.log.flush()
        return (self.directory / "daemon.log").read_text(errors="replace")

    def extract_markers(self, cleanup_safe=False):
        """Print only exact-prefix markers from daemon.log, bounded and deduplicated by offset."""
        if not DIAG_OPT_IN:
            return
        try:
            self.log.flush()
            emitted = 0
            consumed = 0
            truncated_reason = None
            with (self.directory / "daemon.log").open("rb") as handle:
                handle.seek(self.marker_offset)
                while consumed < DIAG_MAX_BYTES and emitted < DIAG_MAX_LINES:
                    line = handle.readline(DIAG_MAX_BYTES + 1)
                    if not line:
                        break
                    if len(line) > DIAG_MAX_BYTES:
                        self.marker_offset += consumed + len(line)
                        print(f"{DIAG_MARKER}DIAG_TRUNCATED oversized_line offset={self.marker_offset}", flush=True)
                        return
                    if not line.endswith(b"\n"):
                        break
                    if consumed + len(line) > DIAG_MAX_BYTES:
                        truncated_reason = f"byte_bound offset={self.marker_offset + consumed}"
                        break
                    consumed += len(line)
                    text = line.decode("utf-8", "replace").rstrip("\n")
                    if text.startswith(DIAG_MARKER):
                        print(text, flush=True)
                        emitted += 1
                at_bound = consumed >= DIAG_MAX_BYTES or emitted >= DIAG_MAX_LINES
            self.marker_offset += consumed
            if truncated_reason is None and at_bound:
                reason = "line_bound" if emitted >= DIAG_MAX_LINES else "byte_bound"
                truncated_reason = f"{reason} offset={self.marker_offset}"
            if truncated_reason is not None:
                print(f"{DIAG_MARKER}DIAG_TRUNCATED {truncated_reason}", flush=True)
        except Exception as error:
            if cleanup_safe:
                print(f"{DIAG_MARKER}DIAG_EXTRACT_ERROR {type(error).__name__}", flush=True)
            else:
                raise

    def query(self, sql, protocol="mysql", timeout=8, check=True):
        environment = os.environ.copy()
        if protocol == "mysql":
            args = ["mysql", "--no-defaults", "--protocol=tcp", "--connect-timeout=2", "--batch",
                    "--skip-column-names", "-h127.0.0.1", f"-P{self.admin}", "-uadmin", "-padmin", "-e", sql]
        else:
            environment["PGPASSWORD"] = "admin"
            environment["PGCONNECT_TIMEOUT"] = "2"
            args = ["psql", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1",
                    "-p", str(self.pgadmin), "-U", "admin", "-d", "admin", "-c", sql]
        result = subprocess.run(args, env=environment, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode:
            raise AssertionError(f"{protocol} {sql!r}: rc={result.returncode}: {result.stderr}\n{self.output()[-6000:]}")
        return result

    def ready(self, protocol="mysql", timeout=20):
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"daemon exited {self.process.returncode}\n{self.output()[-6000:]}")
            try:
                result = self.query("SELECT 1", protocol, timeout=3, check=False)
                if result.returncode == 0:
                    return
                last = result.stderr
            except subprocess.TimeoutExpired:
                last = "Admin query timed out"
            time.sleep(0.05)
        raise AssertionError(f"Admin did not become ready: {last}\n{self.output()[-6000:]}")

    def stop(self, protocol="mysql"):
        self.query("PROXYSQL STOP", protocol)
        self.stops += 1
        deadline = time.monotonic() + 15
        while self.output().count("Shutdown completed!") < self.stops:
            if self.process.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError(f"STOP did not finish\n{self.output()[-6000:]}")
            time.sleep(0.05)
        self.ready(protocol)

    def shutdown(self):
        self.process.send_signal(signal.SIGTERM)
        try:
            code = self.process.wait(timeout=15)
        except subprocess.TimeoutExpired as error:
            raise AssertionError(f"graceful shutdown timed out\n{self.output()[-6000:]}") from error
        if code != 0:
            raise AssertionError(f"daemon exited {code}\n{self.output()[-6000:]}")

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=4)
        self.extract_markers(cleanup_safe=True)
        self.log.close()
        self.temporary.cleanup()


class IsolatedDaemonTest(unittest.TestCase):
    def daemon(self, **kwargs):
        daemon = Daemon(**kwargs)
        self.addCleanup(daemon.close)
        daemon.ready()
        return daemon


class Lifecycle(IsolatedDaemonTest):
    def test_stopped_runtime_reads(self):
        # Each subcase gets its own process: a crash must not hide later failures.
        for protocol in ("mysql", "pgsql"):
            for table in ("runtime_mysql_query_rules", "runtime_mysql_query_rules_fast_routing",
                          "runtime_pgsql_query_rules", "runtime_pgsql_query_rules_fast_routing"):
                with self.subTest(protocol=protocol, table=table):
                    daemon = self.daemon(no_start=True)
                    try:
                        self.assertEqual(daemon.query(f"SELECT COUNT(*) FROM {table}", protocol).stdout.strip(), "0")
                    finally:
                        daemon.close()

    def test_stop_start_cycles(self):
        for protocol in ("mysql", "pgsql"):
            with self.subTest(protocol=protocol):
                daemon = self.daemon()
                for _ in range(2):
                    daemon.stop(protocol)
                    self.assertEqual(daemon.query("SELECT COUNT(*) FROM runtime_mysql_query_rules", protocol).stdout.strip(), "0")
                    daemon.query("LOAD MYSQL SERVERS TO RUNTIME", protocol)
                    daemon.query("LOAD PGSQL SERVERS TO RUNTIME", protocol)
                    daemon.query("PROXYSQL START", protocol)
                    daemon.ready(protocol)
                    daemon.query("SELECT COUNT(*) FROM runtime_pgsql_query_rules", protocol)

    def test_no_start_configuration_and_statistics(self):
        daemon = self.daemon(no_start=True)
        for protocol in ("mysql", "pgsql"):
            daemon.query("LOAD MYSQL SERVERS TO RUNTIME", protocol)
            daemon.query("LOAD PGSQL SERVERS TO RUNTIME", protocol)
            # Read the actual schemas, including the firewall and statistics
            # tables, rather than accepting invented empty result columns.
            for schema, pattern in (("main", "runtime_%"), ("stats", "stats_%")):
                names = daemon.query(
                    f"SELECT name FROM {schema}.sqlite_master WHERE type='table' AND name LIKE '{pattern}'",
                    protocol).stdout.splitlines()
                for name in names:
                    with self.subTest(protocol=protocol, table=name):
                        daemon.query(f'SELECT COUNT(*) FROM {schema}."{name}"', protocol)
            for dialect in ("MYSQL", "PGSQL"):
                daemon.query(f"TRUNCATE stats_{dialect.lower()}_query_digest", protocol)
                daemon.query(f"PURGE stats_{dialect.lower()}_query_digest TO 1", protocol)
                self.assertNotEqual(daemon.query(f"PURGE stats_{dialect.lower()}_query_digest TO 0",
                                                protocol, check=False).returncode, 0)
        daemon.query("INSERT INTO mysql_query_rules (rule_id,active) VALUES (5186,1)")
        self.assertNotEqual(daemon.query("SAVE MYSQL QUERY RULES FROM RUNTIME", check=False).returncode, 0)
        self.assertEqual(daemon.query("SELECT COUNT(*) FROM mysql_query_rules WHERE rule_id=5186").stdout.strip(), "1")

    def test_stopped_runtime_saves_report_errors(self):
        for after_stop in (False, True):
            daemon = self.daemon(no_start=not after_stop)
            if after_stop:
                daemon.stop()
            for protocol in ("mysql", "pgsql"):
                for dialect in ("MYSQL", "PGSQL"):
                    for module in ("QUERY RULES", "FIREWALL"):
                        for operation in ("FROM RUNTIME", "FROM RUN", "TO MEMORY", "TO MEM"):
                            query = f"SAVE {dialect} {module} {operation}"
                            with self.subTest(stopped=after_stop, protocol=protocol, query=query):
                                result = daemon.query(query, protocol, check=False)
                                self.assertNotEqual(result.returncode, 0, query)
                                self.assertIn("Query Processor not started", result.stderr)
            daemon.query("PROXYSQL START")
            for protocol in ("mysql", "pgsql"):
                for dialect in ("MYSQL", "PGSQL"):
                    for module in ("QUERY RULES", "FIREWALL"):
                        daemon.query(f"SAVE {dialect} {module} FROM RUNTIME", protocol)
            daemon.close()

    def test_start_preserves_statistics_refresh(self):
        daemon = self.daemon(no_start=True)
        daemon.query("INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup) VALUES (5217,1,'^SELECT',0)")
        daemon.query("PROXYSQL START")
        self.assertEqual(daemon.query("SELECT COUNT(*) FROM runtime_mysql_query_rules WHERE rule_id=5217").stdout.strip(), "1")
        daemon.query("DELETE FROM mysql_query_rules")
        daemon.query("LOAD MYSQL QUERY RULES TO RUNTIME")
        self.assertEqual(daemon.query("SELECT COUNT(*) FROM runtime_mysql_query_rules").stdout.strip(), "0")

    def test_no_start_metrics(self):
        daemon = self.daemon(no_start=True)
        self.assertIn("proxysql_uptime", daemon.query("SHOW PROMETHEUS METRICS").stdout)

    def test_stop_with_concurrent_readers(self):
        daemon = self.daemon()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(daemon.query, "SELECT COUNT(*) FROM runtime_mysql_query_rules", protocol,
                                   check=False) for protocol in ("mysql", "pgsql")]
            daemon.stop()
            for future in futures:
                # Reload may close a client; it must finish and the daemon must recover.
                future.result(timeout=10)
        daemon.ready()
        daemon.query("PROXYSQL START")
        daemon.ready()


def run_probe_tests():
    if DIAG_OPT_IN:
        emit_proxy_env_presence()
    missing = [tool for tool in ("mysql", "psql") if shutil.which(tool) is None]
    if sys.platform != "linux" or missing:
        reason = "Linux is required" if sys.platform != "linux" else "missing " + ", ".join(missing)
        print(f"SKIP: private daemon probes: {reason}", file=sys.stderr)
        raise SystemExit(77)
    unittest.main(verbosity=2)


if __name__ == "__main__":
    run_probe_tests()
