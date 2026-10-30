#!/usr/bin/env python3
"""Selective module startup regressions. Uses private daemons only.

Usage: python3 test/infra/control/test_module_startup.py [path/to/proxysql]
"""
from pathlib import Path
import socket
import time

from test_module_lifecycle import Daemon, IsolatedDaemonTest, run_probe_tests


class ModuleStartup(IsolatedDaemonTest):
    def test_disabled_workers_preserve_saved_thread_counts(self):
        daemon = self.daemon(threads=(3, 5), extra_args=(
            "--mysql-workers=false", "--pgsql-workers=false"))
        self.expect_started(daemon, False, False)
        # Saving a disabled component must retain its configured positive count.
        # Test both flushers: PostgreSQL replaces the entire variable set.
        for dialect, label, count in (("mysql", "MySQL", "3"), ("pgsql", "PgSQL", "5")):
            with self.subTest(dialect=dialect):
                daemon.query(f"SAVE {dialect.upper()} VARIABLES FROM RUNTIME")
                daemon.query(f"SAVE {dialect.upper()} VARIABLES TO DISK")
                for table in ("global_variables", "runtime_global_variables", "disk.global_variables"):
                    self.assertEqual(daemon.query(f"SELECT variable_value FROM {table} "
                        f"WHERE variable_name='{dialect}-threads'").stdout.strip(), count)
                self.assertEqual(daemon.query(f"SELECT Variable_Value FROM stats_{dialect}_global "
                    f"WHERE Variable_Name='{label}_Thread_Workers'").stdout.strip(), "0")
        daemon.stop()
        daemon.query("PROXYSQL START")
        self.expect_started(daemon, False, False)
        # No --initial: the saved database is authoritative on this relaunch.
        daemon.restart()
        daemon.ready()
        self.expect_started(daemon, True, True)
        for dialect, label, count in (("mysql", "MySQL", "3"), ("pgsql", "PgSQL", "5")):
            with self.subTest(restarted=dialect):
                self.assertEqual(daemon.query("SELECT variable_value FROM runtime_global_variables "
                    f"WHERE variable_name='{dialect}-threads'").stdout.strip(), count)
                self.assertEqual(daemon.query(f"SELECT Variable_Value FROM stats_{dialect}_global "
                    f"WHERE Variable_Name='{label}_Thread_Workers'").stdout.strip(), count)
        daemon.shutdown()

    def listening(self, port):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            return False

    def expect_workers(self, daemon, mysql_workers, pgsql_workers):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if (self.listening(daemon.mysql) == mysql_workers and
                    self.listening(daemon.pgsql) == pgsql_workers):
                return
            self.assertIsNone(daemon.process.poll(), daemon.output()[-3000:])
            time.sleep(0.05)
        self.fail(f"worker listeners did not reach expected state\n{daemon.output()[-6000:]}")

    def expect_started(self, daemon, mysql_workers=True, pgsql_workers=True,
                       mysql_admin=True, pgsql_admin=True):
        # Wait for the new phase 3 even when both worker stacks are disabled.
        # Otherwise an old Admin listener could satisfy the assertion during reload.
        expected_starts = daemon.stops + 1
        deadline = time.monotonic() + 10
        expected = ((daemon.mysql, mysql_workers), (daemon.pgsql, pgsql_workers),
                    (daemon.admin, mysql_admin), (daemon.pgadmin, pgsql_admin))
        while time.monotonic() < deadline:
            if (daemon.output().count("For online documentation") >= expected_starts and
                    all(self.listening(port) == enabled for port, enabled in expected)):
                return
            self.assertIsNone(daemon.process.poll(), daemon.output()[-3000:])
            time.sleep(0.05)
        self.fail(f"START did not preserve worker/Admin listener permissions\n{daemon.output()[-6000:]}")

    def test_worker_admin_combinations(self):
        import itertools
        for mysql_workers, pgsql_workers, mysql_admin, pgsql_admin in itertools.product((False, True), repeat=4):
            with self.subTest(workers=(mysql_workers, pgsql_workers), admin=(mysql_admin, pgsql_admin)):
                args = [f"--{name}={str(value).lower()}" for name, value in (
                    ("mysql-workers", mysql_workers), ("pgsql-workers", pgsql_workers),
                    ("mysql-admin", mysql_admin), ("pgsql-admin", pgsql_admin))]
                daemon = Daemon(extra_args=args + ["--idle-threads"])
                self.addCleanup(daemon.close)
                protocol = "mysql" if mysql_admin else "pgsql"
                try:
                    if mysql_admin or pgsql_admin:
                        daemon.ready(protocol)
                        for dialect in ("mysql", "pgsql"):
                            value = daemon.query("SELECT variable_value FROM runtime_global_variables "
                                f"WHERE variable_name='{dialect}-threads'", protocol).stdout.strip()
                            self.assertEqual(value, "1")
                    else:
                        deadline = time.monotonic() + 15
                        while "For online documentation" not in daemon.output() and time.monotonic() < deadline:
                            self.assertIsNone(daemon.process.poll(), daemon.output()[-2000:])
                            time.sleep(0.05)
                        self.assertIn("For online documentation", daemon.output())
                    self.expect_started(daemon, mysql_workers, pgsql_workers, mysql_admin, pgsql_admin)
                    tasks = Path(f"/proc/{daemon.process.pid}/task")
                    if tasks.is_dir():
                        names = []
                        for path in tasks.glob("*/comm"):
                            try:
                                names.append(path.read_text().strip())
                            except FileNotFoundError:
                                # Transient tasks can exit between enumeration and open.
                                continue
                        for dialect, enabled in (("MySQL", mysql_workers), ("PgSQL", pgsql_workers)):
                            workers = [n for n in names if n.startswith((dialect + "Worker", dialect + "Idle"))]
                            self.assertEqual(bool(workers), enabled, names)
                    if mysql_admin or pgsql_admin:
                        daemon.stop(protocol)
                        daemon.query("LOAD MYSQL SERVERS TO RUNTIME", protocol)
                        daemon.query("LOAD PGSQL SERVERS TO RUNTIME", protocol)
                        daemon.query("PROXYSQL START", protocol)
                        daemon.ready(protocol)
                        self.expect_started(daemon, mysql_workers, pgsql_workers, mysql_admin, pgsql_admin)
                    daemon.shutdown()
                finally:
                    daemon.close()

    def test_cli_config_precedence(self):
        for value in (False, True):
            with self.subTest(cli=value):
                daemon = self.daemon(config_prefix=f'mysql-workers={str(not value).lower()};\n',
                                     extra_args=(f'--mysql-workers={str(value).lower()}',))
                self.assertEqual(daemon.query("SELECT variable_value FROM runtime_global_variables "
                                 "WHERE variable_name='mysql-threads'").stdout.strip(), "1")
                self.expect_started(daemon, value, True)
                daemon.close()

    def test_separate_and_numeric_cli_values(self):
        daemon = self.daemon(extra_args=("--mysql-workers", "0", "--pgsql-workers", "0", "--pgsql-admin", "1"))
        self.expect_started(daemon, False, False)
        for dialect in ("mysql", "pgsql"):
            self.assertEqual(daemon.query("SELECT variable_value FROM runtime_global_variables "
                f"WHERE variable_name='{dialect}-threads'").stdout.strip(), "1")
        daemon.shutdown()

    def test_invalid_configuration_boolean(self):
        daemon = Daemon(config_prefix='mysql-workers="false";\n')
        self.addCleanup(daemon.close)
        self.assertNotEqual(daemon.process.wait(timeout=8), 0)
        self.assertIn("mysql-workers", daemon.output())

    def test_initial_no_start_with_mixed_permissions(self):
        for disabled in ("mysql", "pgsql"):
            protocol = "pgsql" if disabled == "mysql" else "mysql"
            with self.subTest(disabled=disabled):
                daemon = Daemon(no_start=True, extra_args=(
                    f"--{disabled}-workers=false", f"--{disabled}-admin=false"))
                self.addCleanup(daemon.close)
                daemon.ready(protocol)
                self.expect_workers(daemon, False, False)
                daemon.query("LOAD MYSQL SERVERS TO RUNTIME", protocol)
                daemon.query("LOAD PGSQL SERVERS TO RUNTIME", protocol)
                for _ in range(2):
                    daemon.query("PROXYSQL START", protocol)
                    self.expect_started(daemon, disabled != "mysql", disabled != "pgsql",
                                        disabled != "mysql", disabled != "pgsql")
                    daemon.stop(protocol)
                    self.expect_workers(daemon, False, False)
                daemon.shutdown()
                daemon.close()

    def test_monitor_runtime_true_cannot_override_denied_permission(self):
        daemon = self.daemon(no_monitor=False, monitor_enabled=True, extra_args=(
            "--mysql-monitor=false", "--pgsql-monitor=false"))
        self.expect_started(daemon)
        for dialect in ("mysql", "pgsql"):
            self.assertEqual(daemon.query("SELECT variable_value FROM runtime_global_variables "
                f"WHERE variable_name='{dialect}-monitor_enabled'").stdout.strip(), "true")
        self.assertNotIn("Main phase3 : MySQL Monitor initialized in", daemon.output())
        self.assertNotIn("Main phase3 : PgSQL Monitor initialized in", daemon.output())
        daemon.shutdown()

    def test_config_only(self):
        daemon = self.daemon(config_prefix='mysql-workers=false;pgsql-workers=false;pgsql-admin=false;\n')
        for dialect in ("mysql", "pgsql"):
            self.assertEqual(daemon.query("SELECT variable_value FROM runtime_global_variables "
                             f"WHERE variable_name='{dialect}-threads'").stdout.strip(), "1")
        self.expect_started(daemon, False, False, True, False)
        self.assertFalse(self.listening(daemon.pgadmin))

    def test_repeated_cli_values_use_last_value(self):
        for value in (False, True):
            with self.subTest(last=value):
                daemon = self.daemon(extra_args=(
                    f"--mysql-workers={str(not value).lower()}", f"--mysql-workers={str(value).lower()}"))
                self.assertEqual(daemon.query("SELECT variable_value FROM runtime_global_variables "
                    "WHERE variable_name='mysql-threads'").stdout.strip(), "1")
                self.expect_started(daemon, value, True)
                daemon.close()

    def test_invalid_repeated_cli_values(self):
        for last in ("--mysql-workers=tru", "--mysql-workers"):
            with self.subTest(last=last):
                daemon = Daemon(extra_args=("--mysql-workers=true", last))
                self.addCleanup(daemon.close)
                self.assertNotEqual(daemon.process.wait(timeout=5), 0)
                self.assertIn("mysql-workers", daemon.output())
                daemon.close()

    def test_invalid_cli_boolean(self):
        for name in ("mysql-workers", "pgsql-workers", "mysql-admin", "pgsql-admin", "mysql-monitor", "pgsql-monitor"):
            with self.subTest(option=name):
                daemon = Daemon(extra_args=(f"--{name}=tru",))
                self.addCleanup(daemon.close)
                self.assertNotEqual(daemon.process.wait(timeout=8), 0)
                self.assertIn(name, daemon.output())
                daemon.close()

    def test_monitor_permissions_preserve_runtime_settings(self):
        for mysql_monitor, pgsql_monitor in ((False, False), (False, True), (True, False), (True, True)):
            with self.subTest(mysql=mysql_monitor, pgsql=pgsql_monitor):
                daemon = self.daemon(no_monitor=False, extra_args=(
                    f"--mysql-monitor={str(mysql_monitor).lower()}",
                    f"--pgsql-monitor={str(pgsql_monitor).lower()}"))
                self.expect_started(daemon)
                output = daemon.output()
                self.assertEqual("Main phase3 : MySQL Monitor initialized in" in output, mysql_monitor)
                self.assertEqual("Main phase3 : PgSQL Monitor initialized in" in output, pgsql_monitor)
                for dialect in ("mysql", "pgsql"):
                    # Startup permission must not overwrite the configured runtime false.
                    self.assertEqual(daemon.query("SELECT variable_value FROM runtime_global_variables "
                        f"WHERE variable_name='{dialect}-monitor_enabled'").stdout.strip(), "false")
                daemon.stop()
                daemon.query("PROXYSQL START")
                self.expect_started(daemon)
                output = daemon.output()
                self.assertEqual(output.count("For online documentation"), 2)
                self.assertEqual(output.count("Main phase3 : MySQL Monitor initialized in"), 2 * mysql_monitor)
                self.assertEqual(output.count("Main phase3 : PgSQL Monitor initialized in"), 2 * pgsql_monitor)
                daemon.shutdown()
                daemon.close()


if __name__ == "__main__":
    run_probe_tests()
