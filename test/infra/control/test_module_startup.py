#!/usr/bin/env python3
"""Selective module startup regressions. Uses private daemons only.

Usage: python3 test/infra/control/test_module_startup.py [path/to/proxysql]
"""
from pathlib import Path
import socket
import time
import unittest

from test_module_lifecycle import Daemon, IsolatedDaemonTest


class ModuleStartup(IsolatedDaemonTest):
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
                        for dialect, enabled in (("mysql", mysql_workers), ("pgsql", pgsql_workers)):
                            value = daemon.query("SELECT variable_value FROM runtime_global_variables "
                                f"WHERE variable_name='{dialect}-threads'", protocol).stdout.strip()
                            self.assertEqual(value, "1" if enabled else "0")
                    else:
                        deadline = time.monotonic() + 15
                        while "For online documentation" not in daemon.output() and time.monotonic() < deadline:
                            self.assertIsNone(daemon.process.poll(), daemon.output()[-2000:])
                            time.sleep(0.05)
                        self.assertIn("For online documentation", daemon.output())
                    # Admin is ready slightly before phase 3 binds worker ports.
                    deadline = time.monotonic() + 5
                    while (self.listening(daemon.mysql) != mysql_workers or
                           self.listening(daemon.pgsql) != pgsql_workers) and time.monotonic() < deadline:
                        time.sleep(0.05)
                    for port, enabled in ((daemon.admin, mysql_admin), (daemon.pgadmin, pgsql_admin),
                                          (daemon.mysql, mysql_workers), (daemon.pgsql, pgsql_workers)):
                        self.assertEqual(self.listening(port), enabled)
                    tasks = Path(f"/proc/{daemon.process.pid}/task")
                    if tasks.is_dir():
                        names = [p.read_text().strip() for p in tasks.glob("*/comm") if p.exists()]
                        for dialect, enabled in (("MySQL", mysql_workers), ("PgSQL", pgsql_workers)):
                            workers = [n for n in names if n.startswith((dialect + "Worker", dialect + "Idle"))]
                            self.assertEqual(bool(workers), enabled, names)
                    if mysql_admin or pgsql_admin:
                        daemon.stop(protocol)
                        daemon.query("LOAD MYSQL SERVERS TO RUNTIME", protocol)
                        daemon.query("LOAD PGSQL SERVERS TO RUNTIME", protocol)
                        daemon.query("PROXYSQL START", protocol)
                        daemon.ready(protocol)
                        self.expect_workers(daemon, mysql_workers, pgsql_workers)
                    daemon.shutdown()
                finally:
                    daemon.close()

    def test_cli_config_precedence(self):
        for value in (False, True):
            with self.subTest(cli=value):
                daemon = self.daemon(config_prefix=f'mysql-workers={str(not value).lower()};\n',
                                     extra_args=(f'--mysql-workers={str(value).lower()}',))
                self.assertEqual(daemon.query("SELECT variable_value FROM runtime_global_variables "
                                 "WHERE variable_name='mysql-threads'").stdout.strip(), "1" if value else "0")
                daemon.close()

    def test_separate_and_numeric_cli_values(self):
        daemon = self.daemon(extra_args=("--mysql-workers", "0", "--pgsql-workers", "0", "--pgsql-admin", "1"))
        self.expect_workers(daemon, False, False)
        for dialect in ("mysql", "pgsql"):
            self.assertEqual(daemon.query("SELECT variable_value FROM runtime_global_variables "
                f"WHERE variable_name='{dialect}-threads'").stdout.strip(), "0")
        daemon.shutdown()

    def test_invalid_configuration_boolean(self):
        daemon = Daemon(config_prefix='mysql-workers="false";\n')
        self.addCleanup(daemon.close)
        self.assertNotEqual(daemon.process.wait(timeout=8), 0)
        self.assertIn("mysql-workers", daemon.output())

    def test_config_only(self):
        daemon = self.daemon(config_prefix='mysql-workers=false;pgsql-workers=false;pgsql-admin=false;\n')
        for dialect in ("mysql", "pgsql"):
            self.assertEqual(daemon.query("SELECT variable_value FROM runtime_global_variables "
                             f"WHERE variable_name='{dialect}-threads'").stdout.strip(), "0")
        self.assertFalse(self.listening(daemon.pgadmin))

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
                deadline = time.monotonic() + 5
                while "For online documentation" not in daemon.output() and time.monotonic() < deadline:
                    time.sleep(0.05)
                output = daemon.output()
                self.assertEqual("Main phase3 : MySQL Monitor initialized in" in output, mysql_monitor)
                self.assertEqual("Main phase3 : PgSQL Monitor initialized in" in output, pgsql_monitor)
                for dialect in ("mysql", "pgsql"):
                    # Startup permission must not overwrite the configured runtime false.
                    self.assertEqual(daemon.query("SELECT variable_value FROM runtime_global_variables "
                        f"WHERE variable_name='{dialect}-monitor_enabled'").stdout.strip(), "false")
                daemon.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
