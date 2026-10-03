#!/usr/bin/env python3
"""Check the real startup TLS reload with a Linux ASan-instrumented DEBUG daemon.

Run after building ProxySQL with DEBUG and address sanitization:
    python3 test/infra/control/test_startup_tls_ownership.py [path/to/proxysql]

Losing the initial SSL_CTX's owning reference must fail this test at shutdown.
Existing TLS fixtures avoid mixing the certificate-generation path into the
startup reload regression. No backend servers or installed plugins are needed.
"""

import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


def main():
    if sys.platform != "linux":
        print("# SKIP startup TLS ownership regression requires Linux LeakSanitizer")
        return 77
    repo = Path(__file__).resolve().parents[3]
    binary = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else repo / "src/proxysql"
    symbols = subprocess.run(["nm", "-g", str(binary)], capture_output=True, text=True, check=True, timeout=10)
    if "__asan_init" not in symbols.stdout:
        print("# SKIP startup TLS ownership regression requires an ASan daemon")
        return 77
    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=True, timeout=10)
    if "_DEBUG" not in version.stdout:
        print("# SKIP startup TLS ownership regression requires DEBUG for slow shutdown")
        return 77

    fixtures = repo / "test/tap/tests/test_cluster_sync_config/test_cluster_sync_nomonitor"
    with tempfile.TemporaryDirectory(prefix="proxysql-tls-") as temporary:
        runtime = Path(temporary)
        for name in ("proxysql-ca.pem", "proxysql-cert.pem", "proxysql-key.pem"):
            shutil.copyfile(fixtures / name, runtime / name)
        admin_socket = runtime / "admin.sock"
        pgsql_admin_socket = runtime / "pgsql-admin.sock"
        config = runtime / "proxysql.cnf"
        # Only the protocol greeting is needed for readiness. A delimiter-only
        # list creates no unrelated Admin/Stats authentication records; empty
        # strings are rejected by set_variable() and retain the default users.
        config.write_text(
            'admin_variables={admin_credentials=";";stats_credentials=";";mysql_ifaces="'
            + str(admin_socket)
            + '";pgsql_ifaces="'
            + str(pgsql_admin_socket)
            + '";}\n'
            'mysql_variables={threads=1;interfaces="127.0.0.1:6033";monitor_enabled=false;}\n'
            'pgsql_variables={threads=1;interfaces="127.0.0.1:6133";}\n'
            'plugins=();\n'
        )
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = "detect_leaks=1:leak_check_at_exit=1:fast_unwind_on_malloc=0"
        environment["LSAN_OPTIONS"] = "exitcode=23"
        log_path = runtime / "startup.log"
        with log_path.open("w") as log:
            process = subprocess.Popen(
                [str(binary), "-f", "--no-start", "-c", str(config), "-D", str(runtime)],
                stdout=log, stderr=log, env=environment,
            )
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("daemon exited before its Admin listener became ready")
                    try:
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                            connection.settimeout(0.2)
                            connection.connect(str(admin_socket))
                            if connection.recv(4):
                                break
                    except OSError:
                        pass
                    time.sleep(0.05)
                else:
                    raise RuntimeError("daemon Admin listener did not become ready")
                process.send_signal(signal.SIGTERM)
                result = process.wait(timeout=30)
            except Exception:
                process.kill()
                process.wait()
                print(log_path.read_text(), file=sys.stderr)
                raise
        output = log_path.read_text()
        if result != 0 or "Shutdown completed!" not in output or "ERROR: AddressSanitizer" in output:
            print(output, file=sys.stderr)
            raise RuntimeError(f"startup TLS ownership regression failed: daemon exit {result}")
    print("# Startup TLS context ownership regression passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
