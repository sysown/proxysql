# TCP proxy integration tests

These tests exercise the production relay with loopback sockets and a real
ProxySQL daemon. Linux, Python 3, a C++17 compiler, the repository's JSON
dependency and the MySQL client are required. The mapped monitor tests also
need a local `mysqld`; PostgreSQL monitoring uses a controlled protocol fixture.

Build ProxySQL and the TCP plugin together from the repository root:

```sh
make PROXYSQL40=1 -j8 NPROCS=8
```

Run the daemon lifecycle, persistence, hostgroup accounting, status, monitor,
remapping and shared-hostgroup cases:

```sh
python3 plugins/tcp_proxy/tests/daemon_admin_smoke.py \
  --proxysql "$PWD/src/proxysql" --plugin "$PWD/plugins/tcp_proxy/proxysql_tcp_proxy.so" --case all
python3 plugins/tcp_proxy/tests/daemon_mapped_smoke.py \
  --proxysql "$PWD/src/proxysql" --plugin "$PWD/plugins/tcp_proxy/proxysql_tcp_proxy.so" --case all
```

Admin cases report PASS or FAIL; mapped cases report PASS, FAIL or BLOCKED. The fixtures use temporary directories
and loopback ports and stop their child processes when finished.

To run the adversarial socket suite against the production engine:

```sh
cd plugins/tcp_proxy/tests
make -f Makefile.integration test
```

The target builds the harness from `src/config.cpp` and `src/engine.cpp`,
then runs the adversarial socket suite.
