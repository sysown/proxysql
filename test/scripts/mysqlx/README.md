# mysqlx operational test harnesses

Scripts for validating the mysqlx plugin against a running ProxySQL.
These are NOT TAP unit tests — they require live infrastructure (a real
MySQL 8.x backend reachable via X Protocol, a running ProxySQL with the
mysqlx plugin loaded). They exist for the post-merge confidence work
tracked in issues #5677, #5678, #5681.

## Prerequisites

```bash
# 1. ProxySQL built with PROXYSQLGENAI=1 and the mysqlx plugin .so
#    available at plugins/mysqlx/ProxySQL_MySQLX_Plugin.so.
# 2. A MySQL 8.x backend with X Protocol enabled (port 33060), and a
#    test user mapped through proxysql's mysqlx_users / mysqlx_routes.
# 3. mysql-connector-python (X DevAPI bindings):
pip install mysql-connector-python
```

## Scripts

### `behavioral_validation.py` — issue #5678

Validates two operationally-important behaviours:

1. **PROXYSQL SHUTDOWN SLOW mid-traffic**: opens N concurrent
   X-Protocol clients running steady queries; issues
   `PROXYSQL SHUTDOWN SLOW` through the admin port; verifies each
   client receives a clean `Mysqlx::Error` frame with code 1053
   ("Server is shutting down") instead of an unannounced TCP RST.
   Exercises
   `MysqlxSession::shutdown_notify_client()` (commit `55e90d1a7`).

2. **`LOAD MYSQLX ROUTES TO RUNTIME` mid-traffic**: opens N clients on
   route `r1`, then via the admin port deletes `r1` from
   `mysqlx_routes` and reloads. Verifies in-flight sessions continue
   serving queries to the now-removed route's original backend, while
   a new connection to that route gets connection-refused. Exercises
   the documented `remove_listener_for_route` semantics
   (`mysqlx_listener_reconcile.cpp:107-132`).

### `stress.py` — issue #5681

Opens N concurrent X-Protocol clients (configurable, target N=1000)
running query loops. Drives connection churn by periodically opening
new and closing old. Captures throughput, error rate, RSS, fd count,
thread count, and `stats_mysqlx_routes` rows over time. Pass criteria:
60-minute run with no crash, no monotonic growth, error rate < 0.1%.

## Recipes

### Smoke + soak (issue #5677)

```bash
# 1. Stand up a backend MySQL 8.x. Either docker:
docker run -d --name=test_mysql -p 3306:3306 -p 33060:33060 \
    -e MYSQL_ROOT_PASSWORD=root mysql:8.4

# 2. Or use dbdeployer (see test/tap/groups/mysqlx-e2e/setup-infras.bash).

# 3. Configure ProxySQL — add the user/route in the admin shell:
mysql -h 127.0.0.1 -P 6032 -u admin -padmin <<'SQL'
INSERT INTO mysqlx_users(username, default_route) VALUES('alice','r1');
INSERT INTO mysqlx_backend_endpoints(hostname, mysql_port, mysqlx_port)
    VALUES('127.0.0.1', 3306, 33060);
INSERT INTO mysql_servers(hostgroup_id, hostname, port) VALUES(10, '127.0.0.1', 3306);
INSERT INTO mysqlx_routes(name, bind, destination_hostgroup)
    VALUES('r1', '0.0.0.0:6603', 10);
LOAD MYSQLX USERS TO RUNTIME; SAVE MYSQLX USERS TO DISK;
LOAD MYSQLX ROUTES TO RUNTIME; SAVE MYSQLX ROUTES TO DISK;
LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME; SAVE MYSQLX BACKEND ENDPOINTS TO DISK;
SQL

# 4. Run the smoke first:
python3 test/scripts/mysqlx/behavioral_validation.py \
    --proxysql-host 127.0.0.1 --proxysql-port 6603 \
    --user alice --password whatever --duration 30s

# 5. Then the soak (24-72h):
python3 test/scripts/mysqlx/stress.py \
    --proxysql-host 127.0.0.1 --proxysql-port 6603 \
    --user alice --password whatever \
    --concurrent 100 --duration 24h \
    --metrics-out /tmp/mysqlx_soak_metrics.csv
```

Capture `/proc/$(pidof proxysql)/status` (RSS, threads),
`/proc/$(pidof proxysql)/fd | wc -l` (fds), and
`SELECT * FROM stats_mysqlx_routes` periodically. The `--metrics-out`
flag writes a CSV that can be plotted to verify no monotonic growth.

## Status

These harnesses are scaffolds — runnable but not yet exercised against
real infrastructure. They post-date PR #5651's merge window. Confidence
gain comes from someone running them on staging and posting the
results back to the linked issues.
