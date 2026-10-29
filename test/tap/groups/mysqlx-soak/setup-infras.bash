#!/usr/bin/env bash
# mysqlx-soak group: setup hook.
#
# At the point this hook runs, ensure-infras.bash has already brought up:
#   - the dbdeployer-mysql84 backend container (3-node MySQL replication;
#     classic ports 3306-3308 on the docker network, X-protocol ports
#     23306-23308 by dbdeployer convention)
#   - the ProxySQL container (proxysql.${INFRA_ID}) with the mysqlx
#     plugin .so bind-mounted at /usr/lib/proxysql/ProxySQL_MySQLX_Plugin.so
#     and proxysql-ci.cnf declaring `plugins=("...")`. The chassis has
#     already loaded the plugin at Phase A.
#
# What we do here:
#   1. Provision mysqlx_users / mysqlx_routes / mysqlx_backend_endpoints
#      against the running ProxySQL via the admin port.
#   2. LOAD MYSQLX ... TO RUNTIME so the plugin's listener binds.
#   3. Verify the listener is reachable.
#
# The harness scripts (behavioral_validation.py, stress.py) are then
# invoked separately by run-tests-isolated.bash via the standard TAP
# entry points (this hook only does setup).

set -e
set -o pipefail

if [ -z "${INFRA_ID}" ]; then
    echo "ERROR: INFRA_ID is not set" >&2
    exit 1
fi

PROXY_CONTAINER="proxysql.${INFRA_ID}"
ADMIN_USER="admin"
ADMIN_PASS="admin"
TEST_USER="alice"
TEST_PASS="alicepass"
ROOT_PASSWORD="${ROOT_PASSWORD:-$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)}"
BACKEND_INFRA="${DEFAULT_MYSQL_INFRA:-infra-dbdeployer-mysql84}"
BACKEND_INFRA_PROJECT="${BACKEND_INFRA}-${INFRA_ID}"
BACKEND_CONTAINER="${BACKEND_INFRA_PROJECT}-dbdeployer1-1"
MYSQLX_BACKEND_MYSQL_PORT="${MYSQLX_BACKEND_MYSQL_PORT:-3306}"
MYSQLX_BACKEND_X_PORT="${MYSQLX_BACKEND_X_PORT:-13306}"
MYSQLX_BACKEND_HOST="${MYSQLX_BACKEND_HOST:-dbdeployer1.${BACKEND_INFRA}}"
MYSQLX_PROXYSQL_PORT="${MYSQLX_PROXYSQL_PORT:-6603}"

mysql_root() {
    docker exec -i "${BACKEND_CONTAINER}" \
        mysql --table -h127.0.0.1 -P"${MYSQLX_BACKEND_MYSQL_PORT}" \
            -uroot -p"${ROOT_PASSWORD}" "$@"
}

echo ">>> Configuring backend MySQL X listener on ${BACKEND_CONTAINER}"
# dbdeployer's classic MySQL listener is already bound to 0.0.0.0 by
# the infra image. The X Plugin listener has its own bind option; if it
# stays on localhost inside the dbdeployer container, ProxySQL can
# authenticate frontend X sessions but every backend SQL execution dies.
docker exec "${BACKEND_CONTAINER}" bash -lc '
set -euo pipefail
cnf=$(ls /root/sandboxes/rsandbox_*/master/my.sandbox.cnf 2>/dev/null | head -1)
if [ -z "${cnf}" ]; then
    echo "ERROR: master my.sandbox.cnf not found under /root/sandboxes" >&2
    exit 1
fi
if grep -q "^mysqlx-bind-address=" "${cnf}"; then
    sed -i "s/^mysqlx-bind-address=.*/mysqlx-bind-address=0.0.0.0/" "${cnf}"
else
    printf "\nmysqlx-bind-address=0.0.0.0\n" >> "${cnf}"
fi
restart="$(dirname "${cnf}")/restart"
if [ ! -x "${restart}" ]; then
    echo "ERROR: ${restart} is not executable" >&2
    exit 1
fi
"${restart}" >/tmp/mysqlx-master-restart.log 2>&1 || {
    cat /tmp/mysqlx-master-restart.log >&2
    exit 1
}
'

WAIT=30
while [ $WAIT -gt 0 ]; do
    if mysql_root -N -B -e "SELECT 1" >/dev/null 2>&1; then
        break
    fi
    WAIT=$((WAIT - 1))
    sleep 1
done
if [ $WAIT -eq 0 ]; then
    echo "ERROR: backend MySQL did not come back after X listener reconfiguration" >&2
    exit 1
fi

DISCOVERED_X_PORT=$(mysql_root -N -B -e "SHOW VARIABLES LIKE 'mysqlx_port'" 2>/dev/null \
    | awk '$1 == "mysqlx_port" { print $2 }' | tail -1 || true)
if [ -n "${DISCOVERED_X_PORT}" ]; then
    MYSQLX_BACKEND_X_PORT="${DISCOVERED_X_PORT}"
fi
echo ">>> Backend MySQL X endpoint: ${MYSQLX_BACKEND_HOST}:${MYSQLX_BACKEND_X_PORT}"

echo ">>> Provisioning ${TEST_USER} on backend MySQL source"
# The mysqlx plugin uses backend_auth_mode='mapped' which makes the
# backend connection authenticate as the frontend user. The X-Protocol
# auth at the backend needs to find 'alice' in mysql.user with
# mysql_native_password. Without this step
# every backend session fails with "Access denied for user 'alice'",
# so every SQL forwarded from ProxySQL's mysqlx listener errors out —
# surfaced in soak as 100% error rate in the stress harness and as
# 'pre-drop SELECT 1 succeeded on 0/N sessions' in route_drop_inflight.
if ! mysql_root <<SQL
CREATE USER IF NOT EXISTS '${TEST_USER}'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${TEST_PASS}';
ALTER USER '${TEST_USER}'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${TEST_PASS}';
GRANT ALL PRIVILEGES ON *.* TO '${TEST_USER}'@'%';
FLUSH PRIVILEGES;
SELECT user, host, plugin FROM mysql.user WHERE user='${TEST_USER}';
SQL
then
    echo "ERROR: failed to provision ${TEST_USER} on ${BACKEND_CONTAINER}:${MYSQLX_BACKEND_MYSQL_PORT}" >&2
    exit 1
fi

echo ">>> Configuring mysqlx plugin in ${PROXY_CONTAINER}"

# Wait for the plugin's admin tables to exist (they are created by
# Phase B during chassis startup; if they're missing here something is
# wrong with the plugin load).
WAIT=20
while [ $WAIT -gt 0 ]; do
    if docker exec "${PROXY_CONTAINER}" mysql -u${ADMIN_USER} -p${ADMIN_PASS} -h127.0.0.1 -P6032 -N -B -e \
        "SELECT name FROM sqlite_master WHERE type='table' AND name='mysqlx_users'" 2>/dev/null | grep -q mysqlx_users; then
        break
    fi
    WAIT=$((WAIT - 1))
    sleep 1
done

if [ $WAIT -eq 0 ]; then
    echo "ERROR: mysqlx_users table not found on ${PROXY_CONTAINER} — plugin failed to load?" >&2
    docker logs --tail=60 "${PROXY_CONTAINER}" >&2 || true
    exit 1
fi

# Provision the test fixture rows. The frontend mysql_users entry is
# what the X-protocol client authenticates against; the X-specific
# overrides (allowed_auth_methods, default_route, backend_auth_mode)
# live in mysqlx_users.
# --table forces boxed output even on stdin so the SELECT COUNT(*) and
# any error from LOAD MYSQLX ... TO RUNTIME end up in the CI log.
# Without it mysql's stdin-driven default suppresses non-error output.
docker exec -i "${PROXY_CONTAINER}" mysql --table -u${ADMIN_USER} -p${ADMIN_PASS} -h127.0.0.1 -P6032 <<SQL
DELETE FROM mysql_users WHERE username='${TEST_USER}';
INSERT INTO mysql_users (username, password, active, default_hostgroup, frontend, backend)
    VALUES ('${TEST_USER}', '${TEST_PASS}', 1, 10, 1, 1);

DELETE FROM mysqlx_users WHERE username='${TEST_USER}';
INSERT INTO mysqlx_users (username, active, allowed_auth_methods, default_route, backend_auth_mode)
    VALUES ('${TEST_USER}', 1, 'PLAIN,MYSQL41', 'r1', 'mapped');

DELETE FROM mysql_servers WHERE hostgroup_id=10;
INSERT INTO mysql_servers (hostgroup_id, hostname, port, status)
    VALUES (10, '${MYSQLX_BACKEND_HOST}', ${MYSQLX_BACKEND_MYSQL_PORT}, 'ONLINE');

DELETE FROM mysqlx_backend_endpoints WHERE hostname='${MYSQLX_BACKEND_HOST}';
INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port, use_ssl)
    VALUES ('${MYSQLX_BACKEND_HOST}', ${MYSQLX_BACKEND_MYSQL_PORT}, ${MYSQLX_BACKEND_X_PORT}, 0);

DELETE FROM mysqlx_routes WHERE name='r1';
INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active)
    VALUES ('r1', '0.0.0.0:${MYSQLX_PROXYSQL_PORT}', 10, -1, 'first_available', 1);

LOAD MYSQL USERS TO RUNTIME;
LOAD MYSQL SERVERS TO RUNTIME;

-- The mysqlx plugin's install_users_from_admin / install_endpoints_from_
-- admin SELECT runtime_mysql_users and runtime_mysql_servers directly
-- via SQLite, but those tables are only populated by admin's lazy-
-- refresh hook on SELECT — not by LOAD MYSQL {USERS,SERVERS} TO RUNTIME
-- itself. Without a SELECT here the next three LOAD MYSQLX statements
-- see empty source rows and the listener never gets a valid route to
-- bind. The COUNT(*) probes force admin to refresh both tables.
SELECT COUNT(*) FROM runtime_mysql_users;
SELECT COUNT(*) FROM runtime_mysql_servers;

LOAD MYSQLX USERS TO RUNTIME;
LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME;
LOAD MYSQLX ROUTES TO RUNTIME;

-- proxysql-tester.py reloads core MySQL tables from disk before each
-- TAP test. Persist this group's fixture rows so that reset keeps the
-- mysqlx route's destination hostgroup and frontend user available.
SAVE MYSQL USERS TO DISK;
SAVE MYSQL SERVERS TO DISK;
SAVE MYSQLX USERS TO DISK;
SAVE MYSQLX BACKEND ENDPOINTS TO DISK;
SAVE MYSQLX ROUTES TO DISK;

-- Post-LOAD probes: surface what the plugin actually installed so a
-- failure to bind the listener can be diagnosed from the CI log
-- (counts of zero here mean install_*_from_admin saw empty source
-- rows despite the SELECT-COUNT(*) nudge above).
SELECT 'runtime_mysqlx_users' AS table_name, COUNT(*) AS rows FROM runtime_mysqlx_users
UNION ALL SELECT 'runtime_mysqlx_routes', COUNT(*) FROM runtime_mysqlx_routes
UNION ALL SELECT 'runtime_mysqlx_backend_endpoints', COUNT(*) FROM runtime_mysqlx_backend_endpoints;
SQL

echo ">>> Verifying ProxySQL can reach backend X endpoint ${MYSQLX_BACKEND_HOST}:${MYSQLX_BACKEND_X_PORT}"
if ! docker exec "${PROXY_CONTAINER}" bash -c "exec 3<>/dev/tcp/${MYSQLX_BACKEND_HOST}/${MYSQLX_BACKEND_X_PORT}" 2>/dev/null; then
    echo "ERROR: backend X endpoint ${MYSQLX_BACKEND_HOST}:${MYSQLX_BACKEND_X_PORT} is not reachable from ${PROXY_CONTAINER}" >&2
    docker exec "${BACKEND_CONTAINER}" bash -lc "grep -H '^mysqlx-' /root/sandboxes/rsandbox_*/master/my.sandbox.cnf || true" >&2 || true
    exit 1
fi

# Wait for the listener to bind.
# IMPORTANT: use `bash -c`, not `sh -c`. /dev/tcp/<host>/<port> is a
# bash builtin; the proxysql container's /bin/sh is dash (Ubuntu
# default) and silently fails the redirection regardless of whether
# the listener is up — making the probe report "not listening" even
# right after add_listener returns bind+listen OK in the plugin log.
echo ">>> Waiting for mysqlx listener on port ${MYSQLX_PROXYSQL_PORT} ..."
WAIT=10
while [ $WAIT -gt 0 ]; do
    if docker exec "${PROXY_CONTAINER}" bash -c "exec 3<>/dev/tcp/127.0.0.1/${MYSQLX_PROXYSQL_PORT} && echo open" 2>/dev/null | grep -q open; then
        echo ">>> mysqlx listener is up on port ${MYSQLX_PROXYSQL_PORT}"
        break
    fi
    WAIT=$((WAIT - 1))
    sleep 1
done

if [ $WAIT -eq 0 ]; then
    echo "ERROR: mysqlx listener did not bind on port ${MYSQLX_PROXYSQL_PORT} within 10s" >&2
    docker logs --tail=60 "${PROXY_CONTAINER}" >&2 || true
    exit 1
fi

echo ">>> mysqlx-soak setup complete; harness scripts can now connect."
