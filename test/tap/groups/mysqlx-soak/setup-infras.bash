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
docker exec -i "${PROXY_CONTAINER}" mysql -u${ADMIN_USER} -p${ADMIN_PASS} -h127.0.0.1 -P6032 <<SQL
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
LOAD MYSQLX USERS TO RUNTIME;
LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME;
LOAD MYSQLX ROUTES TO RUNTIME;
SQL

# Wait for the listener to bind.
echo ">>> Waiting for mysqlx listener on port ${MYSQLX_PROXYSQL_PORT} ..."
WAIT=10
while [ $WAIT -gt 0 ]; do
    if docker exec "${PROXY_CONTAINER}" sh -c "exec 3<>/dev/tcp/127.0.0.1/${MYSQLX_PROXYSQL_PORT} && echo open" 2>/dev/null | grep -q open; then
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
