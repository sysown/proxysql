#!/usr/bin/env bash
set -o pipefail
#
# AI TAP group pre-hook:
# - starts isolated mysql90 + pgsql containers (group-local compose)
# - configures ProxySQL MCP variables, backends, and MCP profiles/targets
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# TAP defaults (can be overridden by environment).
TAP_MYSQLHOST="${TAP_MYSQLHOST:-127.0.0.1}"
TAP_MYSQLPORT="${TAP_MYSQLPORT:-13306}"
TAP_MYSQLUSERNAME="${TAP_MYSQLUSERNAME:-root}"
TAP_MYSQLPASSWORD="${TAP_MYSQLPASSWORD:-rootpass}"
TEST_DB_NAME="${TEST_DB_NAME:-testdb}"
TAP_MCPPORT="${TAP_MCPPORT:-6071}"
MCP_TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
MCP_AUTH_PROFILE_ID="${MCP_AUTH_PROFILE_ID:-tap_mysql_auth}"
MCP_PGSQL_TARGET_ID="${MCP_PGSQL_TARGET_ID:-tap_pgsql_default}"
MCP_PGSQL_AUTH_PROFILE_ID="${MCP_PGSQL_AUTH_PROFILE_ID:-tap_pgsql_auth}"
MCP_MYSQL_HOSTGROUP_ID="${MCP_MYSQL_HOSTGROUP_ID:-9100}"
MCP_PGSQL_HOSTGROUP_ID="${MCP_PGSQL_HOSTGROUP_ID:-9200}"
AI_PGSQL_HOST="${AI_PGSQL_HOST:-127.0.0.1}"
AI_PGSQL_PORT="${AI_PGSQL_PORT:-15432}"
AI_PGSQL_USER="${AI_PGSQL_USER:-postgres}"
AI_PGSQL_PASSWORD="${AI_PGSQL_PASSWORD:-postgres}"
AI_PGSQL_DB="${AI_PGSQL_DB:-testdb}"

ADMIN_HOST="${TAP_ADMINHOST:-127.0.0.1}"
ADMIN_PORT="${TAP_ADMINPORT:-6032}"
ADMIN_USER="${TAP_ADMINUSERNAME:-radmin}"
ADMIN_PASS="${TAP_ADMINPASSWORD:-radmin}"

if [[ $(mysql --skip-ssl-verify-server-cert -h 2>&1) =~ skip-ssl-verify-server-cert ]]; then
    SSLOPT=--skip-ssl-verify-server-cert
else
    SSLOPT=
fi

exec_admin() {
    mysql ${SSLOPT} -h"${ADMIN_HOST}" -P"${ADMIN_PORT}" -u"${ADMIN_USER}" -p"${ADMIN_PASS}" -e "$1" 2>&1 | sed '/^mysql: .*Warning/d'
}

compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose -f "${SCRIPT_DIR}/docker-compose.yml" "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose -f "${SCRIPT_DIR}/docker-compose.yml" "$@"
    else
        echo "[ERROR] docker compose is not available" >&2
        exit 1
    fi
}

create_mysql_monitor_user() {
    echo "[INFO] AI pre-hook: creating MySQL monitor user monitor/monitor on backend ${TAP_MYSQLHOST}:${TAP_MYSQLPORT}"
    mysql -h"${TAP_MYSQLHOST}" -P"${TAP_MYSQLPORT}" -u"${TAP_MYSQLUSERNAME}" -p"${TAP_MYSQLPASSWORD}" -e "\
CREATE USER IF NOT EXISTS 'monitor'@'%' IDENTIFIED BY 'monitor'; \
GRANT USAGE, PROCESS, REPLICATION CLIENT ON *.* TO 'monitor'@'%'; \
FLUSH PRIVILEGES;"
}

create_pgsql_monitor_user() {
    echo "[INFO] AI pre-hook: creating PostgreSQL monitor user monitor/monitor on backend ${AI_PGSQL_HOST}:${AI_PGSQL_PORT}"
    local sql="DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='monitor') THEN CREATE ROLE monitor LOGIN PASSWORD 'monitor'; END IF; END \$\$; GRANT pg_monitor TO monitor; GRANT CONNECT ON DATABASE postgres TO monitor; GRANT CONNECT ON DATABASE ${AI_PGSQL_DB} TO monitor;"
    if command -v psql >/dev/null 2>&1; then
        PGPASSWORD="${AI_PGSQL_PASSWORD}" psql -h "${AI_PGSQL_HOST}" -p "${AI_PGSQL_PORT}" -U "${AI_PGSQL_USER}" -d "${AI_PGSQL_DB}" -v ON_ERROR_STOP=1 -c "${sql}"
    else
        compose exec -T pgsql psql -U "${AI_PGSQL_USER}" -d "${AI_PGSQL_DB}" -v ON_ERROR_STOP=1 -c "${sql}"
    fi
}

seed_mysql_test_data() {
    echo "[INFO] AI pre-hook: seeding MySQL static-harvest test data"
    mysql -h"${TAP_MYSQLHOST}" -P"${TAP_MYSQLPORT}" -u"${TAP_MYSQLUSERNAME}" -p"${TAP_MYSQLPASSWORD}" < "${SCRIPT_DIR}/mysql-seed.sql"
}

seed_pgsql_test_data() {
    echo "[INFO] AI pre-hook: seeding PostgreSQL static-harvest test data"
    if command -v psql >/dev/null 2>&1; then
        PGPASSWORD="${AI_PGSQL_PASSWORD}" psql -h "${AI_PGSQL_HOST}" -p "${AI_PGSQL_PORT}" -U "${AI_PGSQL_USER}" -d "${AI_PGSQL_DB}" -v ON_ERROR_STOP=1 -f "${SCRIPT_DIR}/pgsql-seed.sql"
    else
        compose exec -T pgsql psql -U "${AI_PGSQL_USER}" -d "${AI_PGSQL_DB}" -v ON_ERROR_STOP=1 < "${SCRIPT_DIR}/pgsql-seed.sql"
    fi
}

echo "[INFO] AI pre-hook: starting group-local containers"
"${SCRIPT_DIR}/docker-compose-init.bash"
create_mysql_monitor_user
create_pgsql_monitor_user
seed_mysql_test_data
seed_pgsql_test_data

echo "[INFO] AI pre-hook: configuring ProxySQL MCP and backend routing"

# Configure MCP runtime variables.
exec_admin "SET mcp-port='${TAP_MCPPORT}';"
exec_admin "SET mcp-use_ssl='true';"
exec_admin "SET mcp-enabled='false';"
exec_admin "LOAD MCP VARIABLES TO RUNTIME; SAVE MCP VARIABLES TO DISK;"

# Keep predictable hostgroups for both direct tests and MCP target routing.
exec_admin "DELETE FROM mysql_servers WHERE hostgroup_id IN (0, ${MCP_MYSQL_HOSTGROUP_ID});"
exec_admin "INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, comment) VALUES (0, '${TAP_MYSQLHOST}', ${TAP_MYSQLPORT}, 'ONLINE', 1, 'ai local mysql');"
exec_admin "INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, comment) VALUES (${MCP_MYSQL_HOSTGROUP_ID}, '${TAP_MYSQLHOST}', ${TAP_MYSQLPORT}, 'ONLINE', 1, 'ai mcp mysql');"
exec_admin "LOAD MYSQL SERVERS TO RUNTIME; SAVE MYSQL SERVERS TO DISK;"

exec_admin "DELETE FROM pgsql_servers WHERE hostgroup_id IN (${MCP_PGSQL_HOSTGROUP_ID});"
exec_admin "INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, weight, comment) VALUES (${MCP_PGSQL_HOSTGROUP_ID}, '${AI_PGSQL_HOST}', ${AI_PGSQL_PORT}, 'ONLINE', 1, 'ai mcp pgsql');"
exec_admin "LOAD PGSQL SERVERS TO RUNTIME; SAVE PGSQL SERVERS TO DISK;"

# Basic frontend mysql users for TAP scripts that connect through ProxySQL.
exec_admin "INSERT OR IGNORE INTO mysql_users (username, password, active, default_hostgroup, comment) VALUES ('${TAP_MYSQLUSERNAME}', '${TAP_MYSQLPASSWORD}', 1, 0, 'ai local');"
exec_admin "INSERT OR IGNORE INTO mysql_users (username, password, active, default_hostgroup, comment) VALUES ('testuser', 'testuser', 1, 0, 'ai local');"
exec_admin "LOAD MYSQL USERS TO RUNTIME; SAVE MYSQL USERS TO DISK;"

# Configure MCP auth and target profiles (mysql + pgsql).
exec_admin "DELETE FROM mcp_target_profiles WHERE target_id IN ('${MCP_TARGET_ID}', '${MCP_PGSQL_TARGET_ID}');"
exec_admin "DELETE FROM mcp_auth_profiles WHERE auth_profile_id IN ('${MCP_AUTH_PROFILE_ID}', '${MCP_PGSQL_AUTH_PROFILE_ID}');"

exec_admin "INSERT INTO mcp_auth_profiles (auth_profile_id, db_username, db_password, default_schema, use_ssl, ssl_mode, comment) VALUES ('${MCP_AUTH_PROFILE_ID}', '${TAP_MYSQLUSERNAME}', '${TAP_MYSQLPASSWORD}', '${TEST_DB_NAME}', 0, '', 'ai mysql mcp auth');"
exec_admin "INSERT INTO mcp_auth_profiles (auth_profile_id, db_username, db_password, default_schema, use_ssl, ssl_mode, comment) VALUES ('${MCP_PGSQL_AUTH_PROFILE_ID}', '${AI_PGSQL_USER}', '${AI_PGSQL_PASSWORD}', '${AI_PGSQL_DB}', 0, '', 'ai pgsql mcp auth');"

exec_admin "INSERT INTO mcp_target_profiles (target_id, protocol, hostgroup_id, auth_profile_id, description, max_rows, timeout_ms, allow_explain, allow_discovery, active, comment) VALUES ('${MCP_TARGET_ID}', 'mysql', ${MCP_MYSQL_HOSTGROUP_ID}, '${MCP_AUTH_PROFILE_ID}', 'AI local MySQL target', 200, 5000, 1, 1, 1, 'ai local');"
exec_admin "INSERT INTO mcp_target_profiles (target_id, protocol, hostgroup_id, auth_profile_id, description, max_rows, timeout_ms, allow_explain, allow_discovery, active, comment) VALUES ('${MCP_PGSQL_TARGET_ID}', 'pgsql', ${MCP_PGSQL_HOSTGROUP_ID}, '${MCP_PGSQL_AUTH_PROFILE_ID}', 'AI local PostgreSQL target', 200, 5000, 1, 1, 1, 'ai local');"

exec_admin "LOAD MCP PROFILES TO RUNTIME; SAVE MCP PROFILES TO DISK;"
exec_admin "SET mcp-enabled='true';"
exec_admin "LOAD MCP VARIABLES TO RUNTIME; SAVE MCP VARIABLES TO DISK;"

sleep 2
echo "[INFO] AI pre-hook completed"
