#!/usr/bin/env bash
set -o pipefail
#
# AI TAP group post-hook:
# - cleans MCP targets/profiles created by pre-hook
# - removes isolated compose containers
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MCP_TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
MCP_AUTH_PROFILE_ID="${MCP_AUTH_PROFILE_ID:-tap_mysql_auth}"
MCP_PGSQL_TARGET_ID="${MCP_PGSQL_TARGET_ID:-tap_pgsql_default}"
MCP_PGSQL_AUTH_PROFILE_ID="${MCP_PGSQL_AUTH_PROFILE_ID:-tap_pgsql_auth}"
MCP_MYSQL_HOSTGROUP_ID="${MCP_MYSQL_HOSTGROUP_ID:-9100}"
MCP_PGSQL_HOSTGROUP_ID="${MCP_PGSQL_HOSTGROUP_ID:-9200}"

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

try_admin() {
    if ! exec_admin "$1"; then
        echo "[WARN] admin cleanup statement failed: $1" >&2
    fi
}

echo "[INFO] AI post-hook: cleaning ProxySQL MCP/group-specific config"

try_admin "DELETE FROM mcp_target_profiles WHERE target_id IN ('${MCP_TARGET_ID}', '${MCP_PGSQL_TARGET_ID}');"
try_admin "DELETE FROM mcp_auth_profiles WHERE auth_profile_id IN ('${MCP_AUTH_PROFILE_ID}', '${MCP_PGSQL_AUTH_PROFILE_ID}');"
try_admin "LOAD MCP PROFILES TO RUNTIME; SAVE MCP PROFILES TO DISK;"

try_admin "DELETE FROM mysql_servers WHERE hostgroup_id IN (${MCP_MYSQL_HOSTGROUP_ID});"
try_admin "LOAD MYSQL SERVERS TO RUNTIME; SAVE MYSQL SERVERS TO DISK;"
try_admin "DELETE FROM pgsql_servers WHERE hostgroup_id IN (${MCP_PGSQL_HOSTGROUP_ID});"
try_admin "LOAD PGSQL SERVERS TO RUNTIME; SAVE PGSQL SERVERS TO DISK;"

echo "[INFO] AI post-hook: destroying group-local containers"
"${SCRIPT_DIR}/docker-compose-destroy.bash"

echo "[INFO] AI post-hook completed"
