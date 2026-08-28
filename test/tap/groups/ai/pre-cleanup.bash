#!/usr/bin/env bash
set -uo pipefail
#
# AI TAP Group Pre-Cleanup Hook
# Executed by run-tests-isolated.bash before test runner cleanup
# Removes MCP configuration from ProxySQL
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check required environment variables
if [ -z "${INFRA_ID:-}" ]; then
    echo "WARNING: INFRA_ID is not set, skipping MCP cleanup"
    exit 0
fi

if [ -z "${WORKSPACE:-}" ]; then
    echo "WARNING: WORKSPACE is not set, skipping MCP cleanup"
    exit 0
fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)
PROXY_CONTAINER="proxysql.${INFRA_ID}"

# Check if ProxySQL container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${PROXY_CONTAINER}$"; then
    echo ">>> AI pre-cleanup hook: ProxySQL container not running, skipping cleanup"
    exit 0
fi

# Set MCP-specific environment variables (with defaults)
export MCP_TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
export MCP_AUTH_PROFILE_ID="${MCP_AUTH_PROFILE_ID:-tap_mysql_auth}"
export MCP_PGSQL_TARGET_ID="${MCP_PGSQL_TARGET_ID:-tap_pgsql_default}"
export MCP_PGSQL_AUTH_PROFILE_ID="${MCP_PGSQL_AUTH_PROFILE_ID:-tap_pgsql_auth}"
export MCP_MYSQL_HOSTGROUP_ID="${MCP_MYSQL_HOSTGROUP_ID:-9100}"
export MCP_PGSQL_HOSTGROUP_ID="${MCP_PGSQL_HOSTGROUP_ID:-9200}"

echo ">>> AI pre-cleanup hook: Removing MCP configuration..."

CLEANUP_SQL="${SCRIPT_DIR}/cleanup.sql"
if [ -f "${CLEANUP_SQL}" ]; then
    if command -v envsubst >/dev/null 2>&1; then
        envsubst < "${CLEANUP_SQL}" | docker exec -i "${PROXY_CONTAINER}" mysql -uradmin -pradmin -h127.0.0.1 -P6032 2>/dev/null || true
    else
        # Fallback: use bash variable expansion
        bash -c "cat <<EOF
$(cat "${CLEANUP_SQL}")
EOF" | docker exec -i "${PROXY_CONTAINER}" mysql -uradmin -pradmin -h127.0.0.1 -P6032 2>/dev/null || true
    fi
    echo ">>> MCP cleanup completed"
else
    echo ">>> WARNING: Cleanup SQL not found at ${CLEANUP_SQL}"
fi
