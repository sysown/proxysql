#!/usr/bin/env bash
#
# mcp_test_helpers.sh - Common helper functions for MCP Query Rules tests
#
# This script provides common functions and configuration for all MCP test phases.
#

# TAP Environment variables with fallbacks to legacy variables
# ProxySQL Admin configuration
PROXYSQL_ADMIN_HOST="${TAP_ADMINHOST:-${PROXYSQL_ADMIN_HOST:-127.0.0.1}}"
PROXYSQL_ADMIN_PORT="${TAP_ADMINPORT:-${PROXYSQL_ADMIN_PORT:-6032}}"
PROXYSQL_ADMIN_USER="${TAP_ADMINUSERNAME:-${PROXYSQL_ADMIN_USER:-radmin}}"
PROXYSQL_ADMIN_PASSWORD="${TAP_ADMINPASSWORD:-${PROXYSQL_ADMIN_PASSWORD:-radmin}}"

# MySQL backend configuration
MYSQL_HOST="${TAP_MYSQLHOST:-${MYSQL_HOST:-127.0.0.1}}"
MYSQL_PORT="${TAP_MYSQLPORT:-${MYSQL_PORT:-3306}}"
MYSQL_USER="${TAP_MYSQLUSERNAME:-${MYSQL_USER:-root}}"
MYSQL_PASSWORD="${TAP_MYSQLPASSWORD:-${MYSQL_PASSWORD:-none}}"
MYSQL_DATABASE="${TEST_DB_NAME:-${MYSQL_DATABASE:-testdb}}"

# MCP server configuration
MCP_HOST="${TAP_ADMINHOST:-${MCP_HOST:-127.0.0.1}}"
MCP_PORT="${TAP_MCPPORT:-${MCP_PORT:-6071}}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "${GREEN}[TEST]${NC} $1"; }
log_verbose() { echo -e "${YELLOW}[VERBOSE]${NC} $1"; }

# Execute MySQL command via ProxySQL admin
# Handles password properly: only adds -p flag if password is set and not "none"
exec_admin() {
    if [ -z "${PROXYSQL_ADMIN_PASSWORD}" ] || [ "${PROXYSQL_ADMIN_PASSWORD}" = "none" ]; then
        mysql -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
              -u "${PROXYSQL_ADMIN_USER}" \
              -e "$1" 2>&1
    else
        mysql -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
              -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
              -e "$1" 2>&1
    fi
}

# Execute MySQL command via ProxySQL admin (silent mode)
exec_admin_silent() {
    set +e
    if [ -z "${PROXYSQL_ADMIN_PASSWORD}" ] || [ "${PROXYSQL_ADMIN_PASSWORD}" = "none" ]; then
        mysql -B -N -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
              -u "${PROXYSQL_ADMIN_USER}" \
              -e "$1" 2>&1 | { grep -vP "^mysql: \[Warning\].* insecure.$" || true; }
    else
        mysql -B -N -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
              -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
              -e "$1" 2>&1 | { grep -vP "^mysql: \[Warning\].* insecure.$" || true; }
    fi
    set -e
}

# Execute MySQL command directly on backend MySQL server
exec_mysql() {
    local db_param=""
    if [ -n "${MYSQL_DATABASE}" ]; then
        db_param="-D ${MYSQL_DATABASE}"
    fi

    if [ -z "${MYSQL_PASSWORD}" ] || [ "${MYSQL_PASSWORD}" = "none" ]; then
        mysql -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" \
              -u "${MYSQL_USER}" \
              ${db_param} -e "$1" 2>&1
    else
        mysql -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" \
              -u "${MYSQL_USER}" -p"${MYSQL_PASSWORD}" \
              ${db_param} -e "$1" 2>&1
    fi
}

# Execute MySQL command directly on backend MySQL server (silent mode)
exec_mysql_silent() {
    set +e
    local db_param=""
    if [ -n "${MYSQL_DATABASE}" ]; then
        db_param="-D ${MYSQL_DATABASE}"
    fi

    if [ -z "${MYSQL_PASSWORD}" ] || [ "${MYSQL_PASSWORD}" = "none" ]; then
        mysql -B -N -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" \
              -u "${MYSQL_USER}" \
              ${db_param} -e "$1" 2>&1 | { grep -vP "^mysql: \[Warning\].* insecure.$" || true; }
    else
        mysql -B -N -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" \
              -u "${MYSQL_USER}" -p"${MYSQL_PASSWORD}" \
              ${db_param} -e "$1" 2>&1 | { grep -vP "^mysql: \[Warning\].* insecure.$" || true; }
    fi
    set -e
}

# Get endpoint URL for MCP requests
get_endpoint_url() {
    local endpoint="$1"
    echo "https://${MCP_HOST}:${MCP_PORT}/mcp/${endpoint}"
}

# Execute MCP request via curl
mcp_request() {
    local endpoint="$1"
    local payload="$2"

    curl -k -s -X POST "$(get_endpoint_url "${endpoint}")" \
        -H "Content-Type: application/json" \
        -d "${payload}" 2>/dev/null
}

# Check if ProxySQL admin is accessible
check_proxysql_admin() {
    if exec_admin_silent "SELECT 1" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Check if MCP server is accessible
check_mcp_server() {
    local response
    response=$(mcp_request "config" '{"jsonrpc":"2.0","method":"ping","id":1}')
    if echo "${response}" | grep -q "result"; then
        return 0
    else
        return 1
    fi
}

# Check if MySQL backend is accessible
check_mysql_backend() {
    if exec_mysql_silent "SELECT 1" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Get rule hit count from stats table
get_rule_hits() {
    local rule_id="$1"
    exec_admin_silent "SELECT hits FROM stats_mcp_query_rules WHERE rule_id = ${rule_id};"
}

# Export functions so they can be used in subshells
export -f exec_admin exec_admin_silent exec_mysql exec_mysql_silent
export -f get_endpoint_url mcp_request
export -f check_proxysql_admin check_mcp_server check_mysql_backend
export -f get_rule_hits
export -f log_info log_error log_test log_verbose
