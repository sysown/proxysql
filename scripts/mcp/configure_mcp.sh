#!/bin/bash
#
# configure_mcp.sh - Configure ProxySQL MCP module
#
# Usage:
#   ./configure_mcp.sh [options]
#
# Options:
#   -h, --host HOST       MySQL host (default: 127.0.0.1)
#   -P, --port PORT       MySQL port (default: 3307)
#   -u, --user USER       MySQL user (default: root)
#   -p, --password PASS   MySQL password (default: test123)
#   -d, --database DB     MySQL database (default: testdb)
#   --mcp-port PORT       MCP server port (default: 6071)
#   --enable              Enable MCP server
#   --disable             Disable MCP server
#   --status              Show current MCP configuration
#

set -e

# Default configuration (can be overridden by environment variables)
MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3307}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD=test123}"  # Use = instead of :- to allow empty passwords
MYSQL_DATABASE="${TEST_DB_NAME:-testdb}"
MCP_PORT="${MCP_PORT:-6071}"
MCP_ENABLED="false"
MCP_USE_SSL="true"  # Default to true for security

# ProxySQL admin configuration
PROXYSQL_ADMIN_HOST="${PROXYSQL_ADMIN_HOST:-127.0.0.1}"
PROXYSQL_ADMIN_PORT="${PROXYSQL_ADMIN_PORT:-6032}"
PROXYSQL_ADMIN_USER="${PROXYSQL_ADMIN_USER:-admin}"
PROXYSQL_ADMIN_PASSWORD="${PROXYSQL_ADMIN_PASSWORD:-admin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Execute MySQL command via ProxySQL admin
exec_admin() {
    mysql -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
          -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
          -e "$1" 2>&1
}

# Execute MySQL command via ProxySQL admin (silent mode)
exec_admin_silent() {
    mysql -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
          -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
          -e "$1" 2>/dev/null
}

# Check if ProxySQL admin is accessible
check_proxysql_admin() {
    log_step "Checking ProxySQL admin connection..."
    if exec_admin_silent "SELECT 1" >/dev/null 2>&1; then
        log_info "Connected to ProxySQL admin at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
        return 0
    else
        log_error "Cannot connect to ProxySQL admin at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
        log_error "Please ensure ProxySQL is running"
        return 1
    fi
}

# Check if MySQL is accessible
check_mysql_connection() {
    log_step "Checking MySQL connection..."
    if mysql -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" \
            -u "${MYSQL_USER}" -p"${MYSQL_PASSWORD}" \
            -e "SELECT 1" >/dev/null 2>&1; then
        log_info "Connected to MySQL at ${MYSQL_HOST}:${MYSQL_PORT}"
        return 0
    else
        log_error "Cannot connect to MySQL at ${MYSQL_HOST}:${MYSQL_PORT}"
        log_error "Please ensure MySQL is running and credentials are correct"
        return 1
    fi
}

# Configure MCP variables
configure_mcp() {
    local enable="$1"

    log_step "Configuring MCP variables..."

    local errors=0

    # Set each variable individually to catch errors
    exec_admin_silent "SET mcp-mysql_hosts='${MYSQL_HOST}';" || { log_error "Failed to set mcp-mysql_hosts"; errors=$((errors + 1)); }
    exec_admin_silent "SET mcp-mysql_ports='${MYSQL_PORT}';" || { log_error "Failed to set mcp-mysql_ports"; errors=$((errors + 1)); }
    exec_admin_silent "SET mcp-mysql_user='${MYSQL_USER}';" || { log_error "Failed to set mcp-mysql_user"; errors=$((errors + 1)); }
    exec_admin_silent "SET mcp-mysql_password='${MYSQL_PASSWORD}';" || { log_error "Failed to set mcp-mysql_password"; errors=$((errors + 1)); }
    exec_admin_silent "SET mcp-mysql_schema='${MYSQL_DATABASE}';" || { log_error "Failed to set mcp-mysql_schema"; errors=$((errors + 1)); }
    exec_admin_silent "SET mcp-port='${MCP_PORT}';" || { log_error "Failed to set mcp-port"; errors=$((errors + 1)); }
    exec_admin_silent "SET mcp-use_ssl='${MCP_USE_SSL}';" || { log_error "Failed to set mcp-use_ssl"; errors=$((errors + 1)); }
    exec_admin_silent "SET mcp-enabled='${enable}';" || { log_error "Failed to set mcp-enabled"; errors=$((errors + 1)); }

    if [ $errors -gt 0 ]; then
        log_error "Failed to configure $errors MCP variable(s)"
        return 1
    fi

    log_info "MCP variables configured:"
    echo "  mcp-mysql_hosts     = ${MYSQL_HOST}"
    echo "  mcp-mysql_ports     = ${MYSQL_PORT}"
    echo "  mcp-mysql_user      = ${MYSQL_USER}"
    echo "  mcp-mysql_password  = ${MYSQL_PASSWORD}"
    echo "  mcp-mysql_schema    = ${MYSQL_DATABASE}"
    echo "  mcp-port            = ${MCP_PORT}"
    echo "  mcp-use_ssl         = ${MCP_USE_SSL}"
    echo "  mcp-enabled         = ${enable}"
}

# Load MCP variables to runtime
load_to_runtime() {
    log_step "Loading MCP variables to RUNTIME..."
    if exec_admin_silent "LOAD MCP VARIABLES TO RUNTIME;" >/dev/null 2>&1; then
        log_info "MCP variables loaded to RUNTIME"
    else
        log_error "Failed to load MCP variables to RUNTIME"
        return 1
    fi
}

# Show current MCP configuration
show_status() {
    log_step "Current MCP configuration:"
    echo ""
    exec_admin_silent "SHOW VARIABLES LIKE 'mcp-%';" | column -t
    echo ""
}

# Test MCP server connectivity
test_mcp_server() {
    log_step "Testing MCP server connectivity..."

    # Wait a moment for server to start
    sleep 2

    # Determine protocol based on SSL setting
    local proto="https"
    if [ "${MCP_USE_SSL}" = "false" ]; then
        proto="http"
    fi

    # Test ping endpoint
    local response
    response=$(curl -s -X POST "${proto}://${PROXYSQL_ADMIN_HOST}:${MCP_PORT}/mcp/config" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"ping","id":1}' 2>/dev/null || echo "")

    if [ -n "$response" ]; then
        log_info "MCP server is responding"
        echo "  Response: $response"
    else
        log_warn "MCP server not responding (may still be starting)"
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--host)
                MYSQL_HOST="$2"
                shift 2
                ;;
            -P|--port)
                MYSQL_PORT="$2"
                shift 2
                ;;
            -u|--user)
                MYSQL_USER="$2"
                shift 2
                ;;
            -p|--password)
                MYSQL_PASSWORD="$2"
                shift 2
                ;;
            -d|--database)
                MYSQL_DATABASE="$2"
                shift 2
                ;;
            --mcp-port)
                MCP_PORT="$2"
                shift 2
                ;;
            --use-ssl)
                MCP_USE_SSL="true"
                shift
                ;;
            --no-ssl)
                MCP_USE_SSL="false"
                shift
                ;;
            --enable)
                MCP_ENABLED="true"
                shift
                ;;
            --disable)
                MCP_ENABLED="false"
                shift
                ;;
            --status)
                show_status
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Show usage
show_usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  -h, --host HOST       MySQL host (default: 127.0.0.1)
  -P, --port PORT       MySQL port (default: 3307)
  -u, --user USER       MySQL user (default: root)
  -p, --password PASS   MySQL password (default: test123)
  -d, --database DB     MySQL database (default: testdb)
  --mcp-port PORT       MCP server port (default: 6071)
  --use-ssl             Enable SSL/TLS for MCP server (HTTPS mode)
  --no-ssl              Disable SSL/TLS for MCP server (HTTP mode)
  --enable              Enable MCP server
  --disable             Disable MCP server
  --status              Show current MCP configuration

Environment Variables:
  MYSQL_HOST            MySQL host (default: 127.0.0.1)
  MYSQL_PORT            MySQL port (default: 3307)
  MYSQL_USER            MySQL user (default: root)
  MYSQL_PASSWORD        MySQL password (default: test123)
  TEST_DB_NAME          MySQL database (default: testdb)
  MCP_PORT              MCP server port (default: 6071)
  MCP_USE_SSL           MCP SSL mode (default: true)
  PROXYSQL_ADMIN_HOST   ProxySQL admin host (default: 127.0.0.1)
  PROXYSQL_ADMIN_PORT   ProxySQL admin port (default: 6032)
  PROXYSQL_ADMIN_USER   ProxySQL admin user (default: admin)
  PROXYSQL_ADMIN_PASSWORD ProxySQL admin password (default: admin)

Examples:
  # Configure with test MySQL on port 3307 and enable MCP (HTTPS mode)
  $0 --host 127.0.0.1 --port 3307 --enable

  # Configure with HTTP mode (no SSL) for development
  $0 --no-ssl --enable

  # Disable MCP server
  $0 --disable

  # Show current configuration
  $0 --status

  # Use environment variables instead of command line options
  export MYSQL_HOST=192.168.1.10
  export MYSQL_PORT=3306
  export MYSQL_USER=myuser
  export MYSQL_PASSWORD=mypass
  export TEST_DB_NAME=production
  export MCP_USE_SSL=false
  $0 --enable
EOF
}

# Main
main() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        show_usage
        exit 0
    fi

    parse_args "$@"

    echo "======================================"
    echo "ProxySQL MCP Configuration"
    echo "======================================"
    echo ""

    # Print environment variables if set
    if [ -n "${MYSQL_HOST}" ] || [ -n "${MYSQL_PORT}" ] || [ -n "${MYSQL_USER}" ] || [ -n "${MYSQL_PASSWORD}" ] || [ -n "${TEST_DB_NAME}" ] || [ -n "${MCP_PORT}" ] || [ -n "${MCP_USE_SSL}" ]; then
        log_info "Environment Variables:"
        [ -n "${MYSQL_HOST}" ] && echo "  MYSQL_HOST=${MYSQL_HOST}"
        [ -n "${MYSQL_PORT}" ] && echo "  MYSQL_PORT=${MYSQL_PORT}"
        [ -n "${MYSQL_USER}" ] && echo "  MYSQL_USER=${MYSQL_USER}"
        [ -n "${MYSQL_PASSWORD}" ] && echo "  MYSQL_PASSWORD=${MYSQL_PASSWORD}"
        [ -n "${TEST_DB_NAME}" ] && echo "  TEST_DB_NAME=${TEST_DB_NAME}"
        [ -n "${MCP_PORT}" ] && echo "  MCP_PORT=${MCP_PORT}"
        [ -n "${MCP_USE_SSL}" ] && echo "  MCP_USE_SSL=${MCP_USE_SSL}"
        echo ""
    fi

    # Check ProxySQL admin connection
    if ! check_proxysql_admin; then
        exit 1
    fi

    # Check MySQL connection (only when enabling)
    if [ "${MCP_ENABLED}" = "true" ]; then
        if ! check_mysql_connection; then
            log_warn "MySQL connection check failed, but continuing with configuration..."
        fi
    fi

    # Configure MCP
    if ! configure_mcp "${MCP_ENABLED}"; then
        log_error "Failed to configure MCP variables"
        exit 1
    fi

    # Load to runtime
    if ! load_to_runtime; then
        log_error "Failed to load MCP variables to runtime"
        exit 1
    fi

    # Show status
    echo ""
    show_status

    # Test server if enabling
    if [ "${MCP_ENABLED}" = "true" ]; then
        echo ""
        test_mcp_server
    fi

    echo ""
    log_info "Configuration complete!"
    if [ "${MCP_ENABLED}" = "true" ]; then
        echo ""
        if [ "${MCP_USE_SSL}" = "true" ]; then
            local proto="https"
            echo "MCP server is now enabled (HTTPS mode) and accessible at:"
        else
            local proto="http"
            echo "MCP server is now enabled (HTTP mode - unencrypted) and accessible at:"
        fi
        echo "  ${proto}://${PROXYSQL_ADMIN_HOST}:${MCP_PORT}/mcp/config  (config endpoint)"
        echo "  ${proto}://${PROXYSQL_ADMIN_HOST}:${MCP_PORT}/mcp/observe (observe endpoint)"
        echo "  ${proto}://${PROXYSQL_ADMIN_HOST}:${MCP_PORT}/mcp/query  (query endpoint)"
        echo "  ${proto}://${PROXYSQL_ADMIN_HOST}:${MCP_PORT}/mcp/admin  (admin endpoint)"
        echo "  ${proto}://${PROXYSQL_ADMIN_HOST}:${MCP_PORT}/mcp/cache  (cache endpoint)"
        echo ""
        echo "Run './test_mcp_tools.sh' to test MCP tools"
    fi
}

main "$@"
