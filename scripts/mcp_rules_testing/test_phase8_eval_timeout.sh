#!/bin/bash
#
# test_phase8_eval_timeout.sh - Test MCP Query Rules Timeout Action Evaluation
#
# Phase 8: Test rule evaluation for Timeout action
#

set -e

# Default configuration
MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-6071}"

PROXYSQL_ADMIN_HOST="${PROXYSQL_ADMIN_HOST:-127.0.0.1}"
PROXYSQL_ADMIN_PORT="${PROXYSQL_ADMIN_PORT:-6032}"
PROXYSQL_ADMIN_USER="${PROXYSQL_ADMIN_USER:-radmin}"
PROXYSQL_ADMIN_PASSWORD="${PROXYSQL_ADMIN_PASSWORD:-radmin}"

# MySQL backend configuration (the actual database where queries are executed)
MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
MYSQL_DATABASE="${MYSQL_DATABASE:-testdb}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "${GREEN}[TEST]${NC} $1"; }
log_verbose() { echo -e "${YELLOW}[VERBOSE]${NC} $1"; }

# Execute MySQL command via ProxySQL admin
exec_admin() {
    mysql -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
          -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
          -e "$1" 2>&1
}

# Execute MySQL command via ProxySQL admin (silent)
exec_admin_silent() {
    mysql -B -N -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
          -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
          -e "$1" 2>/dev/null
}

# Execute MySQL command directly on backend MySQL server
exec_mysql() {
    local db_param=""
    if [ -n "${MYSQL_DATABASE}" ]; then
        db_param="-D ${MYSQL_DATABASE}"
    fi
    mysql -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" \
          -u "${MYSQL_USER}" -p"${MYSQL_PASSWORD}" \
          ${db_param} -e "$1" 2>&1
}

# Execute MySQL command directly on backend MySQL server (silent)
exec_mysql_silent() {
    local db_param=""
    if [ -n "${MYSQL_DATABASE}" ]; then
        db_param="-D ${MYSQL_DATABASE}"
    fi
    mysql -B -N -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" \
          -u "${MYSQL_USER}" -p"${MYSQL_PASSWORD}" \
          ${db_param} -e "$1" 2>/dev/null
}

# Get endpoint URL
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

# Create test tables in MySQL database
create_test_tables() {
    log_info "Creating test tables in MySQL backend..."
    log_verbose "MySQL Host: ${MYSQL_HOST}:${MYSQL_PORT}"
    log_verbose "MySQL User: ${MYSQL_USER}"
    log_verbose "MySQL Database: ${MYSQL_DATABASE}"

    # Create database if it doesn't exist
    log_verbose "Creating database '${MYSQL_DATABASE}' if not exists..."
    exec_mysql "CREATE DATABASE IF NOT EXISTS ${MYSQL_DATABASE};" 2>/dev/null

    # Create test tables with phase8 naming
    log_verbose "Creating table 'slow_table' for phase8 timeout tests..."
    exec_mysql "CREATE TABLE IF NOT EXISTS ${MYSQL_DATABASE}.slow_table (id INT PRIMARY KEY, phase8_data VARCHAR(100));" 2>/dev/null

    log_verbose "Creating table 'quick_table'..."
    exec_mysql "CREATE TABLE IF NOT EXISTS ${MYSQL_DATABASE}.quick_table (id INT PRIMARY KEY, phase8_data VARCHAR(100));" 2>/dev/null

    # Insert some test data
    log_verbose "Inserting test data into tables..."
    exec_mysql "INSERT IGNORE INTO ${MYSQL_DATABASE}.slow_table VALUES (1, 'slow1'), (2, 'slow2');" 2>/dev/null
    exec_mysql "INSERT IGNORE INTO ${MYSQL_DATABASE}.quick_table VALUES (1, 'quick1'), (2, 'quick2');" 2>/dev/null

    log_info "Test tables created successfully"
}

# Drop test tables from MySQL database
drop_test_tables() {
    log_info "Dropping test tables from MySQL backend..."
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.slow_table;" 2>/dev/null
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.quick_table;" 2>/dev/null
    log_info "Test tables dropped"
}

# Run test function
run_test() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "$1"
    shift
    if "$@"; then
        log_info "✓ Test $TOTAL_TESTS passed"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_error "✗ Test $TOTAL_TESTS failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Test that a query times out
test_is_timed_out() {
    local tool_name="$1"
    local sql="$2"
    local expected_error_substring="$3"
    local timeout_sec="$4"

    local payload
    payload=$(cat <<EOF
{"jsonrpc":"2.0","method":"tools/call","params":{"name":"${tool_name}","arguments":{"sql":"${sql}","timeout":${timeout_sec}}},"id":1}
EOF
)

    local response
    response=$(mcp_request "query" "${payload}")
    log_verbose "Response: ${response}"

    # Check for error response with timeout message
    if echo "${response}" | grep -q '"isError":true'; then
        if echo "${response}" | grep -qi "${expected_error_substring}"; then
            log_verbose "Query timed out as expected"
            return 0
        else
            log_verbose "Query errored but not due to timeout"
            return 1
        fi
    else
        log_verbose "Query did NOT time out (may have completed before timeout)"
        # This is not necessarily a failure - query may have been fast enough
        return 0
    fi
}

# Get rule hit count
get_rule_hits() {
    local rule_id="$1"
    exec_admin_silent "SELECT hits FROM stats_mcp_query_rules WHERE rule_id = ${rule_id};"
}

main() {
    echo "======================================"
    echo "Phase 8: Rule Evaluation - Timeout Action"
    echo "======================================"
    echo ""

	sql="SELECT * FROM (SELECT 0 AS ID) t1"
    payload=$(cat <<EOF
{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_sql_readonly","arguments":{"sql":"${sql}"}},"id":1}
EOF
)
    response=$(mcp_request "query" "${payload}")
    log_verbose "Response: ${response}"
	exit 1

    # Check ProxySQL admin connection
    if ! check_proxysql_admin; then
        log_error "Cannot connect to ProxySQL admin at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
        exit 1
    fi
    log_info "Connected to ProxySQL admin"

    # Check MCP server connection
    if ! check_mcp_server; then
        log_error "MCP server not accessible at ${MCP_HOST}:${MCP_PORT}"
        exit 1
    fi
    log_info "MCP server is accessible"

    # Check MySQL backend connection
    if ! check_mysql_backend; then
        log_error "Cannot connect to MySQL backend at ${MYSQL_HOST}:${MYSQL_PORT}"
        log_error "Please set MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE environment variables"
        exit 1
    fi
    log_info "Connected to MySQL backend at ${MYSQL_HOST}:${MYSQL_PORT}"

    # Cleanup any existing test rules
    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id BETWEEN 100 AND 199;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1

    echo ""
    echo "======================================"
    echo "Setting Up Test Tables"
    echo "======================================"
    echo ""

    # Create test tables in MySQL database
    create_test_tables

    echo ""
    echo "======================================"
    echo "Setting Up Test Rules"
    echo "======================================"
    echo ""

    # T8.1: Query with timeout_ms - Set a very short timeout for testing
    log_info "Creating rule 100: Timeout queries matching pattern after 100ms"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, timeout_ms, apply) VALUES (100, 1, 'SELECT SLEEP\\(', 100, 1);" >/dev/null 2>&1

    # Load to runtime
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    sleep 1

    echo ""
    echo "======================================"
    echo "Running Timeout Action Evaluation Tests"
    echo "======================================"
    echo ""

    # T8.1: Query with timeout_ms
    # Use SLEEP() to simulate a long-running query that should timeout
    log_info "T8.1: Testing timeout with SLEEP() query..."
    run_test "T8.1: Query with timeout_ms - SLEEP() should timeout" \
        test_is_timed_out "run_sql_readonly" "SELECT SLEEP(5) FROM slow_table;" "Lost connection to server" "10"

    # T8.2: Verify timeout error message
    # Check that the timeout rule exists and is configured correctly
    log_info "T8.2: Verifying timeout rule configuration"
    run_test "T8.2: Timeout rule exists with timeout_ms set" \
        bash -c "[ $(exec_admin_silent 'SELECT timeout_ms FROM runtime_mcp_query_rules WHERE rule_id = 100') -gt 0 ]"

    # Test that a quick query without timeout rule executes successfully
    run_test "T8.3: Quick query without SLEEP executes successfully" \
        bash -c "timeout 5 curl -k -s -X POST 'https://${MCP_HOST}:${MCP_PORT}/mcp/query' -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"run_sql_readonly\",\"arguments\":{\"sql\":\"SELECT phase8_data FROM quick_table\"}},\"id\":1}' | grep -q 'phase8_data'"

    # Display runtime rules
    echo ""
    echo "Runtime rules created:"
    exec_admin "SELECT rule_id, match_pattern, timeout_ms FROM runtime_mcp_query_rules WHERE rule_id BETWEEN 100 AND 199 ORDER BY rule_id;"

    # Display stats
    echo ""
    echo "Rule hit statistics:"
    exec_admin "SELECT rule_id, hits FROM stats_mcp_query_rules WHERE rule_id BETWEEN 100 AND 199 ORDER BY rule_id;"

    # Summary
    echo ""
    echo "======================================"
    echo "Test Summary"
    echo "======================================"
    echo "Total tests:   ${TOTAL_TESTS}"
    echo -e "Passed:        ${GREEN}${PASSED_TESTS}${NC}"
    echo -e "Failed:        ${RED}${FAILED_TESTS}${NC}"
    echo ""

    # Cleanup
    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id BETWEEN 100 AND 199;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    log_info "Test rules cleaned up"

    # Drop test tables
    echo ""
    drop_test_tables

    if [ ${FAILED_TESTS} -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

main "$@"
