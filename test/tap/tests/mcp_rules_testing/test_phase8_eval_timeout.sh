#!/bin/bash
#
# MCP Query Rules Test Script
#

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the helper functions
if [ -f "${SCRIPT_DIR}/mcp_test_helpers.sh" ]; then
    source "${SCRIPT_DIR}/mcp_test_helpers.sh"
else
    echo "ERROR: mcp_test_helpers.sh not found at ${SCRIPT_DIR}"
    exit 1
fi

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

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

drop_test_tables() {
    log_info "Dropping test tables from MySQL backend..."
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.slow_table;" 2>/dev/null
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.quick_table;" 2>/dev/null
    log_info "Test tables dropped"
}

test_is_timed_out() {
    local tool_name="$1"
    local sql="$2"
    local expected_error_substring="$3"
    local timeout_sec="$4"

    local payload
    payload=$(cat <<EOF
{"jsonrpc":"2.0","method":"tools/call","params":{"name":"${tool_name}","arguments":{"sql":"${sql}","target_id":"${MCP_TARGET_ID}","timeout":${timeout_sec}}},"id":1}
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
        # For timeout tests, we expect the query to time out
        return 1
    fi
}

main() {
    echo "======================================"
    echo "Phase 8: Rule Evaluation - Timeout Action"
    echo "======================================"
    echo ""

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
        bash -c "timeout 5 curl -k -s -X POST 'https://${MCP_HOST}:${MCP_PORT}/mcp/query' -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"run_sql_readonly\",\"arguments\":{\"sql\":\"SELECT phase8_data FROM quick_table\",\"target_id\":\"${MCP_TARGET_ID}\"}},\"id\":1}' | grep -q 'phase8_data'"

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
