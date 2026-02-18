#!/bin/bash
#
# test_phase9_eval_okmsg.sh - Test MCP Query Rules OK Message Action Evaluation
#
# Phase 9: Test rule evaluation for OK Message action
#

set -eo pipefail

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

    # Create test tables with phase9 naming
    log_verbose "Creating table 'status_table' for phase9 tests..."
    exec_mysql "CREATE TABLE IF NOT EXISTS ${MYSQL_DATABASE}.status_table (id INT PRIMARY KEY, phase9_status VARCHAR(100));" 2>/dev/null

    log_verbose "Creating table 'health_table'..."
    exec_mysql "CREATE TABLE IF NOT EXISTS ${MYSQL_DATABASE}.health_table (id INT PRIMARY KEY, phase9_metric VARCHAR(100));" 2>/dev/null

    # Insert some test data
    log_verbose "Inserting test data into tables..."
    exec_mysql "INSERT IGNORE INTO ${MYSQL_DATABASE}.status_table VALUES (1, 'active'), (2, 'inactive');" 2>/dev/null
    exec_mysql "INSERT IGNORE INTO ${MYSQL_DATABASE}.health_table VALUES (1, 'cpu'), (2, 'memory');" 2>/dev/null

    log_info "Test tables created successfully"
}

drop_test_tables() {
    log_info "Dropping test tables from MySQL backend..."
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.status_table;" 2>/dev/null
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.health_table;" 2>/dev/null
    log_info "Test tables dropped"
}

test_query_not_executed() {
    local tool_name="$1"
    local sql="$2"

    # Get initial count from MySQL backend
    local initial_count
    initial_count=$(exec_mysql_silent "SELECT COUNT(*) FROM ${MYSQL_DATABASE}.status_table;")

    local payload
    payload="{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"${tool_name}\",\"arguments\":{\"sql\":\"${sql}\",\"target_id\":\"${MCP_TARGET_ID}\"}},\"id\":1}"

    # Execute the MCP request
    mcp_request "query" "${payload}" >/dev/null 2>&1

    # Get final count from MySQL backend
    local final_count
    final_count=$(exec_mysql_silent "SELECT COUNT(*) FROM ${MYSQL_DATABASE}.status_table;")

    # Compare counts
    if [ "${initial_count}" -eq "${final_count}" ]; then
        log_verbose "Query was NOT executed (count unchanged: ${initial_count})"
        return 0
    else
        log_verbose "Query WAS executed (count changed: ${initial_count} -> ${final_count})"
        return 1
    fi
}

test_returns_okmsg() {
    local tool_name="$1"
    local sql="$2"
    local expected_okmsg="$3"

    local payload
    payload="{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"${tool_name}\",\"arguments\":{\"sql\":\"${sql}\",\"target_id\":\"${MCP_TARGET_ID}\"}},\"id\":1}"

    local response
    response=$(mcp_request "query" "${payload}")
    log_verbose "Response: ${response}"

    # Check for successful response (not error)
    if echo "${response}" | grep -q '"isError":true'; then
        log_verbose "Query returned error (expected OK message)"
        return 1
    else
        # Check if expected OK message is in response
        if echo "${response}" | grep -qi "${expected_okmsg}"; then
            log_verbose "Query returned OK message: ${expected_okmsg}"
            return 0
        else
            log_verbose "Query succeeded but OK message doesn't match expected"
            return 1
        fi
    fi
}

main() {
    echo "======================================"
    echo "Phase 9: Rule Evaluation - OK Message Action"
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

    # T9.1: Query with OK_msg - Simple PING/PONG pattern
    log_info "Creating rule 100: Return 'PONG' for queries matching 'PING' pattern"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, OK_msg, re_modifiers, apply) VALUES (100, 1, 'PING', 'PONG - Service is healthy', 'CASELESS', 1);" >/dev/null 2>&1

    # T9.1: Query with OK_msg - Health check pattern
    log_info "Creating rule 101: Return health status for 'health_check' pattern"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, OK_msg, apply) VALUES (101, 1, 'SELECT.*FROM.*health_check', 'Status: OK - All systems operational', 1);" >/dev/null 2>&1

    # T9.2: Verify success response contains OK_msg
    log_info "Creating rule 102: Return custom message for STATUS queries"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, OK_msg, re_modifiers, apply) VALUES (102, 1, 'SELECT.*STATUS', 'Custom Status Message: Request processed successfully', 'CASELESS', 1);" >/dev/null 2>&1

    # Load to runtime
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    sleep 1

    echo ""
    echo "======================================"
    echo "Running OK Message Action Evaluation Tests"
    echo "======================================"
    echo ""

    # T9.1: Query with OK_msg - PING/PONG test
    run_test "T9.1: Query with OK_msg - PING returns PONG message" \
        test_returns_okmsg "run_sql_readonly" "PING" "PONG"

    # T9.1: Query with OK_msg - Health check test
    run_test "T9.1: Query with OK_msg - health_check returns status message" \
        test_returns_okmsg "run_sql_readonly" "SELECT * FROM health_check;" "Status: OK"

    # T9.1: Query with OK_msg - Verify success response contains OK_msg
    run_test "T9.1: Verify success response contains OK_msg - STATUS query" \
        test_returns_okmsg "run_sql_readonly" "SELECT STATUS FROM status_table;" "Custom Status Message"

    # T9.1: Verify OK message response format is successful (not error)
    log_test "T9.1: Verify OK message response is successful (not error)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_sql_readonly","arguments":{"sql":"PING","target_id":"'"${MCP_TARGET_ID}"'"}},"id":1}'
    response=$(mcp_request "query" "$payload")
    log_verbose "Response: ${response}"

    # Check that response does NOT contain isError:true
    log_verbose "Checking response for isError   has_error=\"false\""
    if echo "$response" | grep -q '"isError":true'; then
        log_error "✗ Test $TOTAL_TESTS failed - Response contains isError:true   response=\"${response}\""
        FAILED_TESTS=$((FAILED_TESTS + 1))
    else
        # Check that it contains PONG (the OK_msg)
        log_verbose "Checking response contains expected OK_msg   expected=\"PONG\" found=\"true\""
        if echo "$response" | grep -q 'PONG'; then
            log_info "✓ Test $TOTAL_TESTS passed - Response contains PONG   ok_msg=\"PONG\" response=\"${response}\""
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            log_error "✗ Test $TOTAL_TESTS failed - Response does not contain expected PONG   response=\"${response}\""
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    fi

    # T9.2: Verify queries with OK_msg are NOT tracked in stats_mcp_query_digest
    # Since the rule exists from the beginning, intercepted queries should not create entries
    log_test "T9.2: Queries with OK_msg - no entries in stats_mcp_query_digest (intercepted)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    # Execute a PING query (should be intercepted by OK_msg rule)
    payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_sql_readonly","arguments":{"sql":"PING","target_id":"'"${MCP_TARGET_ID}"'"}},"id":1}'
    response=$(mcp_request "query" "$payload")
    log_verbose "Response: ${response}"

    # First, verify the response is successful and contains expected OK_msg
    if echo "$response" | grep -q '"isError":true'; then
        log_error "✗ Test $TOTAL_TESTS failed - Response contains isError:true   response=\"${response}\""
        FAILED_TESTS=$((FAILED_TESTS + 1))
    elif ! echo "$response" | grep -q 'PONG'; then
        log_error "✗ Test $TOTAL_TESTS failed - Response does not contain expected PONG   response=\"${response}\""
        FAILED_TESTS=$((FAILED_TESTS + 1))
    else
        # Response is valid, now check that no entry exists in stats_mcp_query_digest for PING queries
        ping_digest=$(exec_admin_silent "SELECT COUNT(*) FROM stats_mcp_query_digest WHERE digest_text LIKE '%PING%';")
        log_verbose "PING digest count: ${ping_digest}"

        if [ "$ping_digest" = "0" ]; then
            log_info "✓ Test $TOTAL_TESTS passed - stats_mcp_query_digest has no PING entries (queries intercepted)   count=\"${ping_digest}\" response_valid=\"true\""
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            log_error "✗ Test $TOTAL_TESTS failed - stats_mcp_query_digest has PING entries (queries were not intercepted)   count=\"${ping_digest}\""
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    fi

    # Also verify other intercepted queries are not tracked
    log_test "T9.2: Verify health_check queries are not tracked"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_sql_readonly","arguments":{"sql":"SELECT * FROM health_check;","target_id":"'"${MCP_TARGET_ID}"'"}},"id":1}'
    response=$(mcp_request "query" "$payload")
    log_verbose "Response: ${response}"

    # First, verify the response is successful and contains expected OK_msg
    if echo "$response" | grep -q '"isError":true'; then
        log_error "✗ Test $TOTAL_TESTS failed - Response contains isError:true   response=\"${response}\""
        FAILED_TESTS=$((FAILED_TESTS + 1))
    elif ! echo "$response" | grep -q 'Status: OK'; then
        log_error "✗ Test $TOTAL_TESTS failed - Response does not contain expected 'Status: OK'   response=\"${response}\""
        FAILED_TESTS=$((FAILED_TESTS + 1))
    else
        # Response is valid, now check that no entry exists in stats_mcp_query_digest for health_check queries
        health_digest=$(exec_admin_silent "SELECT COUNT(*) FROM stats_mcp_query_digest WHERE digest_text LIKE '%health_check%';")
        log_verbose "health_check digest count: ${health_digest}"

        if [ "$health_digest" = "0" ]; then
            log_info "✓ Test $TOTAL_TESTS passed - stats_mcp_query_digest has no health_check entries   count=\"${health_digest}\" response_valid=\"true\""
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            log_error "✗ Test $TOTAL_TESTS failed - stats_mcp_query_digest has health_check entries   count=\"${health_digest}\""
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    fi

    # Display runtime rules
    echo ""
    echo "Runtime rules created:"
    exec_admin "SELECT rule_id, match_pattern, OK_msg, re_modifiers FROM runtime_mcp_query_rules WHERE rule_id BETWEEN 100 AND 199 ORDER BY rule_id;"

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
