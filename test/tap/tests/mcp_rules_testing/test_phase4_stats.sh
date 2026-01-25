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

# Get hit count for a rule
get_hits() {
    local rule_id="$1"
    exec_admin_silent "SELECT hits FROM stats_mcp_query_rules WHERE rule_id = ${rule_id};"
}

main() {
    echo "======================================"
    echo "Phase 4: Statistics Table Tests"
    echo "======================================"
    echo ""

    # Check connections
    if ! check_proxysql_admin; then
        log_error "Cannot connect to ProxySQL admin at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
        exit 1
    fi
    log_info "Connected to ProxySQL admin"

    if ! check_mcp_server; then
        log_error "MCP server not accessible at ${MCP_HOST}:${MCP_PORT}"
        exit 1
    fi
    log_info "MCP server is accessible"

    # Cleanup any existing test rules
    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id BETWEEN 100 AND 199;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1

    # Test 4.1: Query stats_mcp_query_rules table
    run_test "T4.1: Query stats_mcp_query_rules table" \
        exec_admin "SELECT * FROM stats_mcp_query_rules LIMIT 5;"

    # Create test rules
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (100, 1, 'SELECT.*FROM.*test_table', 'Error 100', 1);" >/dev/null 2>&1
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (101, 1, 'DROP TABLE', 'Error 101', 1);" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1

    # Test 4.2: Check that rules exist in stats table with initial hits=0
    sleep 1
    HITS_100=$(get_hits 100)
    HITS_101=$(get_hits 101)
    if [ -n "${HITS_100}" ] && [ -n "${HITS_101}" ]; then
        run_test "T4.2: Rules appear in stats table after load" true
    else
        run_test "T4.2: Rules appear in stats table after load" false
    fi

    # Test 4.3: Verify initial hit count is 0 or non-negative
    if [ "${HITS_100:-0}" -ge 0 ] && [ "${HITS_101:-0}" -ge 0 ]; then
        run_test "T4.3: Initial hit counts are non-negative" true
    else
        run_test "T4.3: Initial hit counts are non-negative" false
    fi

    # Test 4.4: Check stats table schema (rule_id, hits columns)
    SCHEMA_INFO=$(exec_admin "PRAGMA table_info(stats_mcp_query_rules);" 2>/dev/null)
    if echo "${SCHEMA_INFO}" | grep -q "rule_id" && echo "${SCHEMA_INFO}" | grep -q "hits"; then
        run_test "T4.4: Stats table has rule_id and hits columns" true
    else
        run_test "T4.4: Stats table has rule_id and hits columns" false
    fi

    # Test 4.5: Query stats for specific rule_id
    run_test "T4.5: Query stats for specific rule_id" \
        exec_admin "SELECT rule_id, hits FROM stats_mcp_query_rules WHERE rule_id = 100;"

    # Test 4.6: Query stats for multiple rule_ids using IN
    run_test "T4.6: Query stats for multiple rules using IN" \
        exec_admin "SELECT rule_id, hits FROM stats_mcp_query_rules WHERE rule_id IN (100, 101);"

    # Test 4.7: Query stats for rule_id range
    run_test "T4.7: Query stats for rule_id range" \
        exec_admin "SELECT rule_id, hits FROM stats_mcp_query_rules WHERE rule_id BETWEEN 100 AND 199 ORDER BY rule_id;"

    # Test 4.8: Check that non-existent rule returns NULL or empty
    NO_HITS=$(exec_admin_silent "SELECT hits FROM stats_mcp_query_rules WHERE rule_id = 9999;")
    if [ -z "${NO_HITS}" ]; then
        run_test "T4.8: Non-existent rule returns empty result" true
    else
        run_test "T4.8: Non-existent rule returns empty result" false
    fi

    # Test 4.9: Verify stats table is read-only (cannot directly insert)
    exec_admin_silent "INSERT INTO stats_mcp_query_rules (rule_id, hits) VALUES (999, 100);" 2>/dev/null || true
    INSERT_CHECK=$(exec_admin_silent "SELECT COUNT(*) FROM stats_mcp_query_rules WHERE rule_id = 999;")
    if [ "${INSERT_CHECK:-0}" -eq 0 ]; then
        run_test "T4.9: Stats table is read-only (insert ignored)" true
    else
        run_test "T4.9: Stats table is read-only (insert ignored)" false
    fi
    exec_admin_silent "DELETE FROM stats_mcp_query_rules WHERE rule_id = 999;" 2>/dev/null || true

    # Test 4.10: Test ORDER BY on hits column
    run_test "T4.10: Query stats ordered by hits" \
        exec_admin "SELECT rule_id, hits FROM stats_mcp_query_rules WHERE rule_id IN (100, 101) ORDER BY hits DESC;"

    # Test 4.11: Create additional rules and verify they appear in stats
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (102, 1, 'SELECT.*FROM.*products', 'Error 102', 1);" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    sleep 1
    HITS_102=$(get_hits 102)
    if [ -n "${HITS_102}" ]; then
        run_test "T4.11: New rule appears in stats after runtime load" true
    else
        run_test "T4.11: New rule appears in stats after runtime load" false
    fi

    echo ""
    echo "======================================"
    echo "Testing Hit Counter Increments"
    echo "======================================"
    echo ""

    # Get initial hit counts
    HITS_BEFORE_100=$(get_hits 100)
    HITS_BEFORE_101=$(get_hits 101)

    # Test 4.12: Execute MCP query matching rule 100 and verify hit counter increments
    log_info "Executing query matching rule 100..."
    PAYLOAD_100='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_sql_readonly","arguments":{"sql":"SELECT * FROM test_table"}},"id":1}'
    mcp_request "query" "${PAYLOAD_100}" >/dev/null
    sleep 1
    HITS_AFTER_100=$(get_hits 100)
    if [ "${HITS_AFTER_100:-0}" -gt "${HITS_BEFORE_100:-0}" ]; then
        run_test "T4.12: Hit counter incremented for rule 100 (from ${HITS_BEFORE_100:-0} to ${HITS_AFTER_100})" true
    else
        run_test "T4.12: Hit counter incremented for rule 100" false
    fi

    # Test 4.13: Execute MCP query matching rule 101 and verify hit counter increments
    log_info "Executing query matching rule 101..."
    PAYLOAD_101='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_sql_readonly","arguments":{"sql":"DROP TABLE IF EXISTS dummy_table"}},"id":2}'
    mcp_request "query" "${PAYLOAD_101}" >/dev/null
    sleep 1
    HITS_AFTER_101=$(get_hits 101)
    if [ "${HITS_AFTER_101:-0}" -gt "${HITS_BEFORE_101:-0}" ]; then
        run_test "T4.13: Hit counter incremented for rule 101 (from ${HITS_BEFORE_101:-0} to ${HITS_AFTER_101})" true
    else
        run_test "T4.13: Hit counter incremented for rule 101" false
    fi

    # Test 4.14: Execute same query again and verify counter increments again
    log_info "Executing same query for rule 100 again..."
    mcp_request "query" "${PAYLOAD_100}" >/dev/null
    sleep 1
    HITS_FINAL_100=$(get_hits 100)
    if [ "${HITS_FINAL_100:-0}" -gt "${HITS_AFTER_100:-0}" ]; then
        run_test "T4.14: Hit counter increments on repeated matches (from ${HITS_AFTER_100} to ${HITS_FINAL_100})" true
    else
        run_test "T4.14: Hit counter increments on repeated matches" false
    fi

    # Test 4.15: Execute query NOT matching any rule and verify no test rule counter increments
    log_info "Executing query NOT matching any test rule..."
    PAYLOAD_NO_MATCH='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_sql_readonly","arguments":{"sql":"SELECT * FROM other_table"}},"id":3}'
    HITS_BEFORE_NO_MATCH_100=$(get_hits 100)
    HITS_BEFORE_NO_MATCH_101=$(get_hits 101)
    mcp_request "query" "${PAYLOAD_NO_MATCH}" >/dev/null
    sleep 1
    HITS_AFTER_NO_MATCH_100=$(get_hits 100)
    HITS_AFTER_NO_MATCH_101=$(get_hits 101)
    if [ "${HITS_AFTER_NO_MATCH_100}" = "${HITS_BEFORE_NO_MATCH_100}" ] && [ "${HITS_AFTER_NO_MATCH_101}" = "${HITS_BEFORE_NO_MATCH_101}" ]; then
        run_test "T4.15: Hit counters NOT incremented for non-matching query" true
    else
        run_test "T4.15: Hit counters NOT incremented for non-matching query" false
    fi

    # Display current stats
    echo ""
    echo "Current stats for test rules:"
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

    if [ ${FAILED_TESTS} -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

main "$@"
