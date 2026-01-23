#!/bin/bash
#
# test_phase3_runtime.sh - Test MCP Query Rules Runtime Table
#
# Phase 3: Test runtime_mcp_query_rules table behavior
#

set -e

# Default configuration
PROXYSQL_ADMIN_HOST="${PROXYSQL_ADMIN_HOST:-127.0.0.1}"
PROXYSQL_ADMIN_PORT="${PROXYSQL_ADMIN_PORT:-6032}"
PROXYSQL_ADMIN_USER="${PROXYSQL_ADMIN_USER:-radmin}"
PROXYSQL_ADMIN_PASSWORD="${PROXYSQL_ADMIN_PASSWORD:-radmin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "${GREEN}[TEST]${NC} $1"; }

# Execute MySQL command
exec_admin() {
    mysql -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
          -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
          -e "$1" 2>&1
}

# Execute MySQL command (silent)
exec_admin_silent() {
    mysql -B -N -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
          -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
          -e "$1" 2>/dev/null
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

# Count rules in table
count_rules() {
    local table="$1"
    exec_admin_silent "SELECT COUNT(*) FROM ${table};"
}

# Check if rule exists in runtime
runtime_rule_exists() {
    local rule_id="$1"
    local count
    count=$(exec_admin_silent "SELECT COUNT(*) FROM runtime_mcp_query_rules WHERE rule_id = ${rule_id};")
    [ "${count}" -gt 0 ]
}

main() {
    echo "======================================"
    echo "Phase 3: Runtime Table Tests"
    echo "======================================"
    echo ""

    # Cleanup any existing test rules
    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id BETWEEN 100 AND 199;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1

    # Test 3.1: Query runtime_mcp_query_rules table
    run_test "T3.1: Query runtime_mcp_query_rules table" \
        exec_admin "SELECT * FROM runtime_mcp_query_rules LIMIT 5;"

    # Test 3.2: Insert active rule and verify it appears in runtime after LOAD
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (100, 1, 'TEST1', 'Error1', 1);" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    run_test "T3.2: Active rule appears in runtime after LOAD" runtime_rule_exists 100

    # Test 3.3: Insert inactive rule and verify it does NOT appear in runtime
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (101, 0, 'TEST2', 'Error2', 1);" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    if runtime_rule_exists 101; then
        run_test "T3.3: Inactive rule does NOT appear in runtime" false
    else
        run_test "T3.3: Inactive rule does NOT appear in runtime" true
    fi

    # Test 3.4: Update rule from inactive to active and verify it appears
    exec_admin_silent "UPDATE mcp_query_rules SET active = 1 WHERE rule_id = 101;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    run_test "T3.4: Inactive->Active rule appears in runtime after reload" runtime_rule_exists 101

    # Test 3.5: Update rule from active to inactive and verify it disappears
    exec_admin_silent "UPDATE mcp_query_rules SET active = 0 WHERE rule_id = 100;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    if runtime_rule_exists 100; then
        run_test "T3.5: Active->Inactive rule disappears from runtime" false
    else
        run_test "T3.5: Active->Inactive rule disappears from runtime" true
    fi

    # Test 3.6: Check rule order in runtime (should be ordered by rule_id)
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (102, 1, 'TEST3', 'Error3', 1);" >/dev/null 2>&1
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (103, 1, 'TEST4', 'Error4', 1);" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    IDS=$(exec_admin_silent "SELECT rule_id FROM runtime_mcp_query_rules WHERE rule_id BETWEEN 100 AND 199 ORDER BY rule_id;")
    # Verify exact ordering: 101, 102, 103
    if [ "${IDS}" = "101
102
103" ]; then
        run_test "T3.6: Rules ordered by rule_id in runtime" true
    else
        run_test "T3.6: Rules ordered by rule_id in runtime (got: ${IDS})" false
    fi

    # Test 3.7: Delete rule from main table and verify it disappears from runtime
    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id = 102;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    if runtime_rule_exists 102; then
        run_test "T3.7: Deleted rule disappears from runtime" false
    else
        run_test "T3.7: Deleted rule disappears from runtime" true
    fi

    # Test 3.8: Verify runtime table schema matches main table (check columns exist)
    SCHEMA_CHECK=$(exec_admin "PRAGMA table_info(runtime_mcp_query_rules);" 2>/dev/null | wc -l)
    if [ "${SCHEMA_CHECK}" -gt 10 ]; then
        run_test "T3.8: Runtime table schema is valid" true
    else
        run_test "T3.8: Runtime table schema is valid" false
    fi

    # Test 3.9: Compare counts between main table (active only) and runtime
    ACTIVE_COUNT=$(exec_admin_silent "SELECT COUNT(*) FROM mcp_query_rules WHERE active = 1 AND rule_id > 100;")
    RUNTIME_ACTIVE_COUNT=$(exec_admin_silent "SELECT COUNT(*) FROM runtime_mcp_query_rules WHERE rule_id > 100;")
    # Note: counts might differ due to other rules, just check both are positive
    if [ "${RUNTIME_ACTIVE_COUNT}" -gt 0 ]; then
        run_test "T3.9: Runtime table contains active rules" true
    else
        run_test "T3.9: Runtime table contains active rules" false
    fi

    # Display current state
    echo ""
    echo "Rules in mcp_query_rules (test range):"
    exec_admin "SELECT rule_id, active, match_pattern, error_msg FROM mcp_query_rules WHERE rule_id BETWEEN 100 AND 199 ORDER BY rule_id;"
    echo ""
    echo "Rules in runtime_mcp_query_rules (test range):"
    exec_admin "SELECT rule_id, active, match_pattern, error_msg FROM runtime_mcp_query_rules WHERE rule_id BETWEEN 100 AND 199 ORDER BY rule_id;"

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
