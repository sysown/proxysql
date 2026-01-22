#!/bin/bash
#
# test_phase2_load_save.sh - Test MCP Query Rules LOAD/SAVE Commands
#
# Phase 2: Test LOAD/SAVE commands across storage layers (memory, disk, runtime)
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
    exec_admin_silent "SELECT COUNT(*) FROM ${table} WHERE rule_id BETWEEN 100 AND 199;"
}

main() {
    echo "======================================"
    echo "Phase 2: LOAD/SAVE Commands Tests"
    echo "======================================"
    echo ""

    # Cleanup any existing test rules
    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id BETWEEN 100 AND 199;" >/dev/null 2>&1
    exec_admin_silent "DELETE FROM runtime_mcp_query_rules WHERE rule_id BETWEEN 100 AND 199;" >/dev/null 2>&1 || true

    # Create test rules
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (100, 1, 'TEST1', 'Error1', 1);" >/dev/null 2>&1
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (101, 1, 'TEST2', 'Error2', 1);" >/dev/null 2>&1

    # Test 2.1: LOAD MCP QUERY RULES TO MEMORY
    run_test "T2.1: LOAD MCP QUERY RULES TO MEMORY" \
        exec_admin "LOAD MCP QUERY RULES TO MEMORY;"

    # Test 2.2: LOAD MCP QUERY RULES FROM MEMORY
    run_test "T2.2: LOAD MCP QUERY RULES FROM MEMORY" \
        exec_admin "LOAD MCP QUERY RULES FROM MEMORY;"

    # Test 2.3: LOAD MCP QUERY RULES TO RUNTIME
    run_test "T2.3: LOAD MCP QUERY RULES TO RUNTIME" \
        exec_admin "LOAD MCP QUERY RULES TO RUNTIME;"

    # Test 2.4: Verify rules are in runtime after LOAD TO RUNTIME
    RUNTIME_COUNT=$(count_rules "runtime_mcp_query_rules")
    if [ "${RUNTIME_COUNT}" -ge 2 ]; then
        run_test "T2.4: Verify rules in runtime (count=${RUNTIME_COUNT})" true
    else
        run_test "T2.4: Verify rules in runtime (count=${RUNTIME_COUNT})" false
    fi

    # Test 2.5: SAVE MCP QUERY RULES TO DISK
    run_test "T2.5: SAVE MCP QUERY RULES TO DISK" \
        exec_admin "SAVE MCP QUERY RULES TO DISK;"

    # Test 2.6: SAVE MCP QUERY RULES TO MEMORY
    run_test "T2.6: SAVE MCP QUERY RULES TO MEMORY" \
        exec_admin "SAVE MCP QUERY RULES TO MEMORY;"

    # Test 2.7: SAVE MCP QUERY RULES FROM RUNTIME
    run_test "T2.7: SAVE MCP QUERY RULES FROM RUNTIME" \
        exec_admin "SAVE MCP QUERY RULES FROM RUNTIME;"

    # Test 2.8: Test persistence - modify a rule, save to disk, modify again, load from disk
    exec_admin_silent "UPDATE mcp_query_rules SET error_msg = 'Modified' WHERE rule_id = 100;" >/dev/null 2>&1
    exec_admin_silent "SAVE MCP QUERY RULES TO DISK;" >/dev/null 2>&1
    exec_admin_silent "UPDATE mcp_query_rules SET error_msg = 'Modified Again' WHERE rule_id = 100;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES FROM DISK;" >/dev/null 2>&1
    RESULT=$(exec_admin_silent "SELECT error_msg FROM mcp_query_rules WHERE rule_id = 100;")
    if [ "${RESULT}" = "Modified" ]; then
        run_test "T2.8: SAVE TO DISK / LOAD FROM DISK persistence" true
    else
        run_test "T2.8: SAVE TO DISK / LOAD FROM DISK persistence" false
    fi

    # Test 2.9: Test round-trip - memory -> runtime -> memory
    exec_admin_silent "UPDATE mcp_query_rules SET error_msg = 'RoundTrip Test' WHERE rule_id = 100;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    exec_admin_silent "SAVE MCP QUERY RULES FROM RUNTIME;" >/dev/null 2>&1
    RESULT=$(exec_admin_silent "SELECT error_msg FROM mcp_query_rules WHERE rule_id = 100;")
    if [ "${RESULT}" = "RoundTrip Test" ]; then
        run_test "T2.9: Round-trip memory -> runtime -> memory" true
    else
        run_test "T2.9: Round-trip memory -> runtime -> memory" false
    fi

    # Test 2.10: Add new rule and verify LOAD TO RUNTIME works
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (102, 1, 'NEWTEST', 'New Error', 1);" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    RUNTIME_COUNT=$(count_rules "runtime_mcp_query_rules")
    if [ "${RUNTIME_COUNT}" -ge 3 ]; then
        run_test "T2.10: New rule appears in runtime after LOAD" true
    else
        run_test "T2.10: New rule appears in runtime after LOAD" false
    fi

    # Display current state
    echo ""
    echo "Current rules in mcp_query_rules:"
    exec_admin "SELECT rule_id, active, match_pattern, error_msg FROM mcp_query_rules WHERE rule_id BETWEEN 100 AND 199 ORDER BY rule_id;"
    echo ""
    echo "Current rules in runtime_mcp_query_rules:"
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
