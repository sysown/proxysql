#!/bin/bash
#
# test_phase1_crud.sh - Test MCP Query Rules CRUD Operations
#
# Phase 1: Test CREATE, READ, UPDATE, DELETE operations on mcp_query_rules table
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

# Check if table has rule
rule_exists() {
    local rule_id="$1"
    local count
    count=$(exec_admin_silent "SELECT COUNT(*) FROM mcp_query_rules WHERE rule_id = ${rule_id};")
    [ "${count}" -gt 0 ]
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

main() {
    echo "======================================"
    echo "Phase 1: MCP Query Rules CRUD Tests"
    echo "======================================"
    echo ""

    # Cleanup any existing test rules
    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id BETWEEN 100 AND 199;" >/dev/null 2>&1

    # Test 1.1: Create a basic rule with match_pattern
    run_test "T1.1: Create basic rule with match_pattern" \
        exec_admin "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) \
                    VALUES (100, 1, 'DROP TABLE', 'Blocked', 1);"

    # Test 1.2: Verify rule was created
    run_test "T1.2: Verify rule exists in table" rule_exists 100

    # Test 1.3: Read the rule back
    run_test "T1.3: Read rule from table" \
        exec_admin "SELECT rule_id, active, match_pattern, error_msg FROM mcp_query_rules WHERE rule_id = 100;" >/dev/null

    # Test 1.4: Create rule with all action types
    run_test "T1.4: Create rule with all action types" \
        exec_admin "INSERT INTO mcp_query_rules (rule_id, active, username, schemaname, tool_name, \
                    match_pattern, replace_pattern, timeout_ms, error_msg, OK_msg, apply, comment) \
                    VALUES (101, 1, 'testuser', 'testdb', 'run_sql_readonly', \
                    'SELECT.*FROM.*test', 'SELECT COUNT(*) FROM test', 5000, \
                    'Error msg', 'OK msg', 1, 'Full rule test');"

    # Test 1.5: Create rule with username filter
    run_test "T1.5: Create rule with username filter" \
        exec_admin "INSERT INTO mcp_query_rules (rule_id, active, username, match_pattern, error_msg, apply) \
                    VALUES (102, 1, 'adminuser', 'DELETE FROM', 'Blocked for admin', 1);"

    # Test 1.6: Create rule with schemaname filter
    run_test "T1.6: Create rule with schemaname filter" \
        exec_admin "INSERT INTO mcp_query_rules (rule_id, active, schemaname, match_pattern, error_msg, apply) \
                    VALUES (103, 1, 'proddb', 'TRUNCATE', 'Blocked in proddb', 1);"

    # Test 1.7: Create rule with tool_name filter
    run_test "T1.7: Create rule with tool_name filter" \
        exec_admin "INSERT INTO mcp_query_rules (rule_id, active, tool_name, match_pattern, error_msg, apply) \
                    VALUES (104, 1, 'run_sql_readonly', 'INSERT INTO', 'Blocked on readonly', 1);"

    # Test 1.8: Update existing rule
    run_test "T1.8: Update rule error_msg" \
        exec_admin "UPDATE mcp_query_rules SET error_msg = 'Updated error message' WHERE rule_id = 100;"

    # Test 1.9: Verify update worked
    RESULT=$(exec_admin_silent "SELECT error_msg FROM mcp_query_rules WHERE rule_id = 100;")
    if [ "${RESULT}" = "Updated error message" ]; then
        run_test "T1.9: Verify update succeeded" true
    else
        run_test "T1.9: Verify update succeeded" false
    fi

    # Test 1.10: Update multiple fields
    run_test "T1.10: Update multiple fields" \
        exec_admin "UPDATE mcp_query_rules SET active = 0, match_pattern = 'ALTER TABLE' WHERE rule_id = 101;"

    # Test 1.11: Create rule with flagIN/flagOUT
    run_test "T1.11: Create rule with flagIN/flagOUT" \
        exec_admin "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, flagIN, flagOUT, apply, comment) \
                    VALUES (105, 1, 'SELECT', 0, 100, 1, 'Flag chaining rule 1');"

    # Test 1.12: Create second rule for chaining (flagIN=100)
    run_test "T1.12: Create chaining rule with flagIN=100" \
        exec_admin "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, flagIN, apply, comment) \
                    VALUES (106, 1, '.*customers.*', 100, 1, 'Flag chaining rule 2');"

    # Test 1.13: Count all test rules
    COUNT=$(exec_admin_silent "SELECT COUNT(*) FROM mcp_query_rules WHERE rule_id BETWEEN 100 AND 199;")
    if [ "${COUNT}" -ge 7 ]; then
        run_test "T1.13: Verify all rules created (count=${COUNT})" true
    else
        run_test "T1.13: Verify all rules created (count=${COUNT})" false
    fi

    # Test 1.14: Delete a rule
    run_test "T1.14: Delete rule" \
        exec_admin "DELETE FROM mcp_query_rules WHERE rule_id = 106;"

    # Test 1.15: Verify deletion
    if ! rule_exists 106; then
        run_test "T1.15: Verify rule deleted" true
    else
        run_test "T1.15: Verify rule deleted" false
    fi

    # Test 1.16: Delete multiple rules
    run_test "T1.16: Delete multiple rules" \
        exec_admin "DELETE FROM mcp_query_rules WHERE rule_id IN (104, 105);"

    # Display remaining test rules
    echo ""
    echo "Remaining test rules:"
    exec_admin "SELECT rule_id, active, username, schemaname, tool_name, match_pattern FROM mcp_query_rules WHERE rule_id BETWEEN 100 AND 199 ORDER BY rule_id;"

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

    if [ ${FAILED_TESTS} -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

main "$@"
