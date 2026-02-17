#!/bin/bash
#
# test_phase10_eval_explain.sh - Test MCP Query Rules on explain_sql
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/mcp_test_helpers.sh" ]; then
    source "${SCRIPT_DIR}/mcp_test_helpers.sh"
else
    echo "ERROR: mcp_test_helpers.sh not found at ${SCRIPT_DIR}"
    exit 1
fi

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

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

explain_request() {
    local sql="$1"
    local payload
    payload=$(cat <<EOF
{"jsonrpc":"2.0","method":"tools/call","params":{"name":"explain_sql","arguments":{"sql":"${sql}","target_id":"${MCP_TARGET_ID}"}},"id":1}
EOF
)
    mcp_request "query" "${payload}"
}

explain_is_blocked() {
    local sql="$1"
    local expected="$2"
    local response
    response=$(explain_request "${sql}")
    log_verbose "Response: ${response}"
    echo "${response}" | grep -q '"isError":true' && echo "${response}" | grep -qi "${expected}"
}

explain_is_allowed() {
    local sql="$1"
    local response
    response=$(explain_request "${sql}")
    log_verbose "Response: ${response}"
    ! echo "${response}" | grep -q '"isError":true'
}

explain_returns_okmsg() {
    local sql="$1"
    local expected="$2"
    local response
    response=$(explain_request "${sql}")
    log_verbose "Response: ${response}"
    ! echo "${response}" | grep -q '"isError":true' && echo "${response}" | grep -qi "${expected}"
}

main() {
    echo "======================================"
    echo "Phase 10: Rule Evaluation - explain_sql"
    echo "======================================"
    echo ""

    if ! check_proxysql_admin; then
        log_error "Cannot connect to ProxySQL admin at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
        exit 1
    fi
    if ! check_mcp_server; then
        log_error "MCP server not accessible at ${MCP_HOST}:${MCP_PORT}"
        exit 1
    fi

    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id BETWEEN 180 AND 199;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1

    log_info "Creating explain_sql-specific MCP rules..."
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, tool_name, match_pattern, error_msg, apply) VALUES (180, 1, 'explain_sql', 'DROP TABLE', 'Phase10: DROP blocked in explain_sql', 1);" >/dev/null 2>&1
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, tool_name, username, match_pattern, error_msg, apply) VALUES (181, 1, 'explain_sql', '${MYSQL_USER}', 'phase10_user_block', 'Phase10: username rule matched', 1);" >/dev/null 2>&1
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, tool_name, target_id, match_pattern, error_msg, apply) VALUES (182, 1, 'explain_sql', '${MCP_TARGET_ID}', 'phase10_target_block', 'Phase10: target_id rule matched', 1);" >/dev/null 2>&1
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, tool_name, match_pattern, OK_msg, apply) VALUES (183, 1, 'explain_sql', '^SELECT\\s+1$', 'Phase10: explain OK message', 1);" >/dev/null 2>&1
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, tool_name, match_pattern, replace_pattern, apply) VALUES (184, 1, 'explain_sql', 'phase10_rewrite_me', 'SELECT 1', 1);" >/dev/null 2>&1

    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    sleep 1

    run_test "T10.1: explain_sql block rule applies" \
        explain_is_blocked "DROP TABLE phase10_t;" "Phase10: DROP blocked"

    run_test "T10.2: explain_sql username rule applies" \
        explain_is_blocked "SELECT 'phase10_user_block' AS phase10_user_block;" "Phase10: username rule matched"

    run_test "T10.3: explain_sql target_id rule applies" \
        explain_is_blocked "SELECT 'phase10_target_block' AS phase10_target_block;" "Phase10: target_id rule matched"

    run_test "T10.4: explain_sql OK_msg works" \
        explain_returns_okmsg "SELECT 1" "Phase10: explain OK message"

    run_test "T10.5: explain_sql rewrite rule works" \
        explain_is_allowed "phase10_rewrite_me"

    run_test "T10.6: Runtime contains explain_sql target/user columns" \
        bash -c "[ \$(exec_admin_silent \"SELECT COUNT(*) FROM runtime_mcp_query_rules WHERE rule_id IN (181,182) AND (username IS NOT NULL OR target_id IS NOT NULL)\") -ge 2 ]"

    echo ""
    echo "Runtime rules:"
    exec_admin "SELECT rule_id, tool_name, username, target_id, match_pattern, error_msg, OK_msg FROM runtime_mcp_query_rules WHERE rule_id BETWEEN 180 AND 199 ORDER BY rule_id;"

    echo ""
    echo "Rule hit statistics:"
    exec_admin "SELECT rule_id, username, target_id, hits FROM stats_mcp_query_rules WHERE rule_id BETWEEN 180 AND 199 ORDER BY rule_id;"

    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id BETWEEN 180 AND 199;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1

    echo ""
    echo "======================================"
    echo "Test Summary"
    echo "======================================"
    echo "Total tests:   ${TOTAL_TESTS}"
    echo -e "Passed:        ${GREEN}${PASSED_TESTS}${NC}"
    echo -e "Failed:        ${RED}${FAILED_TESTS}${NC}"
    echo ""

    if [ ${FAILED_TESTS} -gt 0 ]; then
        exit 1
    fi
    exit 0
}

main "$@"

