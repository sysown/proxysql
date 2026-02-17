#!/bin/bash
#
# test_phase11_pgsql_target.sh - Validate MCP rule/stats behavior on pgsql target
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

main() {
    echo "======================================"
    echo "Phase 11: pgsql Target / Rules / Stats"
    echo "======================================"
    echo ""

    # Watermark in ProxySQL error log to correlate this phase boundaries.
    exec_admin_silent "LOGENTRY phase 11 of MCP query rules test : starting;" >/dev/null 2>&1 || true
    trap 'exec_admin_silent "LOGENTRY phase 11 of MCP query rules test : ended;" >/dev/null 2>&1 || true' EXIT

    if ! check_proxysql_admin; then
        log_error "Cannot connect to ProxySQL admin at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
        exit 1
    fi
    if ! check_mcp_server; then
        log_error "MCP server not accessible at ${MCP_HOST}:${MCP_PORT}"
        exit 1
    fi

    local pg_target_id
    pg_target_id="${MCP_PGSQL_TARGET_ID:-}"
    if [ -z "${pg_target_id}" ]; then
        pg_target_id=$(exec_admin_silent "SELECT target_id FROM runtime_mcp_target_profiles WHERE protocol='pgsql' AND active=1 ORDER BY target_id LIMIT 1;")
    fi

    if [ -z "${pg_target_id}" ]; then
        echo "msg: # No runtime pgsql MCP target found (set MCP_PGSQL_TARGET_ID or configure one). Skipping Phase 11."
        exit 0
    fi

    local pg_username
    pg_username=$(exec_admin_silent "SELECT a.db_username FROM runtime_mcp_target_profiles t JOIN runtime_mcp_auth_profiles a ON a.auth_profile_id=t.auth_profile_id WHERE t.target_id='${pg_target_id}' LIMIT 1;")
    if [ -z "${pg_username}" ]; then
        echo "msg: # Could not resolve db_username for pgsql target '${pg_target_id}'. Skipping Phase 11."
        exit 0
    fi

    # Isolate this phase from rules possibly left by previous phase failures.
    exec_admin_silent "DELETE FROM mcp_query_rules;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1

    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, tool_name, target_id, match_pattern, error_msg, apply) VALUES (190, 1, 'run_sql_readonly', '${pg_target_id}', 'phase11_pg_target_block', 'Phase11: pg target rule matched', 1);" >/dev/null 2>&1
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, tool_name, username, match_pattern, error_msg, apply) VALUES (191, 1, 'run_sql_readonly', '${pg_username}', 'phase11_pg_user_block', 'Phase11: pg username rule matched', 1);" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    sleep 1

    local resp_block_target
    resp_block_target=$(mcp_request "query" "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"run_sql_readonly\",\"arguments\":{\"sql\":\"SELECT 'phase11_pg_target_block' AS phase11_pg_target_block\",\"target_id\":\"${pg_target_id}\"}},\"id\":1}")
    log_verbose "T11.1 response: ${resp_block_target}"
    run_test "T11.1: pgsql target_id rule blocks run_sql_readonly" \
        bash -c '[[ "$1" == *"\"isError\":true"* && "$1" == *"Phase11: pg target rule matched"* ]]' _ "${resp_block_target}"

    local resp_block_user
    resp_block_user=$(mcp_request "query" "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"run_sql_readonly\",\"arguments\":{\"sql\":\"SELECT 'phase11_pg_user_block' AS phase11_pg_user_block\",\"target_id\":\"${pg_target_id}\"}},\"id\":2}")
    log_verbose "T11.2 response: ${resp_block_user}"
    run_test "T11.2: pgsql username rule blocks run_sql_readonly" \
        bash -c '[[ "$1" == *"\"isError\":true"* && "$1" == *"Phase11: pg username rule matched"* ]]' _ "${resp_block_user}"

    local resp_ok
    resp_ok=$(mcp_request "query" "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"run_sql_readonly\",\"arguments\":{\"sql\":\"SELECT 1\",\"target_id\":\"${pg_target_id}\"}},\"id\":3}")
    log_verbose "T11.3 response: ${resp_ok}"
    run_test "T11.3: pgsql run_sql_readonly executes on target" \
        bash -c '[[ "$1" != *"\"isError\":true"* ]]' _ "${resp_ok}"

    local resp_explain
    resp_explain=$(mcp_request "query" "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"explain_sql\",\"arguments\":{\"sql\":\"SELECT 1\",\"target_id\":\"${pg_target_id}\"}},\"id\":4}")
    log_verbose "T11.4 response: ${resp_explain}"
    run_test "T11.4: pgsql explain_sql executes on target" \
        bash -c '[[ "$1" != *"\"isError\":true"* ]]' _ "${resp_explain}"

    local stats_190
    stats_190=$(exec_admin_silent "SELECT COALESCE(username,'') || '|' || COALESCE(target_id,'') FROM stats_mcp_query_rules WHERE rule_id=190;")
    run_test "T11.5: stats include target_id for pgsql target rule" \
        bash -c "[ \"${stats_190}\" = \"|${pg_target_id}\" ]"

    local stats_191
    stats_191=$(exec_admin_silent "SELECT COALESCE(username,'') || '|' || COALESCE(target_id,'') FROM stats_mcp_query_rules WHERE rule_id=191;")
    run_test "T11.6: stats include username for pgsql user rule" \
        bash -c "[ \"${stats_191}\" = \"${pg_username}|\" ]"

    echo ""
    echo "Phase11 runtime rules:"
    exec_admin "SELECT rule_id, username, target_id, tool_name, match_pattern, error_msg FROM runtime_mcp_query_rules WHERE rule_id BETWEEN 190 AND 199 ORDER BY rule_id;"
    echo ""
    echo "Phase11 rule stats:"
    exec_admin "SELECT rule_id, username, target_id, hits FROM stats_mcp_query_rules WHERE rule_id BETWEEN 190 AND 199 ORDER BY rule_id;"

    exec_admin_silent "DELETE FROM mcp_query_rules;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    exec_admin_silent "LOGENTRY phase 11 of MCP query rules test : ended;" >/dev/null 2>&1 || true

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
