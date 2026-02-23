#!/bin/bash
#
# test_rag_tool_counters.sh - Test RAG Tool Invocation Counters
#
# Tests that tool usage tracking works for RAG endpoint tools
#

set -eo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the helper functions
if [ -f "${SCRIPT_DIR}/../mcp_rules_testing/mcp_test_helpers.sh" ]; then
    source "${SCRIPT_DIR}/../mcp_rules_testing/mcp_test_helpers.sh"
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

# Get tool usage stats for a specific tool
get_tool_stats() {
    local endpoint="$1"
    local tool_name="$2"
    local schema="$3"
    local query="SELECT count, sum_time, min_time, max_time FROM stats_mcp_query_tools_counters WHERE endpoint = '${endpoint}' AND tool = '${tool_name}' AND schema = '${schema}';"
    log_verbose "Admin query: ${query}" >&2
    local result=$(exec_admin_silent "${query}")
    if [ -n "$result" ]; then
        # Convert tabs to pipes for consistent parsing
        echo "$result" | tr '\t' '|'
    fi
}

main() {
    echo "======================================"
    echo "RAG Tool Invocation Counters Tests"
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

    # Clear any existing RAG stats
    exec_admin_silent "DELETE FROM stats_mcp_query_tools_counters WHERE endpoint = 'RAG' AND schema = 'rag';" >/dev/null 2>&1

    echo ""
    echo "======================================"
    echo "Test 1: FTS Search Counter"
    echo "======================================"
    echo ""

    # Get initial stats
    log_info "Getting initial stats for rag.search_fts..."
    INITIAL_STATS=$(get_tool_stats "RAG" "rag.search_fts" "rag")
    log_verbose "Initial stats: ${INITIAL_STATS}"

    # Execute rag.search_fts
    log_info "Executing rag.search_fts tool..."
    payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.search_fts","arguments":{"query":"mysql","k":5}},"id":1}'
    log_verbose "MCP request: ${payload}" >&2
    response=$(mcp_request "rag" "${payload}")
    log_verbose "Response: ${response}"

    # Check if response was successful (counter tracking works even with empty results)
    if echo "${response}" | grep -q '"isError":true'; then
        log_error "FTS search returned error - counter tracking may not work if tool handler crashes"
        response_error=1
    else
        log_info "FTS search executed (results may be empty if RAG DB is not populated)"
        response_error=0
    fi

    # Get stats after execution
    sleep 1
    FINAL_STATS=$(get_tool_stats "RAG" "rag.search_fts" "rag")
    log_verbose "Final stats: ${FINAL_STATS}"

    # Verify counter incremented
    if [ -z "${INITIAL_STATS}" ] && [ -n "${FINAL_STATS}" ]; then
        run_test "TR1.1: Counter created for rag.search_fts" true
    elif [ -n "${FINAL_STATS}" ]; then
        run_test "TR1.1: Counter exists for rag.search_fts" true
    else
        run_test "TR1.1: Counter exists for rag.search_fts" false
    fi

    echo ""
    echo "======================================"
    echo "Test 2: Admin Stats Counter"
    echo "======================================"
    echo ""

    # Get initial stats for admin tool
    log_info "Getting initial stats for rag.admin.stats..."
    INITIAL_ADMIN_STATS=$(get_tool_stats "RAG" "rag.admin.stats" "rag")
    log_verbose "Initial stats: ${INITIAL_ADMIN_STATS}"

    # Execute rag.admin.stats
    log_info "Executing rag.admin.stats tool..."
    admin_payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.admin.stats","arguments":{}},"id":2}'
    log_verbose "MCP request: ${admin_payload}" >&2
    admin_response=$(mcp_request "rag" "${admin_payload}")
    log_verbose "Response: ${admin_response}"

    # Get stats after execution
    sleep 1
    FINAL_ADMIN_STATS=$(get_tool_stats "RAG" "rag.admin.stats" "rag")
    log_verbose "Final stats: ${FINAL_ADMIN_STATS}"

    # Verify counter incremented
    if [ -z "${INITIAL_ADMIN_STATS}" ] && [ -n "${FINAL_ADMIN_STATS}" ]; then
        run_test "TR2.1: Counter created for rag.admin.stats" true
    elif [ -n "${FINAL_ADMIN_STATS}" ]; then
        run_test "TR2.1: Counter exists for rag.admin.stats" true
    else
        run_test "TR2.1: Counter exists for rag.admin.stats" false
    fi

    echo ""
    echo "======================================"
    echo "Test 3: Multiple Invocations"
    echo "======================================"
    echo ""

    # Execute same tool multiple times
    log_info "Executing rag.search_fts 3 more times..."
    for i in 1 2 3; do
        log_verbose "MCP request (${i}/3): ${payload}" >&2
        mcp_request "rag" "${payload}" >/dev/null
        log_verbose "Execution ${i}/3 complete"
    done
    sleep 1

    # Get final stats
    FINAL_STATS_MULTI=$(get_tool_stats "RAG" "rag.search_fts" "rag")
    log_verbose "Final stats after multiple executions: ${FINAL_STATS_MULTI}"

    # Parse count from stats (format: "count|sum_time|min_time|max_time")
    FINAL_COUNT=$(echo "${FINAL_STATS_MULTI}" | cut -d'|' -f1)
    log_verbose "Final count: ${FINAL_COUNT}"

    # Verify count is at least 4 (1 initial + 3 more)
    if [ "${FINAL_COUNT:-0}" -ge 4 ]; then
        run_test "TR3.1: Counter increments correctly with multiple invocations (count=${FINAL_COUNT})" true
    else
        run_test "TR3.1: Counter increments correctly with multiple invocations (count=${FINAL_COUNT})" false
    fi

    echo ""
    echo "======================================"
    echo "Test 4: Timing Statistics"
    echo "======================================"
    echo ""

    # Parse timing stats
    SUM_TIME=$(echo "${FINAL_STATS_MULTI}" | cut -d'|' -f2)
    MIN_TIME=$(echo "${FINAL_STATS_MULTI}" | cut -d'|' -f3)
    MAX_TIME=$(echo "${FINAL_STATS_MULTI}" | cut -d'|' -f4)

    log_verbose "Sum time: ${SUM_TIME} us"
    log_verbose "Min time: ${MIN_TIME} us"
    log_verbose "Max time: ${MAX_TIME} us"

    # Verify timing stats are reasonable
    # All should be positive integers
    if [ "${SUM_TIME:-0}" -gt 0 ] && [ "${MIN_TIME:-0}" -gt 0 ] && [ "${MAX_TIME:-0}" -gt 0 ]; then
        run_test "TR4.1: Timing statistics are positive values" true
    else
        run_test "TR4.1: Timing statistics are positive values" false
    fi

    # Max time should be >= min time
    if [ "${MAX_TIME:-0}" -ge "${MIN_TIME:-0}" ]; then
        run_test "TR4.2: Max time >= Min time" true
    else
        run_test "TR4.2: Max time >= Min time" false
    fi

    # Sum time should be >= max time
    if [ "${SUM_TIME:-0}" -ge "${MAX_TIME:-0}" ]; then
        run_test "TR4.3: Sum time >= Max time" true
    else
        run_test "TR4.3: Sum time >= Max time" false
    fi

    echo ""
    echo "======================================"
    echo "Test 5: Schema Column Value"
    echo "======================================"
    echo ""

    # Verify that schema column is set to "rag" for RAG tools
    log_verbose "Admin query: SELECT schema FROM stats_mcp_query_tools_counters WHERE endpoint = 'RAG' AND tool = 'rag.search_fts' LIMIT 1;"
    SCHEMA_CHECK=$(exec_admin_silent "SELECT schema FROM stats_mcp_query_tools_counters WHERE endpoint = 'RAG' AND tool = 'rag.search_fts' LIMIT 1;")
    if [ "${SCHEMA_CHECK}" = "rag" ]; then
        run_test "TR5.1: Schema column is set to 'rag' for RAG tools" true
    else
        run_test "TR5.1: Schema column is set to 'rag' for RAG tools (got: ${SCHEMA_CHECK})" false
    fi

    echo ""
    echo "======================================"
    echo "Test 6: Endpoint Column Value"
    echo "======================================"
    echo ""

    # Verify that endpoint column is set to "RAG"
    log_verbose "Admin query: SELECT endpoint FROM stats_mcp_query_tools_counters WHERE tool = 'rag.search_fts' AND schema = 'rag' LIMIT 1;"
    ENDPOINT_CHECK=$(exec_admin_silent "SELECT endpoint FROM stats_mcp_query_tools_counters WHERE tool = 'rag.search_fts' AND schema = 'rag' LIMIT 1;")
    if [ "${ENDPOINT_CHECK}" = "RAG" ]; then
        run_test "TR6.1: Endpoint column is set to 'RAG'" true
    else
        run_test "TR6.1: Endpoint column is set to 'RAG' (got: ${ENDPOINT_CHECK})" false
    fi

    echo ""
    echo "======================================"
    echo "Test 7: Unknown Tool Tracking"
    echo "======================================"
    echo ""

    # Try to call an unknown tool - should still be tracked
    log_info "Attempting to call unknown tool..."
    unknown_payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.unknown_tool","arguments":{}},"id":99}'
    log_verbose "MCP request: ${unknown_payload}" >&2
    unknown_response=$(mcp_request "rag" "${unknown_payload}")
    log_verbose "Response: ${unknown_response}"

    sleep 1

    # Verify that unknown tool was also tracked
    UNKNOWN_STATS=$(get_tool_stats "RAG" "rag.unknown_tool" "rag")
    if [ -n "${UNKNOWN_STATS}" ]; then
        run_test "TR7.1: Unknown tool invocations are tracked" true
    else
        run_test "TR7.1: Unknown tool invocations are tracked" false
    fi

    # Display all RAG tool stats
    echo ""
    echo "======================================"
    echo "RAG Tool Usage Statistics"
    echo "======================================"
    echo ""
    exec_admin "SELECT endpoint, tool, schema, count, sum_time, min_time, max_time FROM stats_mcp_query_tools_counters WHERE endpoint = 'RAG' AND schema = 'rag' ORDER BY tool;"

    # Summary
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
    else
        exit 0
    fi
}

main "$@"
