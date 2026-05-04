#!/bin/bash
#
# test_rag_search_log.sh - Test RAG Search Logging
#
# Tests that rag.search_fts operations are properly logged to rag_search_log table
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

# Get search log entries for a specific query
get_search_log() {
    local query_pattern="$1"
    local sql="SELECT log_id, query, k, filters, searched_at FROM rag_search_log WHERE query = '${query_pattern}' ORDER BY log_id DESC LIMIT 1;"
    log_verbose "Admin query: ${sql}" >&2
    local result=$(exec_admin_silent "${sql}")
    if [ -n "$result" ]; then
        # Convert tabs to pipes for consistent parsing
        echo "$result" | tr '\t' '|'
    fi
}

# Count total search log entries
count_search_log() {
    local sql="SELECT COUNT(*) FROM rag_search_log;"
    log_verbose "Admin query: ${sql}" >&2
    exec_admin_silent "${sql}"
}

main() {
    echo "======================================"
    echo "RAG Search Logging Tests"
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

    # Clear any existing search log entries
    exec_admin_silent "DELETE FROM rag_search_log;" >/dev/null 2>&1
    log_info "Cleared existing search log entries"

    echo ""
    echo "======================================"
    echo "Test 1: Basic Search Logging"
    echo "======================================"
    echo ""

    # Get initial count
    log_info "Getting initial search log count..."
    INITIAL_COUNT=$(count_search_log)
    log_verbose "Initial count: ${INITIAL_COUNT}"

    # Execute a simple FTS search
    log_info "Executing rag.search_fts with query 'mysql'..."
    payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.search_fts","arguments":{"query":"mysql","k":5}},"id":1}'
    log_verbose "MCP request: ${payload}" >&2
    response=$(mcp_request "rag" "${payload}")
    log_verbose "Response: ${response}"

    # Wait for logging
    sleep 1

    # Get final count
    FINAL_COUNT=$(count_search_log)
    log_verbose "Final count: ${FINAL_COUNT}"

    # Verify a new entry was created
    if [ "${FINAL_COUNT:-0}" -gt "${INITIAL_COUNT:-0}" ]; then
        run_test "TR1.1: Search log entry created" true
    else
        run_test "TR1.1: Search log entry created" false
    fi

    echo ""
    echo "======================================"
    echo "Test 2: Query Text Logging"
    echo "======================================"
    echo ""

    # Get the log entry for 'mysql' query
    log_info "Retrieving search log entry for query 'mysql'..."
    LOG_ENTRY=$(get_search_log "mysql")
    log_verbose "Log entry: ${LOG_ENTRY}"

    if [ -n "${LOG_ENTRY}" ]; then
        # Parse the entry: log_id|query|k|filters|searched_at
        LOGGED_QUERY=$(echo "${LOG_ENTRY}" | cut -d'|' -f2)
        log_verbose "Logged query: ${LOGGED_QUERY}"

        if [ "${LOGGED_QUERY}" = "mysql" ]; then
            run_test "TR2.1: Query text is correctly logged" true
        else
            run_test "TR2.1: Query text is correctly logged (expected: mysql, got: ${LOGGED_QUERY})" false
        fi
    else
        run_test "TR2.1: Query text is correctly logged" false
        log_error "No log entry found for query 'mysql'"
    fi

    echo ""
    echo "======================================"
    echo "Test 3: K Parameter Logging"
    echo "======================================"
    echo ""

    if [ -n "${LOG_ENTRY}" ]; then
        LOGGED_K=$(echo "${LOG_ENTRY}" | cut -d'|' -f3)
        log_verbose "Logged k: ${LOGGED_K}"

        if [ "${LOGGED_K}" = "5" ]; then
            run_test "TR3.1: K parameter is correctly logged" true
        else
            run_test "TR3.1: K parameter is correctly logged (expected: 5, got: ${LOGGED_K})" false
        fi
    else
        run_test "TR3.1: K parameter is correctly logged" false
    fi

    echo ""
    echo "======================================"
    echo "Test 4: Filters Logging"
    echo "======================================"
    echo ""

    # Execute a search with filters
    log_info "Executing rag.search_fts with filters..."
    filters_payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.search_fts","arguments":{"query":"database","k":10,"filters":{"source_ids":[1]}}},"id":2}'
    log_verbose "MCP request: ${filters_payload}" >&2
    filters_response=$(mcp_request "rag" "${filters_payload}")
    log_verbose "Response: ${filters_response}"

    # Wait for logging
    sleep 1

    # Get the log entry for 'database' query with filters
    log_info "Retrieving search log entry for query 'database'..."
    FILTERS_LOG_ENTRY=$(get_search_log "database")
    log_verbose "Log entry: ${FILTERS_LOG_ENTRY}"

    if [ -n "${FILTERS_LOG_ENTRY}" ]; then
        LOGGED_FILTERS=$(echo "${FILTERS_LOG_ENTRY}" | cut -d'|' -f4)
        log_verbose "Logged filters: ${LOGGED_FILTERS}"

        # Check that filters JSON is present (should contain source_ids)
        if echo "${LOGGED_FILTERS}" | grep -q "source_ids"; then
            run_test "TR4.1: Filters are correctly logged" true
        else
            run_test "TR4.1: Filters are correctly logged (filters: ${LOGGED_FILTERS})" false
        fi
    else
        run_test "TR4.1: Filters are correctly logged" false
        log_error "No log entry found for query 'database'"
    fi

    echo ""
    echo "======================================"
    echo "Test 5: Timestamp Logging"
    echo "======================================"
    echo ""

    if [ -n "${LOG_ENTRY}" ]; then
        LOGGED_TIMESTAMP=$(echo "${LOG_ENTRY}" | cut -d'|' -f5)
        log_verbose "Logged timestamp: ${LOGGED_TIMESTAMP}"

        # Check that timestamp is not empty and looks like ISO format
        if [ -n "${LOGGED_TIMESTAMP}" ] && echo "${LOGGED_TIMESTAMP}" | grep -qE "^[0-9]{4}-[0-9]{2}-[0-9]{2}"; then
            run_test "TR5.1: Timestamp is correctly logged" true
        else
            run_test "TR5.1: Timestamp is correctly logged (timestamp: ${LOGGED_TIMESTAMP})" false
        fi
    else
        run_test "TR5.1: Timestamp is correctly logged" false
    fi

    echo ""
    echo "======================================"
    echo "Test 6: Multiple Search Logging"
    echo "======================================"
    echo ""

    # Get count before multiple searches
    COUNT_BEFORE=$(count_search_log)
    log_verbose "Count before: ${COUNT_BEFORE}"

    # Execute multiple searches
    log_info "Executing 3 different searches..."
    for search_term in "proxy" "sql" "cache"; do
        search_payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.search_fts","arguments":{"query":"'"${search_term}"'","k":3}},"id":3}'
        log_verbose "MCP request: ${search_payload}" >&2
        mcp_request "rag" "${search_payload}" >/dev/null
        log_verbose "Search for '${search_term}' complete"
    done
    sleep 1

    # Get count after
    COUNT_AFTER=$(count_search_log)
    log_verbose "Count after: ${COUNT_AFTER}"

    # Verify 3 new entries were created
    NEW_ENTRIES=$((COUNT_AFTER - COUNT_BEFORE))
    if [ "${NEW_ENTRIES}" -eq 3 ]; then
        run_test "TR6.1: Multiple searches are all logged (count: ${NEW_ENTRIES})" true
    else
        run_test "TR6.1: Multiple searches are all logged (expected: 3, got: ${NEW_ENTRIES})" false
    fi

    echo ""
    echo "======================================"
    echo "Test 7: K Parameter Variation"
    echo "======================================"
    echo ""

    # Execute searches with different k values
    log_info "Executing searches with different k values..."

    # Search with k=20
    k20_payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.search_fts","arguments":{"query":"performance","k":20}},"id":4}'
    log_verbose "MCP request (k=20): ${k20_payload}" >&2
    mcp_request "rag" "${k20_payload}" >/dev/null

    # Search with k=50
    k50_payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.search_fts","arguments":{"query":"optimization","k":50}},"id":5}'
    log_verbose "MCP request (k=50): ${k50_payload}" >&2
    mcp_request "rag" "${k50_payload}" >/dev/null

    sleep 1

    # Verify k values are logged correctly
    K20_LOG=$(get_search_log "performance")
    K50_LOG=$(get_search_log "optimization")

    K20_VALUE=$(echo "${K20_LOG}" | cut -d'|' -f3)
    K50_VALUE=$(echo "${K50_LOG}" | cut -d'|' -f3)

    log_verbose "Logged k for 'performance': ${K20_VALUE}"
    log_verbose "Logged k for 'optimization': ${K50_VALUE}"

    if [ "${K20_VALUE}" = "20" ] && [ "${K50_VALUE}" = "50" ]; then
        run_test "TR7.1: Different k values are correctly logged" true
    else
        run_test "TR7.1: Different k values are correctly logged (k20: ${K20_VALUE}, k50: ${K50_VALUE})" false
    fi

    # Display all search log entries
    echo ""
    echo "======================================"
    echo "RAG Search Log Contents"
    echo "======================================"
    echo ""
    exec_admin "SELECT log_id, query, k, filters, searched_at FROM rag_search_log ORDER BY log_id;"

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
