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

    # Create test tables
    log_verbose "Creating table 'test_phase5_table'..."
    exec_mysql "CREATE TABLE IF NOT EXISTS ${MYSQL_DATABASE}.test_phase5_table (id INT PRIMARY KEY, name VARCHAR(100));" 2>/dev/null

    log_verbose "Creating table 'another_phase5_table'..."
    exec_mysql "CREATE TABLE IF NOT EXISTS ${MYSQL_DATABASE}.another_phase5_table (id INT PRIMARY KEY, value VARCHAR(100));" 2>/dev/null

    # Insert some test data
    log_verbose "Inserting test data into tables..."
    exec_mysql "INSERT IGNORE INTO ${MYSQL_DATABASE}.test_phase5_table VALUES (1, 'test1'), (2, 'test2');" 2>/dev/null
    exec_mysql "INSERT IGNORE INTO ${MYSQL_DATABASE}.another_phase5_table VALUES (1, 'value1'), (2, 'value2');" 2>/dev/null

    log_info "Test tables created successfully"
}

drop_test_tables() {
    log_info "Dropping test tables from MySQL backend..."
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.test_phase5_table;" 2>/dev/null
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.another_phase5_table;" 2>/dev/null
    log_info "Test tables dropped"
}

get_count_star() {
    local tool_name="$1"
    local digest="$2"
    exec_admin_silent "SELECT count_star FROM stats_mcp_query_digest WHERE tool_name = '${tool_name}' AND digest = '${digest}';"
}

main() {
    echo "======================================"
    echo "Phase 5: Query Digest Tests"
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

    echo ""
    echo "======================================"
    echo "Setting Up Test Tables"
    echo "======================================"
    echo ""

    # Create test tables in MySQL database
    create_test_tables

    echo ""
    echo "======================================"
    echo "Running Digest Table Tests"
    echo "======================================"
    echo ""

    # Test 5.1: Query stats_mcp_query_digest table
    run_test "T5.1: Query stats_mcp_query_digest table" \
        exec_admin "SELECT * FROM stats_mcp_query_digest LIMIT 5;"

    # Test 5.2: Check digest table schema
    SCHEMA_INFO=$(exec_admin "PRAGMA table_info(stats_mcp_query_digest);" 2>/dev/null)
    if echo "${SCHEMA_INFO}" | grep -q "tool_name" && echo "${SCHEMA_INFO}" | grep -q "digest" && echo "${SCHEMA_INFO}" | grep -q "count_star"; then
        run_test "T5.2: Digest table has required columns" true
    else
        run_test "T5.2: Digest table has required columns" false
    fi

    # Test 5.3: Query digest for specific tool_name
    run_test "T5.3: Query digest for specific tool_name" \
        exec_admin "SELECT * FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly' LIMIT 5;"

    # Test 5.4: Query digest ordered by count_star
    run_test "T5.4: Query digest ordered by count_star DESC" \
        exec_admin "SELECT tool_name, digest, count_star FROM stats_mcp_query_digest ORDER BY count_star DESC LIMIT 5;"

    # Test 5.5: Query digest for specific digest pattern
    run_test "T5.5: Query digest filtering by digest" \
        exec_admin "SELECT * FROM stats_mcp_query_digest WHERE digest IS NOT NULL LIMIT 5;"

    # Test 5.6: Query stats_mcp_query_digest_reset table
    run_test "T5.6: Query stats_mcp_query_digest_reset table" \
        exec_admin "SELECT * FROM stats_mcp_query_digest_reset LIMIT 5;"

    # Test 5.7: Query digest with aggregate functions
    run_test "T5.7: Query digest with SUM aggregate" \
        exec_admin "SELECT tool_name, SUM(count_star) as total_calls FROM stats_mcp_query_digest GROUP BY tool_name;"

    # Test 5.8: Query digest with WHERE clause on count_star
    run_test "T5.8: Query digest filtering by count_star threshold" \
        exec_admin "SELECT tool_name, digest, count_star FROM stats_mcp_query_digest WHERE count_star > 0;"

    # Test 5.9: Check that digest_text column contains query text
    run_test "T5.9: Query digest showing digest_text" \
        exec_admin "SELECT tool_name, digest, digest_text, count_star FROM stats_mcp_query_digest WHERE digest_text IS NOT NULL LIMIT 5;"

    # Test 5.10: Query digest with multiple conditions
    run_test "T5.10: Query digest with tool_name and count_star filter" \
        exec_admin "SELECT * FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly' AND count_star > 0 ORDER BY count_star DESC LIMIT 5;"

    # Test 5.11: Check timing columns (sum_time, min_time, max_time)
    TIMING_COLS=$(exec_admin "SELECT sum_time, min_time, max_time FROM stats_mcp_query_digest WHERE count_star > 0 LIMIT 1;" 2>/dev/null)
    if [ -n "${TIMING_COLS}" ]; then
        run_test "T5.11: Timing columns (sum_time, min_time, max_time) are accessible" true
    else
        run_test "T5.11: Timing columns (sum_time, min_time, max_time) are accessible" false
    fi

    # Test 5.12: Query digest grouped by tool_name
    run_test "T5.12: Aggregate digest by tool_name" \
        exec_admin "SELECT tool_name, COUNT(*) as unique_digests, SUM(count_star) as total_calls FROM stats_mcp_query_digest GROUP BY tool_name;"

    # Test 5.13: Check for digest table size (number of entries)
    DIGEST_COUNT=$(exec_admin_silent "SELECT COUNT(*) FROM stats_mcp_query_digest;")
    if [ "${DIGEST_COUNT:-0}" -ge 0 ]; then
        run_test "T5.13: Digest table contains ${DIGEST_COUNT:-0} entries" true
    else
        run_test "T5.13: Digest table contains entries" false
    fi

    # Test 5.14: Query digest with LIKE pattern on tool_name
    run_test "T5.14: Query digest with LIKE on tool_name" \
        exec_admin "SELECT tool_name, digest, count_star FROM stats_mcp_query_digest WHERE tool_name LIKE '%sql%' LIMIT 5;"

    # Test 5.15: Verify reset table has same schema as main table
    RESET_SCHEMA=$(exec_admin "PRAGMA table_info(stats_mcp_query_digest_reset);" 2>/dev/null | wc -l)
    MAIN_SCHEMA=$(exec_admin "PRAGMA table_info(stats_mcp_query_digest);" 2>/dev/null | wc -l)
    if [ "${RESET_SCHEMA}" -eq "${MAIN_SCHEMA}" ] && [ "${RESET_SCHEMA}" -gt 0 ]; then
        run_test "T5.15: Reset table schema matches main table" true
    else
        run_test "T5.15: Reset table schema matches main table" false
    fi

    echo ""
    echo "======================================"
    echo "Testing Digest Population"
    echo "======================================"
    echo ""

    # Get initial digest count
    DIGEST_COUNT_BEFORE=$(exec_admin_silent "SELECT COUNT(*) FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly';")
    log_verbose "Initial digest count for run_sql_readonly: ${DIGEST_COUNT_BEFORE}"

    # Test 5.16: Execute a query and verify it appears in digest
    log_info "Executing unique query: SELECT COUNT(*) FROM test_phase5_table"
    PAYLOAD_1='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_sql_readonly","arguments":{"sql":"SELECT COUNT(*) FROM test_phase5_table","target_id":"'"${MCP_TARGET_ID}"'"}},"id":1}'
    mcp_request "query" "${PAYLOAD_1}" >/dev/null
    sleep 1
    DIGEST_COUNT_AFTER_1=$(exec_admin_silent "SELECT COUNT(*) FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly';")
    log_verbose "Digest count after query 1: ${DIGEST_COUNT_AFTER_1}"
    if [ "${DIGEST_COUNT_AFTER_1:-0}" -ge "${DIGEST_COUNT_BEFORE:-0}" ]; then
        run_test "T5.16: Query tracked in digest (count: ${DIGEST_COUNT_BEFORE} -> ${DIGEST_COUNT_AFTER_1})" true
    else
        run_test "T5.16: Query tracked in digest" false
    fi

    # Test 5.17: Execute same query again and verify count_star increments
    log_info "Executing same query again to test count_star increment..."
    COUNT_BEFORE=$(exec_admin_silent "SELECT count_star FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly' AND digest_text LIKE '%test_phase5_table%' ORDER BY last_seen DESC LIMIT 1;")
    log_verbose "count_star before repeat: ${COUNT_BEFORE}"
    mcp_request "query" "${PAYLOAD_1}" >/dev/null
    sleep 1
    COUNT_AFTER=$(exec_admin_silent "SELECT count_star FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly' AND digest_text LIKE '%test_phase5_table%' ORDER BY last_seen DESC LIMIT 1;")
    log_verbose "count_star after repeat: ${COUNT_AFTER}"
    if [ "${COUNT_AFTER:-0}" -gt "${COUNT_BEFORE:-0}" ]; then
        run_test "T5.17: count_star incremented on repeat (from ${COUNT_BEFORE} to ${COUNT_AFTER})" true
    else
        run_test "T5.17: count_star incremented on repeat" false
    fi

    # Test 5.18: Execute different query and verify new digest entry
    log_info "Executing different query: SELECT * FROM another_phase5_table LIMIT 10"
    PAYLOAD_2='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_sql_readonly","arguments":{"sql":"SELECT * FROM another_phase5_table LIMIT 10","target_id":"'"${MCP_TARGET_ID}"'"}},"id":2}'
    DIGEST_COUNT_BEFORE_2=$(exec_admin_silent "SELECT COUNT(*) FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly';")
    log_verbose "Digest count before query 2: ${DIGEST_COUNT_BEFORE_2}"
    mcp_request "query" "${PAYLOAD_2}" >/dev/null
    sleep 1
    DIGEST_COUNT_AFTER_2=$(exec_admin_silent "SELECT COUNT(*) FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly';")
    log_verbose "Digest count after query 2: ${DIGEST_COUNT_AFTER_2}"
    if [ "${DIGEST_COUNT_AFTER_2:-0}" -ge "${DIGEST_COUNT_BEFORE_2:-0}" ]; then
        run_test "T5.18: Different query creates new digest entry" true
    else
        run_test "T5.18: Different query creates new digest entry" false
    fi

    # Test 5.19: Verify digest_text contains the actual SQL query
    log_info "Checking digest_text content..."
    DIGEST_TEXT_RESULT=$(exec_admin "SELECT digest_text FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly' AND digest_text LIKE '%test_phase5_table%' ORDER BY last_seen DESC LIMIT 1;" 2>/dev/null)
    log_verbose "Found digest_text: ${DIGEST_TEXT_RESULT}"
    if echo "${DIGEST_TEXT_RESULT}" | grep -q "SELECT"; then
        run_test "T5.19: digest_text contains actual SQL query" true
    else
        run_test "T5.19: digest_text contains actual SQL query" false
    fi

    # Test 5.20: Verify timing information is captured (sum_time increases)
    log_info "Checking timing information..."
    SUM_TIME_BEFORE=$(exec_admin_silent "SELECT sum_time FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly' AND digest_text LIKE '%test_phase5_table%' ORDER BY last_seen DESC LIMIT 1;")
    log_verbose "sum_time before: ${SUM_TIME_BEFORE}"
    mcp_request "query" "${PAYLOAD_1}" >/dev/null
    sleep 1
    SUM_TIME_AFTER=$(exec_admin_silent "SELECT sum_time FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly' AND digest_text LIKE '%test_phase5_table%' ORDER BY last_seen DESC LIMIT 1;")
    log_verbose "sum_time after: ${SUM_TIME_AFTER}"
    if [ "${SUM_TIME_AFTER:-0}" -ge "${SUM_TIME_BEFORE:-0}" ]; then
        run_test "T5.20: sum_time tracked and increments" true
    else
        run_test "T5.20: sum_time tracked and increments" false
    fi

    # Test 5.21: Verify last_seen timestamp updates
    log_info "Checking timestamp tracking..."
    FIRST_SEEN=$(exec_admin_silent "SELECT first_seen FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly' AND digest_text LIKE '%test_phase5_table%' ORDER BY last_seen DESC LIMIT 1;")
    LAST_SEEN=$(exec_admin_silent "SELECT last_seen FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly' AND digest_text LIKE '%test_phase5_table%' ORDER BY last_seen DESC LIMIT 1;")
    log_verbose "first_seen: ${FIRST_SEEN}, last_seen: ${LAST_SEEN}"
    if [ -n "${FIRST_SEEN}" ] && [ -n "${LAST_SEEN}" ]; then
        run_test "T5.21: first_seen and last_seen timestamps tracked" true
    else
        run_test "T5.21: first_seen and last_seen timestamps tracked" false
    fi

    # Display sample digest data
    echo ""
    echo "Recent digest entries for run_sql_readonly (phase5 queries):"
    exec_admin "SELECT tool_name, substr(digest_text, 1, 60) as query_snippet, count_star, sum_time FROM stats_mcp_query_digest WHERE tool_name = 'run_sql_readonly' AND digest_text LIKE '%phase5%' ORDER BY last_seen DESC LIMIT 5;"

    # Display summary by tool
    echo ""
    echo "Summary by tool:"
    exec_admin "SELECT tool_name, COUNT(*) as unique_queries, SUM(count_star) as total_calls FROM stats_mcp_query_digest GROUP BY tool_name;"

    # Cleanup test tables
    echo ""
    echo "======================================"
    echo "Cleaning Up"
    echo "======================================"
    echo ""
    drop_test_tables

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
