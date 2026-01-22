#!/bin/bash
#
# test_phase6_eval_block.sh - Test MCP Query Rules Block Action Evaluation
#
# Phase 6: Test rule evaluation for Block action with various filters
#

set -e

# Default configuration
MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-6071}"

PROXYSQL_ADMIN_HOST="${PROXYSQL_ADMIN_HOST:-127.0.0.1}"
PROXYSQL_ADMIN_PORT="${PROXYSQL_ADMIN_PORT:-6032}"
PROXYSQL_ADMIN_USER="${PROXYSQL_ADMIN_USER:-radmin}"
PROXYSQL_ADMIN_PASSWORD="${PROXYSQL_ADMIN_PASSWORD:-radmin}"

# MySQL backend configuration (the actual database where queries are executed)
MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
MYSQL_DATABASE="${MYSQL_DATABASE:-testdb}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "${GREEN}[TEST]${NC} $1"; }
log_verbose() { echo -e "${YELLOW}[VERBOSE]${NC} $1"; }

# Execute MySQL command via ProxySQL admin
exec_admin() {
    mysql -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
          -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
          -e "$1" 2>&1
}

# Execute MySQL command via ProxySQL admin (silent)
exec_admin_silent() {
    mysql -B -N -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
          -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
          -e "$1" 2>/dev/null
}

# Execute MySQL command directly on backend MySQL server
exec_mysql() {
    local db_param=""
    if [ -n "${MYSQL_DATABASE}" ]; then
        db_param="-D ${MYSQL_DATABASE}"
    fi
    mysql -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" \
          -u "${MYSQL_USER}" -p"${MYSQL_PASSWORD}" \
          ${db_param} -e "$1" 2>&1
}

# Execute MySQL command directly on backend MySQL server (silent)
exec_mysql_silent() {
    local db_param=""
    if [ -n "${MYSQL_DATABASE}" ]; then
        db_param="-D ${MYSQL_DATABASE}"
    fi
    mysql -B -N -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" \
          -u "${MYSQL_USER}" -p"${MYSQL_PASSWORD}" \
          ${db_param} -e "$1" 2>/dev/null
}

# Get endpoint URL
get_endpoint_url() {
    local endpoint="$1"
    echo "https://${MCP_HOST}:${MCP_PORT}/mcp/${endpoint}"
}

# Execute MCP request via curl
mcp_request() {
    local endpoint="$1"
    local payload="$2"

    curl -k -s -X POST "$(get_endpoint_url "${endpoint}")" \
        -H "Content-Type: application/json" \
        -d "${payload}" 2>/dev/null
}

# Check if ProxySQL admin is accessible
check_proxysql_admin() {
    if exec_admin_silent "SELECT 1" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Check if MCP server is accessible
check_mcp_server() {
    local response
    response=$(mcp_request "config" '{"jsonrpc":"2.0","method":"ping","id":1}')
    if echo "${response}" | grep -q "result"; then
        return 0
    else
        return 1
    fi
}

# Check if MySQL backend is accessible
check_mysql_backend() {
    if exec_mysql_silent "SELECT 1" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Create test tables in MySQL database
create_test_tables() {
    log_info "Creating test tables in MySQL backend..."
    log_verbose "MySQL Host: ${MYSQL_HOST}:${MYSQL_PORT}"
    log_verbose "MySQL User: ${MYSQL_USER}"
    log_verbose "MySQL Database: ${MYSQL_DATABASE}"

    # Create database if it doesn't exist
    log_verbose "Creating database '${MYSQL_DATABASE}' if not exists..."
    exec_mysql "CREATE DATABASE IF NOT EXISTS ${MYSQL_DATABASE};" 2>/dev/null

    # Create test tables with phase6 naming
    log_verbose "Creating table 'fake_table' for phase6 tests..."
    exec_mysql "CREATE TABLE IF NOT EXISTS ${MYSQL_DATABASE}.fake_table (id INT PRIMARY KEY, phase6_allowed_col VARCHAR(100), phase6_blocked_col VARCHAR(100));" 2>/dev/null

    log_verbose "Creating table 'phase6_test_table'..."
    exec_mysql "CREATE TABLE IF NOT EXISTS ${MYSQL_DATABASE}.phase6_test_table (id INT PRIMARY KEY, name VARCHAR(100));" 2>/dev/null

    # Insert some test data
    log_verbose "Inserting test data into tables..."
    exec_mysql "INSERT IGNORE INTO ${MYSQL_DATABASE}.fake_table VALUES (1, 'allowed', 'blocked');" 2>/dev/null
    exec_mysql "INSERT IGNORE INTO ${MYSQL_DATABASE}.phase6_test_table VALUES (1, 'test1'), (2, 'test2');" 2>/dev/null

    log_info "Test tables created successfully"
}

# Drop test tables from MySQL database
drop_test_tables() {
    log_info "Dropping test tables from MySQL backend..."
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.fake_table;" 2>/dev/null
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.phase6_test_table;" 2>/dev/null
    log_info "Test tables dropped"
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

# Test that a query is blocked
test_is_blocked() {
    local tool_name="$1"
    local sql="$2"
    local expected_error_substring="$3"

    local payload
    payload=$(cat <<EOF
{"jsonrpc":"2.0","method":"tools/call","params":{"name":"${tool_name}","arguments":{"sql":"${sql}"}},"id":1}
EOF
)

    local response
    response=$(mcp_request "query" "${payload}")
    log_verbose "Response: ${response}"

    if echo "${response}" | grep -q '"isError":true'; then
        if echo "${response}" | grep -qi "${expected_error_substring}"; then
            log_verbose "Query blocked with: ${expected_error_substring}"
            return 0
        else
            log_verbose "Query blocked but error message doesn't match"
            return 1
        fi
    else
        log_verbose "Query was NOT blocked (expected to be blocked)"
        return 1
    fi
}

# Test that a query is allowed
test_is_allowed() {
    local tool_name="$1"
    local sql="$2"

    local payload
    payload=$(cat <<EOF
{"jsonrpc":"2.0","method":"tools/call","params":{"name":"${tool_name}","arguments":{"sql":"${sql}"}},"id":1}
EOF
)

    local response
    response=$(mcp_request "query" "${payload}")
    log_verbose "Response: ${response}"

    if echo "${response}" | grep -q '"isError":true'; then
        log_verbose "Query was blocked (expected to be allowed)"
        return 1
    else
        log_verbose "Query allowed as expected"
        return 0
    fi
}

# Get rule hit count
get_rule_hits() {
    local rule_id="$1"
    exec_admin_silent "SELECT hits FROM stats_mcp_query_rules WHERE rule_id = ${rule_id};"
}

main() {
    echo "======================================"
    echo "Phase 6: Rule Evaluation - Block Action"
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

    # T6.1: Basic block rule with error_msg
    log_info "Creating rule 100: Basic DROP TABLE block"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (100, 1, 'DROP TABLE', 'DROP TABLE statements are not allowed', 1);" >/dev/null 2>&1

    # T6.2: Case-sensitive match (default, no CASELESS modifier)
    log_info "Creating rule 101: Case-sensitive 'DROP TABLE' block (no CASELESS)"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (101, 1, 'DROP TABLE', 'Case-sensitive match failed', 1);" >/dev/null 2>&1

    # T6.3: Block with negate_match_pattern=1 (block everything EXCEPT pattern)
    log_info "Creating rule 102: Negate pattern - block everything except specific query"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, negate_match_pattern, error_msg, apply) VALUES (102, 1, '^SELECT phase6_allowed_col FROM fake_table$', 1, 'Only specific query is allowed', 1);" >/dev/null 2>&1

    # T6.4: Block specific username
    log_info "Creating rule 103: Block for specific user 'testuser'"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, username, match_pattern, error_msg, apply) VALUES (103, 1, 'testuser', 'DROP', 'User testuser cannot DROP', 1);" >/dev/null 2>&1

    # T6.5: Block specific schema
    log_info "Creating rule 104: Block for specific schema 'testdb'"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, schemaname, match_pattern, error_msg, apply) VALUES (104, 1, 'testdb', 'DROP', 'DROP not allowed in testdb', 1);" >/dev/null 2>&1

    # T6.6: Block specific tool_name
    log_info "Creating rule 105: Block for specific tool 'run_sql_readonly'"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, tool_name, match_pattern, error_msg, apply) VALUES (105, 1, 'run_sql_readonly', 'TRUNCATE', 'TRUNCATE not allowed in readonly mode', 1);" >/dev/null 2>&1

    # Load to runtime
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    sleep 1

    echo ""
    echo "======================================"
    echo "Running Block Action Evaluation Tests"
    echo "======================================"
    echo ""

    # T6.1: Block query with error_msg
    run_test "T6.1: Block DROP TABLE with error_msg" \
        test_is_blocked "run_sql_readonly" "DROP TABLE test_table;" "DROP TABLE statements are not allowed"

    # T6.2: Block with case-sensitive match (lowercase should NOT match if no CASELESS)
    # Note: This test may vary based on regex implementation. Assuming default is case-sensitive.
    run_test "T6.2: Case-sensitive match - exact case matches" \
        test_is_blocked "run_sql_readonly" "DROP TABLE test2;" "DROP"

    # T6.3: Block with negate_match_pattern=1
    # Rule 102: negate_match_pattern=1, pattern='^SELECT phase6_allowed_col FROM fake_table$', so blocks everything EXCEPT that specific query
    run_test "T6.3: Negate pattern - other query should be blocked" \
        test_is_blocked "run_sql_readonly" "SELECT phase6_blocked_col FROM fake_table;" "Only specific query is allowed"

    run_test "T6.3: Negate pattern - exact pattern match should be allowed" \
        test_is_allowed "run_sql_readonly" "SELECT phase6_allowed_col FROM fake_table"

    # T6.4: Block specific username
    # Note: This test depends on the user context. For now, we test that the rule exists.
    # Actual username filtering requires authentication context.
    log_info "T6.4: Username-based filtering (rule 103 created - requires auth context to fully test)"
    run_test "T6.4: Username rule exists in runtime" \
        bash -c "[ $(exec_admin_silent 'SELECT COUNT(*) FROM runtime_mcp_query_rules WHERE rule_id = 103 AND username = "testuser"') -eq 1 ]"

    # T6.5: Block specific schema
    log_info "T6.5: Schema-based filtering (rule 104 created for 'testdb')"
    run_test "T6.5: Schema rule exists in runtime" \
        bash -c "[ $(exec_admin_silent 'SELECT COUNT(*) FROM runtime_mcp_query_rules WHERE rule_id = 104 AND schemaname = "testdb"') -eq 1 ]"

    # T6.6: Block specific tool_name
    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id=102;" >/dev/null 2>&1
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    run_test "T6.6: Block TRUNCATE in run_sql_readonly tool" \
        test_is_blocked "run_sql_readonly" "TRUNCATE TABLE test_table;" "TRUNCATE not allowed"

    # Display runtime rules
    echo ""
    echo "Runtime rules created:"
    exec_admin "SELECT rule_id, username, schemaname, tool_name, match_pattern, negate_match_pattern, error_msg FROM runtime_mcp_query_rules WHERE rule_id BETWEEN 100 AND 199 ORDER BY rule_id;"

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
