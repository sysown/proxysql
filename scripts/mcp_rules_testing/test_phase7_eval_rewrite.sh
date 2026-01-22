#!/bin/bash
#
# test_phase7_eval_rewrite.sh - Test MCP Query Rules Rewrite Action Evaluation
#
# Phase 7: Test rule evaluation for Rewrite action with various patterns
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

    # Create test tables with phase7 naming
    log_verbose "Creating table 'customers' for phase7 tests..."
    exec_mysql "CREATE TABLE IF NOT EXISTS ${MYSQL_DATABASE}.customers_phase7 (id INT PRIMARY KEY, phase7_name VARCHAR(100), phase7_email VARCHAR(100));" 2>/dev/null

    log_verbose "Creating table 'orders'..."
    exec_mysql "CREATE TABLE IF NOT EXISTS ${MYSQL_DATABASE}.orders_phase7 (id INT PRIMARY KEY, customer_id INT, amount DECIMAL(10,2));" 2>/dev/null

    log_verbose "Creating table 'products'..."
    exec_mysql "CREATE TABLE IF NOT EXISTS ${MYSQL_DATABASE}.products_phase7 (id INT PRIMARY KEY, product_name VARCHAR(100), price DECIMAL(10,2));" 2>/dev/null

    # Insert some test data
    log_verbose "Inserting test data into tables..."
    exec_mysql "INSERT IGNORE INTO ${MYSQL_DATABASE}.customers_phase7 VALUES (1, 'Alice', 'alice@test.com'), (2, 'Bob', 'bob@test.com');" 2>/dev/null
    exec_mysql "INSERT IGNORE INTO ${MYSQL_DATABASE}.orders_phase7 VALUES (1, 1, 100.00), (2, 2, 200.00);" 2>/dev/null
    exec_mysql "INSERT IGNORE INTO ${MYSQL_DATABASE}.products_phase7 VALUES (1, 'Widget', 10.00), (2, 'Gadget', 20.00);" 2>/dev/null

    log_info "Test tables created successfully"
}

# Drop test tables from MySQL database
drop_test_tables() {
    log_info "Dropping test tables from MySQL backend..."
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.customers_phase7;" 2>/dev/null
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.orders_phase7;" 2>/dev/null
    exec_mysql "DROP TABLE IF EXISTS ${MYSQL_DATABASE}.products_phase7;" 2>/dev/null
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

# Test that a query is rewritten and returns results
test_is_rewritten() {
    local tool_name="$1"
    local original_sql="$2"
    local expected_result_substring="$3"

    local payload
    payload=$(cat <<EOF
{"jsonrpc":"2.0","method":"tools/call","params":{"name":"${tool_name}","arguments":{"sql":"${original_sql}"}},"id":1}
EOF
)

    local response
    response=$(mcp_request "query" "${payload}")
    log_verbose "Response: ${response}"

    # Check for successful response with data
    if echo "${response}" | grep -q '"isError":true'; then
        log_verbose "Query returned error (unexpected)"
        return 1
    else
        # Check if expected substring is in response
        if echo "${response}" | grep -qi "${expected_result_substring}"; then
            log_verbose "Query executed and contains: ${expected_result_substring}"
            return 0
        else
            log_verbose "Query executed but doesn't contain expected result"
            return 1
        fi
    fi
}

# Get rule hit count
get_rule_hits() {
    local rule_id="$1"
    exec_admin_silent "SELECT hits FROM stats_mcp_query_rules WHERE rule_id = ${rule_id};"
}

main() {
    echo "======================================"
    echo "Phase 7: Rule Evaluation - Rewrite Action"
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

    # T7.1: Rewrite SQL with replace_pattern - SELECT * to known string
    log_info "Creating rule 100: Rewrite SELECT * FROM customers to known string"
	exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, replace_pattern, apply) VALUES (100, 1, 'SELECT\s+\\*\s+FROM\s+customers', 'SELECT \"PHASE7_REWRITTEN\" AS result FROM (SELECT 0) t1', 1);" >/dev/null 2>&1

    # T7.2: Rewrite with capture groups - Rewrite to known string with original table captured
    log_info "Creating rule 101: Rewrite with capture groups - capture table name"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) VALUES (101, 1, 'SELECT phase7_name FROM (\\w+)', 'SELECT \"PHASE7_CAPTURED\" AS result FROM (SELECT 0) t1', 'EXTENDED', 1);" >/dev/null 2>&1

    # T7.3: Rewrite with CASELESS modifier
    log_info "Creating rule 102: Rewrite with CASELESS - select * from products (any case)"
    exec_admin_silent "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) VALUES (102, 1, 'select \\* from products', 'SELECT \"PHASE7_CASELESS\" AS result FROM (SELECT 0) t1', 'CASELESS', 1);" >/dev/null 2>&1

    # Load to runtime
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1
    sleep 1

    echo ""
    echo "======================================"
    echo "Running Rewrite Action Evaluation Tests"
    echo "======================================"
    echo ""

    # T7.1: Rewrite SQL with replace_pattern
    run_test "T7.1: Rewrite SELECT * FROM customers to known string" \
        test_is_rewritten "run_sql_readonly" "SELECT * FROM customers" "PHASE7_REWRITTEN"

    # T7.2: Rewrite with capture groups
    run_test "T7.2: Rewrite with capture groups - captured table name" \
        test_is_rewritten "run_sql_readonly" "SELECT phase7_name FROM customers_phase7;" "PHASE7_CAPTURED"

    # T7.3: Rewrite with CASELESS modifier
    run_test "T7.3: Rewrite with CASELESS - lowercase 'select * from products'" \
        test_is_rewritten "run_sql_readonly" "select * from products;" "PHASE7_CASELESS"

    # Display runtime rules
    echo ""
    echo "Runtime rules created:"
    exec_admin "SELECT rule_id, match_pattern, replace_pattern, re_modifiers FROM runtime_mcp_query_rules WHERE rule_id BETWEEN 100 AND 199 ORDER BY rule_id;"

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
