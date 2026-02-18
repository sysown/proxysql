#!/bin/bash
#
# test_run_sql_readonly_validation.sh - Test run_sql_readonly Query Validation
#
# This script tests that the run_sql_readonly tool properly validates
# queries and rejects non-SELECT queries.
#
# Usage:
#   ./test_run_sql_readonly_validation.sh [options]
#
# Options:
#   -v, --verbose       Show verbose output
#   -h, --help          Show help

set -e

# Check prerequisites
if ! command -v jq >/dev/null 2>&1; then
    echo "Error: 'jq' is required but not installed."
    echo "Please install jq to run this script."
    echo "  - On Ubuntu/Debian: sudo apt-get install jq"
    echo "  - On RHEL/CentOS: sudo yum install jq"
    echo "  - On macOS: brew install jq"
    exit 1
fi

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the MCP test helpers
# shellcheck source=./mcp_test_helpers.sh
if [ -f "${SCRIPT_DIR}/mcp_test_helpers.sh" ]; then
    . "${SCRIPT_DIR}/mcp_test_helpers.sh"
else
    echo "Error: mcp_test_helpers.sh not found at ${SCRIPT_DIR}"
    exit 1
fi

# Test options
VERBOSE=false

# Additional colors not in helpers
BLUE='\033[0;34m'
CYAN='\033[0;36m'

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Override mcp_request to add verbose logging
mcp_request_verbose() {
    local endpoint="$1"
    local payload="$2"

    local response
    response=$(curl -k -s -w "\n%{http_code}" -X POST "$(get_endpoint_url "${endpoint}")" \
        -H "Content-Type: application/json" \
        -d "${payload}" 2>/dev/null)

    local body
    body=$(echo "$response" | head -n -1)
    local code
    code=$(echo "$response" | tail -n 1)

    # Always log request and response (for debugging)
    echo "Request: ${payload}" >&2
    echo "Response (${code}): ${body}" >&2

    echo "${body}"
    return 0
}

# Create test tables in MySQL backend
create_test_tables() {
    log_step "Creating test tables in MySQL backend..."
    log_verbose "MySQL Host: ${MYSQL_HOST}:${MYSQL_PORT}"
    log_verbose "MySQL User: ${MYSQL_USER}"
    log_verbose "MySQL Database: ${MYSQL_DATABASE:-testdb}"

    local db="${MYSQL_DATABASE:-testdb}"

    # Create database if it doesn't exist
    log_verbose "Creating database '${db}' if not exists..."
    exec_mysql "CREATE DATABASE IF NOT EXISTS \`${db}\`;" 2>/dev/null

    # Create test tables
    log_verbose "Creating table 'users' for readonly validation tests..."
    exec_mysql "CREATE TABLE IF NOT EXISTS \`${db}\`.users (id INT PRIMARY KEY, name VARCHAR(100), email VARCHAR(255));" 2>/dev/null

    log_verbose "Creating table 'products' for readonly validation tests..."
    exec_mysql "CREATE TABLE IF NOT EXISTS \`${db}\`.products (id INT PRIMARY KEY, name VARCHAR(100), price DECIMAL(10,2));" 2>/dev/null

    # Insert some test data
    log_verbose "Inserting test data into tables..."
    exec_mysql "INSERT IGNORE INTO \`${db}\`.users VALUES (1, 'Alice', 'alice@example.com'), (2, 'Bob', 'bob@example.com');" 2>/dev/null
    exec_mysql "INSERT IGNORE INTO \`${db}\`.products VALUES (1, 'Widget', 19.99), (2, 'Gadget', 29.99);" 2>/dev/null

    log_info "Test tables created successfully"
}

# Drop test tables from MySQL backend
drop_test_tables() {
    log_step "Dropping test tables from MySQL backend..."
    local db="${MYSQL_DATABASE:-testdb}"

    exec_mysql "DROP TABLE IF EXISTS \`${db}\`.users;" 2>/dev/null
    exec_mysql "DROP TABLE IF EXISTS \`${db}\`.products;" 2>/dev/null
    log_info "Test tables dropped"
}

# Test that a query is rejected
test_rejected_query() {
    local test_name="$1"
    local sql_query="$2"
    local expected_error="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log_test "Testing: ${test_name}"

    local payload
    payload=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "run_sql_readonly",
    "arguments": {
      "sql": ${sql_query},
      "target_id": "${MCP_TARGET_ID}"
    }
  },
  "id": ${TOTAL_TESTS}
}
EOF
)

    local response
    response=$(mcp_request_verbose "query" "${payload}")

    log_verbose "Response: ${response}"

    # Check that response does NOT contain isError:false
    log_verbose "Checking response has isError attribute indicating error..."
    if echo "$response" | grep -q '"isError":false'; then
        log_error "✗ ${test_name} - Query was NOT rejected (response has isError:false)"
        log_error "  Response: ${response}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi

    # Check that response contains isError:true
    log_verbose "Checking response contains isError:true..."
    if ! echo "$response" | grep -q '"isError":true'; then
        log_error "✗ ${test_name} - Response does not contain isError:true"
        log_error "  Response: ${response}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi

    # Extract error message
    local error_msg
    error_msg=$(echo "${response}" | jq -r '.result.content[0].text // .error.message // .error' 2>/dev/null)

    log_verbose "Error message: ${error_msg}"

    # Check if expected error is contained in response
    if echo "${error_msg}" | grep -qi "${expected_error}"; then
        log_info "✓ ${test_name} - Query rejected as expected with proper error message"
        log_verbose "  Error message: ${error_msg}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_error "✗ ${test_name} - Error message mismatch"
        log_error "  Expected substring: ${expected_error}"
        log_error "  Actual: ${error_msg}"
        log_error "  Full response: ${response}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Test that a query is allowed
test_allowed_query() {
    local test_name="$1"
    local sql_query="$2"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log_test "Testing: ${test_name}"

    local payload
    payload=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "run_sql_readonly",
    "arguments": {
      "sql": ${sql_query},
      "target_id": "${MCP_TARGET_ID}"
    }
  },
  "id": ${TOTAL_TESTS}
}
EOF
)

    local response
    response=$(mcp_request_verbose "query" "${payload}")

    log_verbose "Response: ${response}"

    # Check that response does NOT contain isError:true
    # (success responses don't have isError field at all)
    log_verbose "Checking response does not contain isError:true..."
    if echo "$response" | grep -q '"isError":true'; then
        log_error "✗ ${test_name} - Query was rejected (response has isError:true)"
        log_error "  Response: ${response}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi

    # Check that response has result.content (basic structure for success)
    log_verbose "Checking response has result.content structure..."
    if ! echo "$response" | grep -q '"result"' || ! echo "$response" | grep -q '"content"'; then
        log_error "✗ ${test_name} - Response does not have expected structure"
        log_error "  Response: ${response}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi

    log_info "✓ ${test_name} - Query allowed as expected"
    log_verbose "  Response format is valid (has result.content, no isError:true)"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    return 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                cat <<EOF
Usage: $0 [options]

Test run_sql_readonly Query Validation.

Options:
  -v, --verbose       Show verbose output including request/response
  -h, --help          Show this help

Environment Variables:
  MCP_HOST            MCP server host (default: 127.0.0.1)
  MCP_PORT            MCP server port (default: 6071)
  TAP_ADMINHOST       ProxySQL admin host (default: 127.0.0.1)
  TAP_ADMINPORT       ProxySQL admin port (default: 6032)
  TAP_ADMINUSERNAME   ProxySQL admin user (default: radmin)
  TAP_ADMINPASSWORD   ProxySQL admin password (default: radmin)
  TAP_MYSQLHOST       MySQL backend host (default: 127.0.0.1)
  TAP_MYSQLPORT       MySQL backend port (default: 3306)
  TAP_MYSQLUSERNAME   MySQL backend user (default: root)
  TAP_MYSQLPASSWORD   MySQL backend password (default: none)
  TEST_DB_NAME        MySQL database for test tables (default: testdb)

Test Cases:
  Blocked queries (not SELECT):
    1. INSERT statement
    2. UPDATE statement
    3. DELETE statement
    4. DROP TABLE statement
    5. CREATE TABLE statement
    6. ALTER TABLE statement
    7. TRUNCATE statement
    8. REPLACE statement
    9. LOAD DATA statement
    10. CALL statement
    11. EXECUTE statement

  Allowed queries (SELECT variants):
    12. SELECT with FROM
    13. SELECT without FROM (subquery)
    14. WITH clause (CTE)
    15. EXPLAIN SELECT
    16. SHOW TABLES
    17. SHOW DATABASES
    18. DESCRIBE table
    19. USE database
    20. SELECT with leading -- comment
    21. SELECT with multiple leading -- comments
    22. SELECT with leading comment and whitespace

Examples:
  # Run validation tests with default MySQL settings
  $0

  # Run with verbose output
  $0 -v

  # Run with custom MySQL backend
  TAP_MYSQLHOST=192.168.1.100 TAP_MYSQLPORT=3306 \\
  TAP_MYSQLUSERNAME=myuser TAP_MYSQLPASSWORD=mypass $0

EOF
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Main test execution
main() {
    parse_args "$@"

    echo "======================================"
    echo "run_sql_readonly Query Validation Test"
    echo "======================================"
    echo ""
    echo "MCP Server: ${MCP_HOST}:${MCP_PORT}"
    echo "ProxySQL Admin: ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
    echo ""

    # Check connections
    if ! check_proxysql_admin; then
        log_error "Cannot connect to ProxySQL admin"
        exit 1
    fi

    if ! check_mcp_server; then
        log_error "MCP server not accessible. Please run:"
        echo "  ./configure_mcp.sh --enable -u root -p root -P 3306 -d testdb"
        exit 1
    fi

    # Check MySQL backend connection
    if ! check_mysql_backend; then
        log_error "Cannot connect to MySQL backend"
        log_error "Please set TAP_MYSQLHOST, TAP_MYSQLPORT, TAP_MYSQLUSERNAME, TAP_MYSQLPASSWORD, TEST_DB_NAME environment variables"
        exit 1
    fi

    echo ""
    echo "======================================"
    echo "Setting Up Test Tables"
    echo "======================================"
    echo ""

    # Create test tables in MySQL database
    create_test_tables

    echo ""
    echo "======================================"
    echo "Blocked Query Tests"
    echo "======================================"
    echo "Testing queries that should be REJECTED"
    echo ""

    # Test 1: INSERT statement
    test_rejected_query \
        "Test 1: INSERT statement" \
        '"INSERT INTO users (id, name) VALUES (1, \"test\");"' \
        "not read-only"

    # Test 2: UPDATE statement
    test_rejected_query \
        "Test 2: UPDATE statement" \
        '"UPDATE users SET name = \"test\" WHERE id = 1;"' \
        "not read-only"

    # Test 3: DELETE statement
    test_rejected_query \
        "Test 3: DELETE statement" \
        '"DELETE FROM users WHERE id = 1;"' \
        "not read-only"

    # Test 4: DROP TABLE statement
    test_rejected_query \
        "Test 4: DROP TABLE statement" \
        '"DROP TABLE IF EXISTS test_table;"' \
        "not read-only"

    # Test 5: CREATE TABLE statement
    test_rejected_query \
        "Test 5: CREATE TABLE statement" \
        '"CREATE TABLE test_table (id INT);"' \
        "not read-only"

    # Test 6: ALTER TABLE statement
    test_rejected_query \
        "Test 6: ALTER TABLE statement" \
        '"ALTER TABLE users ADD COLUMN email VARCHAR(255);"' \
        "not read-only"

    # Test 7: TRUNCATE statement
    test_rejected_query \
        "Test 7: TRUNCATE statement" \
        '"TRUNCATE TABLE users;"' \
        "not read-only"

    # Test 8: REPLACE statement
    test_rejected_query \
        "Test 8: REPLACE statement" \
        '"REPLACE INTO users (id, name) VALUES (1, \"test\");"' \
        "not read-only"

    # Test 9: LOAD DATA statement
    test_rejected_query \
        "Test 9: LOAD DATA statement" \
        '"LOAD DATA INFILE \"/tmp/data.csv\" INTO TABLE users;"' \
        "not read-only"

    # Test 10: CALL statement
    test_rejected_query \
        "Test 10: CALL statement" \
        '"CALL test_procedure();"' \
        "not read-only"

    # Test 11: EXECUTE statement
    test_rejected_query \
        "Test 11: EXECUTE statement" \
        '"EXECUTE immediate \"SELECT 1\";"' \
        "not read-only"

    echo ""
    echo "======================================"
    echo "Allowed Query Tests"
    echo "======================================"
    echo "Testing queries that should be ALLOWED"
    echo ""

    # Test 12: Basic SELECT
    test_allowed_query \
        "Test 12: SELECT with FROM" \
        '"SELECT * FROM users;"'

    # Test 13: SELECT with subquery
    test_allowed_query \
        "Test 13: SELECT without FROM (subquery)" \
        '"SELECT (SELECT COUNT(*) FROM users);"'

    # Test 14: WITH clause (CTE)
    test_allowed_query \
        "Test 14: WITH clause (CTE)" \
        '"WITH cte AS (SELECT * FROM users) SELECT * FROM cte;"'

    # Test 15: EXPLAIN SELECT
    test_allowed_query \
        "Test 15: EXPLAIN SELECT" \
        '"EXPLAIN SELECT * FROM users;"'

    # Test 16: SHOW TABLES
    test_allowed_query \
        "Test 16: SHOW TABLES" \
        '"SHOW TABLES;"'

    # Test 17: SHOW DATABASES
    test_allowed_query \
        "Test 17: SHOW DATABASES" \
        '"SHOW DATABASES;"'

    # Test 18: DESCRIBE table
    test_allowed_query \
        "Test 18: DESCRIBE table" \
        '"DESCRIBE users;"'

    # Test 19: USE database
    test_rejected_query \
        "Test 19: USE database" \
        '"USE testdb;"'

    # Test 20: SELECT with leading single-line comment
    test_allowed_query \
        "Test 20: SELECT with leading -- comment" \
        '"-- This is a comment\nSELECT * FROM users;"'

    # Test 21: SELECT with multiple leading comments
    test_allowed_query \
        "Test 21: SELECT with multiple leading -- comments" \
        '"-- First comment\n-- Second comment\nSELECT * FROM users;"'

    # Test 22: SELECT with comment and whitespace
    test_allowed_query \
        "Test 22: SELECT with leading comment and whitespace" \
        '"\n  -- Comment after newline and spaces\n  SELECT * FROM users;"'

    # Print summary
    echo ""
    echo "======================================"
    echo "Test Summary"
    echo "======================================"
    echo "Total tests:   ${TOTAL_TESTS}"
    echo -e "Passed:        ${GREEN}${PASSED_TESTS}${NC}"
    echo -e "Failed:        ${RED}${FAILED_TESTS}${NC}"
    echo ""

    # Cleanup test tables
    echo ""
    drop_test_tables

    if [ ${FAILED_TESTS} -gt 0 ]; then
        log_error "Some tests failed!"
        exit 1
    else
        log_info "All tests passed!"
        exit 0
    fi
}

main "$@"
