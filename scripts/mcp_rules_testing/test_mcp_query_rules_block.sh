#!/bin/bash
#
# test_mcp_query_rules_block.sh - Test MCP Query Rules Block Action
#
# This script tests the Block action of MCP query rules by:
# 1. Loading block rules via the admin interface
# 2. Executing MCP tool calls via curl
# 3. Verifying that matching queries are blocked with the error message
#
# Usage:
#   ./test_mcp_query_rules_block.sh [options]
#
# Options:
#   -v, --verbose       Show verbose output
#   -c, --clean         Clean up test rules after testing
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

# Default configuration (can be overridden by environment variables)
MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-6071}"

# ProxySQL admin configuration
PROXYSQL_ADMIN_HOST="${PROXYSQL_ADMIN_HOST:-127.0.0.1}"
PROXYSQL_ADMIN_PORT="${PROXYSQL_ADMIN_PORT:-6032}"
PROXYSQL_ADMIN_USER="${PROXYSQL_ADMIN_USER:-radmin}"
PROXYSQL_ADMIN_PASSWORD="${PROXYSQL_ADMIN_PASSWORD:-radmin}"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="${SCRIPT_DIR}/rules"

# Test options
VERBOSE=false
CLEAN_AFTER=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

log_verbose() {
    if [ "${VERBOSE}" = "true" ]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Execute MySQL command via ProxySQL admin
exec_admin() {
    mysql -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
          -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
          -e "$1" 2>&1
}

# Execute MySQL command via ProxySQL admin (silent mode)
exec_admin_silent() {
    mysql -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
          -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
          -e "$1" 2>/dev/null
}

# Execute SQL file via ProxySQL admin
exec_admin_file() {
    mysql -h "${PROXYSQL_ADMIN_HOST}" -P "${PROXYSQL_ADMIN_PORT}" \
          -u "${PROXYSQL_ADMIN_USER}" -p"${PROXYSQL_ADMIN_PASSWORD}" \
          < "$1" 2>&1
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

    local response
    response=$(curl -k -s -w "\n%{http_code}" -X POST "$(get_endpoint_url "${endpoint}")" \
        -H "Content-Type: application/json" \
        -d "${payload}" 2>/dev/null)

    local body
    body=$(echo "$response" | head -n -1)
    local code
    code=$(echo "$response" | tail -n 1)

    if [ "${VERBOSE}" = "true" ]; then
        echo "Request: ${payload}" >&2
        echo "Response (${code}): ${body}" >&2
    fi

    echo "${body}"
    return 0
}

# Check if ProxySQL admin is accessible
check_proxysql_admin() {
    log_step "Checking ProxySQL admin connection..."
    if exec_admin_silent "SELECT 1" >/dev/null 2>&1; then
        log_info "Connected to ProxySQL admin at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
        return 0
    else
        log_error "Cannot connect to ProxySQL admin at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
        log_error "Please ensure ProxySQL is running"
        return 1
    fi
}

# Check if MCP server is accessible
check_mcp_server() {
    log_step "Checking MCP server accessibility..."

    local response
    response=$(mcp_request "config" '{"jsonrpc":"2.0","method":"ping","id":1}')

    if echo "${response}" | grep -q "result"; then
        log_info "MCP server is accessible at ${MCP_HOST}:${MCP_PORT}"
        return 0
    else
        log_error "MCP server is not accessible"
        log_error "Response: ${response}"
        return 1
    fi
}

# Load block rules from SQL file
load_block_rules() {
    log_step "Loading block rules from SQL file..."

    local sql_file="${RULES_DIR}/block_rule.sql"

    if [ ! -f "${sql_file}" ]; then
        log_error "SQL file not found: ${sql_file}"
        return 1
    fi

    if exec_admin_file "${sql_file}"; then
        log_info "Block rules inserted successfully"
        return 0
    else
        log_error "Failed to insert block rules"
        return 1
    fi
}

# Load MCP query rules to runtime
load_rules_to_runtime() {
    log_step "Loading MCP query rules to RUNTIME..."

    if exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1; then
        log_info "MCP query rules loaded to RUNTIME"
        return 0
    else
        log_error "Failed to load MCP query rules to RUNTIME"
        return 1
    fi
}

# Display current rules in runtime table
display_runtime_rules() {
    log_step "Current rules in runtime_mcp_query_rules:"
    exec_admin "SELECT rule_id, active, username, schemaname, tool_name, match_pattern, error_msg, comment FROM runtime_mcp_query_rules;"
}

# Get rule hit count from stats table
get_rule_hits() {
    local rule_id="$1"
    local hits
    hits=$(exec_admin_silent "SELECT hits FROM stats_mcp_query_rules WHERE rule_id = ${rule_id};")
    echo "${hits:-0}"
}

# Test that a query is blocked by a rule
test_block_action() {
    local test_name="$1"
    local endpoint="$2"
    local tool_name="$3"
    local arguments="$4"
    local expected_error_msg="$5"
    local rule_id="$6"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log_test "Testing: ${test_name}"

    local payload
    payload=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "${tool_name}",
    "arguments": ${arguments}
  },
  "id": ${TOTAL_TESTS}
}
EOF
)

    local response
    response=$(mcp_request "${endpoint}" "${payload}")

    log_verbose "Response: ${response}"

    # Check for error response with expected message
    if echo "${response}" | grep -q '"isError":true'; then
        # Extract error message using jq
        local error_msg
        error_msg=$(echo "${response}" | jq -r '.result.content[0].text // .error.message // .error' 2>/dev/null)

        log_verbose "Error message: ${error_msg}"

        # Check if expected error message is contained in response
        if echo "${error_msg}" | grep -qi "${expected_error_msg}"; then
            log_info "✓ ${test_name} - Query blocked as expected"
            PASSED_TESTS=$((PASSED_TESTS + 1))

            # Verify rule hit counter incremented
            if [ -n "${rule_id}" ]; then
                local hits
                hits=$(get_rule_hits "${rule_id}")
                log_verbose "Rule ${rule_id} hits: ${hits}"
                if [ "${hits}" -gt 0 ]; then
                    log_info "  Rule ${rule_id} hit counter incremented to ${hits}"
                else
                    log_warn "  Rule ${rule_id} hit counter not incremented"
                fi
            fi
            return 0
        else
            log_error "✗ ${test_name} - Error message mismatch"
            log_error "  Expected substring: ${expected_error_msg}"
            log_error "  Actual: ${error_msg}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    else
        log_error "✗ ${test_name} - Query was not blocked (expected error)"
        log_error "  Response: ${response}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Test that a query is allowed (not blocked)
test_allow_action() {
    local test_name="$1"
    local endpoint="$2"
    local tool_name="$3"
    local arguments="$4"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log_test "Testing: ${test_name}"

    local payload
    payload=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "${tool_name}",
    "arguments": ${arguments}
  },
  "id": ${TOTAL_TESTS}
}
EOF
)

    local response
    response=$(mcp_request "${endpoint}" "${payload}")

    log_verbose "Response: ${response}"

    # Check for successful response (no error)
    if echo "${response}" | grep -q '"error"'; then
        log_error "✗ ${test_name} - Query was blocked (unexpected)"
        log_error "  Response: ${response}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    else
        log_info "✓ ${test_name} - Query allowed as expected"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    fi
}

# Clean up test rules
cleanup_test_rules() {
    log_step "Cleaning up test rules..."

    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id IN (100, 101);"
    exec_admin_silent "LOAD MCP QUERY RULES TO RUNTIME;" >/dev/null 2>&1

    log_info "Test rules cleaned up"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -c|--clean)
                CLEAN_AFTER=true
                shift
                ;;
            -h|--help)
                cat <<EOF
Usage: $0 [options]

Test MCP Query Rules Block Action.

Options:
  -v, --verbose       Show verbose output including request/response
  -c, --clean         Clean up test rules after testing
  -h, --help          Show this help

Environment Variables:
  MCP_HOST            MCP server host (default: 127.0.0.1)
  MCP_PORT            MCP server port (default: 6071)
  PROXYSQL_ADMIN_HOST ProxySQL admin host (default: 127.0.0.1)
  PROXYSQL_ADMIN_PORT ProxySQL admin port (default: 6032)
  PROXYSQL_ADMIN_USER ProxySQL admin user (default: radmin)
  PROXYSQL_ADMIN_PASSWORD ProxySQL admin password (default: radmin)

Test Cases:
  1. Block DROP TABLE statement (rule_id=100)
  2. Block SELECT from customers table (rule_id=101)
  3. Allow SELECT from other tables (not blocked)

Examples:
  # Run block rule tests
  $0

  # Run with verbose output
  $0 -v

  # Run and clean up after
  $0 -c

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
    echo "MCP Query Rules - Block Action Test"
    echo "======================================"
    echo ""
    echo "MCP Server: ${MCP_HOST}:${MCP_PORT}"
    echo "ProxySQL Admin: ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
    echo ""

    # Check connections
    if ! check_proxysql_admin; then
        exit 1
    fi

    if ! check_mcp_server; then
        log_error "MCP server not accessible. Please run:"
        echo "  ./configure_mcp.sh --enable"
        exit 1
    fi

    # Clean up any existing test rules
    log_step "Cleaning up any existing test rules..."
    exec_admin_silent "DELETE FROM mcp_query_rules WHERE rule_id IN (100, 101);" >/dev/null 2>&1

    # Load block rules
    if ! load_block_rules; then
        exit 1
    fi

    # Load rules to runtime
    if ! load_rules_to_runtime; then
        exit 1
    fi

    # Display current rules
    echo ""
    display_runtime_rules
    echo ""

    # Give rules a moment to take effect
    sleep 1

    echo "======================================"
    echo "Running Block Rule Tests"
    echo "======================================"
    echo ""

    # Test 1: Block DROP TABLE statement (rule_id=100)
    test_block_action \
        "Test 1: Block DROP TABLE statement" \
        "query" \
        "run_sql_readonly" \
        '{"sql": "DROP TABLE IF EXISTS test_table;"}' \
        "DROP TABLE statements are not allowed" \
        "100"

    # Test 2: Block SELECT from customers table in testdb (rule_id=101)
    test_block_action \
        "Test 2: Block SELECT from customers table" \
        "query" \
        "run_sql_readonly" \
        '{"sql": "SELECT * FROM customers;"}' \
        "customers table is restricted" \
        "101"

    # Test 3: Allow SELECT from other tables (should not be blocked)
    test_allow_action \
        "Test 3: Allow SELECT from other tables" \
        "query" \
        "run_sql_readonly" \
        '{"sql": "SELECT * FROM products;"}'

    # Display final stats
    echo ""
    log_step "Rule hit statistics:"
    exec_admin "SELECT rule_id, hits FROM stats_mcp_query_rules WHERE rule_id IN (100, 101);"

    # Print summary
    echo ""
    echo "======================================"
    echo "Test Summary"
    echo "======================================"
    echo "Total tests:   ${TOTAL_TESTS}"
    echo -e "Passed:        ${GREEN}${PASSED_TESTS}${NC}"
    echo -e "Failed:        ${RED}${FAILED_TESTS}${NC}"
    echo ""

    # Clean up if requested
    if [ "${CLEAN_AFTER}" = "true" ]; then
        cleanup_test_rules
    fi

    if [ ${FAILED_TESTS} -gt 0 ]; then
        log_error "Some tests failed!"
        exit 1
    else
        log_info "All tests passed!"
        exit 0
    fi
}

main "$@"
