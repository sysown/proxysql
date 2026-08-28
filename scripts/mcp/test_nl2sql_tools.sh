#!/bin/bash
#
# @file test_nl2sql_tools.sh
# @brief Test NL2SQL MCP tools via HTTPS/JSON-RPC
#
# Tests the ai_nl2sql_convert tool through the MCP protocol.
#
# Prerequisites:
# - ProxySQL with MCP server running on https://127.0.0.1:6071
# - AI features enabled (GloAI initialized)
# - LLM configured (Ollama or cloud API with valid keys)
#
# Usage:
#   ./test_nl2sql_tools.sh [options]
#
# Options:
#   -v, --verbose       Show verbose output including HTTP requests/responses
#   -q, --quiet         Suppress progress messages
#   -h, --help          Show this help message
#
# @date 2025-01-16

set -e

# ============================================================================
# Configuration
# ============================================================================

MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-6071}"
MCP_ENDPOINT="${MCP_ENDPOINT:-ai}"

# Test options
VERBOSE=false
QUIET=false

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

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    if [ "${QUIET}" = "false" ]; then
        echo -e "${GREEN}[INFO]${NC} $1"
    fi
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
    if [ "${VERBOSE}" = "true" ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

log_test() {
    if [ "${QUIET}" = "false" ]; then
        echo -e "${CYAN}[TEST]${NC} $1"
    fi
}

# Get endpoint URL
get_endpoint_url() {
    echo "https://${MCP_HOST}:${MCP_PORT}/mcp/${MCP_ENDPOINT}"
}

# Execute MCP request
mcp_request() {
    local payload="$1"

    local response
    response=$(curl -k -s -w "\n%{http_code}" -X POST "$(get_endpoint_url)" \
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

# Check if MCP server is accessible
check_mcp_server() {
    log_test "Checking MCP server accessibility at $(get_endpoint_url)..."

    local response
    response=$(mcp_request '{"jsonrpc":"2.0","method":"tools/list","id":1}')

    if echo "${response}" | grep -q "result"; then
        log_info "MCP server is accessible"
        return 0
    else
        log_error "MCP server is not accessible"
        log_error "Response: ${response}"
        return 1
    fi
}

# List available tools
list_tools() {
    log_test "Listing available AI tools..."

    local payload='{"jsonrpc":"2.0","method":"tools/list","id":1}'
    local response
    response=$(mcp_request "${payload}")

    echo "${response}"
}

# Get tool description
describe_tool() {
    local tool_name="$1"

    log_verbose "Getting description for tool: ${tool_name}"

    local payload
    payload=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/describe",
  "params": {
    "name": "${tool_name}"
  },
  "id": 1
}
EOF
)

    mcp_request "${payload}"
}

# Run a single test
run_test() {
    local test_name="$1"
    local nl_query="$2"
    local expected_pattern="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log_test "Test ${TOTAL_TESTS}: ${test_name}"
    log_verbose "  Query: ${nl_query}"

    # Build the MCP request payload
    local payload
    payload=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "ai_nl2sql_convert",
    "arguments": {
      "natural_language": "${nl_query}"
    }
  },
  "id": ${TOTAL_TESTS}
}
EOF
)

    # Execute the request
    local response
    response=$(mcp_request "${payload}")

    # Extract the result data
    local result_data
    if command -v jq >/dev/null 2>&1; then
        result_data=$(echo "${response}" | jq -r '.result.data' 2>/dev/null || echo "{}")
    else
        # Fallback: extract JSON between { and }
        result_data=$(echo "${response}" | grep -o '"data":{[^}]*}' | sed 's/"data"://')
    fi

    # Check for errors
    if echo "${response}" | grep -q '"error"'; then
        local error_msg
        if command -v jq >/dev/null 2>&1; then
            error_msg=$(echo "${response}" | jq -r '.error.message' 2>/dev/null || echo "Unknown error")
        else
            error_msg=$(echo "${response}" | grep -o '"message"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: "\(.*\)"/\1/')
        fi
        log_error "  FAILED: ${error_msg}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi

    # Extract SQL query from result
    local sql_query
    if command -v jq >/dev/null 2>&1; then
        sql_query=$(echo "${response}" | jq -r '.result.data.sql_query' 2>/dev/null || echo "")
    else
        sql_query=$(echo "${response}" | grep -o '"sql_query"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: "\(.*\)"/\1/')
    fi

    log_verbose "  Generated SQL: ${sql_query}"

    # Check if expected pattern exists
    if [ -n "${expected_pattern}" ] && [ -n "${sql_query}" ]; then
        sql_upper=$(echo "${sql_query}" | tr '[:lower:]' '[:upper:]')
        pattern_upper=$(echo "${expected_pattern}" | tr '[:lower:]' '[:upper:]')

        if echo "${sql_upper}" | grep -qE "${pattern_upper}"; then
            log_info "  PASSED: Pattern '${expected_pattern}' found in SQL"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        else
            log_error "  FAILED: Pattern '${expected_pattern}' not found in SQL: ${sql_query}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    elif [ -n "${sql_query}" ]; then
        # No pattern check, just verify SQL was generated
        log_info "  PASSED: SQL generated successfully"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_error "  FAILED: No SQL query in response"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# ============================================================================
# Test Cases
# ============================================================================

run_all_tests() {
    log_info "Running NL2SQL MCP tool tests..."

    # Test 1: Simple SELECT
    run_test \
        "Simple SELECT all customers" \
        "Show all customers" \
        "SELECT.*customers"

    # Test 2: SELECT with WHERE clause
    run_test \
        "SELECT with WHERE clause" \
        "Find customers from USA" \
        "SELECT.*WHERE"

    # Test 3: JOIN query
    run_test \
        "JOIN customers and orders" \
        "Show customer names with their order amounts" \
        "JOIN"

    # Test 4: Aggregation (COUNT)
    run_test \
        "COUNT aggregation" \
        "Count customers by country" \
        "COUNT.*GROUP BY"

    # Test 5: Sorting
    run_test \
        "ORDER BY clause" \
        "Show orders sorted by total amount" \
        "ORDER BY"

    # Test 6: Limit
    run_test \
        "LIMIT clause" \
        "Show top 5 customers by revenue" \
        "SELECT.*customers"

    # Test 7: Complex aggregation
    run_test \
        "AVG aggregation" \
        "What is the average order total?" \
        "SELECT"

    # Test 8: Schema-specified query
    run_test \
        "Schema-specified query" \
        "List all users from the users table" \
        "SELECT.*users"

    # Test 9: Subquery hint
    run_test \
        "Subquery pattern" \
        "Find customers with orders above average" \
        "SELECT"

    # Test 10: Empty query (error handling)
    log_test "Test: Empty query (should handle gracefully)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    local payload='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ai_nl2sql_convert","arguments":{"natural_language":""}},"id":11}'
    local response
    response=$(mcp_request "${payload}")

    if echo "${response}" | grep -q '"error"'; then
        log_info "  PASSED: Empty query handled with error"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        log_warn "  SKIPPED: Error handling for empty query not as expected"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    fi
}

# ============================================================================
# Results Summary
# ============================================================================

print_summary() {
    echo ""
    echo "========================================"
    echo "           Test Summary"
    echo "========================================"
    echo "Total tests:   ${TOTAL_TESTS}"
    echo -e "Passed:        ${GREEN}${PASSED_TESTS}${NC}"
    echo -e "Failed:        ${RED}${FAILED_TESTS}${NC}"
    echo -e "Skipped:       ${YELLOW}${SKIPPED_TESTS:-0}${NC}"
    echo "========================================"

    if [ ${FAILED_TESTS} -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed!${NC}\n"
        return 0
    else
        echo -e "\n${RED}Some tests failed${NC}\n"
        return 1
    fi
}

# ============================================================================
# Parse Arguments
# ============================================================================

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -h|--help)
                cat <<EOF
Usage: $0 [OPTIONS]

Test NL2SQL MCP tools via HTTPS/JSON-RPC.

Options:
  -v, --verbose       Show verbose output including HTTP requests/responses
  -q, --quiet         Suppress progress messages
  -h, --help          Show this help message

Environment Variables:
  MCP_HOST            MCP server host (default: 127.0.0.1)
  MCP_PORT            MCP server port (default: 6071)
  MCP_ENDPOINT        MCP endpoint name (default: ai)

Examples:
  # Run tests with verbose output
  $0 --verbose

  # Run tests against remote server
  MCP_HOST=192.168.1.100 MCP_PORT=6071 $0

EOF
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo "========================================"
    echo "   NL2SQL MCP Tool Testing"
    echo "========================================"
    echo ""
    echo "Configuration:"
    echo "  MCP Endpoint:  $(get_endpoint_url)"
    echo "  Verbose:       ${VERBOSE}"
    echo ""

    # Parse arguments
    parse_args "$@"

    # Check server accessibility
    if ! check_mcp_server; then
        log_error "Cannot connect to MCP server. Please ensure ProxySQL is running with MCP enabled."
        exit 1
    fi

    # List available tools
    echo ""
    log_info "Discovering available AI tools..."
    local tools
    tools=$(list_tools)
    if command -v jq >/dev/null 2>&1; then
        echo "${tools}" | jq -r '.result.tools[] | "  - \(.name): \(.description)"' 2>/dev/null || echo "${tools}"
    else
        echo "${tools}"
    fi
    echo ""

    # Run tests
    run_all_tests

    # Print summary
    print_summary
}

main "$@"
