#!/bin/bash
#
# test_mcp_tools.sh - Test all MCP tools via HTTPS/JSON-RPC
#
# Usage:
#   ./test_mcp_tools.sh [options]
#
# Options:
#   -v, --verbose       Show verbose output
#   -q, --quiet         Suppress progress messages
#   --tool NAME         Test only specific tool
#   --skip-tool NAME    Skip specific tool
#   -h, --help          Show help
#

set -e

# Configuration
MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-6071}"
MCP_CONFIG_URL="https://${MCP_HOST}:${MCP_PORT}/config"
MCP_QUERY_URL="https://${MCP_HOST}:${MCP_PORT}/query"

# Test options
VERBOSE=false
QUIET=false
TEST_TOOL=""
SKIP_TOOLS=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

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
        echo -e "${BLUE}[TEST]${NC} $1"
    fi
}

# Execute MCP request
mcp_request() {
    local endpoint="$1"
    local payload="$2"

    local response
    response=$(curl -k -s -w "\n%{http_code}" -X POST "${endpoint}" \
        -H "Content-Type: application/json" \
        -d "${payload}" 2>/dev/null)

    local body=$(echo "$response" | head -n -1)
    local code=$(echo "$response" | tail -n 1)

    if [ "${VERBOSE}" = "true" ]; then
        echo "Request: ${payload}"
        echo "Response (${code}): ${body}"
    fi

    echo "${body}"
    return 0
}

# Check if MCP server is accessible
check_mcp_server() {
    log_test "Checking MCP server accessibility..."

    local response
    response=$(mcp_request "${MCP_CONFIG_URL}" '{"jsonrpc":"2.0","method":"ping","id":1}')

    if echo "${response}" | grep -q "result"; then
        log_info "MCP server is accessible"
        return 0
    else
        log_error "MCP server is not accessible"
        log_error "Response: ${response}"
        return 1
    fi
}

# Assert that JSON contains expected value
assert_json_contains() {
    local response="$1"
    local field="$2"
    local expected="$3"

    if echo "${response}" | grep -q "\"${field}\"[[:space:]]*:[[:space:]]*${expected}"; then
        return 0
    fi

    # Try with jq if available
    if command -v jq &> /dev/null; then
        local actual
        actual=$(echo "${response}" | jq -r "${field}" 2>/dev/null)
        if [ "${actual}" = "${expected}" ]; then
            return 0
        fi
    fi

    return 1
}

# Assert that JSON array contains expected value
assert_json_array_contains() {
    local response="$1"
    local field="$2"
    local expected="$3"

    if echo "${response}" | grep -q "${expected}"; then
        return 0
    fi

    return 1
}

# Test a tool
test_tool() {
    local tool_name="$1"
    local arguments="$2"
    local expected_field="$3"
    local expected_value="$4"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log_test "Testing tool: ${tool_name}"

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
    response=$(mcp_request "${MCP_QUERY_URL}" "${payload}")

    # Check for error response
    if echo "${response}" | grep -q '"error"'; then
        log_error "Tool ${tool_name} returned error"
        if [ "${VERBOSE}" = "true" ]; then
            echo "Response: ${response}"
        fi
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi

    # Check expected value if provided
    if [ -n "${expected_field}" ] && [ -n "${expected_value}" ]; then
        if assert_json_contains "${response}" "${expected_field}" "${expected_value}"; then
            log_info "✓ ${tool_name}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        else
            log_error "✗ ${tool_name} - assertion failed"
            if [ "${VERBOSE}" = "true" ]; then
                echo "Expected: ${expected_field} = ${expected_value}"
                echo "Response: ${response}"
            fi
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    else
        log_info "✓ ${tool_name}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    fi
}

# Test list_schemas
test_list_schemas() {
    test_tool "list_schemas" "{}"
}

# Test list_tables
test_list_tables() {
    test_tool "list_tables" '{"schema": "testdb"}'
}

# Test describe_table
test_describe_table() {
    test_tool "describe_table" '{"schema": "testdb", "table": "customers"}'
}

# Test get_constraints
test_get_constraints() {
    test_tool "get_constraints" '{"schema": "testdb"}'
}

# Test describe_view
test_describe_view() {
    test_tool "describe_view" '{"schema": "testdb", "view": "customer_orders"}'
}

# Test table_profile
test_table_profile() {
    test_tool "table_profile" '{"schema": "testdb", "table": "customers", "mode": "quick"}'
}

# Test column_profile
test_column_profile() {
    test_tool "column_profile" '{"schema": "testdb", "table": "customers", "column": "name"}'
}

# Test sample_rows
test_sample_rows() {
    test_tool "sample_rows" '{"schema": "testdb", "table": "customers", "limit": 3}'
}

# Test sample_distinct
test_sample_distinct() {
    test_tool "sample_distinct" '{"schema": "testdb", "table": "customers", "column": "name", "limit": 5}'
}

# Test run_sql_readonly
test_run_sql_readonly() {
    test_tool "run_sql_readonly" '{"sql": "SELECT * FROM customers LIMIT 2"}'
}

# Test explain_sql
test_explain_sql() {
    test_tool "explain_sql" '{"sql": "SELECT * FROM customers WHERE id = 1"}'
}

# Test catalog_upsert
test_catalog_upsert() {
    local payload=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_upsert",
    "arguments": {
      "kind": "test",
      "key": "test_key",
      "document": "{\"test\": \"value\"}",
      "tags": "test,mcp"
    }
  },
  "id": 999
}
EOF
)

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Testing tool: catalog_upsert"

    local response
    response=$(mcp_request "${MCP_QUERY_URL}" "${payload}")

    if echo "${response}" | grep -q '"success"[[:space:]]*:[[:space:]]*true'; then
        log_info "✓ catalog_upsert"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_error "✗ catalog_upsert"
        if [ "${VERBOSE}" = "true" ]; then
            echo "Response: ${response}"
        fi
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Test catalog_get
test_catalog_get() {
    local payload=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_get",
    "arguments": {
      "kind": "test",
      "key": "test_key"
    }
  },
  "id": 999
}
EOF
)

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Testing tool: catalog_get"

    local response
    response=$(mcp_request "${MCP_QUERY_URL}" "${payload}")

    if echo "${response}" | grep -q '"success"[[:space:]]*:[[:space:]]*true'; then
        log_info "✓ catalog_get"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_error "✗ catalog_get"
        if [ "${VERBOSE}" = "true" ]; then
            echo "Response: ${response}"
        fi
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Test catalog_search
test_catalog_search() {
    local payload=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "test",
      "limit": 10
    }
  },
  "id": 999
}
EOF
)

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Testing tool: catalog_search"

    local response
    response=$(mcp_request "${MCP_QUERY_URL}" "${payload}")

    if echo "${response}" | grep -q '"success"'; then
        log_info "✓ catalog_search"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_error "✗ catalog_search"
        if [ "${VERBOSE}" = "true" ]; then
            echo "Response: ${response}"
        fi
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Test catalog_delete
test_catalog_delete() {
    local payload=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_delete",
    "arguments": {
      "kind": "test",
      "key": "test_key"
    }
  },
  "id": 999
}
EOF
)

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Testing tool: catalog_delete"

    local response
    response=$(mcp_request "${MCP_QUERY_URL}" "${payload}")

    if echo "${response}" | grep -q '"success"[[:space:]]*:[[:space:]]*true'; then
        log_info "✓ catalog_delete"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_error "✗ catalog_delete"
        if [ "${VERBOSE}" = "true" ]; then
            echo "Response: ${response}"
        fi
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            --tool)
                TEST_TOOL="$2"
                shift 2
                ;;
            --skip-tool)
                SKIP_TOOLS+=("$2")
                shift 2
                ;;
            -h|--help)
                cat <<EOF
Usage: $0 [options]

Test MCP tools via HTTPS/JSON-RPC.

Options:
  -v, --verbose       Show verbose output including request/response
  -q, --quiet         Suppress progress messages
  --tool NAME         Test only specific tool
  --skip-tool NAME    Skip specific tool
  -h, --help          Show this help

Environment Variables:
  MCP_HOST            MCP server host (default: 127.0.0.1)
  MCP_PORT            MCP server port (default: 6071)

Available Tools:
  - list_schemas
  - list_tables
  - describe_table
  - get_constraints
  - describe_view
  - table_profile
  - column_profile
  - sample_rows
  - sample_distinct
  - run_sql_readonly
  - explain_sql
  - catalog_upsert
  - catalog_get
  - catalog_search
  - catalog_delete

Examples:
  # Test all tools
  $0

  # Test only list_schemas
  $0 --tool list_schemas

  # Test with verbose output
  $0 -v

  # Skip catalog tests
  $0 --skip-tool catalog_upsert --skip-tool catalog_get
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

# Check if tool should be skipped
should_skip_tool() {
    local tool="$1"
    for skip in "${SKIP_TOOLS[@]}"; do
        if [ "${tool}" = "${skip}" ]; then
            return 0
        fi
    done
    return 1
}

# Run all tests
run_all_tests() {
    echo "======================================"
    echo "MCP Tools Test Suite"
    echo "======================================"
    echo ""
    echo "MCP Server: ${MCP_CONFIG_URL}"
    echo ""

    # Check MCP server
    if ! check_mcp_server; then
        log_error "MCP server is not accessible. Please run:"
        echo "  ./configure_mcp.sh --enable"
        exit 1
    fi

    echo ""

    # Determine which tests to run
    local tests_to_run=()

    if [ -n "${TEST_TOOL}" ]; then
        # Run only specific tool
        tests_to_run=("${TEST_TOOL}")
    else
        # Run all tools
        tests_to_run=(
            "list_schemas"
            "list_tables"
            "describe_table"
            "get_constraints"
            "describe_view"
            "table_profile"
            "column_profile"
            "sample_rows"
            "sample_distinct"
            "run_sql_readonly"
            "explain_sql"
            "catalog_upsert"
            "catalog_get"
            "catalog_search"
            "catalog_delete"
        )
    fi

    # Run tests
    for tool in "${tests_to_run[@]}"; do
        if should_skip_tool "${tool}"; then
            SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
            log_info "- ${tool} (skipped)"
            continue
        fi

        case "${tool}" in
            list_schemas) test_list_schemas ;;
            list_tables) test_list_tables ;;
            describe_table) test_describe_table ;;
            get_constraints) test_get_constraints ;;
            describe_view) test_describe_view ;;
            table_profile) test_table_profile ;;
            column_profile) test_column_profile ;;
            sample_rows) test_sample_rows ;;
            sample_distinct) test_sample_distinct ;;
            run_sql_readonly) test_run_sql_readonly ;;
            explain_sql) test_explain_sql ;;
            catalog_upsert) test_catalog_upsert ;;
            catalog_get) test_catalog_get ;;
            catalog_search) test_catalog_search ;;
            catalog_delete) test_catalog_delete ;;
            *)
                log_warn "Unknown tool: ${tool}"
                ;;
        esac
    done

    # Print summary
    echo ""
    echo "======================================"
    echo "Test Summary"
    echo "======================================"
    echo "Total tests:   ${TOTAL_TESTS}"
    echo -e "Passed:        ${GREEN}${PASSED_TESTS}${NC}"
    echo -e "Failed:        ${RED}${FAILED_TESTS}${NC}"
    echo "Skipped:      ${SKIPPED_TESTS}"
    echo ""

    if [ ${FAILED_TESTS} -gt 0 ]; then
        log_error "Some tests failed!"
        exit 1
    else
        log_info "All tests passed!"
        exit 0
    fi
}

# Main
parse_args "$@"
run_all_tests
