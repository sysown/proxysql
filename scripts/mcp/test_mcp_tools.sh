#!/bin/bash
#
# test_mcp_tools.sh - Test MCP tools via HTTPS/JSON-RPC with dynamic tool discovery
#
# Usage:
#   ./test_mcp_tools.sh [options]
#
# Options:
#   -v, --verbose       Show verbose output
#   -q, --quiet         Suppress progress messages
#   --endpoint NAME     Test only specific endpoint (config, query, admin, cache, observe)
#   --tool NAME         Test only specific tool
#   --skip-tool NAME    Skip specific tool
#   --list-only         Only list discovered tools without testing
#   -h, --help          Show help
#

set -e

# Configuration
MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-6071}"

# Endpoints (will be used for discovery)
ENDPOINTS=("config" "query" "admin" "cache" "observe")

# Test options
VERBOSE=false
QUIET=false
TEST_ENDPOINT=""
TEST_TOOL=""
SKIP_TOOLS=()
LIST_ONLY=false

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
SKIPPED_TESTS=0

# Temp file for discovered tools
DISCOVERED_TOOLS_FILE=$(mktemp)

# Cleanup on exit
trap "rm -f ${DISCOVERED_TOOLS_FILE}" EXIT

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

# Get endpoint URL
get_endpoint_url() {
    local endpoint="$1"
    echo "https://${MCP_HOST}:${MCP_PORT}/mcp/${endpoint}"
}

# Execute MCP request
mcp_request() {
    local endpoint="$1"
    local payload="$2"

    local response
    response=$(curl -k -s -w "\n%{http_code}" -X POST "${endpoint}" \
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
    log_test "Checking MCP server accessibility..."

    local config_url
    config_url=$(get_endpoint_url "config")
    local response
    response=$(mcp_request "${config_url}" '{"jsonrpc":"2.0","method":"ping","id":1}')

    if echo "${response}" | grep -q "result"; then
        log_info "MCP server is accessible"
        return 0
    else
        log_error "MCP server is not accessible"
        log_error "Response: ${response}"
        return 1
    fi
}

# Discover tools from an endpoint
discover_tools() {
    local endpoint="$1"
    local url
    url=$(get_endpoint_url "${endpoint}")

    log_verbose "Discovering tools from endpoint: ${endpoint}"

    local payload='{"jsonrpc":"2.0","method":"tools/list","id":1}'
    local response
    response=$(mcp_request "${url}" "${payload}")

    # Extract tool names from response
    local tools_json=""

    if command -v jq >/dev/null 2>&1; then
        # Use jq for reliable JSON parsing
        tools_json=$(echo "${response}" | jq -r '.result.tools[].name' 2>/dev/null || echo "")
    else
        # Fallback to grep/sed
        tools_json=$(echo "${response}" | grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: "\(.*\)"/\1/')
    fi

    # Store discovered tools in temp file
    # Format: endpoint:tool_name
    while IFS= read -r tool_name; do
        if [ -n "${tool_name}" ]; then
            echo "${endpoint}:${tool_name}" >> "${DISCOVERED_TOOLS_FILE}"
        fi
    done <<< "${tools_json}"

    log_verbose "Discovered tools from ${endpoint}: ${tools_json}"
}

# Check if a tool is discovered on an endpoint
is_tool_discovered() {
    local endpoint="$1"
    local tool="$2"
    local key="${endpoint}:${tool}"

    if grep -q "^${key}$" "${DISCOVERED_TOOLS_FILE}" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Get discovered tools for an endpoint
get_discovered_tools() {
    local endpoint="$1"
    grep "^${endpoint}:" "${DISCOVERED_TOOLS_FILE}" 2>/dev/null | sed "s/^${endpoint}://" || true
}

# Count discovered tools for an endpoint
count_discovered_tools() {
    local endpoint="$1"
    get_discovered_tools "${endpoint}" | wc -l
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
    if command -v jq >/dev/null 2>&1; then
        local actual
        actual=$(echo "${response}" | jq -r "${field}" 2>/dev/null)
        if [ "${actual}" = "${expected}" ]; then
            return 0
        fi
    fi

    return 1
}

# Test a tool
test_tool() {
    local endpoint="$1"
    local tool_name="$2"
    local arguments="$3"
    local expected_field="$4"
    local expected_value="$5"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log_test "Testing tool: ${tool_name} (endpoint: ${endpoint})"

    local url
    url=$(get_endpoint_url "${endpoint}")

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
    response=$(mcp_request "${url}" "${payload}")

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
            log_info "✓ ${tool_name} (${endpoint})"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        else
            log_error "✗ ${tool_name} (${endpoint}) - assertion failed"
            if [ "${VERBOSE}" = "true" ]; then
                echo "Expected: ${expected_field} = ${expected_value}"
                echo "Response: ${response}"
            fi
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    else
        log_info "✓ ${tool_name} (${endpoint})"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    fi
}

# ============================================================================
# EXPECTED TOOL DEFINITIONS
# ============================================================================
# This section defines the expected tools and their test configurations.
# Tools are only tested if they are discovered via tools/list.
#
# Format: add_test_config endpoint tool_name "arguments" "expected_field" "expected_value"
# ============================================================================

# Array to store test configurations
TEST_ENDPOINTS=()
TEST_TOOLS=()
TEST_ARGUMENTS=()
TEST_EXPECTED_FIELDS=()
TEST_EXPECTED_VALUES=()

add_test_config() {
    local endpoint="$1"
    local tool="$2"
    local arguments="$3"
    local expected_field="$4"
    local expected_value="$5"

    TEST_ENDPOINTS+=("${endpoint}")
    TEST_TOOLS+=("${tool}")
    TEST_ARGUMENTS+=("${arguments}")
    TEST_EXPECTED_FIELDS+=("${expected_field}")
    TEST_EXPECTED_VALUES+=("${expected_value}")
}

# Query endpoint tools (from MySQL_Tool_Handler)
add_test_config "query" "list_schemas" "{}" "" ""
add_test_config "query" "list_tables" '{"schema": "testdb"}' "" ""
add_test_config "query" "describe_table" '{"schema": "testdb", "table": "customers"}' "" ""
add_test_config "query" "get_constraints" '{"schema": "testdb"}' "" ""
add_test_config "query" "describe_view" '{"schema": "testdb", "view": "customer_orders"}' "" ""
add_test_config "query" "table_profile" '{"schema": "testdb", "table": "customers", "mode": "quick"}' "" ""
add_test_config "query" "column_profile" '{"schema": "testdb", "table": "customers", "column": "name"}' "" ""
add_test_config "query" "sample_rows" '{"schema": "testdb", "table": "customers", "limit": 3}' "" ""
add_test_config "query" "sample_distinct" '{"schema": "testdb", "table": "customers", "column": "name", "limit": 5}' "" ""
add_test_config "query" "run_sql_readonly" '{"sql": "SELECT * FROM customers LIMIT 2"}' "" ""
add_test_config "query" "explain_sql" '{"sql": "SELECT * FROM customers WHERE id = 1"}' "" ""
add_test_config "query" "suggest_joins" '{"schema": "testdb", "table": "customers"}' "" ""
add_test_config "query" "find_reference_candidates" '{"schema": "testdb", "table": "customers"}' "" ""
add_test_config "query" "catalog_upsert" '{"kind": "test", "key": "test_key", "document": "{\"test\": \"value\"}", "tags": "test,mcp"}' "success" "true"
add_test_config "query" "catalog_get" '{"kind": "test", "key": "test_key"}' "success" "true"
add_test_config "query" "catalog_search" '{"query": "test", "limit": 10}' "success" "true"
add_test_config "query" "catalog_delete" '{"kind": "test", "key": "test_key"}' "success" "true"
add_test_config "query" "catalog_list" '{"kind": "test"}' "" ""
add_test_config "query" "catalog_stats" '{}' "" ""

# Config endpoint tools (from Config_Tool_Handler) - stub implementations
add_test_config "config" "get_config" '{"variable_name": "mcp_port"}' "" ""
add_test_config "config" "set_config" '{"variable_name": "test_var", "value": "test_value"}' "" ""
add_test_config "config" "reload_config" '{}' "" ""
add_test_config "config" "list_variables" '{}' "" ""
add_test_config "config" "get_status" '{}' "" ""

# Admin endpoint tools (from Admin_Tool_Handler) - stub implementations
add_test_config "admin" "admin_list_users" '{}' "" ""
add_test_config "admin" "admin_create_user" '{"username": "test_user", "password": "test_pass"}' "" ""
add_test_config "admin" "admin_grant_permissions" '{"username": "test_user", "permissions": "SELECT"}' "" ""
add_test_config "admin" "admin_show_processes" '{}' "" ""
add_test_config "admin" "admin_kill_query" '{"query_id": "123"}' "" ""
add_test_config "admin" "admin_flush_cache" '{}' "" ""
add_test_config "admin" "admin_reload" '{}' "" ""

# Cache endpoint tools (from Cache_Tool_Handler) - stub implementations
add_test_config "cache" "get_cache_stats" '{}' "" ""
add_test_config "cache" "invalidate_cache" '{"query": "SELECT * FROM test"}' "" ""
add_test_config "cache" "set_cache_ttl" '{"ttl": 3600}' "" ""
add_test_config "cache" "clear_cache" '{}' "" ""
add_test_config "cache" "warm_cache" '{"queries": ["SELECT 1"]}' "" ""
add_test_config "cache" "get_cache_entries" '{}' "" ""

# Observe endpoint tools (from Observe_Tool_Handler) - stub implementations
add_test_config "observe" "list_stats" '{}' "" ""
add_test_config "observe" "get_stats" '{"stat": "connection_count"}' "" ""
add_test_config "observe" "show_connections" '{}' "" ""
add_test_config "observe" "show_queries" '{}' "" ""
add_test_config "observe" "get_health" '{}' "" ""
add_test_config "observe" "show_metrics" '{}' "" ""

# Print discovered tools report
print_discovery_report() {
    echo ""
    echo "======================================"
    echo "Tool Discovery Report"
    echo "======================================"

    for endpoint in "${ENDPOINTS[@]}"; do
        echo ""
        echo -e "${CYAN}Endpoint: /mcp/${endpoint}${NC}"

        local url
        url=$(get_endpoint_url "${endpoint}")
        echo "  URL: ${url}"

        local discovered
        discovered=$(get_discovered_tools "${endpoint}")

        if [ -z "${discovered}" ]; then
            echo -e "  ${RED}No tools discovered${NC}"
            echo "  (Endpoint may not be implemented yet)"
        else
            local count
            count=$(echo "${discovered}" | wc -l)
            echo -e "  ${GREEN}Discovered ${count} tool(s):${NC}"
            echo "${discovered}" | while read -r tool; do
                echo "    - ${tool}"
            done
        fi
    done

    local total
    total=$(wc -l < "${DISCOVERED_TOOLS_FILE}" 2>/dev/null || echo "0")
    echo ""
    echo "Total tools discovered: ${total}"
    echo ""
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
            --endpoint)
                TEST_ENDPOINT="$2"
                shift 2
                ;;
            --tool)
                TEST_TOOL="$2"
                shift 2
                ;;
            --skip-tool)
                SKIP_TOOLS+=("$2")
                shift 2
                ;;
            --list-only)
                LIST_ONLY=true
                shift
                ;;
            -h|--help)
                cat <<EOF
Usage: $0 [options]

Test MCP tools via HTTPS/JSON-RPC with dynamic tool discovery.

Options:
  -v, --verbose       Show verbose output including request/response
  -q, --quiet         Suppress progress messages
  --endpoint NAME     Test only specific endpoint (config, query, admin, cache, observe)
  --tool NAME         Test only specific tool
  --skip-tool NAME    Skip specific tool
  --list-only         Only list discovered tools without testing
  -h, --help          Show this help

Environment Variables:
  MCP_HOST            MCP server host (default: 127.0.0.1)
  MCP_PORT            MCP server port (default: 6071)

Available Endpoints:
  - config    Configuration management (get_config, set_config, reload_config, etc.)
  - query     Database exploration and query (list_schemas, list_tables, etc.)
  - admin     Administrative operations (admin_list_users, admin_create_user, etc.)
  - cache     Cache management (get_cache_stats, invalidate_cache, etc.)
  - observe   Monitoring and metrics (list_stats, get_stats, etc.)

Examples:
  # Discover and test all tools on all endpoints
  $0

  # Only list discovered tools without testing
  $0 --list-only

  # Test only the query endpoint
  $0 --endpoint query

  # Test only list_schemas tool
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

# Discover all tools from all endpoints
discover_all_tools() {
    log_info "Discovering tools from all endpoints..."
    > "${DISCOVERED_TOOLS_FILE}"  # Clear the file

    if [ -n "${TEST_ENDPOINT}" ]; then
        discover_tools "${TEST_ENDPOINT}"
    else
        for endpoint in "${ENDPOINTS[@]}"; do
            discover_tools "${endpoint}"
        done
    fi
}

# Run all tests
run_all_tests() {
    echo "======================================"
    echo "MCP Tools Test Suite (Dynamic Discovery)"
    echo "======================================"
    echo ""
    echo "MCP Host: ${MCP_HOST}"
    echo "MCP Port: ${MCP_PORT}"
    echo ""

    # Print environment variables if set
    if [ -n "${MCP_HOST}" ] || [ -n "${MCP_PORT}" ]; then
        log_info "Environment Variables:"
        [ -n "${MCP_HOST}" ] && echo "  MCP_HOST=${MCP_HOST}"
        [ -n "${MCP_PORT}" ] && echo "  MCP_PORT=${MCP_PORT}"
        echo ""
    fi

    # Check MCP server
    if ! check_mcp_server; then
        log_error "MCP server is not accessible. Please run:"
        echo "  ./configure_mcp.sh --enable"
        exit 1
    fi

    # Discover all tools
    discover_all_tools

    # Print discovery report
    print_discovery_report

    # Exit if list-only mode
    if [ "${LIST_ONLY}" = "true" ]; then
        exit 0
    fi

    echo "======================================"
    echo "Running Tests"
    echo "======================================"
    echo ""

    # Run tests
    local num_tests=${#TEST_ENDPOINTS[@]}
    for ((i=0; i<num_tests; i++)); do
        local endpoint="${TEST_ENDPOINTS[$i]}"
        local tool_name="${TEST_TOOLS[$i]}"
        local arguments="${TEST_ARGUMENTS[$i]}"
        local expected_field="${TEST_EXPECTED_FIELDS[$i]}"
        local expected_value="${TEST_EXPECTED_VALUES[$i]}"

        # Skip if not testing this endpoint
        if [ -n "${TEST_ENDPOINT}" ] && [ "${endpoint}" != "${TEST_ENDPOINT}" ]; then
            continue
        fi

        # Skip if not testing this tool
        if [ -n "${TEST_TOOL}" ] && [ "${tool_name}" != "${TEST_TOOL}" ]; then
            continue
        fi

        # Check if tool is discovered
        if ! is_tool_discovered "${endpoint}" "${tool_name}"; then
            log_verbose "Skipping ${tool_name} (${endpoint}) - not discovered"
            continue
        fi

        # Check if tool should be skipped
        if should_skip_tool "${tool_name}"; then
            SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
            log_info "- ${tool_name} (${endpoint}) - skipped"
            continue
        fi

        test_tool "${endpoint}" "${tool_name}" "${arguments}" "${expected_field}" "${expected_value}"
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
