#!/bin/bash
#
# test_catalog.sh - Test catalog (LLM memory) functionality
#
# Usage:
#   ./test_catalog.sh [options]
#
# Options:
#   -v, --verbose       Show verbose output
#   -h, --help          Show help
#

set -e

# Configuration
MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-6071}"
MCP_URL="https://${MCP_HOST}:${MCP_PORT}/mcp/query"

# Test options
VERBOSE=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Execute MCP request and unwrap response
mcp_request() {
    local payload="$1"

    local response
    response=$(curl -k -s -X POST "${MCP_URL}" \
        -H "Content-Type: application/json" \
        -d "${payload}" 2>/dev/null)

    # Extract content from MCP protocol wrapper if present
    # MCP format: {"result":{"content":[{"text":"..."}]}}
    local extracted
    extracted=$(echo "${response}" | jq -r 'if .result.content[0].text then .result.content[0].text else . end' 2>/dev/null)

    if [ -n "${extracted}" ] && [ "${extracted}" != "null" ]; then
        echo "${extracted}"
    else
        echo "${response}"
    fi
}

# Test catalog operations
test_catalog() {
    local test_id="$1"
    local operation="$2"
    local payload="$3"
    local expected="$4"

    log_test "${test_id}: ${operation}"

    local response
    response=$(mcp_request "${payload}")

    if [ "${VERBOSE}" = "true" ]; then
        echo "Payload: ${payload}"
        echo "Response: ${response}"
    fi

    if echo "${response}" | grep -q "${expected}"; then
        log_info "✓ ${test_id}"
        return 0
    else
        log_error "✗ ${test_id}"
        if [ "${VERBOSE}" = "true" ]; then
            echo "Expected to find: ${expected}"
        fi
        return 1
    fi
}

# Main test flow
run_catalog_tests() {
    echo "======================================"
    echo "Catalog (LLM Memory) Test Suite"
    echo "======================================"
    echo ""
    echo "Testing catalog operations for LLM memory persistence"
    echo ""

    local passed=0
    local failed=0

    # Test 1: Upsert a table schema entry
    local payload1
    payload1='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_upsert",
    "arguments": {
      "kind": "table",
      "key": "testdb.customers",
      "document": "{\"table\": \"customers\", \"columns\": [{\"name\": \"id\", \"type\": \"INT\"}, {\"name\": \"name\", \"type\": \"VARCHAR\"}], \"row_count\": 5}",
      "tags": "schema,testdb",
      "links": "testdb.orders:customer_id"
    }
  },
  "id": 1
}'

    if test_catalog "CAT001" "Upsert table schema" "${payload1}" '"success"[[:space:]]*:[[:space:]]*true'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 2: Upsert a domain knowledge entry
    local payload2
    payload2='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_upsert",
    "arguments": {
      "kind": "domain",
      "key": "customer_management",
      "document": "{\"description\": \"Customer management domain\", \"entities\": [\"customers\", \"orders\", \"products\"], \"relationships\": [\"customer has many orders\", \"order belongs to customer\"]}",
      "tags": "domain,business",
      "links": ""
    }
  },
  "id": 2
}'

    if test_catalog "CAT002" "Upsert domain knowledge" "${payload2}" '"success"[[:space:]]*:[[:space:]]*true'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 3: Get the upserted table entry
    local payload3
    payload3='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_get",
    "arguments": {
      "kind": "table",
      "key": "testdb.customers"
    }
  },
  "id": 3
}'

    if test_catalog "CAT003" "Get table entry" "${payload3}" '"columns"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 4: Get the upserted domain entry
    local payload4
    payload4='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_get",
    "arguments": {
      "kind": "domain",
      "key": "customer_management"
    }
  },
  "id": 4
}'

    if test_catalog "CAT004" "Get domain entry" "${payload4}" '"entities"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 5: Search for table entries
    local payload5
    payload5='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "customers",
      "limit": 10
    }
  },
  "id": 5
}'

    if test_catalog "CAT005" "Search catalog" "${payload5}" '"results"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 6: List entries by kind
    local payload6
    payload6='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_list",
    "arguments": {
      "kind": "table",
      "limit": 10
    }
  },
  "id": 6
}'

    if test_catalog "CAT006" "List by kind" "${payload6}" '"results"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 7: Update existing entry
    local payload7
    payload7='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_upsert",
    "arguments": {
      "kind": "table",
      "key": "testdb.customers",
      "document": "{\"table\": \"customers\", \"columns\": [{\"name\": \"id\", \"type\": \"INT\"}, {\"name\": \"name\", \"type\": \"VARCHAR\"}, {\"name\": \"email\", \"type\": \"VARCHAR\"}], \"row_count\": 5, \"updated\": true}",
      "tags": "schema,testdb,updated",
      "links": "testdb.orders:customer_id"
    }
  },
  "id": 7
}'

    if test_catalog "CAT007" "Update existing entry" "${payload7}" '"success"[[:space:]]*:[[:space:]]*true'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 8: Verify update
    local payload8
    payload8='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_get",
    "arguments": {
      "kind": "table",
      "key": "testdb.customers"
    }
  },
  "id": 8
}'

    if test_catalog "CAT008" "Verify update" "${payload8}" '"updated"[[:space:]]*:[[:space:]]*true'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 9: Test FTS search with special characters
    local payload9
    payload9='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "customer*",
      "limit": 10
    }
  },
  "id": 9
}'

    if test_catalog "CAT009" "FTS search with wildcard" "${payload9}" '"results"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 13: Special characters in document (JSON parsing bug test)
    local payload13
    payload13='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_upsert",
    "arguments": {
      "kind": "test",
      "key": "special_chars",
      "document": "{\"description\": \"Test with \\\"quotes\\\" and \\\\backslashes\\\\\"}",
      "tags": "test,special",
      "links": ""
    }
  },
  "id": 13
}'

    if test_catalog "CAT013" "Upsert special characters" "${payload13}" '"success"[[:space:]]*:[[:space:]]*true'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 14: Verify special characters can be read back
    local payload14
    payload14='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_get",
    "arguments": {
      "kind": "test",
      "key": "special_chars"
    }
  },
  "id": 14
}'

    if test_catalog "CAT014" "Get special chars entry" "${payload14}" 'quotes'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 15: Cleanup special chars entry
    local payload15
    payload15='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_delete",
    "arguments": {
      "kind": "test",
      "key": "special_chars"
    }
  },
  "id": 15
}'

    if test_catalog "CAT015" "Cleanup special chars" "${payload15}" '"success"[[:space:]]*:[[:space:]]*true'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 10: Delete entry
    local payload10
    payload10='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_delete",
    "arguments": {
      "kind": "table",
      "key": "testdb.customers"
    }
  },
  "id": 10
}'

    if test_catalog "CAT010" "Delete entry" "${payload10}" '"success"[[:space:]]*:[[:space:]]*true'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test 11: Verify deletion
    local payload11
    payload11='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_get",
    "arguments": {
      "kind": "table",
      "key": "testdb.customers"
    }
  },
  "id": 11
}'

    # This should return an error since we deleted it
    log_test "CAT011: Verify deletion (should fail)"
    local response11
    response11=$(mcp_request "${payload11}")

    if echo "${response11}" | grep -q '"error"'; then
        log_info "✓ CAT011"
        passed=$((passed + 1))
    else
        log_error "✗ CAT011"
        failed=$((failed + 1))
    fi

    # Test 12: Cleanup - delete domain entry
    local payload12
    payload12='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_delete",
    "arguments": {
      "kind": "domain",
      "key": "customer_management"
    }
  },
  "id": 12
}'

    if test_catalog "CAT012" "Cleanup domain entry" "${payload12}" '"success"[[:space:]]*:[[:space:]]*true'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Print summary
    echo ""
    echo "======================================"
    echo "Test Summary"
    echo "======================================"
    echo "Total tests:   $((passed + failed))"
    echo -e "Passed:        ${GREEN}${passed}${NC}"
    echo -e "Failed:        ${RED}${failed}${NC}"
    echo ""

    if [ ${failed} -gt 0 ]; then
        log_error "Some tests failed!"
        return 1
    else
        log_info "All catalog tests passed!"
        return 0
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
            -h|--help)
                cat <<EOF
Usage: $0 [options]

Test catalog (LLM memory) functionality.

Options:
  -v, --verbose       Show verbose output including request/response
  -h, --help          Show this help

Environment Variables:
  MCP_HOST            MCP server host (default: 127.0.0.1)
  MCP_PORT            MCP server port (default: 6071)

Tests:
  CAT001: Upsert table schema entry
  CAT002: Upsert domain knowledge entry
  CAT003: Get table entry
  CAT004: Get domain entry
  CAT005: Search catalog
  CAT006: List entries by kind
  CAT007: Update existing entry
  CAT008: Verify update
  CAT009: FTS search with wildcard
  CAT010: Delete entry
  CAT011: Verify deletion
  CAT012: Cleanup domain entry

Examples:
  # Run all catalog tests
  $0

  # Run with verbose output
  $0 -v
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

# Main
parse_args "$@"
run_catalog_tests
