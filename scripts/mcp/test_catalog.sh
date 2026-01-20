#!/bin/bash
#
# test_catalog.sh - Test catalog (LLM memory) functionality
#
# Usage:
#   ./test_catalog.sh [options]
#
# Options:
#   -v, --verbose       Show verbose output
#   -s, --ssl           Use HTTPS (SSL/TLS) for MCP connection (default: auto-detect)
#   --no-ssl            Use HTTP (no SSL) for MCP connection
#   -h, --help          Show help
#

set -e

# Configuration
MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-6071}"
MCP_USE_SSL="${MCP_USE_SSL:-auto}"
MCP_URL=""  # Will be set by setup_connection()

# Test options
VERBOSE=false
USE_SSL=""

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

# Determine URL and curl options based on SSL setting
setup_connection() {
    local ssl_mode="${MCP_USE_SSL}"

    # Auto-detect: try HTTPS first, fall back to HTTP
    if [ "$ssl_mode" = "auto" ]; then
        # Try HTTPS first
        if curl -k -s -m 2 "https://${MCP_HOST}:${MCP_PORT}" >/dev/null 2>&1; then
            USE_SSL=true
            MCP_URL="https://${MCP_HOST}:${MCP_PORT}/mcp/query"
            log_info "Auto-detected: Using HTTPS (SSL)"
        elif curl -s -m 2 "http://${MCP_HOST}:${MCP_PORT}" >/dev/null 2>&1; then
            USE_SSL=false
            MCP_URL="http://${MCP_HOST}:${MCP_PORT}/mcp/query"
            log_info "Auto-detected: Using HTTP (no SSL)"
        else
            # Default to HTTPS if can't detect
            USE_SSL=true
            MCP_URL="https://${MCP_HOST}:${MCP_PORT}/mcp/query"
            log_info "Auto-detect failed, defaulting to HTTPS"
        fi
    elif [ "$ssl_mode" = "true" ] || [ "$ssl_mode" = "1" ]; then
        USE_SSL=true
        MCP_URL="https://${MCP_HOST}:${MCP_PORT}/mcp/query"
    else
        USE_SSL=false
        MCP_URL="http://${MCP_HOST}:${MCP_PORT}/mcp/query"
    fi
}

# Execute MCP request and unwrap response
mcp_request() {
    local payload="$1"

    local response
    if [ "$USE_SSL" = "true" ]; then
        response=$(curl -k -s -X POST "${MCP_URL}" \
            -H "Content-Type: application/json" \
            -d "${payload}" 2>/dev/null)
    else
        response=$(curl -s -X POST "${MCP_URL}" \
            -H "Content-Type: application/json" \
            -d "${payload}" 2>/dev/null)
    fi

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
    echo "MCP Server: ${MCP_URL}"
    echo "SSL Mode: ${USE_SSL:-detecting...}"
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

    echo ""
    echo "======================================"
    echo "FTS5 Enhanced Tests"
    echo "======================================"

    # Setup: Add multiple entries for FTS5 testing
    log_test "Setup: Adding test data for FTS5 tests"

    local setup_payload1='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_upsert",
    "arguments": {
      "kind": "table",
      "key": "fts_test.users",
      "document": "{\"table\": \"users\", \"description\": \"User accounts table with authentication data\", \"columns\": [\"id\", \"username\", \"email\", \"password_hash\"]}",
      "tags": "authentication,users,security",
      "links": ""
    }
  },
  "id": 1001
}'

    local setup_payload2='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_upsert",
    "arguments": {
      "kind": "table",
      "key": "fts_test.products",
      "document": "{\"table\": \"products\", \"description\": \"Product catalog with pricing and inventory\", \"columns\": [\"id\", \"name\", \"price\", \"stock\"]}",
      "tags": "ecommerce,products,catalog",
      "links": ""
    }
  },
  "id": 1002
}'

    local setup_payload3='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_upsert",
    "arguments": {
      "kind": "domain",
      "key": "user_authentication",
      "document": "{\"description\": \"User authentication and authorization domain\", \"flows\": [\"login\", \"logout\", \"password_reset\"], \"policies\": [\"MFA\", \"password_complexity\"]}",
      "tags": "security,authentication",
      "links": ""
    }
  },
  "id": 1003
}'

    local setup_payload4='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_upsert",
    "arguments": {
      "kind": "domain",
      "key": "product_management",
      "document": "{\"description\": \"Product inventory and catalog management\", \"features\": [\"bulk_import\", \"pricing_rules\", \"stock_alerts\"]}",
      "tags": "ecommerce,inventory",
      "links": ""
    }
  },
  "id": 1004
}'

    # Run setup
    mcp_request "${setup_payload1}" > /dev/null
    mcp_request "${setup_payload2}" > /dev/null
    mcp_request "${setup_payload3}" > /dev/null
    mcp_request "${setup_payload4}" > /dev/null

    log_info "Setup complete: Added 4 test entries for FTS5 testing"

    # Test CAT013: FTS5 multi-term search (AND logic)
    local payload13='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "authentication user",
      "limit": 10
    }
  },
  "id": 13
}'

    if test_catalog "CAT013" "FTS5 multi-term search (AND)" "${payload13}" '"results"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test CAT014: FTS5 phrase search with quotes
    local payload14='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "\"user authentication\"",
      "limit": 10
    }
  },
  "id": 14
}'

    if test_catalog "CAT014" "FTS5 phrase search" "${payload14}" '"results"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test CAT015: FTS5 OR search
    local payload15='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "authentication OR inventory",
      "limit": 10
    }
  },
  "id": 15
}'

    if test_catalog "CAT015" "FTS5 OR search" "${payload15}" '"results"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test CAT016: FTS5 NOT search
    local payload16='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "authentication NOT domain",
      "limit": 10
    }
  },
  "id": 16
}'

    if test_catalog "CAT016" "FTS5 NOT search" "${payload16}" '"results"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test CAT017: FTS5 search with kind filter
    local payload17='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "user",
      "kind": "table",
      "limit": 10
    }
  },
  "id": 17
}'

    if test_catalog "CAT017" "FTS5 search with kind filter" "${payload17}" '"results"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test CAT018: FTS5 prefix search (ends with *)
    local payload18='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "auth*",
      "limit": 10
    }
  },
  "id": 18
}'

    if test_catalog "CAT018" "FTS5 prefix search" "${payload18}" '"results"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test CAT019: FTS5 relevance ranking (search for common term, check results exist)
    local payload19='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "table",
      "limit": 5
    }
  },
  "id": 19
}'

    if test_catalog "CAT019" "FTS5 relevance ranking" "${payload19}" '"results"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test CAT020: FTS5 search with tags filter
    local payload20='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "user",
      "tags": "security",
      "limit": 10
    }
  },
  "id": 20
}'

    if test_catalog "CAT020" "FTS5 search with tags filter" "${payload20}" '"results"'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Test CAT021: Empty query should return empty results (FTS5 requires query)
    local payload21='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_search",
    "arguments": {
      "query": "",
      "limit": 10
    }
  },
  "id": 21
}'

    if test_catalog "CAT021" "Empty query returns empty array" "${payload21}" '"results"[[:space:]]*:[[:space:]]*\[\]'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # Cleanup: Remove FTS5 test entries
    log_test "Cleanup: Removing FTS5 test entries"

    local cleanup_payload1='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_delete",
    "arguments": {
      "kind": "table",
      "key": "fts_test.users"
    }
  },
  "id": 2001
}'

    local cleanup_payload2='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_delete",
    "arguments": {
      "kind": "table",
      "key": "fts_test.products"
    }
  },
  "id": 2002
}'

    local cleanup_payload3='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_delete",
    "arguments": {
      "kind": "domain",
      "key": "user_authentication"
    }
  },
  "id": 2003
}'

    local cleanup_payload4='{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "catalog_delete",
    "arguments": {
      "kind": "domain",
      "key": "product_management"
    }
  },
  "id": 2004
}'

    mcp_request "${cleanup_payload1}" > /dev/null
    mcp_request "${cleanup_payload2}" > /dev/null
    mcp_request "${cleanup_payload3}" > /dev/null
    mcp_request "${cleanup_payload4}" > /dev/null

    log_info "Cleanup complete: Removed FTS5 test entries"

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
            -s|--ssl)
                MCP_USE_SSL=true
                shift
                ;;
            --no-ssl)
                MCP_USE_SSL=false
                shift
                ;;
            -h|--help)
                cat <<EOF
Usage: $0 [options]

Test catalog (LLM memory) functionality.

Options:
  -v, --verbose       Show verbose output including request/response
  -s, --ssl           Use HTTPS (SSL/TLS) for MCP connection
  --no-ssl            Use HTTP (no SSL) for MCP connection
  -h, --help          Show this help

Environment Variables:
  MCP_HOST            MCP server host (default: 127.0.0.1)
  MCP_PORT            MCP server port (default: 6071)
  MCP_USE_SSL         SSL mode: true/false/auto (default: auto)
                      auto: Try HTTPS first, fall back to HTTP

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
  FTS5 Enhanced Tests (CAT013-CAT021):
  CAT013: FTS5 multi-term search (AND logic)
  CAT014: FTS5 phrase search with quotes
  CAT015: FTS5 OR search
  CAT016: FTS5 NOT search
  CAT017: FTS5 search with kind filter
  CAT018: FTS5 prefix search (ends with *)
  CAT019: FTS5 relevance ranking
  CAT020: FTS5 search with tags filter
  CAT021: Empty query returns empty array

Examples:
  # Run all catalog tests
  $0

  # Run with verbose output
  $0 -v

  # Force HTTP (no SSL)
  $0 --no-ssl

  # Force HTTPS (SSL)
  $0 --ssl

  # Use custom host and port with auto SSL detection
  MCP_HOST=192.168.1.100 MCP_PORT=8071 $0

  # Force SSL with custom host
  MCP_HOST=proxysql.example.com $0 --ssl
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
setup_connection
run_catalog_tests
