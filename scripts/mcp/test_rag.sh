#!/bin/bash
#
# test_rag.sh - Test RAG functionality via MCP endpoint
#
# Usage:
#   ./test_rag.sh [options]
#
# Options:
#   -v, --verbose       Show verbose output
#   -q, --quiet         Suppress progress messages
#   -h, --help          Show help
#

set -e

# Configuration
MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-6071}"

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

# Helper functions
log() {
    if [ "$QUIET" = false ]; then
        echo "$@"
    fi
}

log_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo "$@"
    fi
}

log_success() {
    if [ "$QUIET" = false ]; then
        echo -e "${GREEN}✓${NC} $@"
    fi
}

log_failure() {
    if [ "$QUIET" = false ]; then
        echo -e "${RED}✗${NC} $@"
    fi
}

# Parse command line arguments
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
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose       Show verbose output"
            echo "  -q, --quiet         Suppress progress messages"
            echo "  -h, --help          Show help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Test MCP endpoint connectivity
test_mcp_connectivity() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log "Testing MCP connectivity to ${MCP_HOST}:${MCP_PORT}..."

    # Test basic connectivity
    if curl -s -k -f "https://${MCP_HOST}:${MCP_PORT}/mcp/rag" >/dev/null 2>&1; then
        log_success "MCP RAG endpoint is accessible"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_failure "MCP RAG endpoint is not accessible"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Test tool discovery
test_tool_discovery() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log "Testing RAG tool discovery..."

    # Send tools/list request
    local response
    response=$(curl -s -k -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/list","id":"1"}' \
        "https://${MCP_HOST}:${MCP_PORT}/mcp/rag")

    log_verbose "Response: $response"

    # Check if response contains tools
    if echo "$response" | grep -q '"tools"'; then
        log_success "RAG tool discovery successful"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_failure "RAG tool discovery failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Test specific RAG tools
test_rag_tools() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log "Testing RAG tool descriptions..."

    # Test rag.admin.stats tool description
    local response
    response=$(curl -s -k -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/describe","params":{"name":"rag.admin.stats"},"id":"1"}' \
        "https://${MCP_HOST}:${MCP_PORT}/mcp/rag")

    log_verbose "Response: $response"

    if echo "$response" | grep -q '"name":"rag.admin.stats"'; then
        log_success "RAG tool descriptions working"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_failure "RAG tool descriptions failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Test RAG admin stats
test_rag_admin_stats() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log "Testing RAG admin stats..."

    # Test rag.admin.stats tool call
    local response
    response=$(curl -s -k -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.admin.stats"},"id":"1"}' \
        "https://${MCP_HOST}:${MCP_PORT}/mcp/rag")

    log_verbose "Response: $response"

    if echo "$response" | grep -q '"sources"'; then
        log_success "RAG admin stats working"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_failure "RAG admin stats failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Main test execution
main() {
    log "Starting RAG functionality tests..."
    log "MCP Host: ${MCP_HOST}:${MCP_PORT}"
    log ""

    # Run tests
    test_mcp_connectivity
    test_tool_discovery
    test_rag_tools
    test_rag_admin_stats

    # Summary
    log ""
    log "Test Summary:"
    log "  Total tests: ${TOTAL_TESTS}"
    log "  Passed: ${PASSED_TESTS}"
    log "  Failed: ${FAILED_TESTS}"

    if [ $FAILED_TESTS -eq 0 ]; then
        log_success "All tests passed!"
        exit 0
    else
        log_failure "Some tests failed!"
        exit 1
    fi
}

# Run main function
main "$@"