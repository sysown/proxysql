#!/bin/bash
#
# TEMPLATE HEADER - Source mcp_test_helpers.sh
#

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the helper functions
if [ -f "${SCRIPT_DIR}/mcp_test_helpers.sh" ]; then
    source "${SCRIPT_DIR}/mcp_test_helpers.sh"
else
    echo "ERROR: mcp_test_helpers.sh not found at ${SCRIPT_DIR}"
    exit 1
fi

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

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
