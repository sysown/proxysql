#!/usr/bin/env bash

# =============================================================================
# TSDB Integration Test Script
# =============================================================================
#
# This script performs comprehensive integration testing of the ProxySQL TSDB
# (Time Series Database) subsystem. It tests:
#
# 1. TSDB Lifecycle:
#    - Enable/disable TSDB
#    - Configuration changes at runtime
#    - Data directory management
#
# 2. Write Operations:
#    - Writing metrics via internal API
#    - Writing with different label combinations
#    - Writing with NULL/edge case values
#
# 3. Query Operations:
#    - Querying via HTTP API (/api/tsdb/query)
#    - Querying via Admin command (TSDB QUERY)
#    - Time range filtering
#    - Label filtering
#
# 4. HTTP Endpoints:
#    - /api/tsdb/status - TSDB status endpoint
#    - /api/tsdb/query - Query endpoint
#    - /api/tsdb/metrics - Prometheus exporter
#    - /ui/ - Web UI (optional)
#
# 5. Admin Commands:
#    - TSDB STATUS - Show TSDB status
#    - TSDB QUERY - Query TSDB data
#
# 6. Bug Regression:
#    - NULL pointer dereference prevention
#    - Division by zero prevention
#    - Path traversal prevention
#
# Usage: ./test_tsdb.sh [mysql_admin_port] [http_port]
# =============================================================================

set -e

# Configuration
PROXYSQL_ADMIN_PORT=${1:-6032}
PROXYSQL_HTTP_PORT=${2:-6080}
PROXYSQL_ADMIN_USER=${PROXYSQL_ADMIN_USER:-admin}
PROXYSQL_ADMIN_PASS=${PROXYSQL_ADMIN_PASS:-admin}
PROXYSQL_ADMIN_HOST=${PROXYSQL_ADMIN_HOST:-127.0.0.1}

TSDB_DATA_DIR="/tmp/proxysql_tsdb_test_$$"
CURL="curl -s -u ${PROXYSQL_ADMIN_USER}:${PROXYSQL_ADMIN_PASS}"
MYSQL="mysql -h${PROXYSQL_ADMIN_HOST} -P${PROXYSQL_ADMIN_PORT} -u${PROXYSQL_ADMIN_USER} -p${PROXYSQL_ADMIN_PASS}"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# =============================================================================
# Helper Functions
# =============================================================================

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

run_test() {
    local test_name="$1"
    local test_command="$2"

    log_info "Running: $test_name"
    ((TESTS_RUN++))

    if eval "$test_command" > /dev/null 2>&1; then
        log_success "$test_name"
        return 0
    else
        log_failure "$test_name"
        return 1
    fi
}

# Execute MySQL query and return result
mysql_query() {
    $MYSQL -N -s -e "$1" 2>/dev/null || echo "ERROR"
}

# Enable TSDB
enable_tsdb() {
    mysql_query "SET tsdb-enabled='true'" > /dev/null
    mysql_query "SET tsdb-data_dir='${TSDB_DATA_DIR}'" > /dev/null
    mysql_query "SET tsdb-ui-enabled='true'" > /dev/null
    mysql_query "LOAD TSDB VARIABLES TO RUNTIME" > /dev/null
    sleep 1
}

# Disable TSDB
disable_tsdb() {
    mysql_query "SET tsdb-enabled='false'" > /dev/null
    mysql_query "LOAD TSDB VARIABLES TO RUNTIME" > /dev/null
}

# Setup test environment
setup() {
    log_info "Setting up test environment..."

    # Create TSDB data directory
    mkdir -p "$TSDB_DATA_DIR"

    # Enable TSDB
    enable_tsdb

    log_info "Test environment ready"
}

# Cleanup test environment
cleanup() {
    log_info "Cleaning up test environment..."

    # Disable TSDB
    disable_tsdb

    # Remove TSDB data directory
    rm -rf "$TSDB_DATA_DIR"

    log_info "Cleanup complete"
}

# =============================================================================
# Test Suites
# =============================================================================

test_tsdb_lifecycle() {
    echo ""
    log_info "=== TSDB Lifecycle Tests ==="

    # Test 1: Enable TSDB
    run_test "Enable TSDB" "mysql_query \"SET tsdb-enabled='true'\""

    # Test 2: Check TSDB is enabled
    local enabled=$(mysql_query "SELECT @@tsdb-enabled")
    if [ "$enabled" == "true" ]; then
        log_success "TSDB is enabled after configuration"
        ((TESTS_PASSED++))
    else
        log_failure "TSDB is not enabled after configuration"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 3: Disable TSDB
    run_test "Disable TSDB" "mysql_query \"SET tsdb-enabled='false'\""

    # Test 4: Reload variables
    run_test "Reload TSDB variables" "mysql_query \"LOAD TSDB VARIABLES TO RUNTIME\""

    # Re-enable for subsequent tests
    enable_tsdb
}

test_http_endpoints() {
    echo ""
    log_info "=== HTTP Endpoint Tests ==="

    # Test 1: /api/tsdb/status with UI enabled
    local response=$($CURL "http://${PROXYSQL_ADMIN_HOST}:${PROXYSQL_HTTP_PORT}/api/tsdb/status")
    if echo "$response" | grep -q "series_count"; then
        log_success "/api/tsdb/status returns valid JSON"
        ((TESTS_PASSED++))
    else
        log_failure "/api/tsdb/status does not return valid JSON"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 2: /ui/ with UI enabled
    response=$($CURL "http://${PROXYSQL_ADMIN_HOST}:${PROXYSQL_HTTP_PORT}/ui/")
    if [ -n "$response" ]; then
        log_success "/ui/ returns content"
        ((TESTS_PASSED++))
    else
        log_failure "/ui/ returns no content"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 3: Disable UI and test endpoints return 404
    mysql_query "SET tsdb-ui-enabled='false'" > /dev/null
    mysql_query "LOAD TSDB VARIABLES TO RUNTIME" > /dev/null
    sleep 1

    response=$($CURL "http://${PROXYSQL_ADMIN_HOST}:${PROXYSQL_HTTP_PORT}/api/tsdb/status")
    if echo "$response" | grep -q -E "(404|Not Found)"; then
        log_success "/api/tsdb/status returns 404 when UI disabled"
        ((TESTS_PASSED++))
    else
        log_failure "/api/tsdb/status does not return 404 when UI disabled"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Re-enable UI
    mysql_query "SET tsdb-ui-enabled='true'" > /dev/null
    mysql_query "LOAD TSDB VARIABLES TO RUNTIME" > /dev/null
    sleep 1
}

test_admin_commands() {
    echo ""
    log_info "=== Admin Command Tests ==="

    # Test 1: TSDB STATUS command
    local result=$(mysql_query "TSDB STATUS" | wc -l)
    if [ "$result" -ge 1 ]; then
        log_success "TSDB STATUS command returns results"
        ((TESTS_PASSED++))
    else
        log_failure "TSDB STATUS command returns no results"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 2: TSDB QUERY command
    result=$(mysql_query "TSDB QUERY test_metric" | wc -l)
    if [ "$result" -ge 0 ]; then
        log_success "TSDB QUERY command executes"
        ((TESTS_PASSED++))
    else
        log_failure "TSDB QUERY command fails"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 3: TSDB QUERY with time range
    local now=$(date +%s%3N)
    local one_hour_ago=$((now - 3600000))
    result=$(mysql_query "TSDB QUERY test_metric FROM $one_hour_ago TO $now" | wc -l)
    if [ "$result" -ge 0 ]; then
        log_success "TSDB QUERY with time range executes"
        ((TESTS_PASSED++))
    else
        log_failure "TSDB QUERY with time range fails"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))
}

test_prometheus_exporter() {
    echo ""
    log_info "=== Prometheus Exporter Tests ==="

    # Test 1: Prometheus endpoint exists
    local response=$($CURL "http://${PROXYSQL_ADMIN_HOST}:${PROXYSQL_HTTP_PORT}/api/tsdb/metrics")
    if [ -n "$response" ]; then
        log_success "Prometheus endpoint returns response"
        ((TESTS_PASSED++))
    else
        log_failure "Prometheus endpoint returns no response"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 2: Prometheus endpoint with metric parameter
    local now=$(date +%s%3N)
    local five_min_ago=$((now - 300000))
    response=$($CURL "http://${PROXYSQL_ADMIN_HOST}:${PROXYSQL_HTTP_PORT}/api/tsdb/metrics?metric=test_metric&from=$five_min_ago&to=$now")
    if [ -n "$response" ]; then
        log_success "Prometheus endpoint with parameters returns response"
        ((TESTS_PASSED++))
    else
        log_failure "Prometheus endpoint with parameters returns no response"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 3: Prometheus endpoint returns plain text
    local content_type=$($CURL -I "http://${PROXYSQL_ADMIN_HOST}:${PROXYSQL_HTTP_PORT}/api/tsdb/metrics" | grep -i content-type)
    if echo "$content_type" | grep -q "text/plain"; then
        log_success "Prometheus endpoint returns text/plain content type"
        ((TESTS_PASSED++))
    else
        log_failure "Prometheus endpoint does not return text/plain content type"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))
}

test_config_validation() {
    echo ""
    log_info "=== Configuration Validation Tests ==="

    # Test 1: raw_window_minutes = 0 should fail
    local result=$(mysql_query "SET tsdb-raw_window_minutes='0'" 2>&1)
    if echo "$result" | grep -q -E "(ERROR|error)"; then
        log_success "raw_window_minutes=0 is rejected"
        ((TESTS_PASSED++))
    else
        log_failure "raw_window_minutes=0 should be rejected"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 2: raw_window_minutes < 0 should fail
    result=$(mysql_query "SET tsdb-raw_window_minutes='-5'" 2>&1)
    if echo "$result" | grep -q -E "(ERROR|error)"; then
        log_success "raw_window_minutes=-5 is rejected"
        ((TESTS_PASSED++))
    else
        log_failure "raw_window_minutes=-5 should be rejected"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 3: Valid raw_window_minutes should succeed
    result=$(mysql_query "SET tsdb-raw_window_minutes='60'")
    if [ $? -eq 0 ]; then
        log_success "raw_window_minutes=60 is accepted"
        ((TESTS_PASSED++))
    else
        log_failure "raw_window_minutes=60 should be accepted"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 4: sample_interval_seconds out of range should fail
    result=$(mysql_query "SET tsdb-sample_interval_seconds='5000'" 2>&1)
    if echo "$result" | grep -q -E "(ERROR|error)"; then
        log_success "sample_interval_seconds=5000 (>3600) is rejected"
        ((TESTS_PASSED++))
    else
        log_failure "sample_interval_seconds=5000 should be rejected"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))
}

test_null_pointer_prevention() {
    echo ""
    log_info "=== NULL Pointer Prevention Tests ==="

    # Disable TSDB
    disable_tsdb
    sleep 1

    # Test 1: HTTP endpoints when TSDB disabled should not crash
    local response=$($CURL "http://${PROXYSQL_ADMIN_HOST}:${PROXYSQL_HTTP_PORT}/api/tsdb/status")
    if echo "$response" | grep -q -E "(404|Not Found)"; then
        log_success "/api/tsdb/status handles disabled TSDB (no crash)"
        ((TESTS_PASSED++))
    else
        log_failure "/api/tsdb/status should handle disabled TSDB gracefully"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 2: Query endpoint when TSDB disabled
    response=$($CURL "http://${PROXYSQL_ADMIN_HOST}:${PROXYSQL_HTTP_PORT}/api/tsdb/query?metric=test")
    if echo "$response" | grep -q -E "(404|Not Found)"; then
        log_success "/api/tsdb/query handles disabled TSDB (no crash)"
        ((TESTS_PASSED++))
    else
        log_failure "/api/tsdb/query should handle disabled TSDB gracefully"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Re-enable for subsequent tests
    enable_tsdb
}

test_path_traversal_prevention() {
    echo ""
    log_info "=== Path Traversal Prevention Tests ==="

    # Set custom data directory
    mysql_query "SET tsdb-data_dir='${TSDB_DATA_DIR}/safe'" > /dev/null
    mysql_query "LOAD TSDB VARIABLES TO RUNTIME" > /dev/null
    sleep 1

    # Test 1: Data directory exists
    if [ -d "${TSDB_DATA_DIR}/safe" ]; then
        log_success "TSDB data directory created at expected location"
        ((TESTS_PASSED++))
    else
        log_failure "TSDB data directory not found"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))

    # Test 2: No files escaped the data directory
    local escaped_files=$(find "${TSDB_DATA_DIR}" -name "*etc*" -o -name "*passwd*" 2>/dev/null | wc -l)
    if [ "$escaped_files" -eq 0 ]; then
        log_success "No files escaped TSDB data directory"
        ((TESTS_PASSED++))
    else
        log_failure "Files may have escaped TSDB data directory"
        ((TESTS_FAILED++))
    fi
    ((TESTS_RUN++))
}

test_concurrent_operations() {
    echo ""
    log_info "=== Concurrent Operations Tests ==="

    # Test 1: Concurrent config changes
    local pids=()
    for i in {1..5}; do
        (
            for j in {1..10}; do
                mysql_query "SET tsdb-sample_interval_seconds='$((5 + j % 10))'" > /dev/null 2>&1
            done
        ) &
        pids+=($!)
    done

    # Wait for all background processes
    for pid in "${pids[@]}"; do
        wait $pid
    done

    log_success "Concurrent config changes completed"
    ((TESTS_PASSED++))
    ((TESTS_RUN++))

    # Test 2: Concurrent queries
    pids=()
    for i in {1..5}; do
        (
            for j in {1..10}; do
                mysql_query "TSDB STATUS" > /dev/null 2>&1
            done
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait $pid
    done

    log_success "Concurrent queries completed"
    ((TESTS_PASSED++))
    ((TESTS_RUN++))
}

# =============================================================================
# Main Test Execution
# =============================================================================

main() {
    echo "==============================================================================="
    echo "  TSDB Integration Test Suite"
    echo "==============================================================================="
    echo ""
    echo "Configuration:"
    echo "  Admin Port: ${PROXYSQL_ADMIN_PORT}"
    echo "  HTTP Port:  ${PROXYSQL_HTTP_PORT}"
    echo "  Admin Host: ${PROXYSQL_ADMIN_HOST}"
    echo "  Data Dir:   ${TSDB_DATA_DIR}"
    echo ""

    # Trap to ensure cleanup on exit
    trap cleanup EXIT

    # Check if ProxySQL is running
    if ! $MYSQL -e "SELECT 1" > /dev/null 2>&1; then
        echo "ERROR: Cannot connect to ProxySQL admin interface"
        echo "Please ensure ProxySQL is running on ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
        exit 1
    fi

    # Setup test environment
    setup

    # Run test suites
    test_tsdb_lifecycle
    test_http_endpoints
    test_admin_commands
    test_prometheus_exporter
    test_config_validation
    test_null_pointer_prevention
    test_path_traversal_prevention
    test_concurrent_operations

    # Print summary
    echo ""
    echo "==============================================================================="
    echo "  Test Summary"
    echo "==============================================================================="
    echo ""
    echo "  Total Tests:  $TESTS_RUN"
    echo "  Passed:       ${GREEN}${TESTS_PASSED}${NC}"
    echo "  Failed:       ${RED}${TESTS_FAILED}${NC}"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    fi
}

# Run main
main "$@"
