#!/bin/bash

# Configuration Validation Test Script
# This script tests the ProxySQL configuration validation framework

set -e

echo "========================================"
echo "ProxySQL Configuration Validation Tests"
echo "========================================"

# Configuration
PROXYSQL_PATH="/home/rene/proxysql_5263/src/proxysql"
TEST_DIR="/home/rene/proxysql_5263/test/config_validation"
LOG_DIR="/tmp/config_validation_tests"
RESULTS_FILE="$LOG_DIR/test_results.txt"

# Create log directory
mkdir -p "$LOG_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Initialize results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to print test header
print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Function to run a test
run_test() {
    local test_name="$1"
    local config_file="$2"
    local expected_mode="$3"
    local expected_result="$4"
    local extra_args="$5"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    local test_output="$LOG_DIR/${test_name// /_}.log"

    echo -e "\n${YELLOW}Running Test: $test_name${NC}"
    echo "Config file: $config_file"
    echo "Expected: $expected_mode - $expected_result"

    # Run the test
    cd "$TEST_DIR"
    timeout 10s "$PROXYSQL_PATH" --validate-only $extra_args "$config_file" > "$test_output" 2>&1
    local exit_code=$?

    # Analyze results
    if [ $exit_code -eq 0 ]; then
        actual_result="PASSED"
    else
        actual_result="FAILED"
    fi

    # Check if the result matches expectation
    if [[ "$actual_result" == "$expected_result" ]]; then
        echo -e "${GREEN}✓ PASS: $test_name${NC}"
        echo "✓ $test_name" >> "$RESULTS_FILE"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL: $test_name${NC}"
        echo "Expected: $expected_result, Got: $actual_result" >> "$RESULTS_FILE"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Function to run verbose test (shows output)
run_verbose_test() {
    local test_name="$1"
    local config_file="$2"
    local expected_mode="$3"

    echo -e "\n${YELLOW}Verbose Test: $test_name${NC}"
    echo "Config file: $config_file"
    echo "Expected mode: $expected_mode"
    echo "Output:"
    echo "----------------------------------------"

    cd "$TEST_DIR"
    timeout 10s "$PROXYSQL_PATH" --validate-only "$config_file"
    local exit_code=$?

    echo "----------------------------------------"
    echo "Exit code: $exit_code"

    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✓ PASSED${NC}"
    else
        echo -e "${RED}✗ FAILED${NC}"
    fi
}

# Function to check if file exists
check_file_exists() {
    if [ ! -f "$1" ]; then
        echo -e "${RED}Error: Config file '$1' not found${NC}"
        exit 1
    fi
}

# Main test execution
main() {
    print_header "Starting Configuration Validation Tests"

    # Check if proxysql binary exists
    if [ ! -f "$PROXYSQL_PATH" ]; then
        echo -e "${RED}Error: ProxySQL binary not found at $PROXYSQL_PATH${NC}"
        echo "Please build ProxySQL first"
        exit 1
    fi

    echo "ProxySQL binary found at: $PROXYSQL_PATH"
    echo "Test directory: $TEST_DIR"

    # Clear previous results
    > "$RESULTS_FILE"

    # Test 1: Valid MySQL Servers configuration
    run_test "Valid MySQL Servers" "valid_mysql_servers.ini" "validate-only" "PASSED"

    # Test 2: Valid MySQL Query Rules configuration
    run_test "Valid MySQL Query Rules" "valid_mysql_query_rules.ini" "validate-only" "PASSED"

    # Test 3: Valid PostgreSQL configuration
    run_test "Valid PostgreSQL" "valid_postgresql.ini" "validate-only" "PASSED"

    # Test 4: MySQL Servers with typo (should fail but provide suggestion)
    run_test "MySQL Servers with Typo" "typo_mysql_servers.ini" "validate-only" "FAILED"

    # Test 5: MySQL Servers with invalid field (should fail)
    run_test "MySQL Servers with Invalid Field" "invalid_field_mysql_servers.ini" "validate-only" "FAILED"

    # Test 6: PostgreSQL Servers with typo (should fail but provide suggestion)
    run_test "PostgreSQL Servers with Typo" "typo_pgsql_servers.ini" "validate-only" "FAILED"

    # Test 7: MySQL Query Rules with typo (should fail but provide suggestion)
    run_test "MySQL Query Rules with Typo" "typo_mysql_query_rules.ini" "validate-only" "FAILED"

    # Test 8: PostgreSQL Users with invalid field (should fail)
    run_test "PostgreSQL Users with Invalid Field" "invalid_pgsql_users.ini" "validate-only" "FAILED"

    # Test 9: Mixed valid and invalid configurations (should fail)
    run_test "Mixed Valid/Invalid Configurations" "mixed_valid_invalid.ini" "validate-only" "FAILED"

    print_header "Test Summary"
    echo -e "Total Tests: $TOTAL_TESTS"
    echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"

    # Test percentage
    if [ $TOTAL_TESTS -gt 0 ]; then
        local percentage=$((PASSED_TESTS * 100 / TOTAL_TESTS))
        echo -e "Success Rate: ${GREEN}$percentage%${NC}"
    fi

    # Show detailed results
    echo -e "\n${BLUE}Detailed Results:${NC}"
    echo "========================================"
    cat "$RESULTS_FILE"

    # Run a few verbose tests to show the actual output
    print_header "Verbose Tests - Showing Actual Output"

    echo -e "\n${YELLOW}1. Valid MySQL Configuration:${NC}"
    cd "$TEST_DIR"
    timeout 10s "$PROXYSQL_PATH" --validate-only "valid_mysql_servers.ini" || echo "Timeout or error occurred"

    echo -e "\n${YELLOW}2. MySQL Servers with Typo:${NC}"
    cd "$TEST_DIR"
    timeout 10s "$PROXYSQL_PATH" --validate-only "typo_mysql_servers.ini" || echo "Timeout or error occurred"

    echo -e "\n${YELLOW}3. PostgreSQL Servers with Typo:${NC}"
    cd "$TEST_DIR"
    timeout 10s "$PROXYSQL_PATH" --validate-only "typo_pgsql_servers.ini" || echo "Timeout or error occurred"

    # Cleanup
    echo -e "\n${BLUE}Test logs saved to: $LOG_DIR${NC}"

    # Final status
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All tests passed!${NC}"
        exit 0
    else
        echo -e "\n${RED}❌ $FAILED_TESTS test(s) failed.${NC}"
        echo "Check the verbose output above and logs in $LOG_DIR for details."
        exit 1
    fi
}

# Run main function
main "$@"