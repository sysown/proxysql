#!/bin/bash

# Comprehensive Test Script for --strict Flag Implementation
# This script tests the ProxySQL configuration validation framework with --strict flag

set -e

echo "========================================"
echo "ProxySQL --strict Flag Validation Tests"
echo "========================================"

# Configuration
PROXYSQL_PATH="/home/rene/proxysql_5263/src/proxysql"
TEST_DIR="/home/rene/proxysql_5263/test/config_validation"
LOG_DIR="/tmp/strict_mode_tests"
RESULTS_FILE="$LOG_DIR/strict_test_results.txt"

# Create log directory
mkdir -p "$LOG_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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

print_subheader() {
    echo -e "\n${CYAN}--- $1 ---${NC}"
}

# Function to run a test
run_test() {
    local test_name="$1"
    local config_file="$2"
    local cli_args="$3"
    local expected_exit_code="$4"
    local should_contain="$5"
    local should_not_contain="$6"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    local test_output="$LOG_DIR/${test_name// /_}.log"

    echo -e "\n${YELLOW}Test $TOTAL_TESTS: $test_name${NC}"
    echo "Config: $config_file"
    echo "Args: $cli_args"
    echo "Expected exit code: $expected_exit_code"

    # Run the test
    cd "$TEST_DIR"
    timeout 10s "$PROXYSQL_PATH" $cli_args "$config_file" > "$test_output" 2>&1
    local exit_code=$?

    # Check exit code
    local exit_passed=0
    if [ $exit_code -eq $expected_exit_code ]; then
        exit_passed=1
    fi

    # Check output contents if specified
    local content_passed=1
    if [ -n "$should_contain" ]; then
        if ! grep -q "$should_contain" "$test_output"; then
            content_passed=0
            echo -e "${RED}  ✗ Output missing expected string: $should_contain${NC}"
        fi
    fi

    if [ -n "$should_not_contain" ]; then
        if grep -q "$should_not_contain" "$test_output"; then
            content_passed=0
            echo -e "${RED}  ✗ Output contains unexpected string: $should_not_contain${NC}"
        fi
    fi

    # Check if the test passed
    if [ $exit_passed -eq 1 ] && [ $content_passed -eq 1 ]; then
        echo -e "${GREEN}  ✓ PASS${NC}"
        echo "✓ $test_name" >> "$RESULTS_FILE"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "${RED}  ✗ FAIL${NC}"
        echo "  Expected exit code: $expected_exit_code, Got: $exit_code"
        if [ -s "$test_output" ]; then
            echo -e "${RED}  Output:${NC}"
            head -20 "$test_output" | sed 's/^/    /'
        fi
        echo "✗ $test_name" >> "$RESULTS_FILE"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Function to run verbose test (shows output)
run_verbose_test() {
    local test_name="$1"
    local config_file="$2"
    local cli_args="$3"

    echo -e "\n${MAGENTA}Verbose Test: $test_name${NC}"
    echo "Config: $config_file"
    echo "Args: $cli_args"
    echo "Output:"
    echo "----------------------------------------"

    cd "$TEST_DIR"
    timeout 10s "$PROXYSQL_PATH" $cli_args "$config_file" 2>&1 || true
    local exit_code=$?

    echo "----------------------------------------"
    echo "Exit code: $exit_code"
}

# Main test execution
main() {
    print_header "Starting --strict Flag Validation Tests"

    # Check if proxysql binary exists
    if [ ! -f "$PROXYSQL_PATH" ]; then
        echo -e "${RED}Error: ProxySQL binary not found at $PROXYSQL_PATH${NC}"
        echo "Please build ProxySQL first"
        exit 1
    fi

    echo "ProxySQL binary: $PROXYSQL_PATH"
    echo "Test directory: $TEST_DIR"

    # Clear previous results
    > "$RESULTS_FILE"

    # ====================================================================
    # Test Group 1: CLI Alias Tests
    # ====================================================================
    print_header "Test Group 1: CLI Aliases"

    print_subheader "Testing --validate-config alias (valid config)"
    run_test \
        "CLI Alias: --validate-config with valid config" \
        "valid_mysql_servers.ini" \
        "--validate-config" \
        0 \
        "Configuration validation passed" \
        "ERROR"

    print_subheader "Testing --dry-run alias (valid config)"
    run_test \
        "CLI Alias: --dry-run with valid config" \
        "valid_mysql_servers.ini" \
        "--dry-run" \
        0 \
        "Configuration validation passed" \
        "ERROR"

    print_subheader "Testing --validate-config alias (invalid config)"
    run_test \
        "CLI Alias: --validate-config with typo" \
        "typo_mysql_servers.ini" \
        "--validate-config" \
        1 \
        "ERROR" \
        "Configuration validation passed"

    # ====================================================================
    # Test Group 2: Non-Strict Mode (Default Behavior)
    # ====================================================================
    print_header "Test Group 2: Non-Strict Mode (Default Warnings)"

    print_subheader "Non-strict: Valid config passes"
    run_test \
        "Non-Strict: Valid MySQL config" \
        "valid_mysql_servers.ini" \
        "" \
        0 \
        "" \
        "ERROR"

    print_subheader "Non-strict: Typo shows warning but passes"
    run_test \
        "Non-Strict: Typo shows warning" \
        "typo_mysql_servers.ini" \
        "" \
        0 \
        "WARNING" \
        "FATAL"

    print_subheader "Non-strict: Invalid regex shows warning"
    run_test \
        "Non-Strict: Invalid regex warning" \
        "invalid_regex_patterns.ini" \
        "" \
        0 \
        "WARNING" \
        "FATAL"

    print_subheader "Non-strict: Invalid value range warning"
    run_test \
        "Non-Strict: Invalid value warning" \
        "invalid_value_ranges.ini" \
        "" \
        0 \
        "WARNING" \
        "FATAL"

    # ====================================================================
    # Test Group 3: Strict Mode (--strict flag)
    # ====================================================================
    print_header "Test Group 3: Strict Mode (Fatal Errors)"

    print_subheader "Strict: Valid config passes"
    run_test \
        "Strict: Valid MySQL config" \
        "valid_mysql_servers.ini" \
        "--strict" \
        0 \
        "" \
        "ERROR"

    print_subheader "Strict: Typo causes fatal error"
    run_test \
        "Strict: Typo causes fatal error" \
        "typo_mysql_servers.ini" \
        "--strict" \
        1 \
        "FATAL" \
        "Configuration validation passed"

    print_subheader "Strict: Unknown field causes fatal error"
    run_test \
        "Strict: Unknown field fatal error" \
        "invalid_field_mysql_servers.ini" \
        "--strict" \
        1 \
        "FATAL" \
        "Configuration validation passed"

    print_subheader "Strict: Invalid regex causes fatal error"
    run_test \
        "Strict: Invalid regex fatal error" \
        "invalid_regex_patterns.ini" \
        "--strict" \
        1 \
        "FATAL" \
        "Configuration validation passed"

    print_subheader "Strict: Invalid value causes fatal error"
    run_test \
        "Strict: Invalid value fatal error" \
        "invalid_value_ranges.ini" \
        "--strict" \
        1 \
        "FATAL" \
        "Configuration validation passed"

    # ====================================================================
    # Test Group 4: Combined Flag Tests
    # ====================================================================
    print_header "Test Group 4: Combined Flag Tests"

    print_subheader "--strict + --validate-config (valid)"
    run_test \
        "Combined: --strict + --validate-config (valid)" \
        "valid_mysql_servers.ini" \
        "--strict --validate-config" \
        0 \
        "Configuration validation passed" \
        "ERROR"

    print_subheader "--strict + --validate-config (invalid)"
    run_test \
        "Combined: --strict + --validate-config (invalid)" \
        "typo_mysql_servers.ini" \
        "--strict --validate-config" \
        1 \
        "FATAL" \
        "Configuration validation passed"

    print_subheader "--strict + --dry-run (valid)"
    run_test \
        "Combined: --strict + --dry-run (valid)" \
        "valid_postgresql.ini" \
        "--strict --dry-run" \
        0 \
        "Configuration validation passed" \
        "ERROR"

    print_subheader "--strict + --dry-run (invalid)"
    run_test \
        "Combined: --strict + --dry-run (invalid)" \
        "typo_pgsql_servers.ini" \
        "--strict --dry-run" \
        1 \
        "FATAL" \
        "Configuration validation passed"

    # ====================================================================
    # Test Group 5: Suggestion Detection Tests
    # ====================================================================
    print_header "Test Group 5: Typo Suggestion Detection"

    print_subheader "Suggestion: 'adddress' -> 'address'"
    run_test \
        "Suggestion: Typo in address field" \
        "typo_mysql_servers.ini" \
        "--validate-config" \
        1 \
        "Did you mean" \
        "Configuration validation passed"

    print_subheader "Suggestion: 'mathc_pattern' -> 'match_pattern'"
    run_test \
        "Suggestion: Typo in match_pattern field" \
        "query_rule_with_typo.ini" \
        "--validate-config" \
        1 \
        "Did you mean" \
        "Configuration validation passed"

    # ====================================================================
    # Test Group 6: Module-Dependent Configuration Tests
    # ====================================================================
    print_header "Test Group 6: Module-Dependent Configuration"

    print_subheader "Module config without module loaded (should pass)"
    run_test \
        "Module Config: SQLite3 settings without module" \
        "module_dependent_config.ini" \
        "--validate-config" \
        0 \
        "" \
        "ERROR"

    print_subheader "Module config in strict mode without module"
    run_test \
        "Module Config: SQLite3 in strict mode" \
        "module_dependent_config.ini" \
        "--strict --validate-config" \
        0 \
        "" \
        "FATAL"

    # ====================================================================
    # Test Group 7: Multiple Configuration Sections
    # ====================================================================
    print_header "Test Group 7: Multi-Section Configuration"

    print_subheader "Mixed valid/invalid (should fail)"
    run_test \
        "Multi-Section: Mixed valid/invalid" \
        "mixed_valid_invalid.ini" \
        "--validate-config" \
        1 \
        "ERROR" \
        "Configuration validation passed"

    print_subheader "All valid sections"
    run_test \
        "Multi-Section: All valid" \
        "valid_mysql_query_rules.ini" \
        "--validate-config" \
        0 \
        "Configuration validation passed" \
        "ERROR"

    # ====================================================================
    # Test Group 8: PostgreSQL Configuration Tests
    # ====================================================================
    print_header "Test Group 8: PostgreSQL Configuration"

    print_subheader "Valid PostgreSQL config"
    run_test \
        "PostgreSQL: Valid config" \
        "valid_postgresql.ini" \
        "--validate-config" \
        0 \
        "Configuration validation passed" \
        "ERROR"

    print_subheader "PostgreSQL with typo in strict mode"
    run_test \
        "PostgreSQL: Typo in strict mode" \
        "typo_pgsql_servers.ini" \
        "--strict --validate-config" \
        1 \
        "FATAL" \
        "Configuration validation passed"

    print_subheader "PostgreSQL users with invalid field"
    run_test \
        "PostgreSQL: Invalid users field" \
        "invalid_pgsql_users.ini" \
        "--validate-config" \
        1 \
        "ERROR" \
        "Configuration validation passed"

    # ====================================================================
    # Test Summary
    # ====================================================================
    print_header "Test Summary"

    echo -e "Total Tests: $TOTAL_TESTS"
    echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"

    # Test percentage
    if [ $TOTAL_TESTS -gt 0 ]; then
        local percentage=$((PASSED_TESTS * 100 / TOTAL_TESTS))
        local percentage_color="$GREEN"
        if [ $percentage -lt 80 ]; then
            percentage_color="$YELLOW"
        fi
        if [ $percentage -lt 50 ]; then
            percentage_color="$RED"
        fi
        echo -e "Success Rate: ${percentage_color}$percentage%${NC}"
    fi

    # Show detailed results
    echo -e "\n${BLUE}Detailed Results:${NC}"
    echo "========================================"
    cat "$RESULTS_FILE"

    # ====================================================================
    # Verbose Tests - Show Actual Output for Key Scenarios
    # ====================================================================
    print_header "Verbose Output Examples"

    echo -e "\n${MAGENTA}1. Valid Configuration with --validate-config:${NC}"
    run_verbose_test "Valid config" "valid_mysql_servers.ini" "--validate-config"

    echo -e "\n${MAGENTA}2. Typo Detection with Suggestion:${NC}"
    run_verbose_test "Typo detection" "typo_mysql_servers.ini" "--validate-config"

    echo -e "\n${MAGENTA}3. Non-Strict Mode (Warning only):${NC}"
    run_verbose_test "Non-strict mode" "typo_mysql_servers.ini" ""

    echo -e "\n${MAGENTA}4. Strict Mode (Fatal Error):${NC}"
    run_verbose_test "Strict mode" "typo_mysql_servers.ini" "--strict --validate-config"

    echo -e "\n${MAGENTA}5. Invalid Regex Pattern:${NC}"
    run_verbose_test "Invalid regex" "invalid_regex_patterns.ini" "--strict --validate-config"

    # ====================================================================
    # Final Status
    # ====================================================================
    echo -e "\n${BLUE}Test logs saved to: $LOG_DIR${NC}"

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
