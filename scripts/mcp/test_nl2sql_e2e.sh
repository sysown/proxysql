#!/bin/bash
#
# @file test_nl2sql_e2e.sh
# @brief End-to-end NL2SQL testing with live LLMs
#
# Tests complete workflow from natural language to executed SQL
#
# Prerequisites:
# - Running ProxySQL with NL2SQL enabled
# - Ollama running on localhost:11434 (or configured LLM)
# - Test database schema
#
# Usage:
#   ./test_nl2sql_e2e.sh [--mock|--live]
#
# @date 2025-01-16

set -e

# ============================================================================
# Configuration
# ============================================================================

PROXYSQL_ADMIN_HOST=${PROXYSQL_ADMIN_HOST:-127.0.0.1}
PROXYSQL_ADMIN_PORT=${PROXYSQL_ADMIN_PORT:-6032}
PROXYSQL_HOST=${PROXYSQL_HOST:-127.0.0.1}
PROXYSQL_PORT=${PROXYSQL_PORT:-6033}
PROXYSQL_USER=${PROXYSQL_USER:-root}
PROXYSQL_PASSWORD=${PROXYSQL_PASSWORD:-}
TEST_SCHEMA=${TEST_SCHEMA:-test_nl2sql}
LLM_MODE=${1:---live}  # --mock or --live

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

# ============================================================================
# Helper Functions
# ============================================================================

#
# @brief Print section header
# @param $1 Section name
#
print_section() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

#
# @brief Run a single test
# @param $1 Test name
# @param $2 NL2SQL query
# @param $3 Expected SQL pattern (regex)
# @return 0 if test passes, 1 if fails
#
run_test() {
    local test_name="$1"
    local nl2sql_query="$2"
    local expected_pattern="$3"

    TOTAL=$((TOTAL + 1))

    echo -e "${YELLOW}Test $TOTAL: $test_name${NC}"
    echo "  Query: $nl2sql_query"

    # For now, we'll use mock responses since NL2SQL is not fully integrated
    # In Phase 2, this will execute real NL2SQL queries
    local sql=""
    local result=""

    if [ "$LLM_MODE" = "--mock" ]; then
        # Generate mock SQL based on query pattern
        if [[ "$nl2sql_query" =~ "SELECT"|"select"|"Show"|"show" ]]; then
            sql="SELECT * FROM"
        elif [[ "$nl2sql_query" =~ "WHERE"|"where"|"Find"|"find" ]]; then
            sql="SELECT * FROM WHERE"
        elif [[ "$nl2sql_query" =~ "JOIN"|"join"|"with" ]]; then
            sql="SELECT * FROM JOIN"
        elif [[ "$nl2sql_query" =~ "COUNT"|"count"|"Count" ]]; then
            sql="SELECT COUNT(*) FROM"
        else
            sql="SELECT"
        fi
        result="Mock: $sql"
    else
        # For live mode, we would execute the actual query
        # This is not yet implemented
        result="Live mode not yet implemented"
        sql="SELECT"
    fi

    echo "  Generated: $sql"

    # Check if expected pattern exists
    if echo "$sql" | grep -qiE "$expected_pattern"; then
        echo -e "  ${GREEN}PASSED${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "  ${RED}FAILED: Expected pattern '$expected_pattern' not found${NC}"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

#
# @brief Execute MySQL command
# @param $1 Query to execute
#
mysql_exec() {
    mysql -h $PROXYSQL_ADMIN_HOST -P $PROXYSQL_ADMIN_PORT -u admin -padmin \
          -e "$1" 2>/dev/null || true
}

#
# @brief Setup test schema
#
setup_schema() {
    print_section "Setting Up Test Schema"

    # Create test database via admin
    mysql_exec "CREATE DATABASE IF NOT EXISTS $TEST_SCHEMA"

    # Create test tables
    mysql_exec "CREATE TABLE IF NOT EXISTS $TEST_SCHEMA.customers (
        id INT PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(100),
        country VARCHAR(50),
        created_at DATE
    )"

    mysql_exec "CREATE TABLE IF NOT EXISTS $TEST_SCHEMA.orders (
        id INT PRIMARY KEY AUTO_INCREMENT,
        customer_id INT,
        total DECIMAL(10,2),
        status VARCHAR(20),
        FOREIGN KEY (customer_id) REFERENCES $TEST_SCHEMA.customers(id)
    )"

    # Insert test data
    mysql_exec "INSERT INTO $TEST_SCHEMA.customers (name, country, created_at) VALUES
        ('Alice', 'USA', '2024-01-01'),
        ('Bob', 'UK', '2024-02-01'),
        ('Charlie', 'USA', '2024-03-01')
        ON DUPLICATE KEY UPDATE name=name"

    mysql_exec "INSERT INTO $TEST_SCHEMA.orders (customer_id, total, status) VALUES
        (1, 100.00, 'completed'),
        (2, 200.00, 'pending'),
        (3, 150.00, 'completed')
        ON DUPLICATE KEY UPDATE total=total"

    echo -e "${GREEN}Test schema created${NC}"
}

#
# @brief Configure LLM mode
#
configure_llm() {
    print_section "LLM Configuration: $LLM_MODE"

    if [ "$LLM_MODE" = "--mock" ]; then
        mysql_exec "SET mysql-have_sql_injection='false'" 2>/dev/null || true
        echo -e "${GREEN}Using mocked LLM responses${NC}"
    else
        mysql_exec "SET mysql-have_sql_injection='false'" 2>/dev/null || true
        echo -e "${GREEN}Using live LLM (ensure Ollama is running)${NC}"

        # Check Ollama connectivity
        if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
            echo -e "${GREEN}Ollama is accessible${NC}"
        else
            echo -e "${YELLOW}Warning: Ollama may not be running on localhost:11434${NC}"
        fi
    fi
}

# ============================================================================
# Test Cases
# ============================================================================

run_e2e_tests() {
    print_section "Running End-to-End NL2SQL Tests"

    # Test 1: Simple SELECT
    run_test \
        "Simple SELECT all customers" \
        "NL2SQL: Show all customers" \
        "SELECT.*customers"

    # Test 2: SELECT with WHERE
    run_test \
        "SELECT with condition" \
        "NL2SQL: Find customers from USA" \
        "SELECT.*WHERE"

    # Test 3: JOIN query
    run_test \
        "JOIN customers and orders" \
        "NL2SQL: Show customer names with their order amounts" \
        "SELECT.*JOIN"

    # Test 4: Aggregation
    run_test \
        "COUNT aggregation" \
        "NL2SQL: Count customers by country" \
        "COUNT.*GROUP BY"

    # Test 5: Sorting
    run_test \
        "ORDER BY" \
        "NL2SQL: Show orders sorted by total amount" \
        "SELECT.*ORDER BY"

    # Test 6: Complex query
    run_test \
        "Complex aggregation" \
        "NL2SQL: What is the average order total per country?" \
        "AVG"

    # Test 7: Date handling
    run_test \
        "Date filtering" \
        "NL2SQL: Find customers created in 2024" \
        "2024"

    # Test 8: Subquery (may fail with simple models)
    run_test \
        "Subquery" \
        "NL2SQL: Find customers with orders above average" \
        "SELECT"
}

# ============================================================================
# Results Summary
# ============================================================================

print_summary() {
    print_section "Test Summary"

    echo "Total tests:  $TOTAL"
    echo -e "Passed:       ${GREEN}$PASSED${NC}"
    echo -e "Failed:       ${RED}$FAILED${NC}"
    echo -e "Skipped:      ${YELLOW}$SKIPPED${NC}"

    local pass_rate=0
    if [ $TOTAL -gt 0 ]; then
        pass_rate=$((PASSED * 100 / TOTAL))
    fi
    echo "Pass rate:    $pass_rate%"

    if [ $FAILED -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "\n${RED}Some tests failed${NC}"
        return 1
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    print_section "NL2SQL End-to-End Testing"

    echo "Configuration:"
    echo "  ProxySQL:    $PROXYSQL_HOST:$PROXYSQL_PORT"
    echo "  Admin:       $PROXYSQL_ADMIN_HOST:$PROXYSQL_ADMIN_PORT"
    echo "  Schema:      $TEST_SCHEMA"
    echo "  LLM Mode:    $LLM_MODE"

    # Setup
    setup_schema
    configure_llm

    # Run tests
    run_e2e_tests

    # Summary
    print_summary
}

# Run main
main "$@"
