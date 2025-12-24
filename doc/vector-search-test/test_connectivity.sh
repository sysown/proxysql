#!/bin/bash

# Vector Search Connectivity Testing Script
# Tests basic connectivity to ProxySQL SQLite3 server

set -e

echo "=== Vector Search Connectivity Testing ==="
echo "Starting at: $(date)"
echo ""

# Configuration
PROXYSQL_HOST="127.0.0.1"
PROXYSQL_PORT="6030"
MYSQL_USER="root"
MYSQL_PASS="root"

# Test results tracking
PASSED=0
FAILED=0

# Function to execute MySQL query and handle results
execute_test() {
    local test_name="$1"
    local sql_query="$2"
    local expected="$3"

    echo "Testing: $test_name"
    echo "Query: $sql_query"

    # Execute query and capture results
    result=$(mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" -s -N -e "$sql_query" 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo "✅ SUCCESS: $test_name"
        echo "Result: $result"
        ((PASSED++))
    else
        echo "❌ FAILED: $test_name"
        echo "Error: $result"
        ((FAILED++))
    fi

    echo "----------------------------------------"
    echo ""
}

# Test 1: Basic connectivity
execute_test "Basic Connectivity" "SELECT 1 as test;" "1"

# Test 2: Database listing
execute_test "Database Listing" "SHOW DATABASES;" "main"

# Test 3: Current database
execute_test "Current Database" "SELECT database();" "main"

# Summary
echo "=== Test Summary ==="
echo "Total tests: $((PASSED + FAILED))"
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -eq 0 ]; then
    echo "🎉 All connectivity tests passed!"
    exit 0
else
    echo "❌ $FAILED tests failed!"
    exit 1
fi