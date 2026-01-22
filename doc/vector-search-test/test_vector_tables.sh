#!/bin/bash

# Vector Table Creation Testing Script
# Tests creation and verification of vector tables

set -e

echo "=== Vector Table Creation Testing ==="
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
    expected_pattern="$3"

    echo "Testing: $test_name"
    echo "Query: $sql_query"

    # Execute the query
    result=$(mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" -s -N -e "$sql_query" 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        # Check if result matches expected pattern
        if [ -n "$expected_pattern" ] && ! echo "$result" | grep -q "$expected_pattern"; then
            echo "❌ FAILED: $test_name - Pattern not matched"
            echo "EXPECTED: $expected_pattern"
            echo "RESULT: $result"
            ((FAILED++))
        else
            echo "✅ SUCCESS: $test_name"
            echo "Result: $result"
            ((PASSED++))
        fi
    else
        echo "❌ FAILED: $test_name - Query execution error"
        echo "ERROR: $result"
        ((FAILED++))
    fi

    echo "----------------------------------------"
    echo ""
}

# Test 1: Create embeddings table
execute_test "Create embeddings table" "
CREATE VIRTUAL TABLE IF NOT EXISTS embeddings USING vec0(
    vector float[128]
);
" ""

# Test 2: Create documents table
execute_test "Create documents table" "
CREATE VIRTUAL TABLE IF NOT EXISTS documents USING vec0(
    embedding float[128]
);
" ""

# Test 3: Create test_vectors table
execute_test "Create test_vectors table" "
CREATE VIRTUAL TABLE IF NOT EXISTS test_vectors USING vec0(
    features float[256]
);
" ""

# Test 4: Verify table creation
execute_test "Verify vector tables" "
SELECT name
FROM sqlite_master
WHERE type='table' AND (name LIKE '%embedding%' OR name LIKE '%document%' OR name LIKE '%vector%')
ORDER BY name;
" "embeddings"

# Summary
echo "=== Test Summary ==="
echo "Total tests: $((PASSED + FAILED))"
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -eq 0 ]; then
    echo "🎉 All vector table tests passed!"
    exit 0
else
    echo "❌ $FAILED tests failed!"
    exit 1
fi