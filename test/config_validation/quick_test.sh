#!/bin/bash

# Quick Test Script for Configuration Validation
# This script quickly tests various configuration scenarios

# Configuration - use relative paths from script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR"
# Allow PROXYSQL_PATH to be overridden by environment variable
PROXYSQL_PATH="${PROXYSQL_PATH:-$SCRIPT_DIR/../../src/proxysql}"

echo "Quick Configuration Validation Tests"
echo "===================================="

# Change to test directory with error handling
cd "$TEST_DIR" || { echo "ERROR: Cannot change to test directory: $TEST_DIR"; exit 1; }

echo -e "\n1. Testing valid MySQL servers configuration..."
timeout 5s "$PROXYSQL_PATH" --validate-only "valid_mysql_servers.ini"
echo "Exit code: $?"

echo -e "\n2. Testing valid MySQL query rules configuration..."
timeout 5s "$PROXYSQL_PATH" --validate-only "valid_mysql_query_rules.ini"
echo "Exit code: $?"

echo -e "\n3. Testing valid PostgreSQL configuration..."
timeout 5s "$PROXYSQL_PATH" --validate-only "valid_postgresql.ini"
echo "Exit code: $?"

echo -e "\n4. Testing MySQL servers with typo..."
timeout 5s "$PROXYSQL_PATH" --validate-only "typo_mysql_servers.ini"
echo "Exit code: $?"

echo -e "\n5. Testing PostgreSQL servers with typo..."
timeout 5s "$PROXYSQL_PATH" --validate-only "typo_pgsql_servers.ini"
echo "Exit code: $?"

echo -e "\n6. Testing invalid field in MySQL servers..."
timeout 5s "$PROXYSQL_PATH" --validate-only "invalid_field_mysql_servers.ini"
echo "Exit code: $?"

echo -e "\n7. Testing invalid field in PostgreSQL users..."
timeout 5s "$PROXYSQL_PATH" --validate-only "invalid_pgsql_users.ini"
echo "Exit code: $?"

echo -e "\nAll quick tests completed!"
