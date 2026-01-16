#!/bin/bash

# Quick Test Script for Configuration Validation
# This script quickly tests various configuration scenarios

PROXYSQL_PATH="/home/rene/proxysql_5263/src/proxysql"
TEST_DIR="/home/rene/proxysql_5263/test/config_validation"

echo "Quick Configuration Validation Tests"
echo "===================================="

# Change to test directory
cd "$TEST_DIR"

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