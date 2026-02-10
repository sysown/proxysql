#!/usr/bin/env bash
#
# mcp_query_rules-t.sh - TAP Test for MCP Query Rules
#
# This script runs all MCP Query Rules test phases and outputs results in TAP format.
#

# change plan here, 0 means auto plan
PLAN=0
DONE=0
FAIL=0

trap fn_exit EXIT
trap fn_exit SIGINT

# Get the test directory
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_TESTS_DIR="${TEST_DIR}/mcp_rules_testing"
CONFIGURE_SCRIPT="${MCP_TESTS_DIR}/configure_mcp.sh"

# Colors (optional, for readability)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

fn_getenv () {
	source .env 2>/dev/null
	source $(basename $(dirname $0)).env 2>/dev/null
	source $(basename $0 | sed 's/.sh//').env 2>/dev/null
}

fn_plan () {
	PLAN=${1:-$PLAN}
	echo "msg: 1..${PLAN/#0/}"
}

fn_exit () {
	trap - EXIT
	trap - SIGINT
	if [[ $DONE -eq $PLAN ]] && [[ $FAIL -eq 0 ]]; then
		echo "msg: Test took $SECONDS sec"
		exit 0
	else
		echo "msg: plan was $PLAN - done $DONE"
		echo "msg: from $DONE done - $FAIL failed"
		echo "msg: Test took $SECONDS sec"
		exit 1
	fi
}

# Execute test script and capture result
fn_run_test () {
	local test_name="$1"
	local test_script="$2"

	DONE=$(( $DONE + 1 ))
	PLAN=$([[ $PLAN -lt $DONE ]] && echo $DONE || echo $PLAN)

	# Run the test script
	if bash "${test_script}"; then
		echo "msg: ok $DONE - $test_name"
	else
		echo "msg: not ok $DONE - $test_name"
		FAIL=$(( $FAIL + 1 ))
	fi
}

# Helper function to run mysql command with proper password handling
fn_mysql_exec () {
	local host="$1"
	local port="$2"
	local user="$3"
	local pass="$4"
	local query="$5"

	# Handle "none" as a special value meaning no password
	if [ -z "${pass}" ] || [ "${pass}" = "none" ]; then
		mysql -h "${host}" -P "${port}" -u "${user}" -e "${query}" 2>&1
	else
		mysql -h "${host}" -P "${port}" -u "${user}" -p"${pass}" -e "${query}" 2>&1
	fi
}

# Check configuration variables
fn_check_config () {
	DONE=$(( $DONE + 1 ))
	PLAN=$([[ $PLAN -lt $DONE ]] && echo $DONE || echo $PLAN)

	local errors=0
	local missing_vars=""
	local config_details=""

	# Check ProxySQL admin configuration
	local admin_user="${TAP_ADMINUSERNAME:-radmin}"
	local admin_pass="${TAP_ADMINPASSWORD:-radmin}"
	local admin_host="${TAP_ADMINHOST:-127.0.0.1}"
	local admin_port="${TAP_ADMINPORT:-6032}"

	if [ -z "${admin_user}" ]; then
		missing_vars="${missing_vars} TAP_ADMINUSERNAME"
		errors=$((errors + 1))
	fi

	if [ -z "${admin_pass}" ]; then
		missing_vars="${missing_vars} TAP_ADMINPASSWORD"
		errors=$((errors + 1))
	fi

	# Check MySQL backend configuration
	local mysql_host="${TAP_MYSQLHOST:-127.0.0.1}"
	local mysql_port="${TAP_MYSQLPORT:-3306}"
	local mysql_user="${TAP_MYSQLUSERNAME:-root}"
	local mysql_pass="${TAP_MYSQLPASSWORD:-none}"

	if [ -z "${mysql_host}" ]; then
		missing_vars="${missing_vars} TAP_MYSQLHOST"
		errors=$((errors + 1))
	fi

	if [ -z "${mysql_port}" ]; then
		missing_vars="${missing_vars} TAP_MYSQLPORT"
		errors=$((errors + 1))
	fi

	if [ -z "${mysql_user}" ]; then
		missing_vars="${missing_vars} TAP_MYSQLUSERNAME"
		errors=$((errors + 1))
	fi

	if [ -z "${mysql_pass}" ]; then
		missing_vars="${missing_vars} TAP_MYSQLPASSWORD"
		errors=$((errors + 1))
	fi

	# Build configuration details for logging
	config_details="ProxySQL Admin: ${admin_user}@${admin_host}:${admin_port} | MySQL Backend: ${mysql_user}@${mysql_host}:${mysql_port}"

	if [ $errors -gt 0 ]; then
		echo "msg: not ok $DONE - Configuration Check - Missing required variables:${missing_vars}"
		echo "msg: #   Config: ${config_details}"
		FAIL=$(( $FAIL + 1 ))
		return 1
	fi

	echo "msg: ok $DONE - Configuration Check - All required variables are set"
	echo "msg: #   Config: ${config_details}"
	return 0
}

# Check if ProxySQL admin is accessible
fn_check_proxysql_admin () {
	DONE=$(( $DONE + 1 ))
	PLAN=$([[ $PLAN -lt $DONE ]] && echo $DONE || echo $PLAN)

	local admin_host="${TAP_ADMINHOST:-127.0.0.1}"
	local admin_port="${TAP_ADMINPORT:-6032}"
	local admin_user="${TAP_ADMINUSERNAME:-radmin}"
	local admin_pass="${TAP_ADMINPASSWORD:-radmin}"

	echo "msg: #   Connecting to ProxySQL Admin: ${admin_user}@${admin_host}:${admin_port}"

	local output
	output=$(fn_mysql_exec "${admin_host}" "${admin_port}" "${admin_user}" "${admin_pass}" "SELECT 1" 2>&1)
	local result=$?

	if [ $result -eq 0 ]; then
		echo "msg: ok $DONE - ProxySQL Admin Connection - Connected successfully to ${admin_host}:${admin_port}"
		return 0
	else
		echo "msg: not ok $DONE - ProxySQL Admin Connection - Failed to connect to ${admin_user}@${admin_host}:${admin_port}"
		echo "msg: #   Error: ${output}"
		FAIL=$(( $FAIL + 1 ))
		return 1
	fi
}

# Check if MCP is configured and configure if needed
fn_check_configure_mcp () {
	DONE=$(( $DONE + 1 ))
	PLAN=$([[ $PLAN -lt $DONE ]] && echo $DONE || echo $PLAN)

	# Check if configure script exists
	if [ ! -f "${CONFIGURE_SCRIPT}" ]; then
		echo "msg: not ok $DONE - MCP Configuration - configure_mcp.sh not found at ${CONFIGURE_SCRIPT}"
		FAIL=$(( $FAIL + 1 ))
		return 1
	fi

	# Make sure it's executable
	chmod +x "${CONFIGURE_SCRIPT}"

	local admin_host="${TAP_ADMINHOST:-127.0.0.1}"
	local admin_port="${TAP_ADMINPORT:-6032}"
	local admin_user="${TAP_ADMINUSERNAME:-radmin}"
	local admin_pass="${TAP_ADMINPASSWORD:-radmin}"

	echo "msg: #   Checking MCP status via ProxySQL Admin..."

	# Check if MCP is already enabled
	local mcp_enabled
	mcp_enabled=$(fn_mysql_exec "${admin_host}" "${admin_port}" "${admin_user}" "${admin_pass}" \
		"SELECT variable_value FROM global_variables WHERE variable_name='mcp-enabled';" \
		2>/dev/null | tail -n 1)

	if [ "${mcp_enabled}" = "true" ]; then
		echo "msg: ok $DONE - MCP Configuration - Already enabled"
		echo "msg: #   MCP server at ${admin_host}:${TAP_MCPPORT:-6071}"
		return 0
	fi

	echo "msg: #   MCP not enabled, attempting to configure..."

	# Set environment variables for configure script
	export PROXYSQL_ADMIN_HOST="${admin_host}"
	export PROXYSQL_ADMIN_PORT="${admin_port}"
	export PROXYSQL_ADMIN_USER="${admin_user}"
	export PROXYSQL_ADMIN_PASSWORD="${admin_pass}"

	# Try to configure MCP
	local config_output
	config_output=$(bash "${CONFIGURE_SCRIPT}" --enable -u $TAP_MYSQLUSERNAME -p $TAP_MYSQLPASSWORD -P $TAP_MYSQLPORT -d "${MYSQL_DATABASE:-testdb}" 2>&1)
	local config_result=$?

	if [ $config_result -eq 0 ]; then
		# Wait for MCP server to start
		sleep 2
		echo "msg: ok $DONE - MCP Configuration - Successfully configured"
		echo "msg: #   MCP server at ${admin_host}:${TAP_MCPPORT:-6071}"
		return 0
	else
		echo "msg: not ok $DONE - MCP Configuration - Failed to configure"
		echo "msg: #   Error: ${config_output}"
		FAIL=$(( $FAIL + 1 ))
		return 1
	fi
}

# Check if MCP server is accessible
fn_check_mcp_server () {
	DONE=$(( $DONE + 1 ))
	PLAN=$([[ $PLAN -lt $DONE ]] && echo $DONE || echo $PLAN)

	local mcp_host="${TAP_ADMINHOST:-127.0.0.1}"
	local mcp_port="${TAP_MCPPORT:-6071}"
	local mcp_url="https://${mcp_host}:${mcp_port}/mcp/config"

	echo "msg: #   Pinging MCP server at ${mcp_url}"

	local response
	local curl_error
	response=$(curl -k -s -X POST "${mcp_url}" \
		-H "Content-Type: application/json" \
		-d '{"jsonrpc":"2.0","method":"ping","id":1}' 2>&1)
	curl_result=$?

	if [ $curl_result -ne 0 ]; then
		echo "msg: not ok $DONE - MCP Server Connection - Failed to connect to ${mcp_url}"
		echo "msg: #   curl error: ${response}"
		FAIL=$(( $FAIL + 1 ))
		return 1
	fi

	if echo "${response}" | grep -q "result"; then
		echo "msg: ok $DONE - MCP Server Connection - Server responding at ${mcp_host}:${mcp_port}"
		return 0
	else
		echo "msg: not ok $DONE - MCP Server Connection - Server did not respond correctly to ping"
		echo "msg: #   Response: ${response}"
		FAIL=$(( $FAIL + 1 ))
		return 1
	fi
}

# Check if MySQL backend is accessible
fn_check_mysql_backend () {
	DONE=$(( $DONE + 1 ))
	PLAN=$([[ $PLAN -lt $DONE ]] && echo $DONE || echo $PLAN)

	local mysql_host="${TAP_MYSQLHOST:-127.0.0.1}"
	local mysql_port="${TAP_MYSQLPORT:-3306}"
	local mysql_user="${TAP_MYSQLUSERNAME:-root}"
	local mysql_pass="${TAP_MYSQLPASSWORD:-none}"

	# Don't log the password, just indicate if it's set or empty
	local pass_status="${mysql_pass}"
	if [ "${mysql_pass}" = "none" ] || [ -z "${mysql_pass}" ]; then
		pass_status="(no password)"
	else
		pass_status="(password set)"
	fi

	echo "msg: #   Connecting to MySQL Backend: ${mysql_user}@${mysql_host}:${mysql_port} ${pass_status}"

	local output
	output=$(fn_mysql_exec "${mysql_host}" "${mysql_port}" "${mysql_user}" "${mysql_pass}" "SELECT 1" 2>&1)
	local result=$?

	if [ $result -eq 0 ]; then
		echo "msg: ok $DONE - MySQL Backend Connection - Connected successfully to ${mysql_host}:${mysql_port}"
		return 0
	else
		echo "msg: not ok $DONE - MySQL Backend Connection - Failed to connect to ${mysql_user}@${mysql_host}:${mysql_port}"
		echo "msg: #   Error: ${output}"
		FAIL=$(( $FAIL + 1 ))
		return 1
	fi
}

# Ensure test scripts are executable
fn_make_executable () {
	find "${MCP_TESTS_DIR}" -name "test_phase*.sh" -exec chmod +x {} \;
	find "${MCP_TESTS_DIR}" -name "test_run_sql_readonly_validation.sh" -exec chmod +x {} \;
}

# Create test database if it doesn't exist
fn_create_test_database () {
	local mysql_host="${TAP_MYSQLHOST:-127.0.0.1}"
	local mysql_port="${TAP_MYSQLPORT:-3306}"
	local mysql_user="${TAP_MYSQLUSERNAME:-root}"
	local mysql_pass="${TAP_MYSQLPASSWORD:-none}"
	local database="${MYSQL_DATABASE:-testdb}"

	echo "msg: #   Creating database '${database}' if not exists..."

	# Handle "none" as a special value meaning no password
	if [ -z "${mysql_pass}" ] || [ "${mysql_pass}" = "none" ]; then
		mysql -h "${mysql_host}" -P "${mysql_port}" \
			-u "${mysql_user}" \
			-e "CREATE DATABASE IF NOT EXISTS \`${database}\`;" 2>&1
	else
		mysql -h "${mysql_host}" -P "${mysql_port}" \
			-u "${mysql_user}" -p"${mysql_pass}" \
			-e "CREATE DATABASE IF NOT EXISTS \`${database}\`;" 2>&1
	fi

	if [ $? -eq 0 ]; then
		echo "msg: #   Database '${database}' ready"
		return 0
	else
		echo "msg: #   Failed to create database '${database}'"
		return 1
	fi
}

# test init
fn_getenv
fn_plan

echo "msg: # MCP Query Rules Test Suite"
echo "msg: #"

# Ensure test scripts are executable
fn_make_executable

# Create test database before running tests
echo "msg: # Creating test database..."
echo "msg: #"
fn_create_test_database

# Pre-flight checks
echo "msg: # Pre-flight checks..."
echo "msg: #"
fn_check_config
fn_check_proxysql_admin
fn_check_configure_mcp
fn_check_mcp_server
fn_check_mysql_backend

echo "msg: #"
echo "msg: # Running Phase Tests..."
echo "msg: #"

# Phase 1: Rule Management Tests (CREATE/READ/UPDATE/DELETE)
echo "msg: # Starting Phase 1: Rule Management (CRUD)"
fn_run_test "Phase 1: Rule Management (CRUD)" "${MCP_TESTS_DIR}/test_phase1_crud.sh"

# Phase 2: LOAD/SAVE Commands Tests
echo "msg: # Starting Phase 2: LOAD/SAVE Commands"
fn_run_test "Phase 2: LOAD/SAVE Commands" "${MCP_TESTS_DIR}/test_phase2_load_save.sh"

# Phase 3: Runtime Table Tests
echo "msg: # Starting Phase 3: Runtime Table"
fn_run_test "Phase 3: Runtime Table" "${MCP_TESTS_DIR}/test_phase3_runtime.sh"

# Phase 4: Statistics Table Tests
echo "msg: # Starting Phase 4: Statistics Table"
fn_run_test "Phase 4: Statistics Table" "${MCP_TESTS_DIR}/test_phase4_stats.sh"

# Phase 5: Query Digest Tests
echo "msg: # Starting Phase 5: Query Digest"
fn_run_test "Phase 5: Query Digest" "${MCP_TESTS_DIR}/test_phase5_digest.sh"

# Phase 6: Rule Evaluation Tests - Block Action
echo "msg: # Starting Phase 6: Rule Evaluation - Block Action"
fn_run_test "Phase 6: Rule Evaluation - Block Action" "${MCP_TESTS_DIR}/test_phase6_eval_block.sh"

# Phase 7: Rule Evaluation Tests - Rewrite Action
echo "msg: # Starting Phase 7: Rule Evaluation - Rewrite Action"
fn_run_test "Phase 7: Rule Evaluation - Rewrite Action" "${MCP_TESTS_DIR}/test_phase7_eval_rewrite.sh"

# Phase 8: Rule Evaluation Tests - Timeout Action (SKIPPED - known limitations)
# Note: Phase 8 is skipped due to MCP connection being killed after timeout
# Uncomment to run when the limitation is fixed:
# echo "msg: # Starting Phase 8: Rule Evaluation - Timeout Action"
# fn_run_test "Phase 8: Rule Evaluation - Timeout Action" "${MCP_TESTS_DIR}/test_phase8_eval_timeout.sh"

# Phase 9: Rule Evaluation Tests - OK Message Action
echo "msg: # Starting Phase 9: Rule Evaluation - OK Message Action"
fn_run_test "Phase 9: Rule Evaluation - OK Message Action" "${MCP_TESTS_DIR}/test_phase9_eval_okmsg.sh"

# Query Tool Validation Tests
echo "msg: #"
echo "msg: # Starting Query Tool Validation Tests"
echo "msg: #"
fn_run_test "Query Tool: run_sql_readonly Validation" "${MCP_TESTS_DIR}/test_run_sql_readonly_validation.sh"

echo "msg: #"
echo "msg: # Test suite completed"

# test done
