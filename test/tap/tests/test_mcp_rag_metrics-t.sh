#!/usr/bin/env bash
#
# test_mcp_rag_metrics-t - TAP Test for MCP RAG Metrics
#
# This script runs all RAG metrics and logging tests and outputs results in TAP format.
#

# change plan here, 0 means auto plan
PLAN=0
DONE=0
FAIL=0

trap fn_exit EXIT
trap fn_exit SIGINT

# Get the test directory
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAG_TESTS_DIR="${TEST_DIR}/rag_stats_testing"

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

	# Check MCP server configuration
	local mcp_host="${TAP_ADMINHOST:-127.0.0.1}"
	local mcp_port="${TAP_MCPPORT:-6071}"

	# Build configuration details for logging
	config_details="ProxySQL Admin: ${admin_user}@${admin_host}:${admin_port} | MCP Server: ${mcp_host}:${mcp_port}"

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

# Check if MCP server is accessible and RAG is enabled
fn_check_mcp_rag () {
	DONE=$(( $DONE + 1 ))
	PLAN=$([[ $PLAN -lt $DONE ]] && echo $DONE || echo $PLAN)

	local mcp_host="${TAP_ADMINHOST:-127.0.0.1}"
	local mcp_port="${TAP_MCPPORT:-6071}"
	local rag_url="https://${mcp_host}:${mcp_port}/mcp/rag"

	echo "msg: #   Checking MCP RAG endpoint at ${rag_url}"

	# Check if genai-rag_enabled is true
	local admin_host="${TAP_ADMINHOST:-127.0.0.1}"
	local admin_port="${TAP_ADMINPORT:-6032}"
	local admin_user="${TAP_ADMINUSERNAME:-radmin}"
	local admin_pass="${TAP_ADMINPASSWORD:-radmin}"

	echo "msg: #   TODO: Checking on 'genai-rag_enabled' disabled, variable is no-op right now..."
	# local rag_enabled
	# rag_enabled=$(fn_mysql_exec "${admin_host}" "${admin_port}" "${admin_user}" "${admin_pass}" \
	# 	"SELECT variable_value FROM global_variables WHERE variable_name='genai-rag_enabled';" \
	# 	2>/dev/null | tail -n 1)

	# if [ "${rag_enabled}" != "true" ]; then
	# 	echo "msg: not ok $DONE - MCP RAG Check - RAG not enabled (genai-rag_enabled=${rag_enabled})"
	# 	echo "msg: #   Enable RAG with: SET genai-rag_enabled=true"
	# 	FAIL=$(( $FAIL + 1 ))
	# 	return 1
	# fi

	echo "msg: #   RAG is enabled, checking endpoint..."

	local response
	local curl_error
	response=$(curl -k -s -X POST "${rag_url}" \
		-H "Content-Type: application/json" \
		-d '{"jsonrpc":"2.0","method":"tools/list","id":1}' 2>&1)
	curl_result=$?

	if [ $curl_result -ne 0 ]; then
		echo "msg: not ok $DONE - MCP RAG Endpoint - Failed to connect to ${rag_url}"
		echo "msg: #   curl error: ${response}"
		FAIL=$(( $FAIL + 1 ))
		return 1
	fi

	if echo "${response}" | grep -q "tools"; then
		echo "msg: ok $DONE - MCP RAG Endpoint - RAG endpoint responding at ${mcp_host}:${mcp_port}"
		return 0
	else
		echo "msg: not ok $DONE - MCP RAG Endpoint - Endpoint did not respond correctly"
		echo "msg: #   Response: ${response}"
		FAIL=$(( $FAIL + 1 ))
		return 1
	fi
}

# Prepare RAG test database
fn_prepare_rag_db () {
	DONE=$(( $DONE + 1 ))
	PLAN=$([[ $PLAN -lt $DONE ]] && echo $DONE || echo $PLAN)

	local prepare_script="${RAG_TESTS_DIR}/prepare_test_db.sh"

	echo "msg: #   Preparing RAG test database..."

	# Check if prepare script exists
	if [ ! -f "${prepare_script}" ]; then
		echo "msg: not ok $DONE - RAG Database Preparation - prepare_test_db.sh not found at ${prepare_script}"
		FAIL=$(( $FAIL + 1 ))
		return 1
	fi

	# Make sure it's executable
	chmod +x "${prepare_script}"

	# Run the prepare script
	local prep_output
	prep_output=$(bash "${prepare_script}" 2>&1)
	local prep_result=$?

	if [ $prep_result -eq 0 ]; then
		echo "msg: ok $DONE - RAG Database Preparation - Database ready"
		echo "msg: #   Data inserted:"
		echo "${prep_output}" | while IFS= read -r line; do
			if [ -n "$line" ]; then
				echo "msg: #     $line"
			fi
		done
		return 0
	else
		echo "msg: not ok $DONE - RAG Database Preparation - Failed to prepare database"
		echo "msg: #   Error: ${prep_output}"
		FAIL=$(( $FAIL + 1 ))
		return 1
	fi
}

# Ensure test scripts are executable
fn_make_executable () {
	find "${RAG_TESTS_DIR}" -name "test_*.sh" -exec chmod +x {} \;
}

# test init
fn_getenv
fn_plan

echo "msg: #"
echo "msg: # === MCP RAG Metrics Test Suite ==="
echo "msg: # This test validates the MCP RAG (Retrieval-Augmented Generation) endpoint:"
echo "msg: # - Pre-flight checks: ProxySQL admin, MCP server, RAG endpoint"
echo "msg: # - RAG Tool Counters: validates tool invocation counters increment"
echo "msg: # - RAG Search Logging: validates search queries are logged correctly"
echo "msg: # The RAG endpoint provides FTS (full-text search) and vector search"
echo "msg: # capabilities for semantic discovery of database schemas."
echo "msg: # ==================================="
echo "msg: #"

# Ensure test scripts are executable
fn_make_executable

# Pre-flight checks
echo "msg: # Pre-flight checks..."
echo "msg: #"
fn_check_config
fn_check_proxysql_admin
fn_check_mcp_rag

# Prepare RAG test database
echo "msg: #"
echo "msg: # Preparing RAG test database..."
echo "msg: #"
fn_prepare_rag_db

echo "msg: #"
echo "msg: # Running RAG Metrics Tests..."
echo "msg: #"

# Test 1: RAG Tool Counters
echo "msg: # Starting Test 1: RAG Tool Invocation Counters"
fn_run_test "RAG Tool Counters" "${RAG_TESTS_DIR}/test_rag_tool_counters.sh"

# Test 2: RAG Search Logging
echo "msg: # Starting Test 2: RAG Search Logging"
fn_run_test "RAG Search Logging" "${RAG_TESTS_DIR}/test_rag_search_log.sh"

echo "msg: #"
echo "msg: # Test suite completed"

# test done
