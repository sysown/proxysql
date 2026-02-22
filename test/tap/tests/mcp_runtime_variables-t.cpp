/**
 * @file mcp_runtime_variables-t.cpp
 * @brief TAP test for MCP runtime_global_variables table population.
 *
 * This test verifies that MCP variables are correctly populated into
 * runtime_global_variables after LOAD MCP VARIABLES TO RUNTIME.
 *
 * Test cases:
 * 1. Verify runtime_global_variables contains MCP variables after LOAD
 * 2. Verify changed variables are reflected in runtime_global_variables after LOAD
 * 3. Verify runtime values match the values set in memory
 */

#include <string>
#include <cstring>
#include <cstdio>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

/**
 * @brief Get the value of an MCP variable as a string
 *
 * @param admin MySQL connection to admin interface
 * @param var_name Variable name (without mcp- prefix)
 * @return std::string The variable value, or empty string on error
 */
string get_mcp_variable(MYSQL* admin, const string& var_name) {
	string query = "SELECT @@mcp-" + var_name;
	if (mysql_query(admin, query.c_str()) != 0) {
		return "";
	}

	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) {
		return "";
	}

	MYSQL_ROW row = mysql_fetch_row(res);
	string value = row && row[0] ? row[0] : "";

	mysql_free_result(res);
	return value;
}

/**
 * @brief Get the value of a variable from runtime_global_variables
 *
 * @param admin MySQL connection to admin interface
 * @param var_name Variable name (with mcp- prefix)
 * @return std::string The variable value, or empty string if not found
 */
string get_runtime_variable(MYSQL* admin, const string& var_name) {
	string query = "SELECT variable_value FROM runtime_global_variables WHERE variable_name='" + var_name + "'";
	if (mysql_query(admin, query.c_str()) != 0) {
		return "";
	}

	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) {
		return "";
	}

	MYSQL_ROW row = mysql_fetch_row(res);
	string value = row && row[0] ? row[0] : "";

	mysql_free_result(res);
	return value;
}

/**
 * @brief Count MCP variables in runtime_global_variables
 *
 * @param admin MySQL connection to admin interface
 * @return int Number of mcp-* variables in runtime_global_variables
 */
int count_mcp_runtime_variables(MYSQL* admin) {
	if (mysql_query(admin, "SELECT COUNT(*) FROM runtime_global_variables WHERE variable_name LIKE 'mcp-%'") != 0) {
		return -1;
	}

	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) {
		return -1;
	}

	MYSQL_ROW row = mysql_fetch_row(res);
	int count = row && row[0] ? atoi(row[0]) : 0;

	mysql_free_result(res);
	return count;
}

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to read TAP environment");
		return exit_status();
	}

	plan(8);

	diag("=== MCP Runtime Variables Table Population Test ===");
	diag("This test verifies that MCP variables are correctly populated into");
	diag("runtime_global_variables after LOAD MCP VARIABLES TO RUNTIME.");
	diag("Test cases:");
	diag("  1. Verify runtime_global_variables contains MCP variables after LOAD");
	diag("  2. Verify changed variables are reflected after LOAD");
	diag("  3. Verify runtime values match global_variables values");
	diag("===================================================");

	MYSQL* admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		skip(8, "Cannot connect to admin");
		return exit_status();
	}
	ok(admin != nullptr, "Admin connection established");

	// Test 1: Verify runtime_global_variables has at least 10 MCP variables after LOAD
	diag("Test 1: Verifying runtime_global_variables is populated with MCP variables");

	// First, ensure we have a clean state and load to runtime
	run_q(admin, "SET mcp-enabled=false");
	run_q(admin, "LOAD MCP VARIABLES TO RUNTIME");

	int count = count_mcp_runtime_variables(admin);
	ok(count >= 10, "runtime_global_variables contains at least 10 MCP variables (got %d)", count);

	// Test 2: Change several variables and verify they update in runtime_global_variables
	diag("Test 2: Changing variables and verifying runtime_global_variables updates");

	// Record original values
	string orig_timeout = get_runtime_variable(admin, "mcp-timeout_ms");
	string orig_queries_max = get_runtime_variable(admin, "mcp-stats_show_queries_max_rows");
	string orig_processlist_max = get_runtime_variable(admin, "mcp-stats_show_processlist_max_rows");

	diag("Original values: timeout_ms=%s, queries_max=%s, processlist_max=%s",
		orig_timeout.c_str(), orig_queries_max.c_str(), orig_processlist_max.c_str());

	// Change the variables
	run_q(admin, "SET mcp-timeout_ms=45000");
	run_q(admin, "SET mcp-stats_show_queries_max_rows=500");
	run_q(admin, "SET mcp-stats_show_processlist_max_rows=300");

	// Load to runtime
	run_q(admin, "LOAD MCP VARIABLES TO RUNTIME");

	// Verify the values changed in runtime_global_variables
	string new_timeout = get_runtime_variable(admin, "mcp-timeout_ms");
	string new_queries_max = get_runtime_variable(admin, "mcp-stats_show_queries_max_rows");
	string new_processlist_max = get_runtime_variable(admin, "mcp-stats_show_processlist_max_rows");

	diag("New values: timeout_ms=%s, queries_max=%s, processlist_max=%s",
		new_timeout.c_str(), new_queries_max.c_str(), new_processlist_max.c_str());

	ok(new_timeout == "45000", "mcp-timeout_ms updated to 45000 in runtime_global_variables (got '%s')", new_timeout.c_str());
	ok(new_queries_max == "500", "mcp-stats_show_queries_max_rows updated to 500 in runtime_global_variables (got '%s')", new_queries_max.c_str());
	ok(new_processlist_max == "300", "mcp-stats_show_processlist_max_rows updated to 300 in runtime_global_variables (got '%s')", new_processlist_max.c_str());

	// Test 3: Verify runtime values match global_variables
	diag("Test 3: Verifying runtime_global_variables matches global_variables");

	// Get values from global_variables
	string global_timeout = get_mcp_variable(admin, "timeout_ms");
	string global_queries = get_mcp_variable(admin, "stats_show_queries_max_rows");
	string global_processlist = get_mcp_variable(admin, "stats_show_processlist_max_rows");

	ok(new_timeout == global_timeout, "runtime timeout_ms (%s) matches global_variables (%s)",
		new_timeout.c_str(), global_timeout.c_str());
	ok(new_queries_max == global_queries, "runtime queries_max (%s) matches global_variables (%s)",
		new_queries_max.c_str(), global_queries.c_str());
	ok(new_processlist_max == global_processlist, "runtime processlist_max (%s) matches global_variables (%s)",
		new_processlist_max.c_str(), global_processlist.c_str());

	// Cleanup: restore original values
	diag("Cleanup: Restoring original values");
	if (!orig_timeout.empty()) {
		run_q(admin, ("SET mcp-timeout_ms=" + orig_timeout).c_str());
	}
	if (!orig_queries_max.empty()) {
		run_q(admin, ("SET mcp-stats_show_queries_max_rows=" + orig_queries_max).c_str());
	}
	if (!orig_processlist_max.empty()) {
		run_q(admin, ("SET mcp-stats_show_processlist_max_rows=" + orig_processlist_max).c_str());
	}
	run_q(admin, "LOAD MCP VARIABLES TO RUNTIME");

	mysql_close(admin);

	return exit_status();
}
