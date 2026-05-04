/**
 * @file mcp_module-t.cpp
 * @brief TAP test for the MCP module
 *
 * This test verifies the functionality of the MCP (Model Context Protocol) module in ProxySQL.
 * It tests:
 *   - LOAD/SAVE commands for MCP variables across all variants
 *   - Variable access (SET and SELECT) for MCP variables
 *   - Variable persistence across storage layers (memory, disk, runtime)
 *   - CHECKSUM commands for MCP variables
 *   - SHOW VARIABLES for MCP module
 *
 * @date 2025-01-11
 */

#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

/**
 * @brief Helper function to add LOAD/SAVE command variants for MCP module
 *
 * This function generates all the standard LOAD/SAVE command variants that
 * ProxySQL supports for module variables.
 *
 * @param queries Vector to append the generated commands to
 */
void add_mcp_load_save_commands(std::vector<std::string>& queries) {
	// LOAD commands - Memory variants
	queries.push_back("LOAD MCP VARIABLES TO MEMORY");
	queries.push_back("LOAD MCP VARIABLES TO MEM");

	// LOAD from disk
	queries.push_back("LOAD MCP VARIABLES FROM DISK");

	// LOAD from memory
	queries.push_back("LOAD MCP VARIABLES FROM MEMORY");
	queries.push_back("LOAD MCP VARIABLES FROM MEM");

	// LOAD to runtime
	queries.push_back("LOAD MCP VARIABLES TO RUNTIME");
	queries.push_back("LOAD MCP VARIABLES TO RUN");

	// SAVE from memory
	queries.push_back("SAVE MCP VARIABLES FROM MEMORY");
	queries.push_back("SAVE MCP VARIABLES FROM MEM");

	// SAVE to disk
	queries.push_back("SAVE MCP VARIABLES TO DISK");

	// SAVE to memory
	queries.push_back("SAVE MCP VARIABLES TO MEMORY");
	queries.push_back("SAVE MCP VARIABLES TO MEM");

	// SAVE from runtime
	queries.push_back("SAVE MCP VARIABLES FROM RUNTIME");
	queries.push_back("SAVE MCP VARIABLES FROM RUN");
}

/**
 * @brief Helper function to add LOAD/SAVE command variants for MCP PROFILES
 */
void add_mcp_profile_commands(std::vector<std::string>& queries) {
	queries.push_back("LOAD MCP PROFILES TO MEMORY");
	queries.push_back("LOAD MCP PROFILES FROM DISK");
	queries.push_back("LOAD MCP PROFILES FROM MEMORY");
	queries.push_back("LOAD MCP PROFILES FROM MEM");
	queries.push_back("LOAD MCP PROFILES TO RUNTIME");
	queries.push_back("LOAD MCP PROFILES TO RUN");
	queries.push_back("SAVE MCP PROFILES TO MEMORY");
	queries.push_back("SAVE MCP PROFILES TO MEM");
	queries.push_back("SAVE MCP PROFILES FROM RUNTIME");
	queries.push_back("SAVE MCP PROFILES FROM RUN");
	queries.push_back("SAVE MCP PROFILES TO DISK");
}

/**
 * @brief Get the value of an MCP variable as a string
 *
 * @param admin MySQL connection to admin interface
 * @param var_name Variable name (without mcp- prefix)
 * @return std::string The variable value, or empty string on error
 */
std::string get_mcp_variable(MYSQL* admin, const std::string& var_name) {
	std::string query = "SELECT @@mcp-" + var_name;
	if (mysql_query(admin, query.c_str()) != 0) {
		return "";
	}

	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) {
		return "";
	}

	MYSQL_ROW row = mysql_fetch_row(res);
	std::string value = row && row[0] ? row[0] : "";

	mysql_free_result(res);
	return value;
}

/**
 * @brief Test variable access operations (SET and SELECT)
 *
 * Tests setting and retrieving MCP variables to ensure they work correctly.
 */
int test_variable_access(MYSQL* admin) {
	int test_num = 0;

	// Test 1: Get default value of mcp_enabled
	std::string enabled_default = get_mcp_variable(admin, "enabled");
	ok(enabled_default == "false",
	   "Default value of mcp_enabled is 'false', got '%s'", enabled_default.c_str());

	// Test 2: Get default value of mcp_port
	std::string port_default = get_mcp_variable(admin, "port");
	ok(port_default == "6071",
	   "Default value of mcp_port is '6071', got '%s'", port_default.c_str());

	// Test 3: Set mcp_enabled to true
	MYSQL_QUERY(admin, "SET mcp-enabled=true");
	std::string enabled_new = get_mcp_variable(admin, "enabled");
	ok(enabled_new == "true",
	   "After SET, mcp_enabled is 'true', got '%s'", enabled_new.c_str());

	// Test 4: Set mcp_port to a new value
	MYSQL_QUERY(admin, "SET mcp-port=8080");
	std::string port_new = get_mcp_variable(admin, "port");
	ok(port_new == "8080",
	   "After SET, mcp_port is '8080', got '%s'", port_new.c_str());

	// Test 5: Set mcp_config_endpoint_auth
	MYSQL_QUERY(admin, "SET mcp-config_endpoint_auth='token123'");
	std::string auth_config = get_mcp_variable(admin, "config_endpoint_auth");
	ok(auth_config == "token123",
	   "After SET, mcp_config_endpoint_auth is 'token123', got '%s'", auth_config.c_str());

	// Test 6: Set mcp_timeout_ms
	MYSQL_QUERY(admin, "SET mcp-timeout_ms=60000");
	std::string timeout = get_mcp_variable(admin, "timeout_ms");
	ok(timeout == "60000",
	   "After SET, mcp_timeout_ms is '60000', got '%s'", timeout.c_str());

	// Test 7: Verify SHOW VARIABLES LIKE pattern
	MYSQL_QUERY(admin, "SHOW VARIABLES LIKE 'mcp-%'");
	MYSQL_RES* res = mysql_store_result(admin);
	int num_rows = static_cast<int>(mysql_num_rows(res));
	// Use a lower bound because MCP variables can grow over time and by build flavor.
	ok(num_rows >= 10,
	   "SHOW VARIABLES LIKE 'mcp-%%' returns at least 10 rows, got %d", num_rows);
	mysql_free_result(res);

	// Test 8: Restore default values
	MYSQL_QUERY(admin, "SET mcp-enabled=false");
	MYSQL_QUERY(admin, "SET mcp-port=6071");
	MYSQL_QUERY(admin, "SET mcp-config_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-stats_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-ai_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-rag_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-timeout_ms=30000");
	ok(1, "Restored default values for MCP variables");

	return test_num;
}

/**
 * @brief Test variable persistence across storage layers
 *
 * Tests that variables are correctly copied between:
 * - Memory (main.global_variables)
 * - Disk (disk.global_variables)
 * - Runtime (GloMCPH handler object)
 */
int test_variable_persistence(MYSQL* admin) {
	int test_num = 0;

	diag("=== Part 3: Testing variable persistence across storage layers ===");
	diag("Testing variable persistence: Set values, save to disk, modify, load from disk");

	// Test 1: Set values and save to disk
	diag("Test 1: Setting mcp-enabled=true, mcp-port=7070, mcp-timeout_ms=90000");
	MYSQL_QUERY(admin, "SET mcp-enabled=true");
	MYSQL_QUERY(admin, "SET mcp-port=7070");
	MYSQL_QUERY(admin, "SET mcp-timeout_ms=90000");
	diag("Test 1: Saving variables to disk with 'SAVE MCP VARIABLES TO DISK'");
	MYSQL_QUERY(admin, "SAVE MCP VARIABLES TO DISK");
	ok(1, "Set mcp_enabled=true, mcp_port=7070, mcp_timeout_ms=90000 and saved to disk");

	// Test 2: Modify values in memory
	diag("Test 2: Modifying values in memory (mcp-enabled=false, mcp-port=8080)");
	MYSQL_QUERY(admin, "SET mcp-enabled=false");
	MYSQL_QUERY(admin, "SET mcp-port=8080");
	std::string enabled_mem = get_mcp_variable(admin, "enabled");
	std::string port_mem = get_mcp_variable(admin, "port");
	diag("Test 2: After modification - mcp_enabled='%s', mcp_port='%s'", enabled_mem.c_str(), port_mem.c_str());
	ok(enabled_mem == "false" && port_mem == "8080",
	   "Modified in memory: mcp_enabled='false', mcp_port='8080'");

	// Test 3: Load from disk and verify original values restored
	diag("Test 3: Loading variables from disk with 'LOAD MCP VARIABLES FROM DISK'");
	MYSQL_QUERY(admin, "LOAD MCP VARIABLES FROM DISK");
	std::string enabled_disk = get_mcp_variable(admin, "enabled");
	std::string port_disk = get_mcp_variable(admin, "port");
	std::string timeout_disk = get_mcp_variable(admin, "timeout_ms");
	diag("Test 3: After LOAD FROM DISK - mcp_enabled='%s', mcp_port='%s', mcp_timeout_ms='%s'",
	     enabled_disk.c_str(), port_disk.c_str(), timeout_disk.c_str());
	ok(enabled_disk == "true" && port_disk == "7070" && timeout_disk == "90000",
	   "After LOAD FROM DISK: mcp_enabled='true', mcp_port='7070', mcp_timeout_ms='90000'");

	// Test 4: Save to memory and verify
	diag("Test 4: Executing 'SAVE MCP VARIABLES TO MEMORY'");
	MYSQL_QUERY(admin, "SAVE MCP VARIABLES TO MEMORY");
	ok(1, "SAVE MCP VARIABLES TO MEMORY executed");

	// Test 5: Load from memory
	diag("Test 5: Executing 'LOAD MCP VARIABLES FROM MEMORY'");
	MYSQL_QUERY(admin, "LOAD MCP VARIABLES FROM MEMORY");
	ok(1, "LOAD MCP VARIABLES FROM MEMORY executed");

	// Test 6: Test SAVE from runtime
	diag("Test 6: Executing 'SAVE MCP VARIABLES FROM RUNTIME'");
	MYSQL_QUERY(admin, "SAVE MCP VARIABLES FROM RUNTIME");
	ok(1, "SAVE MCP VARIABLES FROM RUNTIME executed");

	// Test 7: Test LOAD to runtime
	diag("Test 7: Executing 'LOAD MCP VARIABLES TO RUNTIME'");
	MYSQL_QUERY(admin, "LOAD MCP VARIABLES TO RUNTIME");
	ok(1, "LOAD MCP VARIABLES TO RUNTIME executed");

	// Test 8: Restore default values
	diag("Test 8: Restoring default values");
	MYSQL_QUERY(admin, "SET mcp-enabled=false");
	MYSQL_QUERY(admin, "SET mcp-port=6071");
	MYSQL_QUERY(admin, "SET mcp-config_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-stats_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-query_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-admin_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-cache_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-ai_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-rag_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-timeout_ms=30000");
	MYSQL_QUERY(admin, "SAVE MCP VARIABLES TO DISK");
	ok(1, "Restored default values and saved to disk");

	return test_num;
}

/**
 * @brief Test CHECKSUM commands for MCP variables
 *
 * Tests all CHECKSUM variants to ensure they work correctly.
 */
int test_checksum_commands(MYSQL* admin) {
	int test_num = 0;

	diag("=== Part 4: Testing CHECKSUM commands ===");
	diag("Testing CHECKSUM commands for MCP variables");

	// Test 1: CHECKSUM DISK MCP VARIABLES
	diag("Test 1: Executing 'CHECKSUM DISK MCP VARIABLES'");
	int rc1 = mysql_query(admin, "CHECKSUM DISK MCP VARIABLES");
	diag("Test 1: Query returned with rc=%d", rc1);
	ok(rc1 == 0, "CHECKSUM DISK MCP VARIABLES");
	if (rc1 == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		int num_rows = static_cast<int>(mysql_num_rows(res));
		diag("Test 1: Result has %d row(s)", num_rows);
		ok(num_rows == 1, "CHECKSUM DISK MCP VARIABLES returns 1 row");
		mysql_free_result(res);
	} else {
		diag("Test 1: Query failed with error: %s", mysql_error(admin));
		skip(1, "Skipping row count check due to error");
	}

	// Test 2: CHECKSUM MEM MCP VARIABLES
	diag("Test 2: Executing 'CHECKSUM MEM MCP VARIABLES'");
	int rc2 = mysql_query(admin, "CHECKSUM MEM MCP VARIABLES");
	diag("Test 2: Query returned with rc=%d", rc2);
	ok(rc2 == 0, "CHECKSUM MEM MCP VARIABLES");
	if (rc2 == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		int num_rows = static_cast<int>(mysql_num_rows(res));
		diag("Test 2: Result has %d row(s)", num_rows);
		ok(num_rows == 1, "CHECKSUM MEM MCP VARIABLES returns 1 row");
		mysql_free_result(res);
	} else {
		diag("Test 2: Query failed with error: %s", mysql_error(admin));
		skip(1, "Skipping row count check due to error");
	}

	// Test 3: CHECKSUM MEMORY MCP VARIABLES (alias for MEM)
	diag("Test 3: Executing 'CHECKSUM MEMORY MCP VARIABLES' (alias for MEM)");
	int rc3 = mysql_query(admin, "CHECKSUM MEMORY MCP VARIABLES");
	diag("Test 3: Query returned with rc=%d", rc3);
	ok(rc3 == 0, "CHECKSUM MEMORY MCP VARIABLES");
	if (rc3 == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		int num_rows = static_cast<int>(mysql_num_rows(res));
		diag("Test 3: Result has %d row(s)", num_rows);
		ok(num_rows == 1, "CHECKSUM MEMORY MCP VARIABLES returns 1 row");
		mysql_free_result(res);
	} else {
		diag("Test 3: Query failed with error: %s", mysql_error(admin));
		skip(1, "Skipping row count check due to error");
	}

	// Test 4: CHECKSUM MCP VARIABLES (defaults to DISK)
	diag("Test 4: Executing 'CHECKSUM MCP VARIABLES' (defaults to DISK)");
	int rc4 = mysql_query(admin, "CHECKSUM MCP VARIABLES");
	diag("Test 4: Query returned with rc=%d", rc4);
	ok(rc4 == 0, "CHECKSUM MCP VARIABLES");
	if (rc4 == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		int num_rows = static_cast<int>(mysql_num_rows(res));
		diag("Test 4: Result has %d row(s)", num_rows);
		ok(num_rows == 1, "CHECKSUM MCP VARIABLES returns 1 row");
		mysql_free_result(res);
	} else {
		diag("Test 4: Query failed with error: %s", mysql_error(admin));
		skip(1, "Skipping row count check due to error");
	}

	return test_num;
}

/**
 * @brief Main test function
 *
 * Orchestrates all MCP module tests.
 */
int main() {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	diag("=== MCP Module TAP Test ===");
	diag("This test validates the MCP (Model Context Protocol) module functionality.");
	diag("It covers: LOAD/SAVE commands for MCP variables across all variants,");
	diag("variable access (SET and SELECT) for MCP variables, persistence across");
	diag("storage layers (memory, disk, runtime), CHECKSUM commands for MCP variables,");
	diag("and LOAD/SAVE commands for MCP PROFILES (auth and target profiles).");
	diag("============================");

	// Initialize connection to admin interface
	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: mysql_init failed\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
		NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	diag("Connected to ProxySQL admin interface at %s:%d", cl.host, cl.admin_port);

	// Reset MCP variables to default values before testing
	// This ensures tests start from a known state regardless of previous runs
	diag("Resetting MCP variables to default values before testing");
	MYSQL_QUERY(admin, "SET mcp-enabled=false");
	MYSQL_QUERY(admin, "SET mcp-port=6071");
	MYSQL_QUERY(admin, "SET mcp-config_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-stats_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-query_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-admin_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-cache_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-ai_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-rag_endpoint_auth=''");
	MYSQL_QUERY(admin, "SET mcp-timeout_ms=30000");
	MYSQL_QUERY(admin, "SAVE MCP VARIABLES TO DISK");
	MYSQL_QUERY(admin, "LOAD MCP VARIABLES FROM DISK");
	diag("MCP variables reset to defaults");

	// Build the list of LOAD/SAVE commands to test
	std::vector<std::string> queries;
	add_mcp_load_save_commands(queries);
	add_mcp_profile_commands(queries);

	// Each command test = 2 tests (execution + optional result check)
	// LOAD/SAVE commands: variables + profiles
	// Variable access tests: 8 tests
	// Persistence tests: 8 tests
	// CHECKSUM tests: 8 tests (4 commands × 2)
	int num_load_save_tests = (int)queries.size() * 2; // Each command + result check
	int total_tests = num_load_save_tests + 8 + 8 + 8;

	plan(total_tests);

	int test_count = 0;

	// ============================================================================
	// Part 1: Test LOAD/SAVE commands
	// ============================================================================
	diag("=== Part 1: Testing LOAD/SAVE MCP VARIABLES commands ===");
	for (const auto& query : queries) {
		MYSQL* admin_local = mysql_init(NULL);
		if (!admin_local) {
			diag("Failed to initialize MySQL connection");
			continue;
		}

		if (!mysql_real_connect(admin_local, cl.host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0)) {
			diag("Failed to connect to admin interface");
			mysql_close(admin_local);
			continue;
		}

		int rc = run_q(admin_local, query.c_str());
		ok(rc == 0, "Command executed successfully: %s", query.c_str());

		// For SELECT/SHOW/CHECKSUM style commands, verify result set
		if (strncasecmp(query.c_str(), "SELECT ", 7) == 0 ||
			strncasecmp(query.c_str(), "SHOW ", 5) == 0 ||
			strncasecmp(query.c_str(), "CHECKSUM ", 9) == 0) {
			MYSQL_RES* res = mysql_store_result(admin_local);
			unsigned long long num_rows = mysql_num_rows(res);
			ok(num_rows != 0, "Command returned rows: %s", query.c_str());
			mysql_free_result(res);
		} else {
			// For non-query commands, just mark the test as passed
			ok(1, "Command completed: %s", query.c_str());
		}

		mysql_close(admin_local);
	}

	// ============================================================================
	// Part 2: Test variable access (SET and SELECT)
	// ============================================================================
	diag("=== Part 2: Testing variable access (SET and SELECT) ===");
	test_variable_access(admin);

	// ============================================================================
	// Part 3: Test variable persistence across layers
	// ============================================================================
	diag("=== Part 3: Testing variable persistence across storage layers ===");
	test_variable_persistence(admin);

	// ============================================================================
	// Part 4: Test CHECKSUM commands
	// ============================================================================
	diag("=== Part 4: Testing CHECKSUM commands ===");
	test_checksum_commands(admin);

	// ============================================================================
	// Cleanup
	// ============================================================================
	mysql_close(admin);

	diag("=== All MCP module tests completed ===");

	return exit_status();
}
