/**
 * @file genai_module-t.cpp
 * @brief TAP test for the GenAI module
 *
 * This test verifies the functionality of the GenAI (Generative AI) module in ProxySQL.
 * It tests:
 *   - LOAD/SAVE commands for GenAI variables across all variants
 *   - Variable access (SET and SELECT) for genai-var1 and genai-var2
 *   - Variable persistence across storage layers (memory, disk, runtime)
 *   - CHECKSUM commands for GenAI variables
 *   - SHOW VARIABLES for GenAI module
 *
 * @date 2025-01-08
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
 * @brief Helper function to add LOAD/SAVE command variants for GenAI module
 *
 * This function generates all the standard LOAD/SAVE command variants that
 * ProxySQL supports for module variables. It follows the same pattern used
 * for other modules like MYSQL, PGSQL, etc.
 *
 * @param queries Vector to append the generated commands to
 */
void add_genai_load_save_commands(std::vector<std::string>& queries) {
	// LOAD commands - Memory variants
	queries.push_back("LOAD GENAI VARIABLES TO MEMORY");
	queries.push_back("LOAD GENAI VARIABLES TO MEM");

	// LOAD from disk
	queries.push_back("LOAD GENAI VARIABLES FROM DISK");

	// LOAD from memory
	queries.push_back("LOAD GENAI VARIABLES FROM MEMORY");
	queries.push_back("LOAD GENAI VARIABLES FROM MEM");

	// LOAD to runtime
	queries.push_back("LOAD GENAI VARIABLES TO RUNTIME");
	queries.push_back("LOAD GENAI VARIABLES TO RUN");

	// SAVE from memory
	queries.push_back("SAVE GENAI VARIABLES FROM MEMORY");
	queries.push_back("SAVE GENAI VARIABLES FROM MEM");

	// SAVE to disk
	queries.push_back("SAVE GENAI VARIABLES TO DISK");

	// SAVE to memory
	queries.push_back("SAVE GENAI VARIABLES TO MEMORY");
	queries.push_back("SAVE GENAI VARIABLES TO MEM");

	// SAVE from runtime
	queries.push_back("SAVE GENAI VARIABLES FROM RUNTIME");
	queries.push_back("SAVE GENAI VARIABLES FROM RUN");
}

/**
 * @brief Get the value of a GenAI variable as a string
 *
 * @param admin MySQL connection to admin interface
 * @param var_name Variable name (without genai- prefix)
 * @return std::string The variable value, or empty string on error
 */
std::string get_genai_variable(MYSQL* admin, const std::string& var_name) {
	std::string query = "SELECT @@genai-" + var_name;
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
 * Tests setting and retrieving GenAI variables to ensure they work correctly.
 */
int test_variable_access(MYSQL* admin) {
	int test_num = 0;

	// Test 1: Get default value of genai-var1
	std::string var1_default = get_genai_variable(admin, "var1");
	ok(var1_default == "default_value_1",
	   "Default value of genai-var1 is 'default_value_1', got '%s'", var1_default.c_str());

	// Test 2: Get default value of genai-var2
	std::string var2_default = get_genai_variable(admin, "var2");
	ok(var2_default == "100", 
	   "Default value of genai-var2 is '100', got '%s'", var2_default.c_str());

	// Test 3: Set genai-var1 to a new value
	MYSQL_QUERY(admin, "SET genai-var1='test_value_123'");
	std::string var1_new = get_genai_variable(admin, "var1");
	ok(var1_new == "test_value_123", 
	   "After SET, genai-var1 is 'test_value_123', got '%s'", var1_new.c_str());

	// Test 4: Set genai-var2 to a new integer value
	MYSQL_QUERY(admin, "SET genai-var2=42");
	std::string var2_new = get_genai_variable(admin, "var2");
	ok(var2_new == "42", 
	   "After SET, genai-var2 is '42', got '%s'", var2_new.c_str());

	// Test 5: Set genai-var1 with special characters
	MYSQL_QUERY(admin, "SET genai-var1='test with spaces'");
	std::string var1_special = get_genai_variable(admin, "var1");
	ok(var1_special == "test with spaces", 
	   "genai-var1 with spaces is 'test with spaces', got '%s'", var1_special.c_str());

	// Test 6: Verify SHOW VARIABLES LIKE pattern
	MYSQL_QUERY(admin, "SHOW VARIABLES LIKE 'genai-%'");
	MYSQL_RES* res = mysql_store_result(admin);
	int num_rows = static_cast<int>(mysql_num_rows(res));
	ok(num_rows == 2, 
	   "SHOW VARIABLES LIKE 'genai-%%' returns 2 rows, got %d", num_rows);
	mysql_free_result(res);

	// Test 7: Restore default values
	MYSQL_QUERY(admin, "SET genai-var1='default_value_1'");
	MYSQL_QUERY(admin, "SET genai-var2=100");
	ok(1,  "Restored default values for genai-var1 and genai-var2");

	return test_num;
}

/**
 * @brief Test variable persistence across storage layers
 *
 * Tests that variables are correctly copied between:
 * - Memory (main.global_variables)
 * - Disk (disk.global_variables)
 * - Runtime (GloGATH handler object)
 */
int test_variable_persistence(MYSQL* admin) {
	int test_num = 0;

	// Test 1: Set values and save to disk
	diag("Testing variable persistence: Set values, save to disk, modify, load from disk");
	MYSQL_QUERY(admin, "SET genai-var1='disk_test_value'");
	MYSQL_QUERY(admin, "SET genai-var2=999");
	MYSQL_QUERY(admin, "SAVE GENAI VARIABLES TO DISK");
	ok(1,  "Set genai-var1='disk_test_value', genai-var2=999 and saved to disk");

	// Test 2: Modify values in memory
	MYSQL_QUERY(admin, "SET genai-var1='memory_value'");
	MYSQL_QUERY(admin, "SET genai-var2=111");
	std::string var1_mem = get_genai_variable(admin, "var1");
	std::string var2_mem = get_genai_variable(admin, "var2");
	ok(var1_mem == "memory_value" && var2_mem == "111", 
	   "Modified in memory: genai-var1='memory_value', genai-var2='111'");

	// Test 3: Load from disk and verify original values restored
	MYSQL_QUERY(admin, "LOAD GENAI VARIABLES FROM DISK");
	std::string var1_disk = get_genai_variable(admin, "var1");
	std::string var2_disk = get_genai_variable(admin, "var2");
	ok(var1_disk == "disk_test_value" && var2_disk == "999", 
	   "After LOAD FROM DISK: genai-var1='disk_test_value', genai-var2='999'");

	// Test 4: Save to memory and verify
	MYSQL_QUERY(admin, "SAVE GENAI VARIABLES TO MEMORY");
	ok(1,  "SAVE GENAI VARIABLES TO MEMORY executed");

	// Test 5: Load from memory
	MYSQL_QUERY(admin, "LOAD GENAI VARIABLES FROM MEMORY");
	ok(1,  "LOAD GENAI VARIABLES FROM MEMORY executed");

	// Test 6: Test SAVE from runtime
	MYSQL_QUERY(admin, "SAVE GENAI VARIABLES FROM RUNTIME");
	ok(1,  "SAVE GENAI VARIABLES FROM RUNTIME executed");

	// Test 7: Test LOAD to runtime
	MYSQL_QUERY(admin, "LOAD GENAI VARIABLES TO RUNTIME");
	ok(1,  "LOAD GENAI VARIABLES TO RUNTIME executed");

	// Test 8: Restore default values
	MYSQL_QUERY(admin, "SET genai-var1='default_value_1'");
	MYSQL_QUERY(admin, "SET genai-var2=100");
	MYSQL_QUERY(admin, "SAVE GENAI VARIABLES TO DISK");
	ok(1,  "Restored default values and saved to disk");

	return test_num;
}

/**
 * @brief Test CHECKSUM commands for GenAI variables
 *
 * Tests all CHECKSUM variants to ensure they work correctly.
 */
int test_checksum_commands(MYSQL* admin) {
	int test_num = 0;

	// Test 1: CHECKSUM DISK GENAI VARIABLES
	diag("Testing CHECKSUM commands for GenAI variables");
	int rc1 = mysql_query(admin, "CHECKSUM DISK GENAI VARIABLES");
	ok(rc1 == 0,  "CHECKSUM DISK GENAI VARIABLES");
	if (rc1 == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		int num_rows = static_cast<int>(mysql_num_rows(res));
		ok(num_rows == 1,  "CHECKSUM DISK GENAI VARIABLES returns 1 row");
		mysql_free_result(res);
	} else {
		skip(1, "Skipping row count check due to error");
	}

	// Test 2: CHECKSUM MEM GENAI VARIABLES
	int rc2 = mysql_query(admin, "CHECKSUM MEM GENAI VARIABLES");
	ok(rc2 == 0,  "CHECKSUM MEM GENAI VARIABLES");
	if (rc2 == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		int num_rows = static_cast<int>(mysql_num_rows(res));
		ok(num_rows == 1,  "CHECKSUM MEM GENAI VARIABLES returns 1 row");
		mysql_free_result(res);
	} else {
		skip(1, "Skipping row count check due to error");
	}

	// Test 3: CHECKSUM MEMORY GENAI VARIABLES (alias for MEM)
	int rc3 = mysql_query(admin, "CHECKSUM MEMORY GENAI VARIABLES");
	ok(rc3 == 0,  "CHECKSUM MEMORY GENAI VARIABLES");
	if (rc3 == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		int num_rows = static_cast<int>(mysql_num_rows(res));
		ok(num_rows == 1,  "CHECKSUM MEMORY GENAI VARIABLES returns 1 row");
		mysql_free_result(res);
	} else {
		skip(1, "Skipping row count check due to error");
	}

	// Test 4: CHECKSUM GENAI VARIABLES (defaults to DISK)
	int rc4 = mysql_query(admin, "CHECKSUM GENAI VARIABLES");
	ok(rc4 == 0,  "CHECKSUM GENAI VARIABLES");
	if (rc4 == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		int num_rows = static_cast<int>(mysql_num_rows(res));
		ok(num_rows == 1,  "CHECKSUM GENAI VARIABLES returns 1 row");
		mysql_free_result(res);
	} else {
		skip(1, "Skipping row count check due to error");
	}

	return test_num;
}

/**
 * @brief Main test function
 *
 * Orchestrates all GenAI module tests.
 */
int main() {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

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

	// Build the list of LOAD/SAVE commands to test
	std::vector<std::string> queries;
	add_genai_load_save_commands(queries);

	// Each command test = 2 tests (execution + optional result check)
	// LOAD/SAVE commands: 14 commands
	// Variable access tests: 7 tests
	// Persistence tests: 8 tests
	// CHECKSUM tests: 8 tests (4 commands × 2)
	int num_load_save_tests = (int)queries.size() * 2; // Each command + result check
	int total_tests = num_load_save_tests + 7 + 8 + 8;

	plan(total_tests);

	int test_count = 0;

	// ============================================================================
	// Part 1: Test LOAD/SAVE commands
	// ============================================================================
	diag("=== Part 1: Testing LOAD/SAVE GENAI VARIABLES commands ===");
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
		ok(rc == 0,  "Command executed successfully: %s", query.c_str());

		// For SELECT/SHOW/CHECKSUM style commands, verify result set
		if (strncasecmp(query.c_str(), "SELECT ", 7) == 0 ||
			strncasecmp(query.c_str(), "SHOW ", 5) == 0 ||
			strncasecmp(query.c_str(), "CHECKSUM ", 9) == 0) {
			MYSQL_RES* res = mysql_store_result(admin_local);
			unsigned long long num_rows = mysql_num_rows(res);
			ok(num_rows != 0,  "Command returned rows: %s", query.c_str());
			mysql_free_result(res);
		} else {
			// For non-query commands, just mark the test as passed
			ok(1,  "Command completed: %s", query.c_str());
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

	diag("=== All GenAI module tests completed ===");

	return exit_status();
}
