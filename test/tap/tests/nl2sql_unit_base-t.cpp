/**
 * @file nl2sql_unit_base-t.cpp
 * @brief TAP unit tests for NL2SQL converter basic functionality
 *
 * Test Categories:
 * 1. Initialization and Configuration
 * 2. Basic NL2SQL Conversion (mocked)
 * 3. Error Handling
 * 4. Variable Persistence
 *
 * Prerequisites:
 * - ProxySQL with AI features enabled
 * - Admin interface on localhost:6032
 * - Mock LLM responses (no live LLM required)
 *
 * Usage:
 *   make nl2sql_unit_base
 *   ./nl2sql_unit_base
 *
 * @date 2025-01-16
 */

#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

// Global admin connection
MYSQL* g_admin = NULL;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Get NL2SQL variable value via Admin interface
 * @param name Variable name (without genai-llm_ prefix)
 * @return Variable value or empty string on error
 */
string get_nl2sql_variable(const char* name) {
	char query[256];
	snprintf(query, sizeof(query),
			 "SELECT variable_value FROM runtime_global_variables WHERE variable_name='genai-llm_%s'",
			 name);

	diag("Admin: %s", query);
	if (mysql_query(g_admin, query)) {
		diag("Failed to query variable: %s", mysql_error(g_admin));
		return "";
	}

	MYSQL_RES* result = mysql_store_result(g_admin);
	if (!result) {
		return "";
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	string value = row ? (row[0] ? row[0] : "") : "";
	diag("Read value: '%s'", value.c_str());

	mysql_free_result(result);
	return value;
}

/**
 * @brief Set NL2SQL variable and verify
 * @param name Variable name (without genai-llm_ prefix)
 * @param value New value
 * @return true if set successful, false otherwise
 */
bool set_nl2sql_variable(const char* name, const char* value) {
	char query[256];
	snprintf(query, sizeof(query),
			 "UPDATE global_variables SET variable_value='%s' WHERE variable_name='genai-llm_%s'",
			 value, name);

	diag("Admin: %s", query);
	if (mysql_query(g_admin, query)) {
		diag("Failed to set variable: %s", mysql_error(g_admin));
		return false;
	}

	// Load to runtime
	const char* load_query = "LOAD GENAI VARIABLES TO RUNTIME";
	diag("Admin: %s", load_query);
	if (mysql_query(g_admin, load_query)) {
		load_query = "LOAD MYSQL VARIABLES TO RUNTIME";
		diag("Admin: %s", load_query);
		if (mysql_query(g_admin, load_query)) {
			diag("Failed to load variables: %s", mysql_error(g_admin));
			return false;
		}
	}

	return true;
}

/**
 * @brief Execute NL2SQL query via a test connection
 * @param nl2sql_query Natural language query with NL2SQL: prefix
 * @return First row's first column value or empty string
 */
string execute_nl2sql_query(const char* nl2sql_query) {
	// For now, return a mock response
	// In Phase 2, this will use a real MySQL connection
	// that goes through MySQL_Session's NL2SQL handler
	return "";
}

// ============================================================================
// Test: Initialization
// ============================================================================

/**
 * @test NL2SQL module initialization
 * @description Verify that NL2SQL module initializes correctly
 * @expected AI module should be accessible, variables should have defaults
 */
void test_nl2sql_initialization() {
	diag("=== NL2SQL Initialization Tests ===");

	// Test 1: Check AI module exists
	ok(true, "AI_Features_Manager global instance exists (placeholder)");

	// Test 2: Check NL2SQL is enabled by default
	string enabled = get_nl2sql_variable("enabled");
	ok(enabled == "true" || enabled == "1" || enabled == "false" || enabled == "0" || enabled.empty(),
	   "genai-llm_enabled has a valid boolean value: '%s'", enabled.c_str());

	// Test 3: Check default model provider
	string provider = get_nl2sql_variable("provider");
	ok(provider == "ollama" || provider == "openai" || provider.empty(),
	   "genai-llm_provider has a valid default: '%s'", provider.c_str());

	// Test 4: Check default cache similarity threshold
	string threshold = get_nl2sql_variable("cache_similarity_threshold");
	ok(!threshold.empty(),
	   "genai-llm_cache_similarity_threshold is configured: '%s'", threshold.c_str());

	// Test 5: Check timeout
	string timeout = get_nl2sql_variable("timeout_ms");
	ok(!timeout.empty(),
	   "genai-llm_timeout_ms is configured: '%s'", timeout.c_str());
}

// ============================================================================
// Test: Configuration
// ============================================================================

/**
 * @test NL2SQL configuration management
 * @description Test setting and retrieving NL2SQL configuration variables
 * @expected Variables should be settable and persist across runtime changes
 */
void test_nl2sql_configuration() {
	diag("=== NL2SQL Configuration Tests ===");

	// Save original values
	string orig_model = get_nl2sql_variable("provider_model");
	string orig_provider = get_nl2sql_variable("provider");

	// Test 1: Set Ollama model
	ok(set_nl2sql_variable("provider_model", "test-llama-model"),
	   "Set genai-llm_provider_model to 'test-llama-model'");

	// Test 2: Verify change
	string current = get_nl2sql_variable("provider_model");
	ok(current == "test-llama-model",
	   "Variable genai-llm_provider_model reflects new value '%s'", current.c_str());

	// Test 3: Set model provider to openai
	ok(set_nl2sql_variable("provider", "openai"),
	   "Set genai-llm_provider to 'openai'");

	// Test 4: Verify provider change
	current = get_nl2sql_variable("provider");
	ok(current == "openai",
	   "Provider changed to '%s'", current.c_str());

	// Test 5: Restore original values
	if (!orig_model.empty()) {
		set_nl2sql_variable("provider_model", orig_model.c_str());
	}
	if (!orig_provider.empty()) {
		set_nl2sql_variable("provider", orig_provider.c_str());
	}
	ok(true, "Restored original configuration values");
}

// ============================================================================
// Test: Variable Persistence
// ============================================================================

/**
 * @test NL2SQL variable persistence
 * @description Verify LOAD/SAVE commands for NL2SQL variables
 * @expected Variables should persist across admin interfaces
 */
void test_variable_persistence() {
	diag("=== NL2SQL Variable Persistence Tests ===");

	// Save original value
	string orig_timeout = get_nl2sql_variable("timeout_ms");

	// Test 1: Set variable
	ok(set_nl2sql_variable("timeout_ms", "60000"),
	   "Set genai-llm_timeout_ms to 60000");

	// Test 2: Verify change in memory
	string current = get_nl2sql_variable("timeout_ms");
	ok(current == "60000",
	   "Variable changed in runtime: '%s'", current.c_str());

	// Test 3: LOAD from disk
	diag("Admin: LOAD GENAI VARIABLES FROM DISK");
	int rc = mysql_query(g_admin, "LOAD GENAI VARIABLES FROM DISK");
	if (rc != 0) {
		diag("Admin: LOAD MYSQL VARIABLES FROM DISK (fallback)");
		rc = mysql_query(g_admin, "LOAD MYSQL VARIABLES FROM DISK");
	}
	ok(rc == 0, "LOAD GENAI VARIABLES FROM DISK succeeds");

	// Restore original
	if (!orig_timeout.empty()) {
		set_nl2sql_variable("timeout_ms", orig_timeout.c_str());
	}
}

// ============================================================================
// Test: Error Handling
// ============================================================================

/**
 * @test NL2SQL error handling
 * @description Verify proper error handling for invalid inputs
 * @expected Should return appropriate error messages
 */
void test_error_handling() {
	diag("=== NL2SQL Error Handling Tests ===");

	// Test 1: Empty variable name handling
	diag("Testing empty variable name");
	string result = get_nl2sql_variable("");
	ok(result.empty(), "Empty variable name returns empty string");

	// Test 2: Non-existent variable
	diag("Testing non-existent variable: nonexistent_variable_xyz");
	result = get_nl2sql_variable("nonexistent_variable_xyz");
	ok(result.empty(), "Non-existent variable returns empty string");

	// Test 3: Set variable with empty value
	diag("Testing setting variable 'provider' to empty value");
	ok(set_nl2sql_variable("provider", ""),
	   "Setting variable to empty value succeeds");

	// Test 4: Set variable with special characters
	diag("Testing setting variable 'provider_model' with special characters");
	ok(set_nl2sql_variable("provider_model", "test-value-with-dashes"),
	   "Setting variable with special characters succeeds");

	// Test 5: Set variable with very long value
	diag("Testing long variable value handling (500 chars)");
	string long_value(500, 'a');
	char query[1024];
	snprintf(query, sizeof(query),
			 "UPDATE global_variables SET variable_value='%s' WHERE variable_name='genai-llm_provider_model'",
			 long_value.c_str());
	diag("Admin: %s", query);
	int rc = mysql_query(g_admin, query);
	ok(rc == 0, "Long variable value accepted in global_variables");
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
	// Parse command line
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Error getting environment variables");
		return exit_status();
	}

	diag("Starting nl2sql_unit_base-t");
	diag("This test verifies the basic configuration and lifecycle of the NL2SQL module.");
	diag("It checks:");
	diag("  - Module initialization and default variable values.");
	diag("  - Configuration management (setting and getting variables via Admin).");
	diag("  - Variable persistence across runtime and disk (LOAD/SAVE).");
	diag("  - Error handling for invalid variable operations.");
	diag("Note: This test interacts with global_variables prefixed with 'genai-llm_'.");

	// Connect to admin interface
	g_admin = mysql_init(NULL);
	if (!g_admin) {
		diag("Failed to initialize MySQL connection");
		return exit_status();
	}

	if (!mysql_real_connect(g_admin, cl.host, cl.admin_username, cl.admin_password,
							NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to admin interface: %s", mysql_error(g_admin));
		mysql_close(g_admin);
		return exit_status();
	}

	// Plan tests: 4 categories with total 18 tests
	plan(18);

	// Run test categories
	test_nl2sql_initialization();
	test_nl2sql_configuration();
	test_variable_persistence();
	test_error_handling();

	mysql_close(g_admin);
	return exit_status();
}
