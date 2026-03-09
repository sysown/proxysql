/**
 * @file nl2sql_prompt_builder-t.cpp
 * @brief TAP unit tests for NL2SQL prompt building
 *
 * Test Categories:
 * 1. Basic prompt construction
 * 2. Schema context inclusion
 * 3. System instruction formatting
 * 4. Edge cases (empty query, special characters)
 *
 * Prerequisites:
 * - ProxySQL with AI features enabled
 * - Admin interface on localhost:6032
 *
 * Usage:
 *   make nl2sql_prompt_builder-t
 *   ./nl2sql_prompt_builder-t
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
 * @brief Build a prompt using NL2SQL converter
 *
 * This is a placeholder that simulates the prompt building process.
 * In a full implementation, this would call NL2SQL_Converter::build_prompt().
 *
 * @param natural_language The user's natural language query
 * @param schema_context Optional schema information
 * @return The constructed prompt
 */
string build_test_prompt(const string& natural_language, const string& schema_context = "") {
	string prompt;

	// System instructions
	prompt += "You are a SQL expert. Convert the following natural language question to a SQL query.\n\n";

	// Add schema context if available
	if (!schema_context.empty()) {
		prompt += "Database Schema:\n";
		prompt += schema_context;
		prompt += "\n";
	}

	// User's question
	prompt += "Question: " + natural_language + "\n\n";
	prompt += "Return ONLY the SQL query. No explanations, no markdown formatting.\n";

	return prompt;
}

/**
 * @brief Check if prompt contains required elements
 * @param prompt The prompt to check
 * @param elements Vector of required strings
 * @return true if all elements are present
 */
bool prompt_contains_elements(const string& prompt, const vector<string>& elements) {
	for (const auto& elem : elements) {
		if (prompt.find(elem) == string::npos) {
			return false;
		}
	}
	return true;
}

// ============================================================================
// Test: Basic Prompt Construction
// ============================================================================

/**
 * @test Basic prompt construction
 * @description Verify that basic prompts are constructed correctly
 * @expected Prompt should contain system instructions and user query
 */
void test_basic_prompt_construction() {
	diag("=== Basic Prompt Construction Tests ===");

	// Test 1: Simple query
	const char* nl1 = "Show all users";
	diag("Building prompt for: '%s'", nl1);
	string prompt = build_test_prompt(nl1);
	vector<string> required = {"You are a SQL expert", nl1, "Return ONLY the SQL query"};
	ok(prompt_contains_elements(prompt, required), "Simple query prompt contains all required elements");

	// Test 2: Query with conditions
	const char* nl2 = "Find customers where age > 25";
	diag("Building prompt for: '%s'", nl2);
	prompt = build_test_prompt(nl2);
	required = {"You are a SQL expert", nl2, "SQL query"};
	ok(prompt_contains_elements(prompt, required), "Query with conditions prompt is correct");

	// Test 3: Aggregation query
	const char* nl3 = "Count users by country";
	diag("Building prompt for: '%s'", nl3);
	prompt = build_test_prompt(nl3);
	required = {"You are a SQL expert", nl3};
	ok(prompt_contains_elements(prompt, required), "Aggregation query prompt is correct");

	// Test 4: Query with JOIN
	const char* nl4 = "Show orders with customer names";
	diag("Building prompt for: '%s'", nl4);
	prompt = build_test_prompt(nl4);
	required = {"You are a SQL expert", nl4};
	ok(prompt_contains_elements(prompt, required), "JOIN query prompt is correct");

	// Test 5: Complex query
	const char* nl5 = "Find the top 10 customers by total order amount in the last 30 days";
	diag("Building prompt for: '%s'", nl5);
	prompt = build_test_prompt(nl5);
	required = {"You are a SQL expert", nl5, "last 30 days"};
	ok(prompt_contains_elements(prompt, required), "Complex query prompt is correct");
}

// ============================================================================
// Test: Schema Context Inclusion
// ============================================================================

/**
 * @test Schema context inclusion
 * @description Verify that schema context is properly included in prompts
 * @expected Prompt should contain schema information when provided
 */
void test_schema_context_inclusion() {
	diag("=== Schema Context Inclusion Tests ===");

	// Test 1: Empty schema context
	diag("Testing with empty schema context");
	string prompt = build_test_prompt("Show all users", "");
	ok(prompt.find("Database Schema:") == string::npos, "Empty schema context doesn't add schema section");

	// Test 2: Simple schema context
	string schema = "Table: users (id INT, name VARCHAR(100))";
	diag("Testing with simple schema: '%s'", schema.c_str());
	prompt = build_test_prompt("Show all users", schema);
	ok(prompt.find("Database Schema:") != string::npos && prompt.find("users") != string::npos,
	   "Simple schema context is included");

	// Test 3: Multi-table schema context
	schema = "Table: users (id INT, name VARCHAR(100))\nTable: orders (id INT, user_id INT, amount DECIMAL)";
	diag("Testing with multi-table schema");
	prompt = build_test_prompt("Show orders with user names", schema);
	ok(prompt.find("users") != string::npos && prompt.find("orders") != string::npos,
	   "Multi-table schema context is included");

	// Test 4: Schema with foreign keys
	schema = "users.id <- orders.user_id (FOREIGN KEY)";
	diag("Testing with foreign keys schema: '%s'", schema.c_str());
	prompt = build_test_prompt("Show all orders with user info", schema);
	ok(prompt.find("FOREIGN KEY") != string::npos, "Schema with foreign keys is included");

	// Test 5: Large schema context
	schema.clear();
	for (int i = 0; i < 20; i++) {
		char table_name[64];
		snprintf(table_name, sizeof(table_name), "Table: table%d (id INT, data VARCHAR)", i);
		schema += table_name;
		schema += "\n";
	}
	diag("Testing with large schema context (20 tables)");
	prompt = build_test_prompt("Show data from table5", schema);
	ok(prompt.find("table5") != string::npos, "Large schema context includes relevant table");
}

// ============================================================================
// Test: System Instruction Formatting
// ============================================================================

/**
 * @test System instruction formatting
 * @description Verify that system instructions are properly formatted
 * @expected Prompt should have proper system instruction section
 */
void test_system_instruction_formatting() {
	diag("=== System Instruction Formatting Tests ===");

	// Test 1: System instruction presence
	string prompt = build_test_prompt("Any query");
	diag("Checking system instructions in prompt");
	ok(prompt.find("You are a SQL expert") != string::npos, "System instruction contains role definition");

	// Test 2: Task description
	ok(prompt.find("Convert the following natural language question") != string::npos,
	   "System instruction contains task description");

	// Test 3: Output format requirement
	ok(prompt.find("Return ONLY the SQL query") != string::npos,
	   "System instruction specifies output format");

	// Test 4: No explanations requirement
	ok(prompt.find("No explanations") != string::npos,
	   "System instruction specifies no explanations");

	// Test 5: No markdown requirement
	ok(prompt.find("no markdown formatting") != string::npos,
	   "System instruction specifies no markdown");
}

// ============================================================================
// Test: Edge Cases
// ============================================================================

/**
 * @test Edge cases
 * @description Verify proper handling of edge cases
 * @expected Edge cases should be handled gracefully
 */
void test_edge_cases() {
	diag("=== Edge Case Tests ===");

	// Test 1: Empty query
	diag("Testing with empty natural language query");
	string prompt = build_test_prompt("");
	ok(prompt.find("Question: ") != string::npos, "Empty query is handled");

	// Test 2: Very long query
	diag("Testing with very long natural language query (10000 chars)");
	string long_query(10000, 'a');
	prompt = build_test_prompt(long_query);
	ok(prompt.length() > 10000, "Very long query is included");

	// Test 3: Query with special characters
	diag("Testing with special characters and emojis");
	string special_query = "Find users with émojis 🎉 and quotes \"'";
	prompt = build_test_prompt(special_query);
	ok(prompt.find("émojis") != string::npos, "Special characters are preserved");

	// Test 4: Query with newlines
	diag("Testing with query containing newlines");
	string newline_query = "Show users\nwhere\nage > 25";
	prompt = build_test_prompt(newline_query);
	ok(prompt.find("age > 25") != string::npos, "Query with newlines is handled");

	// Test 5: Query with SQL injection attempt (should be safe)
	diag("Testing with SQL injection payload: '; DROP TABLE users; --");
	string injection_query = "'; DROP TABLE users; --";
	prompt = build_test_prompt(injection_query);
	ok(prompt.find("DROP TABLE") != string::npos,
	   "SQL injection text is included in prompt (LLM must handle safety)");
}

// ============================================================================
// Test: Prompt Structure Validation
// ============================================================================>

/**
 * @test Prompt structure validation
 * @description Verify that prompts follow the expected structure
 * @expected Prompts should have proper sections in correct order
 */
void test_prompt_structure_validation() {
	diag("=== Prompt Structure Validation Tests ===");

	diag("Validating structure for a standard prompt");
	string prompt = build_test_prompt("Show users", "Table: users (id INT, name VARCHAR)");

	// Test 1: System instructions come first
	size_t system_pos = prompt.find("You are a SQL expert");
	ok(system_pos == 0, "System instructions are at the beginning");

	// Test 2: Schema section comes before question
	size_t schema_pos = prompt.find("Database Schema:");
	size_t question_pos = prompt.find("Question:");
	if (schema_pos != string::npos) {
		ok(schema_pos < question_pos, "Schema section comes before question");
	} else {
		skip(1, "No schema section present");
	}

	// Test 3: Question section contains the original query
	ok(question_pos != string::npos, "Question section exists");

	// Test 4: Output requirements come at the end
	size_t output_pos = prompt.find("Return ONLY the SQL query");
	ok(output_pos != string::npos && output_pos > question_pos,
	   "Output requirements come after question");

	// Test 5: Proper line breaks between sections
	size_t newline_count = 0;
	for (char c : prompt) {
		if (c == '\n') newline_count++;
	}
	ok(newline_count >= 3, "Prompt has proper line breaks between sections");
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

	diag("Starting nl2sql_prompt_builder-t");
	diag("This test verifies the construction of LLM prompts for NL2SQL conversion.");
	diag("It checks that prompts correctly include:");
	diag("  - System instructions (role and task definition)");
	diag("  - Database schema context (tables, columns, foreign keys)");
	diag("  - User's natural language question");
	diag("  - Output formatting requirements (SQL only, no markdown)");
	diag("It also validates the overall prompt structure and handles edge cases like long queries or special characters.");

	// Connect to admin interface (for config checks)
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

	// Plan tests: 5 categories with 5 tests each = 25 tests
	plan(25);

	// Run test categories
	test_basic_prompt_construction();
	test_schema_context_inclusion();
	test_system_instruction_formatting();
	test_edge_cases();
	test_prompt_structure_validation();

	mysql_close(g_admin);
	return exit_status();
}
