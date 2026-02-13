/**
 * @file mcp_query_run_sql_readonly-t.cpp
 * @brief TAP test for MCP query endpoint - run_sql_readonly tool validation
 *
 * This test validates that the run_sql_readonly MCP tool properly rejects
 * non-SELECT queries and allows valid read-only queries.
 *
 * Replaces: test/tap/tests/mcp_rules_testing/test_run_sql_readonly_validation.sh
 *
 * Test coverage (20 TAP tests):
 * - Blocked queries: INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, TRUNCATE,
 *                    REPLACE, LOAD DATA, CALL, EXECUTE (11 tests)
 * - Allowed queries: SELECT variants, SHOW, DESCRIBE, WITH/CTE, EXPLAIN,
 *                    queries with comments (9 tests)
 *
 * Setup operations (not counted as tests):
 * - MCP server connectivity check
 * - MySQL connection
 * - Test database creation
 * - Test table creation with sample data
 *
 * Cleanup operations (not counted as tests):
 * - Drop test tables
 * - Close connections
 */

#include <string>
#include <algorithm>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mcp_client.h"

using json = nlohmann::json;

// Test case structure
struct query_test {
	const char* name;
	const char* sql;
};

// Blocked query test cases (11 tests) - all expect "not read-only" error
const query_test blocked_queries[] = {
	{"INSERT rejected", "INSERT INTO users (id, name) VALUES (1, 'test');"},
	{"UPDATE rejected", "UPDATE users SET name = 'test' WHERE id = 1;"},
	{"DELETE rejected", "DELETE FROM users WHERE id = 1;"},
	{"DROP TABLE rejected", "DROP TABLE IF EXISTS test_table;"},
	{"CREATE TABLE rejected", "CREATE TABLE test_table (id INT);"},
	{"ALTER TABLE rejected", "ALTER TABLE users ADD COLUMN email VARCHAR(255);"},
	{"TRUNCATE rejected", "TRUNCATE TABLE users;"},
	{"REPLACE rejected", "REPLACE INTO users (id, name) VALUES (1, 'test');"},
	{"LOAD DATA rejected", "LOAD DATA INFILE '/tmp/data.csv' INTO TABLE users;"},
	{"CALL rejected", "CALL test_procedure();"},
	{"EXECUTE rejected", "EXECUTE immediate 'SELECT 1';"}
};

// Allowed query test cases (9 tests)
const query_test allowed_queries[] = {
	{"SELECT with FROM allowed", "SELECT * FROM users;"},
	{"SELECT without FROM allowed", "SELECT (SELECT COUNT(*) FROM users);"},
	{"WITH clause (CTE) allowed", "WITH cte AS (SELECT * FROM users) SELECT * FROM cte;"},
	{"EXPLAIN SELECT allowed", "EXPLAIN SELECT * FROM users;"},
	{"SHOW TABLES allowed", "SHOW TABLES;"},
	{"SHOW DATABASES allowed", "SHOW DATABASES;"},
	{"DESCRIBE table allowed", "DESCRIBE users;"},
	{"SELECT with leading comment allowed", "-- This is a comment\nSELECT * FROM users;"},
	{"SELECT with multiple comments allowed", "-- First comment\n-- Second comment\nSELECT * FROM users;"}
};

// Helper function prototypes
void create_test_data(MYSQL* mysql);
void test_query_rejected(MCPClient& mcp, const std::string& test_name,
                        const std::string& sql, const std::string& expected_error);
void test_query_allowed(MCPClient& mcp, const std::string& test_name,
                       const std::string& sql);

int main(int argc, char** argv) {
	plan(20);

	// ====================================================================
	// Setup Phase
	// ====================================================================

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get required environmental variables.");
		return exit_status();
	}

	MYSQL* admin = nullptr;
	MYSQL* mysql = nullptr;
	MCPClient* mcp = nullptr;

	diag("Testing MCP run_sql_readonly tool validation");

	// Setup 1: Initialize MCP client and check server connectivity
	mcp = new MCPClient(cl.host, cl.mcp_port);
	if (strlen(cl.mcp_auth_token) > 0) {
		mcp->set_auth_token(cl.mcp_auth_token);
	}
	if (!mcp->check_server()) {
		diag("MCP server not accessible at %s", mcp->get_connection_info().c_str());
		goto cleanup;
	}

	// Setup 2: Connect to Admin interface and MySQL backend 
	admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		diag("ProxySQL admin connection failed");
		goto cleanup;
	}

	mysql = init_mysql_conn(cl.mysql_host, cl.mysql_port, cl.mysql_username, cl.mysql_password);
	if (!mysql) {
		diag("MySQL backend connection failed");
		goto cleanup;
	}

	// Setup 3: Configure MCP MySQL connection parameters
	MYSQL_QUERY_T(admin, "SET mcp-mysql_hosts='" + std::string(cl.mysql_host) + "'");
	MYSQL_QUERY_T(admin, "SET mcp-mysql_ports=" + std::to_string(cl.mysql_port));
	MYSQL_QUERY_T(admin, "SET mcp-mysql_username='" + std::string(cl.mysql_username) + "'");
	MYSQL_QUERY_T(admin, "SET mcp-mysql_password='" + std::string(cl.mysql_password) + "'");
	MYSQL_QUERY_T(admin, "LOAD MCP VARIABLES TO RUNTIME");

	// Setup 4: Create test database and tables
	create_test_data(mysql);

	// ====================================================================
	// Blocked Query Tests (11 tests) - should be REJECTED
	// ====================================================================

	diag("--- Testing blocked queries (should be REJECTED) ---");
	for (const auto& test : blocked_queries) {
		test_query_rejected(*mcp, test.name, test.sql, "not read-only");
	}

	// ====================================================================
	// Allowed Query Tests (9 tests) - should be ALLOWED
	// ====================================================================

	diag("--- Testing allowed queries (should be ALLOWED) ---");
	for (const auto& test : allowed_queries) {
		test_query_allowed(*mcp, test.name, test.sql);
	}

	// ====================================================================
	// Cleanup Phase
	// ====================================================================

cleanup:
	if (mysql) {
		MYSQL_QUERY_T(mysql, "DROP TABLE IF EXISTS test.users");
		MYSQL_QUERY_T(mysql, "DROP TABLE IF EXISTS test.products");
		mysql_close(mysql);
	}

	if (mcp) {
		delete mcp;
	}

	return exit_status();
}

// Helper function implementations

void create_test_data(MYSQL* mysql) {
	run_q(mysql, "CREATE DATABASE IF NOT EXISTS test");
	run_q(mysql, "USE test");

	run_q(mysql, "DROP TABLE IF EXISTS products");
	run_q(mysql, "DROP TABLE IF EXISTS users");

	run_q(mysql, "CREATE TABLE users ("
		"id INT PRIMARY KEY, "
		"name VARCHAR(100), "
		"email VARCHAR(255))");
	run_q(mysql, "CREATE TABLE products ("
		"id INT PRIMARY KEY, "
		"name VARCHAR(100), "
		"price DECIMAL(10,2))");
	run_q(mysql, "INSERT INTO users VALUES "
		"(1, 'Alice', 'alice@example.com'), "
		"(2, 'Bob', 'bob@example.com')");
	run_q(mysql, "INSERT INTO products VALUES "
		"(1, 'Widget', 19.99), "
		"(2, 'Gadget', 29.99)");
}

void test_query_rejected(MCPClient& mcp, const std::string& test_name,
                        const std::string& sql, const std::string& expected_error) {
	json args = {{"sql", sql}, {"schema", "test"}};
	MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);

	// Prepare values before ok() - keep ok() expression clean
	std::string error_msg = resp.get_error_message();
	std::string error_lower = error_msg;
	std::string expected_lower = expected_error;
	std::transform(error_lower.begin(), error_lower.end(), error_lower.begin(), ::tolower);
	std::transform(expected_lower.begin(), expected_lower.end(), expected_lower.begin(), ::tolower);

	bool is_rejected = resp.is_mcp_error();
	bool error_matches = error_lower.find(expected_lower) != std::string::npos;

	ok(is_rejected && error_matches,
	   "%s - Expected error containing '%s', got: '%s'",
	   test_name.c_str(), expected_error.c_str(), error_msg.c_str());
}

void test_query_allowed(MCPClient& mcp, const std::string& test_name,
                       const std::string& sql) {
	json args = {{"sql", sql}, {"schema", "test"}};
	MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);

	// Prepare values before ok() - avoid operators in ok()
	bool is_success = resp.is_success();
	std::string error_msg = is_success ? "none" : resp.get_error_message();

	ok(is_success,
	   "%s - Expected error: none, got: %s",
	   test_name.c_str(), error_msg.c_str());
}
