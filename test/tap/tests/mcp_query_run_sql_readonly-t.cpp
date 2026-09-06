/**
 * @file mcp_query_run_sql_readonly-t.cpp
 * @brief TAP test for MCP query endpoint - run_sql_readonly tool validation
 *
 * This test validates that run_sql_readonly rejects non-read-only SQL and
 * allows valid read-only SQL when routed via a profile-based target_id.
 */

#include <algorithm>
#include <string>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mcp_client.h"

using json = nlohmann::json;

struct query_test {
	const char* name;
	const char* sql;
};

static const char* k_test_schema = "test";
static const char* k_target_id = "tap_mysql_readonly_target";
static const char* k_auth_profile_id = "tap_mysql_readonly_auth";
static const int k_hostgroup_id = 9110;

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

const query_test allowed_queries[] = {
	{"SELECT with FROM allowed", "SELECT * FROM users;"},
	{"SELECT without FROM allowed", "SELECT (SELECT COUNT(*) FROM users);"},
	// {"WITH clause (CTE) allowed", "WITH cte AS (SELECT * FROM users) SELECT * FROM cte;"},  // Disabled: MySQL 5.7 doesn't support CTEs
	{"EXPLAIN SELECT allowed", "EXPLAIN SELECT * FROM users;"},
	{"SHOW TABLES allowed", "SHOW TABLES;"},
	{"SHOW DATABASES allowed", "SHOW DATABASES;"},
	{"DESCRIBE table allowed", "DESCRIBE users;"},
	{"SELECT with leading comment allowed", "-- This is a comment\nSELECT * FROM users;"},
	{"SELECT with multiple comments allowed", "-- First comment\n-- Second comment\nSELECT * FROM users;"}
};

std::string escape_sql_literal(const std::string& input) {
	std::string escaped;
	escaped.reserve(input.size());
	for (char c : input) {
		escaped.push_back(c);
		if (c == '\'') {
			escaped.push_back('\'');
		}
	}
	return escaped;
}

bool configure_mcp_for_test(MYSQL* admin, const CommandLine& cl) {
	const std::string mysql_host = escape_sql_literal(cl.mysql_host);
	const std::string mysql_user = escape_sql_literal(cl.mysql_username);
	const std::string mysql_password = escape_sql_literal(cl.mysql_password);
	const std::string default_schema = escape_sql_literal(k_test_schema);
	const std::string auth_token = escape_sql_literal(cl.mcp_auth_token);

	const std::string q1 = "SET mcp-port=" + std::to_string(cl.mcp_port);
	const std::string q2 = "SET mcp-use_ssl=false";
	const std::string q3 = "SET mcp-enabled=true";
	const std::string q_config_auth =
		"SET mcp-config_endpoint_auth='" + auth_token + "'";
	const std::string q_query_auth =
		"SET mcp-query_endpoint_auth='" + auth_token + "'";
	const std::string q4 = "DELETE FROM mcp_target_profiles WHERE target_id='" + std::string(k_target_id) + "'";
	const std::string q5 = "DELETE FROM mcp_auth_profiles WHERE auth_profile_id='" + std::string(k_auth_profile_id) + "'";
	const std::string q6 =
		"INSERT INTO mcp_auth_profiles (auth_profile_id, db_username, db_password, default_schema, use_ssl, ssl_mode, comment) VALUES "
		"('" + std::string(k_auth_profile_id) + "', '" + mysql_user + "', '" + mysql_password + "', '" + default_schema + "', 0, '', 'TAP MCP readonly auth')";
	const std::string q7 =
		"INSERT INTO mcp_target_profiles (target_id, protocol, hostgroup_id, auth_profile_id, description, max_rows, timeout_ms, allow_explain, allow_discovery, active, comment) VALUES "
		"('" + std::string(k_target_id) + "', 'mysql', " + std::to_string(k_hostgroup_id) + ", '" + std::string(k_auth_profile_id) + "', 'TAP readonly target', 200, 5000, 1, 1, 1, 'TAP test target')";
	const std::string q8 = "DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(k_hostgroup_id);
	const std::string q9 =
		"INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, comment) VALUES (" + std::to_string(k_hostgroup_id) + ", '" + mysql_host + "', "
		+ std::to_string(cl.mysql_port) + ", 'ONLINE', 1, 'TAP MCP readonly backend')";
	const std::string q10 = "LOAD MCP VARIABLES TO RUNTIME";
	const std::string q11 = "LOAD MCP PROFILES TO RUNTIME";
	const std::string q12 = "LOAD MYSQL SERVERS TO RUNTIME";

	return run_q(admin, q1.c_str()) == 0 &&
	       run_q(admin, q2.c_str()) == 0 &&
	       run_q(admin, q3.c_str()) == 0 &&
	       run_q(admin, q_config_auth.c_str()) == 0 &&
	       run_q(admin, q_query_auth.c_str()) == 0 &&
	       run_q(admin, q4.c_str()) == 0 &&
	       run_q(admin, q5.c_str()) == 0 &&
	       run_q(admin, q6.c_str()) == 0 &&
	       run_q(admin, q7.c_str()) == 0 &&
	       run_q(admin, q8.c_str()) == 0 &&
	       run_q(admin, q9.c_str()) == 0 &&
	       run_q(admin, q10.c_str()) == 0 &&
	       run_q(admin, q11.c_str()) == 0 &&
	       run_q(admin, q12.c_str()) == 0;
}

void create_test_data(MYSQL* mysql) {
	run_q(mysql, "CREATE DATABASE IF NOT EXISTS test");
	run_q(mysql, "USE test");

	run_q(mysql, "DROP TABLE IF EXISTS products");
	run_q(mysql, "DROP TABLE IF EXISTS users");

	run_q(mysql, "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100), email VARCHAR(255))");
	run_q(mysql, "CREATE TABLE products (id INT PRIMARY KEY, name VARCHAR(100), price DECIMAL(10,2))");
	run_q(mysql, "INSERT INTO users VALUES (1, 'Alice', 'alice@example.com'), (2, 'Bob', 'bob@example.com')");
	run_q(mysql, "INSERT INTO products VALUES (1, 'Widget', 19.99), (2, 'Gadget', 29.99)");
}

void test_query_rejected(MCPClient& mcp, const std::string& test_name, const std::string& sql, const std::string& expected_error) {
	json args = {{"sql", sql}, {"schema", k_test_schema}, {"target_id", k_target_id}};
	MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);

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

void test_query_allowed(MCPClient& mcp, const std::string& test_name, const std::string& sql) {
	json args = {{"sql", sql}, {"schema", k_test_schema}, {"target_id", k_target_id}};
	MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);

	bool is_success = resp.is_success();
	std::string error_msg = is_success ? "none" : resp.get_error_message();

	ok(is_success,
	   "%s - Expected error: none, got: %s",
	   test_name.c_str(), error_msg.c_str());
}

int main(int argc, char** argv) {
	plan(19);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get required environmental variables.");
		return exit_status();
	}

	diag("=== MCP Query Endpoint: run_sql_readonly Tool Validation ===");
	diag("This test validates the MCP query endpoint's run_sql_readonly tool.");
	diag("It ensures that only read-only SQL statements are allowed when routed");
	diag("via a profile-based target_id. Blocked statements include INSERT, UPDATE,");
	diag("DELETE, DROP, CREATE, ALTER, TRUNCATE, REPLACE, LOAD DATA, CALL, and EXECUTE.");
	diag("Allowed statements include SELECT, WITH (CTE), EXPLAIN SELECT, SHOW, and DESCRIBE.");
	diag("===========================================================================");

	MYSQL* admin = NULL;
	MYSQL* mysql = NULL;
	MCPClient* mcp = NULL;

	diag("Testing MCP run_sql_readonly tool validation");

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

	create_test_data(mysql);

	if (!configure_mcp_for_test(admin, cl)) {
		diag("Failed to configure MCP profile-based routing for test");
		goto cleanup;
	}

	mcp = new MCPClient(cl.admin_host, cl.mcp_port);
	if (strlen(cl.mcp_auth_token) > 0) {
		mcp->set_auth_token(cl.mcp_auth_token);
	}

	if (!mcp->check_server()) {
		diag("MCP server not accessible at %s", mcp->get_connection_info().c_str());
		goto cleanup;
	}

	diag("--- Testing blocked queries (should be REJECTED) ---");
	for (const auto& test : blocked_queries) {
		test_query_rejected(*mcp, test.name, test.sql, "not read-only");
	}

	diag("--- Testing allowed queries (should be ALLOWED) ---");
	for (const auto& test : allowed_queries) {
		test_query_allowed(*mcp, test.name, test.sql);
	}

cleanup:
	if (mysql) {
		run_q(mysql, "DROP TABLE IF EXISTS test.users");
		run_q(mysql, "DROP TABLE IF EXISTS test.products");
		mysql_close(mysql);
	}
	if (admin) {
		if (run_q(admin, "LOAD MCP VARIABLES FROM DISK") != 0) {
			diag("Failed to restore MCP variables from disk: %s", mysql_error(admin));
		} else if (run_q(admin, "LOAD MCP VARIABLES TO RUNTIME") != 0) {
			diag("Failed to apply restored MCP variables: %s", mysql_error(admin));
		}
		run_q(admin, ("DELETE FROM mcp_target_profiles WHERE target_id='" + std::string(k_target_id) + "'").c_str());
		run_q(admin, ("DELETE FROM mcp_auth_profiles WHERE auth_profile_id='" + std::string(k_auth_profile_id) + "'").c_str());
		run_q(admin, ("DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(k_hostgroup_id)).c_str());
		run_q(admin, "LOAD MCP PROFILES TO RUNTIME");
		run_q(admin, "LOAD MYSQL SERVERS TO RUNTIME");
		mysql_close(admin);
	}
	if (mcp) {
		delete mcp;
	}

	return exit_status();
}
