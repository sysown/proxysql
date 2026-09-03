/**
 * @file test_stats_mcp_tables-t.cpp
 * @brief E2E test for stats_mcp_* tables registered by the genai plugin.
 *
 * Sends MCP traffic to populate in-memory counters, then verifies that
 * SELECT against stats_mcp_query_digest, stats_mcp_query_tools_counters,
 * and stats_mcp_query_rules returns correct data via the admin interface.
 * Also verifies _reset semantics (selecting _reset clears counters).
 */

#include <cstring>
#include <string>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mcp_client.h"

using json = nlohmann::json;

static const char* k_test_schema = "test";
static const char* k_target_id = "tap_stats_test_target";
static const char* k_auth_profile_id = "tap_stats_test_auth";
static const int k_hostgroup_id = 9120;

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

bool configure_mcp(MYSQL* admin, const CommandLine& cl) {
	const std::string mysql_host = escape_sql_literal(cl.mysql_host);
	const std::string mysql_user = escape_sql_literal(cl.mysql_username);
	const std::string mysql_password = escape_sql_literal(cl.mysql_password);
	const std::string default_schema = escape_sql_literal(k_test_schema);
	const std::string auth_token = escape_sql_literal(cl.mcp_auth_token);

	const std::string queries[] = {
		"SET mcp-port=" + std::to_string(cl.mcp_port),
		"SET mcp-use_ssl=false",
		"SET mcp-enabled=true",
		"SET mcp-config_endpoint_auth='" + auth_token + "'",
		"SET mcp-query_endpoint_auth='" + auth_token + "'",
		"DELETE FROM mcp_target_profiles WHERE target_id='" + std::string(k_target_id) + "'",
		"DELETE FROM mcp_auth_profiles WHERE auth_profile_id='" + std::string(k_auth_profile_id) + "'",
		"INSERT INTO mcp_auth_profiles (auth_profile_id, db_username, db_password, default_schema, use_ssl, ssl_mode, comment) VALUES "
		"('" + std::string(k_auth_profile_id) + "', '" + mysql_user + "', '" + mysql_password + "', '" + default_schema + "', 0, '', 'stats test auth')",
		"INSERT INTO mcp_target_profiles (target_id, protocol, hostgroup_id, auth_profile_id, description, max_rows, timeout_ms, allow_explain, allow_discovery, active, comment) VALUES "
		"('" + std::string(k_target_id) + "', 'mysql', " + std::to_string(k_hostgroup_id) + ", '" + std::string(k_auth_profile_id) + "', 'stats test target', 200, 5000, 1, 1, 1, 'stats test')",
		"DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(k_hostgroup_id),
		"INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, comment) VALUES (" + std::to_string(k_hostgroup_id) + ", '" + mysql_host + "', "
		+ std::to_string(cl.mysql_port) + ", 'ONLINE', 1, 'stats test backend')",
		"LOAD MCP VARIABLES TO RUNTIME",
		"LOAD MCP PROFILES TO RUNTIME",
		"LOAD MYSQL SERVERS TO RUNTIME"
	};

	for (const auto& q : queries) {
		if (run_q(admin, q.c_str()) != 0) {
			diag("Failed: %s", q.c_str());
			return false;
		}
	}
	return true;
}

void create_test_data(MYSQL* mysql) {
	run_q(mysql, "CREATE DATABASE IF NOT EXISTS test");
	run_q(mysql, "USE test");
	run_q(mysql, "DROP TABLE IF EXISTS test_stats_table");
	run_q(mysql, "CREATE TABLE test_stats_table (id INT PRIMARY KEY, val VARCHAR(100))");
	run_q(mysql, "INSERT INTO test_stats_table VALUES (1, 'hello')");
}

int count_rows(MYSQL* admin, const char* table) {
	std::string q = std::string("SELECT COUNT(*) FROM ") + table;
	if (mysql_query(admin, q.c_str()) != 0) {
		return -1;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) return -1;
	MYSQL_ROW row = mysql_fetch_row(res);
	int count = (row && row[0]) ? atoi(row[0]) : 0;
	mysql_free_result(res);
	return count;
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(12);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get environmental variables");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		BAIL_OUT("mysql_init failed");
	}
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username,
	                       cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		BAIL_OUT("Admin connect failed: %s", mysql_error(admin));
	}

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		BAIL_OUT("mysql_init (backend) failed");
	}
	if (!mysql_real_connect(mysql, cl.mysql_host, cl.mysql_username,
	                       cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
		BAIL_OUT("Backend MySQL connect failed: %s", mysql_error(mysql));
	}

	create_test_data(mysql);

	ok(configure_mcp(admin, cl), "MCP configured for stats test");
	if (count_rows(admin, "stats_mcp_query_digest_reset") < 0 ||
	    count_rows(admin, "stats_mcp_query_tools_counters_reset") < 0) {
		BAIL_OUT("Failed to reset MCP statistics before generating test traffic");
	}

	MCPClient mcp(cl.admin_host, cl.mcp_port);
	if (strlen(cl.mcp_auth_token) > 0) {
		mcp.set_auth_token(cl.mcp_auth_token);
	}

	{
		json args = {
			{"target_id", k_target_id},
			{"sql", "SELECT * FROM test_stats_table"}
		};
		MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);
		ok(resp.is_success(), "First MCP query succeeds (populates stats)");
	}

	{
		json args = {
			{"target_id", k_target_id},
			{"sql", "SELECT val FROM test_stats_table WHERE id=1"}
		};
		MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);
		ok(resp.is_success(), "Second MCP query succeeds (different digest)");
	}

	{
		json args = {
			{"target_id", k_target_id},
			{"sql", "SELECT * FROM test_stats_table"}
		};
		MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);
		ok(resp.is_success(), "Third MCP query succeeds (same digest as first)");
	}

	int digest_rows = count_rows(admin, "stats_mcp_query_digest");
	ok(digest_rows == 2, "stats_mcp_query_digest has exactly 2 rows (got %d)", digest_rows);

	int counters_rows = count_rows(admin, "stats_mcp_query_tools_counters");
	ok(counters_rows >= 1, "stats_mcp_query_tools_counters has >= 1 row (got %d)", counters_rows);

	int rules_rows = count_rows(admin, "stats_mcp_query_rules");
	ok(rules_rows >= 0, "stats_mcp_query_rules accessible (got %d rows)", rules_rows);

	int reset_digest_rows = count_rows(admin, "stats_mcp_query_digest_reset");
	ok(reset_digest_rows >= 2, "stats_mcp_query_digest_reset has >= 2 rows (got %d)", reset_digest_rows);

	int after_reset = count_rows(admin, "stats_mcp_query_digest");
	ok(after_reset == 0, "stats_mcp_query_digest is empty after _reset (got %d)", after_reset);

	int reset_counters_rows = count_rows(admin, "stats_mcp_query_tools_counters_reset");
	ok(reset_counters_rows >= 1, "stats_mcp_query_tools_counters_reset has >= 1 row (got %d)", reset_counters_rows);

	int counters_after_reset = count_rows(admin, "stats_mcp_query_tools_counters");
	ok(counters_after_reset == 0, "stats_mcp_query_tools_counters is empty after _reset (got %d)", counters_after_reset);

	bool cleanup_ok = true;
	// FROM DISK is disk->memory only (issue #6171); TO RUNTIME applies it.
	cleanup_ok = (run_q(admin, "LOAD MCP VARIABLES FROM DISK") == 0) && cleanup_ok;
	cleanup_ok = (run_q(admin, "LOAD MCP VARIABLES TO RUNTIME") == 0) && cleanup_ok;
	cleanup_ok = (run_q(admin,
		("DELETE FROM mcp_target_profiles WHERE target_id='" + std::string(k_target_id) + "'").c_str()) == 0)
		&& cleanup_ok;
	cleanup_ok = (run_q(admin,
		("DELETE FROM mcp_auth_profiles WHERE auth_profile_id='" + std::string(k_auth_profile_id) + "'").c_str()) == 0)
		&& cleanup_ok;
	cleanup_ok = (run_q(admin,
		("DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(k_hostgroup_id)).c_str()) == 0)
		&& cleanup_ok;
	cleanup_ok = (run_q(admin, "LOAD MCP PROFILES TO RUNTIME") == 0) && cleanup_ok;
	cleanup_ok = (run_q(admin, "LOAD MYSQL SERVERS TO RUNTIME") == 0) && cleanup_ok;
	ok(cleanup_ok, "MCP stats fixture cleanup and runtime restoration succeed");
	mysql_close(mysql);
	mysql_close(admin);
	return exit_status();
}
