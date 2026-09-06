/**
 * @file mcp_query_run_sql_readonly_bypass-t.cpp
 * @brief Regression test for GHSA-7wh6-2vcc-gcm4: MCP run_sql_readonly
 *        multi-statement bypass and validator gaps.
 *
 * @details The pre-fix Query_Tool_Handler::validate_readonly_query() only
 *        inspected the first keyword and a substring blacklist, while the
 *        backend MySQL connection was opened with CLIENT_MULTI_STATEMENTS.
 *        A payload like
 *
 *            SELECT 1; RENAME TABLE testdb.x TO testdb.y
 *
 *        passed validation (starts with SELECT, no blacklisted substring in
 *        the dangerous list) and executed both statements.
 *
 *        This test verifies:
 *          1. Multi-statement payloads of every shape are rejected.
 *          2. Side-effecting keywords that the pre-fix blacklist missed
 *             (RENAME, SET, RESET, LOCK, KILL, FLUSH, OPTIMIZE, REPAIR,
 *             HANDLER, ...) are rejected as leading keywords.
 *          3. EXPLAIN ANALYZE is rejected.
 *          4. After every rejection, the side-effect canary table is
 *             still in its original shape (no row inserted, no rename).
 *          5. Legitimate read-only payloads that include semicolons or
 *             comments inside string literals are still accepted (no
 *             regression on the false-positive side).
 */

#include <algorithm>
#include <string>
#include <vector>

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
static const char* k_target_id = "tap_mcp_bypass_target";
static const char* k_auth_profile_id = "tap_mcp_bypass_auth";
static const int   k_hostgroup_id = 9111;

// ---------------------------------------------------------------------------
// Payloads the pre-fix code would have accepted but must now reject.
// ---------------------------------------------------------------------------

static const query_test multi_statement_rejected[] = {
	{ "Demonstrated PoC: SELECT 1; RENAME TABLE",
	  "SELECT 1; RENAME TABLE test.canary TO test.canary_renamed" },
	{ "Multi-statement: SELECT 1; INSERT",
	  "SELECT 1; INSERT INTO test.canary VALUES (99)" },
	{ "Multi-statement: SELECT 1; DROP TABLE",
	  "SELECT 1; DROP TABLE test.canary" },
	{ "Multi-statement: SELECT 1; SET sql_log_bin",
	  "SELECT 1; SET sql_log_bin=0" },
	{ "Multi-statement: SELECT 1; RESET MASTER",
	  "SELECT 1; RESET MASTER" },
	{ "Multi-statement: SELECT 1; LOCK TABLES",
	  "SELECT 1; LOCK TABLES test.canary WRITE" },
	{ "Multi-statement: SELECT 1; KILL",
	  "SELECT 1; KILL 1" },
	{ "Multi-statement: SELECT 1; FLUSH LOGS",
	  "SELECT 1; FLUSH LOGS" },
	{ "Multi-statement: SELECT 1; OPTIMIZE",
	  "SELECT 1; OPTIMIZE TABLE test.canary" },
	{ "Multi-statement after comment",
	  "SELECT 1 /* still readonly */; RENAME TABLE test.canary TO test.canary_renamed" },
};

static const query_test single_statement_rejected[] = {
	{ "Leading RENAME",   "RENAME TABLE test.canary TO test.canary_renamed" },
	{ "Leading SET",      "SET GLOBAL general_log=ON" },
	{ "Leading RESET",    "RESET MASTER" },
	{ "Leading LOCK",     "LOCK TABLES test.canary WRITE" },
	{ "Leading UNLOCK",   "UNLOCK TABLES" },
	{ "Leading KILL",     "KILL 1" },
	{ "Leading FLUSH",    "FLUSH LOGS" },
	{ "Leading OPTIMIZE", "OPTIMIZE TABLE test.canary" },
	{ "Leading REPAIR",   "REPAIR TABLE test.canary" },
	{ "Leading HANDLER",  "HANDLER test.canary OPEN" },
	{ "Leading USE",      "USE test" },
	{ "Leading XA",       "XA START 'tx1'" },
	{ "EXPLAIN ANALYZE",  "EXPLAIN ANALYZE SELECT * FROM test.canary" },
	// GHSA-7wh6-2vcc-gcm4: EXPLAIN ANALYZE bypass variants. The literal
	// "EXPLAIN ANALYZE" substring check missed these; adding ANALYZE to
	// the substring blacklist covers all of them.
	{ "EXPLAIN/**/ANALYZE (block comment)",
	  "EXPLAIN/**/ANALYZE SELECT * FROM test.canary" },
	{ "EXPLAIN  ANALYZE (double space)",
	  "EXPLAIN  ANALYZE SELECT * FROM test.canary" },
	{ "EXPLAIN\\nANALYZE (newline)",
	  "EXPLAIN\nANALYZE SELECT * FROM test.canary" },
	{ "EXPLAIN (ANALYZE) — PostgreSQL parenthesized option",
	  "EXPLAIN (ANALYZE) SELECT * FROM test.canary" },
	{ "EXPLAIN (VERBOSE, ANALYZE) — PostgreSQL with extra options",
	  "EXPLAIN (VERBOSE, ANALYZE) SELECT * FROM test.canary" },
	{ "Standalone ANALYZE TABLE",
	  "ANALYZE TABLE test.canary" },
	{ "Subquery RENAME via comment",
	  "SELECT * FROM test.canary -- ;\nRENAME TABLE test.canary TO test.canary_renamed" },
};

// ---------------------------------------------------------------------------
// Payloads that must still be accepted (no false-positive regression).
// ---------------------------------------------------------------------------

static const query_test still_allowed[] = {
	{ "Trailing semicolon: SELECT 1;",
	  "SELECT 1;" },
	{ "Trailing semicolon with whitespace",
	  "SELECT 1;   " },
	{ "Trailing semicolon with line comment",
	  "SELECT 1; -- trailing comment" },
	{ "Semicolon inside single-quoted string",
	  "SELECT 'a;b' AS literal" },
	{ "Semicolon inside double-quoted string",
	  "SELECT \"a;b\" AS literal" },
	{ "Plain SELECT with subquery",
	  "SELECT * FROM (SELECT 1) AS t" },
};

// ---------------------------------------------------------------------------
// Test helpers.
// ---------------------------------------------------------------------------

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

bool configure_mcp_for_test(MYSQL* admin, const CommandLine& cl, const std::string& query_token) {
	const std::string mysql_host = escape_sql_literal(cl.mysql_host);
	const std::string mysql_user = escape_sql_literal(cl.mysql_username);
	const std::string mysql_password = escape_sql_literal(cl.mysql_password);
	const std::string default_schema = escape_sql_literal(k_test_schema);

	const std::vector<std::string> queries = {
		"SET mcp-port=" + std::to_string(cl.mcp_port),
		"SET mcp-use_ssl=false",
		"SET mcp-enabled=true",
		"SET mcp-config_endpoint_auth='" + escape_sql_literal(query_token) + "'",
		"SET mcp-query_endpoint_auth='" + escape_sql_literal(query_token) + "'",
		"DELETE FROM mcp_target_profiles WHERE target_id='" + std::string(k_target_id) + "'",
		"DELETE FROM mcp_auth_profiles WHERE auth_profile_id='" + std::string(k_auth_profile_id) + "'",
		"INSERT INTO mcp_auth_profiles (auth_profile_id, db_username, db_password, default_schema, use_ssl, ssl_mode, comment) VALUES "
		"('" + std::string(k_auth_profile_id) + "', '" + mysql_user + "', '" + mysql_password + "', '" + default_schema + "', 0, '', 'TAP MCP bypass auth')",
		"INSERT INTO mcp_target_profiles (target_id, protocol, hostgroup_id, auth_profile_id, description, max_rows, timeout_ms, allow_explain, allow_discovery, active, comment) VALUES "
		"('" + std::string(k_target_id) + "', 'mysql', " + std::to_string(k_hostgroup_id) + ", '" + std::string(k_auth_profile_id) + "', 'TAP bypass target', 200, 5000, 1, 1, 1, 'TAP bypass target')",
		"DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(k_hostgroup_id),
		"INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, comment) VALUES "
		"(" + std::to_string(k_hostgroup_id) + ", '" + mysql_host + "', " + std::to_string(cl.mysql_port) + ", 'ONLINE', 1, 'TAP MCP bypass backend')",
		"LOAD MCP VARIABLES TO RUNTIME",
		"LOAD MCP PROFILES TO RUNTIME",
		"LOAD MYSQL SERVERS TO RUNTIME"
	};

	for (const auto& q : queries) {
		if (run_q(admin, q.c_str()) != 0) {
			return false;
		}
	}
	return true;
}

void create_canary_table(MYSQL* mysql) {
	run_q(mysql, "CREATE DATABASE IF NOT EXISTS test");
	run_q(mysql, "USE test");
	run_q(mysql, "DROP TABLE IF EXISTS test.canary_renamed");
	run_q(mysql, "DROP TABLE IF EXISTS test.canary");
	run_q(mysql, "CREATE TABLE test.canary (id INT PRIMARY KEY)");
	run_q(mysql, "INSERT INTO test.canary VALUES (1)");
}

// Returns true if the canary table is intact: name 'canary' (not renamed)
// and contains exactly the one row inserted at setup.
bool canary_is_intact(MYSQL* mysql) {
	if (run_q(mysql, "USE test") != 0) {
		return false;
	}
	if (mysql_query(mysql, "SELECT COUNT(*) FROM information_schema.tables "
	                       "WHERE table_schema='test' AND table_name='canary'")) {
		return false;
	}
	MYSQL_RES* res = mysql_store_result(mysql);
	if (!res) return false;
	MYSQL_ROW row = mysql_fetch_row(res);
	bool exists = row && row[0] && std::string(row[0]) == "1";
	mysql_free_result(res);
	if (!exists) return false;

	if (mysql_query(mysql, "SELECT COUNT(*) FROM information_schema.tables "
	                       "WHERE table_schema='test' AND table_name='canary_renamed'")) {
		return false;
	}
	res = mysql_store_result(mysql);
	if (!res) return false;
	row = mysql_fetch_row(res);
	bool renamed = row && row[0] && std::string(row[0]) != "0";
	mysql_free_result(res);
	if (renamed) return false;

	if (mysql_query(mysql, "SELECT COUNT(*) FROM test.canary")) {
		return false;
	}
	res = mysql_store_result(mysql);
	if (!res) return false;
	row = mysql_fetch_row(res);
	bool row_count_ok = row && row[0] && std::string(row[0]) == "1";
	mysql_free_result(res);
	return row_count_ok;
}

void test_rejected(MCPClient& mcp, MYSQL* backend, const query_test& t) {
	json args = {{"sql", t.sql}, {"schema", k_test_schema}, {"target_id", k_target_id}};
	MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);
	bool is_rejected = resp.is_mcp_error();
	std::string err = resp.is_success() ? "none" : resp.get_error_message();
	ok(is_rejected,
	   "REJECT: %s - sql=%s, got: %s",
	   t.name, t.sql, err.c_str());
	// Backend integrity: even if the request was accepted, the canary must
	// not have been modified.  This catches the demonstrated PoC end-to-end.
	ok(canary_is_intact(backend),
	   "CANARY INTACT after: %s", t.name);
}

void test_allowed(MCPClient& mcp, const query_test& t) {
	json args = {{"sql", t.sql}, {"schema", k_test_schema}, {"target_id", k_target_id}};
	MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);
	bool is_success = resp.is_success();
	std::string err = is_success ? "none" : resp.get_error_message();
	ok(is_success,
	   "ALLOW: %s - sql=%s, got error: %s",
	   t.name, t.sql, err.c_str());
}

int main(int /*argc*/, char** /*argv*/) {
	const size_t n_rejected = sizeof(multi_statement_rejected) / sizeof(multi_statement_rejected[0])
	                          + sizeof(single_statement_rejected) / sizeof(single_statement_rejected[0]);
	const size_t n_allowed = sizeof(still_allowed) / sizeof(still_allowed[0]);
	// 2 plan slots per rejected (reject assertion + canary intact) + 1 per allowed
	const int planned = static_cast<int>(2 * n_rejected + n_allowed);
	plan(planned);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get required environmental variables.");
		return exit_status();
	}

	const std::string query_token = "tap-bypass-token-abc123";

	MYSQL* admin = NULL;
	MYSQL* mysql = NULL;
	MCPClient* mcp = NULL;

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

	create_canary_table(mysql);

	if (!configure_mcp_for_test(admin, cl, query_token)) {
		diag("Failed to configure MCP profile-based routing for test");
		goto cleanup;
	}

	mcp = new MCPClient(cl.admin_host, cl.mcp_port);
	mcp->set_auth_token(query_token);

	if (!mcp->check_server()) {
		diag("MCP server not accessible at %s", mcp->get_connection_info().c_str());
		goto cleanup;
	}

	diag("--- Multi-statement payloads (must be rejected, canary must survive) ---");
	for (const auto& t : multi_statement_rejected) {
		test_rejected(*mcp, mysql, t);
	}

	diag("--- Single-statement bypass keywords (must be rejected) ---");
	for (const auto& t : single_statement_rejected) {
		test_rejected(*mcp, mysql, t);
	}

	diag("--- Legitimate read-only payloads (must still be allowed) ---");
	for (const auto& t : still_allowed) {
		test_allowed(*mcp, t);
	}

cleanup:
	if (mysql) {
		run_q(mysql, "DROP TABLE IF EXISTS test.canary_renamed");
		run_q(mysql, "DROP TABLE IF EXISTS test.canary");
		mysql_close(mysql);
	}
	if (admin) {
		run_q(admin, ("DELETE FROM mcp_target_profiles WHERE target_id='" + std::string(k_target_id) + "'").c_str());
		run_q(admin, ("DELETE FROM mcp_auth_profiles WHERE auth_profile_id='" + std::string(k_auth_profile_id) + "'").c_str());
		run_q(admin, ("DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(k_hostgroup_id)).c_str());
		if (run_q(admin, "LOAD MCP VARIABLES FROM DISK") != 0) {
			diag("Failed to restore MCP variables from disk: %s", mysql_error(admin));
		} else if (run_q(admin, "LOAD MCP VARIABLES TO RUNTIME") != 0) {
			diag("Failed to apply restored MCP variables: %s", mysql_error(admin));
		}
		run_q(admin, "LOAD MCP PROFILES TO RUNTIME");
		run_q(admin, "LOAD MYSQL SERVERS TO RUNTIME");
		mysql_close(admin);
	}
	if (mcp) {
		delete mcp;
	}

	return exit_status();
}
