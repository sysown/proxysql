/**
 * @file test_set_statement_for-t.cpp
 * @brief Test for MariaDB SET STATEMENT ... FOR passthrough support (issue #5686).
 * @details MariaDB supports the syntax:
 *
 *     SET STATEMENT var1=val1 [, var2=val2, ...] FOR <statement>
 *
 * This temporarily sets session variables for the duration of a single
 * statement. Prior to the fix, ProxySQL did not recognize this syntax,
 * causing it to invoke unable_to_parse_set_statement() which locks the
 * session to a single hostgroup. Subsequent queries to a different
 * hostgroup would then fail with error 9006.
 *
 * The fix detects "SET STATEMENT ... FOR" and forwards the query to
 * the backend as-is, without locking the hostgroup.
 *
 * This test verifies:
 *   - The SET STATEMENT ... FOR query itself succeeds
 *   - The query returns a valid result (the backend executed it)
 *   - No hostgroup lock persists after the query
 *   - Multiple variables in a single SET STATEMENT work
 *   - Case-insensitive matching works
 *   - Whitespace tolerance after FOR (multi-line, tab, CRLF, multi-space)
 *   - Schema-based routing to a non-default hostgroup with both query parsers
 *   - A subsequent query can route to a different hostgroup (#6590)
 *
 * This test requires a MariaDB backend. It should only be registered in
 * TAP groups whose infra provides one (e.g. mariadb10-galera-*). The
 * earlier runtime self-skip on non-MariaDB backends has been removed —
 * if the test is misregistered into a MySQL group, that's a groups.json
 * bug and should surface as a loud failure, not a silent skip.
 *
 * @date 2026-05-01
 */

#include <stdio.h>
#include <string.h>
#include <vector>
#include <functional>
#include <exception>
#include <utility>
#include "mysql.h"
#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

// A successful query on the default hostgroup cannot detect #6590. Duplicate
// its backend into another hostgroup and check the digest's actual destination.
static bool test_schema_routing(const CommandLine& cl) {
	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
		NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connection failed: %s", mysql_error(admin));
		mysql_close(admin);
		return false;
	}
	auto exec = [admin](const std::string& sql) {
		if (mysql_query(admin, sql.c_str())) {
			diag("%s: %s", sql.c_str(), mysql_error(admin));
			return false;
		}
		return true;
	};
	auto scalar = [&exec, admin](const std::string& sql) -> std::string {
		if (!exec(sql)) return "";
		MYSQL_RES* res = mysql_store_result(admin);
		MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
		std::string value = row && row[0] ? row[0] : "";
		if (res) mysql_free_result(res);
		return value;
	};
	// SQLite string literals use doubled quotes, including for usernames.
	std::string username = cl.username;
	for (size_t pos = 0; (pos = username.find('\'', pos)) != std::string::npos; pos += 2)
		username.insert(pos, 1, '\'');
	const std::string source = scalar("SELECT default_hostgroup FROM runtime_mysql_users "
		"WHERE username='" + username + "' AND frontend=1 LIMIT 1");
	// Topology mappings can reserve IDs with no runtime servers. Avoid their
	// offline and backup groups when choosing the fixture destination.
	const std::string destination = scalar(
		"SELECT COALESCE(MAX(hostgroup_id),0)+1 FROM ("
		"SELECT hostgroup_id FROM mysql_servers "
		"UNION ALL SELECT hostgroup_id FROM runtime_mysql_servers "
		"UNION ALL SELECT MAX(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup) FROM mysql_galera_hostgroups "
		"UNION ALL SELECT MAX(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup) FROM runtime_mysql_galera_hostgroups "
		"UNION ALL SELECT MAX(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup) FROM mysql_group_replication_hostgroups "
		"UNION ALL SELECT MAX(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup) FROM runtime_mysql_group_replication_hostgroups "
		"UNION ALL SELECT MAX(writer_hostgroup,reader_hostgroup) FROM mysql_replication_hostgroups "
		"UNION ALL SELECT MAX(writer_hostgroup,reader_hostgroup) FROM runtime_mysql_replication_hostgroups)");
	const std::string parser = scalar("SELECT variable_value FROM global_variables WHERE variable_name='mysql-query_processor_parser'");
	const std::string algorithm = scalar("SELECT variable_value FROM global_variables WHERE variable_name='mysql-set_parser_algorithm'");
	const std::string locking = scalar("SELECT variable_value FROM global_variables WHERE variable_name='mysql-set_query_lock_on_hostgroup'");
	if (source.empty() || destination.empty() || parser.empty() || algorithm.empty() || locking.empty()) {
		mysql_close(admin);
		return false;
	}
	if (!exec("CREATE TEMP TABLE test_6590_rules AS SELECT * FROM mysql_query_rules")) {
		mysql_close(admin);
		return false;
	}
	struct Cleanup {
		MYSQL* admin;
		std::function<bool()> restore;
		Cleanup(MYSQL* connection, std::function<bool()> action)
			: admin(connection), restore(std::move(action)) {}
		Cleanup(const Cleanup&) = delete;
		Cleanup& operator=(const Cleanup&) = delete;
		~Cleanup() noexcept {
			try {
				if (!restore()) ok(false, "Schema routing cleanup failed to restore configuration");
			} catch (const std::exception& e) {
				ok(false, "Schema routing cleanup failed: %s", e.what());
			} catch (...) {
				ok(false, "Schema routing cleanup failed with an unknown exception");
			}
			mysql_close(admin);
		}
	} cleanup{admin, [&exec, &destination, &parser, &algorithm, &locking]() {
		bool restored = exec("DELETE FROM mysql_query_rules");
		// Evaluate exec first so every restore is attempted after an SQL failure.
		restored = exec("INSERT INTO mysql_query_rules SELECT * FROM test_6590_rules") && restored;
		restored = exec("LOAD MYSQL QUERY RULES TO RUNTIME") && restored;
		restored = exec("DROP TABLE test_6590_rules") && restored;
		restored = exec("DELETE FROM mysql_servers WHERE hostgroup_id=" + destination) && restored;
		restored = exec("LOAD MYSQL SERVERS TO RUNTIME") && restored;
		restored = exec("SET mysql-query_processor_parser=" + parser) && restored;
		restored = exec("SET mysql-set_parser_algorithm=" + algorithm) && restored;
		restored = exec("SET mysql-set_query_lock_on_hostgroup=" + locking) && restored;
		restored = exec("LOAD MYSQL VARIABLES TO RUNTIME") && restored;
		return restored;
	}};
	if (!exec("INSERT INTO mysql_servers(hostgroup_id,hostname,port,use_ssl) SELECT " + destination +
		",hostname,port,use_ssl FROM runtime_mysql_servers WHERE status='ONLINE' AND hostgroup_id=" + source) ||
		!exec("LOAD MYSQL SERVERS TO RUNTIME") || !exec("DELETE FROM mysql_query_rules") ||
		!exec("INSERT INTO mysql_query_rules(rule_id,active,schemaname,match_pattern,destination_hostgroup,apply) VALUES "
			"(0,1,'information_schema','^SELECT 6591 AS issue6590_followup$'," + source + ",1),"
			"(1,1,'information_schema',NULL," + destination + ",1)") ||
		!exec("LOAD MYSQL QUERY RULES TO RUNTIME") ||
		!exec("SET mysql-set_parser_algorithm=2") || !exec("SET mysql-set_query_lock_on_hostgroup=1")) return false;

	const char* queries[] = {
		"SET STATEMENT max_statement_time=10 FOR SELECT 6590 AS issue6590_route",
		"SET STATEMENT max_statement_time=10 FOR\n SELECT 6590 AS issue6590_route",
		"set statement max_statement_time=10, lock_wait_timeout=60 for select 6590 as issue6590_route"
	};
	for (int mode : {0, 1}) {
		if (!exec("SET mysql-query_processor_parser=" + std::to_string(mode)) ||
			!exec("LOAD MYSQL VARIABLES TO RUNTIME")) return false;
		for (const char* query : queries) {
			MYSQL* client = mysql_init(NULL);
			if (!mysql_real_connect(client, cl.host, cl.username, cl.password,
				"information_schema", cl.port, NULL, 0)) {
				diag("Regression connection failed: %s", mysql_error(client));
				mysql_close(client);
				return false;
			}
			const std::string count_sql = "SELECT COALESCE(SUM(count_star),0) FROM stats_mysql_query_digest "
				"WHERE hostgroup=" + destination + " AND digest_text LIKE '%issue6590_route%'";
			const long long before = atoll(scalar(count_sql).c_str());
			int rc = mysql_query(client, query);
			MYSQL_RES* res = rc == 0 ? mysql_store_result(client) : NULL;
			MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
			ok(row && row[0] && strcmp(row[0], "6590") == 0,
				"parser=%d: schema-routed SET STATEMENT returns backend result", mode);
			if (res) mysql_free_result(res);
			ok(atoll(scalar(count_sql).c_str()) == before + 1,
				"parser=%d: SET STATEMENT reaches rule hostgroup %s instead of default %s",
				mode, destination.c_str(), source.c_str());
			const std::string followup_count_sql = "SELECT COALESCE(SUM(count_star),0) FROM stats_mysql_query_digest "
				"WHERE hostgroup=" + source + " AND digest_text LIKE '%issue6590_followup%'";
			const long long followup_before = atoll(scalar(followup_count_sql).c_str());
			rc = mysql_query(client, "SELECT 6591 AS issue6590_followup");
			res = rc == 0 ? mysql_store_result(client) : NULL;
			row = res ? mysql_fetch_row(res) : NULL;
			ok(row && row[0] && strcmp(row[0], "6591") == 0 &&
				atoll(scalar(followup_count_sql).c_str()) == followup_before + 1,
				"parser=%d: follow-up query can route back to the default hostgroup", mode);
			if (res) mysql_free_result(res);
			mysql_close(client);
		}
	}
	return true;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(5 + 8 + 18);

	diag("=== Test: MariaDB SET STATEMENT ... FOR passthrough ===");
	diag("Issue #5686: ProxySQL should forward SET STATEMENT ... FOR");
	diag("to the backend without locking the hostgroup.");
	diag("");

	// Connect to ProxySQL
	MYSQL* proxysql = mysql_init(NULL);
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	// Test 1: Basic SET STATEMENT ... FOR - query should succeed
	diag("Test 1: Execute 'SET STATEMENT max_statement_time=60 FOR SELECT 1'");
	diag("  ProxySQL should forward this to MariaDB as-is.");
	{
		int rc = mysql_query(proxysql, "SET STATEMENT max_statement_time=60 FOR SELECT 1 AS val");
		ok(rc == 0, "SET STATEMENT max_statement_time=60 FOR SELECT 1 should succeed");
		if (rc != 0) {
			diag("  ERROR: %s", mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			MYSQL_ROW row = mysql_fetch_row(res);
			int rows = mysql_num_rows(res);
			diag("  Result: rows=%d, val=%s", rows, row ? row[0] : "NULL");
			ok(rows == 1 && row && strcmp(row[0], "1") == 0,
				"SET STATEMENT ... FOR should return the result from the inner SELECT");
			mysql_free_result(res);
		}
	}

	diag("");

	// Test 2: Multiple variables in SET STATEMENT
	diag("Test 2: Execute 'SET STATEMENT max_statement_time=60, lock_wait_timeout=60 FOR SELECT 1'");
	diag("  ProxySQL should handle multiple variables in a single SET STATEMENT.");
	{
		int rc = mysql_query(proxysql,
			"SET STATEMENT max_statement_time=60, lock_wait_timeout=60 FOR SELECT 1 AS val");
		ok(rc == 0, "SET STATEMENT with multiple variables should succeed");
		if (rc != 0) {
			diag("  ERROR: %s", mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			mysql_free_result(res);
		}
	}

	diag("");

	// Test 3: No hostgroup lock persists after SET STATEMENT
	diag("Test 3: Execute a plain SELECT after SET STATEMENT");
	diag("  Prior to the fix, unable_to_parse_set_statement() would lock the");
	diag("  hostgroup, causing subsequent queries to fail with error 9006.");
	{
		int rc = mysql_query(proxysql, "SELECT 1 AS no_lock_test");
		ok(rc == 0, "Plain SELECT after SET STATEMENT should succeed (no hostgroup lock)");
		if (rc != 0) {
			diag("  ERROR: %s (this indicates the hostgroup is still locked)", mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			mysql_free_result(res);
		}
	}

	diag("");

	// Test 4: Case-insensitive matching
	diag("Test 4: Execute 'set statement max_statement_time=60 for select 1'");
	diag("  ProxySQL detection should be case-insensitive.");
	{
		int rc = mysql_query(proxysql, "set statement max_statement_time=60 for select 1 as val");
		ok(rc == 0, "Lowercase 'set statement ... for' should also succeed");
		if (rc != 0) {
			diag("  ERROR: %s", mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			mysql_free_result(res);
		}
	}

	diag("");

	// Tests 5-8: whitespace tolerance after 'FOR'. The original PR #5708
	// detection used strcasestr(nq, " FOR "), which is a literal-substring
	// match requiring a space BOTH before and after 'FOR'. A mysql client
	// query typed across multiple lines (the customer-reported failure mode
	// of issue #5686 follow-up) has '\n' immediately after 'FOR' and the
	// detection misses; the SET parser then falls through to
	// unable_to_parse_set_statement() and locks the session to its default
	// hostgroup, surfacing as error 9006 on the next query that routes to
	// a different hostgroup. The fix uses the digest text (which is
	// whitespace-normalised) instead. These tests cover four common
	// post-'FOR' whitespace shapes that the original test missed.
	//
	// Each test: (a) the SET STATEMENT must succeed, (b) a plain SELECT
	// immediately afterwards must succeed (proving no hostgroup lock
	// persists). On the buggy code path, assertion (b) would manifest as
	// error 9006 on any test environment where the follow-up SELECT routes
	// to a different hostgroup than the session's default; on a single-
	// hostgroup environment it would manifest as the SET STATEMENT itself
	// silently going through a different parse path that may or may not
	// produce the expected backend response — either way, the assertions
	// below will fail loudly.

	struct ws_case_t {
		const char* label;
		const char* query;
	};
	std::vector<ws_case_t> ws_cases = {
		{ "newline after FOR",
		  "SET STATEMENT max_statement_time=60 FOR\n  SELECT 1 AS val" },
		{ "tab after FOR",
		  "SET STATEMENT max_statement_time=60 FOR\tSELECT 1 AS val" },
		{ "CRLF after FOR",
		  "SET STATEMENT max_statement_time=60 FOR\r\n  SELECT 1 AS val" },
		{ "multiple spaces after FOR",
		  "SET STATEMENT max_statement_time=60 FOR   SELECT 1 AS val" },
	};

	int idx = 5;
	for (const auto& c : ws_cases) {
		idx++;
		diag("Test %d: SET STATEMENT with %s", idx, c.label);
		int rc = mysql_query(proxysql, c.query);
		ok(rc == 0, "SET STATEMENT (%s) should succeed", c.label);
		if (rc != 0) {
			diag("  ERROR on SET STATEMENT: %s", mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			if (res) mysql_free_result(res);
		}
		// Follow-up plain SELECT to verify no hostgroup lock persists.
		// On the buggy code path, the SET STATEMENT would have triggered
		// unable_to_parse_set_statement() and locked the hostgroup; a
		// subsequent query that routes elsewhere would then fail with
		// error 9006 ("connection is locked to hostgroup X but trying
		// to reach hostgroup Y").
		rc = mysql_query(proxysql, "SELECT 2 AS no_lock_probe");
		ok(rc == 0, "follow-up SELECT after %s should succeed (no hostgroup lock)", c.label);
		if (rc != 0) {
			diag("  ERROR on follow-up SELECT: %s (this indicates the hostgroup was locked)",
				mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			if (res) mysql_free_result(res);
		}
		diag("");
	}

	mysql_close(proxysql);
	if (!test_schema_routing(cl)) return -1;
	diag("=== All tests completed ===");
	return exit_status();
}
