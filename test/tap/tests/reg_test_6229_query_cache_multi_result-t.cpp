/**
 * Regression test for issue #6229: heap overflow when the query cache stores
 * the response of a text-protocol request returning more than one result set.
 *
 * A CALL to a procedure returning two result sets, and a two-statement
 * COM_QUERY, are matched by a rule with cache_ttl and executed three times,
 * with and without CLIENT_DEPRECATE_EOF. Every execution must return every
 * result set with the expected values, the response must not be cached, and
 * ProxySQL must survive. Under ASAN the unfixed code aborts ProxySQL with a
 * heap-buffer-overflow in MySQL_Data_Stream::resultset2buffer().
 *
 * Requires an isolated ProxySQL: flushes the shared cache and replaces the
 * query rules while running. Creates the backend database reg6229 (holding
 * the procedure) and drops it at the end.
 */
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"

namespace {
MYSQL* rules_admin = nullptr;

// Restore runtime first, then any pending in-memory configuration separately.
// BAIL_OUT calls exit(), so use atexit rather than relying on stack unwinding.
void restore_query_rules() {
	if (!rules_admin) return;
	for (const char* sql : {
		"DELETE FROM mysql_query_rules",
		"INSERT INTO mysql_query_rules SELECT * FROM reg6229_runtime_rules",
		"DELETE FROM mysql_query_rules_fast_routing",
		"INSERT INTO mysql_query_rules_fast_routing SELECT * FROM reg6229_runtime_fast_rules",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
		"DELETE FROM mysql_query_rules",
		"INSERT INTO mysql_query_rules SELECT * FROM reg6229_memory_rules",
		"DELETE FROM mysql_query_rules_fast_routing",
		"INSERT INTO mysql_query_rules_fast_routing SELECT * FROM reg6229_memory_fast_rules",
		"DROP TABLE reg6229_runtime_rules",
		"DROP TABLE reg6229_memory_rules",
		"DROP TABLE reg6229_runtime_fast_rules",
		"DROP TABLE reg6229_memory_fast_rules"}) {
		if (mysql_query(rules_admin, sql)) {
			diag("Cannot restore query rules: %s: %s", sql, mysql_error(rules_admin));
			// Do not report a successful test or recursively invoke atexit.
			// std::_Exit() does not flush stdio buffers.
			fflush(stdout);
			std::_Exit(EXIT_FAILURE);
		}
	}
	rules_admin = nullptr;
}

void query(MYSQL* mysql, const std::string& sql) {
	if (mysql_query(mysql, sql.c_str())) {
		BAIL_OUT("Query failed: %s: %s", sql.c_str(), mysql_error(mysql));
	}
}

long long scalar(MYSQL* mysql, const std::string& sql) {
	query(mysql, sql);
	MYSQL_RES* res = mysql_store_result(mysql);
	if (!res) BAIL_OUT("Missing scalar result: %s", mysql_error(mysql));
	MYSQL_ROW row = mysql_fetch_row(res);
	long long value = row && row[0] ? strtoll(row[0], nullptr, 10) : -1;
	mysql_free_result(res);
	return value;
}

long long stat(MYSQL* admin, const char* name) {
	return scalar(admin, std::string("SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='") + name + "'");
}

MYSQL* connect(const CommandLine& cl, bool admin, bool deprecate_eof) {
	MYSQL* mysql = mysql_init(nullptr);
	// A corrupted cache entry can leave the client waiting for packets that never come.
	unsigned int timeout = 10;
	mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT, &timeout);
	mysql->options.client_flag &= ~CLIENT_DEPRECATE_EOF;
	unsigned long flags = admin ? 0 : CLIENT_MULTI_STATEMENTS;
	if (deprecate_eof) flags |= CLIENT_DEPRECATE_EOF;
	if (!mysql_real_connect(mysql, admin ? cl.admin_host : cl.host,
		admin ? cl.admin_username : cl.username, admin ? cl.admin_password : cl.password,
		nullptr, admin ? cl.admin_port : cl.port, nullptr, flags)) {
		BAIL_OUT("Connect failed: %s", mysql_error(mysql));
	}
	return mysql;
}

// Runs a request and returns the first column of the first row of every result set.
// On a protocol error the error text is appended as the last element.
std::vector<std::string> run(MYSQL* mysql, const std::string& sql) {
	std::vector<std::string> out;
	if (mysql_query(mysql, sql.c_str())) {
		out.push_back(std::string("ERROR: ") + mysql_error(mysql));
		return out;
	}
	for (;;) {
		MYSQL_RES* res = mysql_store_result(mysql);
		if (res) {
			MYSQL_ROW row = mysql_fetch_row(res);
			unsigned long* lengths = row ? mysql_fetch_lengths(res) : nullptr;
			out.push_back(row && row[0] ? std::string(row[0], lengths[0]) : std::string("<no row>"));
			mysql_free_result(res);
		} else if (mysql_errno(mysql)) {
			out.push_back(std::string("ERROR: ") + mysql_error(mysql));
			return out;
		}
		int rc = mysql_next_result(mysql);
		if (rc == -1) break;
		if (rc > 0) {
			out.push_back(std::string("ERROR: ") + mysql_error(mysql));
			break;
		}
	}
	return out;
}

std::string describe(const std::vector<std::string>& v) {
	std::string s = "[";
	for (size_t i = 0; i < v.size(); i++) {
		if (i) s += ", ";
		s += v[i].size() > 40 ? v[i].substr(0, 40) + "...(" + std::to_string(v[i].size()) + " bytes)" : v[i];
	}
	return s + "]";
}

void check(MYSQL* mysql, const std::string& sql, const std::vector<std::string>& expected, const char* label) {
	std::vector<std::string> got = run(mysql, sql);
	ok(got == expected, "%s: every result set is returned with the expected values", label);
	if (got != expected) diag("%s: expected %s, got %s", label, describe(expected).c_str(), describe(got).c_str());
}
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	plan(2 * 10 + 1);
	MYSQL* admin = connect(cl, true, true);
	// Materialize the current runtime snapshot before copying its SQLite table.
	scalar(admin, "SELECT count(*) FROM runtime_mysql_query_rules");
	scalar(admin, "SELECT count(*) FROM runtime_mysql_query_rules_fast_routing");
	query(admin, "CREATE TEMPORARY TABLE reg6229_memory_rules AS SELECT * FROM mysql_query_rules");
	query(admin, "CREATE TEMPORARY TABLE reg6229_runtime_rules AS SELECT * FROM runtime_mysql_query_rules");
	query(admin, "CREATE TEMPORARY TABLE reg6229_memory_fast_rules AS SELECT * FROM mysql_query_rules_fast_routing");
	query(admin, "CREATE TEMPORARY TABLE reg6229_runtime_fast_rules AS SELECT * FROM runtime_mysql_query_rules_fast_routing");
	if (std::atexit(restore_query_rules) != 0) BAIL_OUT("Cannot register query-rule cleanup");
	rules_admin = admin;
	// CI installs lower-numbered SELECT routing rules with apply=1. Remove
	// them while testing so our cache rule is actually evaluated.
	// Only memory/runtime are modified; never persist this fixture to disk.
	query(admin, "DELETE FROM mysql_query_rules");
	query(admin, "DELETE FROM mysql_query_rules_fast_routing");
	query(admin, "INSERT INTO mysql_query_rules(rule_id,active,match_pattern,cache_ttl,cache_empty_result,apply) "
		"VALUES(976229,1,'^(SELECT|CALL) /[*] reg6229',60000,1,1)");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	query(admin, "PROXYSQL FLUSH QUERY CACHE");

	// The first result set is much larger than the last one, so that a buffer
	// sized for the last one cannot hold both.
	const std::string wide(4000, 'x');
	const std::vector<std::string> expected = { wide, "6229" };
	// A procedure returning two result sets: each one is followed by the final OK.
	MYSQL* setup = connect(cl, false, false);
	query(setup, "CREATE DATABASE IF NOT EXISTS reg6229");
	query(setup, "DROP PROCEDURE IF EXISTS reg6229.two_results");
	query(setup, "CREATE PROCEDURE reg6229.two_results() BEGIN "
		"SELECT REPEAT('x',4000) AS c1, 1 AS c2, 2 AS c3; SELECT 6229 AS c4; END");
	mysql_close(setup);

	for (bool deprecate_eof : { false, true }) {
		const char* mode = deprecate_eof ? "CLIENT_DEPRECATE_EOF" : "EOF";
		MYSQL* mysql = connect(cl, false, deprecate_eof);
		const std::string tag = std::string("/* reg6229 ") + mode + " */ ";
		const std::string call = "CALL " + tag + "reg6229.two_results()";
		const std::string multi = "SELECT " + tag + "REPEAT('x',4000) AS c1, 1 AS c2, 2 AS c3; SELECT 6229 AS c4";

		for (const auto& c : { std::make_pair("CALL", call), std::make_pair("multi-statement", multi) }) {
			const std::string label = std::string(mode) + " " + c.first;
			const long long sets = stat(admin, "Query_Cache_count_SET");
			check(mysql, c.second, expected, (label + ", first execution").c_str());
			check(mysql, c.second, expected, (label + ", second execution").c_str());
			check(mysql, c.second, expected, (label + ", third execution").c_str());
			// A cache entry holds one result: storing any single result of the
			// response would answer later executions with that result alone.
			ok(stat(admin, "Query_Cache_count_SET") == sets, "%s: response is not stored in the cache", label.c_str());
		}

		// A single-result request on the same connection must still be cached.
		const std::string single = "SELECT " + tag + "6229";
		ok(scalar(mysql, single) == 6229, "%s: single-result query returns its value", mode);
		const long long hits = stat(admin, "Query_Cache_count_GET_OK");
		ok(scalar(mysql, single) == 6229 && stat(admin, "Query_Cache_count_GET_OK") == hits + 1,
			"%s: repeated single-result query hits the cache", mode);
		mysql_close(mysql);
	}

	MYSQL* probe = mysql_init(nullptr);
	ok(mysql_real_connect(probe, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)
		&& mysql_query(probe, "SELECT 1") == 0, "ProxySQL is still serving clients");
	if (MYSQL_RES* res = mysql_store_result(probe)) mysql_free_result(res);
	mysql_close(probe);

	MYSQL* teardown = connect(cl, false, false);
	query(teardown, "DROP DATABASE IF EXISTS reg6229");
	mysql_close(teardown);

	restore_query_rules();
	mysql_close(admin);
	return exit_status();
}
