/**
 * #6430: prepared rows at the 0xFFFFFF payload boundary must terminate before
 * EOF/OK. Check first execution and prepared result-cache replay on the same
 * connection, with both EOF capabilities. Requires backend max_allowed_packet
 * >= 32MiB (the MySQL 8 default is 64MiB).
 */
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"

namespace {
MYSQL* rules_admin = nullptr;

void restore_rules() {
	if (!rules_admin) return;
	for (const char* sql : {
		"DELETE FROM mysql_query_rules",
		"INSERT INTO mysql_query_rules SELECT * FROM reg6430_runtime_rules",
		"DELETE FROM mysql_query_rules_fast_routing",
		"INSERT INTO mysql_query_rules_fast_routing SELECT * FROM reg6430_runtime_fast_rules",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
		"DELETE FROM mysql_query_rules",
		"INSERT INTO mysql_query_rules SELECT * FROM reg6430_memory_rules",
		"DELETE FROM mysql_query_rules_fast_routing",
		"INSERT INTO mysql_query_rules_fast_routing SELECT * FROM reg6430_memory_fast_rules",
		"DROP TABLE reg6430_runtime_rules", "DROP TABLE reg6430_memory_rules",
		"DROP TABLE reg6430_runtime_fast_rules", "DROP TABLE reg6430_memory_fast_rules"}) {
		if (mysql_query(rules_admin, sql)) {
			diag("Cannot restore rules: %s: %s", sql, mysql_error(rules_admin));
			fflush(stdout);
			std::_Exit(EXIT_FAILURE);
		}
	}
	rules_admin = nullptr;
}

void query(MYSQL* mysql, const char* sql) {
	if (mysql_query(mysql, sql)) BAIL_OUT("Query failed: %s: %s", sql, mysql_error(mysql));
}

long long scalar(MYSQL* mysql, const char* sql) {
	query(mysql, sql);
	MYSQL_RES* res = mysql_store_result(mysql);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	if (!row || !row[0]) BAIL_OUT("Missing scalar result: %s", sql);
	const long long value = strtoll(row[0], nullptr, 10);
	mysql_free_result(res);
	return value;
}

long long hits(MYSQL* admin) {
	return scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Query_Cache_count_GET_OK'");
}

long long inserts(MYSQL* admin) {
	return scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Query_Cache_count_SET'");
}

bool cache_enabled(MYSQL* admin) {
	query(admin, "SELECT variable_value FROM global_variables WHERE variable_name='admin-version'");
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	int major = 0, minor = 0;
	if (!row || !row[0] || sscanf(row[0], "%d.%d", &major, &minor) != 2)
		BAIL_OUT("Cannot determine ProxySQL tier from admin-version");
	mysql_free_result(res);
	return major > 3 || (major == 3 && minor >= 1);
}

MYSQL* connect(const CommandLine& cl, bool admin, bool deprecate_eof) {
	MYSQL* mysql = mysql_init(nullptr);
	if (!mysql) BAIL_OUT("mysql_init failed");
	unsigned int timeout = 5;
	mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT, &timeout);
	mysql_options(mysql, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
	mysql->options.client_flag &= ~CLIENT_DEPRECATE_EOF;
	if (!mysql_real_connect(mysql, admin ? cl.admin_host : cl.host,
		admin ? cl.admin_username : cl.username, admin ? cl.admin_password : cl.password,
		nullptr, admin ? cl.admin_port : cl.port, nullptr,
		deprecate_eof ? CLIENT_DEPRECATE_EOF : 0))
		BAIL_OUT("Connect failed: %s", mysql_error(mysql));
	return mysql;
}

bool execute(MYSQL_STMT* stmt, unsigned long length) {
	std::vector<char> value(length, '\0');
	unsigned long returned_length = 0;
	my_bool is_null = false, error = false;
	MYSQL_BIND output {};
	output.buffer_type = MYSQL_TYPE_STRING;
	output.buffer = value.data();
	output.buffer_length = value.size();
	output.length = &returned_length;
	output.is_null = &is_null;
	output.error = &error;
	bool good = mysql_stmt_bind_result(stmt, &output) == 0
		&& mysql_stmt_execute(stmt) == 0 && mysql_stmt_store_result(stmt) == 0;
	if (good) {
		good = mysql_stmt_num_rows(stmt) == 1 && mysql_stmt_fetch(stmt) == 0
			&& !is_null && !error && returned_length == length
			&& std::all_of(value.begin(), value.end(), [](char c) { return c == 'a'; })
			&& mysql_stmt_fetch(stmt) == MYSQL_NO_DATA;
	}
	if (!good) diag("Prepared length=%lu: %s (returned=%lu, null=%d, truncated=%d)",
		length, mysql_stmt_error(stmt), returned_length, is_null, error);
	mysql_stmt_free_result(stmt);
	return good;
}

bool followup(MYSQL* mysql) {
	if (mysql_query(mysql, "SELECT 1")) return false;
	MYSQL_RES* res = mysql_store_result(mysql);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	bool good = row && row[0] && strcmp(row[0], "1") == 0;
	if (res) mysql_free_result(res);
	return good;
}
} // namespace

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	// N + 6 is the binary payload for the first six cases. For the final
	// 2*0xFFFFFF case the length-encoded prefix grows to nine bytes: N + 11.
	const unsigned long lengths[] = {16777208, 16777209, 16777210,
		16777211, 16777212, 16777213, 33554419};
	plan(2 * 5 * (sizeof(lengths) / sizeof(lengths[0])));
	MYSQL* admin = connect(cl, true, false);
	const bool prepared_cache = cache_enabled(admin);
	scalar(admin, "SELECT count(*) FROM runtime_mysql_query_rules");
	scalar(admin, "SELECT count(*) FROM runtime_mysql_query_rules_fast_routing");
	query(admin, "CREATE TEMPORARY TABLE reg6430_memory_rules AS SELECT * FROM mysql_query_rules");
	query(admin, "CREATE TEMPORARY TABLE reg6430_runtime_rules AS SELECT * FROM runtime_mysql_query_rules");
	query(admin, "CREATE TEMPORARY TABLE reg6430_memory_fast_rules AS SELECT * FROM mysql_query_rules_fast_routing");
	query(admin, "CREATE TEMPORARY TABLE reg6430_runtime_fast_rules AS SELECT * FROM runtime_mysql_query_rules_fast_routing");
	if (std::atexit(restore_rules)) BAIL_OUT("Cannot register query-rule cleanup");
	rules_admin = admin;
	query(admin, "DELETE FROM mysql_query_rules");
	query(admin, "DELETE FROM mysql_query_rules_fast_routing");
	query(admin, "INSERT INTO mysql_query_rules(rule_id,active,match_pattern,cache_ttl,apply) "
		"VALUES(976430,1,'^SELECT REPEAT',60000,1)");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	for (bool eof : {false, true}) {
		for (unsigned long length : lengths) {
			MYSQL* mysql = connect(cl, false, eof);
			if (scalar(mysql, "SELECT @@max_allowed_packet") < 33554432)
				BAIL_OUT("Backend max_allowed_packet must be at least 33554432");
			MYSQL_STMT* stmt = mysql_stmt_init(mysql);
			const char* sql = "SELECT REPEAT('a', ?)";
			if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql)))
				BAIL_OUT("Prepare failed: %s", mysql_error(mysql));
			MYSQL_BIND input {};
			input.buffer_type = MYSQL_TYPE_LONG;
			unsigned int n = length;
			input.buffer = &n;
			input.is_unsigned = true;
			if (mysql_stmt_bind_param(stmt, &input)) BAIL_OUT("Bind parameter failed");
			query(admin, "PROXYSQL FLUSH QUERY CACHE");
			const long long initial_hits = hits(admin), initial_inserts = inserts(admin);
			ok(execute(stmt, length), "N=%lu deprecate_eof=%d: backend result has exact length and every byte", length, eof);
			ok(followup(mysql), "N=%lu deprecate_eof=%d: SELECT 1 after backend result", length, eof);
			// Resend parameter types so both execute packets have the same cache key.
			if (mysql_stmt_bind_param(stmt, &input)) BAIL_OUT("Rebind parameter failed");
			ok(execute(stmt, length), "N=%lu deprecate_eof=%d: repeated result has exact length and every byte", length, eof);
			ok(followup(mysql), "N=%lu deprecate_eof=%d: SELECT 1 after repeated result", length, eof);
			ok(hits(admin) == initial_hits + (prepared_cache ? 1 : 0)
				&& inserts(admin) == initial_inserts + (prepared_cache ? 1 : 0),
				"N=%lu deprecate_eof=%d: cache replay and insertion match server tier", length, eof);
			mysql_stmt_close(stmt);
			mysql_close(mysql);
		}
	}
	restore_rules();
	mysql_close(admin);
	return exit_status();
}
