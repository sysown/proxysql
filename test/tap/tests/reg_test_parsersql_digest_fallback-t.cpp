/**
 * @file reg_test_parsersql_digest_fallback-t.cpp
 * @brief Unsupported ALTER statements retain digest-based routing predicates.
 */
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include "mysql.h"
#include "command_line.h"
#include "tap.h"

using Connection = std::unique_ptr<MYSQL, decltype(&mysql_close)>;

static bool execute(MYSQL* conn, const char* sql) {
	if (mysql_query(conn, sql)) {
		diag("Query failed (%u): %s; SQL: %s", mysql_errno(conn), mysql_error(conn), sql);
		return false;
	}
	MYSQL_RES* result = mysql_store_result(conn);
	if (result) mysql_free_result(result);
	return true;
}

struct Fixture {
	MYSQL* admin;
	bool saved = false;
	explicit Fixture(MYSQL* conn) : admin(conn) {}
	Fixture(const Fixture&) = delete;
	Fixture& operator=(const Fixture&) = delete;
	Fixture(Fixture&&) = delete;
	Fixture& operator=(Fixture&&) = delete;
	bool restore() {
		if (!saved) return true;
		bool restored = true;
		for (const char* sql : {
			"DELETE FROM mysql_query_rules",
			"INSERT INTO mysql_query_rules SELECT * FROM digest_fallback_runtime_rules",
			"DELETE FROM mysql_query_rules_fast_routing",
			"INSERT INTO mysql_query_rules_fast_routing SELECT * FROM digest_fallback_runtime_fast",
			"LOAD MYSQL QUERY RULES TO RUNTIME",
			"UPDATE global_variables SET variable_value=(SELECT variable_value FROM digest_fallback_runtime_vars v WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN (SELECT variable_name FROM digest_fallback_runtime_vars)",
			"LOAD MYSQL VARIABLES TO RUNTIME",
			"DELETE FROM mysql_query_rules",
			"INSERT INTO mysql_query_rules SELECT * FROM digest_fallback_rules",
			"DELETE FROM mysql_query_rules_fast_routing",
			"INSERT INTO mysql_query_rules_fast_routing SELECT * FROM digest_fallback_fast",
			"UPDATE global_variables SET variable_value=(SELECT variable_value FROM digest_fallback_vars v WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN (SELECT variable_name FROM digest_fallback_vars)"
		}) restored = execute(admin, sql) && restored;
		saved = !restored;
		return restored;
	}
	~Fixture() noexcept {
		try {
			if (!restore()) std::fputs("Digest fallback fixture restoration failed\n", stderr);
		} catch (...) {
			std::fputs("Digest fallback fixture restoration threw\n", stderr);
		}
	}
};

static bool configure(Fixture& fixture) {
	for (const char* sql : {
		"DROP TABLE IF EXISTS digest_fallback_rules",
		"DROP TABLE IF EXISTS digest_fallback_vars",
		"DROP TABLE IF EXISTS digest_fallback_fast",
		"DROP TABLE IF EXISTS digest_fallback_runtime_rules",
		"DROP TABLE IF EXISTS digest_fallback_runtime_fast",
		"DROP TABLE IF EXISTS digest_fallback_runtime_vars",
		"SELECT count(*) FROM runtime_mysql_query_rules",
		"SELECT count(*) FROM runtime_mysql_query_rules_fast_routing",
		"SELECT count(*) FROM runtime_global_variables",
		"CREATE TEMPORARY TABLE digest_fallback_runtime_rules AS SELECT * FROM runtime_mysql_query_rules",
		"CREATE TEMPORARY TABLE digest_fallback_runtime_fast AS SELECT * FROM runtime_mysql_query_rules_fast_routing",
		"CREATE TEMPORARY TABLE digest_fallback_runtime_vars AS SELECT * FROM runtime_global_variables WHERE variable_name LIKE 'mysql-%'",
		"CREATE TEMPORARY TABLE digest_fallback_fast AS SELECT * FROM mysql_query_rules_fast_routing",
		"CREATE TEMPORARY TABLE digest_fallback_rules AS SELECT * FROM mysql_query_rules",
		"CREATE TEMPORARY TABLE digest_fallback_vars AS SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-%'"
	}) if (!execute(fixture.admin, sql)) return false;
	fixture.saved = true;
	for (const char* sql : {
		"UPDATE global_variables SET variable_value=(SELECT variable_value FROM digest_fallback_runtime_vars v WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN (SELECT variable_name FROM digest_fallback_runtime_vars)",
		"DELETE FROM mysql_query_rules_fast_routing",
		"DELETE FROM mysql_query_rules",
		"INSERT INTO mysql_query_rules(rule_id,active,match_digest,error_msg,apply) VALUES (1,1,'^SELECT','SELECT_DIGEST_ONLY',1),(2,1,'^ALTER','ALTER_DIGEST_ONLY',1)",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
		"SET mysql-query_digests=1"
	}) if (!execute(fixture.admin, sql)) return false;
	return true;
}

static void check_rule(MYSQL* client, int parser, const char* sql, const char* expected_error) {
	const int rc = mysql_query(client, sql);
	const std::string error = mysql_error(client);
	MYSQL_RES* result = mysql_store_result(client);
	if (result) mysql_free_result(result);
	ok(rc != 0 && error == expected_error,
		"Parser %d applies the intended digest rule to %s (got: %s)", parser, sql, error.c_str());
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	Connection admin(mysql_init(nullptr), &mysql_close);
	if (!admin || !mysql_real_connect(admin.get(), cl.admin_host, cl.admin_username,
		cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) return EXIT_FAILURE;
	Fixture fixture(admin.get());
	if (!configure(fixture)) return EXIT_FAILURE;
	plan(5);
	for (int parser : {0, 1}) {
		const std::string setting = "SET mysql-query_processor_parser=" + std::to_string(parser);
		if (!execute(admin.get(), setting.c_str()) ||
			!execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME")) return EXIT_FAILURE;
		Connection client(mysql_init(nullptr), &mysql_close);
		if (!client || !mysql_real_connect(client.get(), cl.host, cl.username, cl.password,
			nullptr, cl.port, nullptr, 0)) return EXIT_FAILURE;
		check_rule(client.get(), parser, "SELECT 42", "SELECT_DIGEST_ONLY");
		// Error-message rules stop execution before any backend DDL is sent.
		check_rule(client.get(), parser, "ALTER TABLE digest_fallback_missing DISCARD TABLESPACE", "ALTER_DIGEST_ONLY");
	}
	ok(fixture.restore(), "Digest fallback fixture restored");
	return exit_status();
}
