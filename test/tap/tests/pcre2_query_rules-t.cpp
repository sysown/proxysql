#include <cstdio>
#include <cstring>
#include <string>

#include "command_line.h"
#include "mysql.h"
#include "tap.h"
#include "utils.h"

static bool run_admin_checked(MYSQL* admin, const char* sql) {
	if (mysql_query_t(admin, sql) == 0) {
		return true;
	}

	diag("Admin command failed [%s]: %s", sql, mysql_error(admin));
	return false;
}

static bool get_single_value(MYSQL* conn, const char* sql, std::string& value) {
	if (mysql_query_t(conn, sql) != 0) {
		diag("Query failed [%s]: %s", sql, mysql_error(conn));
		return false;
	}

	MYSQL_RES* result = mysql_store_result(conn);
	if (result == nullptr) {
		diag("Query returned no result [%s]: %s", sql, mysql_error(conn));
		return false;
	}

	bool success = false;
	if (mysql_num_rows(result) == 1) {
		MYSQL_ROW row = mysql_fetch_row(result);
		if (row != nullptr && row[0] != nullptr) {
			value = row[0];
			success = true;
		}
	}
	if (!success) {
		diag("Expected one value from [%s]", sql);
	}
	mysql_free_result(result);
	return success;
}

// Each case owns the complete in-memory rule set. A pre-existing apply=1 rule
// could otherwise intercept the test query before its fixture rule runs. Keep
// this runtime-only: the TAP harness restores persistent configuration itself.
static bool reset_query_rules(MYSQL* admin) {
	return run_admin_checked(admin, "DELETE FROM mysql_query_rules") &&
		run_admin_checked(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
}

// Name of the engine under test, prefixed to every assertion.
static std::string engine_label;

static bool run_rewrite_case(MYSQL* admin, MYSQL* proxy, const char* insert_rule,
	const char* query, const char* expected, const char* label) {
	std::string value;
	const bool setup_ok =
		reset_query_rules(admin) &&
		run_admin_checked(admin, insert_rule) &&
		run_admin_checked(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	const bool query_ok = setup_ok && get_single_value(proxy, query, value);
	ok(query_ok && value == expected, "%s: %s (expected '%s', got '%s')", engine_label.c_str(), label, expected,
		query_ok ? value.c_str() : "<query failed>");
	return query_ok && value == expected;
}

static void run_negated_error_case(MYSQL* admin, MYSQL* proxy, const char* insert_rule) {
	std::string value;
	const bool setup_ok =
		reset_query_rules(admin) &&
		run_admin_checked(admin, insert_rule) &&
		run_admin_checked(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	const bool matching_ok = setup_ok && get_single_value(proxy, "SELECT 8", value);
	ok(matching_ok && value == "8",
		"%s: negated rule permits its matching statement (expected '8', got '%s')",
		engine_label.c_str(), matching_ok ? value.c_str() : "<query failed>");

	const bool blocked = setup_ok && mysql_query_t(proxy, "SELECT 7") != 0;
	const std::string error = blocked ? mysql_error(proxy) : "";
	ok(blocked && error.find("negated rule blocked") != std::string::npos,
		"%s: negated rule blocks its non-matching statement with the configured error (got '%s')",
		engine_label.c_str(), blocked ? error.c_str() : "<query succeeded>");
}

static constexpr int kCasesPerEngine = 8;

// Runs every case on one regex engine. The cases behave the same on engine 1
// (PCRE) and engine 3 (PCRE2), see doc/query_rules_regex_engines.md.
static void run_engine_cases(MYSQL* admin, MYSQL* proxy, int engine) {
	engine_label = (engine == 3 ? "engine 3 (PCRE2)" : "engine 1 (PCRE)");
	const std::string set_engine = "SET mysql-query_processor_regex=" + std::to_string(engine);
	if (!run_admin_checked(admin, set_engine.c_str()) ||
		!run_admin_checked(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) {
		for (int i = 0; i < kCasesPerEngine; ++i) {
			ok(0, "%s: could not configure mysql-query_processor_regex", engine_label.c_str());
		}
		return;
	}
	run_rewrite_case(admin, proxy,
		"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
		"VALUES (61190, 1, '[0-9]', '9', 'CASELESS', 1)",
		"SELECT 1 + 2", "11", "replaces one match");
	run_rewrite_case(admin, proxy,
		"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
		"VALUES (61191, 1, '[0-9]', '9', 'CASELESS,GLOBAL', 1)",
		"SELECT 1 + 2", "18", "replaces all matches with GLOBAL");
	run_rewrite_case(admin, proxy,
		"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
		"VALUES (61192, 1, '^SELECT ([0-9]+)$', '\\0 + \\1', 'CASELESS', 1)",
		"SELECT 1", "2", "expands legacy whole-match and capture references");
	run_rewrite_case(admin, proxy,
		"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
		"VALUES (61193, 1, 'TOKEN', '\\\\*/ + 1 /*', 'CASELESS', 1)",
		"SELECT 1 /*TOKEN*/", "2", "replacement emits a legacy literal backslash");
	run_rewrite_case(admin, proxy,
		"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
		"VALUES (61194, 1, '^SELECT 7$', 'SELECT \\x', 'CASELESS', 1)",
		"SELECT 7", "7", "malformed legacy escape leaves the query unchanged");
	run_rewrite_case(admin, proxy,
		"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
		"VALUES (61190, 1, '^SELECT ''[A-Z]''$', 'SELECT 9', 'CASELESS', 1)",
		"SELECT 'a'", "9", "CASELESS replacement matches different-case text");
	run_negated_error_case(admin, proxy,
		"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, negate_match_pattern, error_msg, re_modifiers, apply) "
		"VALUES (61194, 1, '^SELECT 8$', 1, 'negated rule blocked', 'CASELESS', 1)");
}

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		return -1;
	}

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (admin == nullptr) {
		BAIL_OUT("Cannot connect to the ProxySQL admin interface");
	}
	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (proxy == nullptr) {
		mysql_close(admin);
		BAIL_OUT("Cannot connect to the ProxySQL MySQL interface");
	}

	std::string original_regex;
	std::string version;
	if (!get_single_value(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='mysql-query_processor_regex'",
			original_regex) ||
		!get_single_value(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='admin-version'", version)) {
		BAIL_OUT("Cannot read mysql-query_processor_regex / admin-version");
	}
	// Engine 3 (PCRE2) exists from v3.1 (PROXYSQL31) on; v3.0 rejects it
	// (issue #6411). Engine 1 (PCRE) is covered on every tier.
	int major = 0, minor = 0;
	if (sscanf(version.c_str(), "%d.%d", &major, &minor) != 2) {
		BAIL_OUT("Cannot determine ProxySQL build tier from admin-version '%s'", version.c_str());
	}
	const bool have_engine3 = major > 3 || (major == 3 && minor >= 1);
	diag("ProxySQL %s: testing engine 1%s", version.c_str(), have_engine3 ? " and engine 3" : "");
	plan(kCasesPerEngine * (have_engine3 ? 2 : 1));

	run_engine_cases(admin, proxy, 1);
	if (have_engine3) {
		run_engine_cases(admin, proxy, 3);
	}

	bool teardown_ok = true;
	teardown_ok &= reset_query_rules(admin);
	if (!original_regex.empty()) {
		teardown_ok &= run_admin_checked(admin, ("SET mysql-query_processor_regex=" + original_regex).c_str());
		teardown_ok &= run_admin_checked(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}
	if (!teardown_ok) {
		diag("Failed to restore MySQL query-rule test state");
	}

	mysql_close(proxy);
	mysql_close(admin);
	return exit_status();
}
