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

static bool run_rewrite_case(MYSQL* admin, MYSQL* proxy, const char* insert_rule,
	const char* query, const char* expected, const char* label) {
	std::string value;
	const bool setup_ok =
		run_admin_checked(admin, "DELETE FROM mysql_query_rules WHERE rule_id BETWEEN 61190 AND 61194") &&
		run_admin_checked(admin, insert_rule) &&
		run_admin_checked(admin, "SAVE MYSQL QUERY RULES TO DISK") &&
		run_admin_checked(admin, "LOAD MYSQL QUERY RULES FROM DISK") &&
		run_admin_checked(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	const bool query_ok = setup_ok && get_single_value(proxy, query, value);
	ok(query_ok && value == expected, "%s (expected '%s', got '%s')", label, expected,
		query_ok ? value.c_str() : "<query failed>");
	return query_ok && value == expected;
}

static void run_negated_error_case(MYSQL* admin, MYSQL* proxy, const char* insert_rule) {
	std::string value;
	const bool setup_ok =
		run_admin_checked(admin, "DELETE FROM mysql_query_rules WHERE rule_id BETWEEN 61190 AND 61194") &&
		run_admin_checked(admin, insert_rule) &&
		run_admin_checked(admin, "SAVE MYSQL QUERY RULES TO DISK") &&
		run_admin_checked(admin, "LOAD MYSQL QUERY RULES FROM DISK") &&
		run_admin_checked(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	const bool matching_ok = setup_ok && get_single_value(proxy, "SELECT 8", value);
	ok(matching_ok && value == "8",
		"negated PCRE2 rule permits its matching statement (expected '8', got '%s')",
		matching_ok ? value.c_str() : "<query failed>");

	const bool blocked = setup_ok && mysql_query_t(proxy, "SELECT 7") != 0;
	const std::string error = blocked ? mysql_error(proxy) : "";
	ok(blocked && error.find("PCRE2 negated rule blocked") != std::string::npos,
		"negated PCRE2 rule blocks its non-matching statement with the configured error (got '%s')",
		blocked ? error.c_str() : "<query succeeded>");
}

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		return -1;
	}

	plan(8);

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (admin == nullptr) {
		return exit_status();
	}
	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (proxy == nullptr) {
		mysql_close(admin);
		return exit_status();
	}

	std::string original_regex;
	const bool configured =
		get_single_value(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='mysql-query_processor_regex'",
			original_regex) &&
		run_admin_checked(admin, "SET mysql-query_processor_regex=1") &&
		run_admin_checked(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	if (configured) {
		run_rewrite_case(admin, proxy,
			"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61190, 1, '[0-9]', '9', 'CASELESS', 1)",
			"SELECT 1 + 2", "11", "PCRE-compatible mode replaces one match");
		run_rewrite_case(admin, proxy,
			"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61191, 1, '[0-9]', '9', 'CASELESS,GLOBAL', 1)",
			"SELECT 1 + 2", "18", "PCRE-compatible mode replaces all matches with GLOBAL");
		run_rewrite_case(admin, proxy,
			"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61192, 1, '^SELECT ([0-9]+)$', '\\0 + \\1', 'CASELESS', 1)",
			"SELECT 1", "2", "PCRE-compatible mode expands legacy whole-match and capture references");
		run_rewrite_case(admin, proxy,
			"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61193, 1, 'TOKEN', '\\\\*/ + 1 /*', 'CASELESS', 1)",
			"SELECT 1 /*TOKEN*/", "2", "PCRE-compatible replacement emits a legacy literal backslash");
		run_rewrite_case(admin, proxy,
			"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61194, 1, '^SELECT 7$', 'SELECT \\x', 'CASELESS', 1)",
			"SELECT 7", "7", "malformed legacy escape leaves the query unchanged");
		run_rewrite_case(admin, proxy,
			"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61190, 1, '^SELECT ''[A-Z]''$', 'SELECT 9', 'CASELESS', 1)",
			"SELECT 'a'", "9", "CASELESS PCRE-compatible replacement matches different-case text");
		run_negated_error_case(admin, proxy,
			"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, negate_match_pattern, error_msg, re_modifiers, apply) "
			"VALUES (61194, 1, '^SELECT 8$', 1, 'PCRE2 negated rule blocked', 'CASELESS', 1)");
	} else {
		for (int i = 0; i < 8; ++i) {
			ok(0, "could not configure mysql-query_processor_regex for PCRE-compatible rewrite test");
		}
	}

	bool teardown_ok = true;
	teardown_ok &= run_admin_checked(admin, "DELETE FROM mysql_query_rules WHERE rule_id BETWEEN 61190 AND 61194");
	teardown_ok &= run_admin_checked(admin, "SAVE MYSQL QUERY RULES TO DISK");
	teardown_ok &= run_admin_checked(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
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
