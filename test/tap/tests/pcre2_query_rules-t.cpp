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
		run_admin_checked(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	const bool query_ok = setup_ok && get_single_value(proxy, query, value);
	ok(query_ok && value == expected, "%s (expected '%s', got '%s')", label, expected,
		query_ok ? value.c_str() : "<query failed>");
	return query_ok && value == expected;
}

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		return -1;
	}

	plan(5);

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
			"SELECT 1 + 2", "11", "pcrecpp replaces one match");
		run_rewrite_case(admin, proxy,
			"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61191, 1, '[0-9]', '9', 'CASELESS,GLOBAL', 1)",
			"SELECT 1 + 2", "18", "pcrecpp replaces all matches with GLOBAL");
		run_rewrite_case(admin, proxy,
			"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61192, 1, '^SELECT ([0-9]+)$', CONCAT('\\\\0:', '\\\\1'), 'CASELESS', 1)",
			"SELECT 1", "SELECT 1:1", "pcrecpp expands whole match and capture references");
		run_rewrite_case(admin, proxy,
			"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61193, 1, '^SELECT 1$', 'SELECT ''\\\\''', 'CASELESS', 1)",
			"SELECT 1", "\\", "pcrecpp replacement preserves a literal backslash");
		run_rewrite_case(admin, proxy,
			"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, re_modifiers, apply) "
			"VALUES (61194, 1, '^SELECT 7$', 'SELECT \\\\x', 'CASELESS', 1)",
			"SELECT 7", "7", "malformed legacy escape leaves the query unchanged");
	} else {
		for (int i = 0; i < 5; ++i) {
			ok(0, "could not configure mysql-query_processor_regex for PCRE-compatible rewrite test");
		}
	}

	const bool teardown_ok =
		run_admin_checked(admin, "DELETE FROM mysql_query_rules WHERE rule_id BETWEEN 61190 AND 61194") &&
		run_admin_checked(admin, "LOAD MYSQL QUERY RULES TO RUNTIME") &&
		(!original_regex.empty() &&
		 run_admin_checked(admin, ("SET mysql-query_processor_regex=" + original_regex).c_str()) &&
		 run_admin_checked(admin, "LOAD MYSQL VARIABLES TO RUNTIME"));
	if (!teardown_ok) {
		diag("Failed to restore MySQL query-rule test state");
	}

	mysql_close(proxy);
	mysql_close(admin);
	return exit_status();
}
