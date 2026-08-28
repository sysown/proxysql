/**
 * @file reg_test_5306-show_warnings_with_comment-t.cpp
 * @brief This test verifies that SHOW WARNINGS with inline comments does not incorrectly return warning_count in EOF packet.
 */

#include <stdio.h>
#include "mysql.h"
#include "mysqld_error.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(4);

	// Initialize Admin connection
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	// Connnect to ProxySQL Admin
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-handle_warnings=1");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Initialize ProxySQL connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}

	// Query that produces a warning (truncation warning, works on MySQL 5.7+)
	const char* WARNING_QUERY = "SELECT CAST('abc' AS SIGNED)";

	// Test cases: SHOW WARNINGS without and with comment
	const char* show_warnings_queries[] = {
		"SHOW WARNINGS",
		"SHOW /* comment */ WARNINGS"
	};

	for (const char* show_query : show_warnings_queries) {
		MYSQL_QUERY(proxysql, WARNING_QUERY);
		MYSQL_RES* res = mysql_store_result(proxysql);
		if (!res) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
			return exit_status();
		}
		mysql_free_result(res);

		unsigned int warning_count_after_query = mysql_warning_count(proxysql);
		diag("After WARNING_QUERY: warning_count=%u", warning_count_after_query);

		MYSQL_QUERY(proxysql, show_query);
		res = mysql_store_result(proxysql);
		if (!res) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
			return exit_status();
		}
		unsigned int row_count = mysql_num_rows(res);
		mysql_free_result(res);

		unsigned int warning_count_after_show = mysql_warning_count(proxysql);
		diag("After '%s': warning_count=%u, rows=%u", show_query, warning_count_after_show, row_count);

		ok(warning_count_after_query == 1,
			"WARNING_QUERY should produce warning. warning_count=%u", warning_count_after_query);

		ok(warning_count_after_show == 0,
			"'%s' should return warning_count=0 in EOF packet. Actual=%u", show_query, warning_count_after_show);
	}

	mysql_close(proxysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
