/**
 * @file test_admin_prometheus_metrics_dump-t.cpp
 * @brief This test admin command: 'SHOW PROMETHEUS METRICS'.
 * @date 2020-11-07
 */

#include <algorithm>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

std::size_t supported_metrics = 121;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(3);

	MYSQL* proxysql_admin = mysql_init(NULL);

	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Connnect to local proxysql
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	MYSQL_QUERY(proxysql_admin, "SHOW PROMETHEUS METRICS\\G");
	MYSQL_RES* p_resulset = mysql_store_result(proxysql_admin);
	MYSQL_ROW data_row = mysql_fetch_row(p_resulset);
	std::string row_value {};
	if (data_row[0]) { row_value = data_row[0]; }

	mysql_free_result(p_resulset);

	std::size_t metrics_num = count_matches(row_value, "HELP");
	ok(
		metrics_num >= supported_metrics,
		"Metrics dump is exporting a currently supported metrics. (Actual: %lu) >= (Expected: %lu)",
		metrics_num,
		supported_metrics
	);

	// Stop ProxySQL
	MYSQL_QUERY(proxysql_admin, "PROXYSQL STOP");
	sleep(2);

	// Check empty output
	MYSQL_QUERY(proxysql_admin, "SHOW PROMETHEUS METRICS\\G");
	p_resulset = mysql_store_result(proxysql_admin);
	data_row = mysql_fetch_row(p_resulset);

	if (data_row[0]) {
		row_value = data_row[0];
	} else {
		row_value = "NULL";
	}

	mysql_free_result(p_resulset);

	ok(
		row_value == "NULL",
		"'Data' should be NULL when ProxySQL is in STOP state."
	);

	// Start ProxySQL again
	MYSQL_QUERY(proxysql_admin, "PROXYSQL START");
	sleep(2);

	// Check empty output
	MYSQL_QUERY(proxysql_admin, "SHOW PROMETHEUS METRICS\\G");
	p_resulset = mysql_store_result(proxysql_admin);
	data_row = mysql_fetch_row(p_resulset);
	if (data_row[0]) { row_value = data_row[0]; }
	mysql_free_result(p_resulset);

	metrics_num = count_matches(row_value, "HELP");
	ok(
		metrics_num >= supported_metrics,
		"Metrics dump is exporting a currently supported metrics. (Actual: %lu) >= (Expected: %lu)",
		metrics_num,
		supported_metrics
	);

	return exit_status();
}
