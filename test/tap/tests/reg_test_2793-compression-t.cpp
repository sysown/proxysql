/**
 * @file test_mixed_compression-t.cpp
 * @brief This test is a regression test for issue #2793.
 * @version v2.1.12
 * @date 2020-05-14
 */

#include <vector>
#include <string>
#include <stdio.h>
#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(1);

	MYSQL* proxysql_admin = mysql_init(NULL);
	MYSQL* proxysql_mysql = mysql_init(NULL);

	// Initialize connections
	if (!proxysql_admin || !proxysql_mysql) {
		if (!proxysql_admin) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		} else {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		}
		return -1;
	}

	// Connnect to local proxysql
	if (!mysql_real_connect(proxysql_admin, "127.0.0.1", "admin", "admin", NULL, 6032, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Mixed compressed / uncompressed queries test #1493
	const char* mysql_select_command = "mysql";
	std::vector<const char*> cargs = { "mysql", "-uroot", "-proot", "-h", "127.0.0.1", "-P6033", "-C", "-e", "select 1" };

	// Query the mysql server in a compressed connection
	std::string result = "";
	int query_res = execvp(mysql_select_command, cargs, result);
	ok(query_res == 0 && result != "", "Compressed query should be executed correctly.");

	return exit_status();
}
