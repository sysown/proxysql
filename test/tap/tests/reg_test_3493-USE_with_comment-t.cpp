/**
 * @file reg_test_3493-USE_with_comment-t.cpp
 * @brief This test verifies that a 'USE' statement is properly tracked by
 *   ProxySQL, even when executed with a leading comment.
 * @details For being sure that the feature is properly supported the
 *   test performs the following actions:
 *
 *   1. Open a MYSQL connection to ProxySQL.
 *   2. Drops and creates a new database called 'reg_test_3493_use_comment'.
 *   3. Checks the currently selected database in **a new backend database
 *      connection** by means of the connection annotation
 *      "create_new_connection=1". This way it's ensured that ProxySQL is
 *      properly keeping track of the database selected in the issued 'USE'
 *      statement.
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>

#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

using nlohmann::json;

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* proxysql_mysql = mysql_init(NULL);

	if (
		!mysql_real_connect(
			proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0
		)
	) {
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			mysql_error(proxysql_mysql)
		);
		return EXIT_FAILURE;
	}

	// Prepare the DB for the test
	MYSQL_QUERY(proxysql_mysql, "DROP DATABASE IF EXISTS reg_test_3493_use_comment");
	MYSQL_QUERY(proxysql_mysql, "CREATE DATABASE reg_test_3493_use_comment");

	int err = mysql_query(proxysql_mysql, "/*+ placeholder_comment */ USE reg_test_3493_use_comment");
	if (err) {
		diag(
			"'USE' command failed with error code '%d' and error '%s'",
			err, mysql_error(proxysql_mysql)
		);
		return EXIT_FAILURE;
	}

	// Perform the 'SELECT DATABASE()' query in a new backend connection, to
	// verify that ProxySQL is properly tracking the previously performed 'USE'
	// statement.
	MYSQL_QUERY(proxysql_mysql, "/*+ ;create_new_connection=1 */ SELECT DATABASE()");
	MYSQL_RES* result = mysql_store_result(proxysql_mysql);
	if (result == nullptr) {
		diag("Invalid 'MYSQL_RES' returned from 'SELECT DATABASE()'");
		return EXIT_FAILURE;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	if (row == nullptr) {
		diag("Invalid 'MYSQL_ROW' returned from 'SELECT DATABASE()'");
		return EXIT_FAILURE;
	}

	std::string database_name { row[0] };

	ok(
		database_name == "reg_test_3493_use_comment",
		"Selected DB name should be equal to actual DB name: (Exp: '%s') == (Act: '%s')",
		"reg_test_3493_use_comment",
		database_name.c_str()
	);

	// Drop created database
	MYSQL_QUERY(proxysql_mysql, "DROP DATABASE IF EXISTS reg_test_3493_use_comment");

	mysql_close(proxysql_mysql);

	return exit_status();
}
