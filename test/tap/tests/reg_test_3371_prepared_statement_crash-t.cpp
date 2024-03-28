/**
 * @file reg_test_3371_prepared_statement_crash-t.cpp
 * @brief Tries to execute prepared statements with a not existing stmt_id.
 * This used to crash ProxySQL , so this tap test verifies that ProxySQL
 * doesn't crash
 */


#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

const int NUM_LOOPS = 100; ///< Number of loops for statement execution.

int main(int argc, char** argv) {
	CommandLine cl;

	// Checking for required environmental variables
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(1+NUM_LOOPS*2); // Plan for testing purposes

	MYSQL* mysql = mysql_init(NULL); ///< MySQL connection object
	if (!mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	// Connecting to ProxySQL
	diag("Connecting to '%s@%s:%d'", cl.mysql_username, cl.host, cl.port);
	if (!mysql_real_connect(mysql, cl.host, cl.mysql_username, cl.mysql_password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	// Initialize and prepare all the statements
	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
		if (!stmt) {
			fprintf(stderr, "mysql_stmt_init(), out of memory\n");
			return exit_status();
		}

	std::string select_query = "SELECT 1";
	diag("select_query: %s", select_query.c_str());
	if (mysql_stmt_prepare(stmt, select_query.c_str(), strlen(select_query.c_str()))) {
		fprintf(stderr, "mysql_stmt_prepare at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return exit_status();
	}

	diag("Increasing stmt_id by 1, so that mysql_stmt_execute() must fail");
	int rc = 0;
	for (int i = 0; i < NUM_LOOPS ; i++) {
		stmt->stmt_id += 1;
		rc = mysql_stmt_execute(stmt);
		ok (rc , "mysql_stmt_execute() must fail");
		if (rc) {
			unsigned int psrc = mysql_stmt_errno(stmt);
			ok( psrc == 1243 , "mysql_stmt_execute at line %d failed: %d , %s", __LINE__ , psrc , mysql_stmt_error(stmt));
		}
	}

	diag("Decreasing stmt_id by 1, so that mysql_stmt_execute() must succeed");
	stmt->stmt_id -= NUM_LOOPS;
	rc = mysql_stmt_execute(stmt);
	ok (rc == 0 , "mysql_stmt_execute() succeeded");
	if (rc) {
		fprintf(stderr, "mysql_stmt_execute at line %d failed: %d , %s\n", __LINE__ , rc , mysql_stmt_error(stmt));
		mysql_close(mysql);
		mysql_library_end();
		return exit_status();
	}
	mysql_close(mysql);

	return exit_status();
}
