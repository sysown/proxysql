/**
 * @file repro_test_leak_3350.cpp
 * @brief Test to reproduce issue #3350.
 * @details This test is not meant to be executed, it's just a left as DOC of how to
 *   reproduce issue #3350.
 * @date 2021-03-18
 */

#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

const int NUM_EXECUTIONS = 10000;

int main(int argc, char** argv) {

	plan(NUM_EXECUTIONS);

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, 6033, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	std::string select_query { "SELECT DAY(?)" };

	// Initialize and prepare the statement
	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		ok(false, "mysql_stmt_init(), out of memory\n");
		return exit_status();
	}

	MYSQL_TIME ts;
	MYSQL_BIND bind;

	if (mysql_stmt_prepare(stmt, select_query.c_str(), strlen(select_query.c_str()))) {
		diag("select_query: %s", select_query.c_str());
		ok(false, "mysql_stmt_prepare at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return exit_status();
	}

	/* set up input buffers for all 3 parameters */
	bind.buffer_type= MYSQL_TYPE_DATE;
	bind.buffer= (char *)&ts;
	bind.is_null= 0;
	bind.length= 0;

	mysql_stmt_bind_param(stmt, &bind);

	ts.year= 2002;
	ts.month= 2;
	ts.day= 3;

	ts.hour= 10;
	ts.minute= 45;
	ts.second= 20;

	// Execute the prepared statement and check that the field count is correct after doing the execute
	for (int i = 0; i < NUM_EXECUTIONS; i++) {

		if (mysql_stmt_execute(stmt)) {
			ok(false, "mysql_stmt_execute at line %d failed: %s\n", __LINE__ , mysql_stmt_error(stmt));
		}
		if (mysql_stmt_fetch(stmt)) {
			ok(false, "mysql_stmt_fetch at line %d failed: %s\n", __LINE__ , mysql_stmt_error(stmt));
		}

		int field_count = mysql_stmt_field_count(stmt);
		ok(field_count == 1, "Field count should be '1'");
	}

	if (mysql_stmt_close(stmt)) {
		ok(false, "mysql_stmt_close at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
	}

	mysql_close(mysql);

	return exit_status();
}
