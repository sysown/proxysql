#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>

#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

const int NUM_EXECUTIONS = 3;

int main(int argc, char** argv) {
	CommandLine cl;

	plan(NUM_EXECUTIONS);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	std::string select_query { "SELECT /*+ MAX_EXECUTION_TIME(10) */ COUNT(*) FROM test.sbtest1 a JOIN test.sbtest1 b WHERE (a.id+b.id)%2" };

	// Initialize and prepare the statement
	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		ok(false, "mysql_stmt_init(), out of memory\n");
		return exit_status();
	}

	if (mysql_stmt_prepare(stmt, select_query.c_str(), strlen(select_query.c_str()))) {
		diag("select_query: %s", select_query.c_str());
		ok(false, "mysql_stmt_prepare at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return exit_status();
	}

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
