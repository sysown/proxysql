/**
 * @file repro_test_leak_3525.cpp
 * @brief Test to reproduce issue #3525.
 * @details This test is not meant to be executed, it's just a left as DOC of how to
 *   reproduce issue #3525.
 * @date 2021-07-30
 */

#include <string>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(1);

	MYSQL* mysql = mysql_init(NULL);
	if (mysql == NULL) {
		return exit_status();
	}

	if (
		!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)
	) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		return exit_status();
	}

	MYSQL_STMT *stmt = mysql_stmt_init(mysql);
	if (stmt == NULL) {
		ok(false, " mysql_stmt_init(), out of memory\n");
		return exit_status();
	}

	// Invalid statement
	bool failed = false;
	std::string my_errmsg {};
	int my_errno = 0;

	std::string query { "BEGIN" };
	if (mysql_stmt_prepare(stmt, query.c_str(), query.size())) {
		my_errno = mysql_errno(mysql);
		my_errmsg = mysql_error(mysql);

		failed = true;
	} else {
		my_errmsg = "NOT A FAILURE!";
	}

	ok(
		failed, "'mysql_stmt_prepare' should fail: ('err_code': %d, 'err_msg': '%s')\n",
		my_errno, my_errmsg.c_str()
	);

	if (mysql_stmt_close(stmt)) {
		ok(false, "mysql_stmt_close at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
		return exit_status();
	}

	mysql_stmt_close(stmt);
	mysql_close(mysql);
	mysql_library_end();

	mysql_close(mysql);
}

