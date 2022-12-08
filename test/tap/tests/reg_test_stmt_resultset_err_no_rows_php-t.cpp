/**
 * @file reg_test_stmt_resultset_err_no_rows_php-t.cpp
 * @brief Checks handling of STMT binary resultsets with errors by means of PHP test
 *   'reg_test_stmt_resultset_err_no_rows.php'.
 */

#include <iostream>
#include <utility>
#include <vector>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

int main(int argc, char** argv) {
	plan(1);

	CommandLine cl {};

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	string php_stdout {};
	string php_stderr {};
	const string php_path { string{ cl.workdir } + "./reg_test_stmt_resultset_err_no_rows.php" };

	to_opts_t opts {2 * 1000 * 1000, 0, 0, 0};
	int exec_res = wexecvp(php_path, {}, opts, php_stdout, php_stderr);

	diag("Output from executed test: '%s'", php_path.c_str());
	diag("========================================================================");

	std::cout << php_stdout;

	diag("========================================================================");

	ok(exec_res == EXIT_SUCCESS, "Test exited with code '%d'", exec_res);
}
