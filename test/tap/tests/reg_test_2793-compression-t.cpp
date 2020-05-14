/**
 * @file reg_test_2793-compression-t.cpp
 * @brief This test is a regression test for issue #2793.
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

	const char* mysql_select_command = "mysql";
	std::vector<const char*> cargs = { "mysql", "-uroot", "-proot", "-h", "127.0.0.1", "-P6033", "-C", "-e", "select 1" };

	// Query the mysql server in a compressed connection
	std::string result = "";
	int query_res = execvp(mysql_select_command, cargs, result);
	ok(query_res == 0 && result != "", "Compressed query should be executed correctly.");

	return exit_status();
}
