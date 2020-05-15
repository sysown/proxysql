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

	const std::string mysql_client = "mysql";
	const std::string name = std::string("-u") + cl.username;
	const std::string pass = std::string("-p") + cl.password;
	const std::string tg_port = std::string("-P") + std::to_string(cl.port);
	const std::vector<const char*> cargs = { "mysql", name.c_str(), pass.c_str(), "-h", cl.host, tg_port.c_str(), "-C", "-e", "select 1" };

	// Query the mysql server in a compressed connection
	std::string result = "";
	int query_res = execvp(mysql_client, cargs, result);
	ok(query_res == 0 && result != "", "Compressed query should be executed correctly.");

	return exit_status();
}
