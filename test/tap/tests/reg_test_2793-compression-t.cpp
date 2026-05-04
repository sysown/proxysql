/**
 * @file reg_test_2793-compression-t.cpp
 * @brief This test is a regression test for issue #2793.
 * @date 2020-05-14
 */

#include <vector>
#include <string>
#include <stdio.h>
#include "mysql.h"
#include "mysqld_error.h"

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

	const std::string mysql_client = "mysql";
	std::string help_output {};
	const int help_res = execvp(mysql_client, { "mysql", "--help" }, help_output);
	const bool mysql_supports_zstd =
		help_res == 0
		&&
		help_output.find("compression-algorithms") != std::string::npos
		&&
		help_output.find("zstd-compression-level") != std::string::npos;

	// +1 test for the new variable visibility
	plan(mysql_supports_zstd ? 3 : 2);

	// Test: mysql-zstd_compression_level is visible via admin
	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (admin) {
		std::string val;
		int rc = get_variable_value(admin, "mysql-zstd_compression_level", val, true);
		ok(rc == EXIT_SUCCESS && val == "3",
			"mysql-zstd_compression_level visible in admin, default=3, got: %s",
			val.c_str());
		mysql_close(admin);
	} else {
		diag("Failed to connect to admin, skipping variable visibility test");
		skip(1, "admin connection failed");
	}

	const std::string name = std::string("-u") + cl.username;
	const std::string pass = std::string("-p") + cl.password;
	const std::string tg_port = std::string("-P") + std::to_string(cl.port);
	const std::vector<const char*> cargs = { "mysql", name.c_str(), pass.c_str(), "-h", cl.host, tg_port.c_str(), "-C", "-e", "select 1" };

	// Query the mysql server in a compressed connection
	std::string result = "";
	int query_res = execvp(mysql_client, cargs, result);
	ok(query_res == 0 && result != "", "Compressed query should be executed correctly.");

	if (mysql_supports_zstd) {
		const std::vector<const char*> zstd_args = {
			"mysql", name.c_str(), pass.c_str(), "-h", cl.host, tg_port.c_str(),
			"--compression-algorithms=zstd", "--zstd-compression-level=3", "-e", "select 1"
		};
		result.clear();
		query_res = execvp(mysql_client, zstd_args, result);
		ok(query_res == 0 && result != "", "ZSTD compressed query should be executed correctly.");
	} else {
		diag("Skipping ZSTD CLI coverage because the local mysql client does not expose zstd compression options.");
	}

	return exit_status();
}
