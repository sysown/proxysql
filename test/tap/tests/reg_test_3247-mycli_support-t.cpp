/**
 * @file reg_test_3247-mycli_support-t.cpp
 * @brief This is a regression test for issue #3247. Testing 'mycli' added support.
*/

#include <strings.h>
#include <string>
#include <stdio.h>
#include "mysql.h"

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

	plan(2);

	// Test that 'mycli' is able to connect and execute a query
	const std::string admin_user = std::string("-u") + cl.admin_username + " ";
	const std::string admin_pass = std::string("-p") + cl.admin_password + " ";
	const std::string admin_port = std::string("-P") + std::to_string(cl.admin_port) + " ";
	const std::string host = std::string("-h ") + std::string(cl.host) + " ";

	int mysqlsh_res = system(
		(std::string("mycli ") + admin_user + admin_pass +
		 admin_port + host + "-e \"SELECT NULL LIMIT 0\"" + " > /dev/null").c_str()
	);
	ok(mysqlsh_res == 0, "'mycli' empty select command should be correctly executed. Err code was: %d", mysqlsh_res);

	// Test the new introduced query "SELECT CONNECTION_ID()"
	MYSQL* mysql_server = mysql_init(NULL);

	if (!mysql_server) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql_server));
		return -1;
	}

	if (!mysql_real_connect(mysql_server, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql_server));
		return -1;
	}

	int query_res = mysql_query(mysql_server, "SELECT CONNECTION_ID()");

	if (query_res == 0) {
		MYSQL_RES* concat_res = mysql_store_result(mysql_server);
		unsigned int concat_num_fields = mysql_num_fields(concat_res);
		MYSQL_ROW concat_row = mysql_fetch_row(concat_res);

		if (concat_row && concat_num_fields == 1) {
			std::string row_result { concat_row[0] };

			ok(
				row_result == std::to_string(0),
				"Output received for \"SELECT CONNECTION_ID()\" was: %s",
				row_result.c_str()
			);
		} else {
			ok(false, "Invalid resulset. Expected 'num_fields' = 1, not %d", concat_num_fields);
		}

		mysql_free_result(concat_res);
	} else {
		ok(false, "Query result for \"SELECT CONNECTION_ID()\" should be 0. Was: %d", query_res);
	}

	return exit_status();
}
