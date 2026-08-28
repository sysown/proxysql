/**
 * @file reg_test_1288-load-mysql-variables-feedback-t.cpp
 * @brief Verify that LOAD MYSQL VARIABLES TO RUNTIME surfaces a Records/Updated/Rejected/Unknown
 *        summary in the OK packet's info field. See issue #1288.
 */

#include <stdio.h>
#include <string>
#include <string.h>
#include "mysql.h"
#include "mysqld_error.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(2);

	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}

	MYSQL_QUERY(admin,
		"INSERT OR REPLACE INTO global_variables(variable_name, variable_value) "
		"VALUES "
		"('mysql-max_connections', '10000'), "
		"('mysql-monitor_ping_interval', '2000')");

	MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='0' WHERE variable_name='mysql-max_connections'");
	MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='foo' WHERE variable_name='mysql-monitor_ping_interval'");
	MYSQL_QUERY(admin, "INSERT OR REPLACE INTO global_variables(variable_name, variable_value) VALUES('mysql-bogus_var_xyz', '1')");

	if (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) {
		diag("LOAD MYSQL VARIABLES TO RUNTIME failed: %s", mysql_error(admin));
		return exit_status();
	}
	const char* info = mysql_info(admin);
	diag("LOAD (mixed) info: %s", info ? info : "(null)");

	bool has_rejected_2 = info && strstr(info, "Rejected: 2") != NULL;
	bool has_unknown_1  = info && strstr(info, "Unknown: 1")  != NULL;
	ok(has_rejected_2 && has_unknown_1,
	   "LOAD MYSQL VARIABLES TO RUNTIME info='%s' includes 'Rejected: 2' and 'Unknown: 1' (issue #1288)",
	   info ? info : "(null)");

	MYSQL_QUERY(admin, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-max_connections'");
	MYSQL_RES* res = mysql_store_result(admin);
	bool runtime_value_reset = false;
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row && row[0]) {
			// The rejected value '0' should NOT be in runtime; the row should reflect the previous valid value ('10000' from setup)
			runtime_value_reset = (strcmp(row[0], "0") != 0);
		}
		mysql_free_result(res);
	}
	ok(runtime_value_reset,
	   "runtime mysql-max_connections was reset away from rejected '0' value");

	MYSQL_QUERY(admin, "DELETE FROM global_variables WHERE variable_name='mysql-bogus_var_xyz'");
	MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='10000' WHERE variable_name='mysql-max_connections'");
	MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='2000' WHERE variable_name='mysql-monitor_ping_interval'");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);
	return exit_status();
}
