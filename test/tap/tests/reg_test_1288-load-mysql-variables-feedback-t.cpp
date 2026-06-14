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
	MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='1' WHERE variable_name='mysql-bogus_var_xyz'");

	if (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) {
		diag("LOAD MYSQL VARIABLES TO RUNTIME failed: %s", mysql_error(admin));
		return exit_status();
	}
	const char* info = mysql_info(admin);
	diag("LOAD (mixed) info: %s", info ? info : "(null)");

	bool has_records_3  = info && strstr(info, "Records: 3")  != NULL;
	bool has_updated_0  = info && strstr(info, "Updated: 0")  != NULL;
	bool has_rejected_2 = info && strstr(info, "Rejected: 2") != NULL;
	bool has_unknown_1  = info && strstr(info, "Unknown: 1")  != NULL;
	ok(has_records_3 && has_updated_0 && has_rejected_2 && has_unknown_1,
	   "LOAD MYSQL VARIABLES TO RUNTIME info='%s' reports Records: 3 Updated: 0 Rejected: 2 Unknown: 1",
	   info ? info : "(null)");

	MYSQL_QUERY(admin, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-max_connections'");
	MYSQL_RES* res = mysql_store_result(admin);
	ok(res != NULL && mysql_fetch_row(res) != NULL,
	   "runtime_global_variables query returned a result set with at least one row");
	if (res) {
		mysql_free_result(res);
	}

	MYSQL_QUERY(admin, "DELETE FROM global_variables WHERE variable_name='mysql-bogus_var_xyz'");
	MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='10000' WHERE variable_name='mysql-max_connections'");
	MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='2000' WHERE variable_name='mysql-monitor_ping_interval'");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);
	return exit_status();
}
