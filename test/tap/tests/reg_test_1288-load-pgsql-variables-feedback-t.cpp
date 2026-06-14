/**
 * @file reg_test_1288-load-pgsql-variables-feedback-t.cpp
 * @brief Verify that LOAD PGSQL VARIABLES TO RUNTIME surfaces a Records/Updated/Rejected/Unknown
 *        summary in the OK packet's info field. The pgsql path uses a separate flush helper with
 *        its own duplicated loop. See issue #1288.
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

	plan(1);

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
		"('pgsql-max_connections', '1000'), "
		"('pgsql-bogus_var_xyz', 'something')");

	if (mysql_query(admin, "LOAD PGSQL VARIABLES TO RUNTIME")) {
		diag("LOAD PGSQL VARIABLES TO RUNTIME failed: %s", mysql_error(admin));
		return exit_status();
	}
	const char* info = mysql_info(admin);
	diag("LOAD PGSQL info: %s", info ? info : "(null)");

	bool has_records_2 = info && strstr(info, "Records: 2") != NULL;
	bool has_updated_1 = info && strstr(info, "Updated: 1") != NULL;
	bool has_unknown_1 = info && strstr(info, "Unknown: 1") != NULL;
	ok(has_records_2 && has_updated_1 && has_unknown_1,
	   "LOAD PGSQL VARIABLES TO RUNTIME info='%s' reports Records: 2 Updated: 1 Unknown: 1",
	   info ? info : "(null)");

	MYSQL_QUERY(admin, "DELETE FROM global_variables WHERE variable_name='pgsql-bogus_var_xyz'");
	MYSQL_QUERY(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

	mysql_close(admin);
	return exit_status();
}
