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

	// Snapshot the original pgsql-max_connections value (may not exist)
	char original_pgsql_max_conn[64] = {0};
	if (mysql_query(admin, "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-max_connections'") == 0) {
		MYSQL_RES* snap = mysql_store_result(admin);
		if (snap) {
			MYSQL_ROW row = mysql_fetch_row(snap);
			if (row && row[0]) {
				snprintf(original_pgsql_max_conn, sizeof(original_pgsql_max_conn), "%s", row[0]);
			}
			mysql_free_result(snap);
		}
	}

	MYSQL_QUERY(admin,
		"INSERT OR REPLACE INTO global_variables(variable_name, variable_value) "
		"VALUES "
		"('pgsql-max_connections', '0'), "
		"('pgsql-bogus_var_xyz', 'something')");

	if (mysql_query(admin, "LOAD PGSQL VARIABLES TO RUNTIME")) {
		diag("LOAD PGSQL VARIABLES TO RUNTIME failed: %s", mysql_error(admin));
		return exit_status();
	}
	const char* info = mysql_info(admin);
	diag("LOAD PGSQL info: %s", info ? info : "(null)");

	int rejected = -1, unknown = -1;
	if (info) {
		const char* r = strstr(info, "Rejected: ");
		if (r) rejected = atoi(r + strlen("Rejected: "));
		const char* u = strstr(info, "Unknown: ");
		if (u) unknown = atoi(u + strlen("Unknown: "));
	}
	ok(info && rejected >= 1 && unknown >= 1,
	   "LOAD PGSQL VARIABLES TO RUNTIME info='%s' has Rejected>=1 and Unknown>=1 (got Rejected: %d, Unknown: %d)",
	   info ? info : "(null)", rejected, unknown);

	MYSQL_QUERY(admin, "DELETE FROM global_variables WHERE variable_name='pgsql-bogus_var_xyz'");
	if (original_pgsql_max_conn[0]) {
		char q[256];
		snprintf(q, sizeof(q), "UPDATE global_variables SET variable_value='%s' WHERE variable_name='pgsql-max_connections'", original_pgsql_max_conn);
		MYSQL_QUERY(admin, q);
	} else {
		MYSQL_QUERY(admin, "DELETE FROM global_variables WHERE variable_name='pgsql-max_connections'");
	}
	MYSQL_QUERY(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

	mysql_close(admin);
	return exit_status();
}
