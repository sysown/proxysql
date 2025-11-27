/**
 * @file test_ignore_min_gtid-t.cpp
 * @brief This test file verifies the functionality of the mysql-ignore_min_gtid_annotations variable.
 *  - Sets mysql-ignore_min_gtid_annotations=true, so queries annotated with min_gtid succeed.
 *  - Sets mysql-ignore_min_gtid_annotations=false, so queries annotated with min_gtid fail.
 */

#include <stdio.h>

#include "command_line.h"
#include "mysql.h"
#include "tap.h"
#include "utils.h"

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(2);

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}

	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return exit_status();
	}

	const char *query = "SELECT /*+ ;min_gtid=01010101-0101-0101-0101-010101010101:101010101010 */ 1";

	diag(" ========== Test 1 ==========");

	MYSQL_QUERY_T(admin, "SET mysql-ignore_min_gtid_annotations = true");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	int rc = run_q(proxy, query);
	if (rc == 0) {
		MYSQL_RES* result = mysql_store_result(proxy);
		mysql_free_result(result);
	}
	ok(rc == 0, "Query execution should be successful. mysql-ignore_min_gtid_annotations=%s, rc=%d", "true", rc);

	diag(" ========== Test 2 ==========");

	MYSQL_QUERY_T(admin, "SET mysql-ignore_min_gtid_annotations = false");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	rc = run_q(proxy, query);
	if (rc == 0) {
		MYSQL_RES* result = mysql_store_result(proxy);
		mysql_free_result(result);
	}
	ok(rc != 0, "Query execution should fail. mysql-ignore_min_gtid_annotations=%s, rc=%d", "false", rc);

	mysql_close(admin);
	mysql_close(proxy);

	return exit_status();
}
