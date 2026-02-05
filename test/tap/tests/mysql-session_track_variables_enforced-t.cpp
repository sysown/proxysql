/**
 * @file mysql-session_track_variables_enforced-t.cpp
 * @brief This test verifies that ProxySQL properly handles session variable tracking
 *   in ENFORCED mode based on MySQL server version. Session tracking should work
 *   on MySQL 5.7+ and backends without support should be rejected (queries should timeout).
 */

#include <stdio.h>
#include <stdlib.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "session_track_variables.h"

int cleanup(MYSQL* admin, MYSQL* proxy) {
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	mysql_close(proxy);
	mysql_close(admin);
	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	plan(1);

	MYSQL* admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}

	// Get server version BEFORE enabling ENFORCED mode, because ENFORCED mode
	// backs off all 5.6 servers and we wouldn't be able to query @@version.
	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return exit_status();
	}

	int major = 0, minor = 0;
	if (get_server_version(proxy, major, minor) != EXIT_SUCCESS) {
		diag("Failed to get server version");
		cleanup(admin, proxy);
		return exit_status();
	}
	mysql_close(proxy);

	diag("Detected MySQL version: %d.%d", major, minor);

	// Set session_track_variables to ENFORCED mode (value 2)
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=2");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		cleanup(admin, proxy);
		return exit_status();
	}

	bool mysql57_plus = (major > 5) || (major == 5 && minor >= 7);
	if (mysql57_plus) {
		int set_value = -1;
		int backend_value = -1;
		int client_value = -1;

		if (test_session_variables(proxy, set_value, backend_value, client_value) != EXIT_SUCCESS) {
			diag("Failed to run test");
			cleanup(admin, proxy);
			return exit_status();
		}

		ok(set_value == backend_value && set_value == client_value,
			"MySQL %d.%d supports session tracking. Match innodb_lock_wait_timeout value with backend & client variable list. Expected: %d, Backend: %d, Client: %d",
			major, minor, set_value, backend_value, client_value);
	} else {
		int rc = run_q(proxy, "DO 1");
		int error_code = mysql_errno(proxy);

		ok(rc != 0 && error_code == 9001,
			"MySQL %d.%d lacks session tracking. ENFORCED mode rejects backends. Query failed with error 9001. rc=%d, error=%d, msg=%s",
			major, minor, rc, error_code, mysql_error(proxy));
	}

	cleanup(admin, proxy);
	return exit_status();
}