/**
 * @file mysql-session_track_variables_optional-t.cpp
 * @brief This test verifies that ProxySQL properly handles session variable tracking
 *   in OPTIONAL mode based on MySQL server version. Session tracking should work
 *   on MySQL 5.7+ and gracefully degrade on 5.6 and below.
 */

#include <stdio.h>
#include <stdlib.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "session_track_variables.h"

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

	// Set session_track_variables to OPTIONAL mode (value 1)
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=1");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password, true);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return exit_status();
	}

	int major = 0, minor = 0;
	if (get_server_version(proxy, major, minor) != EXIT_SUCCESS) {
		diag("Failed to get server version");
		return exit_status();
	}

	diag("Detected MySQL version: %d.%d", major, minor);

	int set_value = -1;
	int backend_value = -1;
	int client_value = -1;

	if (test_session_variables(proxy, set_value, backend_value, client_value) != EXIT_SUCCESS) {
		diag("Failed to run test");
		return exit_status();
	}

	// Verify results based on server version
	bool mysql57_plus = (major > 5) || (major == 5 && minor >= 7);

	if (mysql57_plus) {
		ok(set_value == backend_value && set_value == client_value,
			"MySQL %d.%d supports session tracking. Match innodb_lock_wait_timeout value with backend & client variable list. Expected: %d, Backend: %d, Client: %d",
			major, minor, set_value, backend_value, client_value);
	} else {
		// MySQL 5.6 or below: session tracking should not be enabled
		// The backend and client values should be -1
		ok(backend_value == -1 && client_value == -1,
			"MySQL %d.%d lacks session tracking. Verify tracking disabled. Backend: %d, Client: %d",
			major, minor, backend_value, client_value);
	}

	// Cleanup
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(proxy);
	mysql_close(admin);
	return exit_status();
}
