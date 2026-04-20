/**
 * @file mysql-session_track_variables_ff-t.cpp
 * @brief This test verifies that ProxySQL properly handles session variable tracking
 *        in both OPTIONAL and ENFORCED modes with fast_forward enabled on MySQL 5.7+.
 *        For each mode, it verifies that session tracking is active and tracked values
 *        match the actual variable value.
 */

#include <stdio.h>
#include <stdlib.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "session_track_variables.h"

/**
 * @brief Tests session variable tracking in fast_forward mode for a given
 *        session_track_variables mode (OPTIONAL=1 or ENFORCED=2).
 */
int test_ff_session_tracking(const CommandLine& cl, MYSQL* admin, int mode) {
	const char* mode_name = (mode == 1) ? "OPTIONAL" : "ENFORCED";

	// Set session_track_variables mode
	char query[256];
	snprintf(query, sizeof(query), "SET mysql-session_track_variables=%d", mode);
	MYSQL_QUERY_T(admin, query);
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Enable fast_forward for test user
	MYSQL_QUERY_T(admin, "UPDATE mysql_users SET fast_forward=1 WHERE username='sbtest4'");
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	MYSQL* proxy = mysql_init(NULL);
	// Enable CLIENT_DEPRECATE_EOF. This is required for session tracking
	proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;
	if (!mysql_real_connect(proxy, cl.host, "sbtest4", "sbtest4", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: Failed to connect to proxy\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	int major = 0, minor = 0;
	if (get_server_version(proxy, major, minor) != EXIT_SUCCESS) {
		diag("Failed to get server version");
		mysql_close(proxy);
		return EXIT_FAILURE;
	}
	diag("Detected MySQL version: %d.%d", major, minor);

	// Enable session tracking on client for fast_forward mode
	MYSQL_QUERY_T(proxy, "SET session_track_system_variables='*'");
	MYSQL_QUERY_T(proxy, "SET session_track_state_change=ON");

	int set_value = -1;
	int tracked_value = -1;

	if (test_session_variables_ff(proxy, set_value, tracked_value) != EXIT_SUCCESS) {
		diag("Failed to run test for %s mode", mode_name);
		mysql_close(proxy);
		return EXIT_FAILURE;
	}

	ok(set_value == tracked_value, "MySQL %d.%d: Fast forward with %s mode: Expected: %d, Tracked: %d", major, minor, mode_name, set_value, tracked_value);

	// Cleanup
	MYSQL_QUERY_T(admin, "UPDATE mysql_users SET fast_forward=0 WHERE username='sbtest4'");
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(proxy);
	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	plan(2);

	MYSQL* admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: Failed to connect to admin\n", __FILE__, __LINE__);
		return exit_status();
	}

	diag("============================");
	diag(" Test 1");
	diag(" Session Track Mode : OPTIONAL");
	diag(" MySQL Server       : 5.7+");
	diag("============================");
	test_ff_session_tracking(cl, admin, 1);

	diag("============================");
	diag(" Test 2");
	diag(" Session Track Mode : ENFORCED");
	diag(" MySQL Server       : 5.7+");
	diag("============================");
	test_ff_session_tracking(cl, admin, 2);

	mysql_close(admin);
	return exit_status();
}
