/**
 * @file mysql-session_track_variables_ff-t.cpp
 * @brief This test verifies that ProxySQL properly handles session variable tracking
 *        in both OPTIONAL and ENFORCED modes with fast_forward enabled on MySQL 5.7+.
 *        For each mode and for every tracked-variable spec in
 *        'session_track_default_vars' the test verifies that the client-visible
 *        tracking payload matches the actual server-side value.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string>
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
	// (session tracking payload is carried only in OK packets, not EOF).
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

	// Enable session tracking on the fast-forward client so backend-originated
	// tracking data is exposed to 'mysql_session_track_get_*' on this handle.
	MYSQL_QUERY_T(proxy, "SET session_track_system_variables='*'");
	MYSQL_QUERY_T(proxy, "SET session_track_state_change=ON");

	for (size_t i = 0; i < session_track_default_vars_count; i++) {
		const tracked_var_spec& var = session_track_default_vars[i];
		std::string set_value, tracked_value;

		if (test_session_variables_ff(proxy, var, set_value, tracked_value) != EXIT_SUCCESS) {
			diag("Failed to run test for %s mode, var %s", mode_name, var.name);
			continue;
		}

		ok(!set_value.empty() && set_value == tracked_value,
			"MySQL %d.%d FF %s, %s: Expected: '%s', Tracked: '%s'",
			major, minor, mode_name, var.name, set_value.c_str(), tracked_value.c_str());
	}

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

	// One assertion per (mode, tracked-variable) pair; two modes.
	plan(2 * (int)session_track_default_vars_count);

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
