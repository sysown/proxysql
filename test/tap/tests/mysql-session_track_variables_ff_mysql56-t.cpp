/**
 * @file mysql-session_track_variables_ff_mysql56-t.cpp
 * @brief This test verifies that ProxySQL properly handles session variable tracking
 *        with fast_forward enabled on MySQL 5.6 for both OPTIONAL and ENFORCED modes.
 *
 *        OPTIONAL mode: session tracking should gracefully degrade -- tracked
 *        values must be empty strings for every tracked variable -- without
 *        breaking the fast_forward connection.
 *
 *        ENFORCED mode: 'handle_session_track_capabilities()' rejects all 5.6
 *        backends (they lack CLIENT_DEPRECATE_EOF and CLIENT_SESSION_TRACKING),
 *        so the first query through the fast_forward pipe should fail with
 *        error 9001.
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
 * @brief Tests OPTIONAL mode (value 1) on MySQL 5.6 with fast_forward.
 *
 * Connects without CLIENT_DEPRECATE_EOF (to match the 5.6 backend's capabilities
 * per 'match_ff_req_options()') and verifies that session tracking is not active
 * for any of the tracked variable specs.
 */
int test_ff_optional_mysql56(const CommandLine& cl, MYSQL* admin) {
	// Set session_track_variables to OPTIONAL mode (value 1)
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=1");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Enable fast_forward for test user
	MYSQL_QUERY_T(admin, "UPDATE mysql_users SET fast_forward=1 WHERE username='sbtest4'");
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, "sbtest4", "sbtest4", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: Failed to connect to proxy\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	for (size_t i = 0; i < session_track_default_vars_count; i++) {
		const tracked_var_spec& var = session_track_default_vars[i];
		std::string set_value, tracked_value;

		if (test_session_variables_ff(proxy, var, set_value, tracked_value) != EXIT_SUCCESS) {
			diag("Failed to run test for %s", var.name);
			continue;
		}

		ok(tracked_value.empty(),
			"FF OPTIONAL on MySQL 5.6, %s: Tracking disabled. Tracked: '%s'",
			var.name, tracked_value.c_str());
	}

	// Cleanup
	MYSQL_QUERY_T(admin, "UPDATE mysql_users SET fast_forward=0 WHERE username='sbtest4'");
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(proxy);
	return EXIT_SUCCESS;
}

/**
 * @brief Tests ENFORCED mode (value 2) on MySQL 5.6 with fast_forward.
 *
 * Connects with CLIENT_DEPRECATE_EOF (as ENFORCED mode advertises it in the
 * handshake) and verifies that the first query fails with error 9001, since
 * 'handle_session_track_capabilities()' backs off all 5.6 servers.
 */
int test_ff_enforced_mysql56(const CommandLine& cl, MYSQL* admin) {
	// Set session_track_variables to ENFORCED mode (value 2)
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=2");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Enable fast_forward for test user
	MYSQL_QUERY_T(admin, "UPDATE mysql_users SET fast_forward=1 WHERE username='sbtest4'");
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	MYSQL* proxy = mysql_init(NULL);
	// Enable CLIENT_DEPRECATE_EOF as ENFORCED mode advertises it in the handshake
	proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;
	if (!mysql_real_connect(proxy, cl.host, "sbtest4", "sbtest4", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: Failed to connect to proxy\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	// The first query through the fast_forward pipe triggers backend connection
	// establishment, which will time out because all 5.6 servers are backed off.
	int rc = mysql_query(proxy, "SET session_track_system_variables='*'");

	int error_code = mysql_errno(proxy);
	ok(rc != 0 && error_code == 9001,
		"Fast forward with ENFORCED mode on MySQL 5.6: SET command should fail with error 9001. rc=%d, error=%d, msg=%s",
		rc, error_code, mysql_error(proxy));

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

	// OPTIONAL test: one 'ok' per tracked variable. ENFORCED test: single 'ok'
	// for the error-path assertion (the 5.6 backend is rejected before any
	// per-variable tracking is attempted).
	plan((int)session_track_default_vars_count + 1);

	MYSQL* admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: Failed to connect to admin\n", __FILE__, __LINE__);
		return exit_status();
	}

	diag("============================");
	diag(" Test 1");
	diag(" Session Track Mode : OPTIONAL");
	diag(" MySQL Server       : 5.6");
	diag("============================");
	test_ff_optional_mysql56(cl, admin);

	diag("============================");
	diag(" Test 2");
	diag(" Session Track Mode : ENFORCED");
	diag(" MySQL Server       : 5.6");
	diag("============================");
	test_ff_enforced_mysql56(cl, admin);

	mysql_close(admin);
	return exit_status();
}
