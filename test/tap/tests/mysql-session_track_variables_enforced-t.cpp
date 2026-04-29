/**
 * @file mysql-session_track_variables_enforced-t.cpp
 * @brief This test verifies that ProxySQL properly handles session variable tracking
 *   in ENFORCED mode based on MySQL server version. Session tracking should work
 *   on MySQL 5.7+ and backends without support should be rejected (queries should
 *   fail with ProxySQL error 9001).
 *
 * On MySQL 5.7+ the test iterates over 'session_track_default_vars' to cover
 * both integer and string variable paths.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string>
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

	MYSQL* admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: Failed to connect to admin\n", __FILE__, __LINE__);
		return exit_status();
	}

	// Get server version BEFORE enabling ENFORCED mode, because ENFORCED mode
	// backs off all 5.6 servers and we wouldn't be able to query @@version.
	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: Failed to connect to proxy\n", __FILE__, __LINE__);
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

	bool mysql57_plus = (major > 5) || (major == 5 && minor >= 7);

	// Plan:
	//   - On 5.7+ we expect one assertion per tracked variable.
	//   - On <5.7 ENFORCED mode should reject all backends; a single 'DO 1'
	//     probe is sufficient to validate the 9001 error path.
	plan(mysql57_plus ? (int)session_track_default_vars_count : 1);

	// Set session_track_variables to ENFORCED mode (value 2)
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=2");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		cleanup(admin, proxy);
		return exit_status();
	}

	if (mysql57_plus) {
		for (size_t i = 0; i < session_track_default_vars_count; i++) {
			const tracked_var_spec& var = session_track_default_vars[i];
			std::string set_value, backend_value, client_value;

			if (test_session_variables(proxy, var, set_value, backend_value, client_value) != EXIT_SUCCESS) {
				diag("Failed to run test for %s", var.name);
				continue;
			}

			ok(!set_value.empty() && set_value == backend_value && set_value == client_value,
				"MySQL %d.%d ENFORCED, %s: value matches across server/backend/client. Expected: '%s', Backend: '%s', Client: '%s'",
				major, minor, var.name, set_value.c_str(), backend_value.c_str(), client_value.c_str());
		}
	} else {
		int rc = run_q(proxy, "DO 1");
		int error_code = mysql_errno(proxy);

		ok(rc != 0 && error_code == 9001,
			"MySQL %d.%d lacks session tracking. ENFORCED mode rejects backends. rc=%d, error=%d, msg=%s",
			major, minor, rc, error_code, mysql_error(proxy));
	}

	cleanup(admin, proxy);
	return exit_status();
}
