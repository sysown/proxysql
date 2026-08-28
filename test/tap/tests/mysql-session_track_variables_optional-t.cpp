/**
 * @file mysql-session_track_variables_optional-t.cpp
 * @brief This test verifies that ProxySQL properly handles session variable tracking
 *   in OPTIONAL mode based on MySQL server version. Session tracking should work
 *   on MySQL 5.7+ and gracefully degrade on 5.6 and below.
 *
 * Coverage is broadened to multiple variables via 'session_track_default_vars':
 * an integer variable plus string variables ('time_zone', 'sql_mode'), so the
 * string-handling path in 'MySQL_Session::handler_rc0_Process_Variables' is
 * exercised alongside the numeric path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string>
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

	plan(session_track_default_vars_count);

	MYSQL* admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: Failed to connect to admin\n", __FILE__, __LINE__);
		return exit_status();
	}

	// Set session_track_variables to OPTIONAL mode (value 1)
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=1");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: Failed to connect to proxy\n", __FILE__, __LINE__);
		return exit_status();
	}

	int major = 0, minor = 0;
	if (get_server_version(proxy, major, minor) != EXIT_SUCCESS) {
		diag("Failed to get server version");
		return exit_status();
	}

	diag("Detected MySQL version: %d.%d", major, minor);

	bool mysql57_plus = (major > 5) || (major == 5 && minor >= 7);

	for (size_t i = 0; i < session_track_default_vars_count; i++) {
		const tracked_var_spec& var = session_track_default_vars[i];
		std::string set_value, backend_value, client_value;

		if (test_session_variables(proxy, var, set_value, backend_value, client_value) != EXIT_SUCCESS) {
			diag("Failed to run test for %s", var.name);
			continue;
		}

		if (mysql57_plus) {
			ok(!set_value.empty() && set_value == backend_value && set_value == client_value,
				"MySQL %d.%d, %s: Match value across server/backend/client maps. Expected: '%s', Backend: '%s', Client: '%s'",
				major, minor, var.name, set_value.c_str(), backend_value.c_str(), client_value.c_str());
		} else {
			// MySQL 5.6 or below: session tracking is not active, so ProxySQL
			// should not have populated the variable in either map.
			ok(backend_value.empty() && client_value.empty(),
				"MySQL %d.%d, %s: Tracking disabled on pre-5.7. Backend: '%s', Client: '%s'",
				major, minor, var.name, backend_value.c_str(), client_value.c_str());
		}
	}

	// Cleanup
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(proxy);
	mysql_close(admin);
	return exit_status();
}
