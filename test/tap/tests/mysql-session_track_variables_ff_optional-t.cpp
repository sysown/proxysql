/**
 * @file mysql-session_track_variables_ff_optional-t.cpp
 * @brief This test verifies that ProxySQL properly handles session variable tracking
 *   in OPTIONAL mode with fast_forward enabled. Session tracking should work
 *   on MySQL 5.7+ and gracefully degrade on 5.6 and below.
 */

#include <stdio.h>
#include <stdlib.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

bool get_server_version(MYSQL* proxy, int& major, int& minor) {
	MYSQL_QUERY_T(proxy, "SELECT @@version");
	MYSQL_RES* result = mysql_store_result(proxy);
	if (!result) {
		return false;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	if (!row) {
		mysql_free_result(result);
		return false;
	}

	// Parse version string
	if (sscanf(row[0], "%d.%d", &major, &minor) != 2) {
		mysql_free_result(result);
		return false;
	}

	mysql_free_result(result);
	return true;
}

bool extract_session_variable(MYSQL* proxy, const char* var_name, int& tracked_value) {
	tracked_value = -1;

	if ((proxy != nullptr)
		&& (proxy->net.last_errno == 0)
		&& (proxy->server_status & SERVER_SESSION_STATE_CHANGED)) {
		const char *data;
		size_t length;

		if (mysql_session_track_get_first(proxy, SESSION_TRACK_SYSTEM_VARIABLES, &data, &length) == 0) {
			std::string current_var_name(data, length);
			// get_first() returns a variable_name
			// get_next() will return the value
			bool expect_value = true;

			while (mysql_session_track_get_next(proxy, SESSION_TRACK_SYSTEM_VARIABLES, &data, &length) == 0) {
				if (expect_value) {
					// This is the value for current_var_name
					if (current_var_name == var_name) {
						std::string value_str(data, length);
						tracked_value = atoi(value_str.c_str());
						return true;
					}
					// got a value in this iteration
					// in the next iteration, we have to expect a variable_name
					expect_value = false;
				} else {
					current_var_name = std::string(data, length);
					// got a variable_name in this iteration
					// in the next iteration, we have to expect the value of this variable
					expect_value = true;
				}
			}
		}
	}

	return false;
}

bool test_session_variables(MYSQL* proxy, int& set_value, int& tracked_value) {
	set_value = -1;
	tracked_value = -1;

	MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY_T(proxy, "SELECT 1");
	mysql_free_result(mysql_store_result(proxy));

	MYSQL_QUERY_T(proxy, "DROP PROCEDURE IF EXISTS test.set_innodb_lock_wait_timeout");
	const char* create_proc =
		"CREATE PROCEDURE test.set_innodb_lock_wait_timeout() "
		"BEGIN "
		"  SET innodb_lock_wait_timeout = CAST(FLOOR(50 + (RAND() * 100)) AS UNSIGNED); "
		"END";

	MYSQL_QUERY_T(proxy, create_proc);

	MYSQL_QUERY_T(proxy, "CALL test.set_innodb_lock_wait_timeout()");

	extract_session_variable(proxy, "innodb_lock_wait_timeout", tracked_value);

	MYSQL_QUERY_T(proxy, "SELECT @@innodb_lock_wait_timeout");
	MYSQL_RES* result = mysql_store_result(proxy);
	if (result) {
		MYSQL_ROW row = mysql_fetch_row(result);
		if (row) {
			set_value = atoi(row[0]);
		}
		mysql_free_result(result);
	}

	return true;
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

	// Set session_track_variables to OPTIONAL mode (value 1)
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=1");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Enable fast_forward for test user
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_users WHERE username='ff_test_user'");
	MYSQL_QUERY_T(admin, "INSERT INTO mysql_users (username,password,fast_forward,default_hostgroup) VALUES ('ff_test_user','ff_test_pass',1,0)");
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	MYSQL* proxy = mysql_init(NULL);
	// Enable CLIENT_DEPRECATE_EOF. This is required for session tracking
	proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;
	if (!mysql_real_connect(proxy, cl.host, "ff_test_user", "ff_test_pass", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return exit_status();
	}

	// Enable session tracking on client for fast_forward mode
	MYSQL_QUERY_T(proxy, "SET session_track_system_variables='*'");
	MYSQL_QUERY_T(proxy, "SET session_track_state_change=ON");

	int major = 0, minor = 0;
	if (!get_server_version(proxy, major, minor)) {
		diag("Failed to get server version");
		return exit_status();
	}

	diag("Detected MySQL version: %d.%d", major, minor);

	int set_value = -1;
	int tracked_value = -1;

	if (!test_session_variables(proxy, set_value, tracked_value)) {
		diag("Failed to run test");
		return exit_status();
	}

	// Verify results based on server version
	bool mysql57_plus = (major > 5) || (major == 5 && minor >= 7);

	if (mysql57_plus) {
		ok(set_value == tracked_value,
			"MySQL %d.%d supports session tracking. Fast forward with OPTIONAL mode: Expected: %d, Tracked: %d",
			major, minor, set_value, tracked_value);
	} else {
		// MySQL 5.6 or below: session tracking should not be enabled
		ok(tracked_value == -1,
			"MySQL %d.%d lacks session tracking. Fast forward with OPTIONAL mode: Tracking disabled. Tracked: %d",
			major, minor, tracked_value);
	}

	// Cleanup
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_users WHERE username='ff_test_user'");
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(proxy);
	mysql_close(admin);
	return exit_status();
}
