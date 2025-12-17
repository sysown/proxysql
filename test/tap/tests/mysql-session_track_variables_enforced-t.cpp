/**
 * @file mysql-session_track_variables_enforced-t.cpp
 * @brief This test verifies that ProxySQL properly handles session variable tracking
 *   in ENFORCED mode based on MySQL server version. Session tracking should work
 *   on MySQL 5.7+ and backends without support should be rejected (queries should timeout).
 */

#include <stdio.h>
#include <stdlib.h>
#include "json.hpp"
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using nlohmann::json;

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

bool test_session_variables(MYSQL* proxy, int& set_value, int& backend_value, int& client_value) {
	set_value = -1;
	backend_value = -1;
	client_value = -1;

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

	MYSQL_QUERY_T(proxy, "SELECT @@innodb_lock_wait_timeout");
	MYSQL_RES* result = mysql_store_result(proxy);
	if (result) {
		MYSQL_ROW row = mysql_fetch_row(result);
		if (row) {
			set_value = atoi(row[0]);
		}
		mysql_free_result(result);
	}

	MYSQL_QUERY(proxy, "PROXYSQL INTERNAL SESSION");
	result = mysql_store_result(proxy);
	if (!result) {
		return false;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	if (!row) {
		mysql_free_result(result);
		return false;
	}

	auto j_session = nlohmann::json::parse(row[0]);
	mysql_free_result(result);

	if (j_session.contains("backends")) {
		for (auto& backend : j_session["backends"]) {
			if (backend != nullptr && backend.contains("conn")) {
				if (backend["conn"].contains("innodb_lock_wait_timeout")) {
					backend_value = std::stoi(backend["conn"]["innodb_lock_wait_timeout"].get<std::string>());
					break;
				}
			}
		}
	}

	if (j_session.contains("conn")) {
		if (j_session["conn"].contains("innodb_lock_wait_timeout")) {
			client_value = std::stoi(j_session["conn"]["innodb_lock_wait_timeout"].get<std::string>());
		}
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

	// Set session_track_variables to ENFORCED mode (value 2)
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=2");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password, true);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return exit_status();
	}

	int major = 0, minor = 0;
	if (!get_server_version(proxy, major, minor)) {
		diag("Failed to get server version");
		return exit_status();
	}

	diag("Detected MySQL version: %d.%d", major, minor);

	int set_value = -1;
	int backend_value = -1;
	int client_value = -1;
	bool test_result = test_session_variables(proxy, set_value, backend_value, client_value);

	// Verify results based on server version
	bool mysql57_plus = (major > 5) || (major == 5 && minor >= 7);

	if (mysql57_plus) {
		if (!test_result) {
			diag("Failed to run test");
			return exit_status();
		}

		ok(set_value == backend_value && set_value == client_value,
			"MySQL %d.%d supports session tracking. Match innodb_lock_wait_timeout value with backend & client variable list. Expected: %d, Backend: %d, Client: %d",
			major, minor, set_value, backend_value, client_value);
	} else {
		// MySQL 5.6 or below: enforced mode should reject connections with error 9001
		if (test_result) {
			diag("Test unexpectedly passed on MySQL %d.%d without session tracking support", major, minor);
			return exit_status();
		}

		int error_code = mysql_errno(proxy);
		const char* error_msg = mysql_error(proxy);

		ok(error_code == 9001,
			"MySQL %d.%d lacks session tracking. ENFORCED mode. Connection should timeout with 9001. Error: %d, Message: %s",
			major, minor, error_code, error_msg);
	}

	// Cleanup
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(proxy);
	mysql_close(admin);
	return exit_status();
}
