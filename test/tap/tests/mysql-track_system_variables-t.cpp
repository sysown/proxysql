/**
 * @file test_track_system_variables-t.cpp
 * @brief This test verifies that ProxySQL properly tracks session-specific
 *   system variables across the backend connections.
 */

#include <stdio.h>
#include <stdlib.h>
#include "json.hpp"
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using nlohmann::json;

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

	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=1");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password, true);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return exit_status();
	}

	MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY_T(proxy, "SELECT 1");
	MYSQL_RES* reset_result = mysql_store_result(proxy);
	mysql_free_result(reset_result);

	MYSQL_QUERY_T(proxy, "DROP PROCEDURE IF EXISTS test.set_innodb_lock_wait_timeout");
	const char* create_proc =
		"CREATE PROCEDURE test.set_innodb_lock_wait_timeout() "
		"BEGIN "
		"  SET innodb_lock_wait_timeout = CAST(FLOOR(50 + (RAND() * 100)) AS UNSIGNED); "
		"END";

	MYSQL_QUERY_T(proxy, create_proc);
	MYSQL_QUERY_T(proxy, "CALL test.set_innodb_lock_wait_timeout()");

	int set_value = -1;
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
	MYSQL_ROW row = mysql_fetch_row(result);
	auto j_session = nlohmann::json::parse(row[0]);
	mysql_free_result(result);

	int backend_value = -1;
	int client_value = -1;
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

	ok(set_value == backend_value && set_value == client_value,
		"Match session innodb_lock_wait_timeout value with backend & client variable list. Expected: %d, Backend: %d, Client: %d", set_value, backend_value, client_value);

	// cleanup
	MYSQL_QUERY_T(admin, "SET mysql-session_track_variables=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(proxy);
	mysql_close(admin);
	return exit_status();
}
