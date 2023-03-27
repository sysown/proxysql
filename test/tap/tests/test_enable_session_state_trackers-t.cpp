/**
 * @file test_enable_session_state_trackers-t.cpp
 * @brief This test verifies that 'enable_session_state_trackers' behaves
 * properly.
 *
 * @details It verifies that SESSION_TRACK_STATE_CHANGE and
 * SESSION_TRACK_SYSTEM_VARIABLES are configured after connecting, changing user
 * and resetting connection when enable_session_state_trackers is enabled and
 * the other way around when diabled.
 */

#include "mysql.h"

#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

#include <cstdlib>
#include <string>
#include <unistd.h>
#include <iostream>

using std::string;

#include "json.hpp"

using nlohmann::json;

using namespace std;

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

int check_session_track_variables(MYSQL* proxy, const bool enabled) {
	json json_res = {};
	MYSQL_RES* myres;

	// Values when enable_session_state_trackers is true
	std::string session_track_state_change_enabled = "\"ON\"";
	std::string session_track_system_variables_enabled = "\"*\"";

	MYSQL_QUERY_T(proxy, "PROXYSQL INTERNAL SESSION");
	myres = mysql_store_result(proxy);
	parse_result_json_column(myres, json_res);
	mysql_free_result(myres);

	if (enabled) {
		std::string session_track_state_change = json_res["conn"]["session_track_state_change"].dump();
		std::string session_track_system_variables = json_res["conn"]["session_track_system_variables"].dump();

		ok(
			session_track_state_change == session_track_state_change_enabled,
			"session_track_state_change expected value: %s. Actual value: %s",
			session_track_state_change_enabled.c_str(), session_track_state_change.c_str()
		);

		ok(
			session_track_system_variables == session_track_system_variables_enabled,
			"session_track_system_variables expected value: %s. Actual value: %s",
			session_track_system_variables_enabled.c_str(), session_track_system_variables.c_str()
		);
	} else {
		ok(
			!json_res["conn"].contains("session_track_state_change"),
			"session_track_state_change should be unsetted"
		);

		ok(
			!json_res["conn"].contains("session_track_system_variables"),
			"session_track_system_variables should be unsetted"
		);
	}

	return EXIT_SUCCESS;
}

int test_enable_session_state_trackers(const CommandLine &cl, const bool enabled) {
	int err_code = 0;

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	// By default, enable_session_state_trackers is true
	err_code = check_session_track_variables(proxy, enabled);
	if (err_code != EXIT_SUCCESS) return EXIT_FAILURE;

	// Do reset and get the new values
	err_code = mysql_reset_connection(proxy);
	if (err_code != EXIT_SUCCESS) {
		diag(
			"'mysql_reset_connection' failed with error: (%d,'%s') at ('%s':'%d')",
			mysql_errno(proxy), mysql_error(proxy), __FILE__, __LINE__
		);
		return EXIT_FAILURE;
	}
	if (check_session_track_variables(proxy, enabled)) return EXIT_FAILURE;

	// Change user and get the new values
	std::string username = "sbtest1";
	std::string password = "sbtest1";
	err_code = mysql_change_user(proxy, username.c_str(), password.c_str(), NULL);
	if (err_code != EXIT_SUCCESS) {
		diag(
			"'mysql_change_user' executed with error: (%d,'%s') at ('%s':'%d')",
			mysql_errno(proxy), mysql_error(proxy), __FILE__, __LINE__
		);
		return EXIT_FAILURE;
	}
	if (check_session_track_variables(proxy, enabled)) return EXIT_FAILURE;

	mysql_close(proxy);

	return EXIT_SUCCESS;
}

int main(int, char**) {
	int err_code = 0;
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	// 12 tests: check session_track_state_change and
	// session_track_system_variables on connect, change user and reset with
	// and without enable_session_state_trackers.
	plan(12);

	err_code = test_enable_session_state_trackers(cl, true);
	if (err_code != EXIT_SUCCESS) {
		diag("'test_enable_session_state_trackers(true)' failed at ('%s':'%d')", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	diag("Configure ProxySQL to disable enable_session_state_trackers");
	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;

	}
	MYSQL_QUERY_T(
		admin,
		"UPDATE global_variables SET variable_value = false "
		"WHERE variable_name = 'mysql-enable_session_state_trackers'"
	);
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	mysql_close(admin);

	err_code = test_enable_session_state_trackers(cl, false);
	if (err_code != EXIT_SUCCESS) {
		diag("'test_enable_session_state_trackers(false)' failed at ('%s':'%d')", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	return exit_status();
}
