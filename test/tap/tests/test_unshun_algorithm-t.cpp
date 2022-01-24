/**
 * @file test_unshun_algorithm-t.cpp
 * @brief This test verifies the implementation of the new introduced variable 'mysql-unshun_algorithm'.
 * @details Test performs the following checks:
 *   1. Check that the variable default values and get/set operations works as expected.
 *   2. Check that the 'PROXYSQL_SIMULATOR' command is working properly.
 *   2. Check that the old 'SHUNNING' and 'UNSHUNNING' behavior works as expected. For this, multiple
 *   3. Check that the new 'SHUNNING' and 'UNSHUNNING' behavior 'mysql-unshun_algorithm=1' works as expected.
 *
 *   In order to check that 'SHUNNING' and 'UNSHUNNING' behavior holds:
 *   1. 10 fake servers are placed alone in 10 different hostgroups.
 *   2. The same servers are also placed incrementally in 10 other different hostgroups holding one more
 *      search each time.
 *   3. All the servers are 'SHUNNED' using 'PROXYSQL_SIMULATOR' command.
 *   4. Each of the servers placed in the individual hostgroups is 'UNSHUNNED', checking the proper behavior
 *      related to the other servers depending on 'mysql-unshun_algorithm'.
 */

#include <cstring>
#include <unistd.h>
#include <vector>
#include <string>
#include <stdio.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

const uint32_t SHUN_RECOVERY_TIME = 1;
const uint32_t VALID_RANGE = 1;
const uint32_t SERVERS_COUNT = 10;

using std::string;

int shunn_server(MYSQL* proxysql_admin, uint32_t i, uint32_t j) {
	std::string t_simulator_error_query { "PROXYSQL_SIMULATOR mysql_error %d 127.0.0.1:330%d 1234" };
	std::string simulator_error_q_i {};
	string_format(t_simulator_error_query, simulator_error_q_i, i, j);
	diag("%s: running query: %s", tap_curtime().c_str(), simulator_error_q_i.c_str());
	MYSQL_QUERY(proxysql_admin, simulator_error_q_i.c_str());

	return EXIT_SUCCESS;
}

int shunn_all_servers(MYSQL* proxysql_admin) {
	for (uint32_t i = 0; i < SERVERS_COUNT; i++) {
		shunn_server(proxysql_admin, i, i);

		for (uint32_t j = 0; j <= i; j++) {
			shunn_server(proxysql_admin, i + SERVERS_COUNT, j);
		}
	}

	return EXIT_SUCCESS;
}

int wakup_target_server(MYSQL* proxysql_mysql, uint32_t i) {
	std::string t_simple_do_query { "DO /* ;hostgroup=%d */ 1" };
	std::string simple_do_query {};
	string_format(t_simple_do_query, simple_do_query, i);

	mysql_query(proxysql_mysql, simple_do_query.c_str());
	diag("%s: running query: %s", tap_curtime().c_str(), simple_do_query.c_str());
	sleep(SHUN_RECOVERY_TIME * 2);
	mysql_query(proxysql_mysql, simple_do_query.c_str());
	diag("%s: running query: %s", tap_curtime().c_str(), simple_do_query.c_str());

	return EXIT_SUCCESS;
}

int server_status_checker(MYSQL* admin, const string& f_st, const string& n_st, uint32_t i) {
	std::string t_server_status_query {
		"SELECT status,hostgroup_id FROM runtime_mysql_servers WHERE port=330%d order by hostgroup_id"
	};
	std::string server_status_query {};
	string_format(t_server_status_query, server_status_query, i);
	diag("%s: running query: %s", tap_curtime().c_str(), server_status_query.c_str());
	MYSQL_QUERY(admin, server_status_query.c_str());

	MYSQL_RES* status_res = mysql_store_result(admin);
	bool unexp_row_value = false;

	int num_rows = mysql_num_rows(status_res);
	if (num_rows == 0) {
		unexp_row_value = true;
	} else {
		uint32_t row_num = 0;
		MYSQL_ROW row = nullptr;

		while (( row = mysql_fetch_row(status_res) )) {
			std::string status { row[0] };
			std::string hgid { row[1] };
			diag("Status found for server '%s:127.0.0.1:330%d' was '%s'", hgid.c_str(), i, status.c_str());
			if (row_num == 0) {
				if (status != f_st) {
					unexp_row_value = true;
					break;
				}
			} else {
				if (status != n_st) {
					unexp_row_value = true;
					break;
				}
			}
			row_num++;
		}
	}

	mysql_free_result(status_res);

	return unexp_row_value;
}

int test_unshun_algorithm_variable(MYSQL* proxysql_admin) {
	const auto get_current_unshun_algorithm_val = [](MYSQL* proxysql_admin) -> int32_t {
		int32_t cur_unshun_value = -1;

		int err = mysql_query(proxysql_admin, "SELECT * FROM global_variables WHERE variable_name='mysql-unshun_algorithm'");
		if (err != EXIT_SUCCESS) {
			diag(
				"Query for retrieving value of 'mysql-unshun_algorithm' failed with error: (%d, %s)",
				mysql_errno(proxysql_admin), mysql_error(proxysql_admin)
			);
			return cur_unshun_value;
		}

		MYSQL_RES* myres_unshun_var = mysql_store_result(proxysql_admin);
		if (myres_unshun_var != nullptr) {
			int num_rows = mysql_num_rows(myres_unshun_var);
			MYSQL_ROW row = mysql_fetch_row(myres_unshun_var);

			if (num_rows && row != nullptr) {
				char* endptr = nullptr;
				cur_unshun_value = strtol(row[1], &endptr, SERVERS_COUNT);
			}
		}
		mysql_free_result(myres_unshun_var);

		return cur_unshun_value;
	};

	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES FROM DISK");
	diag("%s: Line:%d running admin query to reload variables: LOAD MYSQL VARIABLES FROM DISK", tap_curtime().c_str(), __LINE__);
	MYSQL_QUERY(proxysql_admin, "SET mysql-hostgroup_manager_verbose=3");
	diag("%s: Line:%d running admin query: SET mysql-hostgroup_manager_verbose=3", tap_curtime().c_str(), __LINE__);
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	int32_t def_unshun_value = get_current_unshun_algorithm_val(proxysql_admin);
	ok(def_unshun_value == 0, "Default 'mysql-unshun_algorithm' should be '0', actual: %d", def_unshun_value);

	std::string t_set_unshun { "SET mysql-unshun_algorithm=%d" };

	for (uint32_t i = 0; i <= VALID_RANGE; i++) {
		std::string set_unshun {};
		string_format(t_set_unshun, set_unshun, i);
		MYSQL_QUERY(proxysql_admin, set_unshun.c_str());
		diag("%s: Line:%d running admin query: %s", tap_curtime().c_str(), __LINE__, set_unshun.c_str());
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		int32_t cur_unshun_val = get_current_unshun_algorithm_val(proxysql_admin);
		ok(cur_unshun_val == i, "Settings and getting 'mysql-unshun_algorithm' works for range value: %d", i);
	}

	{
		std::string set_unshun {};
		string_format(t_set_unshun, set_unshun, VALID_RANGE + 1);
		MYSQL_QUERY(proxysql_admin, set_unshun.c_str());
		diag("%s: Line:%d running admin query: %s", tap_curtime().c_str(), __LINE__, set_unshun.c_str());
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		int32_t cur_unshun_val = get_current_unshun_algorithm_val(proxysql_admin);
		ok(
			cur_unshun_val != VALID_RANGE + 1,
			"Settings and getting 'mysql-unshun_algorithm' doesn't work fo invalid range value: %d",
			VALID_RANGE + 1
		);
	}

	return EXIT_SUCCESS;
}

int test_proxysql_simulator_error(MYSQL* proxysql_admin) {
	MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_servers");
	const std::string t_insert_server_query { "INSERT INTO mysql_servers (hostgroup_id,hostname,port) VALUES (%d,'127.0.0.1',330%d)" };

	// Create ten initial servers not sharing hostgroup
	for (uint32_t i = 0; i < SERVERS_COUNT; i++) {
		std::string insert_server_query {};
		string_format(t_insert_server_query, insert_server_query, i, i);
		MYSQL_QUERY(proxysql_admin, insert_server_query.c_str());
	}
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Check that ALL the servers are in the expected 'ONLINE' state
	for (uint32_t i = 0; i < SERVERS_COUNT; i++) {
		int check_res = server_status_checker(proxysql_admin, "ONLINE", "ONLINE", i);
		if (check_res != false) {
			diag("Found server in a different state than 'ONLINE' 'test_proxysql_simulator_error' can't be performed");
			return EXIT_FAILURE;
		}
	}

	for (uint32_t i = 0; i < SERVERS_COUNT; i++) {
		shunn_server(proxysql_admin, i, i);
		int check_res = server_status_checker(proxysql_admin, "SHUNNED", "SHUNNED", i);
		ok(check_res == false, "'PROXYSQL_SIMULATOR' should set the servers with errors to 'SHUNNED'");
	}


	// Check that 'PROXYSQL_SIMULATOR' command fails when the server specified isn't found
	int shunn_err = shunn_server(proxysql_admin, 20, 20);
	ok(shunn_err == 1, "SHUNNING operation should have failed for a non-existing server.");

	return EXIT_SUCCESS;
}

int test_unshun_algorithm_behavior(MYSQL* proxysql_mysql, MYSQL* proxysql_admin) {
	// Configure Admin variables with lower thresholds
	MYSQL_QUERY(proxysql_admin, "SET mysql-shun_recovery_time_sec=1");
	diag("%s: Line:%d running admin query: SET mysql-shun_recovery_time_sec=1", tap_curtime().c_str(), __LINE__);
	MYSQL_QUERY(proxysql_admin, "SET mysql-hostgroup_manager_verbose=3");
	diag("%s: Line:%d running admin query: SET mysql-hostgroup_manager_verbose=3", tap_curtime().c_str(), __LINE__);
	// NOTE: The following varible value is set here just as a reminder. This change isn't properly propagated
	// to the 'error setting operation' since this is performed from 'ProxySQL_Admin' thread when
	// 'PROXYSQL_SIMULATOR' command is received. Because of this, it's in 'PROXYSQL_SIMULATOR' command impl in
	// 'ProxySQL_Admin' where this variable value is updated before setting the error.
	MYSQL_QUERY(proxysql_admin, "SET mysql-shun_on_failures=5");
	MYSQL_QUERY(proxysql_admin, "SET mysql-connect_retries_on_failure=0");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	// Cleanup the servers and create a good number of hostgroups
	MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_servers");

	const std::string t_insert_server_query { "INSERT INTO mysql_servers (hostgroup_id,hostname,port) VALUES (%d,'127.0.0.1',330%d)" };

	// Create ten initial servers not sharing hostgroup
	for (uint32_t i = 0; i < SERVERS_COUNT; i++) {
		std::string insert_server_query {};
		string_format(t_insert_server_query, insert_server_query, i, i);
		MYSQL_QUERY(proxysql_admin, insert_server_query.c_str());
	}

	// Place the same servers incrementally in ten new hostgroups
	for (uint32_t i = 0; i < SERVERS_COUNT; i++) {
		for (uint32_t j = 0; j <= i; j++) {
			std::string insert_server_query {};
			string_format(t_insert_server_query, insert_server_query, i + SERVERS_COUNT, j);
			MYSQL_QUERY(proxysql_admin, insert_server_query.c_str());
		}
	}

	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	{
		MYSQL_QUERY(proxysql_admin, "SET mysql-unshun_algorithm=0");
		diag("%s: Line:%d running admin query: SET mysql-unshun_algorithm=0", tap_curtime().c_str(), __LINE__);
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		int shunn_err = shunn_all_servers(proxysql_admin);
		if (shunn_err) { return EXIT_FAILURE; }

		for (uint32_t i = 0; i < SERVERS_COUNT; i++) {
			wakup_target_server(proxysql_mysql, i);

			// Check that only server from first hostgroup is 'SHUNNED'
			bool unexp_row_value = server_status_checker(proxysql_admin, "ONLINE", "SHUNNED", i);
			ok(unexp_row_value == false, "Server from first hg was set 'ONLINE' while others remained 'SHUNNED'");
		}
	}

	{
		MYSQL_QUERY(proxysql_admin, "SET mysql-unshun_algorithm=1");
		diag("%s: Line:%d running admin query: SET mysql-unshun_algorithm=1", tap_curtime().c_str(), __LINE__);
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		int shunn_err = shunn_all_servers(proxysql_admin);
		if (shunn_err) { return EXIT_FAILURE; }
		diag(""); // empty line
		for (uint32_t i = 0; i < SERVERS_COUNT; i++) {
			wakup_target_server(proxysql_mysql, i);

			bool unexp_row_value = server_status_checker(proxysql_admin, "ONLINE", "ONLINE", i);
			ok(unexp_row_value == false, "Server from first hg was set 'ONLINE' while others remained 'ONLINE'");
			diag(""); // empty line
		}
	}

	{
		MYSQL_QUERY(proxysql_admin, "SET mysql-unshun_algorithm=0");
		diag("%s: Line:%d running admin query: SET mysql-unshun_algorithm=0", tap_curtime().c_str(), __LINE__);
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		int shunn_err = shunn_all_servers(proxysql_admin);
		if (shunn_err) { return EXIT_FAILURE; }

		for (uint32_t i = 0; i < SERVERS_COUNT; i++) {
			wakup_target_server(proxysql_mysql, i);
		}
		diag(""); // empty line

		MYSQL_QUERY(proxysql_admin, "SET mysql-unshun_algorithm=1");
		diag("%s: Line:%d running admin query: SET mysql-unshun_algorithm=1", tap_curtime().c_str(), __LINE__);
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		for (uint32_t i = 0; i < SERVERS_COUNT; i++) {
			wakup_target_server(proxysql_mysql, i);

			bool unexp_row_value = server_status_checker(proxysql_admin, "ONLINE", "SHUNNED", i);
			ok(unexp_row_value == false, "Server from first hg was set 'ONLINE' while others remained 'SHUNNED'");
			diag(""); // empty line
		}
	}


	return EXIT_SUCCESS;
}
int main(int argc, char** argv) {
	CommandLine cl;

	plan(
		1 + (VALID_RANGE + 1) + 1 + // Variable tests
		SERVERS_COUNT + 1 + // Simulator error tests
		SERVERS_COUNT * 3 // Testing unshun_algorithm behavior
	);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* proxysql_mysql = mysql_init(NULL);
	MYSQL* proxysql_admin = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	}

	{
		int unshun_var_err = test_unshun_algorithm_variable(proxysql_admin);
		if (unshun_var_err == EXIT_FAILURE) { goto cleanup; }
	}

	// Disable Monitor for the following tests
	MYSQL_QUERY(proxysql_admin, "SET mysql-monitor_enabled=0");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	{
		int simulator_err = test_proxysql_simulator_error(proxysql_admin);
		if (simulator_err == EXIT_FAILURE) { goto cleanup; }
	}

	{
		int unshun_algorithm_err = test_unshun_algorithm_behavior(proxysql_mysql, proxysql_admin);
		if (unshun_algorithm_err == EXIT_FAILURE) { goto cleanup; }
	}

cleanup:

	mysql_close(proxysql_admin);
	mysql_close(proxysql_mysql);

	return exit_status();
}
