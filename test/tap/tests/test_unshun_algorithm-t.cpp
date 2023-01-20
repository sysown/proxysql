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
 *
 *  CI-FAILURES-NOTES:
 *  This test received some changes after being detected that was provoking some failures in the CI.
 *  The circumstances of these failures are summarized here together with the issue resolution as a reminder
 *  of the design.
 *
 *  PREVIOUS-DESIGN:
 *  In the previous design the test set the following variables:
 *
 *  ```
 *  "SET mysql-shun_on_failures=5"
 *  "SET mysql-connect_retries_on_failure=0"
 *  ```
 *
 *  These values were chosen to avoid connection retrying when the connection error takes place.
 *  For making sure that the server was properly UNSHUNNED, two queries were issued, with a two second delay
 *  between them. The second query should only produce one error, thus not going over the threshold of at
 *  least '2' errors within the same second to set the server as SHUNNED again.
 *
 *  FLAW:
 *  The assumption that the second query cannot produce a second error is FALSE. The second query can produce
 *  two errors under certain timing conditions. If the call to 'mysql_real_connect_start' doesn't immediately
 *  return, because the underlying socket haven't been yet signaled, then 'MySQL_Session::handler' will
 *  return, this will result into:
 *
 *  1. 'MySQL_Data_Stream' receiving the socket event in next poll, the event will be processed, but because the
 *     server isn't present a error will be generated.
 *  2. The session will later be processed, and due to the server still not being present, a second error will
 *     be generated, resulting into the server being SHUNNED.
 *
 *  SOLUTION:
 *  Test now uses the following values for the variables:
 *
 *  ```
 *  "SET mysql-shun_on_failures=3"
 *  "SET mysql-connect_retries_on_failure=3"
 *  "SET mysql-connect_retries_delay=1000"
 *  ```
 *
 *  This will avoid any accidental SHUNNING due to the previously described situation, and due to
 *  'connect_retries_delay' will prevent more than one connection attempt per second.
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

/**
 * @brief Issues a simple 'DO 1' query to the target hostgroup with the intention of UNSHUNNING the server
 *   present in that hostgroup.
 * @param proxysql_mysql An already opened connection to ProxySQL.
 * @param i The hostgroup to which the query should be issued.
 * @return Since query errors are ignored, because the query is supposed to fail, EXIT_SUCCESS is always
 *   returned.
 */
int wakup_target_server(MYSQL* proxysql_mysql, uint32_t i) {
	std::string t_simple_do_query { "DO /* ;hostgroup=%d */ 1" };
	std::string simple_do_query {};
	string_format(t_simple_do_query, simple_do_query, i);

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

/**
 * @brief Configures the relevant 'mysql' variables for achieving the test desired UNSHUNNING behavior.
 * @details The values set for these variables prevent the target server to be SHUNNED after being UNSHUNNED
 *   by the query issued by 'wakup_target_server', in case the query produces two simultaneous errors instead
 *   of just one. Why this is a possibility is described on the details sections in the file DOC.
 * @param proxysql_admin An already opened connection to ProxySQL Admin.
 * @return EXIT_SUCCESS in case of success, EXIT_FAILURE otherwise.
 */
int configure_mysql_shunning_variables(MYSQL* proxysql_admin) {
	MYSQL_QUERY(proxysql_admin, "SET mysql-shun_on_failures=3");
	diag("%s: Line:%d running admin query: SET mysql-shun_on_failures=3", tap_curtime().c_str(), __LINE__);

	MYSQL_QUERY(proxysql_admin, "SET mysql-connect_retries_on_failure=3");
	diag("%s: Line:%d running admin query: SET mysql-connect_retries_on_failure=3", tap_curtime().c_str(), __LINE__);

	MYSQL_QUERY(proxysql_admin, "SET mysql-connect_retries_delay=1000");
	diag("%s: Line:%d running admin query: SET mysql-connect_retries_delay=1000", tap_curtime().c_str(), __LINE__);

	return EXIT_SUCCESS;
}

int test_unshun_algorithm_behavior(MYSQL* proxysql_mysql, MYSQL* proxysql_admin) {
	// Configure Admin variables with lower thresholds
	MYSQL_QUERY(proxysql_admin, "SET mysql-shun_recovery_time_sec=1");
	diag("%s: Line:%d running admin query: SET mysql-shun_recovery_time_sec=1", tap_curtime().c_str(), __LINE__);

	// Set verbosity up for extra information in ProxySQL log
	MYSQL_QUERY(proxysql_admin, "SET mysql-hostgroup_manager_verbose=3");
	diag("%s: Line:%d running admin query: SET mysql-hostgroup_manager_verbose=3", tap_curtime().c_str(), __LINE__);

	// Configure the relevant variables for the desired UNSHUNNING behavior
	if (configure_mysql_shunning_variables(proxysql_admin)) {
		return EXIT_FAILURE;
	}

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
			if (tests_failed()) {
				return exit_status();
			}
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
			if (tests_failed()) {
				return exit_status();
			}
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
			if (tests_failed()) {
				return exit_status();
			}
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
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
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
