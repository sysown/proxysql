/**
 * @file reg_test_n-lock_hostgroup_special_queries-t.cpp
 * @brief This test verifies that after locking on a hostgroup, ProxySQL forwards
 *  several simple special queries in a proper way, forwarding them to the backend
 *  connection.
 * Note: queries have hostgroup=0 to avoid getting lock on hostgroup 0 and
 *       attempting to run queries on hostgroup 1
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>
#include <functional>

#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

/**
 * @brief Checks that 'SET NAMES' is being executed properly in the backend connection.
 * @param proxysql_mysql A MYSQL handle to an already stablished MySQL connection.
 */
void check_set_names(MYSQL* proxysql_mysql) {
	bool exp_values = false;

	// Issue the target query 'SET NAMES latin7'
	int query_res = mysql_query(proxysql_mysql, "SET NAMES latin7");
	if (query_res) {
		diag("Query failed with error: %s", mysql_error(proxysql_mysql));
		return;
	}

	query_res = mysql_query(proxysql_mysql, "SELECT /* ;hostgroup=0 */ @@character_set_client, @@character_set_results, @@character_set_connection");
	if (query_res) {
		diag("Query failed with error: %s", mysql_error(proxysql_mysql));
		return;
	}

	MYSQL_RES* select_res = mysql_store_result(proxysql_mysql);
	std::string character_set_client {};
	std::string character_set_results {};
	std::string character_set_connection {};

	if (mysql_num_rows(select_res) == 1 && mysql_num_fields(select_res) == 3) {
		MYSQL_ROW row = mysql_fetch_row(select_res);
		character_set_client = std::string { row[0] };
		character_set_results = std::string { row[1] };
		character_set_connection = std::string { row[2] };

		exp_values =
			character_set_client == "latin7" &&
			character_set_results == "latin7" &&
			character_set_connection == "latin7";
	} else {
		diag(
			"mysql_store_result: returned '%lld' rows and '%d' fields, expected '%d' rows and '%d' fields",
			mysql_num_rows(select_res), mysql_num_fields(select_res), 1, 3
		);
	}

	mysql_free_result(select_res);

	ok(
		exp_values,
		"Values after 'SET NAMES latin7' are: (character_set_client: '%s', character_set_results: '%s', character_set_connection: '%s')",
		character_set_client.c_str(),
		character_set_results.c_str(),
		character_set_connection.c_str()
	);
}

/**
 * @brief Checks that 'SET autocommit' is being executed properly in the backend connection.
 * @param proxysql_mysql A MYSQL handle to an already stablished MySQL connection.
 */
void check_autocommit(MYSQL* proxysql_mysql) {
	int query_res = mysql_query(proxysql_mysql, "SELECT /* ;hostgroup=0 */ @@autocommit");
	if (query_res) {
		diag("Query failed with error: %s", mysql_error(proxysql_mysql));
		return;
	}

	// Check current status on @@autocommit
	MYSQL_RES* select_res = mysql_store_result(proxysql_mysql);
	MYSQL_ROW row = mysql_fetch_row(select_res);
	bool autocommit_val = atoi(row[0]);
	mysql_free_result(select_res);

	// Expected autocommit value after chaning current one
	bool exp_autocommit_val = !autocommit_val;

	std::string t_autocommit_query { "SET autocommit=%d" };
	std::string autocommit_query(static_cast<std::size_t>(t_autocommit_query.size() + 12), '\0');
	snprintf(&autocommit_query[0], autocommit_query.size(), t_autocommit_query.c_str(), static_cast<int>(!autocommit_val));

	// Change the current value for autocommit
	mysql_query(proxysql_mysql, autocommit_query.c_str());
	if (query_res) {
		diag("Query failed with error: %s", mysql_error(proxysql_mysql));
		return;
	}

	// Check new status on @@autocommit
	query_res = mysql_query(proxysql_mysql, "SELECT /* ;hostgroup=0 */ @@autocommit");
	if (query_res) {
		diag("Query failed with error: %s", mysql_error(proxysql_mysql));
		return;
	}

	select_res = mysql_store_result(proxysql_mysql);
	row = mysql_fetch_row(select_res);
	autocommit_val = atoi(row[0]);
	mysql_free_result(select_res);

	ok(
		autocommit_val == exp_autocommit_val,
		"'Autocommit' value should match the expected one - (actual: '%d') == (exp: '%d')",
		autocommit_val,
		exp_autocommit_val
	);
}

/**
 * @brief Checks that 'SET SESSION character_set_server' is being executed properly in
 *   the backend connection.
 * @param proxysql_mysql A MYSQL handle to an already stablished MySQL connection.
 */
void check_session_character_set_server(MYSQL* proxysql_mysql) {
	bool exp_values = false;

	// Issue the target query 'SET NAMES latin7'
	std::string set_server_charset_query { "SET SESSION character_set_server=latin7" };
	int query_res = mysql_query(proxysql_mysql, set_server_charset_query.c_str());
	if (query_res) {
		diag("Query failed with error: %s", mysql_error(proxysql_mysql));
		return;
	}

	query_res = mysql_query(proxysql_mysql, "SELECT /* ;hostgroup=0 */ @@character_set_server");
	if (query_res) {
		diag("Query failed with error: %s", mysql_error(proxysql_mysql));
		return;
	}

	MYSQL_RES* select_res = mysql_store_result(proxysql_mysql);
	std::string character_set_server {};
	MYSQL_ROW row = mysql_fetch_row(select_res);
	character_set_server = std::string { row[0] };

	exp_values = character_set_server == "latin7";

	mysql_free_result(select_res);

	ok(
		exp_values,
		"Value after '%s' are: character_set_server: '%s')",
		set_server_charset_query.c_str(),
		character_set_server.c_str()
	);
}

/**
 * @brief Checks that 'SET SESSION character_set_results' is being executed properly in
 *   the backend connection.
 * @param proxysql_mysql A MYSQL handle to an already stablished MySQL connection.
 */
void check_session_character_set_results(MYSQL* proxysql_mysql) {
	bool exp_values = false;

	// Issue the target query 'SET NAMES latin7'
	std::string set_server_charset_query { "SET SESSION character_set_results=latin7" };
	int query_res = mysql_query(proxysql_mysql, set_server_charset_query.c_str());
	if (query_res) {
		diag("Query failed with error: %s", mysql_error(proxysql_mysql));
		return;
	}

	query_res = mysql_query(proxysql_mysql, "SELECT /* ;hostgroup=0 */ @@character_set_results");
	if (query_res) {
		diag("Query failed with error: %s", mysql_error(proxysql_mysql));
		return;
	}

	MYSQL_RES* select_res = mysql_store_result(proxysql_mysql);
	std::string character_set_results {};
	MYSQL_ROW row = mysql_fetch_row(select_res);
	character_set_results = std::string { row[0] };

	exp_values = character_set_results == "latin7";

	mysql_free_result(select_res);

	ok(
		exp_values,
		"Value after '%s' are: character_set_results: '%s')",
		set_server_charset_query.c_str(),
		character_set_results.c_str()
	);
}

/**
 * @brief Vector of pairs holding the test name and the function performing the check.
 */
std::vector<std::pair<std::string, std::function<void(MYSQL*)>>> special_queries_checks {
	{ "'SET NAMES' check", check_set_names },
	{ "'SET autocommit' check", check_autocommit },
	{ "'SET SESSION character_set_server' check", check_session_character_set_server },
	{ "'SET SESSION character_set_results' check", check_session_character_set_results }
};

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(special_queries_checks.size() * 2);
	int check_num = 0;

	for (const auto& query_check : special_queries_checks) {
		// Create a new connection to ProxySQL
		MYSQL* proxysql_mysql = mysql_init(NULL);
		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		// Try to set an invalid variable, ProxySQL should lock on hostgroup.
		int inv_query_res = mysql_query(proxysql_mysql, "SET inexisting_variable = ''");
		ok(inv_query_res != 0, "Preparing check nº: '%d'. Invalid query should fail - errcode: %d", check_num, inv_query_res);

		diag("Performing check: \"%s\"", query_check.first.c_str());

		// Perform the checks in the connection variables
		query_check.second(proxysql_mysql);

		// Close the connection
		mysql_close(proxysql_mysql);
	}

	return exit_status();
}
