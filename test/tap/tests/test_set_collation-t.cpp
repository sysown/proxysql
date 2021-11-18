/**
 * @file test_set_collation-t.cpp
 * @brief This test verifies that ProxySQL is properly setting the specified collation by the
 *  client during connection phase.
 */

#include <cstring>
#include <stdio.h>
#include <mysql.h>
#include <algorithm>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#define NUMBER_NEW_CONNECTIONS 2
#define N_ITERATION_1  10
#define N_ITERATION_2  2
#define N_ITERATION_3  3

/**
 * @brief Creates a different MYSQL connection for each supplied collation. Logs in case of a
 *  failure creating a connection.
 *
 * @param cl The command line parameters required for creating the connection.
 * @param collations The collations with which to initialize the MYSQL connections.
 * @param conns Output parameter which will contain the initialized connections in case of success.
 *
 * @return Returns '0' in case of success, '-1' otherwise.
 */
int create_proxysql_connections(const CommandLine& cl, const std::vector<std::string>& collations, std::vector<MYSQL*>& conns) {
	std::vector<MYSQL*> _conns {};

	for (const auto& collation : collations) {
		MYSQL* mysql = mysql_init(NULL);
		const MARIADB_CHARSET_INFO* charset = proxysql_find_charset_collate(collation.c_str());
		mysql->charset = charset;

		if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			return -1;
		}

		_conns.push_back(mysql);
	}

	// return the created connections
	conns = _conns;

	return 0;
}

int run_change_user_on_all(const CommandLine& cl, const std::vector<std::string>& collations, std::vector<MYSQL*>& conns) {
	// start a transaction in every connection
	// and then trigger a change user
	// we first create a transaction in order to force the reset of the backend using CHANGE_USER
	for (int i = 0; i < conns.size(); i++) {
		MYSQL* mysql = conns[i];
		MYSQL_QUERY(mysql, "START TRANSACTION");
		const MARIADB_CHARSET_INFO* charset = proxysql_find_charset_collate(collations[i].c_str());
		mysql->charset = charset;
		if (mysql_change_user(mysql,cl.username, cl.password, NULL)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			return -1;
		}
		ok(true, "Completed mysql_change_user() for connection %d", i);
	}
	return 0;
}

void check_variables(MYSQL_RES *proxy_res, std::string collation) {
	std::size_t found = collation.find("_");
	std::string charset = collation.substr(0,found);

	MYSQL_ROW row = mysql_fetch_row(proxy_res);
	ok(strcmp(row[1], charset.c_str()) == 0, "'character_set_client' matches (expected: '%s') == (actual: '%s')", charset.c_str(), row[1]);
	row = mysql_fetch_row(proxy_res);
	ok(strcmp(row[1], charset.c_str()) == 0, "'character_set_connection' matches (expected: '%s') == (actual: '%s')", charset.c_str(), row[1]);
	row = mysql_fetch_row(proxy_res);
	ok(strcmp(row[1], charset.c_str()) == 0, "'character_set_results' matches (expected: '%s') == (actual: '%s')", charset.c_str(), row[1]);
	row = mysql_fetch_row(proxy_res);
	ok(strcmp(row[1], collation.c_str()) == 0, "'collation_connection' matches (expected: '%s') == (actual: '%s')", collation.c_str(), row[1]);
}


int query_and_check_session_variables(MYSQL *mysql, std::string collation, int iterations, bool new_connection=false) {
	MYSQL_RES* proxy_res = nullptr;
	std::string query = "";
	if (new_connection)
		query += "/* ;create_new_connection=1 */ ";
	query += "SELECT lower(variable_name), variable_value FROM performance_schema.session_variables WHERE";
	query +=" Variable_name IN ('character_set_client', 'character_set_connection', 'character_set_results', 'collation_connection') ORDER BY Variable_name";

	for (int j = 0; j < iterations; j++) {
		MYSQL_QUERY(mysql, query.c_str());
		proxy_res = mysql_store_result(mysql);
		check_variables(proxy_res, collation);
		mysql_free_result(proxy_res);
	}
	return 0;
}


int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	std::vector<MYSQL*> conns {};
	std::vector<std::string> collations { "latin1_spanish_ci", "latin1_german2_ci", "latin1_danish_ci", "latin1_general_ci", "latin1_bin", "utf8_general_ci", "utf8_unicode_ci" };

	int ntests = 0;
	ntests += 1; // create all connections
	ntests += (NUMBER_NEW_CONNECTIONS) * 4;
	ntests += (N_ITERATION_1 * collations.size()) * 4;
	ntests += collations.size() * 2; // number of times we will call mysql_change_user()
	ntests += (N_ITERATION_2 * collations.size()) * 4;
	ntests += (N_ITERATION_3 * collations.size()) * 4;
	plan(ntests);

	int conns_res = create_proxysql_connections(cl, collations, conns);

	ok(conns_res == 0, "Successfully create all connections with different collations");
	if (conns_res != 0) {
		return exit_status();
	}

	/**
	 * Force ProxySQL to create two new backend connections and simultaneously check that the
	 * 'character_set%' and 'collation_connection' for them are correct.
	 */
	for (int i = 0; i < NUMBER_NEW_CONNECTIONS; i++) {
		MYSQL* mysql = conns[i];
		std::string collation = collations[i];
		query_and_check_session_variables(mysql, collation, 1, true);
	}

	/**
	 * Do multiple iterations over the created connections checking that the 'character_set_%' and 'collation' variables
	 * remain properly set in the client and server side.
	 */
	for (int i = 0; i < conns.size(); i++) {
		MYSQL* mysql = conns[i];
		std::string collation = collations[i];
		query_and_check_session_variables(mysql, collation, N_ITERATION_1);
	}

	// we now want to check what happens after resetting backend connections
	if (run_change_user_on_all(cl, collations, conns))
		return exit_status();

	// we iterate and check through all the connections
	for (int i = 0; i < conns.size(); i++) {
		MYSQL* mysql = conns[i];
		std::string collation = collations[i];
		query_and_check_session_variables(mysql, collation, N_ITERATION_2);
	}

	// we now want to check what happens after resetting backend connections
	// we also reverse the order of collations
	std::reverse(collations.begin(), collations.end());
	if (run_change_user_on_all(cl, collations, conns))
		return exit_status();
	// we iterate and check through all the connections
	for (int i = 0; i < conns.size(); i++) {
		MYSQL* mysql = conns[i];
		std::string collation = collations[i];
		query_and_check_session_variables(mysql, collation, N_ITERATION_3);
	}


	return exit_status();
}
