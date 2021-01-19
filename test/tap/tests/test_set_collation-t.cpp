/**
 * @file test_set_collation-t.cpp
 * @brief This test verifies that ProxySQL is properly setting the specified collation by the
 *  client during connection phase.
 */

#include <cstring>
#include <stdio.h>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

/**
 * NOTE: This is a duplicate of 'proxysql_find_charset_collate' in 'MySQL_Variables.h'. Including
 * 'MySQL_Variables' is not a easy task due to its interdependeces with other ProxySQL modules.
 */
MARIADB_CHARSET_INFO * proxysql_find_charset_collate(const char *collatename) {
	MARIADB_CHARSET_INFO *c = (MARIADB_CHARSET_INFO *)mariadb_compiled_charsets;
	do {
		if (!strcasecmp(c->name, collatename)) {
			return c;
		}
		++c;
	} while (c[0].nr != 0);
	return NULL;
}

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

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	int iterations = 10;
	std::vector<MYSQL*> conns {};
	std::vector<std::string> collations { "latin1_spanish_ci", "latin1_german2_ci", "latin1_danish_ci", "latin1_general_ci", "latin1_bin" };
	int conns_res = create_proxysql_connections(cl, collations, conns);

	ok(conns_res == 0, "Successfully create all connections with different collations");
	if (conns_res != 0) {
		return exit_status();
	}

	/**
	 * Force ProxySQL to create two new backend connections and simultaneously check that the
	 * 'character_set%' and 'collation_connection' for them are correct.
	 */
	for (int i = 0; i < 2; i++) {
		MYSQL* mysql = conns[i];
		std::string collation = collations[i];
		MYSQL_RES* proxy_res = nullptr;

		MYSQL_QUERY(
			mysql,
			"/*+ ;create_new_connection=1 */ SELECT lower(variable_name), variable_value FROM performance_schema.session_variables WHERE"
			" Variable_name IN ('character_set_client', 'character_set_connection', 'character_set_results', 'collation_connection')"
		);
		proxy_res = mysql_store_result(mysql);

		MYSQL_ROW row = mysql_fetch_row(proxy_res);
		ok(strcmp(row[1], "latin1") == 0, "'character_set_client' matches (expected: 'latin1') != (actual: '%s')", row[1]);

		row = mysql_fetch_row(proxy_res);
		ok(strcmp(row[1], "latin1") == 0, "'character_set_connection' matches (expected: 'latin1') != (actual: '%s')", row[1]);

		row = mysql_fetch_row(proxy_res);
		ok(strcmp(row[1], "latin1") == 0, "'character_set_results' matches (expected: 'latin1') != (actual: '%s')", row[1]);

		row = mysql_fetch_row(proxy_res);
		ok(strcmp(row[1], collation.c_str()) == 0, "'collation_connection' matches (expected: '%s') != (actual: '%s')", collation.c_str(), row[1]);
	}

	/**
	 * Do multiple iterations over the created connections checking that the 'character_set_%' and 'collation' variables
	 * remain properly set in the client and server side.
	 */
	for (int i = 0; i < conns.size(); i++) {
		MYSQL* mysql = conns[i];
		std::string collation = collations[i];
		MYSQL_RES* proxy_res = nullptr;

		MYSQL_QUERY(
			mysql,
			"SHOW VARIABLES WHERE Variable_name IN ('character_set_client', 'character_set_connection', 'character_set_results', 'collation_connection')"
		);
		proxy_res = mysql_store_result(mysql);

		MYSQL_ROW row = mysql_fetch_row(proxy_res);
		ok(strcmp(row[1], "latin1") == 0, "'character_set_client' matches (expected: 'latin1') != (actual: '%s')", row[1]);

		row = mysql_fetch_row(proxy_res);
		ok(strcmp(row[1], "latin1") == 0, "'character_set_connection' matches (expected: 'latin1') != (actual: '%s')", row[1]);

		row = mysql_fetch_row(proxy_res);
		ok(strcmp(row[1], "latin1") == 0, "'character_set_results' matches (expected: 'latin1') != (actual: '%s')", row[1]);

		row = mysql_fetch_row(proxy_res);
		ok(strcmp(row[1], collation.c_str()) == 0, "'collation_connection' matches (expected: '%s') != (actual: '%s')", collation.c_str(), row[1]);

		for (int j = 0; j < iterations; j++) {
			MYSQL_QUERY(
				mysql,
				"SELECT lower(variable_name), variable_value FROM performance_schema.session_variables WHERE"
				" Variable_name IN ('character_set_client', 'character_set_connection', 'character_set_results', 'collation_connection')"
			);
			proxy_res = mysql_store_result(mysql);

			MYSQL_ROW row = mysql_fetch_row(proxy_res);
			ok(strcmp(row[1], "latin1") == 0, "'character_set_client' matches (expected: 'latin1') != (actual: '%s')", row[1]);

			row = mysql_fetch_row(proxy_res);
			ok(strcmp(row[1], "latin1") == 0, "'character_set_connection' matches (expected: 'latin1') != (actual: '%s')", row[1]);

			row = mysql_fetch_row(proxy_res);
			ok(strcmp(row[1], "latin1") == 0, "'character_set_results' matches (expected: 'latin1') != (actual: '%s')", row[1]);

			row = mysql_fetch_row(proxy_res);
			ok(strcmp(row[1], collation.c_str()) == 0, "'collation_connection' matches (expected: '%s') != (actual: '%s')", collation.c_str(), row[1]);
		}
	}

	return exit_status();
}
