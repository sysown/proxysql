/**
 * @file reg_test_3493-USE_with_comment-t.cpp
 * @brief This test verifies that a 'USE' statement is properly tracked by
 *   ProxySQL, even when executed with a leading comment.
 * @details For being sure that the feature is properly supported the
 *   test performs the following actions:
 *
 *   1. Open a MYSQL connection to ProxySQL.
 *   2. Drops and creates multiple databases called 'reg_test_3493_use_comment-N'.
 *   3. Performs a 'USE' statement in the connection.
 *   3. Checks the currently selected database in **a new backend database connection** by means of the
 *      connection annotation "create_new_connection=1". This way it's ensured that ProxySQL is properly keeping
 *      track of the database selected in the issued 'USE' statement via 'PROXYSQL INTERNAL SESSION'.
 *   4. Perform the exact same test with 'mysql-query_digests=0'. This just ensures that ProxySQL is properly
 *      executing the 'USE' statement in the backend connection, expected tracking failures are verified for
 *      the listed cases, since 'create_new_connection' annotation shouldn't have any effect, queries will be
 *      executed in the same backend connection, because of this, 'SELECT DATABASE()' should still return the
 *      same database as specified via 'USE' statement.
 */

#include <cstring>
#include <vector>
#include <utility>
#include <string>
#include <stdio.h>

#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

using nlohmann::json;

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

int get_session_schemaname(MYSQL* proxysql, std::string& schemaname) {
	int res = EXIT_FAILURE;

	json j_status;
	int query_res = mysql_query(proxysql, "PROXYSQL INTERNAL SESSION");
	if (query_res) {
		return query_res;
	}

	MYSQL_RES* tr_res = mysql_store_result(proxysql);
	parse_result_json_column(tr_res, j_status);
	mysql_free_result(tr_res);

	try {
		schemaname = j_status["client"]["userinfo"]["schemaname"];
		res = EXIT_SUCCESS;
	} catch (const std::exception& e) {
		diag("Exception while trying to access 'schemaname' from 'PROXYSQL INTERNAL SESSION': '%s'", e.what());
		res = EXIT_FAILURE;
	}

	return res;
}

std::vector<std::tuple<std::string,std::string,bool>> db_query {};

int test_use_queries(MYSQL* proxysql_mysql, bool enabled_digests) {
	int i = 0;

	for (std::vector<std::tuple<std::string,std::string, bool>>::iterator it = db_query.begin(); it != db_query.end() ; it++) {
		const std::string& name = std::get<0>(*it);
		const std::string& query = std::get<1>(*it);
		const bool should_match = std::get<2>(*it);

		int err = mysql_query(proxysql_mysql, query.c_str());
		if (err) {
			diag(
				"'USE' command failed with error code '%d' and error '%s' for query: %s",
				err, mysql_error(proxysql_mysql), query.c_str()
			);
			return EXIT_FAILURE;
		}

		// Perform the 'SELECT DATABASE()' query in a new backend connection, to
		// verify that ProxySQL is properly tracking the previously performed 'USE'
		// statement.
		switch (i%5) {
			case 0:
				MYSQL_QUERY(proxysql_mysql, "/* ;create_new_connection=1 */ SELECT DATABASE()");
				break;
			case 1:
				MYSQL_QUERY(proxysql_mysql, "/* ;create_new_connection=1 */SELECT DATABASE()");
				break;
			case 2:
				MYSQL_QUERY(proxysql_mysql, "SELECT /* ;create_new_connection=1 */ DATABASE()");
				break;
			case 3:
				MYSQL_QUERY(proxysql_mysql, "SELECT/* ;create_new_connection=1 */ DATABASE()");
				break;
			case 4:
				MYSQL_QUERY(proxysql_mysql, "SELECT /* ;create_new_connection=1 */DATABASE()");
				break;
			default:
				assert(0);
		}
		i++;

		MYSQL_RES* result = mysql_store_result(proxysql_mysql);
		if (result == nullptr) {
			diag("Invalid 'MYSQL_RES' returned from 'SELECT DATABASE()'");
			return EXIT_FAILURE;
		}
		MYSQL_ROW row = mysql_fetch_row(result);
		if (row == nullptr) {
			diag("Invalid 'MYSQL_ROW' returned from 'SELECT DATABASE()'");
			return EXIT_FAILURE;
		}
		std::string database_name { row[0] };
		mysql_free_result(result);

		if (name[0] == '`') {
			database_name = "`" + database_name + "`";
		}

		std::string cur_tracked_schema {};
		err = get_session_schemaname(proxysql_mysql, cur_tracked_schema);
		if (err != EXIT_SUCCESS) {
			diag("'get_session_schemaname' failed with error: %d", err);
			return EXIT_FAILURE;
		}

		if (name[0] == '`') {
			cur_tracked_schema = "`" + cur_tracked_schema + "`";
		}

		if (enabled_digests == true) {
			ok(
				database_name == name && cur_tracked_schema == name,
				"Selected and tracked DB names should be equal to actual DB name: "
					"(Exp_SEL: '%s') == (Act_SEL: '%s'), (Exp_TRACKED: '%s') == (Act_TRACKED: '%s')",
				name.c_str(), database_name.c_str(), name.c_str(), cur_tracked_schema.c_str()
			);
		} else {
			if (should_match == true) {
				ok(
					database_name == name && cur_tracked_schema == name,
					"Selected and tracked DB names should be equal to actual DB name: "
						"(Exp_SEL: '%s') == (Act_SEL: '%s'), (Exp_TRACKED: '%s') == (Act_TRACKED: '%s')",
					name.c_str(), database_name.c_str(), name.c_str(), cur_tracked_schema.c_str()
				);
			} else {
				ok(
					database_name == name && cur_tracked_schema != name,
					"Selected DB name should be equal to actual DB name, but tracked DB name should differ: "
						"(Exp_SEL: '%s') == (Act_SEL: '%s'), (Exp_TRACKED: '%s') == (Act_TRACKED: '%s')",
					name.c_str(), database_name.c_str(), name.c_str(), cur_tracked_schema.c_str()
				);
			}
		}
	}

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* proxysql_mysql = mysql_init(NULL);

	db_query.push_back(std::make_tuple("reg_test_3493_use_comment", "/*+ placeholder_comment */ USE reg_test_3493_use_comment", false));
	db_query.push_back(std::make_tuple("`reg_test_3493_use_comment-a1`", "USE /*+ placeholder_comment */ `reg_test_3493_use_comment-a1`", true));
	db_query.push_back(std::make_tuple("reg_test_3493_use_comment_1", "  USE /*+ placeholder_comment */   `reg_test_3493_use_comment_1`", false));
	db_query.push_back(std::make_tuple("reg_test_3493_use_comment_2", "USE/*+ placeholder_comment */ `reg_test_3493_use_comment_2`", false));
	db_query.push_back(std::make_tuple("reg_test_3493_use_comment_3", "USE /*+ placeholder_comment */`reg_test_3493_use_comment_3`", true));
	db_query.push_back(std::make_tuple("reg_test_3493_use_comment_4", "  USE /*+ placeholder_comment */   reg_test_3493_use_comment_4", false));
	db_query.push_back(std::make_tuple("reg_test_3493_use_comment_5", "USE/*+ placeholder_comment */ reg_test_3493_use_comment_5", false));
	db_query.push_back(std::make_tuple("reg_test_3493_use_comment_6", "USE /*+ placeholder_comment */reg_test_3493_use_comment_6", true));
	db_query.push_back(std::make_tuple("`reg_test_3493_use_comment-1`", "  USE /*+ placeholder_comment */   `reg_test_3493_use_comment-1`", false));
	db_query.push_back(std::make_tuple("`reg_test_3493_use_comment-2`", "USE/*+ placeholder_comment */ `reg_test_3493_use_comment-2`", false));
	db_query.push_back(std::make_tuple("`reg_test_3493_use_comment-3`", "USE /*+ placeholder_comment */`reg_test_3493_use_comment-3`", true));
	db_query.push_back(std::make_tuple("`reg_test_3493_use_comment-4`", "/*+ placeholder_comment */USE          `reg_test_3493_use_comment-4`", false));
	db_query.push_back(std::make_tuple("`reg_test_3493_use_comment-5`", "USE/*+ placeholder_comment */`reg_test_3493_use_comment-5`", false));
	db_query.push_back(std::make_tuple("`reg_test_3493_use_comment-6`", "/* comment */USE`reg_test_3493_use_comment-6`", false));
	db_query.push_back(std::make_tuple("`reg_test_3493_use_comment-7`", "USE`reg_test_3493_use_comment-7`", false));

	plan(db_query.size() * 2);

	if (
		!mysql_real_connect(
			proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0
		)
	) {
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			mysql_error(proxysql_mysql)
		);
		return EXIT_FAILURE;
	}

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	// Prepare the DB for the test
	for (std::vector<std::tuple<std::string,std::string, bool>>::iterator it = db_query.begin(); it != db_query.end() ; it++) {
		const std::string& name = std::get<0>(*it);

		std::string s = "";
		s = "DROP DATABASE IF EXISTS " + name;
		MYSQL_QUERY(proxysql_mysql, s.c_str());
		s = "CREATE DATABASE " + name;
		MYSQL_QUERY(proxysql_mysql, s.c_str());
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-query_digests='true'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	// Check 'USE' statements are being properly parsed and tracked when 'mysql-query_digests' is 'ENABLED'.
	test_use_queries(proxysql_mysql, true);

	MYSQL_QUERY(proxysql_admin, "SET mysql-query_digests='false'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	// Check 'USE' statements are being properly executed when 'mysql-query_digests' is 'DISABLED'.
	test_use_queries(proxysql_mysql, false);

	// Drop created database
	for (std::vector<std::tuple<std::string,std::string, bool>>::iterator it = db_query.begin(); it != db_query.end() ; it++) {
		const std::string& name = std::get<0>(*it);

		std::string s = "";
		s = "DROP DATABASE IF EXISTS " + name;
		MYSQL_QUERY(proxysql_mysql, s.c_str());
	}
	mysql_close(proxysql_mysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
