/**
 * @file test_default_value_transaction_isolation_attr-t.cpp
 * @brief This test is meant to test feature introduced in #3466.
 * @details The tests performs the following actions to verify that the feature
 *   is behaving properly:
 *      - Creates several new users with different values for the introduced
 *      attribute 'default-transaction_isolation'.
 *      - Connects with each of the create users verifying that the value has
 *      been correctly tracked for the frontend connection.
 *      - Performs the query 'SELECT @@transaction_isolation' to verify that
 *      the value is correctly propagated to the backend connection.
 *      - Explicitly sets the value and checks that ProxySQL is properly
 *      tracking it performing again the two previous actions.
 *
 * @date 2021-06-14
 */

#include <algorithm>
#include <random>
#include <string>
#include <stdio.h>
#include <tuple>
#include <vector>

#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "proxysql_utils.h"
#include "utils.h"
#include "json.hpp"

using std::string;
using namespace nlohmann;

/**
 * @brief Helper function to convert a 'MYSQL_RES' into a
 *   nlohmann::json.
 *
 * @param result The 'MYSQL_RES*' to be converted into JSON.
 * @param j 'nlohmann::json' output parameter holding the
 *   converted 'MYSQL_RES' supplied.
 */
void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

using user_attributes = std::tuple<std::string, std::string, std::string, std::string>;

/**
 * @brief User names and attributes to be check and verified.
 */
const std::vector<user_attributes> c_user_attributes {
	std::make_tuple(
		"sbtest1",
		"sbtest1",
		"{\"default-transaction_isolation\":\"READ COMMITTED\"}",
		"SERIALIZABLE"
	),
	std::make_tuple(
		"sbtest2",
		"sbtest2",
		"{\"default-transaction_isolation\":\"REPEATABLE READ\"}",
		"READ UNCOMMITTED"
	),
	std::make_tuple(
		"sbtest3",
		"sbtest3",
		"{\"default-transaction_isolation\":\"READ UNCOMMITTED\"}",
		"REPEATABLE READ"
	),
	std::make_tuple(
		"sbtest4",
		"sbtest4",
		"{\"default-transaction_isolation\":\"SERIALIZABLE\"}",
		"READ UNCOMMITTED"
	)
};

int check_front_conn_isolation_level(
	MYSQL* proxysql_mysql,
	const std::string& exp_iso_level,
	const bool set_via_attr
) {
	MYSQL_QUERY(proxysql_mysql, "PROXYSQL INTERNAL SESSION");
	json j_status {};
	MYSQL_RES* int_session_res = mysql_store_result(proxysql_mysql);
	parse_result_json_column(int_session_res, j_status);
	mysql_free_result(int_session_res);

	try {
		std::string front_conn_isolation_level =
			j_status.at("conn").at("isolation_level");

		// Set the 'ok_message' depending on whether the value for
		// isolation level have been set through an attribute,
		// or explicitly via a 'SET statement'
		std::string ok_msg {};
		if (set_via_attr) {
			ok_msg = std::string {
				"Tracked isolation level for frontend connection should match"
				" the one specified in the supplied 'user_attribute':\n"
				"    - (Exp: '%s') == (Act: '%s')",
			};
		} else {
			ok_msg = std::string {
				"Tracked isolation level for frontend connection should match"
				" the one explicitly set via 'SET SESSION TRANSACTION ISOLATION LEVEL':\n"
				"    - (Exp: '%s') == (Act: '%s')",
			};
		}

		ok(
			front_conn_isolation_level == exp_iso_level,
			ok_msg.c_str(),
			exp_iso_level.c_str(),
			front_conn_isolation_level.c_str()
		);
	} catch (std::exception& e) {
		diag("Test failed with exception: '%s'", e.what());

		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int check_backend_conn_isolation_level(
	MYSQL* proxysql_mysql,
	const std::string& exp_iso_level,
	const bool set_via_attr
) {
	// Get 'transaction_isolation' from backend connection
	std::string select_trx_iso_query { "SELECT @@transaction_isolation" };
	MYSQL_QUERY(proxysql_mysql, select_trx_iso_query.c_str());
	MYSQL_RES* trx_iso_res = mysql_store_result(proxysql_mysql);
	MYSQL_ROW trx_iso_row = mysql_fetch_row(trx_iso_res);
	std::string trx_iso_val {};

	// Verify that the query produced a correct result
	if (trx_iso_row && trx_iso_row[0]) {
		trx_iso_val = std::string { trx_iso_row[0] };
	} else {
		const std::string err_msg {
			"Empty result received from query '" + select_trx_iso_query + "'"
		};
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			err_msg.c_str()
		);
		return EXIT_FAILURE;
	}

	// Filter dashes from the query result
	std::replace(std::begin(trx_iso_val), std::end(trx_iso_val), '-', ' ');

	// Perform the check over the expected and actual value
	std::string t_ok_msg {};

	if (set_via_attr) {
		t_ok_msg = std::string {
			"Result of query '" + select_trx_iso_query + "' should match"
			" the isolation level supplied in 'user_attribute':\n"
			"    - (Exp: '%s') == (Act: '%s')",
		};
	} else {
		t_ok_msg = std::string {
			"Result of query '" + select_trx_iso_query + "' should match"
			" the isolation level explicitly set via 'SET SESSION TRANSACTION"
			" ISOLATION LEVEL':\n"
			"    - (Exp: '%s') == (Act: '%s')",
		};
	}

	ok(
		trx_iso_val == exp_iso_level, t_ok_msg.c_str(),
		exp_iso_level.c_str(), trx_iso_val.c_str()
	);

	return EXIT_SUCCESS;
}

int extract_exp_iso_level(
	const std::string& user_attribute,
	std::string& exp_iso_level
) {
	try {
		exp_iso_level =
			nlohmann::json::parse(user_attribute)
				.at("default-transaction_isolation");
	} catch (const std::exception& ex) {
		std::string t_err_msg {
			"Invalid format supplied in 'user-attribute'. Generated"
			" exception was: '%s'"
		};
		std::string err_msg {};
		string_format(t_err_msg, err_msg, ex.what());

		// Log the error while parsing the supplied attribute
		diag("%s", err_msg.c_str());

		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(c_user_attributes.size() * 4);

	MYSQL* proxysql_admin = mysql_init(NULL);
	MYSQL* mysql_server = mysql_init(NULL);

	// Creating the new connections
	if (
		!mysql_real_connect(
			proxysql_admin, cl.host, cl.admin_username,
			cl.admin_password, NULL, cl.admin_port, NULL, 0
		)
	) {
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			mysql_error(proxysql_admin)
		);
		return EXIT_FAILURE;
	}
	if (
		!mysql_real_connect(
			mysql_server, cl.host, "root", "root", NULL, 13306, NULL, 0
		)
	) {
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			mysql_error(mysql_server)
		);
		return EXIT_FAILURE;
	}

	// Creating the new required users
	std::vector<user_config> users_configs {};
	std::transform(
		c_user_attributes.begin(), c_user_attributes.end(), std::back_inserter(users_configs),
		[] (const user_attributes& u_attr) -> user_config {
			return make_tuple(std::get<0>(u_attr), std::get<1>(u_attr), std::get<2>(u_attr));
		}
	);
	int c_users_res =
		create_extra_users(proxysql_admin, mysql_server, users_configs);
	if (c_users_res) { return c_users_res; }

	// Load ProxySQL users to runtime
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL USERS TO RUNTIME");

	// Performing the connection checks
	std::vector<user_attributes> user_attributes { c_user_attributes };
	auto rng = std::default_random_engine {};
	std::shuffle(std::begin(user_attributes), std::end(user_attributes), rng);

	for (const auto& user_attribute : user_attributes) {
		// Create the new connection to verify
		MYSQL* proxysql_mysql = mysql_init(NULL);
		if (
			!mysql_real_connect(
				proxysql_mysql,
				cl.host,
				std::get<0>(user_attribute).c_str(),
				std::get<1>(user_attribute).c_str(),
				NULL, cl.port, NULL, 0)
		) {
			fprintf(
				stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
				mysql_error(proxysql_mysql)
			);
			return EXIT_FAILURE;
		}

		std::string exp_iso_level {};
		if (extract_exp_iso_level(std::get<2>(user_attribute), exp_iso_level)) {
			if (tests_failed()) { return exit_status(); }
			else { return EXIT_FAILURE; }
		}

		// Verify that the fronted connection is properly tracking the
		// isolation level set in the attributes.
		if (check_front_conn_isolation_level(proxysql_mysql, exp_iso_level, true)) {
			if (tests_failed()) { return exit_status(); }
			else { return EXIT_FAILURE; }
		}

		// Verify that the backend connection is properly tracking the
		// isolation level set in the attributes.
		if (check_backend_conn_isolation_level(proxysql_mysql, exp_iso_level, true)) {
			if (tests_failed()) { return exit_status(); }
			else { return EXIT_FAILURE; }
		}

		// Explicitly change the value for 'transaction_isolation' and
		// verify it changed.
		std::string t_set_trx_iso_level_query {
			"SET SESSION TRANSACTION ISOLATION LEVEL %s"
		};
		std::string set_trx_iso_level_query {};
		std::string new_exp_iso_level { std::get<3>(user_attribute) };
		string_format(
			t_set_trx_iso_level_query,
			set_trx_iso_level_query,
			new_exp_iso_level.c_str()
		);
		MYSQL_QUERY(proxysql_mysql, set_trx_iso_level_query.c_str());

		// Check again that the expected isolation level have changed for both connections
		if (check_front_conn_isolation_level(proxysql_mysql, new_exp_iso_level, false)) {
			if (tests_failed()) { return exit_status(); }
			else { return EXIT_FAILURE; }
		}

		if (check_backend_conn_isolation_level(proxysql_mysql, new_exp_iso_level, false)) {
			if (tests_failed()) { return exit_status(); }
			else { return EXIT_FAILURE; }
		}

		// Close the connection
		mysql_close(proxysql_mysql);
	}

	return exit_status();
}
