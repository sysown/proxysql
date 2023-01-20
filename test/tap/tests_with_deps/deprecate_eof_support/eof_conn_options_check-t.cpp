/**
 * @file eof_cache_mixed_flags-t.cpp
 * @brief This test verifies that the the new introduced flags 'mysql-enable_client_deprecate_eof' and
 *   'mysql-enable_server_deprecate_eof' actually impose the addition or deletion of 'client_deprecate_eof'
 *   flag to the "MySQL_Connection::options::client_flag" field.
 *
 * @details For verifying this, it makes use of 'PROXYSQL INTERNAL SESSION', creating a transaction for
 *   each new open connection, making sure that each client connection is paired with a new backend connection
 *   that holds the same flags as the client one. For this, the connections are started with:
 *   `/+\*;create_new_connection=1 \*\/ begin`.
 */

#include <utility>
#include <vector>
#include <string>
#include <stdio.h>
#include <iostream>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "json.hpp"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using nlohmann::json;

/**
 * @brief Extracts all the columns from a `MYSQL_RES` into a `nlohmann::json`.
 *
 * @param result MYSQL_RES to extract to a `nlohmann::json`.
 * @param j Output paramater 'json' to be filled with the contents of the `MYSQL_RES`.
 */
void parseResultJsonColumn(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

/**
 * @brief Queries the internal session status using 'PROXYSQL INTERNAL SESSION' to
 *  retrieve current values for 'client_deprecate_eof' in the client and backend
 *  connections.
 *
 * @param mysql An initialized MYSQL handler to ProxySQL.
 * @param c_s_flags Output parameter holding a 'client_server' pair with the found
 *  flags.
 *
 * @return '-1' in case of error, 0 otherwise.
 */
int queryInternalEOFStatus(MYSQL *mysql, std::pair<int,int>& c_s_flags) {
	char *query = (char*)"PROXYSQL INTERNAL SESSION";
	json j {};

	if (mysql_query(mysql, query)) {
		fprintf(stderr,"ERROR while running -- \"%s\" :  (%d) %s\n", query, mysql_errno(mysql), mysql_error(mysql));
		return -1;
	} else {
		MYSQL_RES *result = mysql_store_result(mysql);
		parseResultJsonColumn(result, j);
		mysql_free_result(result);
	}

	// get 'client_deprecate_eof' status in client connection
	auto client_eof_flag = j["conn"]["client_flag"]["client_deprecate_eof"];
	int server_eof_flag = -1;

	if (client_eof_flag == nullptr) {
		const char* msg = "Unable to find 'client_deprecate_eof' object in 'conn' session object.";
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, msg);
	} else {
		auto backend_it = j["backends"];

		for (const auto& backend : backend_it) {
			auto backend_conn = backend["conn"];
			if (backend_conn != nullptr) {
				server_eof_flag = backend_conn["client_flag"]["client_deprecate_eof"];
			}
		}
	}

	if (server_eof_flag == -1) {
		const char* msg = "Unable to find 'client_deprecate_eof' object in backend session connections.";
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, msg);

		return -1;
	}

	// return the retrieved flags
	c_s_flags = std::pair<int,int> { client_eof_flag, server_eof_flag };

	return 0;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	std::vector<std::pair<int,int>> states {
		{0, 0},
		{0, 1},
		{1, 0},
		{1, 1}
	};

	std::pair<int,int> c_s_flags { -1, -1 };

	MYSQL* proxy_admin = mysql_init(NULL);
	if (!proxy_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return -1;
	}
	if (!mysql_real_connect(proxy_admin ,cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return -1;
	}

	for (const auto& state : states) {
		std::string q_client_deprecate_eof { "SET mysql-enable_client_deprecate_eof='" + std::to_string(state.first) + "'" };
		std::string q_server_deprecate_eof { "SET mysql-enable_server_deprecate_eof='" + std::to_string(state.second) + "'" };

		MYSQL_QUERY(proxy_admin, q_client_deprecate_eof.c_str() );
		MYSQL_QUERY(proxy_admin, q_server_deprecate_eof.c_str() );

		MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		// initiate the 'ok' connection
		MYSQL* proxy_eof = mysql_init(NULL);
		if (!proxy_eof) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_eof));
			return -1;
		}
		if (!mysql_real_connect(proxy_eof, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_eof));
			return -1;
		}

		// start a transaction so we can inspect the backend connection
		MYSQL_QUERY(proxy_eof, "/*+ ;create_new_connection=1 */ begin");
		int st_res = queryInternalEOFStatus(proxy_eof, c_s_flags);

		ok(
			st_res == 0 && (c_s_flags.first == 0) && (c_s_flags.second == state.second),
			"'eof' connection 'client_deprecate_eof' actual (client: %d), (server: %d) != expected (client: %d), (server: %d)",
			c_s_flags.first,
			c_s_flags.second,
			0,
			state.second
		);

		mysql_close(proxy_eof);

		// initiate the 'eof' connection
		MYSQL* proxy_ok = mysql_init(NULL);
		if (!proxy_ok) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_ok));
			return -1;
		}

		proxy_ok->options.client_flag |= CLIENT_DEPRECATE_EOF;
		if (!mysql_real_connect(proxy_ok, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_ok));
			return -1;
		}

		c_s_flags = { -1, -1 };

		// start a transaction so we can inspect the backend connection
		MYSQL_QUERY(proxy_ok, "/*+ ;create_new_connection=1 */ begin");
		st_res = queryInternalEOFStatus(proxy_ok, c_s_flags);

		ok(
			st_res == 0 && (c_s_flags.first == state.first) && (c_s_flags.second == state.second),
			"'ok' connection 'client_deprecate_eof' actual (client: %d), (server: %d) != expected (client: %d), (server: %d)",
			c_s_flags.first,
			c_s_flags.second,
			state.first,
			state.second
		);

		mysql_close(proxy_ok);
	}

	return exit_status();
}
