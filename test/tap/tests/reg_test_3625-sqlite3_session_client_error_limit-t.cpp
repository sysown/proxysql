/**
 * @file reg_test_3625-sqlite3_session_client_error_limit-t.cpp
 * @brief Regression test check that performing a valid connection to ProxySQL SQLite3 server
 *   should be successful when 'client_error_limit' is enabled.
 * @details It performs the following operations:
 *  - Enabling client error limit feature.
 *  - Perform a connection to ProxySQL SQLite3 server.
 */

#include <cstring>
#include <vector>
#include <tuple>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using query_spec = std::tuple<std::string, int>;

const int sqlite3_port = 0;

/**
 * @brief Extract the current 'sqliteserver-mysql_ifaces' from ProxySQL config.
 * @param proxysql_admin An already opened connection to ProxySQL Admin.
 * @return EXIT_SUCCESS, or one of the following error codes:
 *   - EINVAL if supplied 'proxysql_admin' is NULL.
 *   - '-1' in case of ProxySQL returns an 'NULL' row for the query selecting
 *     the variable 'sqliteserver-read_only'.
 *   - EXIT_FAILURE in case other operation failed.
 */
int get_sqlite3_ifaces(MYSQL* proxysql_admin, std::string& sqlite3_ifaces) {
	if (proxysql_admin == NULL) {
		return EINVAL;
	}

	int res = EXIT_FAILURE;

	MYSQL_QUERY(
		proxysql_admin,
		"SELECT * FROM global_variables WHERE Variable_name='sqliteserver-mysql_ifaces'"
	);

	MYSQL_RES* admin_res = mysql_store_result(proxysql_admin);
	if (!admin_res) {
		diag("'mysql_store_result' at line %d failed: %s", __LINE__, mysql_error(proxysql_admin));
		goto cleanup;
	}

	{
		MYSQL_ROW row = mysql_fetch_row(admin_res);
		if (!row || row[0] == nullptr || row[1] == nullptr) {
			diag("'mysql_fetch_row' at line %d returned 'NULL'", __LINE__);
			res = -1;
			goto cleanup;
		}

		std::string _sqlite3_ifaces { row[1] };
		sqlite3_ifaces = _sqlite3_ifaces;
		res = EXIT_SUCCESS;
	}

cleanup:

	return res;
}

int extract_sqlite3_host_port(MYSQL* proxysql_admin, std::pair<std::string, int>& host_port) {
	if (proxysql_admin == nullptr) { return EINVAL; }
	int res = EXIT_SUCCESS;

	std::string sqlite3_ifaces {};
	int ifaces_err = get_sqlite3_ifaces(proxysql_admin, sqlite3_ifaces);

	// ProxySQL is likely to have been launched without "--sqlite3-server" flag
	if (ifaces_err == -1) {
		diag("ProxySQL was launched without '--sqlite3-server' flag");
		res = EXIT_FAILURE;
		return res;
	}

	// Extract the correct port to connect to SQLite server
	std::string::size_type colon_pos = sqlite3_ifaces.find(":");
	if (colon_pos == std::string::npos) {
		diag("ProxySQL returned a malformed 'sqliteserver-mysql_ifaces': %s", sqlite3_ifaces.c_str());
		res = EXIT_FAILURE;
		return res;
	}

	std::string sqlite3_host { sqlite3_ifaces.substr(0, colon_pos) };
	std::string sqlite3_port { sqlite3_ifaces.substr(colon_pos + 1) };

	// Check that port has valid conversion
	char* end_pos = nullptr;
	int i_sqlite3_port = std::strtol(sqlite3_port.c_str(), &end_pos, 10);

	if (errno == ERANGE || (end_pos != &sqlite3_port.back() + 1)) {
		diag(
			"ProxySQL returned a invalid port number within 'sqliteserver-mysql_ifaces': %s",
			sqlite3_ifaces.c_str()
		);
		res = EXIT_FAILURE;
		return res;
	}

	if (res == EXIT_SUCCESS) {
		host_port = { sqlite3_host, i_sqlite3_port };
	}

	return res;
}

int main(int argc, char** argv) {
	CommandLine cl;

	// plan as many tests as queries
	plan(
		/* Enabling 'client_error_limit' succeed */
		2 +
		/* Fail to connect with wrong username and password */ 
		2 +
		/* Correctly connects with proper username and password */
		1
	);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxysql_admin = mysql_init(NULL);

	// Connect to ProxySQL Admin and check current SQLite3 configuration
	if (
		!mysql_real_connect(
			proxysql_admin, cl.host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0
		)
	) {
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			mysql_error(proxysql_admin)
		);
		return EXIT_FAILURE;
	}

	{
		std::pair<std::string, int> host_port {};
		int host_port_err = extract_sqlite3_host_port(proxysql_admin, host_port); 
		if (host_port_err) {
			diag("Failed to get and parse 'sqliteserver-mysql_ifaces' at line '%d'", __LINE__);
			goto cleanup;
		}

		MYSQL* proxysql_sqlite3 = mysql_init(NULL);

		// Enable 'client_error_limit'
		{
			int err_limit_errno = mysql_query(proxysql_admin, "SET mysql-client_host_cache_size=10");
			ok(err_limit_errno == EXIT_SUCCESS, "Successfully updated 'mysql-client_host_cache_size'");
			err_limit_errno = mysql_query(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
			ok(err_limit_errno == EXIT_SUCCESS, "Enabled 'client_host_cache_size'");
		}

		// Perform the invalid connections
		{
			// Connect with invalid username
			std::string inv_user_err {};
			bool failed_to_connect = false;
			if (
				!mysql_real_connect(
					proxysql_sqlite3, host_port.first.c_str(), "foobar_user", cl.password,
					NULL, host_port.second, NULL, 0
				)
			) {
				inv_user_err = mysql_error(proxysql_sqlite3);
				failed_to_connect = true;
			}

			ok(
				failed_to_connect,
				"An invalid user should fail to connect to SQLite3 server, error was: %s",
				inv_user_err.c_str()
			);

			// Reinitialize MYSQL handle
			mysql_close(proxysql_sqlite3);
			proxysql_sqlite3 = mysql_init(NULL);

			// Connect with invalid password
			std::string inv_pass_err {};
			failed_to_connect = false;
			if (
				!mysql_real_connect(
					proxysql_sqlite3, host_port.first.c_str(), cl.username, "foobar_pass",
					NULL, host_port.second, NULL, 0
				)
			) {
				inv_pass_err = mysql_error(proxysql_sqlite3);
				failed_to_connect = true;
			}

			ok(
				failed_to_connect,
				"An invalid user should fail to connect to SQLite3 server, error was: %s",
				inv_pass_err.c_str()
			);

			// Reinitialize MYSQL handle
			mysql_close(proxysql_sqlite3);
			proxysql_sqlite3 = mysql_init(NULL);
		}

		// Perform the valid connection
		{
			// Correctly connect to SQLite3 server
			MYSQL* connect_errno =
				mysql_real_connect(
					proxysql_sqlite3, host_port.first.c_str(), cl.username, cl.password,
					NULL, host_port.second, NULL, 0
				);

			ok(
				connect_errno != NULL,
				"Connection should succeed when using a valid 'username:password' (%s:%s)",
				cl.username, cl.password
			);
			mysql_close(proxysql_sqlite3);
		}
	}

cleanup:

	mysql_close(proxysql_admin);

	return exit_status();
}
