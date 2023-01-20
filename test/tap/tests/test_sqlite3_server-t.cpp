/**
 * @file test_sqlite3_server-t.cpp
 * @brief Test to perform multiple operations over ProxySQL SQLite3 server.
 * @details It performs the following operations:
 *  - Connects to sqlite3 with a wrong username.
 *  - Connects to sqlite3 with a right username but wrong password.
 *  - Successfully connects to sqlite3 and runs:
 *      + SHOW SCHEMAS
 *      + SHOW DATABASES
 *      + SELECT DATABASE()
 *      + select DATABASE(), USER() limit 1
 *      + select @@version_comment limit 1
 *      + select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1
 *  - Successfully connects to sqlite3 and runs a variety of queries:
 *      + CREATE TABLE, SHOW CREATE TABLE, INSERT, SELECT, DROP TABLE...
 *      + Queries that induce errors: syntax error, duplicate keys, etc...
 *  - Changes 'sqliteserver-mysql_ifaces' and tries to connect to the new interface.
 *  - Connects to ProxySQL Admin and performs the following operations:
 *      + LOAD|SAVE SQLITESERVER TO|FROM RUNTIME|MEMORY|DISK
 *
 *  NOTE: 'sqliteserver-read_only' is completely omitted from this test because
 *  it's **currently unused**.
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

#include "modules_server_test.h"

void fetch_and_discard_results(MYSQL_RES* result, bool verbose=false) {
	MYSQL_ROW row = nullptr;
	unsigned int num_fields = 0;
	unsigned int i = 0;
	unsigned int j = 0;

	num_fields = mysql_num_fields(result);
	while ((row = mysql_fetch_row(result))) {
		unsigned long *lengths = mysql_fetch_lengths(result);

		if (verbose) {
			printf("# RowNum_%d: ", j);
		}

		for(i = 0; i < num_fields; i++) {
			if (verbose) {
				printf("[%.*s] ", (int) lengths[i], row[i] ? row[i] : "NULL");
			}
		}

		if (verbose) {
			printf("\n");
		}

		j++;
	}
}

/**
 * @brief Execute the supplied queries and check that the return codes are the
 *   ones specified.
 *
 * @param proxysql_sqlite3 An already opened MYSQL connection to ProxySQL
 *   SQLite3 server.
 * @param queries The queries to be performed and check.
 */
void execute_and_check_queries(MYSQL* proxysql_sqlite3, const std::vector<query_spec>& queries) {
	for (const auto& supp_query : queries) {
		const std::string query = std::get<0>(supp_query);
		const int exp_err_code = std::get<1>(supp_query);

		int query_err = mysql_query(proxysql_sqlite3, query.c_str());
		MYSQL_RES* result = mysql_store_result(proxysql_sqlite3);
		if (result) {
			fetch_and_discard_results(result, true);
			mysql_free_result(result);
		}

		int m_errno = mysql_errno(proxysql_sqlite3);
		const char* m_error = mysql_error(proxysql_sqlite3);

		if (exp_err_code == 0) {
			ok(
				exp_err_code == m_errno,
				"Query '%s' should succeed. Error code: (Expected:'%d' == Actual:'%d')",
				query.c_str(), exp_err_code, m_errno
			);
		} else {
			ok(
				exp_err_code == m_errno,
				"Query '%s' should fail. Error code: (Expected:'%d' == Actual:'%d'), Err: '%s'",
				query.c_str(), exp_err_code, m_errno, m_error
			);
		}
	}
}

/**
 * @brief List of the pairs holding a series of queries that should be
 *   successfully performed against ProxySQL SQLite3 server.
 */
std::vector<query_spec> successful_queries {
	std::make_tuple<std::string, int>("SHOW SCHEMAS", 0),
	std::make_tuple<std::string, int>("SHOW DATABASES", 0),
	std::make_tuple<std::string, int>("SELECT DATABASE()", 0),
	std::make_tuple<std::string, int>("SELECT DATABASE() AS name", 0),
	std::make_tuple<std::string, int>("SELECT DATABASE(), USER() LIMIT 1", 0),
	std::make_tuple<std::string, int>("SELECT @@version_comment LIMIT 1", 0),
	std::make_tuple<std::string, int>("SELECT @@version", 0),
	std::make_tuple<std::string, int>("SELECT version()", 0),
	std::make_tuple<std::string, int>(
		"SELECT @@character_set_client, @@character_set_connection,"
		" @@character_set_server, @@character_set_database LIMIT 1",
		0
	),
	std::make_tuple<std::string, int>(
		"CREATE TABLE IF NOT EXISTS test_sqlite3_server_p0712("
			" c1 INTEGER PRIMARY KEY AUTOINCREMENT,"
			" c2 VARCHAR(100),"
			" c3 VARCHAR(100)"
			")",
		0
	),
	std::make_tuple<std::string, int>("SHOW CREATE TABLE test_sqlite3_server_p0712", 0),
	std::make_tuple<std::string, int>("SHOW CREATE TABLE `test_sqlite3_server_p0712`", 0),
	std::make_tuple<std::string, int>("SHOW TABLES", 0),
	std::make_tuple<std::string, int>(
		"INSERT INTO test_sqlite3_server_p0712"
		" (c2, c3) VALUES ('1234', '1234')",
		0
	),
	std::make_tuple<std::string, int>(
		"INSERT INTO test_sqlite3_server_p0712"
		" (c2, c3) VALUES ('123555555', '12355555')",
		0
	),
	std::make_tuple<std::string, int>(
		"DELETE FROM test_sqlite3_server_p0712",
		0
	),
	std::make_tuple<std::string, int>("SHOW TABLES FROM main", 0),
	std::make_tuple<std::string, int>("SHOW TABLES LIKE test_sqlite3_server_p0712", 0),
	std::make_tuple<std::string, int>("SHOW TABLES LIKE 'test_sqlite3_server_p0712'", 0),
	std::make_tuple<std::string, int>("DROP TABLE test_sqlite3_server_p0712", 0),
	std::make_tuple<std::string, int>("SHOW TABLES", 0),
	std::make_tuple<std::string, int>("START TRANSACTION", 0),
	std::make_tuple<std::string, int>("COMMIT", 0),
	std::make_tuple<std::string, int>("BEGIN", 0),
	std::make_tuple<std::string, int>("ROLLBACK", 0),
};

/**
 * @brief List of the pairs holding a series of queries in which *some*
 *   should fail when executed against ProxySQL SQLite3 server.
 */
std::vector<query_spec> unsuccessful_queries {
	std::make_tuple<std::string, int>("SHOW CHEMAS", 1045),
	std::make_tuple<std::string, int>("SHOW DAABASES", 1045),
	std::make_tuple<std::string, int>("PRAGMA synchronous=0", 1045),
	std::make_tuple<std::string, int>("SELECT DAABASE()", 1045),
	std::make_tuple<std::string, int>("SELECT DAABASE(), USER() LIMIT 1", 1045),
	std::make_tuple<std::string, int>("SHOW CREATE TABLE test_sqlite3_server_p0712", 0),
	std::make_tuple<std::string, int>(
		"CREATE TABLE IF NOT EXISTS test_sqlite3_server_p0712("
			" c1 INTEGER PRIMARY KEY AUTOINCREMENT,"
			" c2 VARCHAR(100),"
			" c3 VARCHAR(100)"
			")",
		0
	),
	std::make_tuple<std::string, int>(
		"INSERT INTO test_sqlite3_server_p0712"
		" (c2, c3) VALUES ('1234', '1234')",
		0
	),
	std::make_tuple<std::string, int>(
		"INSERT INTO test_sqlite3_server_p0712"
		" (c1, c2, c3) VALUES (1, '1235', '1235')",
		1045
	),
	std::make_tuple<std::string, int>(
		"USE foobar",
		1045
	),
	std::make_tuple<std::string, int>(
		"DROP TABLE test_sqlite3_server_p0712_non_existent",
		1045
	),
	std::make_tuple<std::string, int>(
		"DROP TABLE test_sqlite3_server_p0712",
		0
	),
};

/**
 * @brief Perform several admin queries to exercise more paths.
 */
std::vector<std::string> admin_queries {
	"LOAD SQLITESERVER VARIABLES FROM DISK",
	"LOAD SQLITESERVER VARIABLES TO RUNTIME",
	"SAVE SQLITESERVER VARIABLES FROM RUNTIME",
	"SAVE SQLITESERVER VARIABLES TO DISK"
};

/**
 * @brief Perform several admin queries to exercise more paths.
 */
std::vector<std::string> sqlite_intf_queries {
	"SET sqliteserver-mysql_ifaces='127.0.0.1:6035'",
	"LOAD SQLITESERVER VARIABLES TO RUNTIME"
};

int main(int argc, char** argv) {
	CommandLine cl;

	// plan as many tests as queries
	plan(
		2 /* Fail to connect with wrong username and password */ + successful_queries.size()
		+ unsuccessful_queries.size() + admin_queries.size() + sqlite_intf_queries.size()
		+ 1 /* Connect to new setup interface */
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
		int host_port_err = extract_module_host_port(proxysql_admin, "sqliteserver-mysql_ifaces", host_port); 
		if (host_port_err) {
			diag("Failed to get and parse 'sqliteserver-mysql_ifaces' at line '%d'", __LINE__);
			goto cleanup;
		}

		MYSQL* proxysql_sqlite3 = mysql_init(NULL);

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
			"An invalid password should fail to connect to SQLite3 server, error was: %s",
			inv_pass_err.c_str()
		);

		// Reinitialize MYSQL handle
		mysql_close(proxysql_sqlite3);
		proxysql_sqlite3 = mysql_init(NULL);

		// Correctly connect to SQLite3 server
		if (
			!mysql_real_connect(
				proxysql_sqlite3, host_port.first.c_str(), cl.username, cl.password,
				NULL, host_port.second, NULL, 0
			)
		) {
			fprintf(
				stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
				mysql_error(proxysql_sqlite3)
			);
			goto cleanup;
		}

		diag("Started performing successful queries");
		execute_and_check_queries(proxysql_sqlite3, successful_queries);

		diag("Started performing failing queries");
		execute_and_check_queries(proxysql_sqlite3, unsuccessful_queries);

		// Reinitialize MYSQL handle
		mysql_close(proxysql_sqlite3);
		proxysql_sqlite3 = mysql_init(NULL);

		// Change SQLite interface and connect to new port
		for (const auto& admin_query : sqlite_intf_queries) {
			int query_err = mysql_query(proxysql_admin, admin_query.c_str());
			ok(
				query_err == 0, "Admin query '%s' should succeed. Line: %d, Err: '%s'",
				admin_query.c_str(), __LINE__, mysql_error(proxysql_admin)
			);
		}

		// NOTE: Wait for ProxySQL to reconfigure, changing SQLite3 interface.
		// Trying to perform a connection immediately after changing the
		// interface could lead to 'EADDRINUSE' in ProxySQL side.
		// UPDATE: Timeout increased to '5' seconds to avoid previously described issue.
		sleep(5);

		// Connect to the new interface
		std::pair<std::string, int> new_host_port {};
		int ext_intf_err = extract_module_host_port(proxysql_admin, "sqliteserver-mysql_ifaces", new_host_port);
		if (ext_intf_err) {
			diag("Failed to get and parse 'sqliteserver-mysql_ifaces' at line '%d'", __LINE__);
			goto cleanup;
		}

		// Connect with invalid username
		bool success_to_connect = true;
		std::string new_intf_conn_err {};
		if (
			!mysql_real_connect(
				proxysql_sqlite3, new_host_port.first.c_str(), cl.username, cl.password,
				NULL, new_host_port.second, NULL, 0
			)
		) {
			new_intf_conn_err = mysql_error(proxysql_sqlite3);
			success_to_connect = false;
		}

		ok(
			success_to_connect,
			"A connection to the new selected interface should success, error was: '%s'",
			new_intf_conn_err.c_str()
		);

		mysql_close(proxysql_sqlite3);

		// Perform the final Admin queries
		for (const auto& admin_query : admin_queries) {
			int query_err = mysql_query(proxysql_admin, admin_query.c_str());
			ok(
				query_err == 0, "Admin query '%s' should succeed. Line: %d, Err: '%s'",
				admin_query.c_str(), __LINE__, mysql_error(proxysql_admin)
			);
		}
	}

cleanup:

	mysql_close(proxysql_admin);

	return exit_status();
}
