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
 *
 *  NOTE: For manually checking that the test is resilient to port change collisions, the script
 *  'test_sqlite3_server.sh' can be used. Check the file itself for a more detailed description.
 */

#include <cstring>
#include <fstream>
#include <vector>
#include <tuple>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::fstream;
using std::string;
using std::pair;
using std::vector;

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
	"SET sqliteserver-mysql_ifaces='127.0.0.1:6036'",
	"LOAD SQLITESERVER VARIABLES TO RUNTIME"
};

int check_errorlog_for_addrinuse(MYSQL* admin, fstream& logfile) {
	const string command_regex { ".*\\[INFO\\] Received LOAD SQLITESERVER VARIABLES (FROM DISK|TO RUNTIME) command" };
	std::vector<line_match_t> cmd_lines { get_matching_lines(logfile, command_regex) };

	// NOTE: Delay for poll_timeout for SQLite3_Server - harcoded 500ms
	usleep(1000 * 1000);

	const string bind_err_regex { ".*\\[ERROR\\] bind\\(\\): Address already in use" };
	std::vector<line_match_t> err_lines { get_matching_lines(logfile, bind_err_regex) };

	if (cmd_lines.empty()) {
		diag("ERROR: Commands 'LOAD SQLITESERVER' not logged as expected");
		return -1;
	}

	if (err_lines.empty() == false) {
		const string& fst_errline { std::get<LINE_MATCH_T::LINE>(err_lines.front()) };
		diag("Error line detected in logfile: `%s`", fst_errline.c_str());

		return 1;
	} else {
		return 0;
	}
}

string connect_with_retries(MYSQL* sqlite3, const CommandLine& cl, const pair<string,int>& host_port) {
	uint32_t n = 0;
	uint32_t retries = 10;
	bool conn_success = false;

	const char* host { host_port.first.c_str() };
	const int port { host_port.second };
	string conn_err {};

	diag("Attempting connection to new interface on (%s,%d)", host, port);

	while (n < retries) {
		MYSQL* sqlite3 = mysql_init(NULL);
		conn_err.clear();

		if (!mysql_real_connect(sqlite3, host, cl.username, cl.password, NULL, port, NULL, 0)) {
			conn_err = mysql_error(sqlite3);
		}
		mysql_close(sqlite3);

		if (conn_err.empty() == false) {
			diag("Connection attempt '%d 'to the new interface failed with error `%s`. Retring...", n, conn_err.c_str());
			usleep(500 * 1000);
			n += 1;
		} else {
			break;
		}
	}

	return conn_err;
}

int enforce_sqlite_iface_change(MYSQL*admin, fstream& logfile, const uint32_t retries = 10) {
	std::pair<string,int> host_port {};
	if (extract_sqlite3_host_port(admin, host_port)) {
		return -1;
	}

	int logcheck_err = check_errorlog_for_addrinuse(admin, logfile);
	if (logcheck_err == -1) {
		return logcheck_err;
	}

	uint32_t n = 0;
	while (logcheck_err == 1 && n < retries) {
		const string old_sqlite3_port { std::to_string(host_port.second) };
		const string new_sqlite3_port { std::to_string(host_port.second + 5) };

		MYSQL_QUERY_T(admin, ("SET sqliteserver-mysql_ifaces='127.0.0.1:" + new_sqlite3_port + "'").c_str());
		MYSQL_QUERY_T(admin, "LOAD SQLITESERVER VARIABLES TO RUNTIME");

		usleep(100 * 1000);

		MYSQL_QUERY_T(admin, ("SET sqliteserver-mysql_ifaces='127.0.0.1:" + old_sqlite3_port + "'").c_str());
		MYSQL_QUERY_T(admin, "LOAD SQLITESERVER VARIABLES TO RUNTIME");

		logcheck_err = check_errorlog_for_addrinuse(admin, logfile);

		if (logcheck_err == EXIT_SUCCESS) {
			break;
		} else {
			n += 1;
		}
	}

	return logcheck_err;
}

int main(int argc, char** argv) {
	CommandLine cl;

	// plan as many tests as queries
	plan(
		2 /* Fail to connect with wrong username and password */ + successful_queries.size()
		+ unsuccessful_queries.size() + admin_queries.size() + sqlite_intf_queries.size()
		+ 2 /* Check port is properly taken by ProxySQL without error after each change */
		+ 2 /* Connect to new/old interfaces when changed */
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

		const string f_path { get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };
		fstream errlog {};

		int of_err = open_file_and_seek_end(f_path, errlog);
		if (of_err) {
			diag("Failed to open ProxySQL log file. Aborting further testing...");
			goto cleanup;
		}

		// Change SQLite interface and connect to new port
		for (const auto& admin_query : sqlite_intf_queries) {
			int query_err = mysql_query(proxysql_admin, admin_query.c_str());
			ok(query_err == 0, "Query should be executed successfully '%s'", admin_query.c_str());
		}

		int iface_err = enforce_sqlite_iface_change(proxysql_admin, errlog);
		ok(iface_err == 0, "SQLite3 iface should change without error being reported.");

		// Connect to the new interface
		std::pair<std::string, int> new_host_port {};
		int ext_intf_err = extract_module_host_port(proxysql_admin, "sqliteserver-mysql_ifaces", new_host_port);
		if (ext_intf_err) {
			diag("Failed to get and parse 'sqliteserver-mysql_ifaces' at line '%d'", __LINE__);
			goto cleanup;
		}

		std::string new_intf_conn_err { connect_with_retries(proxysql_sqlite3, cl, new_host_port) };

		ok(
			new_intf_conn_err.empty() == true,
			"A connection to the new interface should success, error was: '%s'",
			new_intf_conn_err.c_str()
		);

		// Seek current end-of-file
		errlog.seekg(0, std::ios::end);

		// Perform the final Admin queries
		for (const auto& admin_query : admin_queries) {
			int query_err = mysql_query(proxysql_admin, admin_query.c_str());
			ok(query_err == 0, "Query should be executed successfully '%s'", admin_query.c_str());
		}

		iface_err = enforce_sqlite_iface_change(proxysql_admin, errlog, 20);
		ok(iface_err == 0, "SQLite3 iface should change without error being reported.");

		std::string old_intf_conn_err {};

		// NOTE: If the interface change has failed after the previously specified retries, we assume the
		// interface could be locked somehow by ProxySQL, and we avoid trying to stablish a connection that
		// could stall the test. Instead we intentionally fail.
		if (iface_err == 0) {
			old_intf_conn_err = connect_with_retries(proxysql_sqlite3, cl, host_port);
		} else {
			old_intf_conn_err = "Interface failed to be changed. Skipping connection attempt...";
		}

		ok(
			old_intf_conn_err.empty() == true,
			"A connection to the old interface should success, error was: '%s'",
			old_intf_conn_err.c_str()
		);
	}

cleanup:

	mysql_close(proxysql_admin);

	return exit_status();
}
