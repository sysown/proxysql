/**
 * @file test_clickhouse_server-t.cpp
 * @brief Test to perform multiple operations over ProxySQL Clickhouse server.
 * @details It performs the following operations:
 *  - Connects to clickhouse with a wrong username.
 *  - Connects to clickhouse with a right username but wrong password.
 *  - Successfully connects to clickhouse and runs several queries.
 *      + SHOW SCHEMAS
 *      + SHOW DATABASES
 *      + SELECT DATABASE()
 *  - Successfully connects to clickhouse and runs a variety of queries:
 *      + CREATE TABLE, SHOW CREATE TABLE, INSERT, SELECT, DROP TABLE...
 *      + Queries that induce errors: syntax error, duplicate keys, etc...
 *  - Changes 'clickhouse-mysql_ifaces' and tries to connect to the new interface.
 *  - Connects to ProxySQL Admin and performs the following operations:
 *      + LOAD|SAVE SQLITESERVER TO|FROM RUNTIME|MEMORY|DISK
 *  - This test is also compiled against 'libmysqlclient' resulting in the binary
 *    'test_clickhouse_server_libmysql-t'. This duplicate test exists for testing 'deprecate_eof' support
 *    against ProxySQL ClickHouse server.
 *
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

using query_spec = std::tuple<std::string, int, int>;

const int proxysql_clickhouse_port = 6090;
const int crash_loops = 4;

#include "modules_server_test.h"

int fetch_and_discard_results(MYSQL_RES* result, bool verbose=false);

std::vector<std::pair<std::string,std::string>> credentials = {
	{"cliuser1", "clipass1"},
	{"cliuser2", "clipass2"},
	{"cliuser3", "clipass3"},
	{"cliuser4", "clipass4"}
};

int set_clickhouse_port(MYSQL *pa, int p) {
	std::string query = "SET clickhouse-port=" + std::to_string(p);
	diag("Line: %d . Setting clickhouse-port to %d", __LINE__ , p);
	MYSQL_QUERY(pa, query.c_str()); 
	MYSQL_QUERY(pa, "LOAD CLICKHOUSE VARIABLES TO RUNTIME");
	return 0;
}

int test_crash(const char *host, int port) {
	// try to connect and run queries while there is no backend
	for (int i=0; i<crash_loops; i++) {
		MYSQL * proxysql_clickhouse = mysql_init(NULL);
		diag("Line: %d . Create connection %d in test_cash()", __LINE__ , i);
		// Correctly connect to Clickhouse server
		if (
			!mysql_real_connect(
				proxysql_clickhouse, host, credentials[2].first.c_str(), credentials[2].second.c_str(),
				NULL, port, NULL, 0
			)
		) {
			diag("File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_clickhouse));
			return exit_status();
		}
		char * q = (char *)"SELECT 1";
		int query_err = mysql_query(proxysql_clickhouse, q);
		MYSQL_RES * result = mysql_store_result(proxysql_clickhouse);
		if (result) {
			fetch_and_discard_results(result, false);
			mysql_free_result(result);
		} else {
			diag("Line %d : Query failed: %s . Error: %s", __LINE__, q, mysql_error(proxysql_clickhouse));
		}
		ok(query_err!=0, "Query should fail when the backend is not connected");
		mysql_close(proxysql_clickhouse);
	}
	return 0;
}
int create_users(MYSQL *pa) {
	diag("Emptying clickhouse_users table");
	MYSQL_QUERY(pa, "DELETE FROM clickhouse_users");
	diag("Emptying runtime_clickhouse_users table");
	MYSQL_QUERY(pa, "LOAD CLICKHOUSE USERS TO RUNTIME");
	int query_err;
	MYSQL_RES *result;
	char *q;
	q = (char *)"SELECT * FROM clickhouse_users";
	query_err = mysql_query(pa, q);
	result = mysql_store_result(pa);
	if (result) {
		int j = fetch_and_discard_results(result, true);
		mysql_free_result(result);
		ok(j==0, "Line %d : Rows in clickhouse_users should be 0. Actual: %d" , __LINE__, j);
	} else {
		ok(false,"Line %d : Query failed: %s . Error: %s", __LINE__, q, mysql_error(pa));
		return exit_status();
	}
	q = (char *)"SELECT * FROM runtime_clickhouse_users";
	query_err = mysql_query(pa, q);
	result = mysql_store_result(pa);
	if (result) {
		int j = fetch_and_discard_results(result, true);
		mysql_free_result(result);
		ok(j==0, "Line %d : Rows in clickhouse_users should be 0. Actual: %d" , __LINE__, j);
	} else {
		ok(false,"Line %d : Query failed: %s . Error: %s", __LINE__, q, mysql_error(pa));
		return exit_status();
	}
	for(std::vector<std::pair<std::string,std::string>>::iterator it = credentials.begin(); it!=credentials.end(); it++) {
		std::string query = "INSERT INTO clickhouse_users VALUES ('" + it->first + "', '" + it->second + "', 1, 100)";
		diag("Adding user %s : %s", it->first.c_str(), query.c_str());
		MYSQL_QUERY(pa, query.c_str());
	}
	q = (char *)"SELECT * FROM clickhouse_users";
	query_err = mysql_query(pa, q);
	result = mysql_store_result(pa);
	if (result) {
		int j = fetch_and_discard_results(result, true);
		mysql_free_result(result);
		ok(j==4, "Line %d : Rows in clickhouse_users should be 4. Actual: %d" , __LINE__, j);
	} else {
		ok(false,"Line %d : Query failed: %s . Error: %s", __LINE__, q, mysql_error(pa));
		return exit_status();
	}
	diag("Loading clickhouse_users to runtime");
	MYSQL_QUERY(pa, "LOAD CLICKHOUSE USERS TO RUNTIME");
	q = (char *)"SELECT * FROM runtime_clickhouse_users";
	query_err = mysql_query(pa, q);
	result = mysql_store_result(pa);
	if (result) {
		int j = fetch_and_discard_results(result, true);
		mysql_free_result(result);
		ok(j==4, "Line %d : Rows in clickhouse_users should be 4. Actual: %d" , __LINE__, j);
	} else {
		ok(false,"Line %d : Query failed: %s . Error: %s", __LINE__, q, mysql_error(pa));
		return exit_status();
	}
	return 0;
}

int fetch_and_discard_results(MYSQL_RES* result, bool verbose) {
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
	return j;
}

/**
 * @brief Execute the supplied queries and check that the return codes are the
 *   ones specified.
 *
 * @param proxysql_clickhouse An already opened MYSQL connection to ProxySQL
 *   Clickhouse server.
 * @param queries The queries to be performed and check.
 */
int execute_and_check_queries(MYSQL* proxysql_clickhouse, const std::vector<query_spec>& queries) {
	for (const auto& supp_query : queries) {
		const std::string query = std::get<0>(supp_query);
		const int exp_err_code = std::get<1>(supp_query);
		const int exp_rows = std::get<2>(supp_query); // if >= 0 , it is a select and expects data

		diag("Line: %d . Running query: %s" , __LINE__ , query.c_str());
		int query_err = mysql_query(proxysql_clickhouse, query.c_str());
		MYSQL_RES* result = nullptr;
		// NOTE: For test compatibility with 'libmysqlclient', 'mysql_store_result' should only be called
		// in case no error is present. Otherwise would modify the error itself, thus making test fail.
		if (!query_err) {
			result = mysql_store_result(proxysql_clickhouse);
		}
		if (exp_rows >= 0 && result == NULL) {
			diag ("We were expecting %d rows, but we didn't receive a resultset", exp_rows);
			return exit_status();
		}
		if (exp_rows < 0 && result != NULL) {
			diag ("We were expecting no result, but we received a resultset");
			return exit_status();
		}
		if (result) {
			int j = fetch_and_discard_results(result, true);
			mysql_free_result(result);
			if (j != exp_rows) {
				diag ("We were expecting a result of %d rows, but we received a resultset of %d rows", exp_rows, j);
				return exit_status();	
			}
		}

		int m_errno = mysql_errno(proxysql_clickhouse);
		const char* m_error = mysql_error(proxysql_clickhouse);

		if (exp_err_code == 0) {
			ok(
				exp_err_code == m_errno,
				"Line: %d . Query '%s' should succeed. Error code: (Expected:'%d' == Actual:'%d'), Err: '%s'",
				__LINE__, query.c_str(), exp_err_code, m_errno, m_error
			);
		} else {
			ok(
				exp_err_code == m_errno,
				"Line: %d . Query '%s' should fail. Error code: (Expected:'%d' == Actual:'%d'), Err: '%s'",
				__LINE__, query.c_str(), exp_err_code, m_errno, m_error
			);
		}
	}
	return 0;
}

std::vector<query_spec> queries_set1 {
	std::make_tuple<std::string, int>("SHOW SCHEMAS", 0, 4),
	std::make_tuple<std::string, int>("SHOW DATABASES", 0, 4),
	std::make_tuple<std::string, int>("SELECT DATABASE()", 0, 1),
	std::make_tuple<std::string, int>("SELECT USER()", 0, 1),
	std::make_tuple<std::string, int>("SELECT CURRENT_USER()", 0, 1),
	std::make_tuple<std::string, int>("SELECT VERSION()", 0, 1),
	std::make_tuple<std::string, int>("SELECT CONCAT(version(),'')", 0, 1),
	std::make_tuple<std::string, int>("SELECT 1", 0, 1),
	std::make_tuple<std::string, int>("SELECT 1+1", 0, 1),
	std::make_tuple<std::string, int>("SELECT CONCAT('AAA','BBB')", 0, 1),
	std::make_tuple<std::string, int>("SELECT NULL", 0, 1),
	std::make_tuple<std::string, int>("SELECT NULL AS a", 0, 1),
	std::make_tuple<std::string, int>("SELECT NULL+2 AS a, 'hello', NULL+1, 'world', NULL AS b", 0, 1),
	std::make_tuple<std::string, int>("SELECT CONCAT('AAA',NULL)", 0, 1),
	std::make_tuple<std::string, int>("DROP TABLE IF EXISTS table1", 0, -1),
	std::make_tuple<std::string, int>("CREATE TABLE table1 (CounterID INT, EventDate DATE, col1 INT) ENGINE=MergeTree(EventDate, (CounterID, EventDate), 8192)", 0, -1),
	std::make_tuple<std::string, int>("CREATE TABLE table1 (CounterID INT, EventDate DATE, col1 INT) ENGINE=MergeTree(EventDate, (CounterID, EventDate), 8192)", 1148, -1), // the second time it must fails
	std::make_tuple<std::string, int>("INSERT INTO table1 VALUES (1,NOW(),1)", 1148, -1),
	std::make_tuple<std::string, int>("INSERT INTO table1 SELECT 1,NOW(),1", 0, -1),
	std::make_tuple<std::string, int>("SELECT * FROM table1", 0, 1),
	std::make_tuple<std::string, int>("INSERT INTO table1 SELECT * FROM table1", 0, -1),
	std::make_tuple<std::string, int>("SELECT * FROM table1", 0, 2),
	std::make_tuple<std::string, int>("TRUNCATE TABLE table1", 1148, -1),
	std::make_tuple<std::string, int>("DROP TABLE IF EXISTS table1", 0, -1),
	std::make_tuple<std::string, int>("CREATE TABLE table1 (CounterID INT, EventDate DATE, col1 INT) ENGINE=MergeTree(EventDate, (CounterID, EventDate), 8192)", 0, -1),
	std::make_tuple<std::string, int>("SELECT * FROM table1", 0, 0),
	std::make_tuple<std::string, int>("INSERT INTO table1 SELECT 1,'2022-06-23',1", 0, -1),
	std::make_tuple<std::string, int>("INSERT INTO table1 SELECT 2,'2022-06-23',1", 0, -1),
	std::make_tuple<std::string, int>("INSERT INTO table1 SELECT CounterID+2, '2022-06-23', 1 FROM table1", 0, -1),
	std::make_tuple<std::string, int>("SELECT * FROM table1 ORDER BY CounterID", 0, 4),
	std::make_tuple<std::string, int>("INSERT INTO table1 SELECT * FROM table1", 0, -1),
	std::make_tuple<std::string, int>("INSERT INTO table1 SELECT * FROM table1", 0, -1),
	std::make_tuple<std::string, int>("SELECT CounterID, EventDate, SUM(col1) s FROM table1 GROUP BY CounterID,EventDate ORDER BY CounterID", 0, 4),
	std::make_tuple<std::string, int>("SELECT * FROM table1 t1 JOIN table1 t2 ON t1.CounterID==t2.CounterID ORDER BY t1.CounterID", 0, 64),
	std::make_tuple<std::string, int>("DESC table1", 0, 3),
	std::make_tuple<std::string, int>("SHOW COLUMNS FROM table1", 0, 3),
	std::make_tuple<std::string, int>("LOCK TABLE table1", 0, -1),
	std::make_tuple<std::string, int>("UNLOCK TABLE table1", 0, -1),
};
std::vector<query_spec> queries_set2 {
	std::make_tuple<std::string, int>("DROP TABLE IF EXISTS table2", 0, -1),
	std::make_tuple<std::string, int>("CREATE TABLE table2 (CounterID INT, EventDate DATE, col0 INT, col1 Nullable(INT), col2 Nullable(UInt8), col3 Nullable(UInt16), col4 Nullable(UInt32), col5 Nullable(UInt64), col6 Nullable(Float32), col7 Nullable(Float64), col8 Nullable(Enum8('hello' = 1, 'world' = 2)) , col9 Nullable(Enum16('hello' = 1, 'world' = 2))) ENGINE=MergeTree(EventDate, (CounterID, EventDate), 8192)", 0, -1),
	std::make_tuple<std::string, int>("INSERT INTO table2 SELECT 1,'2022-06-23', 0, 1, 2, 3, 4, 5, 6, 7, 'hello', 'world'", 0, -1),
	std::make_tuple<std::string, int>("INSERT INTO table2 SELECT 1,'2022-06-23', 1, 2, 3, 4, 5, 6, 7, 'hello', 'world'", 1148, -1), // incorrect number of values
	std::make_tuple<std::string, int>("INSERT INTO table2 SELECT 1,'2022-06-23', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL", 1148, -1), // col0 can't be null
	std::make_tuple<std::string, int>("INSERT INTO table2 SELECT 1,'2022-06-23', 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL", 0, -1),
	std::make_tuple<std::string, int>("SELECT * FROM table2 ORDER BY CounterID", 0, 2),
	std::make_tuple<std::string, int>("DESC table2", 0, 12),
	std::make_tuple<std::string, int>("SHOW COLUMNS FROM table2", 0, 12),
};

std::vector<query_spec> queries_set3 {
	std::make_tuple<std::string, int>("SHOW FULL TABLES FROM `default`", 0, 2), // table1 and table2
	std::make_tuple<std::string, int>("SHOW CHARSET", 0, 42),
	std::make_tuple<std::string, int>("SET AUTOCOMMIT=0", 0, -1),
	std::make_tuple<std::string, int>("SET foreign_key_checks=0", 0, -1),
	std::make_tuple<std::string, int>("/*!40101 SET whatever", 0, -1),
	std::make_tuple<std::string, int>("SET NAMES utf8", 0, -1),
	std::make_tuple<std::string, int>("SET WAIT_TIMEOUT=10", 0, -1),
	std::make_tuple<std::string, int>("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED", 0, -1),
	std::make_tuple<std::string, int>("SET SQL_SAFE_UPDATES = OFF", 0, -1),
	std::make_tuple<std::string, int>("SET SQL_AUTO_IS_NULL = OFF", 0, -1),
	std::make_tuple<std::string, int>("SHOW GLOBAL VARIABLES", 0, 6),
	std::make_tuple<std::string, int>("SHOW ALL VARIABLES", 0, 6),
	std::make_tuple<std::string, int>("SHOW GLOBAL STATUS", 0, 6),
	std::make_tuple<std::string, int>("SHOW ENGINES", 0, 1),
	std::make_tuple<std::string, int>("SHOW VARIABLES LIKE 'lower_case_table_names'", 0, 1),
	std::make_tuple<std::string, int>("SELECT * FROM INFORMATION_SCHEMA.COLLATIONS", 0, 375),
	std::make_tuple<std::string, int>("SHOW COLLATION", 0, 375),
	std::make_tuple<std::string, int>("SHOW CHARSET", 0, 42),
	std::make_tuple<std::string, int>("SELECT * FROM INFORMATION_SCHEMA.CHARACTER_SETS", 0, 42),
	std::make_tuple<std::string, int>("SELECT @@collation_server", 0, 1),
	std::make_tuple<std::string, int>("SELECT @@character_set_results", 0, 1),
	std::make_tuple<std::string, int>("SELECT @@have_profiling", 0, 1),
	std::make_tuple<std::string, int>("SELECT @@lower_case_table_names", 0, 1),
	std::make_tuple<std::string, int>("SELECT @@version, @@version_comment", 0, 1),
	std::make_tuple<std::string, int>("SELECT @@storage_engine", 0, 1),
	std::make_tuple<std::string, int>("SELECT `SCHEMA_NAME` FROM `INFORMATION_SCHEMA`.`SCHEMATA`", 0, 4),
	std::make_tuple<std::string, int>("select name, type FROM mysql.proc where db='default'", 0, 0),
	std::make_tuple<std::string, int>("SELECT logfile_group_name FROM information_schema.FILES", 0, 0),
	std::make_tuple<std::string, int>("SELECT tablespace_name FROM information_schema.FILES", 0, 0),
	std::make_tuple<std::string, int>("SELECT CONNECTION_ID()", 0, 1),
	std::make_tuple<std::string, int>("select @@version_comment limit 1", 0, 1),
	std::make_tuple<std::string, int>("select DATABASE(), USER() limit 1", 0, 1),
	std::make_tuple<std::string, int>("select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1", 0, 1),
	std::make_tuple<std::string, int>("SELECT @@version", 0, 1),
	std::make_tuple<std::string, int>("SHOW TABLES FROM default", 0, 2),
	std::make_tuple<std::string, int>("SELECT DATABASE() AS name", 0, 1),
	std::make_tuple<std::string, int>("SHOW MASTER STATUS", 1045, -1),
	std::make_tuple<std::string, int>("SHOW SLAVE STATUS", 1045, -1),
	std::make_tuple<std::string, int>("SHOW MASTER LOGS", 1045, -1),
	std::make_tuple<std::string, int>("LOCK TABLE table1", 0, -1),
	std::make_tuple<std::string, int>("UNLOCK TABLE table1", 0, -1),
};
/**
 * @brief Perform several admin queries to exercise more paths.
 */
std::vector<std::string> admin_queries {
	"LOAD CLICKHOUSE VARIABLES FROM DISK",
	"LOAD CLICKHOUSE VARIABLES TO RUNTIME",
	"SAVE CLICKHOUSE VARIABLES FROM RUNTIME",
	"SAVE CLICKHOUSE VARIABLES TO DISK"
};

/**
 * @brief Perform several admin queries to exercise more paths.
 */
std::vector<std::string> ch_intf_queries {
	"SET clickhouse-mysql_ifaces='127.0.0.1:6091'",
	"LOAD CLICKHOUSE VARIABLES TO RUNTIME"
};

int main(int argc, char** argv) {
	CommandLine cl;

	// plan as many tests as queries
	plan(
		crash_loops
		+ 2 /* Fail to connect with wrong username and password */
		+ 4 // during LOAD USERS TO RUNTIME
		+ 4 // during LOAD USERS TO RUNTIME , second time
		+ queries_set1.size()
		+ queries_set2.size()
		+ queries_set3.size()
		+ admin_queries.size() + ch_intf_queries.size()
		+ 1 /* Connect to new setup interface */
	);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxysql_admin = mysql_init(NULL);

	// Connect to ProxySQL Admin and check current clickhouse configuration
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


	create_users(proxysql_admin);
	create_users(proxysql_admin); // to trigger more code coverage


	{
		std::pair<std::string, int> host_port {};
		int host_port_err = extract_module_host_port(proxysql_admin, "clickhouse-mysql_ifaces", host_port); 
		if (host_port_err) {
			diag("Failed to get and parse 'clickhouse-mysql_ifaces' at line '%d'", __LINE__);
			goto cleanup;
		}

		set_clickhouse_port(proxysql_admin,8000);
		test_crash(host_port.first.c_str(), host_port.second);
		set_clickhouse_port(proxysql_admin,19000);

		MYSQL* proxysql_clickhouse = mysql_init(NULL);

		// Connect with invalid username
		std::string inv_user_err {};
		bool failed_to_connect = false;
		if (
			!mysql_real_connect(
				proxysql_clickhouse, host_port.first.c_str(), "foobar_user", cl.password,
				NULL, host_port.second, NULL, 0
			)
		) {
			inv_user_err = mysql_error(proxysql_clickhouse);
			failed_to_connect = true;
		}

		ok(
			failed_to_connect,
			"An invalid user should fail to connect to Clickhouse server, error was: %s",
			inv_user_err.c_str()
		);

		// Reinitialize MYSQL handle
		mysql_close(proxysql_clickhouse);
		proxysql_clickhouse = mysql_init(NULL);

		// Connect with invalid password
		std::string inv_pass_err {};
		failed_to_connect = false;
		if (
			!mysql_real_connect(
				proxysql_clickhouse, host_port.first.c_str(), credentials[0].first.c_str(), "foobar_pass",
				NULL, host_port.second, NULL, 0
			)
		) {
			inv_pass_err = mysql_error(proxysql_clickhouse);
			failed_to_connect = true;
		}

		ok(
			failed_to_connect,
			"An invalid pass should fail to connect to Clickhouse server, error was: %s",
			inv_pass_err.c_str()
		);

		// Reinitialize MYSQL handle
		mysql_close(proxysql_clickhouse);
		proxysql_clickhouse = mysql_init(NULL);

		// Correctly connect to Clickhouse server
		if (
			!mysql_real_connect(
				proxysql_clickhouse, host_port.first.c_str(), credentials[0].first.c_str(), credentials[0].second.c_str(),
				NULL, host_port.second, NULL, 0
			)
		) {
			fprintf(
				stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
				mysql_error(proxysql_clickhouse)
			);
			goto cleanup;
		}

		diag("Started performing queries set 1");
		if (execute_and_check_queries(proxysql_clickhouse, queries_set1)) {
			return exit_status();
		}

		diag("Started performing queries set 2");
		if (execute_and_check_queries(proxysql_clickhouse, queries_set2)) {
			return exit_status();
		}

		diag("Started performing queries set 3");
		if (execute_and_check_queries(proxysql_clickhouse, queries_set3)) {
			return exit_status();
		}

		// Reinitialize MYSQL handle
		mysql_close(proxysql_clickhouse);
		proxysql_clickhouse = mysql_init(NULL);

		// Change Clickhouse interface and connect to new port
		for (const auto& admin_query : ch_intf_queries) {
			int query_err = mysql_query(proxysql_admin, admin_query.c_str());
			ok(
				query_err == 0, "Admin query '%s' should succeed. Line: %d, Err: '%s'",
				admin_query.c_str(), __LINE__, mysql_error(proxysql_admin)
			);
		}
		// NOTE: Wait for ProxySQL to reconfigure, changing Clickhous interface.
		// Trying to perform a connection immediately after changing the
		// interface could lead to 'EADDRINUSE' in ProxySQL side.
		// UPDATE: Timeout increased to '5' seconds to avoid previously described issue.
		sleep(5);

		// Connect to the new interface
		std::pair<std::string, int> new_host_port {};
		int ext_intf_err = extract_module_host_port(proxysql_admin, "clickhouse-mysql_ifaces", new_host_port);
		if (ext_intf_err) {
			diag("Failed to get and parse 'clickhouse-mysql_ifaces' at line '%d'", __LINE__);
			goto cleanup;
		}

		// Connect with invalid username
		bool success_to_connect = true;
		std::string new_intf_conn_err {};
		if (
			!mysql_real_connect(
				proxysql_clickhouse, new_host_port.first.c_str(), credentials[1].first.c_str(), credentials[1].second.c_str(),
				NULL, new_host_port.second, NULL, 0
			)
		) {
			new_intf_conn_err = mysql_error(proxysql_clickhouse);
			success_to_connect = false;
		}

		ok(
			success_to_connect,
			"A connection to the new selected interface should success, error was: '%s'",
			new_intf_conn_err.c_str()
		);

		mysql_close(proxysql_clickhouse);

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
