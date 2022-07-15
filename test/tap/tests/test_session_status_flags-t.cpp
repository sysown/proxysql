/**
 * @file test_session_status_flags-t.cpp
 * @brief Test file for testing the different operations that modify the 'status_flags' in a MySQL_Session.
 */

#include <stdio.h>
#include <mysql.h>
#include <mysqld_error.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include "json.hpp"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

using nlohmann::json;

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

// This test was previously failing due to replication not catching up quickly enough when doing
// some table creation operations. This variable controls the waiting timeout after these
// create operations are performed. See #3282 for context.
constexpr const int replication_timeout = 10;

int main(int argc, char *argv[]) {
	CommandLine cl;

	if(cl.getEnv()) {
		return exit_status();
	}

	plan(23);

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Set a replication lag inferior to default one (60). This is to prevent reads
	// from a replica in which replication is currently disabled.
	MYSQL_QUERY(proxysql_admin, "UPDATE mysql_servers SET max_replication_lag=20");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Wait for ProxySQL to detect replication issues
	//sleep(10);

	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		// Check that transaction state is reflected when actively in a transaction
		const std::vector<std::string> transaction_queries { "START TRANSACTION", "SELECT 1", "PROXYSQL INTERNAL SESSION", "COMMIT" };
		json j_status;

		for (const auto& query : transaction_queries) {
			MYSQL_QUERY(proxysql_mysql, query.c_str());
			MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
			if (query == "PROXYSQL INTERNAL SESSION") {
				parse_result_json_column(tr_res, j_status);
			}
			mysql_free_result(tr_res);
		}

		if (j_status.contains("backends")) {
			bool found_backend = false;
			for (auto& backend : j_status["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					int32_t server_status = backend["conn"]["mysql"]["server_status"];
					ok(server_status & 0x01, "Connection status should reflect being in a transaction");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		mysql_close(proxysql_mysql);
	}

	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, CLIENT_COMPRESS)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		// Check that state reflects when in a compressed connection
		const std::string internal_session_query { "PROXYSQL INTERNAL SESSION" };
		json j_status;

		MYSQL_QUERY(proxysql_mysql, internal_session_query.c_str());
		MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
		parse_result_json_column(tr_res, j_status);
		mysql_free_result(tr_res);

		bool compression_enabled = j_status["conn"]["status"]["compression"];
		ok(compression_enabled == true, "Connection status should reflect being in a compressed connection");

		mysql_close(proxysql_mysql);
	}

	// USER VARIABLE
	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		// Check that state reflects when in a compressed connection
		const std::vector<std::string> user_variable_queries { "SET @test_variable = 43", "PROXYSQL INTERNAL SESSION" };
		json j_status;

		for (const auto& query : user_variable_queries) {
			MYSQL_QUERY(proxysql_mysql, query.c_str());
			MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
			if (query == "PROXYSQL INTERNAL SESSION") {
				parse_result_json_column(tr_res, j_status);
			}
			mysql_free_result(tr_res);
		}

		if (j_status.contains("backends")) {
			bool found_backend = false;
			for (auto& backend : j_status["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					int32_t user_variable_status = backend["conn"]["status"]["user_variable"];
					ok(user_variable_status == true, "Connection status should reflect that a 'user_variable' have been set.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		mysql_close(proxysql_mysql);
	}

	// PREPARED STATEMENT
	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		const std::vector<std::string> prepared_stmt_queries { "PREPARE stmt_test FROM 'SELECT 1'", "PROXYSQL INTERNAL SESSION" };
		json j_status;

		for (const auto& query : prepared_stmt_queries) {
			MYSQL_QUERY(proxysql_mysql, query.c_str());
			MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
			if (query == "PROXYSQL INTERNAL SESSION") {
				parse_result_json_column(tr_res, j_status);
			}
			mysql_free_result(tr_res);
		}

		if (j_status.contains("backends")) {
			bool found_backend = false;
			for (auto& backend : j_status["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					bool prepared_stmt = backend["conn"]["status"]["prepared_statement"];
					ok(prepared_stmt == true, "Connection status should reflect that a 'prepared statement' have been prepared.");

					bool multiplex_disabled = backend["conn"]["MultiplexDisabled"];
					ok(multiplex_disabled == true, "Connection status should reflect that 'MultiplexDisabled' is enabled due to the 'prepared statement'.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		mysql_close(proxysql_mysql);
	}

	// STATUS_MYSQL_CONNECTION_LOCK_TABLES
	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		const char* create_test_table =
			"CREATE TABLE IF NOT EXISTS sysbench.test_session_var ("
			"  c1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
			"  c2 VARCHAR(100),"
			"  c3 VARCHAR(100)"
			")";
		const std::vector<std::string> prepared_stmt_queries {
			create_test_table,
			"LOCK TABLES sysbench.test_session_var READ",
			"PROXYSQL INTERNAL SESSION",
			// Set a variable so we make sure connection is not dropped after "UNLOCK TABLES"
			"SET @test_variable = 43",
			"UNLOCK TABLES",
			"PROXYSQL INTERNAL SESSION",
			"DROP TABLE sysbench.test_session_var"
		};

		std::vector<json> vj_status;

		for (const auto& query : prepared_stmt_queries) {
			json j_status;
			MYSQL_QUERY(proxysql_mysql, query.c_str());
			MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
			if (query == "PROXYSQL INTERNAL SESSION") {
				parse_result_json_column(tr_res, j_status);
				vj_status.push_back(j_status);
			}
			mysql_free_result(tr_res);
		}

		if (vj_status[0].contains("backends")) {
			bool found_backend = false;
			for (const auto& backend : vj_status[0]["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					bool lock_tables = backend["conn"]["status"]["lock_tables"];
					ok(lock_tables == true, "Connection status should reflect that 'LOCK TABLE' have been executed.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		if (vj_status[1].contains("backends")) {
			bool found_backend = false;
			for (const auto& backend : vj_status[1]["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					bool unlock_tables = backend["conn"]["status"]["lock_tables"];
					ok(unlock_tables == false, "Connection status should reflect that 'UNLOCK TABLE' have been executed.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		mysql_close(proxysql_mysql);
	}

	// STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE
	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		const char* create_test_table =
			"CREATE TEMPORARY TABLE IF NOT EXISTS sysbench.test_temp_table_session_var ("
			"  c1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
			"  c2 VARCHAR(100),"
			"  c3 VARCHAR(100)"
			")";
		const std::vector<std::string> prepared_stmt_queries {
			create_test_table,
			"PROXYSQL INTERNAL SESSION",
			"DROP TABLE sysbench.test_temp_table_session_var"
		};
		json j_status;

		for (const auto& query : prepared_stmt_queries) {
			MYSQL_QUERY(proxysql_mysql, query.c_str());
			MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
			if (query == "PROXYSQL INTERNAL SESSION") {
				parse_result_json_column(tr_res, j_status);
			}
			mysql_free_result(tr_res);
		}

		if (j_status.contains("backends")) {
			bool found_backend = false;
			for (const auto& backend : j_status["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					bool temp_table = backend["conn"]["status"]["temporary_table"];
					ok(temp_table == true, "Connection status should reflect that a 'CREATE TEMPORARY TABLE' have been executed.");

					bool multiplex_disabled = backend["conn"]["MultiplexDisabled"];
					ok(multiplex_disabled == true, "Connection status should reflect that 'MultiplexDisabled' is enabled due to 'CREATE TEMPORARY TABLE'.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		mysql_close(proxysql_mysql);
	}

	// STATUS_MYSQL_CONNECTION_GET_LOCK
	// TODO: Check why when GET_LOCK is executed the first backend is "NULL", and not filled like in the rest
	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		const std::vector<std::string> prepared_stmt_queries {
			"SELECT 1",
			"SELECT GET_LOCK('test_session_vars_lock', 2)",
			"PROXYSQL INTERNAL SESSION",
			"SELECT RELEASE_LOCK('test_session_vars_lock')"
		};
		json j_status;

		for (const auto& query : prepared_stmt_queries) {
			MYSQL_QUERY(proxysql_mysql, query.c_str());
			MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
			if (query == "PROXYSQL INTERNAL SESSION") {
				parse_result_json_column(tr_res, j_status);
			}
			mysql_free_result(tr_res);
		}

		if (j_status.contains("backends")) {
			bool found_backend = false;
			for (auto& backend : j_status["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					bool lock_tables = backend["conn"]["status"]["get_lock"];
					ok(lock_tables == true, "Connection status should reflect that a 'GET_LOCK' have been executed.");

					bool multiplex_disabled = backend["conn"]["MultiplexDisabled"];
					ok(multiplex_disabled == true, "Connection status should reflect that 'MultiplexDisabled' is enabled due to 'GET_LOCK'.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		mysql_close(proxysql_mysql);
	}

	// STATUS_MYSQL_CONNECTION_NO_MULTIPLEX - SET VARIABLE
	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		const std::vector<std::string> prepared_stmt_queries {
			"SET @test_variable = 44",
			"PROXYSQL INTERNAL SESSION",
		};
		json j_status;

		for (const auto& query : prepared_stmt_queries) {
			MYSQL_QUERY(proxysql_mysql, query.c_str());
			MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
			if (query == "PROXYSQL INTERNAL SESSION") {
				parse_result_json_column(tr_res, j_status);
			}
			mysql_free_result(tr_res);
		}

		if (j_status.contains("backends")) {
			bool found_backend = false;
			for (const auto& backend : j_status["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					bool user_variable = backend["conn"]["status"]["user_variable"];
					ok(user_variable == true, "Connection status should have 'status.user_variable' set due to 'SET @variable'.");

					bool no_multiplex = backend["conn"]["status"]["no_multiplex"];
					ok(no_multiplex == true, "Connection status should have 'no_multiplex' set due to 'SET @variable'.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		mysql_close(proxysql_mysql);
	}

	// STATUS_MYSQL_CONNECTION_NO_MULTIPLEX - TRANSACTION SHOULD NOT REPORT DISABLED MULTIPLEXING

	// Transaction detection is done through server status, while the MULTIPLEXING will be disabled for the connection and
	// the connection wont be returned to the connection pool, both of the metrics 'MultiplexDisabled' and 'status.no_multiplex'
	// will report 'false'.
	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		const std::vector<std::string> transaction_queries { "START TRANSACTION", "SELECT 1", "PROXYSQL INTERNAL SESSION", "COMMIT" };
		json j_status;

		for (const auto& query : transaction_queries) {
			MYSQL_QUERY(proxysql_mysql, query.c_str());
			MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
			if (query == "PROXYSQL INTERNAL SESSION") {
				parse_result_json_column(tr_res, j_status);
			}
			mysql_free_result(tr_res);
		}

		if (j_status.contains("backends")) {
			bool found_backend = false;
			for (const auto& backend : j_status["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					bool MultiplexDisabled = backend["conn"]["MultiplexDisabled"];
					ok(MultiplexDisabled == false, "Connection status should have 'MultiplexDisabled' set to false even with 'START TRANSACTION'.");

					bool no_multiplex = backend["conn"]["status"]["no_multiplex"];
					ok(no_multiplex == false, "Connection status should have 'no_multiplex' set to false even with 'START TRANSACTION'.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		mysql_close(proxysql_mysql);
	}

	// STATUS_MYSQL_CONNECTION_NO_MULTIPLEX - Multiplex disabled due to STATUS_MYSQL_CONNECTION_LOCK_TABLES
	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		const char* create_test_table =
			"CREATE TABLE IF NOT EXISTS sysbench.test_session_var ("
			"  c1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
			"  c2 VARCHAR(100),"
			"  c3 VARCHAR(100)"
			")";

		const std::vector<std::string> lock_tables_queries {
			create_test_table,
			"LOCK TABLES sysbench.test_session_var READ",
			"PROXYSQL INTERNAL SESSION",
			"UNLOCK TABLES",
			"PROXYSQL INTERNAL SESSION",
			"DROP TABLE sysbench.test_session_var"
		};

		std::vector<json> vj_status;

		for (const auto& query : lock_tables_queries) {
			json j_status;

			// we are trying to lock new created table 'sysbench.test_session_var'
			if (query == lock_tables_queries[1]) {
				int timeout = 0;
				int query_err = 0;
				int query_errno = 0;

				diag("Executing the locking table query with retrying due to replication lag.");

				while (timeout < replication_timeout) {
					query_err = mysql_query(proxysql_mysql, query.c_str());
					if (query_err) {
						query_errno = mysql_errno(proxysql_mysql);
						if (query_errno != ER_NO_SUCH_TABLE) {
							break;
						} else {
							sleep(1);
						}
					} else {
						break;
					}
					timeout++;
				}

				if (query_err) {
					fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
					return -1;
				} else {
					diag("Replication lag took '%d.'", timeout);
				}
			} else {
				MYSQL_QUERY(proxysql_mysql, query.c_str());
				MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
				if (query == "PROXYSQL INTERNAL SESSION") {
					parse_result_json_column(tr_res, j_status);
					vj_status.push_back(j_status);
				}
				mysql_free_result(tr_res);
			}
		}

		if (vj_status[0].contains("backends")) {
			bool found_backend = false;
			for (const auto& backend : vj_status[0]["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					bool MultiplexDisabled = backend["conn"]["MultiplexDisabled"];
					ok(MultiplexDisabled == true, "Connection status should have 'MultiplexDisabled' set to 'true' 'DUE TO 'LOCK TABLES'.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		if (vj_status[1].contains("backends")) {
			bool found_backend = false;
			for (const auto& backend : vj_status[1]["backends"]) {
				if (backend != nullptr) {
					found_backend = true;
					ok(backend.contains("conn") == false, "Connection should be returned to the connection pool due to 'UNLOCK TABLES'.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		mysql_close(proxysql_mysql);
	}

	// STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0 - Multiplex disabled due to STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0
	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		const std::vector<std::string> sql_log_bin_queries {
			"SET SQL_LOG_BIN=0",
			"SELECT 1",
			"PROXYSQL INTERNAL SESSION"
		};

		json j_status;

		for (const auto& query : sql_log_bin_queries) {
			MYSQL_QUERY(proxysql_mysql, query.c_str());
			MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
			if (query == "PROXYSQL INTERNAL SESSION") {
				parse_result_json_column(tr_res, j_status);
			}
			mysql_free_result(tr_res);
		}

		if (j_status.contains("backends")) {
			bool found_backend = false;
			for (const auto& backend : j_status["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					bool MultiplexDisabled = backend["conn"]["MultiplexDisabled"];
					ok(MultiplexDisabled == true, "Connection status should have 'MultiplexDisabled' set to 'true' 'DUE TO 'SET SQL_LOG_BIN'.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		mysql_close(proxysql_mysql);
	}

	// STATUS_MYSQL_CONNECTION_FOUND_ROWS - Multiplex disabled due to STATUS_MYSQL_CONNECTION_FOUND_ROWS
	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		const char* create_test_table =
			"CREATE TABLE IF NOT EXISTS sysbench.test_session_var ("
			"  c1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
			"  c2 VARCHAR(100),"
			"  c3 VARCHAR(100)"
			")";

		const std::vector<std::string> found_rows {
			create_test_table,
			"SELECT SQL_CALC_FOUND_ROWS * from sysbench.test_session_var",
			"SELECT FOUND_ROWS()",
			"PROXYSQL INTERNAL SESSION"
		};

		json j_status;

		for (const auto& query : found_rows) {
			// we are trying to 'SELECT' over new created table 'sysbench.test_session_var'
			if (query == found_rows[1]) {
				int timeout = 0;
				int query_err = 0;
				int query_errno = 0;

				diag("Executing 'SELECT' with retrying due to replication lag.");

				while (timeout < replication_timeout) {
					query_err = mysql_query(proxysql_mysql, query.c_str());
					if (query_err) {
						query_errno = mysql_errno(proxysql_mysql);
						if (query_errno != ER_NO_SUCH_TABLE) {
							break;
						} else {
							sleep(1);
						}
					} else {
						// free select results
						MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
						mysql_free_result(tr_res);
						break;
					}
					timeout++;
				}

				if (query_err) {
					fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
					return -1;
				} else {
					diag("Replication lag took '%d.'", timeout);
				}
			} else {
				MYSQL_QUERY(proxysql_mysql, query.c_str());
				MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
				if (query == "PROXYSQL INTERNAL SESSION") {
					parse_result_json_column(tr_res, j_status);
				}
				mysql_free_result(tr_res);
			}
		}

		if (j_status.contains("backends")) {
			bool found_backend = false;
			for (const auto& backend : j_status["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					bool found_rows = backend["conn"]["status"]["found_rows"];
					ok(found_rows == true, "Connection status should have 'status.found_rows' set to 'true' 'DUE TO 'SQL_CALC_FOUND_ROWS'.");

					bool MultiplexDisabled = backend["conn"]["MultiplexDisabled"];
					ok(MultiplexDisabled == true, "Connection status should have 'MultiplexDisabled' set to 'true' 'DUE TO 'SQL_CALC_FOUND_ROWS'.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		mysql_close(proxysql_mysql);
	}

	// STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT - Multiplex disabled due to STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT
	{
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return -1;
		}

		const std::vector<std::string> savepoint_queries {
			"SET AUTOCOMMIT=0",
			"SELECT * FROM test.test_savepoint LIMIT 1 FOR UPDATE",
			"SAVEPOINT test_session_variables_savepoint",
			"PROXYSQL INTERNAL SESSION",
			"COMMIT",
			"PROXYSQL INTERNAL SESSION"
		};

		std::vector<json> vj_status;

		for (const auto& query : savepoint_queries) {
			json j_status;
			MYSQL_QUERY(proxysql_mysql, query.c_str());
			MYSQL_RES* tr_res = mysql_store_result(proxysql_mysql);
			if (query == "PROXYSQL INTERNAL SESSION") {
				parse_result_json_column(tr_res, j_status);
				vj_status.push_back(j_status);
			}
			mysql_free_result(tr_res);
		}

		if (vj_status[0].contains("backends")) {
			bool found_backend = false;
			for (const auto& backend : vj_status[0]["backends"]) {
				if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
					found_backend = true;
					bool found_rows = backend["conn"]["status"]["has_savepoint"];
					ok(found_rows == true, "Connection status should have 'status.has_savepoint' set to 'true' 'DUE TO 'SAVEPOINT'.");

					bool MultiplexDisabled = backend["conn"]["MultiplexDisabled"];
					ok(MultiplexDisabled == true, "Connection status should have 'MultiplexDisabled' set to 'true' 'DUE TO 'SAVEPOINT'.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}

		if (vj_status[1].contains("backends")) {
			bool found_backend = false;
			for (const auto& backend : vj_status[1]["backends"]) {
				if (backend != nullptr) {
					found_backend = true;
					ok(backend.contains("conn") == false, "Connection should be returned to the connection pool due to 'COMMIT'.");
				}
			}
			if (found_backend == false) {
				ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
			}
		} else {
			ok(false, "No backends detected for the current connection.");
		}
		mysql_close(proxysql_mysql);
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
