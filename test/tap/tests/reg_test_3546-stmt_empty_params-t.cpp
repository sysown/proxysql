/**
 * @file reg_test_3546-stmt_empty_params-t.cpp
 * @brief This test is a regression test for exercising the code path that lead
 *   to issue #3546. It's not meant to test a specific feature, but to server as
 *   a regression test that should flag the issue under a memory analyzer.
 * @details Memory corruption related to #3546 was double-free provoqued when a
 *   prepared statement with param of types ['MYSQL_TYPE_DATE'|'MYSQL_TYPE_TIMESTAMP'|'MYSQL_TYPE_DATETIME'|'MYSQL_TYPE_TIME'],
 *   was prepared and a later prepared  with 'NULL' parameters. Because the memory
 *   for the buffered was not zeroed neither at initialization or during the later
 *   `free` a corruption takes place during the second execution.
 */

#include <iostream>
#include <chrono>
#include <ctime>
#include <cstring>
#include <unistd.h>
#include <time.h>
#include <vector>
#include <string>
#include <stdio.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "errno.h"

/**
 * @brief String size of the columns created for the testing table.
 */
const int STRING_SIZE=32;
/**
 * @brief Number of iterations to perform.
 */
const uint32_t ITERATIONS = 100;
/**
 * @brief Id for the current writer hostgroup.
 */
const uint32_t WRITER_HOSTGROUP_ID = 0;

int prepare_stmt(
	MYSQL* proxysql_mysql, MYSQL_STMT* stmt, MYSQL_TIME* ts, my_bool* is_null
) {
	int res = EXIT_SUCCESS;
	std::string query {
		"SELECT /* ;hostgroup=0 */ id,c1,c2 FROM test.reg_test_3546 WHERE date IN (?)"
	};

	if (mysql_stmt_prepare(stmt, query.c_str(), strlen(query.c_str()))) {
		diag("mysql_stmt_prepare at line %d failed: %s", __LINE__ , mysql_error(proxysql_mysql));
		mysql_close(proxysql_mysql);
		res = EXIT_FAILURE;
		goto exit;
	}

	MYSQL_BIND bind_params;

	memset(&bind_params, 0, sizeof(MYSQL_BIND));
	bind_params.buffer_type= MYSQL_TYPE_DATE;
	bind_params.buffer= ts;
	bind_params.is_null= is_null;
	bind_params.length= 0;

	if (mysql_stmt_bind_param(stmt, &bind_params)) {
		diag(
			"mysql_stmt_bind_result at line %d failed: %s", __LINE__ ,
			mysql_stmt_error(stmt)
		);
		res = EXIT_FAILURE;
		goto exit;
	}

exit:
	return res;
}

int main(int argc, char** argv) {

	CommandLine cl;

	plan(ITERATIONS);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* proxysql_mysql = mysql_init(NULL);
	MYSQL* proxysql_admin = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Insert the row to be queried with the prepared statement.
	// *************************************************************************
	MYSQL_QUERY(proxysql_mysql, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(proxysql_mysql, "DROP TABLE IF EXISTS test.reg_test_3546");
	MYSQL_QUERY(
		proxysql_mysql,
		"CREATE TABLE IF NOT EXISTS test.reg_test_3546"
		" (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, `c1` BIGINT, `c2` varchar(32), `date` DATE)"
	);
	MYSQL_QUERY(proxysql_mysql, "INSERT INTO test.reg_test_3546(c1, c2, date) VALUES (100, 'abcde', '2009-01-01')");
	mysql_close(proxysql_mysql);

	// *************************************************************************

	// Initialize the connection again
	proxysql_mysql = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}

	{
		MYSQL_STMT* stmt_param = nullptr;
		stmt_param = mysql_stmt_init(proxysql_mysql);
		if (!stmt_param) {
			diag("mysql_stmt_init(), out of memory");
			goto exit;
		}

		// Set the number of maximum connections for servers in the writer hostgroup
		std::string t_update_mysql_servers {
			"UPDATE mysql_servers SET max_connections=1 WHERE hostgroup_id=%d"
		};
		std::string update_mysql_queries {};
		string_format(t_update_mysql_servers, update_mysql_queries, WRITER_HOSTGROUP_ID);
		MYSQL_QUERY(proxysql_admin, update_mysql_queries.c_str());
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		MYSQL_TIME ts;
		char data_param[STRING_SIZE] = {};
		my_bool is_null = 0;

		if (prepare_stmt(proxysql_mysql, stmt_param, &ts, &is_null)) {
			diag("'prepare_stmt' at line %d failed", __LINE__);
			goto exit;
		}

		// Prepare parameters
		ts.year = 2009;
		ts.month = 1;
		ts.day = 1;

		for (uint32_t i = 0; i < ITERATIONS; i++) {
			if (i % 2) {
				is_null = 0;
			} else {
				is_null = 1;
			}

			if (mysql_stmt_execute(stmt_param)) {
				diag(
					"'mysql_stmt_execute' at line %d failed: %s", __LINE__ ,
					mysql_stmt_error(stmt_param)
				);
				goto exit;
			}

			MYSQL_BIND bind[3];
			memset(bind, 0, sizeof(bind));

			int data_id = 0;
			int64_t data_c1 = 0;
			char data_c2[STRING_SIZE] { 0 };
			char is_null[3] { 0 };
			long unsigned int length[3] { 0 };
			char error[3] { 0 };

			bind[0].buffer_type = MYSQL_TYPE_LONG;
			bind[0].buffer = (char *)&data_id;
			bind[0].buffer_length = sizeof(int);
			bind[0].is_null = &is_null[0];
			bind[0].length = &length[0];

			bind[1].buffer_type = MYSQL_TYPE_LONGLONG;
			bind[1].buffer = (char *)&data_c1;
			bind[1].buffer_length = sizeof(int64_t);
			bind[1].is_null = &is_null[1];
			bind[1].length = &length[1];

			bind[2].buffer_type = MYSQL_TYPE_STRING;
			bind[2].buffer = (char *)&data_c2;
			bind[2].buffer_length = STRING_SIZE;
			bind[2].is_null = &is_null[2];
			bind[2].length = &length[2];
			bind[2].error = &error[2];

			if (mysql_stmt_bind_result(stmt_param, bind)) {
				diag(
					"mysql_stmt_bind_result at line %d failed: %s", __LINE__,
					mysql_stmt_error(stmt_param)
				);
				goto exit;
			}

			int fetch_result = mysql_stmt_fetch(stmt_param);
			if (fetch_result == 1) {
				diag(
					"mysql_stmt_fetch at line %d failed: %s", __LINE__,
					mysql_stmt_error(stmt_param)
				);
				goto exit;
			}

			if (i % 2) {
				bool data_match_expected =
					(data_id == static_cast<int64_t>(1)) &&
					(data_c1 == static_cast<int64_t>(100)) &&
					(strcmp(data_c2, "abcde") == 0);

				ok(
					data_match_expected,
					"Prepared statement SELECT result *SHOULD* match expected -"
					" Exp=(id:1, c1:100, c2:'abcde'), Act=(id:%d, c1:%ld, c2:'%s')",
					data_id,
					data_c1,
					data_c2
				);
			} else {
				bool data_match_expected =
					(data_id == static_cast<int64_t>(0)) &&
					(data_c1 == static_cast<int64_t>(0)) &&
					(strcmp(data_c2, "") == 0);

				ok(
					data_match_expected,
					"Prepared statement SELECT result *SHOULD* match expected -"
					" Exp=(id:0, c1:0, c2:''), Act=(id:%d, c1:%ld, c2:'%s')",
					data_id,
					data_c1,
					data_c2
				);
			}
		}

		mysql_stmt_close(stmt_param);
	}

exit:
	mysql_close(proxysql_mysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
