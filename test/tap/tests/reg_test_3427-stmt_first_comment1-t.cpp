/**
 * @file reg_test_3427-stmt_first_comment-t.cpp
 * @brief This test is a regression test for exercising all code related to
 *   'first_comment' changes added in PR #3453.
 * @details Testing revealed that the fix introduced for proper routing of
 *   prepared statements with query rules has invalid interaction with query
 *   annotation 'hostgroup' feature.
 *   For solving the issue, 'first_comment' was made part of 'MySQL_STMT_Global_info'.
 *   This test aims to exercise all the parts of ProxySQL affected by this change.
 *
 *   Procedure:
 *   =========
 *
 *   The test creates a number of prepared statements and execute them, until passing
 *   the limit of prepared statements allowed per connection. After the connection
 *   has been reset by ProxySQL because of the limit exceeding, it tries to execute
 *   the same prepared statements again. This way those prepared statements wont be
 *   available in the connection and will need to be fetched by ProxySQL for the
 *   reset connection.
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
 * @brief Number of max stmt per connection to be configured for
 *  ProxySQL.
 */
const uint32_t MAX_STMT_NUM_QUERIES = 20;
/**
 * @brief Number of queries to RESET the connection being target,
 *  it's simply: MAX_STMT_NUM_QUERIES + 1
 */
const uint32_t RESET_CONNECTION_QUERIES = 2*MAX_STMT_NUM_QUERIES;
/**
 * @brief Id for the current writer hostgroup.
 */
const uint32_t WRITER_HOSTGROUP_ID = 0;

int main(int argc, char** argv) {
	int res = EXIT_SUCCESS;

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	bool param = false;
	{
		// we parse argv[0] to see if filename includes "param"
		std::string str = std::string(argv[0]);
		std::size_t found = str.find("param");
		if (found!=std::string::npos) {
			param = true;
		}
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

	// Insert data in the table to be queried
	// *************************************************************************

	MYSQL_QUERY(proxysql_mysql, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(proxysql_mysql, "DROP TABLE IF EXISTS test.reg_test_3427");
	MYSQL_QUERY(
		proxysql_mysql,
		"CREATE TABLE IF NOT EXISTS test.reg_test_3427"
		" (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, `c1` BIGINT, `c2` varchar(32))"
	);
	MYSQL_QUERY(proxysql_mysql, "INSERT INTO test.reg_test_3427(c1, c2) VALUES (100, 'abcde')");

	mysql_close(proxysql_mysql);

	// Initialize the connection again
	proxysql_mysql = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}

	// *************************************************************************

	{
		// Set the number of maximum connections for servers in the writer hostgroup
		std::string t_update_mysql_servers {
			"UPDATE mysql_servers SET max_connections=1 WHERE hostgroup_id=%d"
		};
		std::string update_mysql_queries {};
		string_format(t_update_mysql_servers, update_mysql_queries, WRITER_HOSTGROUP_ID);
		MYSQL_QUERY(proxysql_admin, update_mysql_queries.c_str());
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		// Set the number of maximum prepared statements per connection
		std::string t_max_stmt_query {
			"SET mysql-max_stmts_per_connection=%d"
		};
		std::string max_stmt_query {};
		string_format(t_max_stmt_query, max_stmt_query, MAX_STMT_NUM_QUERIES);
		MYSQL_QUERY(proxysql_admin, max_stmt_query.c_str());
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		uint32_t query_id = 0;

		for (uint32_t i = 0; i < RESET_CONNECTION_QUERIES; i++) {
			if (i <= MAX_STMT_NUM_QUERIES) {
				query_id = i;
			} else if (i == MAX_STMT_NUM_QUERIES + 1) {
				query_id = 0;
			} else {
				query_id += 1;
			}

			// create unique stmt
			std::string query_t {};

			if (param) {
				query_t = "SELECT /* ;hostgroup=0;%d */ * FROM test.reg_test_3427 WHERE id IN (?)";
			} else {
				query_t = "SELECT /* ;hostgroup=0;%d */ * FROM test.reg_test_3427";
			}

			std::string query {};
			string_format(query_t, query, query_id);

			MYSQL_STMT* stmt = mysql_stmt_init(proxysql_mysql);
			if (!stmt) {
				diag("mysql_stmt_init(), out of memory");
				res = EXIT_FAILURE;
				goto exit;
			}

			if (mysql_stmt_prepare(stmt, query.c_str(), strlen(query.c_str()))) {
				diag("mysql_stmt_prepare at line %d failed: %s", __LINE__ , mysql_error(proxysql_mysql));
				mysql_close(proxysql_mysql);
				res = EXIT_FAILURE;
				goto exit;
			}

			if (param) {
				MYSQL_BIND bind_params;
				int64_t data_param = 1;

				memset(&bind_params, 0, sizeof(MYSQL_BIND));
				bind_params.buffer_type = MYSQL_TYPE_LONGLONG;
				bind_params.buffer = (char *)&data_param;
				bind_params.buffer_length = sizeof(int64_t);

				if (mysql_stmt_bind_param(stmt, &bind_params)) {
					diag(
						"mysql_stmt_bind_result at line %d failed: %s", __LINE__ ,
						mysql_stmt_error(stmt)
					);
					res = EXIT_FAILURE;
					goto exit;
				}
			}

			if (mysql_stmt_execute(stmt)) {
				diag(
					"mysql_stmt_execute at line %d failed: %s", __LINE__ ,
					mysql_stmt_error(stmt)
				);
				res = EXIT_FAILURE;
				goto exit;
			}

			MYSQL_BIND bind[3];
			int data_id;
			int64_t data_c1;
			char data_c2[STRING_SIZE];
			char is_null[3];
			long unsigned int length[3];
			char error[3];
			memset(bind, 0, sizeof(bind));

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

			if (mysql_stmt_bind_result(stmt, bind)) {
				diag(
					"mysql_stmt_bind_result at line %d failed: %s", __LINE__,
					mysql_stmt_error(stmt)
				);
				res = EXIT_FAILURE;
				goto exit;
			}

			if (mysql_stmt_fetch(stmt) == 1) {
				diag(
					"mysql_stmt_fetch at line %d failed: %s", __LINE__,
					mysql_stmt_error(stmt)
				);
				res = EXIT_FAILURE;
				goto exit;
			}

			bool data_match_expected =
				(data_id == static_cast<int64_t>(1)) &&
				(data_c1 == static_cast<int64_t>(100)) &&
				(strcmp(data_c2, "abcde") == 0);

			if (data_match_expected == false) {
				diag(
					"Prepared statement SELECT result didn't matched expected -"
					" Exp=(id:1, c1:100, c2:'abcde'), Act=(id:%d, c1:%ld, c2:'%s')",
					data_id,
					data_c1,
					data_c2
				);
				res = EXIT_FAILURE;
				goto exit;
			}

			mysql_stmt_close(stmt);
		}
	}

exit:
	mysql_close(proxysql_mysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
