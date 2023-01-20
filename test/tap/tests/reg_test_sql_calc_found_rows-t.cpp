/**
 * @file reg_test_stmt_dis_multiplex-t.cpp
 * @brief This is a simple regression test checking that 'STMT_EXECUTE' for queries holding
 *  'SQL_CALC_FOUND_ROWS' disable multiplexing and return the expected results when used in combination with
 *  'FOUND_ROWS()'. Unlike other tests, this test doesn't rely on 'PROXYSQL INTERNAL SESSION' info.
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>
#include <utility>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "json.hpp"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::vector;
using std::string;
using std::pair;

using nlohmann::json;

int get_stmt_result(MYSQL_STMT* stmt, int64_t& out_data) {
	MYSQL_BIND bind[1];
	int64_t data_c;

	char is_null[1];
	long unsigned int length[1];
	char error[1];

	memset(bind, 0, sizeof(bind));

	bind[0].buffer_type = MYSQL_TYPE_LONG;
	bind[0].buffer = (char *)&data_c;
	bind[0].buffer_length = sizeof(int);
	bind[0].is_null = &is_null[0];
	bind[0].length = &length[0];

	if (mysql_stmt_bind_result(stmt, bind)) {
		diag("'mysql_stmt_bind_result' at line %d failed: %s", __LINE__, mysql_stmt_error(stmt));
		return EXIT_FAILURE;
	}

	while (!mysql_stmt_fetch(stmt)) {}

	out_data = data_c;

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(6);

	diag("Checking that 'SQL_CALC_FOUND_ROWS' and 'FOUND_ROWS()' returns expected results for STMT");

	const char* Q_CALC_FOUND_ROWS_1 { "SELECT SQL_CALC_FOUND_ROWS 1" };
	const char* Q_CALC_FOUND_ROWS_2 { "SELECT SQL_CALC_FOUND_ROWS 3 UNION SELECT 4" };
	const char* Q_FOUND_ROWS { "SELECT FOUND_ROWS()" };

	// 1. Prepare the 'SQL_CALC_FOUND_ROWS' stmt in a connection
	MYSQL* proxy_mysql = mysql_init(NULL);

	diag("%s: Openning initial connection...", tap_curtime().c_str());
	if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		return EXIT_FAILURE;
	}

	MYSQL_STMT* stmt_1 = mysql_stmt_init(proxy_mysql);
	MYSQL_STMT* stmt_2 = mysql_stmt_init(proxy_mysql);
	MYSQL_STMT* stmt_3 = nullptr;

	diag("%s: Issuing the prepare for `%s` in init conn", tap_curtime().c_str(), Q_CALC_FOUND_ROWS_1);
	int my_err = mysql_stmt_prepare(stmt_1, Q_CALC_FOUND_ROWS_1, strlen(Q_CALC_FOUND_ROWS_1));
	if (my_err) {
		diag(
			"'mysql_stmt_prepare' failed for query '%s' with error - Err: '%d', ErrMsg: '%s'",
			Q_CALC_FOUND_ROWS_1, mysql_errno(proxy_mysql), mysql_error(proxy_mysql)
		);
		goto cleanup;
	}

	diag("%s: Issuing the prepare for `%s` in init conn", tap_curtime().c_str(), Q_CALC_FOUND_ROWS_2);
	my_err = mysql_stmt_prepare(stmt_2, Q_CALC_FOUND_ROWS_2, strlen(Q_CALC_FOUND_ROWS_2));
	if (my_err) {
		diag(
			"'mysql_stmt_prepare' failed for query '%s' with error - Err: '%d', ErrMsg: '%s'",
			Q_CALC_FOUND_ROWS_1, mysql_errno(proxy_mysql), mysql_error(proxy_mysql)
		);
		goto cleanup;
	}

	mysql_stmt_close(stmt_1);
	mysql_stmt_close(stmt_2);

	diag("%s: Closing initial connection...", tap_curtime().c_str());
	mysql_close(proxy_mysql);

	// 2. Open a new connection and prepare the stmts it again in a new connection
	proxy_mysql = mysql_init(NULL);

	diag("%s: Openning new connection for testing 'Multiplex' disabling", tap_curtime().c_str());
	if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		return EXIT_FAILURE;
	}

	stmt_1 = mysql_stmt_init(proxy_mysql);
	stmt_2 = mysql_stmt_init(proxy_mysql);
	stmt_3 = mysql_stmt_init(proxy_mysql);

	diag("%s: Issuing the prepare for `%s` in new conn", tap_curtime().c_str(), Q_CALC_FOUND_ROWS_1);
	my_err = mysql_stmt_prepare(stmt_1, Q_CALC_FOUND_ROWS_1, strlen(Q_CALC_FOUND_ROWS_1));
	if (my_err) {
		diag(
			"'mysql_stmt_prepare' failed for query '%s' with error - Err: '%d', ErrMsg: '%s'",
			Q_CALC_FOUND_ROWS_1, mysql_errno(proxy_mysql), mysql_error(proxy_mysql)
		);
		goto cleanup;
	}

	{
		diag("%s: Issuing execute for `%s` in new conn", tap_curtime().c_str(), Q_CALC_FOUND_ROWS_1);
		my_err = mysql_stmt_execute(stmt_1);
		if (my_err) {
			diag("'mysql_stmt_execute' at line %d failed: %s", __LINE__, mysql_stmt_error(stmt_1));
			goto cleanup;
		}

		int64_t f_query_res = 0;
		my_err = get_stmt_result(stmt_1, f_query_res);
		if (my_err) {
			diag("'get_stmt_result' at line %d failed", __LINE__);
			goto cleanup;
		}
	}
	{
		diag("%s: Issuing the prepare for `%s` in new conn", tap_curtime().c_str(), Q_CALC_FOUND_ROWS_2);
		my_err = mysql_stmt_prepare(stmt_2, Q_CALC_FOUND_ROWS_2, strlen(Q_CALC_FOUND_ROWS_2));
		if (my_err) {
			diag(
				"'mysql_stmt_prepare' failed for query '%s' with error - Err: '%d', ErrMsg: '%s'",
				Q_CALC_FOUND_ROWS_2, mysql_errno(proxy_mysql), mysql_error(proxy_mysql)
			);
			goto cleanup;
		}

		{
			diag("%s: Issuing execute for `%s` in new conn", tap_curtime().c_str(), Q_CALC_FOUND_ROWS_2);
			my_err = mysql_stmt_execute(stmt_2);
			if (my_err) {
				diag("'mysql_stmt_execute' at line %d failed: %s", __LINE__, mysql_stmt_error(stmt_2));
				goto cleanup;
			}

			int64_t s_query_res = 0;
			my_err = get_stmt_result(stmt_2, s_query_res);
			if (my_err) {
				diag("'get_stmt_result' at line %d failed", __LINE__);
				goto cleanup;
			}
		}

		diag("%s: Issuing the prepare for `%s` in new conn", tap_curtime().c_str(), Q_FOUND_ROWS);
		my_err = mysql_stmt_prepare(stmt_3, Q_FOUND_ROWS, strlen(Q_FOUND_ROWS));
		if (my_err) {
			diag(
				"'mysql_stmt_prepare' failed for query '%s' with error - Err: '%d', ErrMsg: '%s'",
				Q_FOUND_ROWS, mysql_errno(proxy_mysql), mysql_error(proxy_mysql)
			);
			goto cleanup;
		}

		// 4. Perform execs of both stmt followed by 'found_rows()' stmt and check results
		bool exp_results = false;
		const int RETRIES = 3;
		const int ITERATIONS = 5;

		for (int i = 0; i < RETRIES; i++) {
			my_err = mysql_stmt_execute(stmt_1);
			if (my_err) {
				diag("'mysql_stmt_execute' at line %d failed: %s", __LINE__, mysql_stmt_error(stmt_1));
				goto cleanup;
			}

			int64_t f_query_res = 0;
			my_err = get_stmt_result(stmt_1, f_query_res);
			if (my_err) {
				diag("'get_stmt_result' at line %d failed", __LINE__);
				goto cleanup;
			}

			my_err = mysql_stmt_execute(stmt_2);
			if (my_err) {
				diag("'mysql_stmt_execute' at line %d failed: %s", __LINE__, mysql_stmt_error(stmt_2));
				goto cleanup;
			}

			int64_t s_query_res = 0;
			my_err = get_stmt_result(stmt_2, s_query_res);
			if (my_err) {
				diag("'get_stmt_result' at line %d failed", __LINE__);
				goto cleanup;
			}

			pair<int,int> results {f_query_res, s_query_res};
			diag("Results from 'mysql_stmt_execute' were: %s", json {results}.dump().c_str());

			ok(
				results.first == 1 && results.second == 4,
				"'mysql_stmt_execute' returned the expected values - first: %d, second: %d",
				results.first, results.second
			);

			diag("Perform multiple execute for 'FOUND_ROWS()' and check result");

			vector<int> found_rows_results {};

			for (int i = 0; i < ITERATIONS; i++) {
				my_err = mysql_stmt_execute(stmt_3);
				if (my_err) {
					diag("'mysql_stmt_execute' at line %d failed: %s", __LINE__, mysql_stmt_error(stmt_1));
					goto cleanup;
				}

				int64_t found_rows_res = 0;
				my_err = get_stmt_result(stmt_3, found_rows_res);
				found_rows_results.push_back(found_rows_res);
			}

			diag("Results from 'FOUND_ROWS' executions - '%s'", json { found_rows_results }.dump().c_str());

			bool correct_found_rows = false;
			bool exp_f_val = found_rows_results.front() == 2;
			bool exp_tail_val = true;

			for (int i = 1; i < ITERATIONS; i++) {
				exp_tail_val &= exp_tail_val && found_rows_results[i] == 1;
			}

			ok(exp_f_val && exp_tail_val, "'FOUND_ROWS' execution returned expected values");
		}
	}

cleanup:

	mysql_stmt_close(stmt_1);
	mysql_stmt_close(stmt_2);
	mysql_stmt_close(stmt_3);

	mysql_close(proxy_mysql);

	return exit_status();
}
