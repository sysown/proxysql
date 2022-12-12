/**
 * @file reg_test_stmt_resultset_err_no_rows-t.cpp
 * @brief Checks handling of STMT binary resultsets with errors without rows.
 * @details This test compiles against 'libmariadb' and 'libmysqlclient'. This testing is completed by
 *   'reg_test_stmt_resultset_err_no_rows_php-t.cpp' which performs the same checks but using PHP default
 *   connector.
 */

#include <iostream>
#include <ctime>
#include <string>
#include <string.h>
#include <stdio.h>
#include <tuple>
#include <unistd.h>
#include <utility>
#include <vector>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;
using std::tuple;

using test_case_t = tuple<bool,string,string>;

const uint32_t STRING_SIZE = 1024;
const vector<test_case_t> TEST_CASES {
	{true, "$.", ""}, {false, "$", "[\"a\", \"b\"]"}, {true, "$.", ""}, {false, "$.b", "[\"c\"]"}
};

int main(int argc, char** argv) {
	int res = EXIT_SUCCESS;

	plan(TEST_CASES.size());

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxy = mysql_init(NULL);
	MYSQL* admin = mysql_init(NULL);

#ifdef LIBMYSQL_HELPER
	enum mysql_ssl_mode ssl_mode = SSL_MODE_DISABLED;
	mysql_options(proxy, MYSQL_OPT_SSL_MODE, &ssl_mode);
#endif

	proxy->options.client_flag &= ~CLIENT_DEPRECATE_EOF;

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	const string stmt_query { "SELECT json_keys('{\"a\": 0, \"b\": {\"c\": 1}}', ?)" };

	for (const test_case_t& test_case : TEST_CASES) {
		const bool exp_fail { std::get<0>(test_case) };
		const string& param { std::get<1>(test_case) };
		const string& exp_res { std::get<2>(test_case) };

		MYSQL_STMT* stmt = mysql_stmt_init(proxy);

		if (!stmt) {
			diag("mysql_stmt_init(), out of memory");
			res = EXIT_FAILURE;
			goto exit;
		}

		if (mysql_stmt_prepare(stmt, stmt_query.c_str(), strlen(stmt_query.c_str()))) {
			diag("mysql_stmt_prepare at line %d failed: %s", __LINE__ , mysql_error(proxy));
			mysql_close(proxy);
			res = EXIT_FAILURE;
			goto exit;
		}

		MYSQL_BIND bind_params;
		memset(&bind_params, 0, sizeof(MYSQL_BIND));
		char str_data[STRING_SIZE] = { 0 };
		uint64_t str_length = 0;

		bind_params.buffer_type = MYSQL_TYPE_STRING;
		bind_params.buffer = static_cast<char*>(str_data);
		bind_params.buffer_length = STRING_SIZE;
		bind_params.is_null = 0;
		bind_params.length = &str_length;

		if (mysql_stmt_bind_param(stmt, &bind_params)) {
			diag("mysql_stmt_bind_result at line %d failed: '%s'", __LINE__ , mysql_stmt_error(stmt));
			res = EXIT_FAILURE;
			goto exit;
		}

		strncpy(str_data, param.c_str(), STRING_SIZE);
		str_length = strlen(str_data);

		int exec_res = mysql_stmt_execute(stmt);
		if (exec_res) {
			ok(exp_fail, "'mysql_stmt_execute' returned error: '%s'", mysql_stmt_error(stmt));
			if (exp_fail) {
				diag("mysql_stmt_execute at line %d failed: '%s'", __LINE__, mysql_stmt_error(stmt));
				mysql_stmt_close(stmt);
				continue;
			} else {
				diag("mysql_stmt_execute at line %d failed: '%s'", __LINE__, mysql_stmt_error(stmt));
				res = EXIT_FAILURE;
				goto exit;
			}
		}

		MYSQL_BIND bind;
		memset(&bind, 0, sizeof(bind));

		char data_c2[STRING_SIZE] = { 0 };
#ifdef LIBMYSQL_HELPER
		bool is_null[1];
		bool error[1];
		long unsigned int length[1];
#else
		char is_null[1];
		char error[1];
		long unsigned int length[1];
#endif

		bind.buffer_type = MYSQL_TYPE_STRING;
		bind.buffer = (char *)&data_c2;
		bind.buffer_length = STRING_SIZE;
		bind.is_null = &is_null[0];
		bind.length = &length[0];
		bind.error = &error[0];

		if (mysql_stmt_bind_result(stmt, &bind)) {
			diag("mysql_stmt_bind_result at line %d failed: %s", __LINE__, mysql_stmt_error(stmt));
			res = EXIT_FAILURE;
			goto exit;
		}

		int res_err = mysql_stmt_store_result(stmt);
		if (res_err) {
			ok(exp_fail, "'mysql_stmt_store_result' returned error: '%s'", mysql_stmt_error(stmt));

			if (exp_fail) {
				mysql_stmt_close(stmt);
				continue;
			} else {
				res = EXIT_FAILURE;
				goto exit;
			}
		} else {
			int field_count = mysql_stmt_field_count(stmt);

			if (mysql_stmt_fetch(stmt) == 1 && field_count == 1) {
				diag("mysql_stmt_fetch at line %d failed: %s", __LINE__, mysql_stmt_error(stmt));
				res = EXIT_FAILURE;
				goto exit;
			}

			ok(
				string { data_c2 } == exp_res && field_count == 1,
				"Prepared statement SELECT matched expected - FieldCount: '%d', Exp: '%s', Act: '%s'",
				field_count, exp_res.c_str(), data_c2
			);
		}

		mysql_stmt_close(stmt);
	}

exit:
	mysql_close(proxy);
	mysql_close(admin);

	if (res == EXIT_SUCCESS) {
		return exit_status();
	} else {
		return res;
	}
}
