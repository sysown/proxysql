/**
 * @file reg_test_3434-stmt_metadata-t.cpp
 * @brief This test is a regression test for issue #3434.
 * @details This test executes a combination of prepared statements and text protocol
 *  queries to the same ProxySQL backend connection, to create the required flow to
 *  trigger issue #3434. The test tries to particularly stress the code related
 *  to metadata handling.
 * @date 2021-05-04
 */

#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <time.h>
#include <iostream>
#include <thread>

#include <mysql.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

const int STRING_SIZE=32;

int g_seed = 0;

inline int fastrand() {
	g_seed = (214013*g_seed+2531011);
	return (g_seed>>16)&0x7FFF;
}

inline unsigned long long monotonic_time() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

void gen_random_str(char *s, const int len) {
	g_seed = monotonic_time() ^ getpid() ^ pthread_self();
	static const char alphanum[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[fastrand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

int perform_text_select(
	const CommandLine& cl,
	const std::string& query
) {
	MYSQL* proxysql_text = mysql_init(NULL);
	if (!proxysql_text) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_text));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(proxysql_text, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_text));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY(proxysql_text, query.c_str());
	MYSQL_RES* result = mysql_store_result(proxysql_text);
	mysql_free_result(result);
	mysql_close(proxysql_text);

	return EXIT_SUCCESS;
}

int perform_stmt_select(
	const CommandLine& cl,
	const std::string& query,
	uint32_t num_query_params
) {
	int res = EXIT_SUCCESS;
	MYSQL* proxysql_mysql = mysql_init(NULL);

	if (!proxysql_mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	}

	MYSQL_STMT *stmt = mysql_stmt_init(proxysql_mysql);
	if (!stmt) {
		diag("mysql_stmt_init(), out of memory");
		res = EXIT_FAILURE;
		goto exit;
	}

	if (mysql_stmt_prepare(stmt, query.c_str(), strlen(query.c_str()))) {
		diag("mysql_stmt_prepare at line %d failed: %s", __LINE__ , mysql_error(proxysql_mysql));
		mysql_close(proxysql_mysql);
		mysql_library_end();
		res = EXIT_FAILURE;
		goto exit;
	}

	{
		std::vector<MYSQL_BIND> bind_params(num_query_params);
		std::vector<int64_t> data_param(num_query_params, 0);

		for (uint32_t i = 0; i < data_param.size(); i++) {
			data_param[i] = i;
		}

		for (int i = 0; i < num_query_params; i++) {
			memset(&bind_params[i], 0, sizeof(MYSQL_BIND));

			bind_params[i].buffer_type = MYSQL_TYPE_LONGLONG;
			bind_params[i].buffer = (char *)&data_param[i];
			bind_params[i].buffer_length = sizeof(int64_t);
		}

		if (mysql_stmt_bind_param(stmt, &bind_params[0])) {
			diag(
				"mysql_stmt_bind_result at line %d failed: %s", __LINE__ ,
				mysql_stmt_error(stmt)
			);
			res = EXIT_FAILURE;
			goto exit;
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
	}

exit:

	if (stmt) { mysql_stmt_close(stmt); }
	mysql_close(proxysql_mysql);

	return res;
}

std::string build_random_select_query(
	const std::string& rnd_table_name,
	const uint32_t hostgroup,
	const uint32_t num_params
) {
	// Force the 'hostgroup' for the 'SELECT' query
	std::string t_query {
		"SELECT /* ;hostgroup=%d,%s */ * FROM %s WHERE id IN ("
	};

	for (uint32_t i = 0; i < num_params; i++) {
		t_query += "?";

		if (i != num_params - 1) {
			t_query += ",";
		}
	}

	t_query += ")";

	std::string query {};
	std::string rnd_str(static_cast<std::size_t>(20), '\0');
	gen_random_str(&rnd_str[0], 20);

	string_format(
		t_query, query, hostgroup, rnd_str.c_str(), rnd_table_name.c_str()
	);

	return query;
}

uint32_t SELECT_PARAM_NUM = 20000;
uint32_t ITERATIONS = 10;
uint32_t HOSTGROUP = 0;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(1);

	MYSQL* proxysql_mysql = mysql_init(NULL);
	if (!proxysql_mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return exit_status();
	}
	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return exit_status();
	}

	// Configure ProxySQL
	// *************************************************************************

	// We configure ProxySQL allowing a maximum of `1` connections to the backend server
	// we are targetting for this test. This way we ensure that all the operations that
	// trigger this specific bug are performed against the same backend connection.
	// We know this because we are going to later impose this queries to be specifically
	// redirected to the hostgroup of this backend.

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}

	std::string t_update_servers_query {
		"UPDATE mysql_servers SET max_connections=1 WHERE hostgroup_id=%d"
	};
	std::string update_servers_query {};
	string_format(t_update_servers_query, update_servers_query, HOSTGROUP);

	MYSQL_QUERY(proxysql_admin, update_servers_query.c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	sleep(2);

	// *************************************************************************

	// Insert data in the table to be queried
	// *************************************************************************

	MYSQL_QUERY(proxysql_mysql, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(proxysql_mysql, "DROP TABLE IF EXISTS test.reg_test_3434");
	MYSQL_QUERY(
		proxysql_mysql,
		"CREATE TABLE IF NOT EXISTS test.reg_test_3434"
		" (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, `c1` BIGINT, `c2` varchar(32))"
	);
	MYSQL_QUERY(proxysql_mysql, "INSERT INTO test.reg_test_3434 (c1, c2) VALUES (100, 'abcde')");

	mysql_close(proxysql_mysql);

	// *************************************************************************

	// This test support supplying to it the number of iterations that should be
	// performed, for debugging purposes. `1` iteration should be enough to
	// trigger the memory corruption, and experimental tests show that after
	// just `1` ProxySQL always crash. For safety by default we are leaving 10
	// iterations.
	if (argc == 2) {
		ITERATIONS = std::atoi(argv[1]);
		std::cout << "Supplied iterations were: " << ITERATIONS << "\n";
	}

	int query_res = 0;

	// Force the 'hostgroup' for the 'SELECT' queries, to ensure that
	// the connections are going to the same server, and thus,
	// targetting the same backend connection, since we have reduced
	// the maximum number of backend connections for this server to `1`.
	for (int i = 0; i < ITERATIONS; i++) {
		std::string query_1 {
			build_random_select_query("test.reg_test_3434", HOSTGROUP, SELECT_PARAM_NUM)
		};
		std::string text_query_1 {};
		std::string::size_type pos = query_1.find("WHERE");
		if (pos == std::string::npos) {
			text_query_1 = "SELECT 1";
		} else {
			text_query_1 = query_1.substr(0, pos);
		}

		query_res = perform_stmt_select(cl, query_1, SELECT_PARAM_NUM);
		if (query_res != EXIT_SUCCESS) { break; }
		query_res = perform_text_select(cl, text_query_1);
		if (query_res != EXIT_SUCCESS) { break; }

		std::string query_2 {
			build_random_select_query("test.reg_test_3434", HOSTGROUP, SELECT_PARAM_NUM)
		};
		std::string text_query_2 {};
		pos = query_2.find("WHERE");
		if (pos == std::string::npos) {
			text_query_2 = "SELECT 1";
		} else {
			text_query_2 = query_1.substr(0, pos);
		}

		query_res = perform_stmt_select(cl, query_2, SELECT_PARAM_NUM);
		if (query_res != EXIT_SUCCESS) { break; }
	}

	ok(query_res == EXIT_SUCCESS, "Check that none of the queries failed to be executed.");

	mysql_close(proxysql_admin);

	return exit_status();
}
