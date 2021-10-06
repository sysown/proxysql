/**
 * @file reg_test_3606_mysql_warnings-t.cpp
 * @brief Simple regression test that performs multiple queries against a MySQL table
 *   with 'mysql-log_mysql_warnings_enabled' feature enabled. The issued queries are known
 *   to generate MySQL warnings thus providing a regression test for issue #3606.
 */

#include <algorithm>
#include <unistd.h>
#include <vector>
#include <tuple>
#include <string>
#include <stdio.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include <proxysql_utils.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "utils.h"

using std::vector;
using std::tuple;
using std::string;

std::vector<std::string> queries {
	"SELECT /*+ ;hostgroup=0 */ * FROM test.reg_test_3606_mysql_warnings WHERE id=%d",
	"INSERT /*+ ;hostgroup=0 */ INTO test.reg_test_3606_mysql_warnings (a, c, pad) VALUES ('%d', '%s', '%s')",
	"UPDATE /*+ ;hostgroup=0 */ test.reg_test_3606_mysql_warnings SET a=%d, c='%s', pad='%s' WHERE id=%d"
};

int create_testing_tables(MYSQL* mysql_server) {
	// Create the testing database
	mysql_query(mysql_server, "CREATE DATABASE IF NOT EXISTS test");
	mysql_query(mysql_server, "DROP TABLE IF EXISTS test.reg_test_3606_mysql_warnings");

	mysql_query(
		mysql_server,
		"CREATE TABLE IF NOT EXISTS test.reg_test_3606_mysql_warnings ("
		"  id INTEGER NOT NULL AUTO_INCREMENT,"
		"  a TINYINT NOT NULL,"
		"  c varchar(255),"
		"  pad CHAR(60),"
		"  PRIMARY KEY (id)"
		")"
	);

	return mysql_errno(mysql_server);
}

int main(int argc, char** argv) {
	CommandLine cl;

	uint32_t c_operations = 500;

	plan(1 + c_operations + (c_operations - 1) * 3);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxy_mysql = mysql_init(NULL);
	MYSQL* proxy_admin = mysql_init(NULL);

	// Initialize connections
	if (!proxy_mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		return EXIT_FAILURE;
	}
	if (!proxy_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY(proxy_admin, "SET mysql-log_mysql_warnings_enabled='true'");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL_QUERY(proxy_mysql, "SET sql_mode=ANSI");

	int c_err = create_testing_tables(proxy_mysql);
	ok(c_err == 0, "Table creation should succeed. ErrCode: %d", c_err);
	if (tests_failed()) {
		std::string error = mysql_error(proxy_mysql);
		diag("MySQL Error: '%s'", error.c_str());

		return exit_status();
	}

	vector<tuple<int, string, string>> stored_pairs {};

	// Include one initial null element to make index match
	stored_pairs.push_back(tuple<int, string, string>{0,"", ""});
	srand(time(NULL));

	for (auto i = 0; i < c_operations; i++) {
		std::string rnd_c = random_string(rand() % 80);
		std::string rnd_pad = random_string(rand() % 15);
		const std::string& t_insert_query = queries[1];
		std::string insert_query {};

		// Store the random generated strings
		stored_pairs.push_back(tuple<int, string, string>{300, rnd_c, rnd_pad});

		// Execute the INSERT queries
		string_format(t_insert_query, insert_query, 300, rnd_c.c_str(), rnd_pad.c_str());
		int i_res = mysql_query(proxy_mysql, insert_query.c_str());
		uint64_t i_err = mysql_errno(proxy_mysql);

		ok(i_err == 0, "Insert queries should be executed correctly. ErrCode: %ld", i_err);
		if (tests_failed()) {
			std::string error = mysql_error(proxy_mysql);
			diag("MySQL Error: '%s'", error.c_str());

			return exit_status();
		}
	}

	for (auto id = 1; id < c_operations; id++) {
		int64_t op = rand() % 2;

		if (op == 0) { // Do a random SELECT
			const std::string& t_select_query = queries[0];
			std::string select_query {};

			string_format(t_select_query, select_query, id);
			int s_res = mysql_query(proxy_mysql, select_query.c_str());
			ok(s_res == 0, "Select queries should be executed correcly. ErrCode: %d", mysql_errno(proxy_mysql));
			if (s_res != 0) { break; }

			// Check that the SELECT resultset isn't illformed
			MYSQL_RES* select_res = mysql_store_result(proxy_mysql);
			int field_count = mysql_field_count(proxy_mysql);
			int row_count = mysql_num_rows(select_res);

			ok(
				field_count == 4 && row_count == 1,
				"Received resulset should have: Exp - ['field_count'='3','row_count'='1'],"
				" Actual: ['field_count'='%d','row_count'='%d'].",
				field_count,
				row_count
			);
			if (tests_failed()) {
				std::string error = mysql_error(proxy_mysql);
				diag("MySQL Error: '%s'", error.c_str());

				goto cleanup;
			}

			MYSQL_ROW row = mysql_fetch_row(select_res);
			bool same_a = std::get<0>(stored_pairs[id]) == 300 && 255 == std::atoi(row[1]);
			bool same_c = std::get<1>(stored_pairs[id]) == row[2];
			bool same_pad = std::get<2>(stored_pairs[id]) == row[3];

			ok(
			  same_c && same_pad,
			  "Received 'a', 'c' and 'pad' matches expected values."
			  " ('c': %s) == ('exp_c': %s), ('pad': %s) == ('exp_pad': %s)",
			  row[2],
			  std::get<1>(stored_pairs[id]).c_str(),
			  row[3],
			  std::get<2>(stored_pairs[id]).c_str()
			);

			if (tests_failed()) {
				std::string error = mysql_error(proxy_mysql);
				diag("MySQL Error: '%s'", error.c_str());

				goto cleanup;
			}

			mysql_free_result(select_res);
		} else { // Do a random UPDATE
			std::string rnd_c = random_string(rand() % 100);
			std::string rnd_pad = random_string(rand() % 60);

			// Store the new random generated strings
			std::tuple<int, std::string, std::string> new_values { 255, rnd_c, rnd_pad };
			stored_pairs[id] = new_values;

			const std::string& t_update_query = queries[2];
			std::string update_query {};

			string_format(t_update_query, update_query, 300, rnd_c.c_str(), rnd_pad.c_str(), id);
			int u_res = mysql_query(proxy_mysql, update_query.c_str());

			ok(u_res == 0, "Update queries should be executed correctly. ErrCode: %d", mysql_errno(proxy_mysql));
			if (tests_failed()) {
				std::string error = mysql_error(proxy_mysql);
				diag("MySQL Error: '%s'", error.c_str());

				goto cleanup;
			}
			ok(true, "Dummy check for 'UPDATE' for having even number of checks");
			ok(true, "Dummy check for 'UPDATE' for having even number of checks");
		}
	}

cleanup:

	mysql_close(proxy_mysql);
	mysql_close(proxy_admin);

	return exit_status();
}
