/**
 * @file reg_test_3606_mysql_warnings-t.cpp
 * @brief Regression test that performs multiple queries against a MySQL table
 *   with 'mysql-log_mysql_warnings_enabled' feature enabled. The issued queries are known
 *   to generate MySQL warnings thus providing a regression test for issue #3606.
 * @details Test covers the following cases:
 *   * Mixed prepared statements and text protocol queries are executed correctly when
 *     'mysql-log_mysql_warnings_enabled' is enabled.
 *   * Mixed queries generating warnings and not are correctly executed.
 *   * Multistatements queries mixed with the previous ones are also properly executed.
 */

#include <algorithm>
#include <unistd.h>
#include <vector>
#include <tuple>
#include <cstring>
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

enum query_type {
	TEXT_SELECT_WARNING = 0,
	TEXT_SELECT_NO_WARNING,
	TEXT_MULTISTATEMENT_SELECT_WARNING,
	TEXT_INSERT_WARNING,
	TEXT_UPDATE_WARNING,
	TEXT_UPDATE_NO_WARNING
};

std::vector<std::string> queries {
	"SELECT /*+ ;hostgroup=0 */ * FROM test.reg_test_3606_mysql_warnings WHERE id=%d",
	"SELECT * FROM test.reg_test_3606_mysql_warnings WHERE id=%d",
	"SELECT /*+ ;hostgroup=0 */ * FROM test.reg_test_3606_mysql_warnings WHERE id=%d; SELECT /*+ ;hostgroup=0 */ * FROM test.reg_test_3606_mysql_warnings WHERE id=%d;",
	"INSERT /*+ ;hostgroup=0 */ INTO test.reg_test_3606_mysql_warnings (a, c, pad) VALUES ('%d', '%s', '%s')",
	"UPDATE /*+ ;hostgroup=0 */ test.reg_test_3606_mysql_warnings SET a=%d, c='%s', pad='%s' WHERE id=%d",
	"UPDATE test.reg_test_3606_mysql_warnings SET a=%d, c='%s', pad='%s' WHERE id=%d"
};

enum stmt_query_type {
	STMT_SELECT_NO_WARNING = 0,
	STMT_INSERT_WARNING,
	STMT_UPDATE_WARNING
};

std::vector<std::string> stmt_queries {
	"SELECT /*+ ;hostgroup=0 */ id, a, c, pad FROM test.reg_test_3606_mysql_warnings WHERE id=?",
	"INSERT /*+ ;hostgroup=0 */ INTO test.reg_test_3606_mysql_warnings (a, c, pad) VALUES (?, ?, ?)",
	"UPDATE /*+ ;hostgroup=0 */ test.reg_test_3606_mysql_warnings SET a=?, c=?, pad=? WHERE id=?"
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

	double plan_val =
		1.0 + // Table creation
		(double)c_operations + // Initial table filling insert queries
		floor(((double)c_operations - 1.0) * (1.0 / 4.0) * 3.0) + // Number of reguarl selects checks
		floor(((double)c_operations - 1.0) * (1.0 / 8.0) * 3.0) + // Number of non-multistatement select checks
		floor(((double)c_operations - 1.0) * (1.0 / 8.0) * 5.0) + // Number of multistatements select checks
		floor(((double)c_operations - 1.0) * (1.0 / 2.0));  // Number of updates checks
	plan(plan_val);

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

	if (
		!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL,
			CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS)
	) {
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
		std::string rnd_c = random_string(rand() % 80 + 1);
		std::string rnd_pad = random_string(rand() % 15 + 1);
		const std::string& t_insert_query = queries[TEXT_INSERT_WARNING];
		std::string insert_query {};

		// Store the random generated strings
		stored_pairs.push_back(tuple<int, string, string>{ 300, rnd_c, rnd_pad });

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

	const std::string rep_check_query {
		"SELECT CASE WHEN (SELECT COUNT(*) FROM test.reg_test_3606_mysql_warnings) = 500 THEN 'TRUE' ELSE 'FALSE' END"
	};
	int wait_res = wait_for_replication(proxy_mysql, proxy_admin, rep_check_query, 10, 1);
	if (wait_res != EXIT_SUCCESS) {
		diag("Waiting for replication failed... Exiting");
		return EXIT_FAILURE;
	}

	// Prepare STMT queries
	std::vector<MYSQL_STMT*> stmts {};
	for (std::size_t i = 0; i < stmt_queries.size(); i++) {
		MYSQL_STMT* stmt = mysql_stmt_init(proxy_mysql);
		if (stmt == nullptr) {
			diag(
				"'mysql_stmt_init' failed for 'SELECT' with err: ('%s','%s')",
				stmt_queries[STMT_SELECT_NO_WARNING].c_str(), mysql_error(proxy_mysql)
			);
			return EXIT_FAILURE;
		}
		stmts.push_back(stmt);
	}

	// Prepare SELECT
	{
		int err = mysql_stmt_prepare(
			stmts[0], stmt_queries[STMT_SELECT_NO_WARNING].c_str(), stmt_queries[STMT_SELECT_NO_WARNING].size()
		);
		if (err != EXIT_SUCCESS) {
			diag(
				"'mysql_stmt_prepare' failed for 'SELECT' with err: ('%s','%s')",
				stmt_queries[STMT_SELECT_NO_WARNING].c_str(), mysql_error(proxy_mysql)
			);
			return EXIT_FAILURE;
		}
	}
	// Prepare UPDATE
	{
		int err = mysql_stmt_prepare(
			stmts[2], stmt_queries[STMT_UPDATE_WARNING].c_str(), stmt_queries[STMT_UPDATE_WARNING].size()
		);
		if (err != EXIT_SUCCESS) {
			diag(
				"'mysql_stmt_prepare' failed for 'SELECT' with err: ('%s','%s')", stmt_queries[0].c_str(),
				mysql_error(proxy_mysql)
			);
			return EXIT_FAILURE;
		}
	}

	bool multistatement = true;
	bool select_stmt_query = true;
	bool update_stmt_query = true;

	for (auto id = 1; id < c_operations; id++) {
		int64_t op = id % 2;
		int64_t produce_warning = rand() % 2;

		if (op == 0) { // Do a random SELECT
			if (select_stmt_query) {
				diag("Performing 'STMT SELECT' query...");

				MYSQL_BIND bindsi[1];
				memset(bindsi, 0, sizeof(bindsi));
				int copyid = id;

				bindsi[0].buffer_type= MYSQL_TYPE_LONG;
				bindsi[0].buffer= (char *)&copyid;
				bindsi[0].is_null= 0;
				bindsi[0].length= 0;

				int rc = mysql_stmt_bind_param(stmts[0], bindsi);
				if (rc) {
					diag(
						"'mysql_stmt_bind_param' failed for 'SELECT' with err: ('%s','%s')",
						stmt_queries[STMT_SELECT_NO_WARNING].c_str(), mysql_error(proxy_mysql)
					);
					return EXIT_FAILURE;
				}

				MYSQL_BIND binds[4];
				memset(binds, 0, sizeof(binds));

				int64_t id_res;
				int res_a;
				char res_c_buf[256];
				char res_pad_buf[256];
				memset(res_c_buf, 0, sizeof(res_c_buf));
				memset(res_pad_buf, 0, sizeof(res_pad_buf));

				unsigned long length[4] = { 0 };
				my_bool is_null[4] = { 0 };
				my_bool error[4] = { 0 };

				binds[0].buffer_type= MYSQL_TYPE_LONGLONG;
				binds[0].buffer= (char *)&id_res;
				binds[0].is_null= &is_null[0];
				binds[0].length= &length[0];
				binds[0].error= &error[0];

				binds[1].buffer_type= MYSQL_TYPE_LONG;
				binds[1].buffer= (char *)&res_a;
				binds[1].is_null= &is_null[3];
				binds[1].length= &length[3];
				binds[1].error= &error[3];

				binds[2].buffer_type= MYSQL_TYPE_VAR_STRING;
				binds[2].buffer= (char *)res_c_buf;
				binds[2].buffer_length= sizeof(res_c_buf);
				binds[2].is_null= &is_null[1];
				binds[2].length= &length[1];
				binds[2].error= &error[1];

				binds[3].buffer_type= MYSQL_TYPE_VAR_STRING;
				binds[3].buffer= (char *)res_pad_buf;
				binds[3].buffer_length= sizeof(res_pad_buf);
				binds[3].is_null= &is_null[2];
				binds[3].length= &length[2];
				binds[3].error= &error[2];

				rc = mysql_stmt_execute(stmts[0]);
				ok(
					rc == 0, "Select queries should be executed correctly. Err: ('%s', '%d')",
					mysql_error(proxy_mysql), mysql_errno(proxy_mysql)
				);

				if (rc) {
					diag(
						"'mysql_stmt_execute' failed for 'SELECT' with err: ('%s','%s')",
						stmt_queries[STMT_SELECT_NO_WARNING].c_str(), mysql_error(proxy_mysql)
					);
					return EXIT_FAILURE;
				}

				rc = mysql_stmt_bind_result(stmts[0], binds);
				if (rc) {
					diag(
						"'mysql_stmt_execute' failed for 'SELECT' with err: ('%s','%s')",
						stmt_queries[STMT_SELECT_NO_WARNING].c_str(), mysql_error(proxy_mysql)
					);
					return EXIT_FAILURE;
				}

				MYSQL_RES *prepare_meta_result;
				prepare_meta_result = mysql_stmt_result_metadata(stmts[0]);
				if (prepare_meta_result == NULL) {
					diag("mysql_stmt_result_metadata() failed: %s", mysql_stmt_error(stmts[0]));
					return EXIT_FAILURE;
				}

				rc = mysql_stmt_store_result(stmts[0]);
				if (rc) {
					diag("mysql_stmt_store_result() failed: %s", mysql_stmt_error(stmts[0]));
					return EXIT_FAILURE;
				}

				unsigned long long row_count= mysql_stmt_num_rows(stmts[0]);
				uint32_t field_count= mysql_stmt_field_count(stmts[0]);
				ok(
					field_count == 4 && row_count == 1,
					"Received resulset should have: Exp - ['field_count'='3','row_count'='1'],"
					" Actual: ['field_count'='%d','row_count'='%lld'].",
					field_count, row_count
				);

				rc = mysql_stmt_fetch(stmts[0]);
				if (rc && rc != MYSQL_DATA_TRUNCATED) {
					diag("mysql_stmt_fetch() failed: ('%d','%s')", rc, mysql_stmt_error(stmts[0]));
					return EXIT_FAILURE;
				}

				bool same_a = std::get<0>(stored_pairs[id]) == 300 && 127 == res_a;
				bool same_c = std::get<1>(stored_pairs[id]) == std::string { res_c_buf };
				bool same_pad = std::get<2>(stored_pairs[id]) == std::string { res_pad_buf };

				ok(
					same_a && same_c && same_pad,
					"Received 'a', 'c' and 'pad' matches expected values."
					" ('a': '%d') == ('exp_a': '%d'), ('c': '%s') == ('exp_c': '%s'), ('pad': '%s') == ('exp_pad': '%s')",
					res_a, 127, res_c_buf, std::get<1>(stored_pairs[id]).c_str(),
					res_pad_buf, std::get<2>(stored_pairs[id]).c_str()
				);

				mysql_stmt_free_result(stmts[0]);
				mysql_free_result(prepare_meta_result);

				if (tests_failed()) {
					diag("Failed, aborting further tests...");
					goto cleanup;
				}
			} else {
				if (multistatement) {
					diag("Performing 'TEXT PROTOCOL MULTISTATEMENT SELECT' query...");
				} else {
					diag("Performing 'TEXT PROTOCOL SELECT' query...");
				}

				std::string t_select_query {};
				std::string select_query {};

				if (multistatement) {
					t_select_query = queries[TEXT_MULTISTATEMENT_SELECT_WARNING];
					string_format(t_select_query, select_query, id, id);
				} else {
					if (produce_warning) {
						t_select_query = queries[TEXT_SELECT_WARNING];
					} else {
						t_select_query = queries[TEXT_SELECT_NO_WARNING];
					}
					string_format(t_select_query, select_query, id);
				}

				int rc = mysql_query(proxy_mysql, select_query.c_str());
				ok(
					rc == 0, "Select queries should be executed correctly. Err: ('%s', '%d')",
					mysql_error(proxy_mysql), mysql_errno(proxy_mysql)
				);
				if (rc != 0) {
					diag("Failed, aborting further tests...");
					goto cleanup;
				}

				const auto check_result = [&](MYSQL_RES* select_res) -> bool {
					int field_count = mysql_field_count(proxy_mysql);
					int row_count = mysql_num_rows(select_res);

					ok(
						field_count == 4 && row_count == 1,
							"Received resulset should have: Exp - ['field_count'='3','row_count'='1'],"
							" Actual: ['field_count'='%d','row_count'='%d'].",
							field_count, row_count
					);

					if (tests_failed()) {
						return false;
					}

					MYSQL_ROW row = mysql_fetch_row(select_res);
					bool same_a = std::get<0>(stored_pairs[id]) == 300 && 127 == std::atoi(row[1]);
					bool same_c = std::get<1>(stored_pairs[id]) == row[2];
					bool same_pad = std::get<2>(stored_pairs[id]) == row[3];

					ok(
						same_a && same_c && same_pad,
						"Received 'a', 'c' and 'pad' matches expected values."
						" ('a': '%d') == ('exp_a': '%d'), ('c': '%s') == ('exp_c': '%s'), ('pad': '%s') == ('exp_pad': '%s')",
						std::atoi(row[1]), 127, row[2], std::get<1>(stored_pairs[id]).c_str(), row[3],
						std::get<2>(stored_pairs[id]).c_str()
					);

					return tests_failed() == 0;
				};

				// Check that the SELECT resultset isn't illformed
				int next_result = 0;
				int result_count = 0;
				while(next_result == 0) {
					result_count++;

					MYSQL_RES* select_res = mysql_store_result(proxy_mysql);
					bool check_res = check_result(select_res);
					mysql_free_result(select_res);
					if (check_res == false) {
						diag("Failed, aborting further tests...");
						goto cleanup;
					}
					next_result = mysql_next_result(proxy_mysql);
				}

				if (tests_failed()) {
					diag("Failed, aborting further tests...");
					goto cleanup;
				}

				// Next iteration perform the opposite operation
				multistatement = !multistatement;
			}

			// Next iteration perform the opposite operation
			select_stmt_query = !select_stmt_query;
		} else { // Do a random UPDATE
			if (update_stmt_query) {
				diag("Performing 'STMT UPDATE' query...");

				MYSQL_BIND binds_u[4];
				memset(binds_u, 0, sizeof(binds_u));
				unsigned long length[4] = { 0 };

				int64_t id_param = id;
				int param_a = 99;

				if (produce_warning) {
					param_a = 255;
				}

				std::string param_c { random_string(rand() % 100 + 5) };
				std::string param_pad { random_string(rand() % 60 + 5) };

				unsigned long param_c_len = param_c.size();
				unsigned long param_pad_len = param_pad.size();

				my_bool is_null[4] = { 0 };

				binds_u[0].buffer_type= MYSQL_TYPE_LONG;
				binds_u[0].buffer= (char *)&param_a;
				binds_u[0].is_null= 0;
				binds_u[0].length= 0;

				binds_u[1].buffer_type= MYSQL_TYPE_VAR_STRING;
				binds_u[1].buffer= (char *)param_c.c_str();
				binds_u[1].buffer_length= param_c.size();
				binds_u[1].is_null= 0;
				binds_u[1].length= &param_c_len;

				binds_u[2].buffer_type= MYSQL_TYPE_VAR_STRING;
				binds_u[2].buffer= (char *)param_pad.c_str();
				binds_u[2].buffer_length= param_pad.size();
				binds_u[2].is_null= 0;
				binds_u[2].length= &param_pad_len;

				binds_u[3].buffer_type= MYSQL_TYPE_LONGLONG;
				binds_u[3].buffer= (char *)&id_param;
				binds_u[3].is_null= 0;
				binds_u[3].length= &length[0];

				int rc = mysql_stmt_bind_param(stmts[2], binds_u);
				if (rc) {
					diag(
						"'mysql_stmt_bind_param' failed for 'SELECT' with err: ('%s','%s')",
						stmt_queries[STMT_UPDATE_WARNING].c_str(), mysql_stmt_error(stmts[2])
					);
					return EXIT_FAILURE;
				}

				rc = mysql_stmt_execute(stmts[2]);
				if (rc) {
					diag(
						"'mysql_stmt_execute' failed for 'SELECT' with err: ('%s','%s')",
						stmt_queries[STMT_UPDATE_WARNING].c_str(), mysql_error(proxy_mysql)
					);

					goto cleanup;
				}

				int affected_rows= mysql_stmt_affected_rows(stmts[2]);
				ok(
					rc == 0 && affected_rows == 1,
					"Update queries should be executed correctly. ErrCode: %d", mysql_stmt_errno(stmts[2])
				);

				if (tests_failed()) {
					diag("Failed, aborting further tests...");
					goto cleanup;
				}
			} else {
				diag("Performing 'TEXT PROTOCOL UPDATE' query...");

				std::string rnd_c = random_string(rand() % 100 + 5);
				std::string rnd_pad = random_string(rand() % 60 + 5);

				// Store the new random generated strings
				std::tuple<int, std::string, std::string> new_values { 255, rnd_c, rnd_pad };
				stored_pairs[id] = new_values;

				std::string update_query {};

				if (produce_warning) {
					const std::string& t_update_query = queries[TEXT_UPDATE_WARNING];
					string_format(t_update_query, update_query, 300, rnd_c.c_str(), rnd_pad.c_str(), id);
				} else {
					const std::string& t_update_query = queries[TEXT_UPDATE_NO_WARNING];
					string_format(t_update_query, update_query, 100, rnd_c.c_str(), rnd_pad.c_str(), id);
				}
				int u_res = mysql_query(proxy_mysql, update_query.c_str());

				ok(
					u_res == 0, "Update queries should be executed correctly. ErrCode: %d",
					mysql_errno(proxy_mysql)
				);
				if (tests_failed()) {
					diag("Failed, aborting further tests...");
					goto cleanup;
				}
			}

			// Next iteration perform the opposite operation
			update_stmt_query = !update_stmt_query;
		}
	}
cleanup:

	for (MYSQL_STMT* stmt : stmts) {
		mysql_stmt_close(stmt);
	}
	mysql_close(proxy_mysql);
	mysql_close(proxy_admin);

	return exit_status();
}
