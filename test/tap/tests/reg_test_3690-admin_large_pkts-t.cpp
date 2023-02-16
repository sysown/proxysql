/**
 * @file reg_test_3690-admin_large_pkts-t.cpp
 * @brief This test is a regression test for issue #3690.
 * @details The test performs the following operations:
 *   1. Creates a table in ProxySQL internal SQLite using an admin connection.
 *   2. Fills this table with random length strings, varying from small to higher than 0xFFFFFF size.
 *   3. Queries the generated rows, and checks that the received rows length matches the previously inserted
 *      rows length.
 *
 * @date 2021-12-01
 */

#include <tuple>
#include <vector>
#include <string>
#include <iostream>
#include <random>

#include <mysql.h>

#include "json.hpp"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

string create_testing_table_query(int col_num) {
	string test_table_query { "CREATE TABLE reg_test_3690_table (id INT" };

	for (int i = 0; i < col_num; i++) {
		test_table_query += ", v" + std::to_string(i) + " TEXT";
	}

	test_table_query += ")";

	return test_table_query;
}

uint32_t TESTING_TABLE_COLUMNS = 10;

vector<uint32_t> generate_random_row_lens(int cols_num) {
	std::random_device rd;
	std::default_random_engine gen(rd());
	std::uniform_int_distribution<> elem_type_dst(0, 4);
	std::uniform_int_distribution<> small_value_dst(1, 30);
	vector<uint32_t> row_lens {};

	for (int i = 0; i < cols_num; i++) {
		int elem_type = elem_type_dst(gen);

		if (elem_type == 0) {
			row_lens.push_back(0);
		} else if (elem_type == 1) {
			row_lens.push_back(small_value_dst(gen));
		} else if (elem_type == 2) {
			row_lens.push_back(small_value_dst(gen) + 0xFFFFFF*2);
		} else {
			row_lens.push_back(small_value_dst(gen) + 0xFFFFFF);
		}
	}

	return row_lens;
}

string generate_insert_query(const vector<uint32_t>& cols_lens) {
	string random_insert_query { "INSERT INTO reg_test_3690_table (" };

	for (uint32_t i = 0; i < cols_lens.size(); i++) {
		random_insert_query += "v" + std::to_string(i);

		if (i != cols_lens.size() - 1) {
			random_insert_query += ",";
		}
	}

	random_insert_query += ") VALUES (";

	for (vector<uint32_t>::const_iterator it = cols_lens.begin(); it != cols_lens.end(); it++) {
		if (*it == 0) {
			random_insert_query += "\"\"";
		} else {
			random_insert_query += "printf('%.' || " + std::to_string(*it) + " || 'c', '*')";
		}

		if (std::next(it) != cols_lens.end()) {
			random_insert_query += ",";
		}
	}

	random_insert_query += ")";

	return random_insert_query;
}

using row_act_exp_lens = std::tuple<uint32_t, vector<uint32_t>, vector<uint32_t>>;

/**
 * @brief Returns a vector holding the length of all the elements found for each row in the resulset.
 */
vector<vector<uint32_t>> fetch_rows_lens(MYSQL_RES* res) {
	vector<vector<uint32_t>> rows {};

	if (res == NULL) {
		return rows;
	}

	MYSQL_ROW row = nullptr;
	int num_fields = mysql_num_fields(res);

	while ((row = mysql_fetch_row(res))) {
		vector<uint32_t> row_vals {};

		unsigned long *lengths;
		lengths = mysql_fetch_lengths(res);

		for(int i = 1; i < num_fields; i++) {
			if (row[i]) {
				row_vals.push_back(lengths[i]);
			} else {
				row_vals.push_back(0);
			}
		}

		rows.push_back(row_vals);
	}

	return rows;
}

void match_row_lens(MYSQL_RES* t1_rows, const vector<vector<uint32_t>>& exp_rows_lens) {
	vector<vector<uint32_t>> act_rows_lens { fetch_rows_lens(t1_rows) };
	vector<row_act_exp_lens> result {};

	for (uint32_t row_id = 0; row_id < exp_rows_lens.size(); row_id++) {
		nlohmann::json j_exp_row_lens(exp_rows_lens[row_id]);
		nlohmann::json j_act_row_lens(act_rows_lens[row_id]);

		ok(
			exp_rows_lens[row_id] == act_rows_lens[row_id],
			"Actual rows lengths should match expected ones:\n"
			" - Expected: '%s'\n - Actual: '%s'",
			j_exp_row_lens.dump().c_str(), j_act_row_lens.dump().c_str()
		);
	}
}

uint32_t COLUMN_NUM = 10;
uint32_t ROW_NUM = 10;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxysql_admin = mysql_init(NULL);

	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	// Connnect to local proxysql
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	// There should be a test for each inserted row
	plan(ROW_NUM);

	// Drop the testing table if exists
	MYSQL_QUERY(proxysql_admin, "DROP TABLE IF EXISTS reg_test_3690_table");

	// Create the testing table
	std::string testing_table_query { create_testing_table_query(COLUMN_NUM) };
	MYSQL_QUERY(proxysql_admin, testing_table_query.c_str());

	// Insert the randomly sized rows
	vector<vector<uint32_t>> inserted_rows {};
	for (int i = 0; i < ROW_NUM; i++) {
		auto row = generate_random_row_lens(COLUMN_NUM);
		string insert_query = generate_insert_query(row);
		MYSQL_QUERY(proxysql_admin, insert_query.c_str());

		inserted_rows.push_back(row);
	}

	// Get the rows
	MYSQL_QUERY(proxysql_admin, "SELECT * FROM reg_test_3690_table");
	MYSQL_RES* select_res = mysql_store_result(proxysql_admin);
	match_row_lens(select_res, inserted_rows);

	// Cleanup the used table
	MYSQL_QUERY(proxysql_admin, "DROP TABLE IF EXISTS reg_test_3690_table");

	return exit_status();
}
