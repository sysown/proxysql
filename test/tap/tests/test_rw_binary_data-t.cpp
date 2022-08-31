/**
 * @file test_rw_binary_data-t.cpp
 * @brief Test performs the reading and writing of binary data through ProxySQL, verifying data
 * 	correctness after each operation, and that 'stats_mysql_query_digest' are not polluted by the data being
 * 	inserted.
 * @details Test performs the following actions over a connection using 'NO_BACKSLASH_ESCAPES' to simplify the
 *  binary data insertion:
 *  1. Creates a table with a ranging number of columns, from 1 to N.
 *  2. Performs INSERT/SELECT operations for both TEXT and BINARY protocols over the table, checking that
 *     inserted that matches received data.
 *  3. After performing the operations, checks that the expected query digest is present on
 *     'stats_mysql_query_digest'. Field 'count_star' is used to ensure that only the expected digest was
 *     introduced by the previous operations and no pollution has taken place.
 *
 *  TODO: Test current avoid generating random binary strings that ends with '\' (0x5c). The use of
 *  'NO_BACKSLASH_ESCAPES' in the connection makes possible to create valid queries with strings ending with
 *  '\', this edge case is currently not properly handled and pollutes 'stats_mysql_query_digest'.
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>
#include <iostream>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "command_line.h"
#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

using std::vector;
using std::string;

const std::string fdev_random { "/dev/random" };
const size_t NUM_TESTS = 100;

/**
 * @brief Create a random binary string of the supplied size. The string isn't allowed to contain single
 *  quotes ''' or end with '0x5c' when specified in the second parameter.
 *
 * @param str_size The size of the string to be generated.
 * @param rm_final_5c If the generated binary string is allowed to contain '0x5c' as a final character. If
 *  'true' character is removed and replaced by a zero, if 'false' character is preserved.
 *
 * @return The randomly generated binary string.
 */
int get_random_bin_str(std::size_t str_size, string& str_bin_data, bool rm_final_5c = true) {
	std::ifstream ifs_random(fdev_random, std::ios::binary);
	if (!ifs_random.is_open()) {
		std::cout << "failed to open " << fdev_random << '\n';
		diag("Failed to open '%s' with error '%s'", fdev_random.c_str(), strerror(errno));
		return EXIT_FAILURE;
	}

	std::vector<char> binary_data(str_size, 0);

	for (char& c : binary_data) {
		char tmp_c = 0;
		ifs_random.read(reinterpret_cast<char*>(&tmp_c), sizeof(char));

		if (tmp_c == '\'' || (rm_final_5c && (&c == &binary_data.back()) && tmp_c == '\\')) {
			c = 0;
		} else {
			c = tmp_c;
		}
	}

	std::string result { binary_data.begin(), binary_data.end() };
	str_bin_data = result;

	return EXIT_SUCCESS;
}

string gen_text_insert_query(const size_t idx, const vector<string>& insert_data) {
	string f_insert_query { "INSERT INTO test.rw_bindata (idx, " };
	const string s_insert_query { ")" };

	for (size_t i = 0; i < insert_data.size(); i++) {
		f_insert_query += "v" + std::to_string(i);

		if (i != insert_data.size() - 1) {
			f_insert_query += ", ";
		}
	}

	f_insert_query += ") VALUES (%ld, ";

	string_format(f_insert_query, f_insert_query, idx);
	size_t query_size = f_insert_query.size() + s_insert_query.size();

	for (const string& str : insert_data) {
		query_size += str.size();
	}

	// Space for quotes and comma in values to add: # '_VAL_', # .
	query_size += insert_data.size() * 3 - 1;

	void* f_query = malloc(query_size);
	void* query_buffer = f_query;

	memcpy(query_buffer, f_insert_query.data(), f_insert_query.size() * sizeof(char));
	query_buffer = static_cast<char*>(query_buffer) + f_insert_query.size();

	for (const string& str_bin_data : insert_data) {
		*static_cast<char*>(query_buffer) = '\'';
		query_buffer = static_cast<char*>(query_buffer) + 1;

		memcpy(query_buffer, str_bin_data.data(), str_bin_data.size() * sizeof(char));
		query_buffer = static_cast<char*>(query_buffer) + str_bin_data.size();

		*static_cast<char*>(query_buffer) = '\'';
		query_buffer = static_cast<char*>(query_buffer) + 1;

		if (&str_bin_data != &insert_data.back()) {
			*static_cast<char*>(query_buffer) = ',';
			query_buffer = static_cast<char*>(query_buffer) + 1;
		}
	}

	memcpy(query_buffer, s_insert_query.data(), s_insert_query.size() * sizeof(char));
	query_buffer = static_cast<char*>(query_buffer) + s_insert_query.size();

	string result(static_cast<char*>(f_query), query_size);
	free(f_query);

	return result;
}

string gen_stmt_insert_query(const size_t num_columns) {
	string f_insert_query { "INSERT INTO test.rw_bindata (idx," };

	for (size_t i = 0; i < num_columns; i++) {
		f_insert_query += "v" + std::to_string(i);

		if (i != num_columns - 1) {
			f_insert_query += ", ";
		}
	}

	f_insert_query += ") VALUES (?,";

	for (size_t i = 0; i < num_columns; i++) {
		f_insert_query += "?";

		if (i != num_columns - 1) {
			f_insert_query += ",";
		}
	}

	f_insert_query += ")";

	return f_insert_query;
}

string gen_exp_insert_digest(const size_t num_columns, uint32_t grouping_limit) {
	string f_insert_query { "INSERT INTO test.rw_bindata (idx," };

	for (size_t i = 0; i < num_columns; i++) {
		f_insert_query += "v" + std::to_string(i);

		if (i != num_columns - 1) {
			f_insert_query += ",";
		}
	}

	f_insert_query += ") VALUES (?,";

	for (size_t i = 0; i < num_columns; i++) {
		if (i == grouping_limit - 1) {
			// notice that num_columns doesn't include 'idx' column
			if (num_columns > grouping_limit) {
				f_insert_query += "...";
				break;
			}
		}

		f_insert_query += "?";

		if (i != num_columns - 1) {
			f_insert_query += ",";
		}
	}

	f_insert_query += ")";

	return f_insert_query;
}

void text_protocol_check(MYSQL* proxy, const size_t idx, const vector<string>& bin_data) {
	string insert_query { gen_text_insert_query(idx, bin_data) };
	mysql_send_query(proxy, insert_query.data(), insert_query.size());
	int query_res = mysql_read_query_result(proxy);

	if (query_res != 0) {
		std::cout << "Failed query - " << insert_query << "\n";
		return;
	}

	std::string select_query {};
	string_format("/* hostgroup=0 */ SELECT * FROM test.rw_bindata WHERE idx=%ld", select_query, idx);
	mysql_query(proxy, select_query.c_str());

	std::cout << "Issued SELECT QUERY: '" << select_query << "\n";

	MYSQL_RES* result { mysql_store_result(proxy) };
	MYSQL_ROW row = mysql_fetch_row(result);

	if (row) {
	    unsigned int num_fields = mysql_num_fields(result);
	    unsigned long* lengths = mysql_fetch_lengths(result);

		vector<string> res_bin_data {};

		std::cout << "Read data from 'ProxySQL':\n";
		for (unsigned int i = 1; i < num_fields; i++) {
			string result_bin_data(row[i], lengths[i]);

			std::cout << std::oct << "- # ";
			for (const char c : result_bin_data) {
				std::cout << std::hex << (static_cast<int8_t>(c) & 0xff);
			}
			std::cout << std::oct << " #\n";

			res_bin_data.push_back(result_bin_data);
		}

		ok(bin_data == res_bin_data, "Inserted and read data should match for TEXT protocol");
	} else {
		std::cout << "Empty row\n";
	}

	mysql_free_result(result);
}

string gen_create_table(const size_t columns, const string& charset) {
	string create_table_query {
		"CREATE TABLE test.rw_bindata ( idx INT NOT NULL,"
	};

	for (size_t i = 0; i < columns; i++) {
		create_table_query += "v" + std::to_string(i) + " varbinary(200) DEFAULT NULL";

		if (i != columns - 1) {
			create_table_query += ", ";
		}
	}

	create_table_query += ") ENGINE=InnoDB " + charset;

	return create_table_query;
}

void stmt_protocol_check(MYSQL* proxy, MYSQL* admin, const size_t idx, const vector<string>& bin_data) {
	MYSQL_STMT* stmt = mysql_stmt_init(proxy);

	const string stmt_insert_query { gen_stmt_insert_query(bin_data.size()) };
	if (mysql_stmt_prepare(stmt, stmt_insert_query.c_str(), stmt_insert_query.size())) {
		diag("Failed to prepare query '%s' with error '%s'", stmt_insert_query.c_str(), mysql_stmt_error(stmt));
		return;
	}

	unsigned long p_count = mysql_stmt_param_count(stmt);
	if (p_count != 1 + bin_data.size()) {
		diag("Invalid parameter count returned by MySQL - Exp: %ld, Act: %ld", 1 + bin_data.size(), p_count);
		return;
	}

	vector<MYSQL_BIND> bind_params(1 + bin_data.size());
	memset(&bind_params[0], 0, sizeof(MYSQL_BIND));

	bind_params[0].buffer_type = MYSQL_TYPE_LONGLONG;
	bind_params[0].buffer = const_cast<size_t*>(&idx);
	bind_params[0].buffer_length = sizeof(size_t);
	bind_params[0].is_null = 0;
	bind_params[0].length = 0;

	for (size_t i = 0; i < bin_data.size(); i++) {
		memset(&bind_params[i+1], 0, sizeof(MYSQL_BIND));

		bind_params[i+1].buffer_type = MYSQL_TYPE_STRING;
		bind_params[i+1].buffer = const_cast<char*>(bin_data[i].data());
		bind_params[i+1].buffer_length = bin_data[i].size();
	}

	if (mysql_stmt_bind_param(stmt, &bind_params[0])) {
		diag("'mysql_stmt_bind_result' at line %d failed: %s", __LINE__ , mysql_stmt_error(stmt));
		return;
	}

	if (mysql_stmt_execute(stmt)) {
		diag("'mysql_stmt_execute' at line %d failed: %s", __LINE__ , mysql_stmt_error(stmt));
		return;
	}

	MYSQL_STMT* select_stmt = mysql_stmt_init(proxy);
	const string STMT_SELECT { "/* hostgroup=0 */ SELECT * FROM test.rw_bindata WHERE idx=?" };

	if (mysql_stmt_prepare(select_stmt, STMT_SELECT.c_str(), STMT_SELECT.size())) {
		diag("'mysql_stmt_prepare' at line %d failed: %s", __LINE__ , mysql_stmt_error(select_stmt));
		return;
	}

	p_count = mysql_stmt_param_count(select_stmt);
	if (p_count != 1) {
		diag(
			"Invalid parameter count at line '%d' returned by MySQL - Exp: %ld, Act: %ld",
			__LINE__, 1 + bin_data.size(), p_count
		);
		return;
	}

	MYSQL_BIND index_param {};
	index_param.buffer_type = MYSQL_TYPE_LONGLONG;
	index_param.buffer = const_cast<size_t*>(&idx);
	index_param.buffer_length = sizeof(size_t);

	if (mysql_stmt_bind_param(select_stmt, &index_param)) {
		diag("'mysql_stmt_bind_result' at line %d failed: %s", __LINE__ , mysql_stmt_error(select_stmt));
		return;
	}

	if (mysql_stmt_execute(select_stmt)) {
		diag("'mysql_stmt_execute' at line %d failed: %s", __LINE__ , mysql_stmt_error(select_stmt));
		return;
	}

	vector<MYSQL_BIND> bind_results(1 + bin_data.size());
	size_t res_idx = 0;
	vector<char> is_null(1 + bin_data.size());
	vector<unsigned long> length(1 + bin_data.size());
	vector<string> res_bin_data {};

	// Initialize the buffers for holding the expected binary data
	for (size_t i = 0; i < bin_data.size(); i++) {
		res_bin_data.push_back(string(bin_data[i].size(), '\0'));
	}

	bind_results[0].buffer_type = MYSQL_TYPE_LONG;
	bind_results[0].buffer = const_cast<size_t*>(&res_idx);
	bind_results[0].buffer_length = sizeof(size_t);
	bind_results[0].is_null = &is_null[0];
	bind_results[0].length = &length[0];

	for (size_t i = 0; i < res_bin_data.size(); i++) {
		bind_results[i+1].buffer_type = MYSQL_TYPE_STRING;
		bind_results[i+1].buffer = const_cast<char*>(res_bin_data[i].data());
		bind_results[i+1].buffer_length = res_bin_data[i].size();

		bind_results[i+1].is_null = &is_null[i+1];
		bind_results[i+1].length = &length[i+1];
	}

	if (mysql_stmt_bind_result(select_stmt, &bind_results[0])) {
		diag("'mysql_stmt_bind_result' at line %d failed: %s", __LINE__ , mysql_stmt_error(select_stmt));
		return;
	}

	if (mysql_stmt_store_result(select_stmt)) {
		diag("'mysql_stmt_store_result' at line %d failed: %s", __LINE__ , mysql_stmt_error(select_stmt));
		return;
	}

	// fetch all the rows
	while (!mysql_stmt_fetch(select_stmt)) {}

	std::cout << "Read data from 'ProxySQL':\n";
	{
		for (const string& str_bin_data : res_bin_data) {
			std::cout << std::oct << "- # ";
			for (const char c : str_bin_data) {
				std::cout << std::hex << (static_cast<int8_t>(c) & 0xff);
			}
			std::cout << std::oct << " #\n";
		}
	}

	ok(bin_data == res_bin_data, "Inserted and read data should match for BINARY protocol");

	mysql_stmt_close(stmt);
	mysql_stmt_close(select_stmt);
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxy = mysql_init(NULL);
	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	// if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, 13306, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	// Reset 'stats_mysql_query_digest' to verify that test doesn't pollute the content
	MYSQL_QUERY(admin, "TRUNCATE stats_mysql_query_digest");

	// Make sure that the activated digest compression (grouping_limit) is the expected one
	const uint32_t grouping_limit = 3;
	string set_grouping_limit_query { "SET mysql-query_digests_grouping_limit=%d" };
	string_format(set_grouping_limit_query, set_grouping_limit_query, grouping_limit);
	MYSQL_QUERY(admin, set_grouping_limit_query.c_str());
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// We just care about the data, so we intentionally ignore '\'
	MYSQL_QUERY(proxy, "SET sql_mode='NO_BACKSLASH_ESCAPES'");

	size_t MAX_COLUMNS = 5;

	for (size_t num_columns = 1; num_columns < MAX_COLUMNS; num_columns++) {
		string create_table_query { gen_create_table(num_columns, "DEFAULT CHARSET=latin2") };

		MYSQL_QUERY(proxy, "DROP TABLE IF EXISTS test.rw_bindata");
		MYSQL_QUERY(proxy, create_table_query.c_str());

		int rc = 0;

		for (size_t idx = 0; idx < NUM_TESTS; idx++) {
			std::vector<string> bin_data {};

			for (size_t i = 0; i < num_columns; i++) {
				size_t str_size = rand() % 50;
				string str_bin_data {};
				rc = get_random_bin_str(str_size, str_bin_data);

				if (rc == EXIT_SUCCESS) {
					bin_data.push_back(str_bin_data);
				} else {
					break;
				}
			}

			if (rc != EXIT_SUCCESS) {
				break;
			}

			std::cout << "Read data from '" + fdev_random +  "':\n";
			{
				for (const string& str_bin_data : bin_data) {
					std::cout << std::oct << "- # ";
					for (const char c : str_bin_data) {
						std::cout << std::hex << (static_cast<int8_t>(c) & 0xff);
					}
					std::cout << std::oct << " #\n";
				}
			}

			// 1. Perform the text protocol operations and check
			text_protocol_check(proxy, idx, bin_data);

			// 2. Perform the text protocol operations and check
			stmt_protocol_check(proxy, admin, idx, bin_data);
		}

		// 3. Check that 'stats_mysql_query_digest' hasn't been polluted by the operations
		string exp_digest { gen_exp_insert_digest(num_columns, grouping_limit) };
		string digest_stats_query { "SELECT count_star from stats_mysql_query_digest WHERE digest_text=\"%s\"" };
		string_format(digest_stats_query, digest_stats_query, exp_digest.c_str());

		uint32_t timeout = 10;
		uint32_t count = 0;
		uint32_t count_star = 0;

		while (count < timeout) {
			diag("Waiting for exp digest '%s' to be present in 'stats_mysql_query_digest'...", exp_digest.c_str());

			int rc = mysql_query(admin, digest_stats_query.c_str());
			if (rc == 0) {
				MYSQL_RES* myres = mysql_store_result(admin);
				MYSQL_ROW myrow = mysql_fetch_row(myres);

				if (myrow && myrow[0]) {
					count_star = std::stol(myrow[0]);

					if (count_star == NUM_TESTS * 3) {
						count = timeout;
					}
				}

				mysql_free_result(myres);
			}

			if (count == timeout) {
				break;
			}

			count += 1;
			sleep(1);
		}

		ok(count_star == NUM_TESTS * 3, "Digest matches expected 'count_star' number");
	}

cleanup:

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
