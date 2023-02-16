/**
 * @file eof_mixed_flags_queries-t.cpp
 * @brief This test verifies that ProxySQL handles properly any combination of:
 *   - 'mysql-enable_client_deprecate_eof'
 *   - 'mysql-enable_server_deprecate_eof'
 *   - Compression for frontend and backend connections.
 *   - Fast forward
 *
 *   For both TEXT and BINARY protocols. The test also performs all the checks over fresh/reused backend
 *   connections.
 */

#include <algorithm>
#include <utility>
#include <vector>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <iostream>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

vector<vector<bool>> get_all_bin_vec(size_t tg_size) {
	vector<vector<bool>> all_bin_strs {};
	vector<bool> bin_vec(tg_size, 0);

	for (size_t i = 0; i < tg_size; i++) {
		if (i == 0) {
			bin_vec[i] = 0;
			for (const vector<bool> p : get_permutations(bin_vec)) {
				all_bin_strs.push_back(p);
			}
		}

		bin_vec[i] = 1;
		for (const vector<bool> p : get_permutations(bin_vec)) {
			all_bin_strs.push_back(p);
		}
	}

	return all_bin_strs;
}

vector<conn_cnf_t> gen_all_configs(const string& ff_user) {
	vector<vector<bool>> all_bin_vec { get_all_bin_vec(5) };
	std::sort(all_bin_vec.begin(), all_bin_vec.end());

	vector<conn_cnf_t> all_test_cnfs {};

	for (const vector<bool>& bin_vec : all_bin_vec) {
		all_test_cnfs.push_back({ bin_vec[4], bin_vec[3], bin_vec[2], bin_vec[1], bin_vec[0], ff_user });
	}

	return all_test_cnfs;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const string FF_USER { cl.username };

	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	const auto execute_target_test = [&cl, &admin, &FF_USER] (const string test_file, bool clear_conns) -> int {
		vector<conn_cnf_t> all_test_confs { gen_all_configs(FF_USER) };

		for (const conn_cnf_t& cnf : all_test_confs) {
			const string cnf_str { to_string(cnf) };

			if (clear_conns) {
				diag("Executing test '%s' in FRESH backend conns with config '%s'", test_file.c_str(), cnf_str.c_str());

				MYSQL_QUERY_T(admin, "UPDATE mysql_servers set max_connections=0");
				MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

				int wait_res = wait_for_backend_conns(admin, "ConnFree", 0, 5);
				if (wait_res != EXIT_SUCCESS) {
					diag("Error waiting for ProxySQL to close backend connection.");
					return EXIT_FAILURE;
				}

				MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS FROM DISK");
				MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");
			} else {
				diag("Executing test '%s' REUSING backend conns with config '%s'", test_file.c_str(), cnf_str.c_str());
			}

			int test_res = execute_eof_test(cl, admin, test_file, cnf);
			if (test_res != 0) {
				break;
			}
		}

		return EXIT_SUCCESS;
	};

	diag("Executing target tests with FRESH backend connections");
	int rc = execute_target_test("eof_packet_mixed_queries-t", true);
	if (rc != EXIT_SUCCESS) return rc;
	rc = execute_target_test("ok_packet_mixed_queries-t", true);
	if (rc != EXIT_SUCCESS) return rc;

	diag("Executing target tests REUSING backend connections");
	rc = execute_target_test("eof_packet_mixed_queries-t", false);
	if (rc != EXIT_SUCCESS) return rc;
	rc = execute_target_test("ok_packet_mixed_queries-t", false);
	if (rc != EXIT_SUCCESS) return rc;

	mysql_close(admin);

	return exit_status();
}
