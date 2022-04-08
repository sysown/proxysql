/**
 * @file test_auto_increment_delay_multiplex-t.cpp
 * @brief This test verifies the features 'mysql-auto_increment_delay_multiplex' and
 *  'mysql-auto_increment_delay_multiplex_timeout_ms' is working properly.
 * @details This test checks that:
 *  1. Variables 'mysql-auto_increment_delay_multiplex' and 'mysql-auto_increment_delay_multiplex_timeout_ms'
 *     are present.
 *  2. 'auto_increment_delay_multiplex' behaves properly for different values.
 *  3. 'auto_increment_delay_multiplex_timeout_ms' behaves properly for different values.
 *  4. 'auto_increment_delay_multiplex_timeout_ms' behaves properly for value '0' (disabled).
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>

#include <unistd.h>
#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "json.hpp"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

int get_query_result(MYSQL* mysql, const string& query, uint64_t& out_val) {
	int rc = mysql_query(mysql, query.c_str());
	if (rc != EXIT_SUCCESS) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return EXIT_FAILURE;
	}

	MYSQL_RES* myres = mysql_store_result(mysql);
	if (myres == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return EXIT_FAILURE;
	}

	MYSQL_ROW row = mysql_fetch_row(myres);
	if (row == nullptr || row[0] == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "mysql_fetch_row() failed");
		return EXIT_FAILURE;
	}

	out_val = std::stol(row[0]);

	mysql_free_result(myres);

	return EXIT_SUCCESS;
}

#define log_err(err_msg) fprintf(stderr, "File %s, line %d, Error: \"%s\"\n", __FILE__, __LINE__, err_msg);

int get_conn_auto_inc_delay_token(MYSQL* proxy_mysql, int& out_auto_inc_delay) {
	MYSQL_QUERY(proxy_mysql, "PROXYSQL INTERNAL SESSION");
	MYSQL_RES* my_res = mysql_store_result(proxy_mysql);
	vector<mysql_res_row> int_sess_res = extract_mysql_rows(my_res);
	mysql_free_result(my_res);

	int cur_auto_inc_delay_mult = 0;

	if (int_sess_res.empty()) {
		log_err("Empty result received from 'PROXYSQL INTERNAL SESSION'");
		return EXIT_FAILURE;
	}

	try {
		nlohmann::json j_int_sess = nlohmann::json::parse(int_sess_res[0][0]);
		nlohmann::json backend_conns = j_int_sess.at("backends");
		nlohmann::json m_off_conn {};

		for (const auto& j_conn : backend_conns) {
			if (j_conn.find("conn") != j_conn.end()) {
				m_off_conn = j_conn.at("conn");
			}
		}

		if (m_off_conn.empty()) {
			cur_auto_inc_delay_mult = -1;
		} else {
			cur_auto_inc_delay_mult = m_off_conn.at("auto_increment_delay_token").get<int>();
		}
	} catch (const std::exception& ex) {
		const string err_msg {
			string { "Invalid JSON received from 'PROXYSQL INTERNAL SESSION'. Ex: '" } + ex.what()  + "'"
		};
		log_err(err_msg.c_str());
		return EXIT_FAILURE;
	}

	out_auto_inc_delay = cur_auto_inc_delay_mult;

	return EXIT_SUCCESS;
}

uint32_t VAL_RANGE = 10;
uint32_t STEP = 5;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(
		1 + // Check variables are present
		((VAL_RANGE / STEP) + 1) * 2 + // Tests for different 'auto_increment_delay_multiplex' values
		(VAL_RANGE / STEP) * 3 + // Tests for different 'auto_increment_delay_multiplex_timeout_ms' values
		3 // Tests for 'auto_increment_delay_multiplex_timeout_ms' zero value
	);

	MYSQL* proxy_mysql = mysql_init(NULL);
	MYSQL* proxy_admin = mysql_init(NULL);

	if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: \"%s\"\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: \"%s\"\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY(proxy_mysql, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(proxy_mysql, "DROP TABLE IF EXISTS test.auto_inc_multiplex");
	MYSQL_QUERY(proxy_mysql, "CREATE TABLE IF NOT EXISTS test.auto_inc_multiplex (c1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY, c2 VARCHAR(100), c3 VARCHAR(100))");

	// 1. Check that the required variables are present
	{
		uint64_t auto_increment_delay_multiplex = 0;
		MYSQL_QUERY(proxy_admin, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-auto_increment_delay_multiplex'");
		MYSQL_RES* my_res_auto_inc_multiplex = mysql_store_result(proxy_admin);
		uint64_t auto_inc_row_num = mysql_num_rows(my_res_auto_inc_multiplex);
		mysql_free_result(my_res_auto_inc_multiplex);

		MYSQL_QUERY(proxy_admin, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-auto_increment_delay_multiplex_timeout_ms'");
		MYSQL_RES* my_res_auto_inc_multiplex_to = mysql_store_result(proxy_admin);
		uint64_t auto_inc_to_row_num = mysql_num_rows(my_res_auto_inc_multiplex_to);
		mysql_free_result(my_res_auto_inc_multiplex_to);

		ok(
			auto_inc_row_num == 1 && auto_inc_to_row_num == 1,
			"'mysql-auto_increment_delay_multiplex' and 'mysql-auto_increment_delay_multiplex_timeout_ms' variables present"
		);
	}

	// 2. Change and check 'auto_increment_delay_multiplex' behavior
	{
		// Disable the 'timeout' for the this check since it can be fixated now
		MYSQL_QUERY(proxy_admin, "SET mysql-auto_increment_delay_multiplex_timeout_ms=0");

		int cur_auto_inc_delay_mult = 0;
		int exp_auto_inc_delay_mult = 0;

		for (uint32_t val = 0; val <= VAL_RANGE; val += STEP) {
			MYSQL_QUERY(proxy_admin, string {"SET mysql-auto_increment_delay_multiplex=" + std::to_string(val)}.c_str());
			MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
			MYSQL_QUERY(proxy_mysql, "INSERT INTO test.auto_inc_multiplex (c2, c3) VALUES ('foo','bar')");

			for (uint32_t i = 1; i < val; i++) {
				// We target the same hostgroup as before
				MYSQL_QUERY(proxy_mysql, "DO 1");
				int g_res = get_conn_auto_inc_delay_token(proxy_mysql, cur_auto_inc_delay_mult);
				if (g_res != EXIT_SUCCESS) {
					return EXIT_FAILURE;
				}

				exp_auto_inc_delay_mult = val - i;

				diag(
					"'auto_increment_delay_token' should be reduced by one with each query to the same hostgroup: { Exp: %d, Act: %d }",
					exp_auto_inc_delay_mult, cur_auto_inc_delay_mult
				);
				if (cur_auto_inc_delay_mult != exp_auto_inc_delay_mult) {
					break;
				}
			}

			ok(
				exp_auto_inc_delay_mult == cur_auto_inc_delay_mult,
				"'auto_increment_delay_token' should be reduced by one with each query to the same hostgroup: { Exp: %d, Act: %d }",
				exp_auto_inc_delay_mult, cur_auto_inc_delay_mult
			);

			if (cur_auto_inc_delay_mult != exp_auto_inc_delay_mult) {
				break;
			}

			// Check that the connection is no longer attached when `auto_increment_delay_token` reaches `0`.
			MYSQL_QUERY(proxy_mysql, "DO 1");
			int g_res = get_conn_auto_inc_delay_token(proxy_mysql, cur_auto_inc_delay_mult);
			if (g_res != EXIT_SUCCESS) {
				return EXIT_FAILURE;
			}

			ok(
				cur_auto_inc_delay_mult == -1,
				"Connection should no longer be attached when 'auto_increment_delay_token' reaches '0'"
			);
		}
	}

	const auto check_auto_increment_to = [] (MYSQL* proxy_admin, MYSQL* proxy_mysql, uint32_t f_auto_incr_val, uint64_t poll_to, uint32_t auto_inc_delay_to) -> int {
		int cur_auto_inc_delay_mult = 0;
		const string set_auto_inc_to_query {
			"SET mysql-auto_increment_delay_multiplex_timeout_ms=" + std::to_string(auto_inc_delay_to)
		};
		MYSQL_QUERY(proxy_admin, set_auto_inc_to_query.c_str());
		MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		MYSQL_QUERY(proxy_mysql, "INSERT INTO test.auto_inc_multiplex (c2, c3) VALUES ('foo','bar')");

		// Wait at least '500' milliseconds over the poll period
		usleep((poll_to + 500) * 1000);
		uint32_t waited = poll_to + 500;

		int g_res = get_conn_auto_inc_delay_token(proxy_mysql, cur_auto_inc_delay_mult);
		if (g_res != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		ok(
			f_auto_incr_val == cur_auto_inc_delay_mult,
			"'auto_increment_delay_token' val unchanged before timeout:"
			" { Exp: %d, Act: %d, Timeout: %d, Waited: %d }",
			f_auto_incr_val, cur_auto_inc_delay_mult, auto_inc_delay_to, waited
		);

		uint32_t DEF_TIMEOUT = 5;
		uint32_t timeout = auto_inc_delay_to == 0 ? DEF_TIMEOUT : auto_inc_delay_to;

		// Wait timeout and check that the connection is detached
		usleep((timeout + poll_to + 500) * 1000);
		waited = (timeout + poll_to + 500);

		// Check 'auto_increment_delay_token' is '0' after timeout
		g_res = get_conn_auto_inc_delay_token(proxy_mysql, cur_auto_inc_delay_mult);
		if (g_res != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		if (auto_inc_delay_to == 0) {
			ok(
				f_auto_incr_val == cur_auto_inc_delay_mult,
				"'auto_increment_delay_token' val should remain unchanged '%d' after default timeout:"
				" { Exp: %d, Act: %d, mysql-auto_increment_delay_multiplex_timeout_ms: %d, Timeout: %d, Waited: %d }",
				f_auto_incr_val, f_auto_incr_val, cur_auto_inc_delay_mult, auto_inc_delay_to, timeout, waited
			);
		} else {
			ok(
				0 == cur_auto_inc_delay_mult,
				"'auto_increment_delay_token' val should be '0' after timeout:"
				" { Exp: %d, Act: %d, Timeout: %d, Waited: %d }",
				0, cur_auto_inc_delay_mult, auto_inc_delay_to, waited
			);
		}

		MYSQL_QUERY(proxy_mysql, "DO 1");
		uint32_t old_auto_inc_delay_mult = cur_auto_inc_delay_mult;
		g_res = get_conn_auto_inc_delay_token(proxy_mysql, cur_auto_inc_delay_mult);
		if (g_res != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		if (auto_inc_delay_to == 0) {
			ok(
				old_auto_inc_delay_mult == cur_auto_inc_delay_mult + 1,
				"'auto_increment_delay_token' should be reduced by one because timeout is meaningless: { Old: %d, New: %d }",
				old_auto_inc_delay_mult, cur_auto_inc_delay_mult
			);
		} else {
			ok(
				cur_auto_inc_delay_mult == -1,
				"Connection should no longer be attached when 'auto_increment_delay_token' reaches '0'"
			);
		}

		return EXIT_SUCCESS;
	};

	// 3. Change and check 'auto_increment_delay_multiplex_timeout_ms' behavior
	{
		// Set the default 'mysql-auto_increment_delay_multiplex' since it's no longer relevant
		const int f_auto_incr_val = 5;
		const string set_auto_inc_query {
			"SET mysql-auto_increment_delay_multiplex=" + std::to_string(f_auto_incr_val)
		};
		MYSQL_QUERY(proxy_admin, set_auto_inc_query.c_str());

		uint64_t poll_timeout = 0;
		const string q_poll_timeout { "SELECT variable_value FROM global_variables WHERE variable_name='mysql-poll_timeout'" };
		int g_res = get_query_result(proxy_admin, q_poll_timeout.c_str(), poll_timeout);
		if (g_res != EXIT_SUCCESS) { return EXIT_FAILURE; }

		// Check that different values for 'auto_increment_delay_multiplex_timeout_ms' behave properly
		for (uint32_t auto_inc_delay_to = 5; auto_inc_delay_to <= VAL_RANGE; auto_inc_delay_to += STEP) {
			uint32_t _auto_inc_delay_to = auto_inc_delay_to * 1000;

			if (_auto_inc_delay_to < (poll_timeout + 500)) {
				diag(
					"Error: Supplied 'auto_increment_delay_multiplex_timeout_ms' too small: { Act: %d, Min: %ld }",
					_auto_inc_delay_to, poll_timeout + 500
				);
				return EXIT_FAILURE;
			}

			int c_res = check_auto_increment_to(proxy_admin, proxy_mysql, f_auto_incr_val, poll_timeout, _auto_inc_delay_to);
			if (c_res != EXIT_SUCCESS) { return EXIT_FAILURE; }
		}

		// Check that value '0' for 'auto_increment_delay_multiplex_timeout_ms' disables the feature
		int c_res = check_auto_increment_to(proxy_admin, proxy_mysql, f_auto_incr_val, poll_timeout, 0);
		if (c_res != EXIT_SUCCESS) { return EXIT_FAILURE; }
	}

cleanup:

	mysql_close(proxy_admin);
	mysql_close(proxy_mysql);

	return exit_status();
}
