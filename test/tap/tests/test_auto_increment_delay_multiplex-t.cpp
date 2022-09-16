/**
 * @file test_auto_increment_delay_multiplex-t.cpp
 * @brief This test verifies the features 'mysql-auto_increment_delay_multiplex' and
 *  'mysql-auto_increment_delay_multiplex_timeout_ms' is working properly.
 * @details This test checks that:
 *  1. Variables 'mysql-auto_increment_delay_multiplex' and 'mysql-auto_increment_delay_multiplex_timeout_ms'
 *     are present.
 *  2. 'auto_increment_delay_multiplex' behaves properly for different values.
 *  3. 'auto_increment_delay_multiplex_timeout_ms' behaves properly for different values.
 *  4. 'auto_increment_delay_multiplex_timeout_ms' should be delayed by queries in the same hostgroup.
 *  5. 'auto_increment_delay_multiplex_timeout_ms' should not take effect on transactions.
 *  6. 'auto_increment_delay_multiplex_timeout_ms' should not take effect on multiplex dissabling scenarios.
 *     Eg: SET statements that create session variables.
 *  7. Test 'connection_delay_multiplex_ms' retaining and expiring connections
 *  8. Test 'connection_delay_multiplex_ms' integration with multiplexing disabling operations.
 *  9. Test 'connection_delay_multiplex_ms' integration with traffic hitting the session.
 *  10. Test 'connection_delay_multiplex_ms' interaction with 'auto_increment_delay_multiplex_timeout_ms'.
 *
 *  TODO: This test requires a deep rework in order to make the code more clear and structured.
 */

#include <cstring>
#include <chrono>
#include <functional>
#include <vector>
#include <string>
#include <stdio.h>
#include <iostream>

#include <unistd.h>
#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "json.hpp"

#include "command_line.h"
#include "proxysql_utils.h"
#include "utils.h"
#include "tap.h"


using std::function;
using std::string;
using std::vector;
using nlohmann::json;

const char* INSERT_QUERY { "INSERT INTO test.auto_inc_multiplex (c2, c3) VALUES ('foo','bar')" };
const char* CREATE_TABLE_QUERY {
	"CREATE TABLE IF NOT EXISTS test.auto_inc_multiplex "
		"(c1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY, c2 VARCHAR(100), c3 VARCHAR(100))"
};

uint32_t VAL_RANGE = 10;
uint32_t STEP = 5;

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

int get_session_backends(MYSQL* proxy_mysql,vector<json>& out_backend_conns) {
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
		vector<json> _out_conns {};

		for (const auto& j_conn : backend_conns) {
			_out_conns.push_back(j_conn);
		}

		out_backend_conns = _out_conns;
	} catch (const std::exception& ex) {
		const string err_msg {
			string { "Invalid JSON received from 'PROXYSQL INTERNAL SESSION'. Ex: '" } + ex.what()  + "'"
		};
		log_err(err_msg.c_str());
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int check_auto_increment_timeout(
	MYSQL* proxy_admin, MYSQL* proxy_mysql, uint32_t f_auto_incr_val, uint64_t poll_to, uint32_t auto_inc_delay_to
) {
	int cur_auto_inc_delay_mult = 0;
	const string set_auto_inc_to_query {
		"SET mysql-auto_increment_delay_multiplex_timeout_ms=" + std::to_string(auto_inc_delay_to)
	};
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_auto_inc_to_query.c_str());
	MYSQL_QUERY(proxy_admin, set_auto_inc_to_query.c_str());

	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL_QUERY(proxy_mysql, INSERT_QUERY);
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), INSERT_QUERY);

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
			-1 == cur_auto_inc_delay_mult,
			"'auto_increment_delay_token' val should be '-1' after timeout:"
			" { Exp: %d, Act: %d, Timeout: %d, Waited: %d }",
			-1, cur_auto_inc_delay_mult, auto_inc_delay_to, waited
		);
	}

	MYSQL_QUERY(proxy_mysql, "DO 1");
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "DO 1");

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
			"Connection should no longer be attached when 'auto_increment_delay_token' reaches '0': { Exp: %d, Act: %d }",
			-1, cur_auto_inc_delay_mult
		);
	}

	return EXIT_SUCCESS;
};

int check_variables_config(MYSQL* proxy_mysql, MYSQL* proxy_admin) {
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

	return EXIT_SUCCESS;
}

int check_auto_increment_delay_multiplex(MYSQL* proxy_mysql, MYSQL* proxy_admin) {
	// Disable the 'timeout' for the this check since it can be fixated now
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "SET mysql-auto_increment_delay_multiplex_timeout_ms=0");
	MYSQL_QUERY(proxy_admin, "SET mysql-auto_increment_delay_multiplex_timeout_ms=0");
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "SET mysql-connection_delay_multiplex_ms=0");
	MYSQL_QUERY(proxy_admin, "SET mysql-connection_delay_multiplex_ms=0");

	int cur_auto_inc_delay_mult = 0;
	int exp_auto_inc_delay_mult = 0;

	for (uint32_t val = 0; val <= VAL_RANGE; val += STEP) {
		diag("Testing 'mysql-auto_increment_delay_multiplex_timeout_ms' for value '%d'", val);
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

	return EXIT_SUCCESS;
}

int check_auto_increment_delay_multiplex_timeout(MYSQL* proxy_mysql, MYSQL* proxy_admin) {
	// Set the default 'mysql-auto_increment_delay_multiplex' since it's no longer relevant
	const int f_auto_incr_val = 5;
	const string set_auto_inc_query { "SET mysql-auto_increment_delay_multiplex=" + std::to_string(f_auto_incr_val) };
	uint64_t poll_timeout = 0;
	int g_res = 0;

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_auto_inc_query.c_str());
	MYSQL_QUERY(proxy_admin, set_auto_inc_query.c_str());
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "SET mysql-connection_delay_multiplex_ms=0");
	MYSQL_QUERY(proxy_admin, "SET mysql-connection_delay_multiplex_ms=0");

	const string q_poll_timeout { "SELECT variable_value FROM global_variables WHERE variable_name='mysql-poll_timeout'" };
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), q_poll_timeout.c_str());
	g_res = get_query_result(proxy_admin, q_poll_timeout.c_str(), poll_timeout);
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

		int c_res = check_auto_increment_timeout(proxy_admin, proxy_mysql, f_auto_incr_val, poll_timeout, _auto_inc_delay_to);
		if (c_res != EXIT_SUCCESS) { return EXIT_FAILURE; }
	}

	// Check that value '0' for 'auto_increment_delay_multiplex_timeout_ms' disables the feature
	int c_res = check_auto_increment_timeout(proxy_admin, proxy_mysql, f_auto_incr_val, poll_timeout, 0);
	if (c_res != EXIT_SUCCESS) { return EXIT_FAILURE; }

	// Check that using the connection reset the internal timer, keeping the connection attached
	const uint32_t timeout_ms = 2000;
	// Impose a big delay so we are sure only 'timeout' is being relevant
	const uint32_t delay = 100;
	const string timeout_query {
		"SET mysql-auto_increment_delay_multiplex_timeout_ms=" + std::to_string(timeout_ms)
	};
	const string delay_query { "SET mysql-auto_increment_delay_multiplex=" + std::to_string(delay) };
	poll_timeout = 0;
	const string poll_timeout_query {
		"SELECT variable_value FROM global_variables WHERE variable_name='mysql-poll_timeout'"
	};

	g_res = get_query_result(proxy_admin, poll_timeout_query.c_str(), poll_timeout);
	if (g_res != EXIT_SUCCESS) { return EXIT_FAILURE; }

	MYSQL_QUERY(proxy_admin, delay_query.c_str());
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), delay_query.c_str());
	MYSQL_QUERY(proxy_admin, timeout_query.c_str());
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), timeout_query.c_str());
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	{
		// Insert disabling multiplexing for the connection
		diag("%s: Executing query `%s`...", tap_curtime().c_str(), INSERT_QUERY);
		MYSQL_QUERY(proxy_mysql, INSERT_QUERY);

		// Perform queries in the same connection
		diag("Execute queries beyond imposed timeout");
		uint32_t waited = 0;
		while (waited < timeout_ms * 3) {
			sleep(1);

			diag("%s: Executing query `%s`...", tap_curtime().c_str(), "/* hostgroup=0 */ DO 1");
			MYSQL_QUERY(proxy_mysql, "/* hostgroup=0 */ DO 1");
			waited += 1000;
		}

		int cur_delay = 0;
		int g_res = get_conn_auto_inc_delay_token(proxy_mysql, cur_delay);
		if (g_res != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		uint32_t exp_delay = delay - (waited/1000);
		ok(
			exp_delay == cur_delay,
			"Connection was kept after timeout due to queries issues in the same hostgroup:"
			" 'auto_increment_delay_multiplex' - Exp: '%d', Act: '%d'",
			exp_delay, cur_delay
		);

		waited = 0;
		// Perform queries in other connections
		while (waited < timeout_ms * 3) {
			sleep(1);

			diag("%s: Executing query `%s`...", tap_curtime().c_str(), "SELECT 1");
			MYSQL_QUERY(proxy_mysql, "SELECT 1");
			mysql_free_result(mysql_store_result(proxy_mysql));

			waited += 1000;
			// After this time the connection should have timeout already
			if (waited > timeout_ms + poll_timeout + 500) {
				break;
			}
		}

		cur_delay = 0;
		g_res = get_conn_auto_inc_delay_token(proxy_mysql, cur_delay);
		if (g_res != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		ok(
			-1 == cur_delay,
			"Connection returned to connpool when queries are issued in different hostgroup - Exp: '%d', Act: '%d'",
			-1, cur_delay
		);
	}

	// Transactions connections should be preserved by 'auto_increment_delay_multiplex_timeout_ms'
	{
		diag("%s: Executing query `%s`...", tap_curtime().c_str(), "BEGIN");
		MYSQL_QUERY(proxy_mysql, "BEGIN");
		diag("%s: Executing query `%s`...", tap_curtime().c_str(), INSERT_QUERY);
		MYSQL_QUERY(proxy_mysql, INSERT_QUERY);

		// Wait for the timeout and check the value
		diag("%s: Waiting for timeout to expire...", tap_curtime().c_str());
		usleep(timeout_ms * 1000 + poll_timeout * 1000 + 500 * 1000 * 2);

		diag("%s: Extracting current auto inc delay...", tap_curtime().c_str());
		int cur_delay = 0;
		int g_res = get_conn_auto_inc_delay_token(proxy_mysql, cur_delay);
		if (g_res != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		ok(
			delay == cur_delay,
			"Connection should not be returned to conn_pool due to transaction - Exp: '%d', Act: '%d'",
			delay, cur_delay
		);

		diag("%s: Executing query `%s`...", tap_curtime().c_str(), "COMMIT");
		MYSQL_QUERY(proxy_mysql, "COMMIT");

		diag("%s: Waiting for timeout to expire...", tap_curtime().c_str());
		usleep(timeout_ms * 1000 + poll_timeout * 1000 + 500 * 1000 * 2);

		diag("%s: Extracting current auto inc delay...", tap_curtime().c_str());
		cur_delay = 0;
		g_res = get_conn_auto_inc_delay_token(proxy_mysql, cur_delay);
		if (g_res != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		ok(
			-1 == cur_delay,
			"Connection should be returned to conn_pool after 'COMMIT' and 'timeout' wait - Exp: '%d', Act: '%d'",
			-1, cur_delay
		);
	}

	// Multiplex disabled by any action should take precedence over 'auto_increment_delay_multiplex_timeout_ms'
	{
		const char* set_query { "SET @local_var='foo'" };
		diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_query);
		MYSQL_QUERY(proxy_mysql, set_query);
		diag("%s: Executing query `%s`...", tap_curtime().c_str(), INSERT_QUERY);
		MYSQL_QUERY(proxy_mysql, INSERT_QUERY);

		// Wait for the timeout and check the value
		diag("%s: Waiting for timeout to expire...", tap_curtime().c_str());
		usleep(timeout_ms * 1000 + poll_timeout * 1000 + 500 * 1000 * 2);

		diag("%s: Extracting current auto inc delay...", tap_curtime().c_str());
		int cur_delay = 0;
		int g_res = get_conn_auto_inc_delay_token(proxy_mysql, cur_delay);
		if (g_res != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		ok(
			delay == cur_delay,
			"Connection should not be returned to conn_pool due to SET session var - Exp: '%d', Act: '%d'",
			delay, cur_delay
		);

		// A new connection is required after multiplexing is disabled by local session variables
		mysql_close(proxy_mysql);
	}

	return EXIT_SUCCESS;
}

typedef std::chrono::high_resolution_clock hrc;

void check_connection_retained(MYSQL* proxy_mysql, uint32_t exp_conns) {
	vector<json> j_sess_backends {};

	diag("Extracting info from 'PROXYSQL INTERNAL SESSION'");
	int g_res = get_session_backends(proxy_mysql, j_sess_backends);
	if (g_res != EXIT_SUCCESS) {
		diag("Failed to optain info from 'PROXYSQL INTERNAL SESSION'");
	}

	uint32_t backend_conns = 0;
	for (const json& j_sess_backend : j_sess_backends) {
		if (j_sess_backend.find("conn") != j_sess_backend.end()) {
			backend_conns += 1;
		}
	}

	if (exp_conns > 0) {
		ok(
			backend_conns == exp_conns,
			"Backend connection should be RETAINED - NumBackendConns: '%d'",
			backend_conns
		);
	} else {
		ok(
			backend_conns == exp_conns,
			"Backend connection should be RETURNED - NumBackendConns: '%d'",
			backend_conns
		);
	}
};

int check_transactions_and_multiplex_disable(
	MYSQL* proxy_mysql, const char* query, const uint32_t timeout, uint64_t poll_timeout=2
) {
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "BEGIN");
	MYSQL_QUERY(proxy_mysql, "BEGIN");
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), query);
	MYSQL_QUERY(proxy_mysql, query);

	diag("Checking connection present before timeout...");
	check_connection_retained(proxy_mysql, 1);

	diag("Sleeping for '%ld' seconds", timeout + poll_timeout);
	sleep(timeout + poll_timeout);

	diag("Checking connection is still present after timeout due to transaction...");
	check_connection_retained(proxy_mysql, 1);

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "COMMIT");
	MYSQL_QUERY(proxy_mysql, "COMMIT");

	diag("Sleeping for '%lf' seconds", timeout / 2.0);
	sleep(timeout / 2.0);

	diag("Checking connection is present after 'COMMIT' due to timeout...");
	check_connection_retained(proxy_mysql, 1);

	diag("Sleeping for '%ld' seconds", timeout + poll_timeout);
	sleep(timeout + poll_timeout);

	diag("Checking connection is RETURNED after 'COMMIT' and after timeout...");
	check_connection_retained(proxy_mysql, 0);

	diag("Checking multiplex disabled by any action take precedence over 'connection_delay_multiplex_ms'...");

	const char* set_query { "SET @local_var='foo'" };
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_query);
	MYSQL_QUERY(proxy_mysql, set_query);

	diag("Sleeping for '%ld' seconds", timeout + poll_timeout);
	sleep(timeout + poll_timeout);

	check_connection_retained(proxy_mysql, 1);

	return EXIT_SUCCESS;
}


int check_connection_delay_multiplex_ms(MYSQL* proxy_mysql, MYSQL* proxy_admin) {
	std::chrono::nanoseconds duration;
	hrc::time_point start;
	hrc::time_point end;

	const uint32_t timeout = 3;
	string set_delay_multiplex {};
	string_format("SET mysql-connection_delay_multiplex_ms=%d", set_delay_multiplex, timeout * 1000);
	const char* set_auto_inc_delay { "SET mysql-auto_increment_delay_multiplex_timeout_ms=0" };

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_delay_multiplex.c_str());
	MYSQL_QUERY(proxy_admin, set_delay_multiplex.c_str());

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_auto_inc_delay);
	MYSQL_QUERY(proxy_admin, set_auto_inc_delay);

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL_QUERY(proxy_mysql, "SELECT 1");
	mysql_free_result(mysql_store_result(proxy_mysql));

	start = hrc::now();

	check_connection_retained(proxy_mysql, 1);
	diag("Sleeping for '%d' seconds", 2);
	sleep(2);

	end = hrc::now();
	duration = end - start;

	double waited = duration.count() / pow(10, 9);
	if (waited < 3) {
		diag("Performing second check after '%lf' waited seconds...", waited);
		check_connection_retained(proxy_mysql, 1);
	} else {
		diag("Second check can't be performed due to timeout already expired.");
	}

	diag("Sleeping for '%d' seconds", 2);
	sleep(2);
	waited += 2;

	diag("Performing third check after '%lf' waited seconds...", waited);
	check_connection_retained(proxy_mysql, 0);

	return EXIT_SUCCESS;
}

int check_multiplex_disabled_connection_delay_multiplex_ms(MYSQL* proxy_mysql, MYSQL* proxy_admin) {
	const uint32_t timeout = 2;
	string set_delay_multiplex {};
	string_format("SET mysql-connection_delay_multiplex_ms=%d", set_delay_multiplex, timeout * 1000);
	const char* set_auto_inc_delay { "SET mysql-auto_increment_delay_multiplex_timeout_ms=0" };

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_delay_multiplex.c_str());
	MYSQL_QUERY(proxy_admin, set_delay_multiplex.c_str());

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_auto_inc_delay);
	MYSQL_QUERY(proxy_admin, set_auto_inc_delay);

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Check transactions behavior and multiplex disabling actions
	check_transactions_and_multiplex_disable(proxy_mysql, "DO 1", timeout);

	return EXIT_SUCCESS;
}

int check_traffic_connection_delay_multiplex_ms(MYSQL* proxy_mysql, MYSQL* proxy_admin) {
	const uint32_t timeout = 2;
	const char* set_delay_multiplex_query { "SET mysql-connection_delay_multiplex_ms=2000" };
	const char* set_auto_inc_timeout_query { "SET mysql-auto_increment_delay_multiplex_timeout_ms=0" };

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_delay_multiplex_query);
	MYSQL_QUERY(proxy_admin, set_delay_multiplex_query);
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_auto_inc_timeout_query);
	MYSQL_QUERY(proxy_admin, set_auto_inc_timeout_query);
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Retain connection in 'hg=0'
	diag("Checking connection not expiring with traffic on same hostgroup...");

	uint32_t waited = 0;
	while (waited < 2*timeout) {
		diag("%s: Executing query `%s`...", tap_curtime().c_str(), "DO 1");
		MYSQL_QUERY(proxy_mysql, "DO 1");

		sleep(1);
		waited += 1;
	}
	check_connection_retained(proxy_mysql, 1);

	diag("Check connection expiring when traffic stops to the hostgroup...");
	diag("Sleeping for '%d' seconds", timeout + 1);
	sleep(timeout + 1);
	check_connection_retained(proxy_mysql, 0);

	diag("Check connection expiring when traffic issued to different hostgroup...");

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "DO 1");
	MYSQL_QUERY(proxy_mysql, "DO 1");
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "SELECT 1");
	MYSQL_QUERY(proxy_mysql, "SELECT 1");
	mysql_free_result(mysql_store_result(proxy_mysql));

	diag("* First check that connections from both hostgroups have been retained before timeout");

	diag("Sleeping '%d' seconds...", 1);
	sleep(1);

	{
		vector<json> j_sess_backends {};
		int b_conns_res = get_session_backends(proxy_mysql, j_sess_backends);
		if (b_conns_res != EXIT_SUCCESS) {
			return b_conns_res;
		}

		vector<int32_t> hg_ids {};

		for (const json& j_backend : j_sess_backends) {
			if (j_backend.find("hostgroup_id") != j_backend.end() && j_backend.find("conn") != j_backend.end()) {
				hg_ids.push_back(j_backend.at("hostgroup_id").get<int32_t>());
			}
		}

		bool hgs_found =
			std::find(hg_ids.begin(), hg_ids.end(), 0) != hg_ids.end() &&
			std::find(hg_ids.begin(), hg_ids.end(), 1) != hg_ids.end();

		ok(
			hgs_found && hg_ids.size() == 2,
			"Found expected retained connections in target hgs - hostgroups: '%s'",
			json { hg_ids }.dump().c_str()
		);
	}

	// Check for connections retained in 'hg 0'
	waited = 0;
	while (waited < timeout * 2) {
		diag("%s: Executing query `%s`...", tap_curtime().c_str(), "SELECT 1");
		MYSQL_QUERY(proxy_mysql, "SELECT 1");
		mysql_free_result(mysql_store_result(proxy_mysql));

		sleep(1);
		waited += 1;
	}

	diag("* Check that connections from hostgroup '0' (not traffic) is expired after timeout");

	{
		vector<json> j_sess_backends {};
		int b_conns_res = get_session_backends(proxy_mysql, j_sess_backends);
		if (b_conns_res != EXIT_SUCCESS) {
			return b_conns_res;
		}

		vector<int32_t> hg_ids {};

		for (const json& j_backend : j_sess_backends) {
			if (j_backend.find("hostgroup_id") != j_backend.end() && j_backend.find("conn") != j_backend.end()) {
				hg_ids.push_back(j_backend.at("hostgroup_id").get<int32_t>());
			}
		}

		bool hgs_found = std::find(hg_ids.begin(), hg_ids.end(), 1) != hg_ids.end();

		ok(
			hgs_found && hg_ids.size() == 1,
			"Found expected retained connections in target hgs - hostgroups: '%s'",
			json { hg_ids }.dump().c_str()
		);
	}

	return EXIT_SUCCESS;
}

int check_auto_inc_delay_and_conn_delay_multiplex(MYSQL* proxy_mysql, MYSQL* proxy_admin) {
	uint64_t poll_timeout = 0;
	const string poll_timeout_query { "SELECT variable_value FROM global_variables WHERE variable_name='mysql-poll_timeout'" };
	string auto_inc_timeout_query {};

	int g_res = get_query_result(proxy_admin, poll_timeout_query.c_str(), poll_timeout);
	if (g_res != EXIT_SUCCESS) { return EXIT_FAILURE; }

	const uint32_t timeout = 2;
	const char* set_delay_multiplex_query { "SET mysql-connection_delay_multiplex_ms=2000" };
	const char* set_auto_inc_timeout_query { "SET mysql-auto_increment_delay_multiplex_timeout_ms=0" };

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_delay_multiplex_query);
	MYSQL_QUERY(proxy_admin, set_delay_multiplex_query);
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_auto_inc_timeout_query);
	MYSQL_QUERY(proxy_admin, set_auto_inc_timeout_query);
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Retain connection in 'hg=0'
	diag("Checking connection not expiring due to 'auto_increment_delay_multiplex'.");

	uint32_t waited = 0;
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), INSERT_QUERY);
	MYSQL_QUERY(proxy_mysql, INSERT_QUERY);

	diag("* Check connection retained after executing the query");
	check_connection_retained(proxy_mysql, 1);

	diag("* Check connection NOT expiring after imposed timeout '%d'.", timeout);
	diag("Sleeping for '%d' seconds", timeout + 1);
	sleep(timeout + 1);

	check_connection_retained(proxy_mysql, 1);

	diag(
		"Checking interaction with 'auto_increment_delay_multiplex_timeout_ms' -"
		" 'auto_increment_delay_multiplex_timeout_ms' is the higher value"
	);

	string_format("SET mysql-auto_increment_delay_multiplex_timeout_ms=%d", auto_inc_timeout_query, timeout*2*1000);
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), auto_inc_timeout_query.c_str());
	MYSQL_QUERY(proxy_admin, auto_inc_timeout_query.c_str());

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), INSERT_QUERY);
	MYSQL_QUERY(proxy_mysql, INSERT_QUERY);

	diag("Sleeping for '%d' seconds", timeout + 1);
	sleep(timeout + 1);

	diag(
		"Connection SHOULDN'T be returned due because:"
			" auto_increment_delay_multiplex_timeout_ms='%d', connection_delay_multiplex_ms='%d', waited='%d'",
		timeout*2, timeout, timeout + 1
	);

	check_connection_retained(proxy_mysql, 1);

	diag("Sleeping for '%d' seconds", timeout + 1);
	sleep(timeout + 1 );

	diag(
		"Connection SHOULD be returned due because:"
			" auto_increment_delay_multiplex_timeout_ms='%d', connection_delay_multiplex_ms='%d', waited='%d'",
		timeout*2, timeout, (timeout + 1) * 2
	);

	check_connection_retained(proxy_mysql, 0);

	diag(
		"Checking interaction with 'auto_increment_delay_multiplex_timeout_ms' -"
		" 'auto_increment_delay_multiplex_timeout_ms' is the smaller value. Higher value should prevail."
	);

	string_format("SET mysql-auto_increment_delay_multiplex_timeout_ms=%d", auto_inc_timeout_query, timeout*1000);
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), auto_inc_timeout_query.c_str());
	MYSQL_QUERY(proxy_admin, auto_inc_timeout_query.c_str());

	const char* set_delay_multiplex_query_2 { "SET mysql-connection_delay_multiplex_ms=4000" };
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), set_delay_multiplex_query_2);
	MYSQL_QUERY(proxy_admin, set_delay_multiplex_query_2);

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), INSERT_QUERY);
	MYSQL_QUERY(proxy_mysql, INSERT_QUERY);

	diag("Sleeping for '%d' seconds", timeout + 1);
	sleep(timeout + 1);

	diag(
		"Connection SHOULDN'T be returned due because:"
			" auto_increment_delay_multiplex_timeout_ms='%d', connection_delay_multiplex_ms='%d', waited='%d'",
		timeout*2*1000, timeout*1000, timeout + 1
	);

	check_connection_retained(proxy_mysql, 1);

	diag("Sleeping for '%d' seconds", timeout + 1);
	sleep(timeout + 1);

	diag(
		"Connection SHOULD be returned due because:"
			" auto_increment_delay_multiplex_timeout_ms='%d', connection_delay_multiplex_ms='%d', waited='%d'",
		timeout*2*1000, timeout*1000, (timeout + 1) * 2
	);

	check_connection_retained(proxy_mysql, 0);

	// Check transactions behavior and multiplex disabling actions with both 'connection_delay_multiplex_ms'
	// and 'auto_increment_delay_multiplex_timeout_ms' enabled.
	uint64_t higher_timeout = 4;
	check_transactions_and_multiplex_disable(proxy_mysql, INSERT_QUERY, higher_timeout);

	return EXIT_SUCCESS;
}

const vector<function<int(MYSQL*, MYSQL*)>> auto_increment_delay_multiplex_tests {
	// 1. Check that the required variables are present
	check_variables_config,
	// 2. Change and check 'auto_increment_delay_multiplex' behavior
	check_auto_increment_delay_multiplex,
	// 3. Change and check 'auto_increment_delay_multiplex_timeout_ms' behavior
	check_auto_increment_delay_multiplex_timeout
};

const vector<function<int(MYSQL*, MYSQL*)>> conn_delay_multiplex_tests {
	// 4. Test 'connection_delay_multiplex_ms' retaining and expiring connections
	check_connection_delay_multiplex_ms,
	// 5. Test 'connection_delay_multiplex_ms' integration with multiplexing disabling operations.
	check_multiplex_disabled_connection_delay_multiplex_ms,
	// 5. Test 'connection_delay_multiplex_ms' integration with traffic hitting the session.
	check_traffic_connection_delay_multiplex_ms,
	// 7. Test 'connection_delay_multiplex_ms' interaction with 'auto_increment_delay_multiplex_timeout_ms'
	check_auto_inc_delay_and_conn_delay_multiplex
};

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
		3 + // Tests for 'auto_increment_delay_multiplex_timeout_ms' zero value
		2 + // Tests for 'auto_increment_delay_multiplex_timeout_ms' keep alive queries
		2 + // Tests for 'auto_increment_delay_multiplex_timeout_ms' transaction behavior
		1 + // Tests for 'auto_increment_delay_multiplex_timeout_ms' multiplex disabled by SET statement
		23  // Tests for 'connection_delay_multiplex_ms' and also tests for
			// integration with 'auto_increment_delay_multiplex_timeout_ms'.
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
	MYSQL_QUERY(proxy_mysql, CREATE_TABLE_QUERY);

	for (const function<int(MYSQL*, MYSQL*)>& test : auto_increment_delay_multiplex_tests) {
		if (test(proxy_mysql, proxy_admin) != EXIT_SUCCESS) {
			break;
		}
	}

	mysql_close(proxy_admin);

	for (const function<int(MYSQL*, MYSQL*)>& test : conn_delay_multiplex_tests) {
		proxy_mysql = mysql_init(NULL);
		proxy_admin = mysql_init(NULL);

		if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: \"%s\"\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
			return EXIT_FAILURE;
		}
		if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: \"%s\"\n", __FILE__, __LINE__, mysql_error(proxy_admin));
			return EXIT_FAILURE;
		}

		test(proxy_mysql, proxy_admin);

		mysql_close(proxy_admin);
		mysql_close(proxy_mysql);
	}

cleanup:

	return exit_status();
}
