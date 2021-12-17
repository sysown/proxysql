/**
 * @file test_qps_limit_rules-t.cpp
 * @brief This test verifies the implementation of 'qps_limit_rules'.
 * @details The following checks are performed:
 *   - Test 1: Open several connections to ProxySQL using the same user, perform multiple queries per
 *     connections checking that:
 *       1. The rate is stable and matches the target value.
 *       2. It's evenly distributed between connections.
 *   - Test 2: Test that different sets of rules are updated and matched as expected. WIP
 */

#include <chrono>
#include <cstring>
#include <future>
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <stdio.h>
#include <tuple>
#include <thread>
#include <mutex>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "proxysql_utils.h"
#include "command_line.h"
#include "utils.h"

using std::map;
using std::string;
using std::vector;
using std::tuple;

using hrc = std::chrono::high_resolution_clock;

map<string,vector<string>> fetch_row_values_(MYSQL_RES* res) {
	map<string, vector<string>> row_map {};

	if (res == NULL) {
		return row_map;
	}

	std::vector<std::string> field_names {};

	MYSQL_ROW row = nullptr;
	int num_fields = mysql_num_fields(res);
	MYSQL_FIELD* fields = mysql_fetch_fields(res);

	for(int i = 0; i < num_fields; i++) {
		row_map.insert({string { fields[i].name }, vector<string> {}});
	}

	while ((row = mysql_fetch_row(res))) {
		for(int i = 0; i < num_fields; i++) {
			string field_name { fields[i].name };

			if (row[i]) {
				row_map[field_name].push_back(row[i]);
			} else {
				row_map[field_name].push_back("");
			}
		}
	}

	return row_map;
}

struct conn_opts {
	string host;
	string user;
	string pass;
	int port;
};

int create_connections(const conn_opts& conn_opts, uint32_t cons_num, std::vector<MYSQL*>& proxy_conns) {
	std::vector<MYSQL*> result {};

	for (uint32_t i = 0; i < cons_num; i++) {
		MYSQL* proxysql_mysql = mysql_init(NULL);

		if (
			!mysql_real_connect(
				proxysql_mysql, conn_opts.host.c_str(), conn_opts.user.c_str(), conn_opts.pass.c_str(),
				NULL, conn_opts.port, NULL, 0
			)
		) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return EXIT_FAILURE;
		} else {
			result.push_back(proxysql_mysql);
		}
	}

	proxy_conns = result;
	return EXIT_SUCCESS;
}

const string t_qps_limit_rule {
	"INSERT INTO mysql_qps_limit_rules (username, schemaname, flagIN, qps_limit, bucket_size)"
	" VALUES ('%s', '%s', %d, %d, %d)"
};

int conn_query_executor(
	MYSQL* proxysql, const string query, const uint64_t delay_ms, uint64_t* query_count, bool* stop
) {
	usleep(delay_ms * 1000);

	while(__sync_fetch_and_add((char*)stop, 0) == 0) {
		MYSQL_QUERY(proxysql, query.c_str());
		MYSQL_RES* myres = mysql_use_result(proxysql);
		if (myres != nullptr) { mysql_free_result(myres); }
		__sync_fetch_and_add(query_count, 1);
	}

	return EXIT_SUCCESS;
}

double ret_expected_qps(const int64_t qps_limit, const uint64_t burst_size, double time) {
	if (time == 0) { return 0; }
	return ((qps_limit + burst_size) + (qps_limit * (time - 1))) / time;
}

int check_single_conn_qps_limits_count(MYSQL* proxysql, const int64_t qps_limit, const uint64_t burst_size) {
	double CONN_TIME = 2.0;
	double WAIT_TIME_US = CONN_TIME*pow(10, 6);

	uint64_t query_count = 0;
	bool stop = 0;

	std::chrono::nanoseconds duration;
	hrc::time_point start = hrc::now();

	auto future = std::async(conn_query_executor, proxysql, "SELECT 1", 0, &query_count, &stop);

	usleep(WAIT_TIME_US);
	__sync_fetch_and_add((char*)&stop, 1);
	int conn_res = future.get();

	hrc::time_point end = hrc::now();
	duration = end - start;

	double duration_s = duration.count() / pow(10,9);
	double duration_epsilon = (duration_s * 10) / 100;
	double wait_time_s = WAIT_TIME_US / pow(10, 6);

	diag("Global duration check for stalling detection: { duration: '%lf' }", duration_s);
	ok(
		conn_res == EXIT_SUCCESS &&
		duration_s > (wait_time_s - duration_epsilon) && duration_s < (wait_time_s + duration_epsilon),
		"Queries execution duration: { exp_duration: '%lf', act_duration: '%lf', epsilon: '%lf' }",
		wait_time_s, duration_s, duration_epsilon
	);

	double expected_qps = ret_expected_qps(qps_limit, burst_size, CONN_TIME);
	uint32_t EPSILON = (expected_qps * 15) / 100;

	ok(
		conn_res == EXIT_SUCCESS &&
		(query_count / CONN_TIME) > expected_qps - EPSILON && (query_count / CONN_TIME) < expected_qps + EPSILON,
		"Expected QPS for single conn:"
		" { err: '%d', burst_size: '%ld', QPS_Limit: '%ld', Exp_QPS: '%lf', QPS: '%lf', EPSILON: '%d' }",
		conn_res, burst_size, qps_limit, expected_qps, query_count / CONN_TIME, EPSILON
	);
	diag("");

	return EXIT_SUCCESS;
}

int check_multi_conn_qps_limits_count(vector<MYSQL*> conns, const int64_t qps_limit, const uint64_t burst_size) {
	uint32_t init_delay = 500;
	double CONN_TIME = 10.0;
	double WAIT_TIME_US = CONN_TIME*pow(10, 6) + init_delay*1000;

	vector<std::future<int>> conns_ths {};
	vector<uint64_t> conns_count(conns.size(), { 0 });
	bool stop = 0;
	size_t conn_pos = 0;

	std::chrono::nanoseconds duration;
	hrc::time_point start = hrc::now();

	for (MYSQL* conn : conns) {
		conns_ths.push_back(std::async(
			conn_query_executor, conn, "SELECT 1", init_delay, &conns_count[conn_pos], &stop
		));

		conn_pos += 1;
	}

	usleep(WAIT_TIME_US);
	__sync_fetch_and_add((char*)&stop, 1);

	int conns_res = EXIT_SUCCESS;
	for (std::future<int>& conn_th : conns_ths) {
		if (conn_th.valid()) {
			conns_res |= conn_th.get();
		} else {
			conns_res |= EXIT_FAILURE;
		}
	}

	hrc::time_point end = hrc::now();
	duration = end - start;

	double duration_s = duration.count() / pow(10,9);
	double duration_epsilon = (duration_s * 10) / 100;
	double wait_time_s = WAIT_TIME_US / pow(10, 6);

	diag("Global duration check for stalling detection: { duration: '%lf' }", duration_s);
	ok(
		conns_res == EXIT_SUCCESS &&
		duration_s > (wait_time_s - duration_epsilon) && duration_s < (wait_time_s + duration_epsilon),
		"Queries execution duration: { exp_duration: '%lf', act_duration: '%lf', epsilon: '%lf' }",
		wait_time_s, duration_s, duration_epsilon
	);

	size_t conn_num = 0;
	uint64_t total_query_count = 0;
	for (uint64_t query_count : conns_count) {
		double expected_qps = ret_expected_qps(qps_limit, burst_size, CONN_TIME) / conns.size();
		uint32_t EPSILON = (expected_qps * 15) / 100;

		bool condition =
			conns_res == EXIT_SUCCESS &&
			(query_count / CONN_TIME) > expected_qps - EPSILON && (query_count / CONN_TIME) < expected_qps + EPSILON;

		ok(
			condition,
			"Expected QPS for conn_num '%ld':"
			" { err: '%d', burst_size: '%ld', QPS_Limit: '%ld', Exp_QPS: '%lf', QPS: '%lf', EPSILON: '%d' }",
			conn_num, conns_res, burst_size, qps_limit, expected_qps, query_count / CONN_TIME, EPSILON
		);

		conn_num += 1;
		total_query_count += query_count;
	}
	diag("Total query count: '%d'\n", total_query_count);
	diag("");

	return EXIT_SUCCESS;
}

using qps_limit = uint64_t;
using burst_size = uint64_t;
using std::pair;

const vector<pair<qps_limit,burst_size>> tests_payloads {
	// { 1000, 20 }, { 1000, 50 }, { 1000, 100 },
	// { 1000, 150 }, { 1000, 500 }, { 1000, 500 },
	{ 1500, 1600 }, { 2000, 2000 }, { 2000, 3000 },
};

int main(int argc, char** argv) {
	CommandLine cl;

	plan(tests_payloads.size() * 5);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	// Test 1: a) Check QPS limitation holds for a single connection
	/*
	{
		const string TEST_USER { "sbtest1" };
		const string TEST_PASS { "sbtest1" };

		MYSQL* proxysql = mysql_init(NULL);
		if (!mysql_real_connect(proxysql, cl.host, TEST_USER.c_str(), TEST_PASS.c_str(), NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
			return EXIT_FAILURE;
		}

		for (const auto& test_payload : tests_payloads) {
			uint32_t qps_limit = test_payload.first;
			uint32_t burst_size = test_payload.second;

			// Setup 'qps_limit_rules'
			string user_limit_rule {};
			string_format(t_qps_limit_rule, user_limit_rule, TEST_USER.c_str(), "", 0, qps_limit, burst_size);

			MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_qps_limit_rules");
			MYSQL_QUERY(proxysql_admin, user_limit_rule.c_str());
			MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

			// Give at least 1s between executions
			usleep(1000 * 1000);

			int test_rc = check_single_conn_qps_limits_count(proxysql, qps_limit, burst_size);
			if (test_rc != EXIT_SUCCESS) { return EXIT_FAILURE; }
		}

		mysql_close(proxysql);

		// Give some time for the update
		usleep(500 * 1000);
	}
	*/

	// Test 1: b) Check that:
	//   1. For multiple connections the rate is stable and matches the target value.
	//   2. It's evenly distributed between multiple connections.
	{
		const string TEST_USER { "sbtest1" };
		const string TEST_PASS { "sbtest1" };

		conn_opts conn_opts { cl.host, TEST_USER, TEST_PASS, cl.port };
		for (int i = 9; i < 10; i++) {
			vector<MYSQL*> conns {};
			int conns_err = create_connections(conn_opts, i, conns);
			if (conns_err != EXIT_SUCCESS) { return EXIT_FAILURE; }

			for (const auto& test_payload : tests_payloads) {
				uint32_t qps_limit = test_payload.first;
				uint32_t burst_size = test_payload.second;

				// Setup 'qps_limit_rules'
				string user_limit_rule {};
				string_format(t_qps_limit_rule, user_limit_rule, TEST_USER.c_str(), "", 0, qps_limit, burst_size);

				MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_qps_limit_rules");
				MYSQL_QUERY(proxysql_admin, user_limit_rule.c_str());
				MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

				// Give at least 1s between executions
				usleep(1000 * 1000);

				int test_rc = check_multi_conn_qps_limits_count(conns, qps_limit, burst_size);
				if (test_rc != EXIT_SUCCESS) { return EXIT_FAILURE; }
			}

			for (MYSQL* conn : conns) {
				mysql_close(conn);
			}
		}
	}

	// Test 2: WIP

	mysql_close(proxysql_admin);

	return exit_status();
}
