/**
 * @file test_qps_limit_rules-t.cpp
 * @brief This test verifies the implementation of 'qps_limit_rules'.
 * @details The following checks are performed:
 *   - Test 1: Checks that QPS limitation holds for a single connection.
 *   - Test 2: Checks that:
 *       1. For multiple connections the rate is stable and matches the target value.
 *       2. It's evenly distributed between multiple connections.
 *       3. The target global value of QPS matches the expected one, taking into account initial burst.
 *       4. Completion of all queries is performed within the expected time interval, no query stalling took
 *          place.
 *   - Test 3: Checks that the QPS converge to the stablished limit within the expected time period after changing
 *     the QPS limit and number of connections doesn't affect the outcome. Connections creation and query limits
 *     are changed while serving traffic.
 *   - Test 4: Checks that the different QPS limit configurations work as expected.
 *       1. Creates three different rules for three different users.
 *       2. Checks in different connections that the imposed rules are holding.
 *       3. Populates 'mysql_qps_limit_rules' table with unused rules to force hashmap resizing. This tests
 *       the changes performed to 'khash' value initialization for smart pointers.
 *   - Test 5: Checks that '0' is a valid QPS value, and that when set connections matching the rules stall
 *     until limit is changed, or removed.
 */

#include <algorithm>
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

using std::string;
using std::vector;
using std::tuple;

using hrc = std::chrono::high_resolution_clock;

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

const string t_update_qps_limit_rule {
	"UPDATE mysql_qps_limit_rules SET qps_limit=%d, bucket_size=%d WHERE username='%s' AND schemaname='%s' AND flagIN='%d'"
};

int conn_query_executor(
	MYSQL* proxysql, const string query, const uint64_t delay_ms, uint64_t* query_count, char* stop
) {
	usleep(delay_ms * 1000);

	while(__sync_fetch_and_add(stop, 0) == 0) {
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

int stop_workers(
	vector<MYSQL*>& cur_conns, vector<std::future<int>>& workers, vector<uint64_t>& query_counts,
	vector<char>& stop_flags, uint32_t workers_num
) {
	if (query_counts.size() != stop_flags.size()) { return EXIT_FAILURE; }

	uint32_t cur_worker_num = workers.size() - 1;
	uint32_t rc_code = 0;

	for (uint32_t i = 0; i < workers_num; i++) {
		std::future<int>& worker = workers[cur_worker_num - i];
		MYSQL* conn = cur_conns[cur_worker_num - i];
		stop_flags[cur_worker_num - i] = 1;
		query_counts[cur_worker_num - i] = 0;

		rc_code |= worker.get();
		mysql_close(conn);
		cur_conns.pop_back();
		workers.pop_back();

		if (rc_code != EXIT_SUCCESS) {
			break;
		}
	}

	return rc_code;
}

int add_workers(
	const conn_opts& conn_opts, const string& query, vector<MYSQL*>& cur_conns, vector<std::future<int>>& workers,
	vector<uint64_t>& query_counts, vector<char>& stop_flags, uint32_t workers_num
) {
	if (query_counts.size() != stop_flags.size()) { return EXIT_FAILURE; }

	uint32_t worker_num = 0;
	uint32_t rc_code = 0;

	vector<MYSQL*> conns {};
	rc_code = create_connections(conn_opts, workers_num, conns);
	if (rc_code != EXIT_SUCCESS) { return rc_code; }

	for (MYSQL* conn : conns) {
		worker_num = workers.size();
		if (worker_num > query_counts.size()) {
			rc_code = 2;
			break;
		} else {
			workers.push_back(
				std::async(
					conn_query_executor, conn, query, 0, &query_counts[worker_num], &stop_flags[worker_num]
				)
			);
		}
	}

	cur_conns.insert(cur_conns.end(), conns.begin(), conns.end());

	return rc_code;
}

int check_single_conn_qps_limits_count(
	MYSQL* proxysql, const string query, const int64_t qps_limit, const uint64_t burst_size
) {
	double CONN_TIME = 2.0;
	double WAIT_TIME_US = CONN_TIME*pow(10, 6);

	uint64_t query_count = 0;
	char stop = 0;

	std::chrono::nanoseconds duration;
	hrc::time_point start = hrc::now();

	auto future = std::async(conn_query_executor, proxysql, query, 0, &query_count, &stop);

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
	double CONN_TIME = 5.0;
	double WAIT_TIME_US = CONN_TIME*pow(10, 6) + init_delay*1000;

	vector<std::future<int>> conns_ths {};
	vector<uint64_t> conns_count(conns.size(), { 0 });
	char stop = 0;
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
	__sync_fetch_and_add(&stop, 1);

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
		double exp_conn_qps = ret_expected_qps(qps_limit, burst_size, CONN_TIME) / conns.size();
		uint32_t conn_epsilon = (exp_conn_qps * 25) / 100;

		bool condition =
			conns_res == EXIT_SUCCESS &&
			(query_count / CONN_TIME) > exp_conn_qps - conn_epsilon && (query_count / CONN_TIME) < exp_conn_qps + conn_epsilon;

		ok(
			condition,
			"Expected QPS for conn_num '%ld':"
			" { err: '%d', burst_size: '%ld', QPS_Limit: '%ld', Exp_QPS: '%lf', QPS: '%lf', EPSILON: '%d' }",
			conn_num, conns_res, burst_size, qps_limit, exp_conn_qps, query_count / CONN_TIME, conn_epsilon
		);

		conn_num += 1;
		total_query_count += query_count;
	}

	double exp_qps = ret_expected_qps(qps_limit, burst_size, CONN_TIME);
	double total_qps = total_query_count / CONN_TIME;
	double total_qps_epsilon = (qps_limit * 10) / 100.0;

	ok(
		total_qps > exp_qps - total_qps_epsilon && total_qps < exp_qps + total_qps_epsilon,
		"Averall QPS: { Total_Queries: '%ld', Exp_QPS: '%lf', QPS: '%lf', Epsilon: '%lf' }",
		total_query_count, exp_qps, total_qps, total_qps_epsilon
	);
	diag("");

	return EXIT_SUCCESS;
}

int check_multi_conn_qps_limits_conv(vector<MYSQL*> conns, const int64_t qps_limit, const uint64_t burst_size) {
	uint32_t init_delay = 500;
	double CONN_TIME = 5.0;
	double WAIT_TIME_US = CONN_TIME*pow(10, 6) + init_delay*1000;

	vector<std::future<int>> conns_ths {};
	vector<uint64_t> conns_count(conns.size(), { 0 });
	char stop = 0;
	size_t conn_pos = 0;

	std::chrono::nanoseconds duration;
	hrc::time_point start = hrc::now();

	for (MYSQL* conn : conns) {
		conns_ths.push_back(std::async(
			conn_query_executor, conn, "SELECT 1", init_delay, &conns_count[conn_pos], &stop
		));

		conn_pos += 1;
	}

	hrc::time_point end = hrc::now();
	duration = end - start;

	double duration_s = duration.count() / pow(10,9);
	double duration_epsilon = (duration_s * 10) / 100;
	double wait_time_s = WAIT_TIME_US / pow(10, 6);

	usleep(WAIT_TIME_US);
	__sync_fetch_and_add(&stop, 1);

	return EXIT_SUCCESS;
}

double check_target_qps(
	vector<uint64_t>& query_counts, uint64_t qps_limit, uint32_t epsilon, double timeout_s, uint32_t* cur_qps
) {
	bool qps_limit_reached = false;
	bool timeout = false;

	uint32_t current_qps = 0;
	uint32_t time_waited = 0;
	uint64_t prev_query_count = 0;

	std::chrono::nanoseconds duration;
	hrc::time_point start = hrc::now();

	while(qps_limit_reached == false && timeout == false) {
		sleep(1);

		uint64_t cur_query_count = 0;
		for (size_t i = 0; i < query_counts.size(); i++) {
			cur_query_count += __sync_fetch_and_add(&query_counts[i], 0);
		}

		current_qps = cur_query_count - prev_query_count;

		if (qps_limit != 0 && current_qps > (qps_limit - epsilon) && current_qps < (qps_limit + epsilon)) {
			qps_limit_reached = true;
		} else {
			prev_query_count = cur_query_count;
			if (time_waited >= timeout_s) {
				timeout = true;
			}
		}

		time_waited += 1;
	}

	hrc::time_point end = hrc::now();
	duration = end - start;
	double duration_s = duration.count() / pow(10,9);

	*cur_qps = current_qps;

	if (qps_limit_reached == true) {
		return duration_s;
	} else {
		return 0;
	}
}

void stop_all_workers(vector<std::future<int>>& workers, vector<char>& stop_flags) {
	for (uint32_t i = 0; i < workers.size(); i++) {
		stop_flags[i] = 1;
	}
	for (std::future<int>& worker : workers) {
		worker.get();
	}
}

using qps_limit = uint64_t;
using burst_size = uint64_t;
using std::pair;

using user = string;
using pass = string;
using schema = string;
using flagIN = uint32_t;

const vector<pair<qps_limit,burst_size>> tests_payloads {
	{ 1000, 20 }, { 1000, 50 },  { 500, 100 }, { 1000, 1500 }, { 1000, 150 },
	{ 1000, 500 }, { 1000, 500 }, { 1500, 1600 }, { 2000, 2000 }, { 2000, 3000 }
};

const uint32_t test_2_max_conns = 35;
const uint32_t test_2_min_conns = 5;
const uint32_t test_2_its = (test_2_max_conns - test_2_min_conns) / 10;

using test_config = tuple<user,pass,schema,flagIN,string>;

vector<test_config> test_4_configs {
	std::make_tuple("sbtest1", "sbtest1", "", 0, "SELECT 1"),
	std::make_tuple("sbtest2", "sbtest2", "qps_limit_db", 0, "SELECT 1"),
	std::make_tuple("sbtest3", "sbtest3", "qps_limit_db", 3, "DO 1")
};
const vector<pair<qps_limit,burst_size>> test_4_payloads { { 1000, 20 }, { 2000, 20 } };
const vector<pair<qps_limit,burst_size>> test_5_payloads { { 200, 1000 }, { 1000, 500 } };

vector<int32_t> test_2_target_conns { 10, 20, 10, 5, 40, 9 };
vector<int32_t> test_3_target_conns { 10, 20, 10, 5, 40, 9 };
vector<int32_t> test_5_target_conns { 1, 20, 5, 10, 35 };

int main(int argc, char** argv) {
	CommandLine cl;

	plan(
		// Test 1: Expected tests
		tests_payloads.size()*2 +
		// Test 2: Expected tests
		10*tests_payloads.size()*((test_2_its + 1)*test_2_its/2) + test_2_its*tests_payloads.size()*2 - test_2_its*5*tests_payloads.size() +
		// Test 3: Expected tests
		tests_payloads.size() * test_3_target_conns.size() +
		// Test 4: Expected tests
		test_4_payloads.size() * test_4_configs.size() * 4 +
		// Test 5: Expected tests
		test_5_payloads.size() * test_5_target_conns.size() * 2
	);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	// Test 1: See description on top
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

			// Wait for the QPS counting to stabilize after the previous value
			usleep(qps_limit*1000 + 500*1000);

			int test_rc = check_single_conn_qps_limits_count(proxysql, "SELECT 1", qps_limit, burst_size);
			if (test_rc != EXIT_SUCCESS) { return EXIT_FAILURE; }
		}

		mysql_close(proxysql);

		// Give some time for the update
		usleep(500 * 1000);
	}

	// Test 2: See description on top
	{
		const string TEST_USER { "sbtest1" };
		const string TEST_PASS { "sbtest1" };

		conn_opts conn_opts { cl.host, TEST_USER, TEST_PASS, cl.port };
		for (int i = 5; i < test_2_max_conns; i += 10) {
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

				// Wait for the QPS counting to stabilize after the previous value
				usleep(qps_limit*1000 + 500*1000);

				int test_rc = check_multi_conn_qps_limits_count(conns, qps_limit, burst_size);
				if (test_rc != EXIT_SUCCESS) { return EXIT_FAILURE; }
			}

			for (MYSQL* conn : conns) {
				mysql_close(conn);
			}
		}
	}

	// Test 3: See description on top
	{
		const string TEST_USER { "sbtest1" };
		const string TEST_PASS { "sbtest1" };

		uint64_t max_conn_num = static_cast<uint64_t>(*std::max_element(test_3_target_conns.begin(), test_3_target_conns.end()));
		conn_opts conn_opts { cl.host, TEST_USER, TEST_PASS, cl.port };

		int32_t cur_conns = 0;
		vector<MYSQL*> conns {};
		vector<std::future<int>> workers {};
		vector<uint64_t> query_counts(max_conn_num, { 0 });
		vector<char> stop_flags(max_conn_num, { 0 });

		for (int tg_conns : test_3_target_conns) {
			int32_t conns_diff = tg_conns - cur_conns;

			if (conns_diff < 0) {
				diag("Removing '%d' worker threads...", std::abs(conns_diff));
				int stop_res = stop_workers(conns, workers, query_counts, stop_flags, std::abs(conns_diff));
				if (stop_res != EXIT_SUCCESS) {
					diag("Failed to stop workers with error: '%d'", stop_res);
					return EXIT_FAILURE;
				}
			} else {
				diag("Adding '%d' worker threads...", conns_diff);
				int add_res = add_workers(
						conn_opts, "SELECT 1", conns, workers, query_counts, stop_flags, std::abs(conns_diff)
					);
				if (add_res != EXIT_SUCCESS) {
					diag("Failed to add workers with error: '%d'", add_res);
					return EXIT_FAILURE;
				}
			}
			cur_conns = conns.size();

			diag("Started checking test payloads...");
			for (const auto& test_payload : tests_payloads) {
				uint32_t qps_limit = test_payload.first;
				uint32_t burst_size = test_payload.second;

				// Setup 'qps_limit_rules'
				string user_limit_rule {};
				string_format(t_qps_limit_rule, user_limit_rule, TEST_USER.c_str(), "", 0, qps_limit, burst_size);

				MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_qps_limit_rules");
				MYSQL_QUERY(proxysql_admin, user_limit_rule.c_str());
				MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

				double timeout_s = (qps_limit*1000 + 500*1000) / pow(10, 6);
				timeout_s = timeout_s < 1 ? 1 : timeout_s;
				uint32_t epsilon = qps_limit * 10 / 100;
				uint32_t current_qps = 0;

				double duration_s = check_target_qps(query_counts, qps_limit, epsilon, timeout_s, &current_qps);

				ok(
					static_cast<uint32_t>(duration_s) != 0,
					"Target QPS limit reached before timeout: { qps_limit: '%d', qps: '%d', epsilon: '%d', duration: '%lf' }",
					qps_limit, current_qps, epsilon, duration_s
				);
			}
		}

		stop_all_workers(workers, stop_flags);
		for (MYSQL* conn : conns) {
			mysql_close(conn);
		}
	}

	// Test 4: See description on top
	{
		vector<MYSQL*> tests_conns {};

		for (const test_config& test_config : test_4_configs) {
			const string& TEST_USER = std::get<0>(test_config);
			const string& TEST_PASS = std::get<1>(test_config);

			MYSQL* conn = mysql_init(NULL);
			if (!mysql_real_connect(conn, cl.host, TEST_USER.c_str(), TEST_PASS.c_str(), NULL, cl.port, NULL, 0)) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conn));
				return EXIT_FAILURE;
			}

			tests_conns.push_back(conn);
		}

		// Cleanup and prepare
		MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_qps_limit_rules");
		MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_query_rules WHERE rule_id=3");
		MYSQL_QUERY(
			proxysql_admin,
			"INSERT INTO mysql_query_rules (rule_id,active,flagOUT,match_digest,destination_hostgroup,apply)"
			" VALUES (3,1,3,'^DO',1,1)"
		);
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

		// Second connection
		MYSQL_QUERY(tests_conns[1], "DROP DATABASE IF EXISTS qps_limit_db");
		MYSQL_QUERY(tests_conns[1], "CREATE DATABASE qps_limit_db");

		MYSQL_QUERY(tests_conns[1], "USE qps_limit_db");
		MYSQL_QUERY(tests_conns[2], "USE qps_limit_db");

		for (const auto& test_payload : test_4_payloads) {
			uint32_t config_num = 0;
			uint32_t qps_limit = test_payload.first;
			uint32_t burst_size = test_payload.second;

			MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_qps_limit_rules");
			for (const test_config& test_config : test_4_configs) {
				const string& TEST_USER = std::get<0>(test_config);
				const string& schema = std::get<2>(test_config);
				const uint32_t flagIN = std::get<3>(test_config);

				string user_limit_rule {};
				string_format(t_qps_limit_rule, user_limit_rule, TEST_USER.c_str(), schema.c_str(), flagIN, qps_limit, burst_size);

				MYSQL_QUERY(proxysql_admin, user_limit_rule.c_str());
			}

			for (MYSQL* conn : tests_conns) {
				const string& TEST_USER = std::get<0>(test_4_configs[config_num]);
				const string& schemaname = std::get<2>(test_4_configs[config_num]);
				const uint32_t flagIN = std::get<3>(test_4_configs[config_num]);
				const string& query = std::get<4>(test_4_configs[config_num]);

				// Setup 'qps_limit_rules'
				string user_limit_rule {};
				string_format(
					t_update_qps_limit_rule, user_limit_rule, qps_limit, burst_size, TEST_USER.c_str(),
					schemaname.c_str(), flagIN
				);

				MYSQL_QUERY(proxysql_admin, user_limit_rule.c_str());
				MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

				// Wait for the QPS counting to stabilize after the previous value
				usleep(qps_limit*1000 + 500*1000);

				int test_rc = check_single_conn_qps_limits_count(conn, query.c_str(), qps_limit, burst_size);
				if (test_rc != EXIT_SUCCESS) { return EXIT_FAILURE; }

				MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_qps_limit_rules WHERE username NOT IN ('sbtest1', 'sbtest2', 'sbtest3')");
				MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

				// Fill the map with random unused keys
				for (uint32_t i = 4; i < 1024; i++) {
					const string TEST_USER { "sbtest" + std::to_string(i) };
					string user_limit_rule {};
					string_format(t_qps_limit_rule, user_limit_rule, TEST_USER.c_str(), "qps_limit_db", i, 0, 0);

					MYSQL_QUERY(proxysql_admin, user_limit_rule.c_str());
				}

				MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

				test_rc = check_single_conn_qps_limits_count(conn, query.c_str(), qps_limit, burst_size);
				if (test_rc != EXIT_SUCCESS) { return EXIT_FAILURE; }

				config_num += 1;
			}
		}

		for (MYSQL* conn : tests_conns) {
			mysql_close(conn);
		}
	}

	// Test 5: See description on top
	{
		const string TEST_USER { "sbtest1" };
		const string TEST_PASS { "sbtest1" };

		uint64_t max_conn_num = static_cast<uint64_t>(*std::max_element(test_5_target_conns.begin(), test_5_target_conns.end()));
		conn_opts conn_opts { cl.host, TEST_USER, TEST_PASS, cl.port };

		int32_t cur_conns = 0;
		vector<MYSQL*> conns {};
		vector<std::future<int>> workers {};
		vector<uint64_t> query_counts(max_conn_num, { 0 });
		vector<char> stop_flags(max_conn_num, { 0 });

		for (int target_conns : test_5_target_conns) {
			int32_t conns_diff = target_conns - cur_conns;

			if (conns_diff < 0) {
				diag("Removing '%d' worker threads...", std::abs(conns_diff));
				int stop_res = stop_workers(conns, workers, query_counts, stop_flags, std::abs(conns_diff));
				if (stop_res != EXIT_SUCCESS) {
					diag("Failed to stop workers with error: '%d'", stop_res);
					return EXIT_FAILURE;
				}
			} else {
				diag("Adding '%d' worker threads...", conns_diff);
				int add_res = add_workers(
						conn_opts, "SELECT 1", conns, workers, query_counts, stop_flags, std::abs(conns_diff)
					);
				if (add_res != EXIT_SUCCESS) {
					diag("Failed to add workers with error: '%d'", add_res);
					return EXIT_FAILURE;
				}
			}
			cur_conns = conns.size();

			diag("Started checking test payloads...");
			for (const auto& test_payload : test_5_payloads) {
				uint32_t qps_limit = test_payload.first;
				uint32_t burst_size = test_payload.second;

				// Setup 'qps_limit_rules'
				string user_limit_rule {};
				string_format(t_qps_limit_rule, user_limit_rule, TEST_USER.c_str(), "", 0, qps_limit, burst_size);

				MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_qps_limit_rules");
				MYSQL_QUERY(proxysql_admin, user_limit_rule.c_str());
				MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

				double timeout_s = (qps_limit*1000 + 500*1000) / pow(10, 6);
				timeout_s = timeout_s < 1 ? 1 : timeout_s;
				uint32_t epsilon = qps_limit * 10 / 100;
				uint32_t current_qps = 0;
				uint32_t zero_qps_timeout = 2;

				double duration_s = check_target_qps(query_counts, qps_limit, epsilon, timeout_s, &current_qps);

				ok(
					duration_s != 0,
					"Target QPS limit reached before timeout: { qps_limit: '%d', qps: '%d', epsilon: '%d', duration: '%lf' }",
					qps_limit, current_qps, epsilon, duration_s
				);

				string update_user_limit_rule {};
				string_format(t_update_qps_limit_rule, update_user_limit_rule, 0, 0, TEST_USER.c_str(), "", 0);
				MYSQL_QUERY(proxysql_admin, update_user_limit_rule.c_str());
				MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

				duration_s = check_target_qps(query_counts, 0, epsilon, zero_qps_timeout, &current_qps);

				ok(
					static_cast<uint32_t>(duration_s) == 0 && current_qps == 0,
					"Zero QPS during specified time: { qps_limit: '%d', qps: '%d', epsilon: '%d', duration: '%d' }",
					qps_limit, current_qps, 0, zero_qps_timeout
				);

				// Unblock the connections
				MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_qps_limit_rules");
				MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
			}
		}

		stop_all_workers(workers, stop_flags);
		for (MYSQL* conn : conns) {
			mysql_close(conn);
		}

		MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_qps_limit_rules");
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
