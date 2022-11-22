/**
 * @file test_session_hostgroup_metrics-t.cpp
 * @brief Test for checking the metrics from stats table 'stats_mysql_hostgroups'.
 * @details The following checks are performed:
 *   - Test 1: Open multiple connections to ProxySQL, perform one query per connection and check that:
 *       1. The average waiting time match the expected when a waiting is imposed via 'max_connections=0'.
 *       2. 'conns_reqs_waiting' and 'conns_reqs_waited' match the number of oppened connections when the
 *          connections are still oppened.
 *       3. Once limitation is removed, connections are returned and queries executed, and 'conns_reqs_waiting'
 *          pass to have '0' value and 'conns_total' and 'queries_total' match the number of oppened
 *   - Test 2. Open a transaction and check that:
 *       1. The number of connections != number of queries executed in the hostgroup.
 *       2. Hostgroup tracking is properly performed, transaction queries being counted in 'hostgroup 0' and
 *          SELECTS in 'hostgroup 1'.
 *   - Test 3. Checks that the number of waiting sessions is decreased accordingly when a sessions times out
 *     without getting a connection, and the waited time is updated properly.
 *   - Test 4: Imposes a connection limit for a server, open multiple connections to ProxySQL, perform one
 *     query per connection against that server and checks that:
 *       1. The connections exceeding the limit are represented in 'conns_reqs_waiting' metric.
 *       2. Once all the connections are served, all the metrics are properly updated.
 */

#include <algorithm>
#include <cstring>
#include <chrono>
#include <ctime>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <stdio.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

#include <sys/resource.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "command_line.h"
#include "json.hpp"
#include "tap.h"
#include "utils.h"

using std::vector;
using std::string;
using std::map;
using std::tuple;

const uint32_t MAX_NUM_CONNECTIONS = 10000;

/**
 * @brief Helper function to feed to 'std::accumulate' for value comparison.
 */
bool value_matcher(bool res, const tuple<string,uint32_t,uint32_t>& id_act_exp) {
	if (std::get<1>(id_act_exp) == std::get<2>(id_act_exp)) {
		return res && true;
	} else {
		return res && false;
	}
};

/**
 * @brief Helper function to feed to 'std::accumulate' for error message construction.
 */
string msg_generator(const string& cur_msg, const tuple<string,uint32_t,uint32_t>& id_act_exp) {
	const string m_id { std::get<0>(id_act_exp) };
	const string m_act_val { std::to_string(std::get<1>(id_act_exp)) };
	const string m_exp_val { std::to_string(std::get<2>(id_act_exp)) };

	return cur_msg + string { m_id + ": (Act: '" + m_act_val + "', Exp: '" + m_exp_val + "'), " };
};

int test_1(CommandLine& cl, MYSQL* proxysql_admin, bool check_p_metrics=false) {
	const uint32_t CONN_NUM = 10;
	double EPSILON = 0.1;
	uint32_t WAITED_TIME = 3;
	const uint32_t COLUMNS_NUM = 6;

	vector<MYSQL*> proxy_conns {};
	int conn_err = open_connections(cl, CONN_NUM, proxy_conns);
	if (conn_err) { return EXIT_FAILURE; }

	MYSQL_QUERY(proxysql_admin, "UPDATE mysql_servers SET max_connections=0");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	vector<std::thread> query_threads {};
	std::mutex query_res_mutex;
	vector<int> query_err_codes {};

	std::map<string, double> p_metrics {};
	int p_res = fetch_prometheus_metrics(proxysql_admin, p_metrics);
	if (p_res != EXIT_SUCCESS) { return p_res; }

	if (check_p_metrics) {
		auto it_p_conns_reqs_waited = p_metrics.find("proxysql_hostgroup_conns_reqs_waited_total{hostgroup=\"1\"}");
		auto it_p_conns_reqs_waited_time_total = p_metrics.find("proxysql_hostgroup_conns_reqs_waited_time_total{hostgroup=\"1\"}");
		auto it_p_conns_reqs_waiting = p_metrics.find("proxysql_hostgroup_conns_reqs_waiting{hostgroup=\"1\"}");
		auto it_p_conns_total = p_metrics.find("proxysql_hostgroup_conns_total{hostgroup=\"1\"}");
		auto it_p_queries_total = p_metrics.find("proxysql_hostgroup_queries_total{hostgroup=\"1\"}");

		ok(
			it_p_conns_reqs_waited != p_metrics.end() && it_p_conns_reqs_waited_time_total != p_metrics.end() &&
			it_p_conns_reqs_waiting != p_metrics.end() && it_p_conns_total != p_metrics.end() &&
			it_p_queries_total != p_metrics.end(),
			"Test 1: The supported prometheus hostgroup metrics should be present."
		);
	} else {
		ok(true, "NOTE: Placeholder test executed when prometheus metrics checks are disabled. See: #3571");
	}

	std::transform(
		proxy_conns.begin(), proxy_conns.end(), std::back_inserter(query_threads),
		[&query_res_mutex, &query_err_codes](MYSQL* conn) -> std::thread {
			return std::thread([&query_res_mutex, &query_err_codes,conn]() -> void {
				mysql_query(conn, "SELECT 1");
				std::lock_guard<std::mutex> lock_guard(query_res_mutex);
				query_err_codes.push_back(mysql_errno(conn));
			});
		}
	);

	sleep(WAITED_TIME);

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM stats_mysql_hostgroups WHERE hostgroup=1");
	MYSQL_RES* latencies_res = mysql_store_result(proxysql_admin);
	map<string, vector<string>> row_map = fetch_row_values(latencies_res);
	mysql_free_result(latencies_res);

	p_res = fetch_prometheus_metrics(proxysql_admin, p_metrics);
	if (p_res != EXIT_SUCCESS) { return p_res; }

	uint32_t conns_reqs_waiting = std::stoll(row_map["conns_reqs_waiting"][0], NULL, 10);
	uint32_t conns_total = std::stoll(row_map["conns_total"][0], NULL, 10);
	uint32_t queries_total = std::stoll(row_map["queries_total"][0], NULL, 10);
	uint32_t conns_reqs_waited = std::stoll(row_map["conns_reqs_waited"][0], NULL, 10);

	ok(
		row_map.size() == COLUMNS_NUM && row_map["hostgroup"].size() == 1,
		"Test 1: Numbers of columns should match expected and there should be only one row per hostgroup"
	);

	uint32_t p_conns_reqs_waited = 0;
	uint32_t p_conns_reqs_waited_time_total = 0;
	uint32_t p_conns_reqs_waiting = 0;
	uint32_t p_conns_total = 0;
	uint32_t p_queries_total = 0;

	vector<tuple<string,uint32_t,uint32_t>> t_id_act_exp {
		{ "conns_reqs_waiting", conns_reqs_waiting, CONN_NUM },
		{ "conns_reqs_waited", conns_reqs_waited, CONN_NUM },
		{ "conns_total", conns_total, 0 },
		{ "queries_total", queries_total, 0 },
	};

	bool t_exp_vals_match = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), true, value_matcher);
	string t_exp_vals_msg = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), string {""}, msg_generator);

	if (check_p_metrics) {
		try {
			p_conns_reqs_waited = p_metrics.at("proxysql_hostgroup_conns_reqs_waited_total{hostgroup=\"1\"}");
			p_conns_reqs_waited_time_total = p_metrics.at("proxysql_hostgroup_conns_reqs_waited_time_total{hostgroup=\"1\"}");
			p_conns_reqs_waiting = p_metrics.at("proxysql_hostgroup_conns_reqs_waiting{hostgroup=\"1\"}");
			p_conns_total = p_metrics.at("proxysql_hostgroup_conns_total{hostgroup=\"1\"}");
			p_queries_total = p_metrics.at("proxysql_hostgroup_queries_total{hostgroup=\"1\"}");
		} catch (std::exception& e) {
			diag("Failed to optain value from prometheus metrics map: '%s'", e.what());
		}

		const vector<tuple<string,uint32_t,uint32_t>> p_id_act_exp {
			{ "p_conns_reqs_waiting", p_conns_reqs_waiting, CONN_NUM },
			{ "p_conns_reqs_waited", p_conns_reqs_waited, CONN_NUM },
			{ "p_conns_total", p_conns_total, 0 },
			{ "p_queries_total", p_queries_total, 0 },
		};

		bool p_exp_vals_match = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), true, value_matcher);
		string p_exp_vals_msg = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), string {""}, msg_generator);

		ok(
			t_exp_vals_match && p_exp_vals_match,
			"Test 1: Table and prometheus metric values should match expected: {\n    %s\n    %s\n}",
			t_exp_vals_msg.c_str(), p_exp_vals_msg.c_str()
		);
	} else {
		ok(t_exp_vals_match, "Test 1: Table metric values should match expected: {\n    %s\n}", t_exp_vals_msg.c_str());
	}

	MYSQL_QUERY(proxysql_admin, "UPDATE mysql_servers SET max_connections=10");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	std::for_each(query_threads.begin(), query_threads.end(), [](std::thread& th) -> void { th.join(); });
	std::for_each(proxy_conns.begin(), proxy_conns.end(), [](MYSQL* conn) -> void { mysql_close(conn); });

	// Give some extra time to ProxySQL for the sessions processing
	usleep(500 * 1000);

	// Check that all the queries succeeded because sessions received the connection from connection pool
	bool conns_succeed = std::accumulate(
		query_err_codes.begin(), query_err_codes.end(), true,
		[](bool res, int res_code) { return res == true && res_code == 0; }
	);

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM stats_mysql_hostgroups WHERE hostgroup=1");
	latencies_res = mysql_store_result(proxysql_admin);
	row_map = fetch_row_values(latencies_res);
	mysql_free_result(latencies_res);

	conns_reqs_waited = std::stoll(row_map["conns_reqs_waited"][0], NULL, 10);
	uint32_t conns_reqs_waited_time_total = std::stoll(row_map["conns_reqs_waited_time_total"][0], NULL, 10);
	double avg_waiting_time = conns_reqs_waited == 0 ? 0 :
		(conns_reqs_waited_time_total / static_cast<double>(conns_reqs_waited)) / pow(10,6);

	ok(
		conns_succeed && avg_waiting_time > WAITED_TIME - EPSILON && avg_waiting_time < WAITED_TIME + EPSILON,
		"Test 1: Connections succeed and average waiting time should match explicit waited time:"
		" { conn_succeed: '%d', conn_reqs_waited_time_total: %d, conn_reqs_waited: '%d', exp: '%d', act: '%f', epsilon: '%f' }",
		conns_succeed, conns_reqs_waited_time_total, conns_reqs_waited, WAITED_TIME, avg_waiting_time, EPSILON
	);

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM stats_mysql_hostgroups WHERE hostgroup=1");
	latencies_res = mysql_store_result(proxysql_admin);
	row_map = fetch_row_values(latencies_res);
	mysql_free_result(latencies_res);

	p_res = fetch_prometheus_metrics(proxysql_admin, p_metrics);
	if (p_res != EXIT_SUCCESS) { return p_res; }

	conns_reqs_waited = std::stoll(row_map["conns_reqs_waited"][0], NULL, 10);
	conns_reqs_waiting = std::stoll(row_map["conns_reqs_waiting"][0], NULL, 10);
	conns_total = std::stoll(row_map["conns_total"][0], NULL, 10);
	queries_total = std::stoll(row_map["queries_total"][0], NULL, 10);

	t_id_act_exp = {
		{ "conns_reqs_waiting", conns_reqs_waiting, 0 },
		{ "conns_reqs_waited", conns_reqs_waited, CONN_NUM },
		{ "conns_total", conns_total, CONN_NUM },
		{ "queries_total", queries_total, CONN_NUM },
	};

	t_exp_vals_match = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), true, value_matcher);
	t_exp_vals_msg = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), string {""}, msg_generator);

	if (check_p_metrics) {
		try {
			p_conns_reqs_waited = p_metrics.at("proxysql_hostgroup_conns_reqs_waited_total{hostgroup=\"1\"}");
			p_conns_reqs_waited_time_total = p_metrics.at("proxysql_hostgroup_conns_reqs_waited_time_total{hostgroup=\"1\"}");
			p_conns_reqs_waiting = p_metrics.at("proxysql_hostgroup_conns_reqs_waiting{hostgroup=\"1\"}");
			p_conns_total = p_metrics.at("proxysql_hostgroup_conns_total{hostgroup=\"1\"}");
			p_queries_total = p_metrics.at("proxysql_hostgroup_queries_total{hostgroup=\"1\"}");
		} catch (std::exception& e) {
			diag("Failed to optain value from prometheus metrics map: '%s'", e.what());
		}

		const vector<tuple<string,uint32_t,uint32_t>> p_id_act_exp {
			{ "p_conns_reqs_waiting", p_conns_reqs_waiting, 0 },
			{ "p_conns_reqs_waited", p_conns_reqs_waited, CONN_NUM },
			{ "p_conns_total", p_conns_total, CONN_NUM },
			{ "p_queries_total", p_queries_total, CONN_NUM },
		};

		bool p_exp_vals_match = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), true, value_matcher);
		string p_exp_vals_msg = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), string {""}, msg_generator);

		ok(
			t_exp_vals_match && p_exp_vals_match,
			"Test 1: Table and prometheus metric values should match expected: {\n    %s\n    %s\n}",
			t_exp_vals_msg.c_str(), p_exp_vals_msg.c_str()
		);
	} else {
		ok(t_exp_vals_match, "Test 1: Table metric values should match expected: {\n    %s\n}", t_exp_vals_msg.c_str());
	}

	return EXIT_SUCCESS;
}

int test_2(CommandLine& cl, MYSQL* proxysql_admin, bool check_p_metrics=false) {
	uint32_t HG0_QUERY_NUM = 0;
	uint32_t HG0_DO_1_QUERIES = 100;
	uint32_t WAITED_TIME = 1;

	MYSQL* proxysql_mysql = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY(proxysql_mysql, "BEGIN");
	HG0_QUERY_NUM += 1;

	for (uint32_t i = 0; i < HG0_DO_1_QUERIES; i++) {
		mysql_query(proxysql_mysql, "DO 1");
		HG0_QUERY_NUM += 1;
	}

	MYSQL_QUERY(proxysql_mysql, "COMMIT");
	HG0_QUERY_NUM += 1;

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM stats_mysql_hostgroups WHERE hostgroup=0");
	MYSQL_RES* latencies_res = mysql_store_result(proxysql_admin);
	map<string, vector<string>> row_map = fetch_row_values(latencies_res);
	mysql_free_result(latencies_res);

	std::map<string, double> p_metrics {};
	int p_res = fetch_prometheus_metrics(proxysql_admin, p_metrics);
	if (p_res != EXIT_SUCCESS) { return p_res; }

	uint32_t queries_total = std::stoll(row_map["queries_total"][0], NULL, 10);
	uint32_t conns_total = std::stoll(row_map["conns_total"][0], NULL, 10);

	uint32_t p_conns_reqs_waited = 0;
	uint32_t p_conns_reqs_waited_time_total = 0;
	uint32_t p_conns_reqs_waiting = 0;
	uint32_t p_conns_total = 0;
	uint32_t p_queries_total = 0;

	vector<tuple<string,uint32_t,uint32_t>> t_id_act_exp {
		{ "conns_total", conns_total, 1 },
		{ "queries_total", queries_total, HG0_QUERY_NUM },
	};

	bool t_exp_vals_match = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), true, value_matcher);
	string t_exp_vals_msg = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), string {""}, msg_generator);

	if (check_p_metrics) {
		try {
			p_conns_total = p_metrics.at("proxysql_hostgroup_conns_total{hostgroup=\"0\"}");
			p_queries_total = p_metrics.at("proxysql_hostgroup_queries_total{hostgroup=\"0\"}");
		} catch (std::exception& e) {
			diag("Failed to optain value from prometheus metrics map: '%s'", e.what());
		}

		const vector<tuple<string,uint32_t,uint32_t>> p_id_act_exp {
			{ "p_conns_total", p_conns_total, 1 },
			{ "p_queries_total", p_queries_total, HG0_QUERY_NUM },
		};

		bool p_exp_vals_match = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), true, value_matcher);
		string p_exp_vals_msg = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), string {""}, msg_generator);

		ok(
			t_exp_vals_match && p_exp_vals_match,
			"Test 2: Table and prometheus metric values should match expected: {\n    %s\n    %s\n}",
			t_exp_vals_msg.c_str(), p_exp_vals_msg.c_str()
		);
	} else {
		ok(t_exp_vals_match, "Test 2: Table metric values should match expected: {\n    %s\n}", t_exp_vals_msg.c_str());
	}

	MYSQL_QUERY(proxysql_mysql, "BEGIN");
	HG0_QUERY_NUM += 1;

	MYSQL_QUERY(proxysql_admin, "UPDATE mysql_servers SET max_connections=0");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	MYSQL_QUERY(proxysql_mysql, "DO 1");
	HG0_QUERY_NUM += 1;
 
	sleep(WAITED_TIME);

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM stats_mysql_hostgroups WHERE hostgroup=0");
	latencies_res = mysql_store_result(proxysql_admin);
	row_map = fetch_row_values(latencies_res);
	mysql_free_result(latencies_res);

	p_res = fetch_prometheus_metrics(proxysql_admin, p_metrics);
	if (p_res != EXIT_SUCCESS) { return p_res; }

	uint32_t conns_reqs_waited = std::stoll(row_map["conns_reqs_waited"][0], NULL, 10);
	uint32_t conns_reqs_waited_time_total = std::stoll(row_map["conns_reqs_waited_time_total"][0], NULL, 10);
	uint32_t conns_reqs_waiting = std::stoll(row_map["conns_reqs_waiting"][0], NULL, 10);

	conns_total = std::stoll(row_map["conns_total"][0], NULL, 10);
	queries_total = std::stoll(row_map["queries_total"][0], NULL, 10);

	const vector<tuple<string,uint32_t,uint32_t>> t_conns_id_act_exp {
		{ "p_conns_total", conns_total, 2 },
		{ "p_queries_total", queries_total, HG0_QUERY_NUM },
	};

	bool t_conns_exp_match =
		std::accumulate(t_conns_id_act_exp.begin(), t_conns_id_act_exp.end(), true, value_matcher);
	string t_conns_exp_msg =
		std::accumulate(t_conns_id_act_exp.begin(), t_conns_id_act_exp.end(), string {""}, msg_generator);

	if (check_p_metrics) {
		try {
			p_conns_reqs_waiting = p_metrics.at("proxysql_hostgroup_conns_reqs_waiting{hostgroup=\"0\"}");
			p_conns_reqs_waited = p_metrics.at("proxysql_hostgroup_conns_reqs_waited_total{hostgroup=\"0\"}");
			p_conns_reqs_waited_time_total = p_metrics.at("proxysql_hostgroup_conns_reqs_waited_time_total{hostgroup=\"0\"}");

			p_conns_total = p_metrics.at("proxysql_hostgroup_conns_total{hostgroup=\"0\"}");
			p_queries_total = p_metrics.at("proxysql_hostgroup_queries_total{hostgroup=\"0\"}");
		} catch (std::exception& e) {
			diag("Failed to optain value from prometheus metrics map: '%s'", e.what());
		}

		const vector<tuple<string,uint32_t,uint32_t>> p_id_act_exp {
			{ "p_conns_reqs_waiting", p_conns_reqs_waiting, 0 },
			{ "p_conns_reqs_waited", p_conns_reqs_waited, 0 },
			{ "p_conns_reqs_waited_time_total", p_conns_reqs_waited_time_total, 0 }
		};

		bool p_exp_vals_match = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), true, value_matcher);
		string p_exp_vals_msg = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), string {""}, msg_generator);

		ok(
			t_exp_vals_match && p_exp_vals_match,
			"Test 2: No waiting expected session already got the connection when 'max_connections' value was changed:"
			" {\n    %s\n    %s\n}", t_exp_vals_msg.c_str(), p_exp_vals_msg.c_str()
		);

		const vector<tuple<string,uint32_t,uint32_t>> p_conns_id_act_exp {
			{ "p_conns_total", p_conns_total, 2 },
			{ "p_queries_total", p_queries_total, HG0_QUERY_NUM },
		};

		bool p_conns_exp_match =
			std::accumulate(p_conns_id_act_exp.begin(), p_conns_id_act_exp.end(), true, value_matcher);
		string p_conns_exp_msg =
			std::accumulate(p_conns_id_act_exp.begin(), p_conns_id_act_exp.end(), string {""}, msg_generator);

		ok(
			t_conns_exp_match && p_conns_exp_match,
			"Test 2: 'conns_total' and 'queries_total' should match expected values: {\n    %s\n    %s\n}",
			t_conns_exp_msg.c_str(), p_conns_exp_msg.c_str()
		);
	} else {
		ok(
			t_exp_vals_match,
			"Test 2: No waiting expected session already got the connection when 'max_connections' value was changed: {\n    %s\n}",
			t_exp_vals_msg.c_str()
		);

		ok(
			t_conns_exp_match, "Test 2: 'conns_total' and 'queries_total' should match expected values: {\n    %s\n}",
			t_conns_exp_msg.c_str()
		);
	}

	mysql_close(proxysql_mysql);

	return EXIT_SUCCESS;
}

int test_3(CommandLine& cl, MYSQL* proxysql_admin, bool check_p_metrics=false) {
	const uint32_t CONN_NUM = 10;
	const uint32_t CONNECT_TIMEOUT_SERVER_MAX = 3000;
	double EPSILON = 0.5;

	MYSQL_QUERY(
		proxysql_admin,
		string {"SET mysql-connect_timeout_server_max=" + std::to_string(CONNECT_TIMEOUT_SERVER_MAX)}.c_str()
	);
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	vector<MYSQL*> proxy_conns {};
	int conn_err = open_connections(cl, CONN_NUM, proxy_conns);
	if (conn_err) { return EXIT_FAILURE; }

	MYSQL_QUERY(proxysql_admin, "UPDATE mysql_servers SET max_connections=0");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME"); usleep(500 * 1000);

	vector<std::thread> query_threads {};

	std::mutex query_res_mutex;
	vector<int> query_err_codes {};

	std::transform(
		proxy_conns.begin(), proxy_conns.end(), std::back_inserter(query_threads),
		[&query_res_mutex, &query_err_codes](MYSQL* conn) -> std::thread {
			return std::thread([&query_res_mutex, &query_err_codes,conn]() -> void {
				mysql_query(conn, "SELECT 1");
				std::lock_guard<std::mutex> lock_guard(query_res_mutex);
				query_err_codes.push_back(mysql_errno(conn));
			});
		}
	);

	usleep(CONNECT_TIMEOUT_SERVER_MAX * 1000 + 100*1000);

	std::for_each(query_threads.begin(), query_threads.end(), [](std::thread& th) -> void { th.join(); });
	std::for_each(proxy_conns.begin(), proxy_conns.end(), [](MYSQL* conn) -> void { mysql_close(conn); });

	// Give some extra time to ProxySQL for the sessions processing
	usleep(500 * 1000);

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM stats_mysql_hostgroups WHERE hostgroup=1");
	MYSQL_RES* latencies_res = mysql_store_result(proxysql_admin);
	map<string, vector<string>> row_map = fetch_row_values(latencies_res);
	mysql_free_result(latencies_res);

	bool conns_timed_out = std::accumulate(
		query_err_codes.begin(), query_err_codes.end(), true,
		[](bool res, int res_code) { return res == true && res_code == 9001; }
	);

	uint32_t conns_reqs_waited = std::stoll(row_map["conns_reqs_waited"][0], NULL, 10);
	uint32_t conns_reqs_waited_time_total = std::stoll(row_map["conns_reqs_waited_time_total"][0], NULL, 10);
	double avg_waiting_time = conns_reqs_waited == 0 ? 0 :
		(conns_reqs_waited_time_total / static_cast<double>(conns_reqs_waited)) / pow(10,6);

	ok(
		avg_waiting_time > (CONNECT_TIMEOUT_SERVER_MAX / 1000.0) - EPSILON &&
		avg_waiting_time < (CONNECT_TIMEOUT_SERVER_MAX / 1000.0) + EPSILON,
		"Test 3: Connections timed out and average waiting time should match the imposed 'CONNECT_TIMEOUT_SERVER_MAX':"
		"{ conns_timed_out: '%d', exp: '%d', act: '%f', epsilon: '%f' }",
		conns_timed_out, CONNECT_TIMEOUT_SERVER_MAX, avg_waiting_time, EPSILON
	);

	uint32_t conns_reqs_waiting = std::stoll(row_map["conns_reqs_waiting"][0], NULL, 10);
	uint32_t conns_total = std::stoll(row_map["conns_total"][0], NULL, 10);
	uint32_t queries_total = std::stoll(row_map["queries_total"][0], NULL, 10);

	vector<tuple<string,uint32_t,uint32_t>> t_id_act_exp = {
		{ "conns_reqs_waiting", conns_reqs_waiting, 0 },
		{ "conns_total", conns_total, 0 },
		{ "queries_total", queries_total, 0 },
	};

	bool t_exp_vals_match = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), true, value_matcher);
	string t_exp_vals_msg = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), string {""}, msg_generator);

	if (check_p_metrics) {
		std::map<string, double> p_metrics {};
		int p_res = fetch_prometheus_metrics(proxysql_admin, p_metrics);
		if (p_res != EXIT_SUCCESS) { return p_res; }

		uint32_t p_conns_reqs_waiting = 0;
		uint32_t p_conns_total = 0;
		uint32_t p_queries_total = 0;

		try {
			p_conns_reqs_waiting = p_metrics.at("proxysql_hostgroup_conns_reqs_waiting{hostgroup=\"1\"}");
			p_conns_total = p_metrics.at("proxysql_hostgroup_conns_total{hostgroup=\"1\"}");
			p_queries_total = p_metrics.at("proxysql_hostgroup_queries_total{hostgroup=\"1\"}");
		} catch (std::exception& e) {
			diag("Failed to optain value from prometheus metrics map: '%s'", e.what());
		}

		const vector<tuple<string,uint32_t,uint32_t>> p_id_act_exp {
			{ "p_conns_reqs_waiting", p_conns_reqs_waiting, 0 },
			{ "p_conns_total", p_conns_total, 0 },
			{ "p_queries_total", p_queries_total, 0 },
		};

		bool p_exp_vals_match = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), true, value_matcher);
		string p_exp_vals_msg = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), string {""}, msg_generator);

		ok(
			t_exp_vals_match && p_exp_vals_match,
			"Test 3: Table and prometheus metric values should match expected: {\n    %s\n    %s\n}",
			t_exp_vals_msg.c_str(), p_exp_vals_msg.c_str()
		);
	} else {
		ok(t_exp_vals_match, "Test 3: Table metric values should match expected: {\n    %s\n}", t_exp_vals_msg.c_str());
	}


	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES FROM DISK");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	return EXIT_SUCCESS;
}

int test_4(CommandLine& cl, MYSQL* proxysql_admin, bool check_p_metrics=false) {
	const uint32_t CONN_NUM = 500;
	const uint32_t CONNECT_TIMEOUT_SERVER_MAX = 20000;
	const uint32_t MAX_CONNECTIONS = 300;
	const uint32_t SLEEP_TIME = 5;
	// NOTE: This number was kept big because with small connections numbers, the average time can deviate
	// sightly from the expected value.
	double EPSILON = 2;

	MYSQL_QUERY(
		proxysql_admin,
		string {"SET mysql-connect_timeout_server_max=" + std::to_string(CONNECT_TIMEOUT_SERVER_MAX)}.c_str()
	);

	MYSQL_QUERY(proxysql_admin, "SET mysql-poll_timeout=100");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	vector<MYSQL*> proxy_conns {};
	int conn_err = open_connections(cl, CONN_NUM, proxy_conns);
	if (conn_err) { return EXIT_FAILURE; }

	MYSQL_QUERY(
		proxysql_admin,
		string {"UPDATE mysql_servers SET max_connections=" + std::to_string(MAX_CONNECTIONS)}.c_str()
	);
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	usleep(500 * 1000);

	vector<std::thread> query_threads {};
	std::mutex query_res_mutex;
	vector<int> query_err_codes {};

	std::transform(
		proxy_conns.begin(), proxy_conns.end(), std::back_inserter(query_threads),
		[&query_res_mutex,&query_err_codes,SLEEP_TIME](MYSQL* conn) -> std::thread {
			return std::thread([&query_res_mutex,&query_err_codes,conn,SLEEP_TIME]() -> void {
				std::string query {
					"/* hostgroup=0 */ SELECT SLEEP(" + std::to_string(SLEEP_TIME) + ")"
				};
				mysql_query(conn, query.c_str());
				std::lock_guard<std::mutex> lock_guard(query_res_mutex);
				query_err_codes.push_back(mysql_errno(conn));
			});
		}
	);

	// Give some time after launching connections
	usleep(500 * 1000);

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM stats_mysql_hostgroups WHERE hostgroup=0");
	MYSQL_RES* latencies_res = mysql_store_result(proxysql_admin);
	map<string, vector<string>> row_map = fetch_row_values(latencies_res);
	mysql_free_result(latencies_res);

	uint32_t conns_reqs_waited = std::stoll(row_map["conns_reqs_waited"][0], NULL, 10);
	uint32_t conns_reqs_waiting = std::stoll(row_map["conns_reqs_waiting"][0], NULL, 10);
	uint32_t conns_total = std::stoll(row_map["conns_total"][0], NULL, 10);
	uint32_t queries_total = std::stoll(row_map["queries_total"][0], NULL, 10);

	uint32_t p_conns_reqs_waiting = 0;
	uint32_t p_conns_reqs_waited = 0;
	uint32_t p_conns_reqs_waited_time_total = 0;
	uint32_t p_conns_total = 0;
	uint32_t p_queries_total = 0;

	vector<tuple<string,uint32_t,uint32_t>> t_id_act_exp {
		{ "conns_reqs_waiting", conns_reqs_waiting, CONN_NUM - MAX_CONNECTIONS },
		{ "conns_reqs_waited", conns_reqs_waited, CONN_NUM - MAX_CONNECTIONS },
		{ "conns_total", conns_total, MAX_CONNECTIONS },
		{ "queries_total", queries_total, 0 },
	};

	bool t_exp_vals_match = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), true, value_matcher);
	string t_exp_vals_msg = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), string {""}, msg_generator);

	if (check_p_metrics) {
		std::map<string, double> p_metrics {};
		int p_res = fetch_prometheus_metrics(proxysql_admin, p_metrics);
		if (p_res != EXIT_SUCCESS) { return p_res; }

		try {
			p_conns_reqs_waited = p_metrics.at("proxysql_hostgroup_conns_reqs_waited_total{hostgroup=\"0\"}");
			p_conns_reqs_waited_time_total = p_metrics.at("proxysql_hostgroup_conns_reqs_waited_time_total{hostgroup=\"0\"}");
			p_conns_reqs_waiting = p_metrics.at("proxysql_hostgroup_conns_reqs_waiting{hostgroup=\"0\"}");
			p_conns_total = p_metrics.at("proxysql_hostgroup_conns_total{hostgroup=\"0\"}");
			p_queries_total = p_metrics.at("proxysql_hostgroup_queries_total{hostgroup=\"0\"}");
		} catch (std::exception& e) {
			diag("Failed to optain value from prometheus metrics map: '%s'", e.what());
		}

		const vector<tuple<string,uint32_t,uint32_t>> p_id_act_exp {
			{ "p_conns_reqs_waiting", p_conns_reqs_waiting, CONN_NUM - MAX_CONNECTIONS },
			{ "p_conns_reqs_waited", p_conns_reqs_waited, CONN_NUM - MAX_CONNECTIONS },
			{ "p_conns_total", p_conns_total, MAX_CONNECTIONS },
			{ "p_queries_total", p_queries_total, 0 },
		};

		bool p_exp_vals_match = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), true, value_matcher);
		string p_exp_vals_msg = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), string {""}, msg_generator);

		ok(
			t_exp_vals_match && p_exp_vals_match,
			"Test 4: Table and prometheus metric values should match expected: {\n    %s\n    %s\n}",
			t_exp_vals_msg.c_str(), p_exp_vals_msg.c_str()
		);
	} else {
		ok(t_exp_vals_match, "Test 4: Table metric values should match expected: {\n    %s\n}", t_exp_vals_msg.c_str());
	}

	sleep(SLEEP_TIME);

	MYSQL_QUERY(
		proxysql_admin,
		string {"UPDATE mysql_servers SET max_connections=" + std::to_string(MAX_CONNECTIONS + 100)}.c_str()
	);
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	std::for_each(query_threads.begin(), query_threads.end(), [](std::thread& th) -> void { th.join(); });
	std::for_each(proxy_conns.begin(), proxy_conns.end(), [](MYSQL* conn) -> void { mysql_close(conn); });

	// Check that all the queries succeeded because sessions received the connection from connection pool
	bool conns_succeed = std::accumulate(
		query_err_codes.begin(), query_err_codes.end(), true,
		[](bool res, int res_code) { return res == true && res_code == 0; }
	);

	// Give some extra time to ProxySQL for the sessions processing
	usleep(500 * 1000);

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM stats_mysql_hostgroups WHERE hostgroup=0");
	latencies_res = mysql_store_result(proxysql_admin);
	row_map = fetch_row_values(latencies_res);
	mysql_free_result(latencies_res);

	conns_reqs_waited = std::stoll(row_map["conns_reqs_waited"][0], NULL, 10);
	uint32_t conns_reqs_waited_time_total = std::stoll(row_map["conns_reqs_waited_time_total"][0], NULL, 10);
	double avg_waiting_time = conns_reqs_waited == 0 ? 0 :
		(conns_reqs_waited_time_total / static_cast<double>(conns_reqs_waited)) / pow(10,6);

	ok(
		conns_succeed && avg_waiting_time > SLEEP_TIME - EPSILON && avg_waiting_time < SLEEP_TIME + EPSILON,
		"Test 4: Connections succeed and average waiting time should match explicit waited time:"
		" { conn_succeed: '%d', conn_reqs_waited_time_total: %d, conn_reqs_waited: '%d', exp: '%d', act: '%f', epsilon: '%f' }",
		conns_succeed, conns_reqs_waited_time_total, conns_reqs_waited, SLEEP_TIME, avg_waiting_time, EPSILON
	);

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM stats_mysql_hostgroups WHERE hostgroup=0");
	latencies_res = mysql_store_result(proxysql_admin);
	row_map = fetch_row_values(latencies_res);
	mysql_free_result(latencies_res);

	conns_reqs_waited = std::stoll(row_map["conns_reqs_waited"][0], NULL, 10);
	conns_reqs_waiting = std::stoll(row_map["conns_reqs_waiting"][0], NULL, 10);
	conns_total = std::stoll(row_map["conns_total"][0], NULL, 10);
	queries_total = std::stoll(row_map["queries_total"][0], NULL, 10);

	t_id_act_exp  = {
		{ "conns_reqs_waiting", conns_reqs_waiting, 0 },
		{ "conns_reqs_waited", conns_reqs_waited, CONN_NUM - MAX_CONNECTIONS },
		{ "conns_total", conns_total, CONN_NUM },
		{ "queries_total", queries_total, CONN_NUM },
	};

	t_exp_vals_match = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), true, value_matcher);
	t_exp_vals_msg = std::accumulate(t_id_act_exp.begin(), t_id_act_exp.end(), string {""}, msg_generator);

	if (check_p_metrics) {
		std::map<string, double> p_metrics {};
		int p_res = fetch_prometheus_metrics(proxysql_admin, p_metrics);
		if (p_res != EXIT_SUCCESS) { return p_res; }

		try {
			p_conns_reqs_waited = p_metrics.at("proxysql_hostgroup_conns_reqs_waited_total{hostgroup=\"0\"}");
			p_conns_reqs_waited_time_total = p_metrics.at("proxysql_hostgroup_conns_reqs_waited_time_total{hostgroup=\"0\"}");
			p_conns_reqs_waiting = p_metrics.at("proxysql_hostgroup_conns_reqs_waiting{hostgroup=\"0\"}");
			p_conns_total = p_metrics.at("proxysql_hostgroup_conns_total{hostgroup=\"0\"}");
			p_queries_total = p_metrics.at("proxysql_hostgroup_queries_total{hostgroup=\"0\"}");
		} catch (std::exception& e) {
			diag("Failed to optain value from prometheus metrics map: '%s'", e.what());
		}

		const vector<tuple<string,uint32_t,uint32_t>> p_id_act_exp {
			{ "p_conns_reqs_waiting", p_conns_reqs_waiting, 0 },
			{ "p_conns_reqs_waited", p_conns_reqs_waited, CONN_NUM - MAX_CONNECTIONS },
			{ "p_conns_total", p_conns_total, CONN_NUM },
			{ "p_queries_total", p_queries_total, CONN_NUM },
		};

		bool p_exp_vals_match = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), true, value_matcher);
		string p_exp_vals_msg = std::accumulate(p_id_act_exp.begin(), p_id_act_exp.end(), string {""}, msg_generator);

		ok(
			t_exp_vals_match && p_exp_vals_match,
			"Test 4: Table and prometheus metric values should match expected: {\n    %s\n    %s\n}",
			t_exp_vals_msg.c_str(), p_exp_vals_msg.c_str()
		);
	} else {
		ok(t_exp_vals_match, "Test 4: Table metric values should match expected: {\n    %s\n}", t_exp_vals_msg.c_str());
	}

	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES FROM DISK");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	return EXIT_SUCCESS;
}

const std::vector<std::function<int(CommandLine&,MYSQL*,bool)>> planned_tests {
	test_1, test_2, test_3, test_4
};

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	// Numbers of tests counted per functional test
	plan(5 + 3 + 2 + 3);

	// Just in case more than 1024 connections want to be tried
	struct rlimit limits { 0, 0 };
	getrlimit(RLIMIT_NOFILE, &limits);
	diag("test_session_hostgroup_metrics-t: Old process limits: { %ld, %ld }", limits.rlim_cur, limits.rlim_max);
	limits.rlim_cur = MAX_NUM_CONNECTIONS;
	setrlimit(RLIMIT_NOFILE, &limits);
	diag("test_session_hostgroup_metrics-t: New process limits: { %ld, %ld }", limits.rlim_cur, limits.rlim_max);

	MYSQL* proxysql_admin = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	auto reconnect_admin = [](CommandLine& cl, uint32_t timeout) -> MYSQL* {
		uint32_t count = 0;
		MYSQL* proxysql_admin;

		while (count < timeout) {
			MYSQL* tmp_conn = mysql_init(NULL);
			proxysql_admin = tmp_conn;

			bool connect_success =
				mysql_real_connect(tmp_conn, cl.host, cl.admin_username, cl.admin_password,
					NULL, cl.admin_port, NULL, 0) != nullptr;

			if (connect_success) {
				break;
			} else {
				mysql_close(tmp_conn);
				sleep(1);
			}
			count++;
		}

		return proxysql_admin;
	};

	for (const auto planned_test : planned_tests) {
		// MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS FROM DISK");
		// MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
		// MYSQL_QUERY(proxysql_admin, "SELECT * FROM stats_mysql_hostgroups_reset");
		// mysql_free_result(mysql_store_result(proxysql_admin));

		// usleep(500 * 1000);

		// int test_res = planned_test(cl, proxysql_admin, false);
		// if (test_res != EXIT_SUCCESS) {
		// 	break;
		// }

		// TODO: Currently disabled due to issue #3571.
		//
		mysql_query(proxysql_admin, "PROXYSQL RESTART");
		mysql_close(proxysql_admin);
		proxysql_admin = reconnect_admin(cl, 10);
		if (mysql_errno(proxysql_admin) != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return EXIT_FAILURE;
		}

		usleep(500 * 1000);
		
		int test_res = planned_test(cl, proxysql_admin, true);
		if (test_res != EXIT_SUCCESS) {
			break;
		}
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
