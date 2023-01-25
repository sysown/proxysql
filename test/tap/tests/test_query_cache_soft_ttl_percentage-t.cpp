/**
 * @file test_query_cache_soft_ttl_percentage-t.cpp
 * @brief This test that query cache entries are refreshed when soft ttl is
 * reached.
 * @details This test configures a query rule with cache and configures the
 * global variable mysql-query_cache_soft_ttl_percentage. Then, caches a
 * "SELECT SLEEP(1) and creates 4 threads to send this same query when the soft
 * ttl have been reached. Finally, checks that only one of the threads has hit
 * the hostgroup looking at how long it has taken for each thread to execute
 * the query, and looking in the table "stats_mysql_query_digest"
 */

#include <unistd.h>
#include <iostream>
#include <mysql.h>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <map>

#include "proxysql_utils.h"
#include "command_line.h"
#include "utils.h"
#include "tap.h"

using std::vector;
using std::string;

double timer_result_one = 0;
double timer_result_two = 0;
double timer_result_three = 0;
double timer_result_four = 0;

const string DUMMY_QUERY = "SELECT SLEEP(1)";

class timer {
public:
	std::chrono::time_point<std::chrono::high_resolution_clock> lastTime;
	timer() : lastTime(std::chrono::high_resolution_clock::now()) {}
	inline double elapsed() {
		std::chrono::time_point<std::chrono::high_resolution_clock> thisTime = std::chrono::high_resolution_clock::now();
		double deltaTime = std::chrono::duration<double>(thisTime-lastTime).count();
		lastTime = thisTime;
		return deltaTime;
	}
};

void run_dummy_query(
	const char* host, const char* username, const char* password, const int port, double* timer_result
) {
	MYSQL* proxy_mysql = mysql_init(NULL);

	if (!mysql_real_connect(proxy_mysql, host, username, password, NULL, port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		*timer_result = -1.0;
		return;
	}

	int soft_ttl_seconds = 2;

	for (int i = 0; i < 2; i++) {
		sleep(1);

		timer stopwatch;
		int err = mysql_query(proxy_mysql, DUMMY_QUERY.c_str());
		if (err) {
			diag("Failed to executed query `%s`", DUMMY_QUERY.c_str());
			*timer_result = -1.0;
			mysql_close(proxy_mysql);
			return;
		}
		*timer_result += stopwatch.elapsed();

		MYSQL_RES* res = NULL;
		res = mysql_store_result(proxy_mysql);
		mysql_free_result(res);
	}

	mysql_close(proxy_mysql);
}

const string STATS_QUERY_DIGEST =
	"SELECT hostgroup, SUM(count_star) FROM stats_mysql_query_digest "
	"WHERE digest_text = 'SELECT SLEEP(?)' GROUP BY hostgroup";

std::map<string, int> get_digest_stats_dummy_query(MYSQL* proxy_admin) {
	diag("Running: %s", STATS_QUERY_DIGEST.c_str());
	mysql_query(proxy_admin, STATS_QUERY_DIGEST.c_str());

	std::map<string, int> stats {{"cache", 0}, {"hostgroups", 0}}; // {hostgroup, count_star}

	MYSQL_RES* res = mysql_store_result(proxy_admin);

	MYSQL_ROW row;
	while (row = mysql_fetch_row(res)) {
		if (atoi(row[0]) == -1)
			stats["cache"] += atoi(row[1]);
		else
			stats["hostgroups"] += atoi(row[1]);
	}
	mysql_free_result(res);

	return stats;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxy_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	vector<string> admin_queries = {
		"UPDATE mysql_query_rules SET cache_ttl = 4000 WHERE rule_id = 2",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
		"UPDATE global_variables SET variable_value=50 WHERE variable_name='mysql-query_cache_soft_ttl_percentage'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};

	for (const auto &query : admin_queries) {
		diag("Running: %s", query.c_str());
		MYSQL_QUERY(proxy_admin, query.c_str());
	}

	std::map<string, int> stats_before = get_digest_stats_dummy_query(proxy_admin);

	MYSQL* proxy_mysql = mysql_init(NULL);
	if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		mysql_close(proxy_admin);
		return EXIT_FAILURE;
	}

	diag("Running: %s", DUMMY_QUERY.c_str());
	MYSQL_QUERY(proxy_mysql, DUMMY_QUERY.c_str()); // We want to cache query "SELECT SLEEP(1)"

	MYSQL_RES* res = NULL;
	res = mysql_store_result(proxy_mysql);
	mysql_free_result(res);
	mysql_close(proxy_mysql);

	std::thread client_one(
		run_dummy_query, cl.host, cl.username, cl.password, cl.port, &timer_result_one
	);
	std::thread client_two(
		run_dummy_query, cl.host, cl.username, cl.password, cl.port, &timer_result_two
	);
	std::thread client_three(
		run_dummy_query, cl.host, cl.username, cl.password, cl.port, &timer_result_three
	);
	std::thread client_four(
		run_dummy_query, cl.host, cl.username, cl.password, cl.port, &timer_result_four
	);
	client_one.join();
	client_two.join();
	client_three.join();
	client_four.join();

	if (
		timer_result_one == -1.0 ||
		timer_result_two == -1.0 ||
		timer_result_three == -1.0 ||
		timer_result_four == -1.0
	) {
		fprintf(
			stderr, "File %s, line %d, Error: one or more threads finished with errors", __FILE__, __LINE__
		);
		mysql_close(proxy_admin);
		return EXIT_FAILURE;
	}

	// Get the number of clients that take more 1 second or more to execute the
	// query by casting double to int.
	int num_slow_clients =
		(int)(timer_result_one + timer_result_two + timer_result_three + timer_result_four);
	int expected_num_slow_clients = 1;
	ok(
		num_slow_clients == expected_num_slow_clients,
		"Only one client should take 1 second to execute the query. "
		"Number of clients that take more than 1 second - Exp:'%d', Act:'%d'",
		expected_num_slow_clients, num_slow_clients
	);

	std::map<string, int> stats_after = get_digest_stats_dummy_query(proxy_admin);

	std::map<string, int> expected_stats {{"cache", 7}, {"hostgroups", 2}};
	ok(
		expected_stats["cache"] == stats_after["cache"] - stats_before["cache"],
		"Query cache should have been hit %d times. Number of hits - Exp:'%d', Act:'%d'",
		expected_stats["cache"], expected_stats["cache"], stats_after["cache"] - stats_before["cache"]
	);
	ok(
		expected_stats["hostgroups"] == stats_after["hostgroups"] - stats_before["hostgroups"],
		"Hostgroups should have been hit %d times. Number of hits - Exp:'%d', Act:'%d'",
		expected_stats["hostgroups"], expected_stats["hostgroups"],
		stats_after["hostgroups"] - stats_before["hostgroups"]
	);

	return exit_status();
}
