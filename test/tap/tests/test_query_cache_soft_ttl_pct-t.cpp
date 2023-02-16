/**
 * @file test_query_cache_soft_ttl_pct-t.cpp
 * @brief This test that query cache entries are refreshed when soft ttl is
 * reached.
 * @details This test configures a query rule with cache and configures the
 * global variable mysql-query_cache_soft_ttl_pct. Then, caches a
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

#define NUM_QUERIES	3
#define NUM_THREADS 8

CommandLine cl;
double timer_results[NUM_THREADS];

const char * DUMMY_QUERY = (const char *)"SELECT SLEEP(1)";

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

void run_dummy_query(double* timer_result) {
	MYSQL* proxy_mysql = mysql_init(NULL);

	if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		*timer_result = -1.0;
		return;
	}

	for (int i = 0; i < NUM_QUERIES; i++) {
		// execute the query at 1.4 , 2.8 and 4.2 second
		// Running 3 queries we verify:
		// 1. the cache before the threshold
		// 2. the cache after the threshold
		// 3. that the cache has been refreshed
		usleep(1400000);

		timer stopwatch;
		int err = mysql_query(proxy_mysql, DUMMY_QUERY);
		if (err) {
			diag("Failed to executed query `%s`", DUMMY_QUERY);
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
	diag("Queries hitting the cache:     %d", stats["cache"]);
	diag("Queries NOT hitting the cache: %d", stats["hostgroups"]);
	mysql_free_result(res);

	return stats;
}

int main(int argc, char** argv) {

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(3); // always specify the number of tests that are going to be performed

	MYSQL* proxy_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	vector<string> admin_queries = {
		"DELETE FROM mysql_query_rules",
		"INSERT INTO mysql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
		"UPDATE global_variables SET variable_value=50 WHERE variable_name='mysql-query_cache_soft_ttl_pct'",
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

	diag("Running: %s", DUMMY_QUERY);
	MYSQL_QUERY(proxy_mysql, DUMMY_QUERY); // We want to cache query "SELECT SLEEP(1)"

	MYSQL_RES* res = NULL;
	res = mysql_store_result(proxy_mysql);
	mysql_free_result(res);
	mysql_close(proxy_mysql);

	std::thread * mythreads[NUM_THREADS];

	// start all threads
	for (unsigned int i = 0; i < NUM_THREADS; i++)
		mythreads[i] = new std::thread(run_dummy_query, &timer_results[i]);

	// wait all threads to complete
	for (unsigned int i = 0; i < NUM_THREADS; i++)
		mythreads[i]->join();

	for (unsigned int i = 0; i < NUM_THREADS; i++) {
	if (timer_results[i] == -1.0) {
		fprintf(
			stderr, "File %s, line %d, Error: one or more threads finished with errors", __FILE__, __LINE__
		);
		mysql_close(proxy_admin);
		return EXIT_FAILURE;
	}
	}

	// Get the number of clients that take more 1 second or more to execute the
	// query by casting double to int.
	int num_slow_clients = 0;
	for (unsigned int i = 0; i < NUM_THREADS; i++) {
		num_slow_clients += (int)timer_results[i];
	}
	int expected_num_slow_clients = 1;
	ok(
		num_slow_clients == expected_num_slow_clients,
		"Only one client should take 1 second to execute the query. "
		"Number of clients that take more than 1 second - Exp:'%d', Act:'%d'",
		expected_num_slow_clients, num_slow_clients
	);

	std::map<string, int> stats_after = get_digest_stats_dummy_query(proxy_admin);

	std::map<string, int> expected_stats {{"cache", NUM_THREADS*NUM_QUERIES-1}, {"hostgroups", 2}};
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
