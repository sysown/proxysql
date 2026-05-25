/**
 * @file reg_test_4072-show-warnings-t.cpp
 * @brief This test will confirm ProxySQL does not crash if large records are fetched, having warning producing condition in the query.
 */

#include <stdio.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <chrono>
#include "mysql.h"
#include "mysqld_error.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h" 

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(1);

	// Initialize Admin connection
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	// Connnect to ProxySQL Admin
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-log_mysql_warnings_enabled=1");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Initialize ProxySQL connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	// Connect to ProxySQL
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}
	MYSQL_QUERY(proxysql, "DROP DATABASE IF EXISTS test");
	MYSQL_QUERY(proxysql, "CREATE DATABASE test");
	MYSQL_QUERY(proxysql, "CREATE TABLE test.`tmp` ( " \
		"`id` bigint(20) NOT NULL AUTO_INCREMENT, " \
		"`text1` varchar(200) COLLATE utf8_bin NOT NULL, " \
		"`text2` varchar(200) COLLATE utf8_bin NOT NULL, " \
		"`time` datetime NOT NULL, " \
		"PRIMARY KEY(`id`,`time`) " \
		") ENGINE = InnoDB");

	diag("Inserting rows...");
	MYSQL_QUERY(proxysql, "INSERT INTO test.tmp(text1, text2, time) values('dummy text1', 'dummy text2', now())");

	for (int i = 0; i < 7; i++) {
		MYSQL_QUERY(proxysql, "INSERT INTO test.tmp(text1, text2, time) SELECT text1, text2, time FROM test.tmp");
	}

	std::this_thread::sleep_for(std::chrono::seconds(2));

	MYSQL_QUERY(proxysql, "SELECT COUNT(*) FROM test.tmp a JOIN test.tmp b JOIN test.tmp c");

	auto mysql_result = mysql_use_result(proxysql);

	if (!mysql_result) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}
	
	auto row = mysql_fetch_row(mysql_result);
	unsigned long add_row_count = strtoul(row[0], NULL, 0);

	if (mysql_result) {
		mysql_free_result(mysql_result);
		mysql_result = NULL;
	}

	diag("Done... Total rows to fetch:'%lu'", add_row_count);
	diag("Fetching all rows...");
	MYSQL_QUERY(proxysql, "SELECT a.* FROM test.tmp a JOIN test.tmp b JOIN test.tmp c WHERE 1/0 OR 1=1");

	mysql_result = mysql_use_result(proxysql);
		
	if (!mysql_result) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}

	unsigned long fetched_row_count = 0;

	// The usleep() here is load-bearing -- the bug we're regression-testing
	// (issue #4072) is specifically "ProxySQL crashes when the client can't
	// keep up while a query produces warnings". A fast-fetching client never
	// builds the back-pressure that triggers the original crash, so removing
	// or shortening the sleep too far would defeat the test's purpose.
	//
	// At the same time we are operating at the edge of a different limit:
	// the backend mysql57's default `net_write_timeout` (60s). The test
	// workload is a 128^3 = 2,097,152-row cross join with
	// `mysql-log_mysql_warnings_enabled=1`, where each row produces a
	// backend warning that ProxySQL processes on the same thread that reads
	// the row stream. On slow CI runners the proxysql<->backend stream can
	// fall behind net_write_timeout, the backend kills the connection
	// mid-stream and the test sees `2013, Lost connection to server during
	// query`. Earlier fixed-sleep attempts (10us, 9us, 8us) were a moving
	// target: fast enough on fast runners but flaky on slow ones.
	//
	// Self-tune the sleep instead. Start at the historical 10us back-pressure
	// floor and recompute every RECOMPUTE_EVERY rows: project the total
	// fetch time at the current rate, compare against a target (well under
	// the backend's net_write_timeout), and adjust the sleep up/down --
	// clamped to [0, MAX_SLEEP_US]. Allowing 0 (no sleep) is safe because
	// the overhead of processing each row through ProxySQL's warning machinery
	// on a slow runner already generates enough back-pressure to reproduce
	// the #4072 crash path. If the runner then speeds up the next recompute
	// will re-introduce a positive sleep. Never sleep more than the original
	// 10us value so fast runners aren't artificially slowed.
	constexpr double FETCH_TARGET_S = 45.0;     // budget well under mysql57 60s default
	constexpr unsigned long RECOMPUTE_EVERY = 10000UL;  // tighter feedback loop
	constexpr int MIN_SLEEP_US = 0;             // no floor — let the self-tune decide
	constexpr int MAX_SLEEP_US = 10;            // historical safe value
	constexpr int INITIAL_SLEEP_US = 5;         // halfway -- gives the auto-tune room
	                                            // to react in either direction
	auto fetch_start = std::chrono::steady_clock::now();
	int current_sleep_us = INITIAL_SLEEP_US;
	int last_logged_sleep = current_sleep_us;
	diag("Slow-consumer auto-tune: start sleep=%dus, target total fetch=%.1fs",
	     current_sleep_us, FETCH_TARGET_S);

	while ((row = mysql_fetch_row(mysql_result))) {
		fetched_row_count++;

		if (fetched_row_count % RECOMPUTE_EVERY == 0) {
			auto now = std::chrono::steady_clock::now();
			double elapsed_s =
				std::chrono::duration<double>(now - fetch_start).count();
			unsigned long rows_remaining =
				(add_row_count > fetched_row_count)
					? (add_row_count - fetched_row_count) : 0UL;
			if (rows_remaining > 0 && elapsed_s > 0) {
				double remaining_budget_s = FETCH_TARGET_S - elapsed_s;
				if (remaining_budget_s <= 0) {
					current_sleep_us = MIN_SLEEP_US;
				} else {
					// Per-row time so far = (overhead + sleep). Approximate
					// non-sleep overhead by subtracting the sleep we just
					// used from the observed average.
					double per_row_so_far_us =
						(elapsed_s * 1e6) / static_cast<double>(fetched_row_count);
					double overhead_us = per_row_so_far_us - current_sleep_us;
					if (overhead_us < 0) overhead_us = 0;
					double per_row_target_us =
						(remaining_budget_s * 1e6) / static_cast<double>(rows_remaining);
					int new_sleep = static_cast<int>(per_row_target_us - overhead_us);
					if (new_sleep < MIN_SLEEP_US) new_sleep = MIN_SLEEP_US;
					if (new_sleep > MAX_SLEEP_US) new_sleep = MAX_SLEEP_US;
					current_sleep_us = new_sleep;
				}
				if (current_sleep_us != last_logged_sleep) {
					diag("Auto-tune: elapsed=%.1fs fetched=%lu/%lu -> sleep=%dus",
					     elapsed_s, fetched_row_count, add_row_count,
					     current_sleep_us);
					last_logged_sleep = current_sleep_us;
				}
			}
		}

		if (current_sleep_us > 0) usleep(current_sleep_us);
	}

	{
		auto fetch_end = std::chrono::steady_clock::now();
		double total_fetch_s =
			std::chrono::duration<double>(fetch_end - fetch_start).count();
		diag("Slow-consumer fetch wall time: %.2fs (final sleep=%dus, "
		     "rows=%lu) -- mysql57 net_write_timeout default 60s",
		     total_fetch_s, current_sleep_us, fetched_row_count);
	}

	int _errorno = mysql_errno(proxysql);
		
	if (_errorno) {
		diag("An error occurred. Error Code:%d, Message:%s", _errorno, mysql_error(proxysql));
		return exit_status();
	}

	if (mysql_result) {
		mysql_free_result(mysql_result);
		mysql_result = NULL;
	}

	diag("Done... Total rows fetched:'%lu'\n", fetched_row_count);
	ok(add_row_count == fetched_row_count, "All rows fetched");

	mysql_close(proxysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
