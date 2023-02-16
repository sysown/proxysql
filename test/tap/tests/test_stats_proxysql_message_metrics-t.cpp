/**
 * @file test_stats_proxysql_message_metrics-t.cpp
 * @brief This test verifies the behavior of table 'stats_proxysql_message_metrics'.
 * @date 2022-03-23
 */

#include <vector>
#include <string>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "utils.h"

using std::vector;
using std::string;

int induce_set_parsing_failure(MYSQL* proxy) {
	int rc = mysql_query(proxy, "SET NAMES");
	if (rc != EXIT_FAILURE) {
		diag(
			"Invalid query 'SET NAMES' should have failed - ErrCode: %d, ErrMsg: %s",
			mysql_errno(proxy), mysql_error(proxy)
		);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int test_table_reset(MYSQL* proxy_admin) {
	// Initial reset
	int rc = mysql_query(proxy_admin, "SELECT * FROM stats.stats_proxysql_message_metrics_reset");
	ok(rc == EXIT_SUCCESS, "Successfully queries 'stats.stats_proxysql_message_metrics_reset'");
	mysql_free_result(mysql_store_result(proxy_admin));
	if (rc == EXIT_FAILURE) { return EXIT_FAILURE; }

	// Query the table again and check it's empty
	MYSQL_QUERY(proxy_admin, "SELECT * FROM stats.stats_proxysql_message_metrics");
	MYSQL_RES* my_res = mysql_store_result(proxy_admin);
	uint64_t num_rows = mysql_num_rows(my_res);
	mysql_free_result(my_res);
	ok(num_rows == 0, "After reset 'stats.stats_proxysql_message_metrics' should be empty");

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	plan(
		2 + // Table reset and check empty table
		3 + // Initial table population + Update check
		2   // Check proper reset again
	);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxy = mysql_init(NULL);
	MYSQL* proxy_admin = mysql_init(NULL);

	// Initialize connections
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}
	if (!proxy_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	// Reset the target table and check it's empty but present in 'stats' db
	{
		if (test_table_reset(proxy_admin) != EXIT_SUCCESS) { return EXIT_FAILURE; }
	}

	// Create failure triggering the intented logging: PMC-10002
	{
		if (induce_set_parsing_failure(proxy) != EXIT_SUCCESS) { return EXIT_FAILURE; }
	}

	// Check table is populated
	{
		MYSQL_QUERY(proxy_admin, "SELECT * FROM stats.stats_proxysql_message_metrics");
		MYSQL_RES* my_res = mysql_store_result(proxy_admin);
		uint64_t num_rows = mysql_num_rows(my_res);

		// Data expected not to change in a regular basis
		const string exp_msgid { "10002" };
		const string exp_filename { "MySQL_Session.cpp" };
		const string exp_func { "handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo" };
		// Generated data
		uint64_t exp_count_star = 1;
		time_t exp_aprox_first_seen = time(NULL);

		ok(num_rows == 1, "Table has been properly populated and now contains '%ld' rows", num_rows);
		if (num_rows == 1) {
			vector<string> row = extract_mysql_rows(my_res)[0];

			const string act_msgid { row[0] };
			const string act_filename { row[1] };
			const uint64_t act_line = std::stoll(row[2]);
			const string act_func { row[3] };

			const uint64_t act_count_star = std::stoll(row[4]);
			const uint64_t act_first_seen = std::stoll(row[5]);
			const uint64_t act_last_seen = std::stoll(row[6]);

			bool first_seen_in_exp_interval =
				(exp_aprox_first_seen + 2) > act_first_seen && (exp_aprox_first_seen - 2) < act_first_seen;

			bool message_id_matches_exp =
				exp_msgid == act_msgid && exp_filename == act_filename && exp_func == act_func && act_line != 0 &&
				first_seen_in_exp_interval && act_first_seen == act_last_seen;

			const char* ok_msg =
				"Message id info matches expected: {"
					"{ exp_msgid: '%s', act_msgid: '%s' }, { exp_filename: '%s', act_filename: '%s' },"
					"{ exp_func: '%s', act_func: '%s' }, { exp_line: '%s', act_line: '%d' },"
					"{ exp_count_star: '%d', act_count_star: '%d' }, { exp_first_seen: '%d'(+/-2), act_first_seen: '%d' },"
					"{ act_first_seen: '%d', act_last_seen: '%d' }"
				" }";

			// Simple data consistency check
			ok(
				message_id_matches_exp, ok_msg, exp_msgid.c_str(), act_msgid.c_str(), exp_filename.c_str(),
				act_filename.c_str(), exp_func.c_str(), act_func.c_str(), "NonZero", act_line, exp_count_star,
				act_count_star, exp_aprox_first_seen, act_first_seen, act_first_seen, act_last_seen
			);

			// Check that values are properly incremented
			usleep(1000*1500);

			if (induce_set_parsing_failure(proxy) != EXIT_SUCCESS) { return EXIT_FAILURE; }
			MYSQL_QUERY(proxy_admin, "SELECT * FROM stats.stats_proxysql_message_metrics");
			my_res = mysql_store_result(proxy_admin);
			row = extract_mysql_rows(my_res)[0];

			const uint64_t new_count_star = std::stoll(row[4]);
			const uint64_t new_first_seen = std::stoll(row[5]);
			const uint64_t new_last_seen = std::stoll(row[6]);

			bool vals_updated =
				new_count_star == (act_count_star + 1) &&
				new_first_seen == act_first_seen &&
				new_last_seen > act_last_seen;

			const char* new_ok_msg =
				"Updated values matches expected: {"
					"{ new_count_star: '%d', act_count_star: '%d + 1' }, { new_first_seen: '%d', act_first_seen: '%d' },"
					"{ new_last_seen: '%d' > act_last_seen: '%d' }"
				"}";

			ok(
				vals_updated, new_ok_msg, new_count_star, act_count_star, new_first_seen, act_first_seen,
				new_last_seen, act_last_seen
			);

			// Check table reset again once it's populated
			if (test_table_reset(proxy_admin) != EXIT_SUCCESS) { return EXIT_FAILURE; }
		}
	}
}
