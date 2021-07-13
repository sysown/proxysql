/**
 * @file test_filtered_set_statements-t.cpp
 * @brief Test for checking that all the supported 'SET statements' are
 *   handled properly by ProxySQL.
 * @details The test performs all the valid supported combinations of
 *   all the specified 'SET' statements that should be specially handled
 *   by ProxySQL. For confirming that this is being the case, the test
 *   checks that 'sum_time' is always '0' for all these special queries
 *   after issuing them.
 *
 * @date 2021-03-26
 */

#include <vector>
#include <string>
#include <stdio.h>
#include <mysql.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include <iostream>

/**
 * @brief Queries to be tested that are known to be filtered by ProxySQL.
 *
 * TODO: Fill with all the statements that should be properly handled by ProxySQL.
 */
std::vector<std::pair<std::string, std::string>> filtered_set_queries {
	{ "sql_mode", "ONLY_FULL_GROUP_BY,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO" },
	{ "wait_timeout", "28801" },
	{ "character_set_results", "latin1" },
	{ "character_set_connection", "latin1" },
	{ "character_set_database", "latin1" },
//  TODO: This queries fails for some values
//  { "character_set_server", "latin1" },
//  { "character_set_client", "latin1" },
	{ "autocommit", "1" },
	{ "sql_select_limit", "4294967295" },
	{ "net_write_timeout", "25" },
	{ "max_join_size", "18446744073709551615" },
	{ "wsrep_sync_wait", "12" },
	{ "group_concat_max_len", "4294967295" },
	{ "sql_safe_updates", "true" },
	{ "session_track_gtids", "OWN_GTID" },
	{ "interactive_timeout", "28801" },
	{ "net_read_timeout", "28801" },
	// NOTE: This variable has been temporarily ignored. Check issues #3442 and #3441.
	{ "session_track_schema", "1" },
	// Added several variables to be set using `grave accents`. See issue #3479.
	{ "`wait_timeout`", "28801" },
	{ "`character_set_results`", "latin1" },
	{ "`character_set_results`", "latin1" },
	{ "`autocommit`", "1" },
	{ "`max_join_size`", "18446744073709551615" },
};

std::vector<std::string> get_valid_set_query_set(const std::string& set_query, const std::string param) {
	std::vector<std::string> result {};

	result.push_back(std::string("SET @@") + set_query + "=" + param);
	result.push_back(std::string("SET @@") + set_query + " = " + param);
	result.push_back(std::string("SET ") + set_query + "=" + param);
	result.push_back(std::string("SET ") + set_query + " = " + param);
	result.push_back(std::string("SET SESSION ") + set_query + "=" + param);
	result.push_back(std::string("SET SESSION ") + set_query + " = " + param);

	return result;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// plan one test per statement attempt + one check 'SUM(sum_time) == 0' for each 'filtered_set_queries'
	plan(filtered_set_queries.size() + filtered_set_queries.size()*get_valid_set_query_set("", "").size());

	// create a regular connection to 'proxysql'
	MYSQL* proxysql_mysql = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}

	// create a connection to 'proxysql_admin'
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_password, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// first clean the 'stats_mysql_query_digest' table
	MYSQL_QUERY(proxysql_admin, "SELECT null FROM stats.stats_mysql_query_digest_reset LIMIT 0");
	MYSQL_RES* reset_result = mysql_store_result(proxysql_admin);
	mysql_free_result(reset_result);

	std::string t_sum_query { "SELECT SUM(sum_time) FROM stats.stats_mysql_query_digest WHERE digest_text LIKE '%%%s%%'" };

	for (const auto& filtered_query : filtered_set_queries) {
		const std::vector<std::string> f_filtered_query_set =
			get_valid_set_query_set(filtered_query.first, filtered_query.second);

		for (const auto& set_query : f_filtered_query_set) {
			int query_err = mysql_query(proxysql_mysql, set_query.c_str());
			ok (query_err == 0, "Query '%s' should be properly executed.", set_query.c_str());

		}

		std::string sum_query { "" };
		string_format(t_sum_query, sum_query, filtered_query.first.c_str());
		MYSQL_QUERY(proxysql_admin, sum_query.c_str());

		MYSQL_RES* sum_query_res = mysql_store_result(proxysql_admin);
		int sum_sum_time = -1;

		int field_count = mysql_num_fields(sum_query_res);
		if (field_count == 1) {
			MYSQL_ROW row = mysql_fetch_row(sum_query_res);

			if (row[0] != nullptr) {
				sum_sum_time = atoi(row[0]);
			}
		}

		mysql_free_result(sum_query_res);

		ok (
			sum_sum_time == 0,
			"The SUM(sum_time) of all the variations for the 'set_statements:%s' should be zero. Value was: %d",
			filtered_query.first.c_str(),
			sum_sum_time
		);
	}

	// close proxysql connection
	mysql_close(proxysql_mysql);

	// close admin connection
	mysql_close(proxysql_admin);

	return exit_status();
}
