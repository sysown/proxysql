/**
 * @file test_admin_stats-t.cpp
 * @brief This tests the Statistics module and its lookup code and tables.
 * 
 * @details The following tests are performed :
 *  1. The lookup table has at least 50 rows generated after first metrics inserted
 *  2. There should be multiple distinct timestaps present in the history table
 *  3. The number of distinct variable_id's in the lookup and history tables should match
 *  4. Each variable_id has the same number of rows in history table
 *  5. The number of rows in the history table increases appropriately after insert interval changes
 *
 * @date 2021-10-28
 */

#include <algorithm>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::to_string;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

    /** @brief Minimum number of distinct variable_name strings in the history_mysql_status_variables_lookup table */
    const int min_distinct_variable_names = 50;

	plan(5);

	MYSQL* proxysql_admin = mysql_init(NULL);

	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Connnect to local proxysql
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Setup the interval of how often new status entries are created
	uint16_t new_stats_interval_sec = 5; // @note: valid values 5, 10, 30, 60, 120, 300

	// Run command to set the interval
	MYSQL_QUERY(proxysql_admin, ("SET admin-stats_mysql_connections=" + to_string(new_stats_interval_sec)).c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");	

	// If on a fresh install, wait long enough for the first run of stats to be created
	// The lookup table will be empty until the first run!
	sleep(new_stats_interval_sec + 1);
	
    // Test 1: Lookup table has at least 50 rows
	int64_t lookup_row_count = 0;
    MYSQL_QUERY(proxysql_admin, "SELECT COUNT(*) FROM history_mysql_status_variables_lookup");
	MYSQL_RES* result = mysql_store_result(proxysql_admin);
	MYSQL_ROW row = mysql_fetch_row(result);

	if (row[0]) 
		lookup_row_count = strtoll(row[0], nullptr, 10);
	
	mysql_free_result(result);

	ok(
		lookup_row_count >= 50,
		"Lookup table 'history_mysql_status_variables_lookup' has at least 50 rows. %lu rows found.",
		lookup_row_count
	);

	sleep(new_stats_interval_sec + 1);

	// Test 2: There are multiple distinct timestaps present in history table
	int64_t distinct_timestamp_count = 0; 
	MYSQL_QUERY(proxysql_admin, "SELECT COUNT(DISTINCT(timestamp)) FROM history_mysql_status_variables");
	result = mysql_store_result(proxysql_admin);
	row = mysql_fetch_row(result);

	if (row[0]) 
		distinct_timestamp_count = strtoll(row[0], nullptr, 10);

	mysql_free_result(result);

	ok(
		distinct_timestamp_count >= 2,
		"History table 'history_mysql_status_variables' has at least 2 distinct timestamps. %lu distinct timestamps found.",
		distinct_timestamp_count
	);

	// Test 3: Matching distinct variable_id counts in lookup and history table
	int64_t distinct_var_ids_in_history = 0;
	int64_t distinct_var_ids_in_lookup = 0;
	
	MYSQL_QUERY(proxysql_admin, "SELECT COUNT(DISTINCT(variable_id)) from history_mysql_status_variables_lookup");
	result = mysql_store_result(proxysql_admin);
	row = mysql_fetch_row(result);

	if (row[0])
		distinct_var_ids_in_lookup = strtoll(row[0], nullptr, 10);

	mysql_free_result(result);

	MYSQL_QUERY(proxysql_admin, "SELECT COUNT(DISTINCT(variable_id)) from history_mysql_status_variables");
	result = mysql_store_result(proxysql_admin);
	row = mysql_fetch_row(result);

	if (row[0])
		distinct_var_ids_in_history = strtoll(row[0], nullptr, 10);

	mysql_free_result(result);

	ok(
		distinct_var_ids_in_history == distinct_var_ids_in_lookup,
		"Distinct variable_id count matches in history and lookup tables. History:%lu, Lookup:%lu",
		distinct_var_ids_in_history,
		distinct_var_ids_in_lookup
	);

	// Test 4: Each variable_id has same number of rows in history table

	// As the CI tests are done on a fresh install, these should match in this instance
	// In practice, they could differ if new metrics variables are added.

	std::vector<int64_t> rows_per_var_id;
	time_t two_mins_ago = time(nullptr) - 60*2;
	const string query = "SELECT variable_id, COUNT(*) FROM history_mysql_status_variables WHERE timestamp < " + to_string(two_mins_ago) + " GROUP BY variable_id";
	MYSQL_QUERY(proxysql_admin, query.c_str());
	result = mysql_store_result(proxysql_admin);

	for (int i = 0; i < result->row_count; i++) {
		row = mysql_fetch_row(result);
		rows_per_var_id.push_back(strtoll(row[1], nullptr, 10));
	}

	mysql_free_result(result);

	bool each_var_row_count_equal = std::adjacent_find(rows_per_var_id.begin(), rows_per_var_id.end(), std::not_equal_to<int64_t>()) == rows_per_var_id.end(); // no adjacent unequal values found

	ok(
		each_var_row_count_equal,
		"Each variable_id in the history table has the same number of rows."
	);

	// Test 5: Number of rows in history table increases appropriately after insert interval changes
	int64_t history_rows_before = 0;
	int64_t history_rows_after = 0;

	MYSQL_QUERY(proxysql_admin, "SELECT COUNT(*) FROM history_mysql_status_variables");
	result = mysql_store_result(proxysql_admin);
	row = mysql_fetch_row(result);

	if (row[0])
		history_rows_before = strtoll(row[0], nullptr, 10);

	mysql_free_result(result);

	// Increase interval and wait for next round of inserts.
	// distinct_var_ids_in_history should equal the # of records inserted.
	// If the interval isn't updated, then there'd be double what's expected.
	new_stats_interval_sec = 10;
	MYSQL_QUERY(proxysql_admin, ("SET admin-stats_mysql_connections=" + to_string(new_stats_interval_sec)).c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	sleep(new_stats_interval_sec + 1); // give it time to insert next round of stats

	MYSQL_QUERY(proxysql_admin, "SELECT COUNT(*) FROM history_mysql_status_variables");
	result = mysql_store_result(proxysql_admin);
	row = mysql_fetch_row(result);

	if (row[0])
		history_rows_after = strtoll(row[0], nullptr, 10);

	mysql_free_result(result);

	ok(
		(history_rows_before + distinct_var_ids_in_history) == history_rows_after,
		"Number of rows in history table increases correctly after insert interval change. Before: %lu After: %lu Difference should be: %lu",
		history_rows_before,
		history_rows_after,
		distinct_var_ids_in_history
	);

	return exit_status();
}
