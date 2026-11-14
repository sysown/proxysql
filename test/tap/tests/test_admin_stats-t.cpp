/**
 * @file test_admin_stats-t.cpp
 * @brief This tests the Statistics module and its lookup code and tables.
 * 
 * @details The following tests are performed :
 *  1. The current sampler has at least 50 lookup-backed variables
 *  2. There should be multiple distinct timestaps present in the history table
 *  3. Every currently sampled variable_id should have a lookup entry
 *  4. Each variable_id has the same number of rows in history table
 *  5. The number of rows in the history table increases appropriately after insert interval changes
 *
 * @date 2021-10-28
 */

#include <algorithm>
#include <chrono>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "noise_utils.h"

using std::string;
using std::to_string;
using std::vector;

struct history_cohort {
	uint64_t timestamp;
	int64_t rows;
};

/**
 * @brief Fetch timestamp cohorts newer than 'after_timestamp'.
 *
 * The latest timestamp can be observed while its main and MyHGM stages are
 * still being inserted, so a cohort is only considered complete when it has
 * one lookup-backed row for every currently sampled variable.
 */
int fetch_full_cohorts(MYSQL* proxysql_admin, uint64_t after_timestamp, int64_t full_row_count,
	vector<history_cohort>& cohorts, string& error, bool closed_only = false) {
	cohorts.clear();
	error.clear();

	const string query =
		"SELECT h.timestamp, COUNT(*), COUNT(l.variable_id) "
		"FROM history_mysql_status_variables h LEFT JOIN history_mysql_status_variables_lookup l USING(variable_id) "
		"WHERE h.timestamp > " + to_string(after_timestamp) +
		" GROUP BY h.timestamp ORDER BY h.timestamp ASC";

	if (mysql_query(proxysql_admin, query.c_str())) {
		error = string("history cohort query failed: ") + mysql_error(proxysql_admin);
		return EXIT_FAILURE;
	}

	MYSQL_RES* result = mysql_store_result(proxysql_admin);
	if (result == NULL) {
		error = string("history cohort result failed: ") + mysql_error(proxysql_admin);
		return EXIT_FAILURE;
	}

	uint64_t latest_timestamp = 0;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) {
		if (row[0] == NULL || row[1] == NULL || row[2] == NULL) {
			continue;
		}

		history_cohort cohort {
			static_cast<uint64_t>(strtoull(row[0], nullptr, 10)),
			strtoll(row[1], nullptr, 10)
		};

		latest_timestamp = cohort.timestamp;
		if (cohort.rows == full_row_count && strtoll(row[2], nullptr, 10) == full_row_count) {
			cohorts.push_back(cohort);
		}
	}

	mysql_free_result(result);
	if (closed_only && !cohorts.empty() && cohorts.back().timestamp == latest_timestamp) {
		cohorts.pop_back();
	}
	return EXIT_SUCCESS;
}

/**
 * @brief Wait for at least two complete cohorts newer than 'anchor'.
 *
 * Polls once per second for up to 'timeout' seconds. Complete cohorts are
 * timestamp groups whose row count equals the active sampler size, so an
 * incomplete latest timestamp cannot become a window boundary.
 */
int wait_for_full_cohorts(MYSQL* proxysql_admin, uint64_t anchor, int64_t& full_row_count,
	uint32_t timeout, vector<history_cohort>& cohorts) {
	string error;

	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
	while (true) {
		// Lookup IDs survive upgrades. Only new closed sampler output defines
		// the expected set; the newest timestamp may still be in progress.
		const string active_query =
			"SELECT COUNT(DISTINCT variable_id) FROM history_mysql_status_variables WHERE timestamp > " +
			to_string(anchor) + " AND timestamp < (SELECT MAX(timestamp) FROM history_mysql_status_variables)";
		MYSQL_QUERY(proxysql_admin, active_query.c_str());
		MYSQL_RES* lookup = mysql_store_result(proxysql_admin);
		if (lookup == nullptr) {
			return EXIT_FAILURE;
		}
		MYSQL_ROW row = mysql_fetch_row(lookup);
		full_row_count = (row && row[0]) ? strtoll(row[0], nullptr, 10) : 0;
		mysql_free_result(lookup);
		if (full_row_count >= 50
			&& fetch_full_cohorts(proxysql_admin, anchor, full_row_count, cohorts, error, true) == EXIT_SUCCESS
			&& cohorts.size() >= 2) {
			return EXIT_SUCCESS;
		}

		if (std::chrono::steady_clock::now() >= deadline) {
			break;
		}
		diag("Waiting for complete 'history_mysql_status_variables' cohorts...");
		sleep(1);
	}

	diag("Timed out after %u seconds waiting for complete history cohorts: %s",
		timeout, error.empty() ? "fewer than two complete cohorts" : error.c_str());
	return EXIT_FAILURE;
}

int wait_for_next_full_cohort(MYSQL* proxysql_admin, uint64_t anchor, int64_t full_row_count,
	uint32_t timeout, history_cohort& cohort) {
	string error;
	vector<history_cohort> cohorts;

	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
	while (true) {
		if (fetch_full_cohorts(proxysql_admin, anchor, full_row_count, cohorts, error) != EXIT_SUCCESS) {
			diag("%s", error.c_str());
			return EXIT_FAILURE;
		}
		if (!cohorts.empty()) {
			cohort = cohorts.front();
			return EXIT_SUCCESS;
		}
		if (std::chrono::steady_clock::now() >= deadline) {
			break;
		}
		diag("Waiting for the next complete 'history_mysql_status_variables' cohort...");
		sleep(1);
	}

	diag("Timed out after %u seconds waiting for the next complete history cohort: %s",
		timeout, error.empty() ? "no complete cohort found" : error.c_str());
	return EXIT_FAILURE;
}

// Complete the whole observed range rather than one timestamp: the main and
// MyHGM stages can land in adjacent seconds. No interior rows are discarded.
int wait_for_balanced_history(MYSQL* proxysql_admin, uint64_t anchor, int64_t expected_variables,
	uint32_t timeout, int64_t& new_rows) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
	const string query =
		"SELECT h.variable_id, COUNT(*), MAX(l.variable_id) "
		"FROM history_mysql_status_variables h LEFT JOIN history_mysql_status_variables_lookup l USING(variable_id) "
		"WHERE h.timestamp > " + to_string(anchor) + " GROUP BY h.variable_id";
	while (true) {
		MYSQL_QUERY(proxysql_admin, query.c_str());
		MYSQL_RES* result = mysql_store_result(proxysql_admin);
		if (result == nullptr) {
			return EXIT_FAILURE;
		}
		const uint64_t variable_count = mysql_num_rows(result);
		int64_t rows_per_variable = -1;
		new_rows = 0;
		bool balanced = variable_count == static_cast<uint64_t>(expected_variables);
		MYSQL_ROW row;
		while ((row = mysql_fetch_row(result))) {
			const int64_t count = row[1] ? strtoll(row[1], nullptr, 10) : 0;
			if (rows_per_variable == -1) {
				rows_per_variable = count;
			}
			balanced = balanced && row[2] != nullptr && count == rows_per_variable;
			new_rows += count;
		}
		mysql_free_result(result);
		// No sample within the observation interval must fail the cadence check;
		// waiting for a later sample here would make a slow interval pass.
		if (variable_count == 0 || balanced) {
			return EXIT_SUCCESS;
		}
		if (std::chrono::steady_clock::now() >= deadline) {
			diag("Timed out after %u seconds waiting for all history insertion stages", timeout);
			return EXIT_FAILURE;
		}
		sleep(1);
	}
}

int64_t count_rows_through_timestamp(MYSQL* proxysql_admin, uint64_t timestamp) {
	const string query =
		"SELECT COUNT(*) FROM history_mysql_status_variables WHERE timestamp <= " +
		to_string(timestamp);

	if (mysql_query(proxysql_admin, query.c_str())) {
		diag("Failed to count history rows through timestamp '%llu': '%s'",
			static_cast<unsigned long long>(timestamp), mysql_error(proxysql_admin));
		return -1;
	}

	MYSQL_RES* result = mysql_store_result(proxysql_admin);
	if (result == NULL) {
		diag("NULL history row count result: '%s'", mysql_error(proxysql_admin));
		return -1;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	int64_t row_count = (row && row[0]) ? strtoll(row[0], nullptr, 10) : -1;
	mysql_free_result(result);
	return row_count;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	spawn_internal_noise(cl, internal_noise_admin_pinger);
	spawn_internal_noise(cl, internal_noise_random_stats_poller);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});

    /** @brief Minimum number of lookup-backed variables emitted by the current sampler */
    const int min_distinct_variable_names = 50;

	if (cl.use_noise) {
		plan(5 + 3);
	} else {
		plan(5);
	}

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

	// Freeze a non-destructive window starting after the newest pre-existing
	// timestamp. No history rows are removed, so an insertion stage that is
	// already in progress cannot be split by the test.
	uint64_t window_anchor = 0;
	MYSQL_QUERY(proxysql_admin, "SELECT COALESCE(MAX(timestamp), 0) FROM history_mysql_status_variables");
	MYSQL_RES* result = mysql_store_result(proxysql_admin);
	if (result == nullptr) {
		return EXIT_FAILURE;
	}
	MYSQL_ROW row = mysql_fetch_row(result);
	if (row && row[0]) {
		window_anchor = strtoull(row[0], nullptr, 10);
	}
	mysql_free_result(result);

	// Setup the interval of how often new status entries are created
	uint16_t new_stats_interval_sec = 5; // @note: valid values 5, 10, 30, 60, 120, 300

	// Run command to set the interval
	MYSQL_QUERY(proxysql_admin, ("SET admin-stats_mysql_connections=" + to_string(new_stats_interval_sec)).c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");	

	// Wait on sampler progress, retaining every interior row between the first
	// and last complete closed cohorts. The newest timestamp is never a boundary.
	int64_t lookup_row_count = 0;
	vector<history_cohort> frozen_cohorts;
	const int window_res = wait_for_full_cohorts(proxysql_admin, window_anchor, lookup_row_count, 20, frozen_cohorts);
	ok(
		lookup_row_count >= min_distinct_variable_names,
		"Current sampler has at least 50 lookup-backed variables. %lu variables found.",
		lookup_row_count
	);
	if (window_res != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	const uint64_t window_start = frozen_cohorts.front().timestamp;
	const uint64_t window_end = frozen_cohorts.back().timestamp;
	const string window_filter =
		"timestamp BETWEEN " + to_string(window_start) + " AND " + to_string(window_end);
	diag("Frozen history window: %llu through %llu", static_cast<unsigned long long>(window_start),
		static_cast<unsigned long long>(window_end));

	// Test 2: There are multiple distinct timestaps present in the frozen window
	int64_t distinct_timestamp_count = 0; 
	MYSQL_QUERY(proxysql_admin, ("SELECT COUNT(DISTINCT(timestamp)) FROM history_mysql_status_variables WHERE " + window_filter).c_str());
	result = mysql_store_result(proxysql_admin);
	row = mysql_fetch_row(result);

	if (row && row[0])
		distinct_timestamp_count = strtoll(row[0], nullptr, 10);

	mysql_free_result(result);

	ok(
		distinct_timestamp_count >= 2,
		"History table 'history_mysql_status_variables' has at least 2 distinct timestamps. %lu distinct timestamps found.",
		distinct_timestamp_count
	);

	// Test 3: Every distinct variable_id in the new window has a lookup entry
	int64_t distinct_var_ids_in_history = -1;
	int64_t distinct_var_ids_in_lookup = -1;
	
	// Restrict the append-only lookup to IDs emitted in this new window.
	// A missing lookup ID still makes this count differ from history below.
	MYSQL_QUERY(proxysql_admin, ("SELECT COUNT(DISTINCT l.variable_id) FROM "
		"history_mysql_status_variables_lookup l JOIN history_mysql_status_variables h USING(variable_id) WHERE h." +
		window_filter).c_str());
	result = mysql_store_result(proxysql_admin);
	if (result == NULL) {
		diag("NULL result received. Errno: '%d', Error: '%s'", mysql_errno(proxysql_admin), mysql_error(proxysql_admin));
	}
	row = mysql_fetch_row(result);

	if (row && row[0])
		distinct_var_ids_in_lookup = strtoll(row[0], nullptr, 10);

	mysql_free_result(result);

	MYSQL_QUERY(proxysql_admin, ("SELECT COUNT(DISTINCT(variable_id)) from history_mysql_status_variables WHERE " + window_filter).c_str());
	result = mysql_store_result(proxysql_admin);
	if (result == NULL) {
		diag("NULL result received. Errno: '%d', Error: '%s'", mysql_errno(proxysql_admin), mysql_error(proxysql_admin));
	}
	row = mysql_fetch_row(result);

	if (row && row[0])
		distinct_var_ids_in_history = strtoll(row[0], nullptr, 10);

	mysql_free_result(result);

	ok(
		distinct_var_ids_in_history == distinct_var_ids_in_lookup,
		"Distinct variable_id count matches in history and lookup tables. History:%lu, Lookup:%lu",
		distinct_var_ids_in_history,
		distinct_var_ids_in_lookup
	);

	// Test 4: Each variable_id has same number of rows in the frozen history window

	// All rows inside the bounds count, including any incomplete interior cohort.

	std::vector<int64_t> rows_per_var_id;
	const string query =
		"SELECT variable_id, COUNT(*) FROM history_mysql_status_variables WHERE " +
		window_filter + " GROUP BY variable_id";
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

	// Establish the baseline after changing the interval. A complete boundary
	// keeps the two insertion stages out of the row-count comparison.
	MYSQL_QUERY(proxysql_admin, "SELECT COALESCE(MAX(timestamp), 0) FROM history_mysql_status_variables");
	result = mysql_store_result(proxysql_admin);
	if (result == nullptr) {
		return EXIT_FAILURE;
	}
	row = mysql_fetch_row(result);
	const uint64_t cadence_anchor = (row && row[0]) ? strtoull(row[0], nullptr, 10) : 0;
	mysql_free_result(result);

	new_stats_interval_sec = 10;
	MYSQL_QUERY(proxysql_admin, ("SET admin-stats_mysql_connections=" + to_string(new_stats_interval_sec)).c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	history_cohort cadence_baseline;
	if (wait_for_next_full_cohort(proxysql_admin, cadence_anchor, lookup_row_count, 20, cadence_baseline) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	history_rows_before = count_rows_through_timestamp(proxysql_admin, cadence_baseline.timestamp);
	if (history_rows_before < 0) {
		return EXIT_FAILURE;
	}

	sleep(new_stats_interval_sec + 1);

	// If the observed sample is still being written, wait for equal counts
	// across every expected variable. Keeping the entire range means an old
	// five-second cadence produces two cohorts and still fails the assertion.
	int64_t new_history_rows = 0;
	if (wait_for_balanced_history(proxysql_admin, cadence_baseline.timestamp, lookup_row_count,
		20, new_history_rows) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	history_rows_after = history_rows_before + new_history_rows;

	ok(
		(history_rows_before + distinct_var_ids_in_history) == history_rows_after,
		"Number of rows in history table increases correctly after insert interval change. Before: %lu After: %lu Difference should be: %lu",
		history_rows_before,
		history_rows_after,
		distinct_var_ids_in_history
	);

	return exit_status();
}
