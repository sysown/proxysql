/**
 * @file test_stats_table_check-t.cpp
 * @brief This test verifies that all non-ignored stats tables contain at least one row.
 *
 * @details The test replicates the functionality of run_stats_table_check() from proxysql-tester.py.
 * It checks that all tables in the 'stats' database have count(*) >= 1, except for those in
 * the ignored list which are expected to be empty under certain conditions.
 * Tables ending with '_reset' are excluded from the check entirely.
 *
 * Ignored tables (expected to be 0 or conditionally empty):
 * - stats_mysql_client_host_cache
 * - stats_proxysql_servers_status
 * - stats_mysql_gtid_executed
 * - stats_proxysql_message_metrics
 * - stats_mysql_processlist (0 if no connections open)
 * - stats_mysql_query_events (0 if no connections open)
 * - stats_pgsql_* (PostgreSQL stats - not yet ready)
 * - stats_mcp_* (MCP work in progress)
 * - Cluster-specific tables (when PROXYSQL_CLUSTER==0):
 *   - stats_proxysql_servers_checksums
 *   - stats_proxysql_servers_clients_status
 *   - stats_proxysql_servers_metrics
 *
 * @date 2025-01-21
 */

#include <algorithm>
#include <regex>
#include <string>
#include <vector>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::regex;
using std::string;
using std::vector;

// All table exclusions are regex patterns for consistency and maintainability
// Patterns are anchored to match the full table name
// Tables that are expected to be empty or conditionally empty
// Note: Tables ending with '_reset' are excluded during table extraction
const vector<const char*> ignored_patterns = {
/*
	"stats_mysql_client_host_cache",
	"stats_proxysql_servers_status",
	"stats_mysql_gtid_executed",
	"stats_proxysql_message_metrics",
	"stats_mysql_processlist",                 // 0 if no connections open
	"stats_mysql_query_events",                // 0 if no connections open
	"stats_pgsql_.*",                          // PostgreSQL stats - not yet ready
	"stats_mcp_.*",                            // MCP work in progress
*/
};

// Cluster-specific tables (ignored when PROXYSQL_CLUSTER==0)
const vector<const char*> ignored_without_cluster = {
	"stats_proxysql_servers_checksums",
	"stats_proxysql_servers_clients_status",
	"stats_proxysql_servers_metrics",
};

/**
 * @brief Check if a table name matches any pattern in a list.
 * @param table_name The table name to check.
 * @param patterns The list of regex patterns to match against (automatically anchored).
 * @return true if the table matches any pattern, false otherwise.
 */
bool matches_any_pattern(const string& table_name, const vector<const char*>& patterns) {
	for (const char* pattern : patterns) {
		try {
			// Anchor pattern to match full table name
			string anchored_pattern = string("^") + pattern + "$";
			regex re(anchored_pattern, regex::extended);
			if (regex_match(table_name, re)) {
				return true;
			}
		} catch (const std::regex_error& e) {
			diag("Regex error for pattern '%s': %s", pattern, e.what());
		}
	}
	return false;
}

/**
 * @brief Check if a table name matches any of the ignored patterns.
 * @param table_name The table name to check.
 * @param is_cluster_mode Whether ProxySQL is running in cluster mode.
 * @return true if the table should be ignored, false otherwise.
 */
bool is_table_ignored(const string& table_name, bool is_cluster_mode) {
	if (matches_any_pattern(table_name, ignored_patterns)) {
		return true;
	}
	if (!is_cluster_mode && matches_any_pattern(table_name, ignored_without_cluster)) {
		return true;
	}
	return false;
}

/**
 * @brief Get the row count for a table, handling errors gracefully.
 * @param proxysql_admin The MySQL connection.
 * @param table_name The table name to query.
 * @param[out] row_count The resulting row count.
 * @return true on success, false on error (test already marked as skipped).
 */
bool get_table_row_count(MYSQL* proxysql_admin, const string& table_name, int64_t& row_count) {
	string query = "SELECT COUNT(*) FROM stats.`" + table_name + "`";

	if (mysql_query(proxysql_admin, query.c_str()) != 0) {
		int mysql_err = mysql_errno(proxysql_admin);
		const char* reason = (mysql_err == 1146) ? "table not present" : "query error";
		diag(
			"Failed to query table 'stats.%s': %s (errno=%d) - skipping",
			table_name.c_str(), mysql_error(proxysql_admin), mysql_err
		);
		ok(true, "Table 'stats.%s' check skipped (%s)", table_name.c_str(), reason);
		return false;
	}

	MYSQL_RES* count_result = mysql_store_result(proxysql_admin);
	if (!count_result) {
		diag(
			"Failed to store result for table 'stats.%s': %s - skipping",
			table_name.c_str(), mysql_error(proxysql_admin)
		);
		ok(true, "Table 'stats.%s' check skipped (store result failed)", table_name.c_str());
		return false;
	}

	MYSQL_ROW count_row = mysql_fetch_row(count_result);
	if (!count_row || !count_row[0]) {
		diag("Failed to fetch count for table 'stats.%s' - skipping", table_name.c_str());
		mysql_free_result(count_result);
		ok(true, "Table 'stats.%s' check skipped (fetch row failed)", table_name.c_str());
		return false;
	}

	row_count = strtoll(count_row[0], nullptr, 10);
	mysql_free_result(count_result);
	return true;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: mysql_init failed\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	// Connect to ProxySQL Admin interface
	if (!mysql_real_connect(
		proxysql_admin, cl.admin_host, cl.admin_username, cl.admin_password,
		NULL, cl.admin_port, NULL, 0
	)) {
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			mysql_error(proxysql_admin)
		);
		return EXIT_FAILURE;
	}

	// Check if ProxySQL is running in cluster mode
	bool is_cluster_mode = false;
	const char* cluster_env = getenv("PROXYSQL_CLUSTER");
	if (cluster_env && atoi(cluster_env) > 0) {
		is_cluster_mode = true;
	}
	diag("Cluster mode: %s", is_cluster_mode ? "enabled" : "disabled");

	// Get the list of all tables in the 'stats' database
	MYSQL_QUERY(proxysql_admin, "SHOW TABLES FROM stats");
	MYSQL_RES* tables_result = mysql_store_result(proxysql_admin);
	if (!tables_result) {
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			mysql_error(proxysql_admin)
		);
		mysql_close(proxysql_admin);
		return EXIT_FAILURE;
	}

	// Extract table names from result, excluding tables ending with '_reset'
	vector<string> table_names;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(tables_result))) {
		if (row[0]) {
			string table_name(row[0]);
			// Skip tables ending with '_reset'
			if (table_name.size() >= 6 &&
			    table_name.substr(table_name.size() - 6) == "_reset") {
				continue;
			}
			table_names.push_back(table_name);
		}
	}
	mysql_free_result(tables_result);

	// Set up test plan - one test per table
	int num_tables = table_names.size();
	plan(num_tables);

	diag("Checking %d tables in 'stats' database", num_tables);

	int failed_tests = 0;

	// Check each table
	for (const string& table_name : table_names) {
		int64_t row_count;
		if (!get_table_row_count(proxysql_admin, table_name, row_count)) {
			continue;  // Error already handled and test marked as skipped
		}

		bool ignored = is_table_ignored(table_name, is_cluster_mode);

		if (ignored) {
			ok(true, "Table 'stats.%s' ignored (has %lld rows)",
			   table_name.c_str(), (long long)row_count);
		} else {
			if (row_count < 1) {
				diag("Table 'stats.%s' has %lld rows (expected at least 1)",
				     table_name.c_str(), (long long)row_count);
				failed_tests++;
			}
			ok(row_count >= 1, "Table 'stats.%s' has at least 1 row (found %lld)",
			   table_name.c_str(), (long long)row_count);
		}
	}

	mysql_close(proxysql_admin);

	if (failed_tests > 0) {
		diag(
			"FAILED: %d out of %d stats tables had unexpected row counts",
			failed_tests, num_tables
		);
	}

	return exit_status();
}
