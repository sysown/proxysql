#include <map>
#include <string>
#include <cstdlib>
#include <ctime>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::map;
using std::string;

static void drain_results(MYSQL* mysql) {
	MYSQL_RES* res;
	while (1) {
		res = mysql_store_result(mysql);
		if (res) mysql_free_result(res);
		if (mysql_next_result(mysql) != 0) break;
	}
}

static bool fetch_single_string(MYSQL* mysql, const string& query, string& out) {
	if (mysql_query(mysql, query.c_str())) {
		diag("Query failed: %s (Error: %s)", query.c_str(), mysql_error(mysql));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(mysql);
	if (!res) {
		diag("No result set for query: %s", query.c_str());
		drain_results(mysql);
		return false;
	}
	MYSQL_ROW row = mysql_fetch_row(res);
	if (!row || !row[0]) {
		mysql_free_result(res);
		drain_results(mysql);
		return false;
	}
	out = row[0];
	mysql_free_result(res);
	drain_results(mysql);
	return true;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(19);

	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Connection failed: %s", mysql_error(admin));
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	int rc;
	drain_results(admin);

	// 1. Test SET and validation
	diag("Running command: SET tsdb-enabled='1'");
	rc = mysql_query(admin, "SET tsdb-enabled='1'");
	ok(rc == 0, "SET tsdb-enabled works");
	drain_results(admin);

	diag("Running command: SET tsdb-sample_interval='1'");
	rc = mysql_query(admin, "SET tsdb-sample_interval='1'");
	ok(rc == 0, "SET tsdb-sample_interval works");
	drain_results(admin);

	diag("Running command: SET tsdb-monitor_enabled='1'");
	rc = mysql_query(admin, "SET tsdb-monitor_enabled='1'");
	ok(rc == 0, "SET tsdb-monitor_enabled works");
	drain_results(admin);

	diag("Running command: SET tsdb-monitor_interval='1'");
	rc = mysql_query(admin, "SET tsdb-monitor_interval='1'");
	ok(rc == 0, "SET tsdb-monitor_interval works");
	drain_results(admin);

	// 2. Test LOAD TSDB VARIABLES
	diag("Running command: LOAD TSDB VARIABLES TO RUNTIME");
	rc = mysql_query(admin, "LOAD TSDB VARIABLES TO RUNTIME");
	ok(rc == 0, "`LOAD TSDB VARIABLES TO RUNTIME` is supported");
	drain_results(admin);

	// 3. Test SHOW TSDB VARIABLES
	diag("Running command: SHOW TSDB VARIABLES");
	rc = mysql_query(admin, "SHOW TSDB VARIABLES");
	ok(rc == 0, "SHOW TSDB VARIABLES is supported");
	MYSQL_RES* res = mysql_store_result(admin);
	if (res) {
		int rows = mysql_num_rows(res);
		ok(rows == 5, "SHOW TSDB VARIABLES returns 5 rows (found %d)", rows);
		mysql_free_result(res);
	} else {
		ok(0, "SHOW TSDB VARIABLES returned no result set");
	}
	drain_results(admin);

	// 4. Test Runtime values (Virtual table refresh)
	diag("Verifying runtime_global_variables for tsdb- prefix");
	string count;
	bool count_ok = fetch_single_string(
		admin,
		"SELECT COUNT(*) FROM runtime_global_variables WHERE variable_name LIKE 'tsdb-%'",
		count
	);
	ok(count_ok && count == "5", "Five tsdb-* runtime variables are present (found %s)", count.c_str());

	// 5. Test SAVE TSDB VARIABLES
	diag("Running command: SAVE TSDB VARIABLES TO DISK");
	rc = mysql_query(admin, "SAVE TSDB VARIABLES TO DISK");
	ok(rc == 0, "`SAVE TSDB VARIABLES TO DISK` is supported");
	drain_results(admin);

	diag("Verifying global_variables on disk");
	string disk_enabled;
	bool disk_ok = fetch_single_string(
		admin,
		"SELECT variable_value FROM disk.global_variables WHERE variable_name='tsdb-enabled'",
		disk_enabled
	);
	ok(disk_ok && disk_enabled == "1", "TSDB variable is persisted to disk (value: %s)", disk_enabled.c_str());

	// 6. Test SHOW TSDB STATUS (triggers refresh)
	diag("Running command: SHOW TSDB STATUS");
	rc = mysql_query(admin, "SHOW TSDB STATUS");
	ok(rc == 0, "SHOW TSDB STATUS is supported");
	res = mysql_store_result(admin);
	if (res) {
		int rows = mysql_num_rows(res);
		ok(rows >= 5, "SHOW TSDB STATUS returns at least 5 rows (found %d)", rows);
		mysql_free_result(res);
	} else {
		ok(0, "SHOW TSDB STATUS returned no result set");
	}
	drain_results(admin);

	// 7. Verify table schemas
	diag("Verifying tsdb_metrics table in stats_history");
	string table_name;
	bool table_exists = fetch_single_string(
		admin,
		"SELECT name FROM stats_history.sqlite_master WHERE type='table' AND name='tsdb_metrics'",
		table_name
	);
	ok(
		table_exists,
		"tsdb_metrics table exists in stats_history"
	);

	// 8. Wait for background loops to collect some data
	diag("Waiting for TSDB background loops (sampler and monitor) to collect data...");
	sleep(4);

	// 9. Verify data collection in tsdb_metrics
	diag("Checking if metrics were collected in stats_history.tsdb_metrics");
	string metric_count;
	bool metrics_collected = fetch_single_string(
		admin,
		"SELECT COUNT(*) FROM stats_history.tsdb_metrics",
		metric_count
	);
	ok(metrics_collected && atoi(metric_count.c_str()) > 0, "Metrics are being collected in tsdb_metrics (count: %s)", metric_count.c_str());

	// 10. Verify data collection in tsdb_backend_health
	diag("Checking if tsdb_backend_health is accessible in stats_history");
	string health_count;
	bool health_accessible = fetch_single_string(
		admin,
		"SELECT COUNT(*) FROM stats_history.tsdb_backend_health",
		health_count
	);
	ok(health_accessible, "tsdb_backend_health table is accessible");

	// 11. Test SHOW TSDB STATUS again to see updated values
	diag("Checking updated stats in SHOW TSDB STATUS");
	rc = mysql_query(admin, "SHOW TSDB STATUS");
	ok(rc == 0, "Second SHOW TSDB STATUS call successful");
	drain_results(admin);

	bool dp_ok = fetch_single_string(admin, "SELECT Variable_Value FROM stats_tsdb WHERE Variable_Name='Total_Datapoints'", count);
	ok(dp_ok && atoi(count.c_str()) > 0, "SHOW TSDB STATUS reports datapoints > 0 (found %s)", count.c_str());

	// 12. Test Downsampling command
	// NOTE: Downsampling only processes COMPLETED hours (data with timestamps before current_hour).
	// Since we only have a few seconds of data, insert test data in the most recently
	// completed hour. Downsampling deliberately refreshes this boundary bucket so
	// metrics committed just after an earlier pass are not lost.
	diag("Testing TSDB downsampling via command...");

	// Get current timestamp and calculate the start of the previous hour.
	time_t now = time(NULL);
	time_t completed_hour = ((now - 3600) / 3600) * 3600;
	diag("Current time: %ld, Previous hour boundary: %ld", now, completed_hour);

	// Insert test data with timestamps from the completed hour.
	diag("Inserting test metrics data with timestamps from completed hour...");
	char insert_query[512];
	snprintf(insert_query, sizeof(insert_query),
		"INSERT OR REPLACE INTO stats_history.tsdb_metrics (timestamp, metric_name, labels, value) "
		"VALUES (%ld, 'test_downsample_metric', '{\"test\":\"true\"}', 42.0)",
		completed_hour);
	rc = mysql_query(admin, insert_query);
	if (rc != 0) {
		diag("Failed to insert test data: %s", mysql_error(admin));
	}
	drain_results(admin);
	diag("Inserted test metric at timestamp %ld", completed_hour);

	// Also insert a few more data points in the same hour for realistic test
	for (int i = 1; i <= 3; i++) {
		snprintf(insert_query, sizeof(insert_query),
			"INSERT OR REPLACE INTO stats_history.tsdb_metrics (timestamp, metric_name, labels, value) "
			"VALUES (%ld, 'test_downsample_metric', '{\"test\":\"true\"}', %f)",
			completed_hour + i * 60, 42.0 + i); // Add data points every minute
		mysql_query(admin, insert_query);
		drain_results(admin);
	}
	diag("Inserted 4 total test data points in the completed hour");

	// Check metrics count before downsampling
	string before_count;
	fetch_single_string(admin, "SELECT COUNT(*) FROM stats_history.tsdb_metrics WHERE metric_name='test_downsample_metric'", before_count);
	diag("Test metrics in tsdb_metrics before downsample: %s", before_count.c_str());

	// Run the downsample command
	rc = mysql_query(admin, "PROXYSQL TSDB DOWNSAMPLE");
	ok(rc == 0, "PROXYSQL TSDB DOWNSAMPLE command is supported");
	drain_results(admin);

	// Check hourly table after downsampling
	diag("Verifying downsampled data...");
	string ds_count;
	bool ds_ok = fetch_single_string(admin, "SELECT COUNT(*) FROM stats_history.tsdb_metrics_hour", ds_count);
	diag("Rows in tsdb_metrics_hour after downsample: %s", ds_count.c_str());

	// Also check for our specific test metric
	string test_metric_count;
	bool test_metric_ok = fetch_single_string(admin,
		"SELECT COUNT(*) FROM stats_history.tsdb_metrics_hour WHERE metric_name='test_downsample_metric'",
		test_metric_count);
	diag("Test metric rows in tsdb_metrics_hour: %s", test_metric_count.c_str());

	ok(
		ds_ok && test_metric_ok && atoi(test_metric_count.c_str()) > 0,
		"Downsample produced rows for test_downsample_metric (metric rows: %s, total rows: %s)",
		test_metric_count.c_str(), ds_count.c_str()
	);

	// Cleanup: remove test data
	diag("Cleaning up test data...");
	mysql_query(admin, "DELETE FROM stats_history.tsdb_metrics WHERE metric_name='test_downsample_metric'");
	drain_results(admin);
	mysql_query(admin, "DELETE FROM stats_history.tsdb_metrics_hour WHERE metric_name='test_downsample_metric'");
	drain_results(admin);

	mysql_close(admin);
	return exit_status();
}
