#include <map>
#include <string>
#include <cstdlib>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::map;
using std::string;

static bool fetch_single_string(MYSQL* mysql, const string& query, string& out) {
	if (mysql_query(mysql, query.c_str())) {
		return false;
	}
	MYSQL_RES* res = mysql_store_result(mysql);
	if (!res) {
		return false;
	}
	MYSQL_ROW row = mysql_fetch_row(res);
	if (!row || !row[0]) {
		mysql_free_result(res);
		return false;
	}
	out = row[0];
	mysql_free_result(res);
	return true;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(12);

	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(admin, "SET tsdb-enabled='1'");
	MYSQL_QUERY_T(admin, "SET tsdb-sample_interval='11'");
	MYSQL_QUERY_T(admin, "SET tsdb-retention_days='30'");
	MYSQL_QUERY_T(admin, "SET tsdb-monitor_enabled='1'");
	MYSQL_QUERY_T(admin, "SET tsdb-monitor_interval='13'");
	
	int rc = mysql_query(admin, "LOAD TSDB VARIABLES TO RUNTIME");
	ok(rc == 0, "`LOAD TSDB VARIABLES TO RUNTIME` is supported");

	string count;
	bool count_ok = fetch_single_string(
		admin,
		"SELECT COUNT(*) FROM runtime_global_variables WHERE variable_name LIKE 'tsdb-%'",
		count
	);
	ok(count_ok, "Read runtime TSDB variable count from runtime_global_variables");
	ok(count == "5", "Exactly five tsdb-* runtime variables are present");

	const map<string, string> expected_runtime_values{
		{"tsdb-enabled", "1"},
		{"tsdb-sample_interval", "11"},
		{"tsdb-retention_days", "30"},
		{"tsdb-monitor_enabled", "1"},
		{"tsdb-monitor_interval", "13"},
	};

	for (const auto& kv : expected_runtime_values) {
		string value;
		bool ok_fetch = fetch_single_string(
			admin,
			"SELECT variable_value FROM runtime_global_variables WHERE variable_name='" + kv.first + "'",
			value
		);
		ok(ok_fetch && value == kv.second, "Runtime value matches for %s", kv.first.c_str());
	}

	rc = mysql_query(admin, "SAVE TSDB VARIABLES TO DISK");
	ok(rc == 0, "`SAVE TSDB VARIABLES TO DISK` is supported");

	string disk_enabled;
	bool disk_ok = fetch_single_string(
		admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='tsdb-enabled'",
		disk_enabled
	);
	ok(disk_ok && disk_enabled == "1", "TSDB variable is persisted to disk via SAVE TSDB VARIABLES");

	string metrics_schema;
	bool schema_metrics_ok = fetch_single_string(
		admin,
		"SELECT sql FROM statsdb_disk.sqlite_master WHERE type='table' AND name='tsdb_metrics'",
		metrics_schema
	);
	ok(
		schema_metrics_ok && metrics_schema.find("PRIMARY KEY (timestamp, metric_name, labels)") != string::npos,
		"tsdb_metrics schema uses labels in primary key"
	);

	string metrics_hour_schema;
	bool schema_hour_ok = fetch_single_string(
		admin,
		"SELECT sql FROM statsdb_disk.sqlite_master WHERE type='table' AND name='tsdb_metrics_hour'",
		metrics_hour_schema
	);
	ok(
		schema_hour_ok && metrics_hour_schema.find("PRIMARY KEY (bucket, metric_name, labels)") != string::npos,
		"tsdb_metrics_hour schema uses labels in primary key"
	);

	mysql_close(admin);
	return exit_status();
}
