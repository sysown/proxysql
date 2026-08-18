/**
 * @file statistics_unit-t.cpp
 * @brief Unit tests for ProxySQL_Statistics.
 *
 * Tests cover:
 *   - Constructor / init / table creation
 *   - Timer functions (MySQL_Threads_Handler_timetoget, system_cpu_timetoget,
 *     MySQL_Query_Cache_timetoget, eventslog timer functions)
 *   - TSDB variable management (set_variable, get_variable, has_variable,
 *     get_variables_list) — guarded by PROXYSQLTSDB
 *   - TSDB timer functions (tsdb_sampler_timetoget, tsdb_downsample_timetoget,
 *     tsdb_monitor_timetoget, tsdb_retention_timetoget) — guarded by PROXYSQLTSDB
 *   - TSDB metric insertion and query (insert_tsdb_metric, query_tsdb_metrics)
 *     which indirectly exercises the anonymous-namespace helpers
 *     escape_sql_string_literal and valid_label_key
 *   - TSDB backend health insertion and query
 *   - TSDB downsampling and retention cleanup
 *   - TSDB status retrieval
 *
 * All tests use in-memory or /tmp SQLite3 databases — no external deps.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Thread.h"

#include "prometheus/text_serializer.h"

#include <cstring>
#include <cstdlib>
#include <array>
#include <chrono>
#include <string>
#include <map>
#include <memory>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>

// Forward-declare the extern that the constructor reads.
// GloVars is defined in test_globals.cpp via the PROXYSQL_EXTERN mechanism.

static ProxySQL_Statistics *stats = nullptr;
static std::string tmpdb_path;

// ============================================================
// Setup / teardown
// ============================================================

static void setup_stats() {
	// ProxySQL_Statistics constructor opens GloVars.statsdb_disk as a file path.
	// Use /tmp directly to avoid datadir issues in CI environments.
	const char *tmpdir = getenv("TMPDIR");
	if (tmpdir == nullptr) {
		tmpdir = "/tmp";
	}
	tmpdb_path = std::string(tmpdir) + "/proxysql_test_statsdb_" + std::to_string(getpid()) + ".db";

	// Ensure datadir exists (needed by other parts of ProxySQL_Statistics)
	if (GloVars.datadir != nullptr) {
		mkdir(GloVars.datadir, 0755);
	}

	// Set the global so the constructor can open it
	GloVars.statsdb_disk = strdup(tmpdb_path.c_str());

	stats = new ProxySQL_Statistics();
	if (stats->statsdb_disk == nullptr) {
		diag("statsdb_disk is NULL after construction — possible struct layout mismatch");
		diag("(rebuild with: make clean && make debug in test/tap/tests/unit/)");
		diag("GloVars.statsdb_disk=%s", GloVars.statsdb_disk ? GloVars.statsdb_disk : "NULL");
	}
	if (stats->statsdb_disk != nullptr) {
		stats->init();
	}
}

static void teardown_stats() {
	delete stats;
	stats = nullptr;

	// Clean up temp database files
	unlink(tmpdb_path.c_str());
	std::string wal = tmpdb_path + "-wal";
	std::string shm = tmpdb_path + "-shm";
	unlink(wal.c_str());
	unlink(shm.c_str());

	if (GloVars.statsdb_disk != nullptr) {
		free(GloVars.statsdb_disk);
		GloVars.statsdb_disk = nullptr;
	}
}

// ============================================================
// MySQL user-variable tracking stats registration
// ============================================================

static unsigned int global_status_name_count(const SQLite3_result* result, const char* name) {
	unsigned int count = 0;
	for (unsigned long long i = 0; i < result->rows_count; ++i) {
		if (strcmp(result->rows[i]->fields[0], name) == 0) {
			++count;
		}
	}
	return count;
}

static unsigned int text_count(const std::string& text, const std::string& needle) {
	unsigned int count = 0;
	for (size_t pos = text.find(needle); pos != std::string::npos; pos = text.find(needle, pos + needle.size())) {
		++count;
	}
	return count;
}

static unsigned int prometheus_help_metric_count(
	const std::string& text, const std::string& metric_name) {
	return text_count(text, "# HELP " + metric_name + " ");
}

static void test_user_variable_metric_name_is_exact() {
	const std::string metric_name = "proxysql_mysql_user_variable_assignments_tracked_total";
	const std::string fixture = "# HELP " + metric_name + "_v2 unrelated metric\n";
	ok(prometheus_help_metric_count(fixture, metric_name) == 0,
		"Prometheus descriptor check rejects a longer prefix-sharing metric name");
}

static void test_user_variable_tracking_stats_registration() {
	const std::array<const char*, 5> status_names {
		"User_variable_assignments_tracked",
		"User_variable_replay_commands",
		"User_variable_replay_failures",
		"User_variable_fallback_unsupported",
		"User_variable_fallback_limits"
	};
	const std::array<const char*, 5> metric_names {
		"proxysql_mysql_user_variable_assignments_tracked_total",
		"proxysql_mysql_user_variable_replay_commands_total",
		"proxysql_mysql_user_variable_replay_failures_total",
		"proxysql_mysql_user_variable_fallback_unsupported_total",
		"proxysql_mysql_user_variable_fallback_limits_total"
	};

	MySQL_Threads_Handler handler;
	std::unique_ptr<SQLite3_result> status(handler.SQL3_GlobalStatus(false));
	for (const char* name : status_names) {
		ok(global_status_name_count(status.get(), name) == 1,
			"global status registers %s exactly once", name);
	}

	prometheus::TextSerializer serializer;
	const std::string metrics = serializer.Serialize(GloVars.prometheus_registry->Collect());
	for (const char* name : metric_names) {
		ok(prometheus_help_metric_count(metrics, name) == 1,
			"Prometheus registers %s exactly once", name);
	}
}

// ============================================================
// Constructor and init
// ============================================================

static bool statsdb_ok = false;

static void test_constructor_creates_databases() {
	ok(stats != nullptr, "ProxySQL_Statistics object created successfully");
	statsdb_ok = (stats != nullptr && stats->statsdb_disk != nullptr);
	ok(statsdb_ok, "statsdb_disk is not null after construction");
}

static void test_init_creates_tables() {
	if (!statsdb_ok) {
		skip(3, "statsdb_disk is NULL — struct layout mismatch (clean rebuild needed)");
		return;
	}
	// After init(), standard tables should exist. Verify by querying them.
	SQLite3_result *resultset = nullptr;
	char *error = nullptr;
	int cols = 0, affected_rows = 0;

	stats->statsdb_disk->execute_statement(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mysql_connections'",
		&error, &cols, &affected_rows, &resultset);
	if (error) { free(error); error = nullptr; }
	ok(resultset != nullptr && resultset->rows_count > 0 &&
	   strcmp(resultset->rows[0]->fields[0], "1") == 0,
	   "init: mysql_connections table exists on disk");
	delete resultset;

	resultset = nullptr;
	stats->statsdb_disk->execute_statement(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='system_cpu'",
		&error, &cols, &affected_rows, &resultset);
	if (error) { free(error); error = nullptr; }
	ok(resultset != nullptr && resultset->rows_count > 0 &&
	   strcmp(resultset->rows[0]->fields[0], "1") == 0,
	   "init: system_cpu table exists on disk");
	delete resultset;

	resultset = nullptr;
	stats->statsdb_disk->execute_statement(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='history_mysql_query_digest'",
		&error, &cols, &affected_rows, &resultset);
	if (error) { free(error); error = nullptr; }
	ok(resultset != nullptr && resultset->rows_count > 0 &&
	   strcmp(resultset->rows[0]->fields[0], "1") == 0,
	   "init: history_mysql_query_digest table exists on disk");
	delete resultset;
}

#ifdef PROXYSQLTSDB
static void test_init_creates_tsdb_tables() {
	SQLite3_result *resultset = nullptr;
	char *error = nullptr;
	int cols = 0, affected_rows = 0;

	stats->statsdb_disk->execute_statement(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='tsdb_metrics'",
		&error, &cols, &affected_rows, &resultset);
	if (error) { free(error); error = nullptr; }
	ok(resultset != nullptr && resultset->rows_count > 0 &&
	   strcmp(resultset->rows[0]->fields[0], "1") == 0,
	   "init: tsdb_metrics table exists on disk");
	delete resultset;

	resultset = nullptr;
	stats->statsdb_disk->execute_statement(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='tsdb_metrics_hour'",
		&error, &cols, &affected_rows, &resultset);
	if (error) { free(error); error = nullptr; }
	ok(resultset != nullptr && resultset->rows_count > 0 &&
	   strcmp(resultset->rows[0]->fields[0], "1") == 0,
	   "init: tsdb_metrics_hour table exists on disk");
	delete resultset;

	resultset = nullptr;
	stats->statsdb_disk->execute_statement(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='tsdb_backend_health'",
		&error, &cols, &affected_rows, &resultset);
	if (error) { free(error); error = nullptr; }
	ok(resultset != nullptr && resultset->rows_count > 0 &&
	   strcmp(resultset->rows[0]->fields[0], "1") == 0,
	   "init: tsdb_backend_health table exists on disk");
	delete resultset;
}
#endif

// ============================================================
// Timer functions — MySQL_Threads_Handler_timetoget
// ============================================================

static void test_timer_returns_false_when_disabled() {
	// When stats_mysql_connections is 0, timetoget should return false
	stats->variables.stats_mysql_connections = 0;
	bool result = stats->MySQL_Threads_Handler_timetoget(1000000ULL);
	ok(result == false, "MySQL_Threads_Handler_timetoget: returns false when interval is 0");
}

static void test_timer_returns_true_on_first_call() {
	// With interval > 0 and curtime > next_timer (initially 0), should return true
	stats->variables.stats_mysql_connections = 5;
	bool result = stats->MySQL_Threads_Handler_timetoget(5000000ULL);
	ok(result == true, "MySQL_Threads_Handler_timetoget: returns true on first call (timer was 0)");
}

static void test_timer_returns_false_before_interval() {
	// After a successful trigger, calling again immediately should return false
	stats->variables.stats_mysql_connections = 60;  // 60 second interval
	// First call triggers and sets next_timer
	stats->MySQL_Threads_Handler_timetoget(1000000000ULL);  // 1000 seconds in usec
	// Call again at almost the same time — should not trigger
	bool result = stats->MySQL_Threads_Handler_timetoget(1000000001ULL);
	ok(result == false, "MySQL_Threads_Handler_timetoget: returns false before interval elapses");
}

static void test_timer_returns_true_after_interval() {
	stats->variables.stats_mysql_connections = 5;  // 5 second interval
	// First call at t=1000s triggers
	stats->MySQL_Threads_Handler_timetoget(1000000000ULL);
	// Call again at t=1006s — should trigger (5s+ elapsed)
	bool result = stats->MySQL_Threads_Handler_timetoget(1006000000ULL);
	ok(result == true, "MySQL_Threads_Handler_timetoget: returns true after interval elapses");
}

// ============================================================
// Timer functions — MySQL_Query_Cache_timetoget
// ============================================================

static void test_query_cache_timer_disabled() {
	stats->variables.stats_mysql_query_cache = 0;
	ok(stats->MySQL_Query_Cache_timetoget(5000000ULL) == false,
	   "MySQL_Query_Cache_timetoget: returns false when interval is 0");
}

static void test_query_cache_timer_triggers() {
	stats->variables.stats_mysql_query_cache = 10;
	ok(stats->MySQL_Query_Cache_timetoget(2000000000ULL) == true,
	   "MySQL_Query_Cache_timetoget: returns true on first call");
}

// ============================================================
// Timer functions — system_cpu_timetoget
// ============================================================

static void test_system_cpu_timer_disabled() {
	stats->variables.stats_system_cpu = 0;
	ok(stats->system_cpu_timetoget(5000000ULL) == false,
	   "system_cpu_timetoget: returns false when interval is 0");
}

static void test_system_cpu_timer_triggers() {
	stats->variables.stats_system_cpu = 10;
	ok(stats->system_cpu_timetoget(3000000000ULL) == true,
	   "system_cpu_timetoget: returns true on first call");
}

// ============================================================
// Timer functions — eventslog timers
// ============================================================

static void test_mysql_eventslog_timer_disabled() {
	stats->variables.stats_mysql_eventslog_sync_buffer_to_disk = 0;
	ok(stats->MySQL_Logger_dump_eventslog_timetoget(5000000ULL) == false,
	   "MySQL_Logger_dump_eventslog_timetoget: returns false when interval is 0");
}

static void test_mysql_eventslog_timer_triggers() {
	stats->variables.stats_mysql_eventslog_sync_buffer_to_disk = 5;
	ok(stats->MySQL_Logger_dump_eventslog_timetoget(6000000ULL) == true,
	   "MySQL_Logger_dump_eventslog_timetoget: returns true on first call");
}

static void test_mysql_eventslog_timer_no_retrigger() {
	stats->variables.stats_mysql_eventslog_sync_buffer_to_disk = 10;
	stats->MySQL_Logger_dump_eventslog_timetoget(10000000ULL);  // triggers, sets last_timer
	ok(stats->MySQL_Logger_dump_eventslog_timetoget(15000000ULL) == false,
	   "MySQL_Logger_dump_eventslog_timetoget: returns false before 10s elapses");
}

static void test_pgsql_eventslog_timer_disabled() {
	stats->variables.stats_pgsql_eventslog_sync_buffer_to_disk = 0;
	ok(stats->PgSQL_Logger_dump_eventslog_timetoget(5000000ULL) == false,
	   "PgSQL_Logger_dump_eventslog_timetoget: returns false when interval is 0");
}

static void test_pgsql_eventslog_timer_triggers() {
	stats->variables.stats_pgsql_eventslog_sync_buffer_to_disk = 5;
	ok(stats->PgSQL_Logger_dump_eventslog_timetoget(6000000ULL) == true,
	   "PgSQL_Logger_dump_eventslog_timetoget: returns true on first call");
}

// ============================================================
// Timer functions — mysql_query_digest_to_disk_timetoget
// ============================================================

static void test_digest_to_disk_timer_disabled() {
	stats->variables.stats_mysql_query_digest_to_disk = 0;
	ok(stats->mysql_query_digest_to_disk_timetoget(5000000ULL) == false,
	   "mysql_query_digest_to_disk_timetoget: returns false when interval is 0");
}

static void test_digest_to_disk_timer_triggers() {
	stats->variables.stats_mysql_query_digest_to_disk = 10;
	ok(stats->mysql_query_digest_to_disk_timetoget(4000000000ULL) == true,
	   "mysql_query_digest_to_disk_timetoget: returns true on first call");
}

// ============================================================
// TSDB variable management (PROXYSQLTSDB only)
// ============================================================

#ifdef PROXYSQLTSDB

static void test_set_variable_enabled() {
	ok(stats->set_variable("enabled", "1") == true,
	   "set_variable: 'enabled' accepts value '1'");
	ok(stats->set_variable("enabled", "0") == true,
	   "set_variable: 'enabled' accepts value '0'");
}

static void test_set_variable_enabled_out_of_range() {
	ok(stats->set_variable("enabled", "2") == false,
	   "set_variable: 'enabled' rejects value '2' (max=1)");
	ok(stats->set_variable("enabled", "-1") == false,
	   "set_variable: 'enabled' rejects value '-1' (min=0)");
}

static void test_set_variable_sample_interval() {
	ok(stats->set_variable("sample_interval", "1") == true,
	   "set_variable: 'sample_interval' accepts min value '1'");
	ok(stats->set_variable("sample_interval", "3600") == true,
	   "set_variable: 'sample_interval' accepts max value '3600'");
	ok(stats->set_variable("sample_interval", "0") == false,
	   "set_variable: 'sample_interval' rejects value '0' (below min)");
	ok(stats->set_variable("sample_interval", "3601") == false,
	   "set_variable: 'sample_interval' rejects value '3601' (above max)");
}

static void test_set_variable_retention_days() {
	ok(stats->set_variable("retention_days", "1") == true,
	   "set_variable: 'retention_days' accepts value '1'");
	ok(stats->set_variable("retention_days", "3650") == true,
	   "set_variable: 'retention_days' accepts max value '3650'");
	ok(stats->set_variable("retention_days", "0") == false,
	   "set_variable: 'retention_days' rejects '0'");
	ok(stats->set_variable("retention_days", "3651") == false,
	   "set_variable: 'retention_days' rejects '3651'");
}

static void test_set_variable_monitor_enabled() {
	ok(stats->set_variable("monitor_enabled", "0") == true,
	   "set_variable: 'monitor_enabled' accepts '0'");
	ok(stats->set_variable("monitor_enabled", "1") == true,
	   "set_variable: 'monitor_enabled' accepts '1'");
	ok(stats->set_variable("monitor_enabled", "3") == false,
	   "set_variable: 'monitor_enabled' rejects '3'");
}

static void test_set_variable_monitor_interval() {
	ok(stats->set_variable("monitor_interval", "10") == true,
	   "set_variable: 'monitor_interval' accepts '10'");
	ok(stats->set_variable("monitor_interval", "0") == false,
	   "set_variable: 'monitor_interval' rejects '0'");
}

static void test_set_variable_invalid_name() {
	ok(stats->set_variable("nonexistent_var", "1") == false,
	   "set_variable: unknown variable name returns false");
}

static void test_set_variable_null_inputs() {
	ok(stats->set_variable(nullptr, "1") == false,
	   "set_variable: null name returns false");
	ok(stats->set_variable("enabled", nullptr) == false,
	   "set_variable: null value returns false");
	ok(stats->set_variable("enabled", "") == false,
	   "set_variable: empty value returns false");
}

static void test_set_variable_non_integer_value() {
	ok(stats->set_variable("enabled", "abc") == false,
	   "set_variable: non-integer value returns false");
	ok(stats->set_variable("enabled", "1.5") == false,
	   "set_variable: float value returns false");
	ok(stats->set_variable("enabled", "1abc") == false,
	   "set_variable: trailing garbage returns false");
}

static void test_set_variable_case_insensitive() {
	ok(stats->set_variable("ENABLED", "1") == true,
	   "set_variable: variable name is case-insensitive (uppercase)");
	ok(stats->set_variable("Enabled", "0") == true,
	   "set_variable: variable name is case-insensitive (mixed case)");
}

static void test_get_variable() {
	stats->set_variable("enabled", "1");
	char *val = stats->get_variable("enabled");
	ok(val != nullptr && strcmp(val, "1") == 0,
	   "get_variable: returns '1' after set_variable('enabled', '1')");
	free(val);

	stats->set_variable("sample_interval", "42");
	val = stats->get_variable("sample_interval");
	ok(val != nullptr && strcmp(val, "42") == 0,
	   "get_variable: returns '42' after set_variable('sample_interval', '42')");
	free(val);

	stats->set_variable("retention_days", "365");
	val = stats->get_variable("retention_days");
	ok(val != nullptr && strcmp(val, "365") == 0,
	   "get_variable: returns '365' after set_variable('retention_days', '365')");
	free(val);

	stats->set_variable("monitor_enabled", "1");
	val = stats->get_variable("monitor_enabled");
	ok(val != nullptr && strcmp(val, "1") == 0,
	   "get_variable: returns '1' for monitor_enabled");
	free(val);

	stats->set_variable("monitor_interval", "30");
	val = stats->get_variable("monitor_interval");
	ok(val != nullptr && strcmp(val, "30") == 0,
	   "get_variable: returns '30' for monitor_interval");
	free(val);
}

static void test_get_variable_null_and_unknown() {
	ok(stats->get_variable(nullptr) == nullptr,
	   "get_variable: null name returns null");
	ok(stats->get_variable("nonexistent") == nullptr,
	   "get_variable: unknown name returns null");
}

static void test_has_variable() {
	ok(stats->has_variable("enabled") == true,
	   "has_variable: 'enabled' exists");
	ok(stats->has_variable("sample_interval") == true,
	   "has_variable: 'sample_interval' exists");
	ok(stats->has_variable("retention_days") == true,
	   "has_variable: 'retention_days' exists");
	ok(stats->has_variable("monitor_enabled") == true,
	   "has_variable: 'monitor_enabled' exists");
	ok(stats->has_variable("monitor_interval") == true,
	   "has_variable: 'monitor_interval' exists");
	ok(stats->has_variable("nonexistent") == false,
	   "has_variable: 'nonexistent' does not exist");
	ok(stats->has_variable(nullptr) == false,
	   "has_variable: null returns false");
}

static void test_get_variables_list() {
	char **list = stats->get_variables_list();
	ok(list != nullptr, "get_variables_list: returns non-null");

	int count = 0;
	if (list) {
		while (list[count] != nullptr) count++;
	}
	ok(count == 5, "get_variables_list: returns 5 variables (got %d)", count);

	// Free the list
	if (list) {
		for (int i = 0; list[i]; i++) free(list[i]);
		free(list);
	}
}

// ============================================================
// TSDB timer functions
// ============================================================

static void test_tsdb_sampler_timer_disabled() {
	stats->set_variable("enabled", "0");
	ok(stats->tsdb_sampler_timetoget(5000000ULL) == false,
	   "tsdb_sampler_timetoget: returns false when TSDB disabled");
}

static void test_tsdb_sampler_timer_triggers() {
	stats->set_variable("enabled", "1");
	stats->set_variable("sample_interval", "5");
	// next_timer starts at 0, curtime > 0 should trigger
	ok(stats->tsdb_sampler_timetoget(1000000ULL) == true,
	   "tsdb_sampler_timetoget: returns true on first call when enabled");
}

static void test_tsdb_sampler_timer_no_retrigger() {
	stats->set_variable("enabled", "1");
	stats->set_variable("sample_interval", "10");
	stats->tsdb_sampler_timetoget(1000000ULL);  // triggers, sets next = 1 + 10s = 11000000
	ok(stats->tsdb_sampler_timetoget(5000000ULL) == false,
	   "tsdb_sampler_timetoget: returns false before interval elapses");
}

static void test_tsdb_downsample_timer() {
	stats->set_variable("enabled", "0");
	ok(stats->tsdb_downsample_timetoget(5000000ULL) == false,
	   "tsdb_downsample_timetoget: returns false when disabled");

	stats->set_variable("enabled", "1");
	ok(stats->tsdb_downsample_timetoget(1000000ULL) == true,
	   "tsdb_downsample_timetoget: returns true on first call when enabled");
}

static void test_tsdb_monitor_timer() {
	stats->set_variable("enabled", "1");
	stats->set_variable("monitor_enabled", "0");
	ok(stats->tsdb_monitor_timetoget(5000000ULL) == false,
	   "tsdb_monitor_timetoget: returns false when monitor disabled");

	stats->set_variable("monitor_enabled", "1");
	stats->set_variable("monitor_interval", "10");
	ok(stats->tsdb_monitor_timetoget(1000000ULL) == true,
	   "tsdb_monitor_timetoget: returns true on first call when both enabled");
}

static void test_tsdb_retention_timer() {
	stats->set_variable("enabled", "0");
	ok(stats->tsdb_retention_timetoget(5000000ULL) == false,
	   "tsdb_retention_timetoget: returns false when disabled");

	stats->set_variable("enabled", "1");
	ok(stats->tsdb_retention_timetoget(1000000ULL) == true,
	   "tsdb_retention_timetoget: returns true on first call when enabled");
}

// ============================================================
// TSDB metric insertion and query
// ============================================================

static void test_insert_and_query_tsdb_metric() {
	stats->set_variable("enabled", "1");

	std::map<std::string, std::string> labels;
	labels["instance"] = "localhost:6032";

	time_t now = time(nullptr);
	stats->insert_tsdb_metric("test_metric", labels, 42.5, now);
	stats->insert_tsdb_metric("test_metric", labels, 43.0, now + 1);

	// Query back
	std::map<std::string, std::string> no_filter;
	SQLite3_result *result = stats->query_tsdb_metrics("test_metric", no_filter, now - 10, now + 10);
	ok(result != nullptr, "query_tsdb_metrics: returns non-null result for inserted metric");
	if (result) {
		ok(result->rows_count == 2, "query_tsdb_metrics: returns 2 rows (got %lu)",
		   (unsigned long)result->rows_count);
		delete result;
	} else {
		ok(false, "query_tsdb_metrics: returns 2 rows (null result)");
	}
}

static void test_query_tsdb_metric_with_label_filter() {
	time_t now = time(nullptr) + 100;  // offset to not collide with previous test

	std::map<std::string, std::string> labels_a;
	labels_a["host"] = "server_a";
	stats->insert_tsdb_metric("cpu_usage", labels_a, 75.0, now);

	std::map<std::string, std::string> labels_b;
	labels_b["host"] = "server_b";
	stats->insert_tsdb_metric("cpu_usage", labels_b, 90.0, now);

	// Filter by label
	std::map<std::string, std::string> filter;
	filter["host"] = "server_a";
	SQLite3_result *result = stats->query_tsdb_metrics("cpu_usage", filter, now - 10, now + 10);
	ok(result != nullptr, "query_tsdb_metrics: label filter returns non-null");
	if (result) {
		ok(result->rows_count == 1, "query_tsdb_metrics: label filter returns 1 row (got %lu)",
		   (unsigned long)result->rows_count);
		delete result;
	} else {
		ok(false, "query_tsdb_metrics: label filter returns 1 row (null result)");
	}
}

static void test_query_tsdb_metric_with_single_quote_in_name() {
	// This exercises escape_sql_string_literal indirectly
	time_t now = time(nullptr) + 200;

	std::map<std::string, std::string> labels;
	stats->insert_tsdb_metric("metric_with'quote", labels, 10.0, now);

	std::map<std::string, std::string> no_filter;
	SQLite3_result *result = stats->query_tsdb_metrics("metric_with'quote", no_filter, now - 10, now + 10);
	ok(result != nullptr, "query_tsdb_metrics: metric name with single quote works (escape_sql_string_literal)");
	if (result) {
		ok(result->rows_count == 1, "query_tsdb_metrics: single-quote metric returns 1 row (got %lu)",
		   (unsigned long)result->rows_count);
		delete result;
	} else {
		ok(false, "query_tsdb_metrics: single-quote metric returns 1 row (null result)");
	}
}

static void test_query_tsdb_metric_swapped_time_range() {
	// query_tsdb_metrics should swap from/to if to < from
	time_t now = time(nullptr) + 300;
	std::map<std::string, std::string> labels;
	stats->insert_tsdb_metric("swap_test", labels, 1.0, now);

	std::map<std::string, std::string> no_filter;
	SQLite3_result *result = stats->query_tsdb_metrics("swap_test", no_filter, now + 10, now - 10);
	ok(result != nullptr, "query_tsdb_metrics: swapped time range still returns result");
	if (result) {
		ok(result->rows_count == 1, "query_tsdb_metrics: swapped range returns correct row count");
		delete result;
	} else {
		ok(false, "query_tsdb_metrics: swapped range returns correct row count (null)");
	}
}

static void test_query_tsdb_metric_invalid_label_key() {
	// valid_label_key rejects keys with special chars — query should return NULL
	time_t now = time(nullptr) + 400;
	std::map<std::string, std::string> bad_filter;
	bad_filter["bad key!"] = "value";  // space and ! are invalid

	SQLite3_result *result = stats->query_tsdb_metrics("some_metric", bad_filter, now - 10, now + 10);
	ok(result == nullptr, "query_tsdb_metrics: invalid label key returns null (valid_label_key rejects it)");
}

// ============================================================
// TSDB backend health
// ============================================================

static void test_insert_and_query_backend_health() {
	time_t now = time(nullptr) + 500;

	stats->insert_backend_health(1, "db1.example.com", 3306, true, 5, now);
	stats->insert_backend_health(1, "db2.example.com", 3306, false, -1, now);
	stats->insert_backend_health(2, "db3.example.com", 5432, true, 2, now);

	SQLite3_result *result = stats->get_backend_health_metrics(now - 10, now + 10);
	ok(result != nullptr, "get_backend_health_metrics: returns non-null for inserted data");
	if (result) {
		ok(result->rows_count == 3, "get_backend_health_metrics: returns 3 rows (got %lu)",
		   (unsigned long)result->rows_count);
		delete result;
	} else {
		ok(false, "get_backend_health_metrics: returns 3 rows (null result)");
	}

	// Filter by hostgroup
	result = stats->get_backend_health_metrics(now - 10, now + 10, 1);
	ok(result != nullptr, "get_backend_health_metrics: hostgroup filter returns non-null");
	if (result) {
		ok(result->rows_count == 2, "get_backend_health_metrics: hostgroup=1 returns 2 rows (got %lu)",
		   (unsigned long)result->rows_count);
		delete result;
	} else {
		ok(false, "get_backend_health_metrics: hostgroup=1 returns 2 rows (null result)");
	}
}

static void test_tsdb_query_does_not_wait_for_backend_probe() {
	// TEST-NET-1 is deliberately non-routable on the public Internet. The
	// monitor's nonblocking connect therefore remains in poll() until its
	// one-second timeout, giving us a deterministic in-flight probe window.
	srv_info_t info;
	info.addr = "192.0.2.1";
	info.port = 65000;
	info.kind = "tsdb-unit-test";
	srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 1;
	opts.use_ssl = 0;

	MyHGM->wrlock();
	const int add_rc = MyHGM->create_new_server_in_hg(65000, info, opts);
	MyHGM->wrunlock();
	if (add_rc != 0) {
		ok(false, "TSDB monitor probe fixture is created");
		return;
	}

	stats->set_variable("enabled", "1");
	stats->set_variable("monitor_enabled", "1");
	std::thread monitor([]() { stats->tsdb_monitor_loop(); });
	std::this_thread::sleep_for(std::chrono::milliseconds(100));

	const auto started = std::chrono::steady_clock::now();
	(void)stats->get_tsdb_status();
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - started).count();

	monitor.join();
	MyHGM->wrlock();
	MyHGM->remove_server_in_hg(65000, info.addr, info.port);
	MyHGM->wrunlock();

	ok(elapsed < 500,
	   "TSDB status query does not wait for backend probe completion (elapsed=%lldms)",
	   static_cast<long long>(elapsed));
}

// ============================================================
// TSDB status
// ============================================================

static void test_get_tsdb_status() {
	// We have already inserted some metrics above
	ProxySQL_Statistics::tsdb_status_t st = stats->get_tsdb_status();
	ok(st.total_datapoints > 0, "get_tsdb_status: total_datapoints > 0 (got %zu)", st.total_datapoints);
	ok(st.total_series > 0, "get_tsdb_status: total_series > 0 (got %zu)", st.total_series);
	ok(st.newest_datapoint > 0, "get_tsdb_status: newest_datapoint is set");
}

// ============================================================
// TSDB downsampling
// ============================================================

static void test_tsdb_downsample_disabled() {
	stats->set_variable("enabled", "0");
	// Should just return without error
	stats->tsdb_downsample_metrics();
	ok(true, "tsdb_downsample_metrics: does not crash when TSDB disabled");
}

static void test_tsdb_retention_cleanup_disabled() {
	stats->set_variable("enabled", "0");
	stats->tsdb_retention_cleanup();
	ok(true, "tsdb_retention_cleanup: does not crash when TSDB disabled");
}

static void test_tsdb_downsample_runs() {
	stats->set_variable("enabled", "1");
	// Insert some metrics at specific bucket-aligned times
	time_t hour_start = (time(nullptr) / 3600) * 3600 - 7200;  // 2 hours ago
	std::map<std::string, std::string> labels;
	for (int i = 0; i < 10; i++) {
		stats->insert_tsdb_metric("downsample_test", labels, (double)i, hour_start + i * 60);
	}

	stats->tsdb_downsample_metrics();
	ok(true, "tsdb_downsample_metrics: runs without error on data");

	// Check that hourly data was created
	SQLite3_result *resultset = nullptr;
	char *error = nullptr;
	int cols = 0, affected_rows = 0;
	stats->statsdb_disk->execute_statement(
		"SELECT COUNT(*) FROM tsdb_metrics_hour WHERE metric_name='downsample_test'",
		&error, &cols, &affected_rows, &resultset);
	if (error) { free(error); error = nullptr; }
	bool has_hourly = false;
	if (resultset && resultset->rows_count > 0 && resultset->rows[0]->fields[0]) {
		has_hourly = atoi(resultset->rows[0]->fields[0]) > 0;
	}
	ok(has_hourly, "tsdb_downsample_metrics: creates hourly aggregated data");
	delete resultset;
}

static void test_tsdb_retention_cleanup_runs() {
	stats->set_variable("enabled", "1");
	stats->set_variable("retention_days", "1");

	// Insert old data
	time_t old_time = time(nullptr) - 86400 * 5;  // 5 days ago
	std::map<std::string, std::string> labels;
	stats->insert_tsdb_metric("old_metric", labels, 1.0, old_time);

	stats->tsdb_retention_cleanup();

	// Verify old data was removed
	SQLite3_result *resultset = nullptr;
	char *error = nullptr;
	int cols = 0, affected_rows = 0;
	char buf[256];
	snprintf(buf, sizeof(buf),
		"SELECT COUNT(*) FROM tsdb_metrics WHERE metric_name='old_metric' AND timestamp < %ld",
		(long)(time(nullptr) - 86400));
	stats->statsdb_disk->execute_statement(buf, &error, &cols, &affected_rows, &resultset);
	if (error) { free(error); error = nullptr; }
	bool old_removed = false;
	if (resultset && resultset->rows_count > 0 && resultset->rows[0]->fields[0]) {
		old_removed = atoi(resultset->rows[0]->fields[0]) == 0;
	}
	ok(old_removed, "tsdb_retention_cleanup: removes data older than retention_days");
	delete resultset;
}

#endif // PROXYSQLTSDB

// ============================================================
// Main
// ============================================================

int main() {
	// Count tests
	int num_tests = 0;

	// Constructor + init tests: 5
	num_tests += 5;
	// Timer tests: 15
	num_tests += 15;
	// MySQL user-variable tracking stats registration: 10
	num_tests += 10;
	// MySQL user-variable tracking exact metric-name matching: 1
	num_tests += 1;

#ifdef PROXYSQLTSDB
	// TSDB table init: 3
	num_tests += 3;
	// Variable management: 42
	num_tests += 42;
	// TSDB timers: 9
	num_tests += 9;
	// TSDB metric insert/query: 9
	num_tests += 9;
	// TSDB backend health: 4
	num_tests += 4;
	// TSDB monitor concurrency: 1
	num_tests += 1;
	// TSDB status: 3
	num_tests += 3;
	// TSDB downsampling/retention: 5
	num_tests += 5;
#endif

	plan(num_tests);

	test_init_minimal();
	test_init_hostgroups();
	setup_stats();

	// Constructor + init
	test_constructor_creates_databases();
	test_init_creates_tables();

	// Timer tests
	test_timer_returns_false_when_disabled();
	test_timer_returns_true_on_first_call();
	test_timer_returns_false_before_interval();
	test_timer_returns_true_after_interval();
	test_query_cache_timer_disabled();
	test_query_cache_timer_triggers();
	test_system_cpu_timer_disabled();
	test_system_cpu_timer_triggers();
	test_mysql_eventslog_timer_disabled();
	test_mysql_eventslog_timer_triggers();
	test_mysql_eventslog_timer_no_retrigger();
	test_pgsql_eventslog_timer_disabled();
	test_pgsql_eventslog_timer_triggers();
	test_digest_to_disk_timer_disabled();
	test_digest_to_disk_timer_triggers();
	test_user_variable_metric_name_is_exact();
	test_user_variable_tracking_stats_registration();

#ifdef PROXYSQLTSDB
	// TSDB table init
	test_init_creates_tsdb_tables();

	// Variable management
	test_set_variable_enabled();
	test_set_variable_enabled_out_of_range();
	test_set_variable_sample_interval();
	test_set_variable_retention_days();
	test_set_variable_monitor_enabled();
	test_set_variable_monitor_interval();
	test_set_variable_invalid_name();
	test_set_variable_null_inputs();
	test_set_variable_non_integer_value();
	test_set_variable_case_insensitive();
	test_get_variable();
	test_get_variable_null_and_unknown();
	test_has_variable();
	test_get_variables_list();

	// TSDB timers
	test_tsdb_sampler_timer_disabled();
	test_tsdb_sampler_timer_triggers();
	test_tsdb_sampler_timer_no_retrigger();
	test_tsdb_downsample_timer();
	test_tsdb_monitor_timer();
	test_tsdb_retention_timer();

	// TSDB metric insert/query
	test_insert_and_query_tsdb_metric();
	test_query_tsdb_metric_with_label_filter();
	test_query_tsdb_metric_with_single_quote_in_name();
	test_query_tsdb_metric_swapped_time_range();
	test_query_tsdb_metric_invalid_label_key();

	// TSDB backend health
	test_insert_and_query_backend_health();
	test_tsdb_query_does_not_wait_for_backend_probe();

	// TSDB status
	test_get_tsdb_status();

	// TSDB downsampling/retention
	test_tsdb_downsample_disabled();
	test_tsdb_retention_cleanup_disabled();
	test_tsdb_downsample_runs();
	test_tsdb_retention_cleanup_runs();
#endif

	teardown_stats();
	test_cleanup_hostgroups();
	test_cleanup_minimal();

	return exit_status();
}
