/**
 * @file reg_test_5389-flush_logs_no_drop-t.cpp
 * @brief Regression test for dropped query logs during concurrent FLUSH LOGS.
 *
 * This test creates sustained query traffic using multiple client threads while
 * a concurrent admin thread repeatedly issues `FLUSH LOGS`.
 *
 * Query accounting is verified through Prometheus metrics:
 *   proxysql_query_logger_logged_queries_total{protocol="mysql"}
 *
 * After stopping traffic and performing a final `FLUSH LOGS`, the metric delta
 * is compared against the number of successfully executed client queries.
 */

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

using std::string;
using std::map;
using std::vector;

#define TAP_NAME "TAP_EVENTSLOG_FLUSH_RACE___"

/**
 * @brief Number of concurrent client connections/threads generating load.
 * @details Tunable via env: `TAP_EVENTSLOG_FLUSH_RACE___CLIENT_THREADS`.
 */
const int CLIENT_THREADS = get_env_int(TAP_NAME "CLIENT_THREADS", 20);
/**
 * @brief Total workload execution time in seconds.
 * @details Tunable via env: `TAP_EVENTSLOG_FLUSH_RACE___TEST_DURATION_SEC`.
 */
const int TEST_DURATION_SEC = get_env_int(TAP_NAME "TEST_DURATION_SEC", 5);
/**
 * @brief Delay between `PROXYSQL FLUSH LOGS` operations from the admin flusher thread.
 * @details Tunable via env: `TAP_EVENTSLOG_FLUSH_RACE___FLUSH_INTERVAL_MS`.
 */
const int FLUSH_INTERVAL_MS = get_env_int(TAP_NAME "FLUSH_INTERVAL_MS", 50);
const char* PROXYSQL_FLUSH_LOGS = "PROXYSQL FLUSH LOGS";

/**
 * @brief Executes an admin query and consumes optional result metadata.
 * @param admin Open admin connection.
 * @param query SQL command to execute.
 * @return `EXIT_SUCCESS` on success, `EXIT_FAILURE` otherwise.
 */
static int run_admin_query(MYSQL* admin, const string& query) {
	if (mysql_query_t(admin, query.c_str())) {
		diag("Admin query failed   query=\"%s\" err=\"%s\"", query.c_str(), mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Release result metadata if query returned a resultset.
	MYSQL_RES* res = mysql_store_result(admin);
	if (res != nullptr) {
		mysql_free_result(res);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Reads current Prometheus metrics using `SHOW PROMETHEUS METRICS\G`.
 * @param admin Open admin connection.
 * @param metrics_vals Output map filled with `metric_line -> value`.
 * @return `EXIT_SUCCESS` on success, `EXIT_FAILURE` otherwise.
 */
static int fetch_prometheus_metrics(MYSQL* admin, map<string, double>& metrics_vals) {
	if (mysql_query_t(admin, "SHOW PROMETHEUS METRICS\\G")) {
		diag("Failed to fetch Prometheus metrics   err=\"%s\"", mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL_RES* p_resultset = mysql_store_result(admin);
	if (p_resultset == nullptr) {
		diag("SHOW PROMETHEUS METRICS returned no resultset");
		return EXIT_FAILURE;
	}

	MYSQL_ROW data_row = mysql_fetch_row(p_resultset);
	string row_value {};
	if (data_row != nullptr && data_row[0] != nullptr) {
		row_value = data_row[0];
	}

	mysql_free_result(p_resultset);
	metrics_vals = parse_prometheus_metrics(row_value);

	return EXIT_SUCCESS;
}

/**
 * @brief Retrieves a metric value from parsed Prometheus metrics.
 * @param metrics_vals Parsed metrics map.
 * @param metric_key Exact metric key including labels.
 * @param out Output value when metric exists.
 * @return `true` if metric is found, `false` otherwise.
 */
static bool get_metric_value(const map<string, double>& metrics_vals, const string& metric_key, double& out) {
	const auto m_it = metrics_vals.find(metric_key);
	if (m_it == metrics_vals.end()) {
		return false;
	}

	out = m_it->second;
	return true;
}

/**
 * @brief Creates a query for a variable value from the supplied admin table.
 * @param table Source table name (`runtime_global_variables` or `global_variables`).
 * @param var_name Variable name.
 * @return SQL query returning the variable value.
 */
static string variable_value_query(const char* table, const char* var_name) {
	return "SELECT variable_value FROM " + string(table) + " WHERE variable_name='" + string(var_name) + "'";
}

/**
 * @brief Fetches an admin variable first from runtime table, then global table.
 * @tparam T Target value type used by `mysql_query_ext_val`.
 * @param admin Open admin connection.
 * @param var_name Variable name.
 * @param default_val Value used if query/parsing fails.
 * @return Parsed variable value and error code.
 */
template <typename T>
static ext_val_t<T> fetch_var_with_fallback(MYSQL* admin, const char* var_name, const T& default_val) {
	const ext_val_t<T> runtime_val {
		mysql_query_ext_val(admin, variable_value_query("runtime_global_variables", var_name), default_val)
	};
	if (runtime_val.err == EXIT_SUCCESS) {
		return runtime_val;
	}

	const ext_val_t<T> global_val {
		mysql_query_ext_val(admin, variable_value_query("global_variables", var_name), default_val)
	};
	return global_val;
}

/**
 * @brief Snapshot of eventslog runtime variables used for restore.
 */
struct old_log_vars_t {
	bool valid { false };
	string eventslog_filename {};
	int32_t eventslog_default_log { 1 };
	int32_t eventslog_format { 2 };
	int32_t eventslog_rate_limit { 1 };
};

/**
 * @brief Fetches current mysql-eventslog runtime variables for rollback.
 * @param admin Open admin connection.
 * @return Captured variables; `valid=false` when fetch fails.
 */
static old_log_vars_t fetch_old_log_vars(MYSQL* admin) {
	old_log_vars_t old_vars {};

	const ext_val_t<string> eventslog_filename {
		fetch_var_with_fallback(admin, "mysql-eventslog_filename", string(""))
	};
	const ext_val_t<int32_t> eventslog_default_log {
		fetch_var_with_fallback(admin, "mysql-eventslog_default_log", int32_t(1))
	};
	const ext_val_t<int32_t> eventslog_format {
		fetch_var_with_fallback(admin, "mysql-eventslog_format", int32_t(2))
	};
	const ext_val_t<int32_t> eventslog_rate_limit {
		fetch_var_with_fallback(admin, "mysql-eventslog_rate_limit", int32_t(1))
	};

	if (
		eventslog_filename.err != EXIT_SUCCESS
		|| eventslog_default_log.err != EXIT_SUCCESS
		|| eventslog_format.err != EXIT_SUCCESS
		|| eventslog_rate_limit.err != EXIT_SUCCESS
	) {
		diag("Failed to fetch previous mysql-eventslog_* runtime vars; restore will be skipped");
		return old_vars;
	}

	old_vars.valid = true;
	old_vars.eventslog_filename = eventslog_filename.val;
	old_vars.eventslog_default_log = eventslog_default_log.val;
	old_vars.eventslog_format = eventslog_format.val;
	old_vars.eventslog_rate_limit = eventslog_rate_limit.val;

	return old_vars;
}

/**
 * @brief Restores mysql-eventslog runtime variables captured before the test.
 * @param admin Open admin connection.
 * @param old_vars Previously captured variable values.
 */
static void restore_old_log_vars(MYSQL* admin, const old_log_vars_t& old_vars) {
	if (!old_vars.valid) {
		return;
	}

	run_admin_query(admin, "SET mysql-eventslog_filename='" + old_vars.eventslog_filename + "'");
	run_admin_query(admin, "SET mysql-eventslog_default_log=" + std::to_string(old_vars.eventslog_default_log));
	run_admin_query(admin, "SET mysql-eventslog_format=" + std::to_string(old_vars.eventslog_format));
	run_admin_query(admin, "SET mysql-eventslog_rate_limit=" + std::to_string(old_vars.eventslog_rate_limit));
	run_admin_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

/**
 * @brief Worker loop issuing client queries continuously until stop is requested.
 * @param cl TAP connection config.
 * @param query Marker query used for accounting.
 * @param stop Shared stop flag.
 * @param exec_success Output counter for successfully executed queries.
 * @param conn_errors Output counter for connection failures.
 * @param query_errors Output counter for execution failures.
 */
static void worker_query_loop(
	const CommandLine& cl,
	const string& query,
	std::atomic<bool>& stop,
	std::atomic<uint64_t>& exec_success,
	std::atomic<uint64_t>& conn_errors,
	std::atomic<uint64_t>& query_errors
) {
	MYSQL* conn = mysql_init(nullptr);
	if (conn == nullptr) {
		conn_errors.fetch_add(1, std::memory_order_relaxed);
		return;
	}

	if (!mysql_real_connect(conn, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		conn_errors.fetch_add(1, std::memory_order_relaxed);
		diag("Worker failed to connect   err=\"%s\"", mysql_error(conn));
		mysql_close(conn);
		return;
	}

	while (!stop.load(std::memory_order_relaxed)) {
		if (mysql_query(conn, query.c_str()) == 0) {
			MYSQL_RES* res = mysql_store_result(conn);
			if (res != nullptr) {
				mysql_free_result(res);
			}
			exec_success.fetch_add(1, std::memory_order_relaxed);
		} else {
			const uint64_t err_n = query_errors.fetch_add(1, std::memory_order_relaxed) + 1;
			if (err_n <= 3) {
				diag("Worker query failed   err=\"%s\"", mysql_error(conn));
			}
			MYSQL_RES* res = mysql_store_result(conn);
			if (res != nullptr) {
				mysql_free_result(res);
			}
			usleep(1000);
		}
	}

	mysql_close(conn);
}

/**
 * @brief Admin loop that periodically issues `PROXYSQL FLUSH LOGS`.
 * @param cl TAP connection config.
 * @param stop Shared stop flag.
 * @param flush_ok Output counter for successful flushes.
 * @param flush_errors Output counter for failed flushes.
 * @param conn_errors Output counter for admin connection failures.
 */
static void admin_flush_loop(
	const CommandLine& cl,
	std::atomic<bool>& stop,
	std::atomic<uint64_t>& flush_ok,
	std::atomic<uint64_t>& flush_errors,
	std::atomic<uint64_t>& conn_errors
) {
	MYSQL* admin = mysql_init(nullptr);
	if (admin == nullptr) {
		conn_errors.fetch_add(1, std::memory_order_relaxed);
		return;
	}

	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		conn_errors.fetch_add(1, std::memory_order_relaxed);
		diag("Flush thread failed to connect admin   err=\"%s\"", mysql_error(admin));
		mysql_close(admin);
		return;
	}

	while (!stop.load(std::memory_order_relaxed)) {
		if (mysql_query(admin, PROXYSQL_FLUSH_LOGS) == 0) {
			MYSQL_RES* res = mysql_store_result(admin);
			if (res != nullptr) {
				mysql_free_result(res);
			}
			flush_ok.fetch_add(1, std::memory_order_relaxed);
		} else {
			const uint64_t err_n = flush_errors.fetch_add(1, std::memory_order_relaxed) + 1;
			if (err_n <= 3) {
				diag("FLUSH LOGS failed   err=\"%s\"", mysql_error(admin));
			}
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(FLUSH_INTERVAL_MS));
	}

	mysql_close(admin);
}

/**
 * @brief Executes the regression scenario and validates query-accounting integrity.
 *
 * @details
 * 1. Configure mysql eventslog runtime variables for deterministic logging.
 * 2. Read baseline value of metric
 *    `proxysql_query_logger_logged_queries_total{protocol="mysql"}`.
 * 3. Run concurrent client query load and admin `PROXYSQL FLUSH LOGS`.
 * 4. Read post-workload metric and assert metric delta equals executed queries.
 */
int main(int argc, char** argv) {
	CommandLine cl {};
	MYSQL* admin = nullptr;
	bool admin_connected = false;

	plan(16);

	const int env_rc = cl.getEnv();
	ok(env_rc == 0, "Required TAP environment variables are available");
	if (env_rc != 0) {
		skip(15, "missing TAP environment");
		return exit_status();
	}

	const string test_id = std::to_string(getpid()) + "_" + std::to_string(monotonic_time());
	const string log_base = "tap_flush_race_" + test_id + ".log";
	const string marker = "tap_flush_race_marker_" + test_id;
	const string query = "SELECT '" + marker + "'";
	const string logged_queries_metric_key = "proxysql_query_logger_logged_queries_total{protocol=\"mysql\"}";

	admin = mysql_init(nullptr);
	ok(admin != nullptr, "Admin MYSQL handle initialized");
	if (admin == nullptr) {
		skip(14, "admin handle initialization failed");
		return exit_status();
	}

	admin_connected = mysql_real_connect(
		admin, cl.admin_host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0
	);
	ok(admin_connected, "Connected to ProxySQL admin");
	if (!admin_connected) {
		skip(13, "admin connection failed");
		mysql_close(admin);
		return exit_status();
	}

	const old_log_vars_t old_vars = fetch_old_log_vars(admin);

	int setup_rc = EXIT_SUCCESS;
	setup_rc |= run_admin_query(admin, "SET mysql-eventslog_filename='" + log_base + "'");
	setup_rc |= run_admin_query(admin, "SET mysql-eventslog_default_log=1");
	setup_rc |= run_admin_query(admin, "SET mysql-eventslog_format=2");
	setup_rc |= run_admin_query(admin, "SET mysql-eventslog_rate_limit=1");
	setup_rc |= run_admin_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	setup_rc |= run_admin_query(admin, PROXYSQL_FLUSH_LOGS);

	ok(setup_rc == EXIT_SUCCESS, "Configured mysql-eventslog and forced initial rotation");
	if (setup_rc != EXIT_SUCCESS) {
		skip(12, "eventslog setup failed");
		restore_old_log_vars(admin, old_vars);
		mysql_close(admin);
		return exit_status();
	}

	map<string, double> pre_metrics {};
	const int pre_metrics_rc = fetch_prometheus_metrics(admin, pre_metrics);
	ok(pre_metrics_rc == EXIT_SUCCESS, "Fetched Prometheus metrics before workload");

	double pre_logged_queries = 0;
	const bool pre_metric_found = get_metric_value(pre_metrics, logged_queries_metric_key, pre_logged_queries);
	ok(pre_metric_found, "Found metric '%s' before workload", logged_queries_metric_key.c_str());

	std::atomic<bool> stop { false };
	std::atomic<uint64_t> exec_success { 0 };
	std::atomic<uint64_t> worker_conn_errors { 0 };
	std::atomic<uint64_t> worker_query_errors { 0 };
	std::atomic<uint64_t> flush_ok { 0 };
	std::atomic<uint64_t> flush_errors { 0 };
	std::atomic<uint64_t> flush_conn_errors { 0 };

	vector<std::thread> workers {};
	workers.reserve(CLIENT_THREADS);

	for (int i = 0; i < CLIENT_THREADS; ++i) {
		workers.emplace_back(
			worker_query_loop,
			std::ref(cl),
			std::cref(query),
			std::ref(stop),
			std::ref(exec_success),
			std::ref(worker_conn_errors),
			std::ref(worker_query_errors)
		);
	}

	std::thread flusher(
		admin_flush_loop,
		std::ref(cl),
		std::ref(stop),
		std::ref(flush_ok),
		std::ref(flush_errors),
		std::ref(flush_conn_errors)
	);

	std::this_thread::sleep_for(std::chrono::seconds(TEST_DURATION_SEC));
	stop.store(true, std::memory_order_relaxed);

	for (std::thread& worker : workers) {
		worker.join();
	}
	flusher.join();

	ok(worker_conn_errors.load(std::memory_order_relaxed) == 0, "Worker connections established");
	ok(worker_query_errors.load(std::memory_order_relaxed) == 0, "Worker queries succeeded without errors");
	ok(exec_success.load(std::memory_order_relaxed) > 0, "Workers executed at least one query");
	ok(flush_conn_errors.load(std::memory_order_relaxed) == 0, "Flush thread connected to admin");
	ok(flush_ok.load(std::memory_order_relaxed) > 0, "Flush thread executed FLUSH LOGS successfully");
	ok(flush_errors.load(std::memory_order_relaxed) == 0, "Flush thread had no FLUSH LOGS errors");

	const int final_flush_rc = run_admin_query(admin, PROXYSQL_FLUSH_LOGS);
	ok(final_flush_rc == EXIT_SUCCESS, "Final FLUSH LOGS succeeded");

	const uint64_t executed_queries = exec_success.load(std::memory_order_relaxed);

	map<string, double> post_metrics {};
	const int post_metrics_rc = fetch_prometheus_metrics(admin, post_metrics);
	ok(post_metrics_rc == EXIT_SUCCESS, "Fetched Prometheus metrics after workload");

	double post_logged_queries = 0;
	const bool post_metric_found = get_metric_value(post_metrics, logged_queries_metric_key, post_logged_queries);
	ok(post_metric_found, "Found metric '%s' after workload", logged_queries_metric_key.c_str());

	uint64_t logged_queries_delta = 0;
	if (post_logged_queries >= pre_logged_queries) {
		logged_queries_delta = static_cast<uint64_t>(post_logged_queries - pre_logged_queries + 0.5);
	}

	diag(
		"Query accounting   executed=%lu metric_delta=%lu metric_pre=%.0f metric_post=%.0f threads=%d duration_s=%d flush_ok=%lu",
		executed_queries,
		logged_queries_delta,
		pre_logged_queries,
		post_logged_queries,
		CLIENT_THREADS,
		TEST_DURATION_SEC,
		flush_ok.load(std::memory_order_relaxed)
	);

	ok(
		logged_queries_delta == executed_queries,
		"No marker query was dropped during concurrent FLUSH LOGS   executed=%lu metric_delta=%lu",
		executed_queries,
		logged_queries_delta
	);

	restore_old_log_vars(admin, old_vars);

	if (admin != nullptr) {
		mysql_close(admin);
	}

	return exit_status();
}
