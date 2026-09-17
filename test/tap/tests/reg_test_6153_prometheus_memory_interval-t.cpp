/**
 * @file reg_test_6153_prometheus_memory_interval-t.cpp
 * @brief Verify that MySQL buffer gauges honor the Prometheus memory refresh interval.
 */

#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

using mysql_ptr = std::unique_ptr<MYSQL, decltype(&mysql_close)>;

namespace {

constexpr const char* MEMORY_INTERVAL = "admin-prometheus_memory_metrics_interval";
constexpr const char* FRONTEND_BUFFERS_METRIC =
	"proxysql_mysql_frontend_buffers_bytes{protocol=\"mysql\"}";

mysql_ptr connect_mysql(
	const char* host,
	int port,
	const char* username,
	const char* password
) {
	MYSQL* mysql = mysql_init(nullptr);
	if (!mysql) {
		diag("mysql_init() failed");
		return mysql_ptr(nullptr, &mysql_close);
	}

	if (!mysql_real_connect(mysql, host, username, password, nullptr, port, nullptr, 0)) {
		diag("mysql_real_connect(%s:%d) failed: %s", host, port, mysql_error(mysql));
		mysql_close(mysql);
		return mysql_ptr(nullptr, &mysql_close);
	}

	return mysql_ptr(mysql, &mysql_close);
}

bool set_memory_interval(MYSQL* admin, const std::string& value) {
	return set_admin_global_variable(admin, MEMORY_INTERVAL, value) == EXIT_SUCCESS &&
		mysql_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME") == EXIT_SUCCESS;
}

bool get_frontend_buffers_metric(MYSQL* admin, double& value) {
	if (mysql_query(admin, "SHOW PROMETHEUS METRICS") != EXIT_SUCCESS) {
		diag("SHOW PROMETHEUS METRICS failed: %s", mysql_error(admin));
		return false;
	}

	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) {
		diag("SHOW PROMETHEUS METRICS returned no resultset");
		return false;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	const std::string output = row && row[0] ? row[0] : "";
	mysql_free_result(result);

	const auto metrics = parse_prometheus_metrics(output);
	const auto metric = metrics.find(FRONTEND_BUFFERS_METRIC);
	if (metric == metrics.end()) {
		return false;
	}

	value = metric->second;
	return true;
}

class MemoryIntervalRestorer {
public:
	MemoryIntervalRestorer(MYSQL* admin, std::string original_value)
		: admin_(admin), original_value_(std::move(original_value)) {}
	MemoryIntervalRestorer(const MemoryIntervalRestorer&) = delete;
	MemoryIntervalRestorer& operator=(const MemoryIntervalRestorer&) = delete;
	MemoryIntervalRestorer(MemoryIntervalRestorer&&) = delete;
	MemoryIntervalRestorer& operator=(MemoryIntervalRestorer&&) = delete;

	bool restore() {
		if (!active_) {
			return true;
		}

		const bool restored = set_memory_interval(admin_, original_value_);
		if (!restored) {
			diag("Failed to restore %s=%s", MEMORY_INTERVAL, original_value_.c_str());
		}
		active_ = false;
		return restored;
	}

	~MemoryIntervalRestorer() { (void)restore(); }

private:
	MYSQL* admin_;
	std::string original_value_;
	bool active_ = true;
};

} // namespace

int main() {
	plan(8);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables");
		skip(8, "Cannot continue without the required TAP environment");
		return EXIT_FAILURE;
	}

	auto admin = connect_mysql(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	auto anchor = connect_mysql(cl.host, cl.port, cl.username, cl.password);
	if (!admin || !anchor) {
		return EXIT_FAILURE;
	}

	std::string original_interval;
	if (show_admin_global_variable(admin.get(), MEMORY_INTERVAL, original_interval) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	MemoryIntervalRestorer restore_interval(admin.get(), original_interval);

	if (!set_memory_interval(admin.get(), "1")) {
		diag("Failed to set %s=1", MEMORY_INTERVAL);
		return EXIT_FAILURE;
	}

	// Ensure the next scrape crosses the interval gate and captures the anchor session.
	sleep(2);
	double baseline = 0;
	const bool baseline_found = get_frontend_buffers_metric(admin.get(), baseline);
	ok(baseline_found, "%s is exported", FRONTEND_BUFFERS_METRIC);
	ok(baseline > 0, "%s has a non-zero baseline", FRONTEND_BUFFERS_METRIC);

	if (!set_memory_interval(admin.get(), "3600")) {
		diag("Failed to set %s=3600", MEMORY_INTERVAL);
		return EXIT_FAILURE;
	}

	std::vector<mysql_ptr> extra_connections;
	for (int i = 0; i < 4; ++i) {
		auto connection = connect_mysql(cl.host, cl.port, cl.username, cl.password);
		if (connection) {
			extra_connections.emplace_back(std::move(connection));
		}
	}
	ok(extra_connections.size() == 4, "Created four additional frontend sessions");

	double cached = 0;
	const bool cached_found = get_frontend_buffers_metric(admin.get(), cached);
	ok(cached_found, "%s remains exported", FRONTEND_BUFFERS_METRIC);
	ok(
		cached == baseline,
		"Frontend buffer gauge remains cached inside the memory interval (before=%lf, after=%lf)",
		baseline,
		cached
	);

	if (!set_memory_interval(admin.get(), "1")) {
		diag("Failed to set %s=1", MEMORY_INTERVAL);
		return EXIT_FAILURE;
	}

	// Once the interval expires, the newly opened sessions must be reflected.
	sleep(2);
	double refreshed = 0;
	const bool refreshed_found = get_frontend_buffers_metric(admin.get(), refreshed);
	ok(refreshed_found, "%s remains exported after refresh", FRONTEND_BUFFERS_METRIC);
	ok(
		refreshed > cached,
		"Frontend buffer gauge refreshes after the memory interval (cached=%lf, refreshed=%lf)",
		cached,
		refreshed
	);
	ok(restore_interval.restore(), "Original Prometheus memory metrics interval is restored");

	return exit_status();
}
