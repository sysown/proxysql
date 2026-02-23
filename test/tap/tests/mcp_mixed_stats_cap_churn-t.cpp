/**
 * @file mcp_mixed_stats_cap_churn-t.cpp
 * @brief TAP focused on live MCP cap churn during mixed MySQL+PgSQL load.
 *
 * This test runs `mcp_mixed_mysql_pgsql_concurrency_stress-t` in churn-enabled
 * modes where `mcp-stats_show_processlist_max_rows` and
 * `mcp-stats_show_queries_max_rows` are updated repeatedly while mixed protocol
 * traffic and MCP polling are in progress.
 */

#include <cstdlib>
#include <deque>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include "tap.h"

namespace {

/**
 * @brief Cap-churn execution profile for child mixed-stress runs.
 */
struct churn_profile_t {
	std::string name;
	int runtime_sec;
	int mysql_workers;
	int pgsql_workers;
	int processlist_cap;
	int show_queries_cap;
	int churn_interval_ms;
};

/**
 * @brief Convert `system()` status to a normalized exit code.
 *
 * @param rc Raw `system()` return code.
 * @return Process exit code, signal-mapped code, or -1 on launcher failure.
 */
int normalize_system_rc(int rc) {
	if (rc == -1) {
		return -1;
	}
	if (WIFEXITED(rc)) {
		return WEXITSTATUS(rc);
	}
	if (WIFSIGNALED(rc)) {
		return 128 + WTERMSIG(rc);
	}
	return rc;
}

/**
 * @brief Print the tail of a log file via TAP diagnostics.
 *
 * @param path Log file path.
 * @param max_lines Maximum number of lines to print.
 */
void diag_log_tail(const std::string& path, size_t max_lines) {
	std::ifstream in(path);
	if (!in.good()) {
		diag("Cannot open log file: %s", path.c_str());
		return;
	}

	std::deque<std::string> tail;
	std::string line;
	while (std::getline(in, line)) {
		tail.push_back(line);
		if (tail.size() > max_lines) {
			tail.pop_front();
		}
	}

	diag("---- child log tail (%s) ----", path.c_str());
	for (const auto& l : tail) {
		diag("%s", l.c_str());
	}
	diag("---- end child log tail ----");
}

/**
 * @brief Execute one cap-churn profile as a child process.
 *
 * @param profile Churn configuration.
 * @param workdir Directory containing the test executables.
 * @param log_path Output log path used by the child command.
 * @return Normalized child exit code.
 */
int run_churn_profile(const churn_profile_t& profile, const std::string& workdir, std::string& log_path) {
	std::ostringstream log_name;
	log_name << "/tmp/mcp_mixed_cap_churn_" << profile.name << "_" << getpid() << ".log";
	log_path = log_name.str();

	std::ostringstream cmd;
	cmd << "TAP_QUIET_ENVLOAD=1 "
	    << "MCP_MIXED_STRESS_RUNTIME_SEC=" << profile.runtime_sec << " "
	    << "MCP_MIXED_STRESS_MYSQL_WORKERS=" << profile.mysql_workers << " "
	    << "MCP_MIXED_STRESS_PGSQL_WORKERS=" << profile.pgsql_workers << " "
	    << "MCP_MIXED_STRESS_PROCESSLIST_CAP=" << profile.processlist_cap << " "
	    << "MCP_MIXED_STRESS_SHOW_QUERIES_CAP=" << profile.show_queries_cap << " "
	    << "MCP_MIXED_STRESS_ENABLE_CAP_CHURN=1 "
	    << "MCP_MIXED_STRESS_CAP_CHURN_INTERVAL_MS=" << profile.churn_interval_ms << " "
	    << workdir << "/mcp_mixed_mysql_pgsql_concurrency_stress-t"
	    << " > " << log_path << " 2>&1";

	const int rc = std::system(cmd.str().c_str());
	return normalize_system_rc(rc);
}

} // namespace

int main() {
	plan(4);

	diag("=== MCP Mixed Stats Cap Churn Test ===");
	diag("This test runs mcp_mixed_mysql_pgsql_concurrency_stress-t in churn-enabled");
	diag("mode where mcp-stats_show_processlist_max_rows and mcp-stats_show_queries_max_rows");
	diag("are updated repeatedly while mixed protocol traffic and MCP polling are active.");
	diag("Profiles include 'moderate' and 'aggressive' churn rates. The goal is to validate");
	diag("that MCP stats remains stable when cap variables change dynamically under load.");
	diag("=======================================");

	const char* workdir = getenv("TAP_WORKDIR");
	if (!workdir) {
		diag("Failed to get TAP_WORKDIR environment variable.");
		return EXIT_FAILURE;
	}

	const std::string child_binary = std::string(workdir) + "/mcp_mixed_mysql_pgsql_concurrency_stress-t";
	const bool child_available = (access(child_binary.c_str(), X_OK) == 0);
	ok(child_available, "Child mixed-stress binary is available");
	if (!child_available) {
		skip(3, "Cannot run cap-churn scenarios without child mixed-stress binary");
		return exit_status();
	}

	const std::vector<churn_profile_t> profiles = {
		{"moderate", 7, 10, 10, 120, 180, 200},
		{"aggressive", 9, 12, 12, 120, 180, 90}
	};

	bool all_ok = true;
	for (const auto& profile : profiles) {
		std::string log_path;
		const int exit_code = run_churn_profile(profile, workdir, log_path);
		const bool passed = (exit_code == 0);
		ok(
			passed,
			"Cap-churn profile `%s` completed successfully (exit_code=%d)",
			profile.name.c_str(),
			exit_code
		);
		if (!passed) {
			diag_log_tail(log_path, 140);
			all_ok = false;
		}
	}

	ok(all_ok, "All MCP cap-churn mixed-load scenarios passed");

	return exit_status();
}
