/**
 * @file mcp_mixed_stats_profile_matrix-t.cpp
 * @brief TAP matrix runner for MCP mixed MySQL+PgSQL stress profiles.
 *
 * This test executes `mcp_mixed_mysql_pgsql_concurrency_stress-t` multiple times
 * using different runtime/load/churn profiles. The objective is validating that
 * MCP stats remains stable across quick, churn-enabled, and heavier mixed-load
 * scenarios without duplicating the full workload implementation.
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
 * @brief Stress profile used to parameterize a child mixed-stress run.
 */
struct stress_profile_t {
	std::string name;
	int runtime_sec;
	int mysql_workers;
	int pgsql_workers;
	int processlist_cap;
	int show_queries_cap;
	int cap_churn_enabled;
	int cap_churn_interval_ms;
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
 * @brief Execute one mixed-stress profile as a child process.
 *
 * The child output is redirected to a profile-specific log file to keep TAP
 * output from the parent test protocol-clean.
 *
 * @param profile Profile configuration.
 * @param workdir Directory containing the test executables.
 * @param log_path Output log path used by the child command.
 * @return Normalized child exit code.
 */
int run_profile(const stress_profile_t& profile, const std::string& workdir, std::string& log_path) {
	std::ostringstream log_name;
	log_name << "/tmp/mcp_mixed_profile_" << profile.name << "_" << getpid() << ".log";
	log_path = log_name.str();

	std::ostringstream cmd;
	cmd << "TAP_QUIET_ENVLOAD=1 "
	    << "MCP_MIXED_STRESS_RUNTIME_SEC=" << profile.runtime_sec << " "
	    << "MCP_MIXED_STRESS_MYSQL_WORKERS=" << profile.mysql_workers << " "
	    << "MCP_MIXED_STRESS_PGSQL_WORKERS=" << profile.pgsql_workers << " "
	    << "MCP_MIXED_STRESS_PROCESSLIST_CAP=" << profile.processlist_cap << " "
	    << "MCP_MIXED_STRESS_SHOW_QUERIES_CAP=" << profile.show_queries_cap << " "
	    << "MCP_MIXED_STRESS_ENABLE_CAP_CHURN=" << profile.cap_churn_enabled << " "
	    << "MCP_MIXED_STRESS_CAP_CHURN_INTERVAL_MS=" << profile.cap_churn_interval_ms << " "
	    << workdir << "/mcp_mixed_mysql_pgsql_concurrency_stress-t"
	    << " > " << log_path << " 2>&1";

	const int rc = std::system(cmd.str().c_str());
	return normalize_system_rc(rc);
}

} // namespace

int main() {
	plan(5);

	diag("=== MCP Mixed Stats Profile Matrix Test ===");
	diag("This test runs the mcp_mixed_mysql_pgsql_concurrency_stress-t binary");
	diag("multiple times using different runtime/load/churn profiles. Profiles include:");
	diag("  - quick: short runtime, no cap churn");
	diag("  - churn: medium runtime with cap variable updates");
	diag("  - heavy: longer runtime with more workers and cap churn");
	diag("The goal is to validate MCP stats stability across diverse load scenarios.");
	diag("============================================");

	const char* workdir = getenv("TAP_WORKDIR");
	if (!workdir) {
		diag("Failed to get TAP_WORKDIR environment variable.");
		return EXIT_FAILURE;
	}

	const std::string child_binary = std::string(workdir) + "/mcp_mixed_mysql_pgsql_concurrency_stress-t";
	const bool child_available = (access(child_binary.c_str(), X_OK) == 0);
	ok(child_available, "Child mixed-stress binary is available");
	if (!child_available) {
		skip(4, "Cannot run profile matrix without child mixed-stress binary");
		return exit_status();
	}

	const std::vector<stress_profile_t> profiles = {
		{"quick", 6, 8, 8, 120, 180, 0, 700},
		{"churn", 6, 8, 8, 120, 180, 1, 250},
		{"heavy", 8, 14, 14, 120, 180, 1, 120}
	};

	bool all_ok = true;
	for (const auto& profile : profiles) {
		std::string log_path;
		const int exit_code = run_profile(profile, workdir, log_path);
		const bool passed = (exit_code == 0);
		ok(
			passed,
			"Profile `%s` completed successfully (exit_code=%d)",
			profile.name.c_str(),
			exit_code
		);
		if (!passed) {
			diag_log_tail(log_path, 120);
			all_ok = false;
		}
	}

	ok(all_ok, "All MCP mixed-stress profiles passed");

	return exit_status();
}
