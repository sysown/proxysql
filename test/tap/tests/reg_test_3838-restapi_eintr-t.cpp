/**
 * @file reg_test_3838-restapi_eintr-t.cpp
 * @brief This is a regression test for issue #3838. Test checks that scripts executed via RESTAPI doesn't get
 *   unproperly interrupted by signals.
 * @details The test register a simple waiting script into the RESTAPI, for latter issuing multiple different
 *   signals to it and checks that:
 *   - ProxySQL properly handles the signals being set to the executed script.
 *   - Timeouts work properly no matter the signaling.
 *   - ProxySQL correctly reports the child termination exit status. E.g. If terminated by a signal.
 * @date 2022-04-27
 */

#include <algorithm>
#include <string>
#include <stdio.h>
#include <vector>
#include <thread>
#include <tuple>

#include <signal.h>
#include <unistd.h>

#include "curl/curl.h"

#include "mysql.h"
#include "mysqld_error.h"

#include "json.hpp"
#include "tap.h"
#include "proxysql_utils.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

const int SIGNAL_NUM = 5;
// base_address is constructed at runtime using the ProxySQL host from the environment.
static string base_address { "http://proxysql:6070/sync/" };

using params = std::string;
using signal_t = int;
using rescode_t = long;

vector<std::tuple<string, params, rescode_t, signal_t, int>> endpoint_requests {
	std::make_tuple("simple_sleep", "1", 200, SIGCONT, 0),
	std::make_tuple("simple_sleep_timeout", "4", 424, SIGCONT, ETIME),
	std::make_tuple("simple_sleep_timeout", "4", 424, SIGSTOP, ETIME),
	std::make_tuple("simple_sleep", "2", 424, SIGTERM, SIGTERM),
};

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	// Build the RESTAPI base address using the actual ProxySQL host from the environment.
	base_address = string("http://") + string(cl.host) + ":6070/sync/";

	diag("=== Regression Test #3838: RESTAPI Script Execution & Signals ===");
	diag("This test verifies that scripts executed via ProxySQL RESTAPI");
	diag("are not improperly interrupted by signals.");
	diag("The test strategy is:");
	diag("1. Register scripts in ProxySQL RESTAPI routes.");
	diag("2. Issue multiple POST requests to these endpoints.");
	diag("3. Issue various signals (SIGCONT, SIGSTOP, SIGTERM) to the child processes.");
	diag("4. Verify that ProxySQL correctly reports exit statuses and handles timeouts.");
	diag("==================================================================");

	const char* tap_host_env = getenv("TAP_HOST");
	string target_host = (tap_host_env ? tap_host_env : "127.0.0.1");
	bool is_remote = (target_host != "127.0.0.1" && target_host != "localhost" && target_host != "0.0.0.0");

	if (is_remote) {
		plan(0);
		diag("Skipping test: ProxySQL is running on a remote host or different container (%s).", target_host.c_str());
		diag("This test requires a shared PID namespace to signal child processes.");
		return exit_status();
	}

	plan(endpoint_requests.size());

	MYSQL* proxysql_admin = mysql_init(NULL);

	// Initialize connections
	diag("Connecting to ProxySQL Admin at %s:%d as %s", cl.host, cl.admin_port, cl.admin_username);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	// Enable 'RESTAPI'
	diag("Enabling RESTAPI on port 6070");
	MYSQL_QUERY(proxysql_admin, "SET admin-restapi_enabled='true'");
	MYSQL_QUERY(proxysql_admin, "SET admin-restapi_port=6070");

	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	// Clean current 'restapi_routes' if any
	diag("Configuring RESTAPI routes...");
	MYSQL_QUERY(proxysql_admin, "DELETE FROM restapi_routes");

	// Configure restapi_routes to be used
	const char* d_env = getenv("REGULAR_INFRA_DATADIR"); string test_script_base_path = (d_env ? string(d_env) + "/reg_test_3838_scripts" : string(cl.workdir) + "reg_test_3838_scripts");

	vector<string> t_valid_scripts_inserts {
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment)"
		" VALUES (1,3000,'POST','simple_sleep','%s/simple_sleep.sh','simple_sleep_comment')",
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment)"
		" VALUES (1,3000,'POST','simple_sleep_timeout','%s/simple_sleep.sh','simple_sleep_to_comment')",
	};
	vector<string> valid_scripts_inserts {};

	for (const auto& t_valid_script_insert : t_valid_scripts_inserts) {
		string valid_script_insert {};
		string_format(t_valid_script_insert, valid_script_insert, test_script_base_path.c_str());
		valid_scripts_inserts.push_back(valid_script_insert);
	}

	// Configure routes for valid scripts
	for (const auto& valid_script_insert : valid_scripts_inserts) {
		MYSQL_QUERY(proxysql_admin, valid_script_insert.c_str());
	}

	// Load RESTAPI
	diag("Loading RESTAPI to runtime");
	MYSQL_QUERY(proxysql_admin, "LOAD RESTAPI TO RUNTIME");

	// Sensible wait until the new configured enpoints are ready. Use the first enpoint for the check
	const auto& first_request_tuple { endpoint_requests.front() };
	const string full_endpoint {
		base_address + std::get<0>(first_request_tuple) + "/"
	};
	diag("Waiting for endpoint %s to be ready...", full_endpoint.c_str());
	int endpoint_timeout = wait_post_enpoint_ready(full_endpoint, std::get<1>(first_request_tuple), 10, 500);

	if (endpoint_timeout) {
		diag(
			"Timeout while trying to reach first valid enpoint. Test failed, skipping endpoint testing..."
		);
		goto skip_endpoints_testing;
	}

	for (const auto& request : endpoint_requests) {
		const string endpoint { base_address + std::get<0>(request) + "/"};
		const string params { std::get<1>(request) };
		const long exp_rc = std::get<2>(request);
		const int signal = std::get<3>(request);
		const int exp_child_exit_st = std::get<4>(request);

		diag("Processing request: endpoint=%s params=%s exp_rc=%ld signal=%d", endpoint.c_str(), params.c_str(), exp_rc, signal);

		string post_out_err { "" };
		uint64_t curl_res_code = 0;

		CURLcode post_err = CURLE_HTTP_POST_ERROR;

		// 1. Perform the POST operation
		diag("  Starting POST request in separate thread...");
		std::thread post_op_th([&] () -> void {
			post_err = perform_simple_post(endpoint, params, curl_res_code, post_out_err);
		});

		// 2. Find the child process
		string s_pid {};

		int timeout = 2000;
		int waited = 0;
		int e_res= 0;

		diag("  Waiting for child process to spawn (searching for simple_sleep.sh)...");
		while (waited < timeout) {
			e_res = exec("ps aux | grep \"simple_sleep.sh\" | grep -v grep | awk '{print $2}'", s_pid);

			if (e_res == 0 && s_pid.empty()) {
				usleep(100 * 1000);
				waited += 100;
			} else if (e_res == 0 && !s_pid.empty()) {
				// Sometimes multiple PIDs are returned if multiple threads/tests are running
				std::stringstream ss(s_pid);
				string first_pid;
				if (ss >> first_pid) {
					s_pid = first_pid;
					break;
				}
			} else {
				break;
			}
		}

		if (e_res != EXIT_SUCCESS || s_pid.empty()) {
			if (e_res != EXIT_SUCCESS) {
				fprintf(stderr, "File %s, line %d, 'exec' failed with error: '%d'\n", __FILE__, __LINE__, e_res);
			} else {
				diag("  Warning: Could not find child process simple_sleep.sh after %dms. Signaling might fail.", waited);
			}
		} else {
			// 3. Send multiple signals to the child process
			int pid = std::stol(s_pid);
			int k_res = 0;

			diag("  Found child PID: %d. Sending %d signals (signal type: %d)...", pid, SIGNAL_NUM, signal);
			if (signal == SIGCONT) {
				for (int i = 0; i < SIGNAL_NUM; i++) {
					k_res = kill(pid, SIGSTOP);
					if (k_res != 0) { 
						diag("  kill(SIGSTOP) failed: %s", strerror(errno));
						break; 
					}

					usleep(50*1000);

					k_res = kill(pid, SIGCONT);
					if (k_res != 0) { 
						diag("  kill(SIGCONT) failed: %s", strerror(errno));
						break; 
					}
				}
			} else {
				for (int i = 0; i < SIGNAL_NUM; i++) {
					k_res = kill(pid, signal);
					if (k_res != 0) {
						diag("  kill(%d) failed: %s", signal, strerror(errno));
					}
				}
			}
		}

		diag("  Waiting for POST request to complete...");
		post_op_th.join();
		diag("  Request completed with curl_res_code=%ld and post_err=%d", curl_res_code, post_err);

		try {
			int child_exit_st = 0;
			int signaled = 0;
			int exp_signaled = 0;

			nlohmann::json j_curl_err = nlohmann::json::parse(post_out_err);
			if (j_curl_err.contains("error_code")) {
				child_exit_st = std::stol(j_curl_err["error_code"].get<string>());
			}
			diag("  Parsed response: child_exit_st=%d", child_exit_st);

			// NOTE: This is pointless because the value doesn't change, but it's a demonstration on how to
			// recover child process exit statuses for debugging purposes.
			if (exp_child_exit_st == SIGTERM) {
				exp_signaled = 1;
				signaled = WIFSIGNALED(child_exit_st);
				child_exit_st = WTERMSIG(child_exit_st);
			}

			bool ok_check =
				post_err == CURLE_OK && curl_res_code == exp_rc &&
				exp_signaled == signaled && exp_child_exit_st == child_exit_st;

			ok(
				ok_check,
				"Performing a POST over endpoint '%s' should result into a '%ld' response:"
				" (curl_err: '%d', response_errcode: '%ld', signaled: '%d', child_exit_st: '%d', curlerr: '%s')",
				endpoint.c_str(), exp_rc, post_err, curl_res_code, signaled, child_exit_st, post_out_err.c_str()
			);
		} catch (const std::exception& ex) {
			diag("Invalid error kind returned by ProxySQL, JSON '%s' parsing failed with error: %s", post_out_err.c_str(), ex.what());
		}
	}

skip_endpoints_testing:

	mysql_close(proxysql_admin);

	return exit_status();
}
