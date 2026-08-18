/**
 * @file reg_test_4001-restapi_scripts_num_fds-t.cpp
 * @brief Regression test for checking that RESTAPI is able to execute scripts when ProxySQL is handling more
 *   than 'FD_SETSIZE' file descriptors.
 */

#include <cstring>
#include <chrono>
#include <vector>
#include <thread>
#include <string>
#include <stdio.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/resource.h>

#include "mysql.h"

#include "command_line.h"
#include "proxysql_utils.h"
#include "json.hpp"
#include "tap.h"
#include "utils.h"

using nlohmann::json;
using std::string;
using std::vector;

const int NUM_CONNECTIONS = 1300;
// base_address is constructed at runtime using the ProxySQL host from the environment.
// It is defined as a mutable global so check functions at file scope can access it.
static string base_address { "http://proxysql:6070/sync/" };

const vector<honest_req_t> honest_requests {
	{ { "valid_output_script", "%s.py", "POST", 5000 }, { "{}" } },
	{ { "valid_params_script", "%s.py", "POST", 5000 }, { "{\"param1\": \"value1\", \"param2\": \"value2\"}" } },
	{ { "valid_params_script", "%s.py", "GET", 5000 }, { "", "?param1='value1'&param2='\"value2\"'" } },
};

int main(int argc, char** argv) {
	CommandLine cl;

	diag("================================================================================");
	diag("TEST DESCRIPTION: RESTAPI Stability with High File Descriptor Usage");
	diag("This test verifies that ProxySQL's RESTAPI remains functional even when the");
	diag("number of concurrent MySQL connections exceeds FD_SETSIZE (1024).");
	diag("================================================================================");

	if (cl.getEnv()) {
		diag("ERROR: Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	// Build the RESTAPI base address using the actual ProxySQL host from the environment.
	base_address = string("http://") + string(cl.host) + ":6070/sync/";

	diag("Connection Context:");
	diag("  - Target Host: %s", cl.host);
	diag("  - Admin Port:  %d", cl.admin_port);
	diag("  - RESTAPI Base: %s", base_address.c_str());

	const char* ws_env = getenv("WORKSPACE");
	if (!ws_env) {
		diag("ERROR: WORKSPACE environment variable not set. Cannot locate scripts.");
		return EXIT_FAILURE;
	}

	// PROVISIONING: Copy scripts to /var/lib/proxysql so ProxySQL container can see them
	string script_src = string(ws_env) + "/test/tap/tests/reg_test_3223_scripts";
	string script_dst = "/var/lib/proxysql/reg_test_3223_scripts";
	diag("Provisioning scripts:");
	diag("  - Source: %s", script_src.c_str());
	diag("  - Dest:   %s", script_dst.c_str());
	
	string cmd = "mkdir -p " + script_dst + " && cp -rp " + script_src + "/. " + script_dst + "/ && chmod -R 777 " + script_dst;
	if (system(cmd.c_str()) != 0) {
		diag("ERROR: Failed to provision scripts to %s", script_dst.c_str());
		return EXIT_FAILURE;
	}
	diag("Provisioning successful.");

	diag("Setting new process limits beyond 'FD_SETSIZE'");
	struct rlimit limits { 0, 0 };
	getrlimit(RLIMIT_NOFILE, &limits);
	diag("Old process limits: { %ld, %ld }", (long)limits.rlim_cur, (long)limits.rlim_max);
	limits.rlim_cur = NUM_CONNECTIONS * 2 + 100;
	setrlimit(RLIMIT_NOFILE, &limits);
	diag("New process limits: { %ld, %ld }", (long)limits.rlim_cur, (long)limits.rlim_max);

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}
	
	diag("Enabling RESTAPI in ProxySQL...");
	MYSQL_QUERY(admin, "SET admin-restapi_enabled='true'");
	MYSQL_QUERY(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	diag("RESTAPI enabled.");

	string script_base_path = script_dst;
	const bool with_asan = get_env_int("WITHASAN", 0) != 0;
	const uint64_t endpoint_timeout = with_asan ? 15000 : 5000;
	const ept_info_t dummy_ept { "dummy_ept_script", "%s.py", "POST", endpoint_timeout };

	vector<ept_info_t> v_epts_info {};
	for (const auto& req : honest_requests) {
		ept_info_t ept_info = req.ept_info;
		ept_info.timeout = endpoint_timeout;
		v_epts_info.push_back(ept_info);
	}

	diag("Configuring RESTAPI endpoints using scripts in: %s", script_base_path.c_str());
	int ept_conf_res = configure_endpoints(admin, script_base_path, v_epts_info, dummy_ept, true);
	if (ept_conf_res) {
		diag("Endpoint configuration failed. Check ProxySQL log for execution errors.");
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	std::vector<MYSQL*> mysql_connections {};
	diag("Establishing %d baseline connections to ProxySQL...", NUM_CONNECTIONS);
	for (int i = 0; i < NUM_CONNECTIONS; i++) {
		MYSQL* proxy = mysql_init(NULL);
		if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			return EXIT_FAILURE;
		}
		mysql_connections.push_back(proxy);
		if ((i + 1) % 200 == 0) diag("  Established %d/%d connections...", i + 1, NUM_CONNECTIONS);
	}

	typedef std::chrono::high_resolution_clock hrc;
	const uint64_t test_duration = 10000;
	const uint32_t FAILURE_RATE = 10;
	int conn_creation_res = EXIT_FAILURE;
	uint64_t conn_count = 0;
	uint64_t mysql_fails = 0;

	diag("Starting simultaneous RESTAPI requests and connection churn...");
	{
		std::thread create_conns([&]() -> int {
			hrc::time_point start = hrc::now();
			while (true) {
				if (conn_count > 0 && mysql_fails > (conn_count * FAILURE_RATE) / 100) {
					conn_creation_res = EXIT_FAILURE;
					return EXIT_FAILURE;
				}
				MYSQL* proxy = mysql_init(NULL);
				if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
					mysql_fails += 1;
				} else {
					if (mysql_query(proxy, "DO 1")) mysql_fails += 1;
					mysql_close(proxy);
				}
				if (std::chrono::duration_cast<std::chrono::milliseconds>(hrc::now() - start).count() >= test_duration) break;
				conn_count += 1;
			}
			conn_creation_res = EXIT_SUCCESS;
			return EXIT_SUCCESS;
		});

		hrc::time_point start = hrc::now();
		int api_request_count = 0;
		while (true) {
			int rc = 0;
			for (const honest_req_t& req : honest_requests) {
				for (const string& params : req.params) {
					const string ept { join_path(base_address, req.ept_info.name) };
					std::string curl_res_data {};
					uint64_t curl_res_code = 0;
					CURLcode curl_err = (req.ept_info.method == "POST") ? 
						perform_simple_post(ept, params, curl_res_code, curl_res_data) :
						perform_simple_get(ept + params, curl_res_code, curl_res_data);

					ok(curl_err == CURLE_OK && curl_res_code == 200, "RESTAPI request should succeed");
					if (curl_err != CURLE_OK || curl_res_code != 200) {
						diag("  Failure detail: method=%s, endpoint=%s, curl_err=%d, res_code=%ld, data=%s", 
							req.ept_info.method.c_str(), ept.c_str(), curl_err, curl_res_code, curl_res_data.c_str());
					}
					if (curl_err == 7) { rc = 1; break; }
					api_request_count++;
				}
				if (rc) break;
			}
			if (std::chrono::duration_cast<std::chrono::milliseconds>(hrc::now() - start).count() >= test_duration || rc) break;
		}
		create_conns.join();
		diag("Test finished. API requests: %d, Churn conns: %ld, Failures: %ld", api_request_count, conn_count, mysql_fails);
		ok(conn_creation_res == EXIT_SUCCESS, "MySQL failure rate within limits");
	}

	for (MYSQL* conn : mysql_connections) mysql_close(conn);
	mysql_close(admin);
	curl_global_cleanup();
	return exit_status();
}
