/**
 * @file reg_test_4001-restapi_scripts_num_fds-t.cpp
 * @brief Regression test for checking that RESTAPI is able to execute scripts when ProxySQL is handling more
 *   than 'FD_SETSIZE' file descriptors.
 *
 * @details The tests creates a higher number of connections than the default maximum number of file
 *  descriptors determined by `FD_SETSIZE` (1024). After doing this, it tries to enable the 'RESTAPI' and
 *  performs requests to different endpoints while constantly creating and destroying new client connections.
 *  This covers two scenarios:
 *     - The usage of the RESTAPI when ProxySQL is using more than `FD_SETSIZE` file descriptors.
 *     - The reproduction of the scenario leading to crash reported in issue #4001.
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
const string base_address { "http://proxysql:6070/sync/" };

const vector<honest_req_t> honest_requests {
	{ { "valid_output_script", "%s.py", "POST", 1000 }, { "{}" } },
	// Check that 'POST' correctly forwards supplied parameters:
	//  1 - Target script performs a check on the supplied parameters and fails in case they are unexpected
	{ { "valid_params_script", "%s.py", "POST", 1000 }, { "{\"param1\": \"value1\", \"param2\": \"value2\"}" } },
	// On top of the previous check, also check that 'GET' allows:
	//  1 - Empty parameters: We internally translate into an empty well-formed JSON '{}'
	//  2 - Escaped values: As long as the JSON is correct, the RESTAPI forwarding should be able to handle it
	{ { "valid_params_script", "%s.py", "GET", 1000 }, { "", "?param1='value1'&param2='\"value2\"'" } },
};

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	diag("=== Regression Test #4001: RESTAPI with High FD Usage ===");
	diag("This test verifies that the RESTAPI remains operational when ProxySQL");
	diag("is handling a large number of concurrent file descriptors (> FD_SETSIZE).");
	diag("The test strategy is:");
	diag("1. Elevate process FD limits.");
	diag("2. Establish 1300 concurrent MySQL connections to ProxySQL.");
	diag("3. While these connections are held, perform continuous RESTAPI requests.");
	diag("4. Simultaneously create and destroy additional MySQL connections.");
	diag("5. Verify that RESTAPI requests and connection operations remain stable.");
	diag("==========================================================");

	diag("Setting new process limits beyond 'FD_SETSIZE'");
	struct rlimit limits { 0, 0 };
	getrlimit(RLIMIT_NOFILE, &limits);
	diag("Old process limits: { %ld, %ld }", limits.rlim_cur, limits.rlim_max);
	limits.rlim_cur = NUM_CONNECTIONS * 2 + 100;
	setrlimit(RLIMIT_NOFILE, &limits);
	diag("New process limits: { %ld, %ld }", limits.rlim_cur, limits.rlim_max);

	MYSQL* admin = mysql_init(NULL);

	// Initialize connections
	diag("Connecting to ProxySQL Admin at %s:%d as %s", cl.host, cl.admin_port, cl.admin_username);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	const char* d_env = getenv("REGULAR_INFRA_DATADIR"); string script_base_path = (d_env ? string(d_env) + "/reg_test_3223_scripts" : string(cl.workdir) + "reg_test_3223_scripts");
	const ept_info_t dummy_ept { "dummy_ept_script", "%s.py", "POST", 1000 };

	vector<ept_info_t> v_epts_info {};
	const auto ext_v_epts_info = [] (const honest_req_t& req) { return req.ept_info; };
	std::transform(
		honest_requests.begin(), honest_requests.end(), std::back_inserter(v_epts_info), ext_v_epts_info
	);

	diag("Configuring RESTAPI endpoints...");
	int ept_conf_res = configure_endpoints(admin, script_base_path, v_epts_info, dummy_ept, true);
	if (ept_conf_res) {
		diag("Endpoint configuration failed. Skipping endpoint testing...");
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
	diag("Baseline connections established.");

	typedef std::chrono::high_resolution_clock hrc;
	const uint64_t test_duration = 10000;

	const uint32_t FAILURE_RATE = 10;
	int conn_creation_res = EXIT_FAILURE;
	uint64_t conn_count = 0;
	uint64_t mysql_fails = 0;

	diag("Starting simultaneous RESTAPI requests and connection churn (Duration: %ldms)...", test_duration);
	{
		std::thread create_conns([&]() -> int {
			std::chrono::nanoseconds duration;
			hrc::time_point start;
			hrc::time_point end;

			start = hrc::now();

			while (true) {
				if (conn_count > 0 && mysql_fails > (conn_count * FAILURE_RATE) / 100) {
					diag("Too many mysql failures in connection creation, considering test as failed...");
					conn_creation_res = EXIT_FAILURE;
					return EXIT_FAILURE;
				}

				MYSQL* proxy = mysql_init(NULL);

				if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
					diag("Churn connection failed: %s", mysql_error(proxy));
					mysql_fails += 1;
				} else {
					int rc = mysql_query(proxy, "DO 1");
					if (rc) {
						diag("Churn query failed: mysql_errno: '%d', mysql_error: '%s'", mysql_errno(proxy), mysql_error(proxy));
						mysql_fails += 1;
					}
					mysql_close(proxy);
				}

				end = hrc::now();
				duration = end - start;

				if (duration.count() >= (test_duration*1000*1000)) {
					break;
				}

				conn_count += 1;
			}

			conn_creation_res = EXIT_SUCCESS;
			return EXIT_SUCCESS;
		});

		std::chrono::nanoseconds duration;
		hrc::time_point start;
		hrc::time_point end;

		start = hrc::now();

		int api_request_count = 0;
		while (true) {
			int rc = 0;

			for (const honest_req_t& req : honest_requests) {
				for (const string& params : req.params) {
					const string ept { join_path(base_address, req.ept_info.name) };
					std::string curl_res_data {};
					uint64_t curl_res_code = 0;

					CURLcode curl_err = CURLE_COULDNT_CONNECT;

					if (req.ept_info.method == "POST") {
						curl_err = perform_simple_post(ept, params, curl_res_code, curl_res_data);

						ok(
							curl_err == CURLE_OK && curl_res_code == 200,
							"'%s' over '%s' should result into a '200' res code: (curl_err: '%d', curl_res_code: '%ld')",
							req.ept_info.method.c_str(), ept.c_str(), curl_err, curl_res_code
						);
					} else {
						const string get_ept { ept + params };
						curl_err = perform_simple_get(get_ept, curl_res_code, curl_res_data);

						ok(
							curl_err == CURLE_OK && curl_res_code == 200,
							"'%s' over '%s' should result into a '200' res code: (curl_err: '%d', curl_res_code: '%ld')",
							req.ept_info.method.c_str(), ept.c_str(), curl_err, curl_res_code
						);
					}

					if (curl_err == 7) {
						diag("Operation over endpoint %s failed with 'CURLE_COULDNT_CONNECT'. Aborting...", ept.c_str());
						rc = 1;
						break;
					}
					api_request_count++;
				}
				if (rc) break;
			}

			end = hrc::now();
			duration = end - start;

			if (duration.count() >= test_duration*1000*1000 || rc) {
				break;
			}
		}

		diag("Joining churn thread and cleaning up...");
		create_conns.join();
		diag("Churn thread finished. Total API requests: %d, Total churn conns: %ld, Failures: %ld", api_request_count, conn_count, mysql_fails);

		ok(
			conn_creation_res == EXIT_SUCCESS,
			"MySQL conns operations shouldn't had more than a '%d'%% failure rate - conn_count: %ld, failures: %ld",
			FAILURE_RATE, conn_count, mysql_fails
		);
	}
skip_endpoints_testing:

	for (MYSQL* conn : mysql_connections) {
		mysql_close(conn);
	}

	mysql_close(admin);

	curl_global_cleanup();

	return exit_status();
}
