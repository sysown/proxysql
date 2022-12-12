/**
 * @file reg_test_3223-restapi_return_codes-t.cpp
 * @brief This test ensures that RESTAPI is able to execute scripts returning the proper error
 *   codes in case of success or failure.
 * @date 2021-03-10
 */

#include <algorithm>
#include <chrono>
#include <string>
#include <stdio.h>
#include <tuple>
#include <unistd.h>
#include <vector>

#include <signal.h>

#include "curl/curl.h"
#include "json.hpp"
#include "mysql.h"
#include "mysql/mysqld_error.h"

#include "command_line.h"
#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

using std::string;
using std::vector;

using hrc = std::chrono::high_resolution_clock;
using nlohmann::json;

const string base_address { "http://localhost:6070/sync/" };

const vector<honest_req_t> honest_requests {
	{ { "valid_output_script", "%s.py", "POST", 1000 }, { "{}" } },
	// Check that 'POST' correctly forwards supplied parameters:
	//  1 - Target script performs a check on the supplied parameters and fails in case they are unexpected
	{ { "valid_params_script", "%s.py", "POST", 1000 }, { "{\"param1\": \"value1\", \"param2\": \"value2\"}" } },
	// On top of the previous check, also check that 'GET' allows:
	//  1 - Empty parameters: We internally translate into an empty well-formed JSON '{}'
	//  2 - Escaped values: As long as the JSON is correct, the RESTAPI forwarding should be able to handle it
	{ { "valid_params_script", "%s.py", "GET", 1000 }, { "", "?param1='value1'&param2='\"value2\"'" } },
	// Checks that RESTAPI behaves correctly with scripts with big outputs
	{ { "large_output_script", "%s.py", "POST", 5000 }, { "{}" } },
	// Checks that RESTAPI is being able to properly read scripts with partial output flushes
	{ { "partial_output_flush_script", "%s.py", "POST", 10000 }, { "{}" } },
};

const vector<faulty_req_t> invalid_requests {
	// Checks that 'POST' fails for:
	//   1 - Empty parameters.
	//   2 - Invalid JSON input.
	//   3 - Valid JSON input but unexpected (checking script correctness itself).
	{
		{ "valid_params_script", "%s.py", "POST", 1000 },
		{
			// Empty parameters is considered and invalid JSON input for a POST request:
			//   - '400' error, 'Invalid Request'.
			//   - Error code of '0', script was never executed.
			{ "", 400, 0 },
			// Invalid JSON input should result in:
			//   - '400' error, 'Invalid Request'.
			//   - Error code of '0', script was never executed.
			{ "\"param1\": \"value1\", \"param2\": \"value2}", 400, 0 },
			// Valid JSON input, that fails script check:
			//   - '424' error, script was the one failing during execution.
			//   - Error code of '1'. Script exit code for failed input validation.
			{ "{\"foo\": \"bar\"}", 424, 1 },
		}
	},
	// Check invalid output (non valid JSON) for 'POST' and 'GET'
	{ { "invalid_output_script", "%s.py", "POST", 1000 }, { { "{}",  424, 0 } } },
	{ { "invalid_output_script", "%s.py", "GET", 1000 }, { { "",  424, 0 } } },
	// Check timeout script for 'POST' and 'GET'
	{ { "timeout_script", "%s.py", "POST", 1000 }, { { "{}", 424, ETIME } } },
	{ { "timeout_script", "%s.py", "GET", 1000 }, { { "", 424, ETIME } } },
	// Check error code from script failing to execute (Python exit code)
	{ { "invalid_script", "%s.py", "POST", 1000 }, { { "{}", 424, 1 } } },
	// Check non being able to execute the target script - Invalid Path
	{ { "non_existing_script", "%s", "POST", 1000 }, { { "{}", 424, ENOENT } } },
	// Check non being able to execute the target script - Insufficient perms
	{ { "script_no_permissions", "%s", "POST", 1000 }, { { "{}", 424, EACCES } } },
	// Check error code from script killed by signal
	{ { "bash_sigsev_script", "%s.bash", "POST", 1000 }, { { "{}", 424, 128 + SIGSEGV } } },
	// Check killing of script that closes communication pipes with ProxySQL
	{ { "close_stdout_script", "%s.py", "POST", 1000 }, { { "{}", 424, ETIME } } },
};

int count_exp_tests(const vector<honest_req_t>& v1, const vector<faulty_req_t>& v2) {
	int exp_tests = 0;

	for (const honest_req_t& req : v1) {
		exp_tests += req.params.size() * 3;
	}

	for (const faulty_req_t& req : v2) {
		for (const ept_pl_t& ept_pl : req.ept_pls) {
			if (ept_pl.script_err != ETIME) {
				exp_tests += 4;
			} else {
				exp_tests += 5;
			}
		}
	}

	return exp_tests;
}

/**
 * @details
 *  ProxySQL could give a total grace period of '4' seconds to a finishing script before issuing a SIGKILL.
 *  This scenario takes place when something goes wrong during the script execution in ProxySQL side, or when
 *  the script closes the communication PIPES without finishing.
 *    - Initial wait of 1s second after communication is broken waiting for script to gracefully finish.
 *    - A maximum 3s of waiting time after SIGTERM before issuing SIGKILL.
 */
const uint32_t PROXY_GRACE_PERIOD = 1000 + 3000;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(count_exp_tests(honest_requests, invalid_requests));

	MYSQL* admin = mysql_init(NULL);

	// Initialize connections
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Enable 'RESTAPI'
	MYSQL_QUERY(admin, "SET admin-restapi_enabled='true'");
	MYSQL_QUERY(admin, "SET admin-restapi_port=6070");

	MYSQL_QUERY(admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	// Clean current 'restapi_routes' if any
	MYSQL_QUERY(admin, "DELETE FROM restapi_routes");

	// Configure restapi_routes to be used
	string script_base_path { string { cl.workdir  } + "reg_test_3223_scripts" };
	const ept_info_t dummy_ept { "dummy_ept_script", "%s.py", "POST", 1000 };

	// Configure the valid requests
	vector<ept_info_t> v_epts_info {};
	const auto ext_v_epts_info = [] (const honest_req_t& req) { return req.ept_info; };
	std::transform(
		honest_requests.begin(), honest_requests.end(), std::back_inserter(v_epts_info), ext_v_epts_info
	);

	int ept_conf_res = configure_endpoints(admin, script_base_path, v_epts_info, dummy_ept, true);
	if (ept_conf_res) {
		diag("Endpoint configuration failed. Skipping endpoint testing...");
		return EXIT_FAILURE;
	}

	{
		for (const auto& req : honest_requests) {
			for (const string& params : req.params) {
				const string ept { join_path(base_address, req.ept_info.name) };
				diag(
					"%s: Checking valid '%s' request - ept: '%s', params: '%s'", tap_curtime().c_str(),
					req.ept_info.method.c_str(), ept.c_str(), params.c_str()
				);
				std::chrono::nanoseconds duration;
				hrc::time_point start;
				hrc::time_point end;

				string curl_res_data { "" };
				uint64_t curl_res_code = 0;

				CURLcode post_err = CURLE_AGAIN;

				if (req.ept_info.method == "POST") {
					start = hrc::now();
					post_err = perform_simple_post(ept, params, curl_res_code, curl_res_data);
					end = hrc::now();

					duration = end - start;
					double duration_ms = duration.count() / static_cast<double>(1000*1000);

					ok(
						duration_ms < (req.ept_info.timeout + PROXY_GRACE_PERIOD),
						"Request duration should always be smaller than (timeout + grace period) -"
							" timeout: '%ld', duration_ms: '%lf', grace_period: '%d'",
						req.ept_info.timeout, duration_ms, PROXY_GRACE_PERIOD
					);

					bool json_parse_failure = false;

					try {
						json _ = json::parse(curl_res_data);
					} catch (std::exception& e) {
						diag("Failed to parse response JSON - '%s'", e.what());
						json_parse_failure = true;
					}

					const char* out_res_data = "'skipped_due_to_size'";

					if (curl_res_data.length() > 50) {
						diag("Omit print of 'curl_res_data' due to big size '%ld'", curl_res_data.length());
					} else {
						out_res_data = curl_res_data.c_str();
					}

					ok(
						json_parse_failure == false,
						"Valid JSON received for VALID '%s' request - params: '%s', curl_err_resp: '%s'",
						req.ept_info.method.c_str(), params.c_str(), out_res_data
					);

					ok(
						post_err == CURLE_OK && curl_res_code == 200,
						"'%s' over '%s' should result into a '200' res code:"
						" (curl_err: '%d', curl_res_code: '%ld', curl_res_data: '%s')",
						req.ept_info.method.c_str(), ept.c_str(), post_err, curl_res_code, out_res_data
					);
				} else {
					const string get_ept { ept + params };
					start = hrc::now();
					post_err = perform_simple_get(get_ept, curl_res_code, curl_res_data);
					end = hrc::now();
					bool json_parse_failure = false;

					duration = end - start;
					double duration_ms = duration.count() / static_cast<double>(1000*1000);

					ok(
						duration_ms < (req.ept_info.timeout + PROXY_GRACE_PERIOD),
						"Request duration should always be smaller than (timeout + grace period) -"
							" timeout: '%ld', duration_ms: '%lf', grace_period: '%d'",
						req.ept_info.timeout, duration_ms, PROXY_GRACE_PERIOD
					);

					try {
						json _ = json::parse(curl_res_data);
					} catch (std::exception& e) {
						diag("Failed to parse response JSON - '%s'", e.what());
						json_parse_failure = true;
					}

					const char* out_res_data = "'skipped_due_to_size'";

					if (curl_res_data.length() > 50) {
						diag("Omit print of 'curl_res_data' due to big size '%ld'", curl_res_data.length());
					} else {
						out_res_data = curl_res_data.c_str();
					}

					ok(
						json_parse_failure == false,
						"Valid JSON received for VALID '%s' request - params: '%s', curl_err_resp: '%s'",
						req.ept_info.method.c_str(), params.c_str(), out_res_data
					);

					ok(
						post_err == CURLE_OK && curl_res_code == 200,
						"'%s' over '%s' should result into a '200' res code:"
							" (curl_err: '%d', curl_res_code: '%ld', curl_res_data: '%s')",
						req.ept_info.method.c_str(), ept.c_str(), post_err, curl_res_code, out_res_data
					);
				}
			}
		}
	}

	vector<ept_info_t> i_epts_info {};
	const auto ext_i_epts_info = [] (const faulty_req_t& req) { return req.ept_info; };
	std::transform(
		invalid_requests.begin(), invalid_requests.end(), std::back_inserter(i_epts_info), ext_i_epts_info
	);

	ept_conf_res = configure_endpoints(admin, script_base_path, i_epts_info, dummy_ept, true);
	if (ept_conf_res) {
		diag("Endpoint configuration failed. Skipping endpoint testing...");
		return EXIT_FAILURE;
	}

	for (const auto& req : invalid_requests) {
		for (const ept_pl_t& ept_pl : req.ept_pls) {
			std::chrono::nanoseconds duration;
			hrc::time_point start;
			hrc::time_point end;

			const string ept { join_path(base_address, req.ept_info.name) };
			diag(
				"%s: Checking valid '%s' request - ept: '%s', params: '%s'", tap_curtime().c_str(),
				req.ept_info.method.c_str(), ept.c_str(), ept_pl.params.c_str()
			);

			// Get the target script full path
			string f_exe_name {};
			string_format(req.ept_info.file, f_exe_name, req.ept_info.name.c_str());
			const string script_path { join_path(script_base_path, f_exe_name) };
			const string sigterm_file_flag { script_path + "-RECV_SIGTERM" };

			string curl_res_data {};
			uint64_t curl_res_code = 0;

			// Prepare target folder in case of expected ETIME error
			if (ept_pl.script_err == ETIME) {
				remove(sigterm_file_flag.c_str());
			}

			// Perform the POST operation
			CURLcode curl_code = CURLE_AGAIN;

			start = hrc::now();
			if (req.ept_info.method == "POST") {
				curl_code = perform_simple_post(ept, ept_pl.params, curl_res_code, curl_res_data);
			} else {
				const string get_ept { ept + ept_pl.params };
				curl_code = perform_simple_get(get_ept, curl_res_code, curl_res_data);
			}
			end = hrc::now();

			duration = end - start;
			double duration_ms = duration.count() / static_cast<double>(1000*1000);

			ok(
				duration_ms < (req.ept_info.timeout + PROXY_GRACE_PERIOD),
				"Request duration should always be smaller than (timeout + grace period) -"
					" timeout: '%ld', duration_ms: '%lf', grace_period: '%d'",
				req.ept_info.timeout, duration_ms, PROXY_GRACE_PERIOD
			);

			uint64_t script_err = 0;
			string str_resp_err {};

			try {
				json curl_err_rsp = json::parse(curl_res_data);
				str_resp_err = curl_err_rsp["error"];
				script_err = std::stoi(curl_err_rsp["error_code"].get<string>());
			} catch (std::exception&) {}

			ok(
				str_resp_err.empty() == false,
				"Valid JSON received for INVALID request - params: '%s', curl_res_data: '%s'",
				ept_pl.params.c_str(), curl_res_data.c_str()
			);

			ok(
				curl_code == CURLE_OK && ept_pl.curl_rc == curl_res_code,
				"'%s' sould have failed: (curl_err: '%d', exp_rc: '%ld', act_rc: '%ld')",
				req.ept_info.method.c_str(), curl_code, ept_pl.curl_rc, curl_res_code
			);

			ok(
				ept_pl.script_err == script_err,
				"Script error code should match expected - Exp: '%ld', Act: '%ld'",
				ept_pl.script_err, script_err
			);

			// A SIGTERM signal should have been issued before SIGKILL; script should acknowledge it
			if (ept_pl.script_err == ETIME) {
				int f_exists = access(sigterm_file_flag.c_str(), F_OK);
				ok(f_exists == 0, "Script '%s' should receive a 'SIGTERM' signal", f_exe_name.c_str());
			}
		}
	}

skip_endpoints_testing:
	mysql_close(admin);

	return exit_status();
}
