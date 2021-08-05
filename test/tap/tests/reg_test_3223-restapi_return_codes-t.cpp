/**
 * @file reg_test_3223-restapi_return_codes-t.cpp
 * @brief This test ensures that RESTAPI is able to execute scripts returning the proper error
 *   codes in case of success or failure.
 * @date 2021-03-10
 */

#include <algorithm>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>

#include <curl/curl.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;


/**
 * @brief Dummy write function to avoid CURL to write received output to stdout.
 * @return Returns the size presented.
 */
size_t my_dummy_write(char*, size_t size, size_t nmemb, void*) {
	return size * nmemb;
}

/**
 * @brief Perform a simple POST query to the specified endpoint using the supplied
 *  'post_params'.
 *
 * @param endpoint The endpoint to be exercised by the POST.
 * @param post_params The post parameters to be supplied to the script.
 * @param curl_out_err A uint64_t reference returning the result code of the
 *   query in case it has been performed. In case the query couldn't be
 *   performed, this value is never initialized.
 * @param curl_out_err A string reference to collect the error as a string reported
 *   by 'libcurl' in case of failure.
 *
 * @return The response code of the query in case of the query.
 */
CURLcode perform_simple_post(
	const string& endpoint, const string& post_params, uint64_t& curl_res_code,
	string& curl_out_err
) {
	CURL *curl;
	CURLcode res;

	curl_global_init(CURL_GLOBAL_ALL);

	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_params.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &my_dummy_write);

		res = curl_easy_perform(curl);

		if(res != CURLE_OK) {
			curl_out_err = std::string { curl_easy_strerror(res) };
		} else {
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curl_res_code);
		}

		curl_easy_cleanup(curl);
	}

	return res;
}

const std::string base_address { "http://localhost:6070/sync/" };

std::vector<std::tuple<std::string, std::string, long>> valid_endpoints {
	std::make_tuple( "large_output_script", "{}", 200 ),
	std::make_tuple( "partial_output_flush_script", "{}", 200 ),
	std::make_tuple( "valid_output_script", "{}", 200 ),
	// check scripts remain operational
	// NOTE: Disable due to requiring python2 annotation in file
	// std::make_tuple( "metrics", "{\"user\":\"admin\", \"password\":\"admin\", \"host\":\"127.0.0.1\", \"port\":\"6032\"}", 200 )
};

std::vector<std::tuple<std::string, std::string, long>> invalid_requests {
	std::make_tuple( "invalid_output_script", "{}", 424 ),
	std::make_tuple( "timeout_script", "{}", 424 ),
	std::make_tuple( "invalid_script", "{}", 424 ),
	std::make_tuple( "non_existing_script", "{}", 400 ),
	// supplied with invalid params
	std::make_tuple( "valid_output_script", "", 400 )
};

/**
 * @brief Waits until the provided endpoint is ready to be used or the
 *   timeout period expired. For this checks the return code of
 *   'perform_simple_post' which only fails in case the 'CURL' request couldn't
 *   be performed, which is interpreted as endpoint not being yet ready.
 *
 * @param endpoint The endpoint to be queried.
 * @param post_params The required params to be supplied for the 'POST' endpoint
 *   call.
 * @param timeout The max time to wait before declaring a timeout, and
 *   returning '-1'.
 * @param delay The delay specified in 'ms' to be waited between retries.
 *
 * @return '0' in case the endpoint became available before the timeout, or
 *   '-1' in case the timeout expired.
 */
int wait_until_enpoint_ready(
	std::string endpoint, std::string post_params, uint32_t timeout, uint32_t delay=100
) {
	double waited = 0;
	int res = -1;

	while (waited < timeout) {
		std::string curl_str_err {};
		uint64_t curl_res_code = 0;
		int curl_err = perform_simple_post(endpoint, post_params, curl_res_code, curl_str_err);

		if (curl_err != CURLE_OK) {
			diag(
				"'curl_err_code': %d, 'curl_err': '%s', waiting for '%d'ms...",
				curl_err, curl_str_err.c_str(), delay
			);
			waited += static_cast<double>(delay) / 1000;
			usleep(delay * 1000);
		} else {
			res = 0;
			break;
		}
	}

	return res;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(valid_endpoints.size() + invalid_requests.size());

	MYSQL* proxysql_admin = mysql_init(NULL);

	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Enable 'RESTAPI'
	MYSQL_QUERY(proxysql_admin, "SET admin-restapi_enabled='true'");
	MYSQL_QUERY(proxysql_admin, "SET admin-restapi_port=6070");

	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	// Clean current 'restapi_routes' if any
	MYSQL_QUERY(proxysql_admin, "DELETE FROM restapi_routes");

	// Configure restapi_routes to be used
	std::string test_script_base_path {
		std::string { cl.workdir  } + "reg_test_3223_scripts"
	};

	std::vector<std::string> t_valid_scripts_inserts {
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,5000,'POST','large_output_script','%s/large_output_script.py','comm')",
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,5000,'POST','partial_output_flush_script','%s/partial_output_flush_script.py','comm')",
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,1000,'POST','valid_output_script','%s/valid_output_script.py','comm')"
	};
	std::vector<std::string> valid_scripts_inserts {};

	for (const auto& t_valid_script_insert : t_valid_scripts_inserts) {
		std::string valid_script_insert {};
		string_format(t_valid_script_insert, valid_script_insert, test_script_base_path.c_str());
		valid_scripts_inserts.push_back(valid_script_insert);
	}

	// Configure routes for valid scripts
	for (const auto& valid_script_insert : valid_scripts_inserts) {
		MYSQL_QUERY(
			proxysql_admin,
			valid_script_insert.c_str()
		);
	}

	// NOTE: Disable due to requiring python2 annotation in file
	// MYSQL_QUERY(
	// 	proxysql_admin,
	// 	"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
	// 	"VALUES (1,1000,'POST','metrics','../scripts/metrics.py','comm')"
	// );

	std::vector<std::string> t_invalid_scripts_inserts {
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,1000,'POST','invalid_output_script','%s/invalid_output_script.py','comm')",
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,1000,'POST','timeout_script','%s/timeout_script.py','comm')",
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,1000,'POST','invalid_script','%s/invalid_script.py','comm')"
	};
	std::vector<std::string> invalid_scripts_inserts {};
	
	for (const auto& t_invalid_script_insert : t_invalid_scripts_inserts) {
		std::string invalid_script_insert {};
		string_format(t_invalid_script_insert, invalid_script_insert, test_script_base_path.c_str());
		invalid_scripts_inserts.push_back(invalid_script_insert);
	}

	// Configure routes for invalid scripts
	for (const auto& invalid_script_insert : invalid_scripts_inserts) {
		MYSQL_QUERY(
			proxysql_admin,
			invalid_script_insert.c_str()
		);
	}

	MYSQL_QUERY(proxysql_admin, "LOAD restapi TO RUNTIME");

	// Sensible wait until the new configured enpoints are ready.
	// Use the first enpoint for the check
	const auto& first_request_tuple { valid_endpoints.front() };
	const std::string full_endpoint {
		base_address + std::get<0>(first_request_tuple) + "/"
	};
	int endpoint_timeout = wait_until_enpoint_ready(
		full_endpoint, std::get<1>(first_request_tuple), 10, 500
	);

	if (endpoint_timeout) {
		diag(
			"Timeout while trying to reach first valid enpoint."
			" Test failed, skipping endpoint testing..."
		);
		goto skip_endpoints_testing;
	}

	for (const auto& valid_request_tuple : valid_endpoints) {
		const std::string full_endpoint { base_address + std::get<0>(valid_request_tuple) + "/"};
		std::string post_out_err { "" };
		uint64_t curl_res_code = 0;

		// perform the POST operation
		CURLcode post_err = perform_simple_post(
			full_endpoint, std::get<1>(valid_request_tuple), curl_res_code, post_out_err
		);

		ok(
			post_err == CURLE_OK && curl_res_code == 200,
			"Performing a POST over endpoint '%s' should result into a 200 response:"
			" (curl_err: '%d', response_errcode: '%ld', curlerr: '%s')",
			full_endpoint.c_str(),
			post_err,
			curl_res_code,
			post_out_err.c_str()
		);
	}

	for (const auto& invalid_request_tuple : invalid_requests) {
		const std::string full_endpoint { base_address + std::get<0>(invalid_request_tuple) + "/" };
		std::string post_out_err { "" };
		uint64_t curl_res_code = 0;

		// perform the POST operation
		CURLcode post_err = perform_simple_post(
			full_endpoint, std::get<1>(invalid_request_tuple), curl_res_code, post_out_err);

		ok(
			post_err == CURLE_OK && curl_res_code == std::get<2>(invalid_request_tuple),
			"Performing a POST over endpoint '%s' shouldn't result into a 200 response:"
			" (curl_err: '%d', response_errcode: '%ld', curlerr: '%s')",
			full_endpoint.c_str(),
			post_err,
			curl_res_code,
			post_out_err.c_str()
		);
	}

skip_endpoints_testing:

	return exit_status();
}
