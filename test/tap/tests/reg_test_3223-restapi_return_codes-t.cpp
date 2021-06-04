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
 * @param curl_out_err A string reference to collect the error as a string reported
 *   by 'libcurl' in case of failure.
 *
 * @return The response code of the query in case of the query.
 */
long perform_simple_post(const string& endpoint, const string& post_params, string& curl_out_err) {
	CURL *curl;
	CURLcode res;
	long response_code;

	curl_global_init(CURL_GLOBAL_ALL);

	curl = curl_easy_init();
	if(curl) {
		diag("endpoint: %s", endpoint.c_str());

		curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_params.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &my_dummy_write);

		res = curl_easy_perform(curl);

		if(res != CURLE_OK) {
			curl_out_err = std::string { curl_easy_strerror(res) };
		} else {
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		}

		curl_easy_cleanup(curl);
	}

	return response_code;
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

	// Congigure routes for valid scripts
	MYSQL_QUERY(
		proxysql_admin,
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,5000,'POST','large_output_script','../test/tap/tests/reg_test_3223_scripts/large_output_script.py','comm')"
	);
	MYSQL_QUERY(
		proxysql_admin,
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,5000,'POST','partial_output_flush_script','../test/tap/tests/reg_test_3223_scripts/partial_output_flush_script.py','comm')"
	);
	MYSQL_QUERY(
		proxysql_admin,
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,1000,'POST','valid_output_script','../test/tap/tests/reg_test_3223_scripts/valid_output_script.py','comm')"
	);

	// NOTE: Disable due to requiring python2 annotation in file
	// MYSQL_QUERY(
	// 	proxysql_admin,
	// 	"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
	// 	"VALUES (1,1000,'POST','metrics','../scripts/metrics.py','comm')"
	// );

	// Congigure routes for invalid scripts
	MYSQL_QUERY(
		proxysql_admin,
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,1000,'POST','invalid_output_script','../test/tap/tests/reg_test_3223_scripts/invalid_output_script.py','comm')"
	);
	MYSQL_QUERY(
		proxysql_admin,
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,1000,'POST','timeout_script','../test/tap/tests/reg_test_3223_scripts/timeout_script.py','comm')"
	);
	MYSQL_QUERY(
		proxysql_admin,
		"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,1000,'POST','invalid_script','../test/tap/tests/reg_test_3223_scripts/invalid_script.py','comm')"
	);

	MYSQL_QUERY(proxysql_admin, "LOAD restapi TO RUNTIME");

	for (const auto& valid_request_tuple : valid_endpoints) {
		const std::string full_endpoint { base_address + std::get<0>(valid_request_tuple) + "/"};
		std::string post_out_err { "" };

		// perform the POST operation
		int post_err = perform_simple_post(full_endpoint, std::get<1>(valid_request_tuple), post_out_err);

		ok(
			post_err == 200,
			"Performing a POST over endpoint '%s' should result into a 200 response: (errcode: '%d', curlerr: '%s' )",
			full_endpoint.c_str(),
			post_err,
			post_out_err.c_str()
		);
	}

	for (const auto& invalid_request_tuple : invalid_requests) {
		const std::string full_endpoint { base_address + std::get<0>(invalid_request_tuple) + "/" };
		std::string post_out_err { "" };

		// perform the POST operation
		int post_err = perform_simple_post(full_endpoint, std::get<1>(invalid_request_tuple), post_out_err);

		ok(
			post_err == std::get<2>(invalid_request_tuple),
			"Performing a POST over endpoint '%s' shouldn't result into a 200 response: (errcode: '%d', curlerr: '%s' )",
			full_endpoint.c_str(),
			post_err,
			post_out_err.c_str()
		);
	}

	return exit_status();
}
