/**
 * @file reg_test_4055_restapi-t.cpp
 * @brief Simple regression test sending malformed query to RESTAPI.
 * @details This test performs the following actions:
 *   - Issue a malformed request to the RESTAPI.
 *   - Checks that Admin interface is still responsive.
 *   - Checks that the 'metrics' endpoint from the RESTAPI is still responsive.
 *   - Perform minor correctness check on the 'metrics' endpoint response.
 * @date 2022-12-15
 */

#include <cstring>
#include <unistd.h>
#include <vector>
#include <string>
#include <stdio.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

/* This is an estimation of the supported number of metrics as for '2022-12-15' */
uint32_t SUPPORTED_METRICS = 148;

int main(int argc, char** argv) {
	plan(5);

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Enable 'RESTAPI'
	MYSQL_QUERY(admin, "SET admin-restapi_enabled='true'");
	MYSQL_QUERY(admin, "SET admin-restapi_port=6070");
	MYSQL_QUERY(admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	int socket_desc;
	struct sockaddr_in server;

	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1) {
		return errno;
	}

	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(6070);

	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0) {
		return errno;
	}

	// Perform the invalid request, and add a sleep to let ProxySQL process the data
	{
		ssize_t n = write(socket_desc, static_cast<const void*>(" \n"), strlen(" \n"));
		diag("Written '%lu' bytes into socket", n);
		sleep(1);
	}

	int myrc = mysql_query(admin, "SELECT version()");
	ok(myrc == EXIT_SUCCESS, "ProxySQL is still up and reachable");

	MYSQL_RES* myres = mysql_store_result(admin);
	MYSQL_ROW myrow = mysql_fetch_row(myres);

	string recv_version {};
	if (myrow && myrow[0]) { recv_version = myrow[0]; }
	mysql_free_result(myres);

	ok(recv_version.empty() == false, "Received non empty ProxySQL version '%s'", recv_version.c_str());

	uint64_t curl_res_code = 0;
	string curl_res_data {};

	CURLcode code = perform_simple_get("http://localhost:6070/metrics/", curl_res_code, curl_res_data);

	ok(
		code == CURLE_OK && curl_res_code == 200,
		"RESTAPI still up and responding to requests - curl_code: %d, res_code: %lu",
		code, curl_res_code
	);

	size_t matches = count_matches(curl_res_data, "# ");
	const uint32_t min_exp_metrics = SUPPORTED_METRICS - 20;

	ok(
		matches % 2 == 0,
		"Response from endpoint is well-formed (even number of '# ' metrics descriptions) - matches: '%ld'",
		matches
	);

	ok(
		min_exp_metrics < (matches / 2),
		"Response contains more than a minimum of expected metrics - min: %d, act: %lu",
		min_exp_metrics, matches / 2
	);

	if (tests_failed()) {
		diag("Failed! Received GET response: \n\n%s", curl_res_data.c_str());
	}

	close(socket_desc);
	mysql_close(admin);

	return exit_status();
}
