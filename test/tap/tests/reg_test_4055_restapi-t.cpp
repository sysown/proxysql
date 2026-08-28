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
#include <netdb.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

/* This is an estimation of the supported number of metrics as for '2022-12-15' */
uint32_t SUPPORTED_METRICS = 148;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	diag("=== Regression Test #4055: RESTAPI Robustness against Malformed Input ===");
	diag("This test verifies that ProxySQL remains stable and operational when");
	diag("receiving a malformed request on its RESTAPI interface.");
	diag("The test strategy is:");
	diag("1. Enable RESTAPI on port 6070.");
	diag("2. Send a malformed byte sequence directly to the RESTAPI socket.");
	diag("3. Verify that ProxySQL Admin interface is still responsive.");
	diag("4. Verify that the RESTAPI 'metrics' endpoint is still responding correctly.");
	diag("==========================================================================");

	plan(5);

	MYSQL* admin = mysql_init(NULL);

	diag("Connecting to ProxySQL Admin at %s:%d as %s", cl.host, cl.admin_port, cl.admin_username);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Enable 'RESTAPI'
	diag("Enabling RESTAPI on port 6070");
	MYSQL_QUERY(admin, "SET admin-restapi_enabled='true'");
	MYSQL_QUERY(admin, "SET admin-restapi_port=6070");
	MYSQL_QUERY(admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	int socket_desc;
	struct sockaddr_in server;

	diag("Creating socket to send malformed data to %s:6070", cl.host);
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1) {
		diag("Failed to create socket: %s", strerror(errno));
		return errno;
	}

	struct addrinfo hints{}, *res;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	int status = getaddrinfo(cl.host, "6070", &hints, &res);
	if (status != 0) {
		diag("Failed to resolve host %s: %s", cl.host, gai_strerror(status));
		close(socket_desc);
		return EXIT_FAILURE;
	}

	if (connect(socket_desc , res->ai_addr , res->ai_addrlen) < 0) {
		diag("Failed to connect to RESTAPI socket at %s:6070: %s", cl.host, strerror(errno));
		freeaddrinfo(res);
		close(socket_desc);
		return errno;
	}
	freeaddrinfo(res);

	// Perform the invalid request, and add a sleep to let ProxySQL process the data
	{
		diag("Sending malformed byte sequence to RESTAPI...");
		ssize_t n = write(socket_desc, static_cast<const void*>(" \n"), strlen(" \n"));
		diag("Written '%lu' bytes into socket", n);
		sleep(1);
	}

	diag("Verifying ProxySQL Admin responsiveness...");
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

	diag("Verifying RESTAPI /metrics endpoint responsiveness via %s:6070...", cl.host);
	const string metrics_url { string("http://") + string(cl.host) + ":6070/metrics/" };
	CURLcode code = perform_simple_get(metrics_url, curl_res_code, curl_res_data);

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
