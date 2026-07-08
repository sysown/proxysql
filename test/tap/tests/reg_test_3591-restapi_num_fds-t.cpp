/**
 * @file reg_test_3591-restapi_num_fds-t.cpp
 * @brief This is a regression test for issue #3591. The test checks that
 *   ProxySQL metrics endpoint can be enabled and it's functional when
 *   '2047' connections are oppened against it.
 *
 * @details The tests creates a higher number of connections than the default
 *   maximum number of file descriptors determined by `FD_SETSIZE` (1024).
 *   After doing this, it tries to enable the 'RESTAPI' and checks that the
 *   endpoint is functional.
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

#include <sys/time.h>
#include <sys/resource.h>

using nlohmann::json;
using std::string;

const int NUM_CONNECTIONS = 2047;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	diag("=== Regression Test #3591: RESTAPI with High Number of FDs ===");
	diag("This test verifies that the ProxySQL metrics endpoint remains functional");
	diag("even when a large number of client connections (2047) are opened.");
	diag("The test strategy is:");
	diag("1. Elevate process FD limits.");
	diag("2. Enable RESTAPI on port 6070.");
	diag("3. Open 2047 concurrent MySQL connections to ProxySQL.");
	diag("4. Verify that the /metrics endpoint is still reachable.");
	diag("==============================================================");

	struct rlimit limits { 0, 0 };
	getrlimit(RLIMIT_NOFILE, &limits);
	diag("Old process limits: { %ld, %ld }", limits.rlim_cur, limits.rlim_max);
	limits.rlim_cur = NUM_CONNECTIONS * 2;
	setrlimit(RLIMIT_NOFILE, &limits);
	diag("New process limits: { %ld, %ld }", limits.rlim_cur, limits.rlim_max);

	MYSQL* admin = mysql_init(NULL);

	// Initialize connections
	diag("Connecting to ProxySQL Admin at %s:%d as %s", cl.host, cl.admin_port, cl.admin_username);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}

	// Enable 'RESTAPI'
	diag("Enabling RESTAPI on port 6070");
	MYSQL_QUERY(admin, "SET admin-restapi_enabled='true'");
	MYSQL_QUERY(admin, "SET admin-restapi_port=6070");
	MYSQL_QUERY(admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	std::vector<MYSQL*> mysql_connections {};

	diag("Establishing %d connections to ProxySQL...", NUM_CONNECTIONS);
	for (int i = 0; i < NUM_CONNECTIONS; i++) {
		MYSQL* proxy = mysql_init(NULL);
		if (
			!mysql_real_connect(
				proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0
			)
		) {
			fprintf(
				stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
				mysql_error(proxy)
			);
			return EXIT_FAILURE;
		}
		mysql_connections.push_back(proxy);
		if ((i + 1) % 500 == 0) diag("  Established %d/%d connections...", i + 1, NUM_CONNECTIONS);
	}
	diag("Connections established.");

	const string metrics_url { string("http://") + string(cl.host) + ":6070/metrics/" };
	diag("Verifying RESTAPI /metrics endpoint via %s...", metrics_url.c_str());
	int endpoint_timeout = wait_get_enpoint_ready(metrics_url, 1000, 100);
	ok(endpoint_timeout == 0, "The endpoint should be available instead of timing out.");

	diag("Closing connections and cleaning up...");
	for (int i = 0; i < NUM_CONNECTIONS; i++) {
		mysql_close(mysql_connections[i]);
	}

	mysql_close(admin);

	return exit_status();
}
