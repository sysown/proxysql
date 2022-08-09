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

#include <mysql.h>

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
	struct rlimit limits { 0, 0 };
	getrlimit(RLIMIT_NOFILE, &limits);
	diag("Old process limits: { %ld, %ld }", limits.rlim_cur, limits.rlim_max);
	limits.rlim_cur = NUM_CONNECTIONS * 2;
	setrlimit(RLIMIT_NOFILE, &limits);
	diag("New process limits: { %ld, %ld }", limits.rlim_cur, limits.rlim_max);

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

	std::vector<MYSQL*> mysql_connections {};

	for (int i = 0; i < NUM_CONNECTIONS; i++) {
		MYSQL* proxysql_mysql = mysql_init(NULL);
		if (
			!mysql_real_connect(
				proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0
			)
		) {
			fprintf(
				stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
				mysql_error(proxysql_mysql)
			);
			return EXIT_FAILURE;
		}
		mysql_connections.push_back(proxysql_mysql);
	}

	int endpoint_timeout = wait_until_enpoint_ready("http://localhost:6070/metrics/", "{}", 10, 500);
	ok(endpoint_timeout == 0, "The endpoint should be available instead of timing out.");

	for (int i = 0; i < NUM_CONNECTIONS; i++) {
		mysql_close(mysql_connections[i]);
	}

	return exit_status();
}
