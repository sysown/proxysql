/**
 * @file test_mysql_connect_retries_delay-t.cpp
 * @brief This test verifies the behavior for 'mysql-connect_retries_delay'.
 * @details For doing this check, the test performs the following actions:
 *   1. Disable monitoring and configure ProxySQL with a non-existing server in it's own hostgroup.
 *   2. Configure 'mysql-connect_retries_delay'.
 *   3. Create a connection against ProxySQL and issue a query against the non-existing server.
 *   4. Check that the execution time of the query till the error matches 'mysql-connect_retries_delay'.
 *   5. Repeat the previous 3 points for several values.
 */

#include <algorithm>
#include <chrono>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "proxysql_utils.h"

using std::string;
using std::vector;

typedef std::chrono::high_resolution_clock hrc;

const vector<uint32_t> test_retry_delays { 1000, 2000, 3000 };
const double DUR_EPSILON = 1;

int main() {
	CommandLine cl;

	plan(test_retry_delays.size());

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxysql_admin = mysql_init(NULL);
	MYSQL* proxysql = mysql_init(NULL);

	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return EXIT_FAILURE;
	}

	// Global config
	MYSQL_QUERY(proxysql_admin, "SET mysql-monitor_enabled=0");
	MYSQL_QUERY(proxysql_admin, "SET mysql-poll_timeout=100");
	MYSQL_QUERY(proxysql_admin, "SET mysql-connect_retries_on_failure=3");
	MYSQL_QUERY(proxysql_admin, "SET mysql-connect_timeout_server_max=20000");

	// Cleanup servers and configure just a non-existing server
	MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_servers");
	MYSQL_QUERY(proxysql_admin, "INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (10,'127.0.0.1',13330,180,500,'mysql_not_here')");

	// Load the new config
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	for (uint32_t retry_delay : test_retry_delays) {
		string connect_retries_query {};
		string_format("SET mysql-connect_retries_delay=%d", connect_retries_query, retry_delay);

		// Load the new connect retry config
		MYSQL_QUERY(proxysql_admin, connect_retries_query.c_str());
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		// Issue a query and check the timing
		std::chrono::nanoseconds dur;
		hrc::time_point start;
		hrc::time_point end;

		start = hrc::now();

		{
			mysql_query(proxysql, "DO /* hostgroup=10 */ 1");
		}

		end = hrc::now();
		dur = end - start;

		double dur_s = dur.count() / pow(10,9);
		double exp_dur = retry_delay * 3 / 1000.0;

		ok(
			dur_s > (exp_dur - DUR_EPSILON) && dur_s < (exp_dur + DUR_EPSILON),
			"Test duration matches the expected duration: { act_dur: %lf, exp_dur: %lf }", dur_s, exp_dur
		);
	}

	mysql_close(proxysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
