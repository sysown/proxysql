/**
 * @file test_qps_limit_rules-t.cpp
 * @brief This test verifies the implementation of 'qps_limit_rules'.
 * @details The following checks are performed:
 *   - Test 1: Open several connections to ProxySQL using the same user, perform multiple queries per
 *     connections checking that:
 *       1. The rate is stable and matches the target value. WIP
 *       2. It's evenly distributed between connections. WIP
 *   - Test 2: WIP
 *   - Test 3: WIP
 */

#include <chrono>
#include <cstring>
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <stdio.h>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "proxysql_utils.h"
#include "command_line.h"
#include "utils.h"

using std::string;

using hrc = std::chrono::high_resolution_clock;

int main(int argc, char** argv) {
	CommandLine cl;

	plan(1);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	const string t_qps_limit_rule {
		"INSERT INTO mysql_qps_limit_rules (username, schemaname, flagIN, qps_limit, bucket_size)"
		" VALUES ('%s', '%s', %d, %d, %d)"
	};

	MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_qps_limit_rules");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	// Test 1
	{
		const string TEST_USER { "sbtest1" };
		const string TEST_PASS { "sbtest1" };

		const uint64_t qps_limit = 100;
		const uint64_t burst_size = 100;
		const uint64_t qps_factor = 6;
		const double EPSILON = 0.1;

		// Setup 'qps_limit_rules'
		string user_limit_rule {};
		string_format(t_qps_limit_rule, user_limit_rule, TEST_USER.c_str(), "", 0, qps_limit, burst_size);
		MYSQL_QUERY(proxysql_admin, user_limit_rule.c_str());
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

		MYSQL* sbtest1_conn = mysql_init(NULL);
		if (!mysql_real_connect(sbtest1_conn, cl.host, TEST_USER.c_str(), TEST_PASS.c_str(), NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(sbtest1_conn));
			return EXIT_FAILURE;
		}

		// Check that queries takes the expected ammount of time to be exectued
		std::chrono::nanoseconds duration;
		hrc::time_point start = hrc::now();

		for (uint64_t i = 0; i < qps_limit*6; i++) {
			MYSQL_QUERY(sbtest1_conn, "/* hostgroup=0 */ SELECT 1");
			mysql_free_result(mysql_store_result(sbtest1_conn));
		}

		hrc::time_point end = hrc::now();
		duration = end - start;
		double s_duration = duration.count() / pow(10,9);

		ok(
			(s_duration > (qps_factor - 1) - EPSILON) && (s_duration < (qps_factor - 1) + EPSILON),
			"Waited time should match the QPS limit times factor minus one: { Exp: '%ld', Act: '%lf' }",
			qps_factor - 1, s_duration
		);

		mysql_close(sbtest1_conn);
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
