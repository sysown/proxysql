#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <random>

#include <unistd.h>

#include <string>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	/*
	 * 1. Read and command line parameters
	 */

	// Define comman line parser
	CommandLine cl;

	// Initialize tests parameters from environment variables
	// Test parameters are similar to the mysql command line parameters but
	// additionally they include admin interface username/password, host and port,
	// working directory for test files.
	if(cl.getEnv())
		return exit_status();

	/*
	 * Prepare TAP framework to run tests
	 */

	// Initialize TAP with planned number of checks and print the name of the test
	plan(6);
	diag("Testing query rules fast routing");

	/*
	 * Initialize connections to the servers and prepare data for test.
	 * Also initialize additional libraries.
	 */

	// Initialize connection to the proxysql admin interface
	MYSQL* mysqlAdmin = mysql_init(NULL);
	if (!mysqlAdmin) return exit_status();
	if (!mysql_real_connect(mysqlAdmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) return exit_status();

	// Initialize extra functionality that will be used durin the test
	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<> dis(100000, 1000000);

	/*
	 * Execute test performing required checks during execution
	 */

	const auto NUM_REPS=3;
	char query[1024] = {0};
	for (auto i=0; i<NUM_REPS; i++) {
		unsigned long long gen_rows = dis(gen);
		MYSQL_QUERY(mysqlAdmin, "DELETE FROM mysql_query_rules_fast_routing");
		snprintf(query, sizeof(query), "PROXYSQLTEST 11 %llu", gen_rows);
		MYSQL_QUERY(mysqlAdmin, query);
		auto affected_rows = mysql_affected_rows(mysqlAdmin);
		ok(gen_rows == affected_rows, "Number of affected rows expected [%llu], actual [%llu]", gen_rows, affected_rows);

		if (mysql_query(mysqlAdmin, "LOAD MYSQL QUERY RULES TO RUNTIME")) return exit_status();

		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 14 1");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 17 1");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 14 11");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 17 11");

		MYSQL_QUERY(mysqlAdmin, "DELETE FROM mysql_query_rules_fast_routing");
		gen_rows = dis(gen);
		snprintf(query, sizeof(query), "PROXYSQLTEST 15 %llu", gen_rows);
		MYSQL_QUERY(mysqlAdmin, query);
		affected_rows = mysql_affected_rows(mysqlAdmin);
		ok(gen_rows == affected_rows, "Number of affected rows expected [%llu], actual [%llu]", gen_rows, affected_rows);

		if (mysql_query(mysqlAdmin, "LOAD MYSQL QUERY RULES TO RUNTIME")) return exit_status();

		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 14 1");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 17 1");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 14 11");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 17 11");
	}


	/*
	 * Teardown test set up. Reload proxysql configuration.
	 */

	if (mysql_query(mysqlAdmin, "load mysql query rules from disk")) return exit_status();
	if (mysql_query(mysqlAdmin, "load mysql query rules to runtime")) return exit_status();

	mysql_close(mysqlAdmin);

	return exit_status();
}

