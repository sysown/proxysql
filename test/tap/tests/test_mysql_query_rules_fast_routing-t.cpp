#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <unistd.h>

#include <string>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

std::vector<int> params = { 100, 1234, 2356, 129645, 345123, 412317 };

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
	plan(params.size());
	diag("Testing query rules fast routing");

	/*
	 * Initialize connections to the servers and prepare data for test.
	 * Also initialize additional libraries.
	 */

	// Initialize connection to the proxysql admin interface
	MYSQL* mysqlAdmin = mysql_init(NULL);
	if (!mysqlAdmin) return exit_status();
	if (!mysql_real_connect(mysqlAdmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) return exit_status();

	/*
	 * Execute test performing required checks during execution
	 */

	char query[1024] = {0};
	std::string queryS = "";
	for (auto i=0; i<params.size(); i++) {
		unsigned long long gen_rows = params[i];
		MYSQL_QUERY(mysqlAdmin, "DELETE FROM mysql_query_rules_fast_routing");
		snprintf(query, sizeof(query), "PROXYSQLTEST %d %llu", (i%2 == 0 ? 11 : 15) , gen_rows);
		diag("Running query: %s", query);
		MYSQL_QUERY(mysqlAdmin, query);
		auto affected_rows = mysql_affected_rows(mysqlAdmin);
		ok(gen_rows == affected_rows, "Number of affected rows expected [%llu], actual [%llu]", gen_rows, affected_rows);

		if (mysql_query(mysqlAdmin, "LOAD MYSQL QUERY RULES TO RUNTIME")) return exit_status();

		queryS = "PROXYSQLTEST 14 1";  diag("Running query: %s", queryS.c_str()); MYSQL_QUERY(mysqlAdmin, queryS.c_str());
		queryS = "PROXYSQLTEST 17 1";  diag("Running query: %s", queryS.c_str()); MYSQL_QUERY(mysqlAdmin, queryS.c_str());
		queryS = "PROXYSQLTEST 14 11"; diag("Running query: %s", queryS.c_str()); MYSQL_QUERY(mysqlAdmin, queryS.c_str());
		queryS = "PROXYSQLTEST 17 11"; diag("Running query: %s", queryS.c_str()); MYSQL_QUERY(mysqlAdmin, queryS.c_str());
	}


	/*
	 * Teardown test set up. Reload proxysql configuration.
	 */

	if (mysql_query(mysqlAdmin, "load mysql query rules from disk")) return exit_status();
	if (mysql_query(mysqlAdmin, "load mysql query rules to runtime")) return exit_status();

	mysql_close(mysqlAdmin);

	return exit_status();
}

