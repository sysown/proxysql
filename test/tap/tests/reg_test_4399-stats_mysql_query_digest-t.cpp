/**
 * @file reg_test_4399-stats_mysql_query_digest-t.cpp
 * @brief This test verifies stability of ProxySQL by checking if it remains operational when 
 *		stats_mysql_query_digest table is queried frequently while actively serving traffic.
 */

#include <stdio.h>
#include <future>
#include <thread>
#include "mysql.h"
#include "mysqld_error.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h" 

CommandLine cl;

const unsigned int QUERY_COUNT = 1000;

int main(int argc, char** argv) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(2);

	// Initialize Admin connection
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	// Connnect to ProxySQL Admin
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-query_digests='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-query_digests_keep_comment='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-query_digests_normalize_digest_text='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-query_digests_max_digest_length=2048");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// clearing previously stored digests
	MYSQL_QUERY(proxysql_admin, "SELECT COUNT(*) FROM stats_mysql_query_digest_reset");
	mysql_free_result(mysql_store_result(proxysql_admin));

	// Initialize ProxySQL connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	// Connect to ProxySQL
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}

	auto handle = std::async(std::launch::async, [&]() -> int {
			char query[128]{};
			diag("Generating simulated traffic...");
			for (unsigned int i=0; i < QUERY_COUNT; i++) {
				sprintf(query, "DO /*#%d#*/ %d", i, i);
				MYSQL_QUERY(proxysql, query);
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}
			return EXIT_SUCCESS; 
		}
	);

	bool result = true;
	diag("Querying stats_mysql_query_digest table...");
	for (unsigned int i=0; i < QUERY_COUNT; i++) {
		if (mysql_query(proxysql_admin, "SELECT COUNT(*) FROM stats_mysql_query_digest")) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			result = false;
			break;
		}
		mysql_free_result(mysql_store_result(proxysql_admin));
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	ok(result == true, "All queries on stats_mysql_query_digest table were executed successfully");
	ok(handle.get() == EXIT_SUCCESS, "Successfully ran a set of dummy queries to simulate traffic");

	mysql_close(proxysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
