/**
 * @file test_connection_annotation-t.cpp
 * @brief This test verifies the feature 'create_new_connection' annotation is working properly. Strategy used is doing
 *  a random number of queries that by themselves shouldn't increase the number of free connections ('ConnFree'), but with
 *  the new supported annotation, and verify that the total number of free connections is increased by that random number.
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(1);

	diag("Test: Connection Annotation 'create_new_connection'");
	diag("This test verifies that the '/* ;create_new_connection=1 */' annotation");
	diag("properly forces ProxySQL to establish a new connection to the backend.");
	diag("The test strategy is:");
	diag("1. Wait for a stable state with free connections available across multiple backends.");
	diag("2. Record the current total number of connections (Used + Free) in hostgroup 1.");
	diag("3. Execute a random number of queries using the annotation.");
	diag("4. Verify that the total number of connections increased by exactly that random number.");

	MYSQL* proxysql_mysql = mysql_init(NULL);
	MYSQL* proxysql_admin = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_mysql, cl.root_host, cl.root_username, cl.root_password, NULL, cl.root_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}

	const char* stats_mysql_connection_pool = "SELECT COUNT(*) FROM (SELECT ConnFree FROM stats.stats_mysql_connection_pool WHERE hostgroup=1) WHERE ConnFree >= 1";

	// Warmup phase: execute queries to ensure connections are established and freed in HG 1
	diag("Warmup phase: executing queries to populate HG 1 connection pool...");
	for (int i = 0; i < 5; i++) {
		MYSQL_QUERY(proxysql_mysql, "SELECT /* ;hostgroup=1 */ 1");
		MYSQL_RES* proxy_res = mysql_store_result(proxysql_mysql);
		mysql_free_result(proxy_res);
	}

	int wait_retries = 0;
	while (wait_retries < 1000) {
		MYSQL_QUERY(proxysql_mysql, "SELECT /* ;hostgroup=1 */ 1");
		MYSQL_RES* proxy_res = mysql_store_result(proxysql_mysql);
		mysql_free_result(proxy_res);

		MYSQL_QUERY(proxysql_admin, stats_mysql_connection_pool);
		MYSQL_RES* admin_res = mysql_store_result(proxysql_admin);
		MYSQL_ROW row = mysql_fetch_row(admin_res);

		bool done = false;
		int count = 0;
		if (row && row[0]) {
			count = atoi(row[0]);
			if (count >= 3) {
				done = true;
			}
		}
		
		if (wait_retries % 50 == 0 || done) {
			diag("Waiting for stable state: found %d backends with ConnFree >= 1 in HG 1 (Retries: %d)", count, wait_retries);
			if (count < 3) {
				// Debug: show which HGs actually have connections
				MYSQL_QUERY(proxysql_admin, "SELECT hostgroup, SUM(ConnFree) FROM stats.stats_mysql_connection_pool GROUP BY hostgroup HAVING SUM(ConnFree) > 0");
				MYSQL_RES* debug_res = mysql_store_result(proxysql_admin);
				if (debug_res) {
					MYSQL_ROW d_row;
					while ((d_row = mysql_fetch_row(debug_res))) {
						diag("  Found HG %s with %s total free connections", d_row[0], d_row[1]);
					}
					mysql_free_result(debug_res);
				}
			}
		}
		
		mysql_free_result(admin_res);

		if (done) break;
		
		usleep(10000); // 10ms
		wait_retries++;
	}

	if (wait_retries >= 1000) {
		diag("Warning: Timed out waiting for stable connection state (3 backends with free conns). Proceeding anyway.");
	}

	// We should check and store all the actual free connections
	diag("Recording initial connection counts for HG 1...");
	MYSQL_QUERY(proxysql_admin, "SELECT ConnUsed, ConnFree, srv_host, srv_port FROM stats.stats_mysql_connection_pool WHERE hostgroup=1");
	MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);

	std::vector<int> cur_connections {};
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(proxy_res))) {
		int row_used_conn = atoi(row[0]);
		int row_free_conn = atoi(row[1]);
		cur_connections.push_back(row_used_conn + row_free_conn);
		diag("Backend %s:%s - Initial ConnUsed: %d, ConnFree: %d", row[2], row[3], row_used_conn, row_free_conn);
	}

	mysql_free_result(proxy_res);

	// Do a random number of normal selects using the anotation and verify that the connections has increased by that number
	srand(time(NULL));
	int rand_conn = (rand() % 50) + 1; // At least 1 connection
	diag("Executing %d queries with /* ;create_new_connection=1;hostgroup=1 */ annotation...", rand_conn);
	for (int i = 0; i < rand_conn; i++) {
		MYSQL_QUERY(proxysql_mysql, "SELECT /* ;create_new_connection=1;hostgroup=1 */ 1");
		proxy_res = mysql_store_result(proxysql_mysql);
		mysql_free_result(proxy_res);
		if ((i + 1) % 10 == 0) {
			diag("Executed %d/%d annotated queries...", i + 1, rand_conn);
		}
	}
	diag("All annotated queries executed.");

	diag("Verifying final connection counts for HG 1...");
	MYSQL_QUERY(proxysql_admin, "SELECT ConnUsed, ConnFree, srv_host, srv_port FROM stats.stats_mysql_connection_pool WHERE hostgroup=1");
	proxy_res = mysql_store_result(proxysql_admin);
	std::vector<int> new_cur_connections {};

	while ((row = mysql_fetch_row(proxy_res))) {
		int row_used_conn = atoi(row[0]);
		int row_free_conn = atoi(row[1]);
		int srv_port = atoi(row[2]);
		new_cur_connections.push_back(row_used_conn + row_free_conn);

		diag("srv_port: %d - ConnUsed: %d, ConnFree: %d", srv_port, row_used_conn, row_free_conn);
	}

	mysql_free_result(proxy_res);

	int new_total_conn = 0;
	// Sum the differences between previous free and new free connections
	for (int i = 0; i < cur_connections.size(); i++) {
		new_total_conn += new_cur_connections[i] - cur_connections[i];
	}

	ok(rand_conn == new_total_conn, "The number of queries executed with annotations should be equal to the number of new connections: %d == %d", rand_conn, new_total_conn);

	return exit_status();
}
