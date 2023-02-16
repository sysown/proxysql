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

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* proxysql_mysql = mysql_init(NULL);
	MYSQL* proxysql_admin = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}

	const char* stats_mysql_connection_pool = "SELECT COUNT(*) FROM (SELECT ConnFree FROM stats.stats_mysql_connection_pool WHERE hostgroup=1) WHERE ConnFree >= 1";

	while (true) {
		MYSQL_QUERY(proxysql_mysql, "SELECT 1");
		MYSQL_RES* proxy_res = mysql_store_result(proxysql_mysql);
		mysql_free_result(proxy_res);

		MYSQL_QUERY(proxysql_admin, stats_mysql_connection_pool);
		MYSQL_RES* admin_res = mysql_store_result(proxysql_admin);
		MYSQL_ROW row = mysql_fetch_row(admin_res);

		if (strstr(row[0], "3")) {
			break;
		}
	}

	// We should check and store all the actual free connections
	MYSQL_QUERY(proxysql_admin, "SELECT ConnUsed, ConnFree FROM stats.stats_mysql_connection_pool WHERE hostgroup=1");
	MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);

	std::vector<int> cur_connections {};
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(proxy_res))) {
		int row_used_conn = atoi(row[0]);
		int row_free_conn = atoi(row[1]);
		cur_connections.push_back(row_used_conn + row_free_conn);
	}

	mysql_free_result(proxy_res);

	// Do a random number of normal selects using the anotation and verify that the connections has increased by that number
	srand(time(NULL));
	int rand_conn = rand() % 100;
	for (int i = 0; i < rand_conn; i++) {
		MYSQL_QUERY(proxysql_mysql, "SELECT /* ;create_new_connection=1 */ 1");
		proxy_res = mysql_store_result(proxysql_mysql);
		mysql_free_result(proxy_res);
	}

	MYSQL_QUERY(proxysql_admin, "SELECT ConnUsed, ConnFree, srv_port FROM stats.stats_mysql_connection_pool WHERE hostgroup=1");
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
