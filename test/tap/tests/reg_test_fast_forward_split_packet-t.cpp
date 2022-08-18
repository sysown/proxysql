/**
 * @file reg_test_fast_forward_split_packet-t.cpp
 * @brief This is a simple regression test for checking that 'FAST_FORWARD' is able to handle split packets
 *   received in a connection that is yet in 'CONNECTING_SERVER' state.
 * @details In order to achieve this behavior consistently, the test performs the following operations:
 *  1. Enables 'fast_forward' for 'mysql_users'.
 *  2. Creates a number of connections.
 *  3. Performs a unique 'INSERT' query of increasing size in each of the connections.
 *
 *  If the issue is present and ProxySQL cannot handle this situation, the test can fail before reaching
 *  'QUEUE_T_DEFAULT_SIZE', but will for sure fail after this threshold is reached. Since the input buffer
 *  is filled by the query, there won't be other option that processing the received packet in two different
 *  iterations of 'MySQL_Session::handler', which will force the 'CONNECTING_SERVER' situation.
 */

#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

const int NUM_CONNS = 35;

MYSQL* conns[NUM_CONNS];

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// One query that should succeed per-connection
	plan(NUM_CONNS);

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	MYSQL_QUERY(proxysql_admin, "UPDATE mysql_users SET fast_forward=1");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL USERS TO RUNTIME");

	std::random_device rd {};
	std::mt19937 mt(rd());
	std::uniform_int_distribution<int> dist(0.0, 9.0);

	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = mysql_init(NULL);
		if (!mysql) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			return EXIT_FAILURE;
		}

		if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			return EXIT_FAILURE;
		}
		conns[i] = mysql;
	}

	MYSQL_QUERY(conns[0], "DROP TABLE IF EXISTS test.reg_test_fast_forward_split");
	MYSQL_QUERY(
		conns[0],
		"CREATE TABLE IF NOT EXISTS test.reg_test_fast_forward_split ("
			" `id` int(10) unsigned NOT NULL AUTO_INCREMENT, `k` int(10) unsigned NOT NULL DEFAULT '0',"
			" `c` char(120) NOT NULL DEFAULT '', `pad` char(60) NOT NULL DEFAULT '',"
			"  PRIMARY KEY (`id`), KEY `k_1` (`k`) "
		")"
	);

	int query_num = 10;
	std::string q { "INSERT INTO test.reg_test_fast_forward_split (k, c, pad) values " };
	bool put_comma=false;

	for (int j = 0; j < NUM_CONNS; j++) {
		MYSQL* proxysql_mysql = conns[j];

		for (int i=0; i< query_num; ++i) {
			int k = dist(mt);
			std::string c;
			for (int j=0; j<10; j++) {
				for (int k=0; k<11; k++) {
					c += std::to_string(dist(mt));
				}
				if (j<9)
					c += "-";
			}
			std::string pad;
			for (int j=0; j<5; j++) {
				for (int k=0; k<11; k++) {
					pad += std::to_string(dist(mt));
				}
				if (j<4)
					pad += "-";
			}
			if (put_comma) q += ",";
			if (!put_comma) put_comma=true;

			q += "(" + std::to_string(k) + ",'" + c + "','" + pad + "')";
		}

		int q_err = mysql_query(proxysql_mysql, q.c_str());
		ok(q_err == EXIT_SUCCESS, "Executing query of size: '%ld', should succeed", q.size());
	}

	for (int j = 0; j < NUM_CONNS; j++) {
		mysql_close(conns[j]);
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
