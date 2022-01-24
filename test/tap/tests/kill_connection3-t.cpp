#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"


/*
This test verifies that client connections are dropped because of:
- mysql-wait_timeout
- mysql-max_transaction_time
*/

const int NUM_CONNS = 35;

int run_q(MYSQL *mysql, const char *q) {
	MYSQL_QUERY(mysql,q);
	return 0;
}

MYSQL * conns[NUM_CONNS];
unsigned long mythreadid[NUM_CONNS];

int create_connections(CommandLine& cl) {
	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = mysql_init(NULL);
		if (!mysql) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			return exit_status();
		}

		if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			return exit_status();
		}
		conns[i] = mysql;
	}
	return 0;
}

int find_tids() {
	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		unsigned long tid;
		MYSQL_ROW row;
		MYSQL_QUERY(mysql, "SELECT CONNECTION_ID()");
		MYSQL_RES * proxy_res = mysql_store_result(mysql);
		while ((row = mysql_fetch_row(proxy_res))) {
			tid = atoll(row[0]);
		}
		mysql_free_result(proxy_res);
		ok(tid == mysql_thread_id(mysql), "tid: %lu, mysql_thread_id(): %lu", tid, mysql_thread_id(mysql));
		mythreadid[i] = tid;
	}

	return 0;
}

int main(int argc, char** argv) {
	CommandLine cl;

	int np = 0;
	np += 2; // for processlist
	np += NUM_CONNS ;	// to get connection id
	np += 1; // for processlist
	np += NUM_CONNS ;	// to kill connections
	np += NUM_CONNS ;	// to run first DO 1
	np += NUM_CONNS ;	// to get connection id
	np += 1; // for processlist
	np += NUM_CONNS ;	// to run BEGIN
	np += 1; // for processlist
	np += NUM_CONNS ;	// to kill connections
	np += NUM_CONNS ;	// to run second DO 1

	plan(np);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}


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

	MYSQL_QUERY(proxysql_admin, "SET mysql-have_ssl='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-have_compress='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-show_processlist_extended=1");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL_RES* proxy_res;
	int rc = 0;
	rc = create_connections(cl);
	if (rc != 0) {
		return exit_status();
	}

	rc = run_q(proxysql_admin, "SELECT * FROM stats_mysql_processlist");
	ok(rc == 0 , "SELECT FROM stats_mysql_processlist");
	proxy_res = mysql_store_result(proxysql_admin);
	mysql_free_result(proxy_res);

	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		if (i == 0) {
			if (create_table_test_sbtest1(10,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
				return exit_status();
			}
		} else {
			if (add_more_rows_test_sbtest1(10,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: add_more_rows_sbtest1() failed\n", __FILE__, __LINE__);
				return exit_status();
			}
		}
	}

	rc = run_q(proxysql_admin, "SELECT * FROM stats_mysql_processlist");
	ok(rc == 0 , "SELECT FROM stats_mysql_processlist");
	proxy_res = mysql_store_result(proxysql_admin);
	mysql_free_result(proxy_res);

	rc = find_tids();
	if (rc != 0) {
		return exit_status();
	}

	rc = run_q(proxysql_admin, "SELECT * FROM stats_mysql_processlist");
	ok(rc == 0 , "SELECT FROM stats_mysql_processlist");
	proxy_res = mysql_store_result(proxysql_admin);
	mysql_free_result(proxy_res);

	// kill all the connections
	for (int i = 0; i < NUM_CONNS ; i++) {
		std::string s = "KILL CONNECTION " + std::to_string(mythreadid[i]);
		rc = run_q(proxysql_admin, s.c_str());
		ok(rc == 0 , "%s" , s.c_str());
	}
	sleep(1);
	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		int rc = run_q(mysql, "DO 1");
		ok(rc != 0, (rc == 0 ? "Connection still alive" : "Connection killed"));
	}
	MYSQL_QUERY(proxysql_admin, "SET mysql-show_processlist_extended=2");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	rc = create_connections(cl);
	if (rc != 0) {
		return exit_status();
	}

	rc = find_tids();
	if (rc != 0) {
		return exit_status();
	}

	rc = run_q(proxysql_admin, "SELECT * FROM stats_mysql_processlist");
	ok(rc == 0 , "SELECT FROM stats_mysql_processlist");
	proxy_res = mysql_store_result(proxysql_admin);
	mysql_free_result(proxy_res);

	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		int rc = run_q(mysql, "BEGIN");
		ok(rc == 0, "Running BEGIN on new connection");
	}

	rc = run_q(proxysql_admin, "SELECT * FROM stats_mysql_processlist");
	ok(rc == 0 , "SELECT FROM stats_mysql_processlist");
	proxy_res = mysql_store_result(proxysql_admin);
	mysql_free_result(proxy_res);

	// kill all the connections
	for (int i = 0; i < NUM_CONNS ; i++) {
		std::string s = "KILL CONNECTION " + std::to_string(mythreadid[i]);
		rc = run_q(proxysql_admin, s.c_str());
		ok(rc == 0 , "%s" , s.c_str());
	}

	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		int rc = run_q(mysql, "DO 1");
		ok(rc != 0, (rc == 0 ? "Connection still alive" : "Connection killed"));
	}

	return exit_status();
}
