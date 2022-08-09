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
This test verifies a variety of things:
- the following queries run as expected:
  * SELECT LAST_INSERT_ID()
  * SELECT LAST_INSERT_ID() LIMIT 1
  * SELECT @@IDENTITY
  * SELECT CONNECTION_ID()
- that killing backend connections works
*/

const int NUM_CONNS = 5;

int run_q(MYSQL *mysql, const char *q) {
	MYSQL_QUERY(mysql,q);
	return 0;
}

int main(int argc, char** argv) {
	CommandLine cl;

	int np = NUM_CONNS ; // for last insert id
	np += NUM_CONNS -1 ;	// to compare all last insert id
	np += NUM_CONNS ;	// to get connection id
	np += NUM_CONNS -1 ;	// failed query on killed connection

	plan(np);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL * conns[NUM_CONNS];
	unsigned long long last_id[NUM_CONNS];
	unsigned long mythreadid[NUM_CONNS];
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

	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		if (i == 0) {
			if (create_table_test_sbtest1(100,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
				return exit_status();
			}
		} else {
			if (add_more_rows_test_sbtest1(100,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: add_more_rows_sbtest1() failed\n", __FILE__, __LINE__);
				return exit_status();
			}
		}
		unsigned long long a, b, c;
		unsigned long tid;
		MYSQL_ROW row;
		MYSQL_QUERY(mysql, "SELECT LAST_INSERT_ID()");
		MYSQL_RES* proxy_res = mysql_store_result(mysql);
		while ((row = mysql_fetch_row(proxy_res))) {
			a = atoll(row[0]);
		}
		mysql_free_result(proxy_res);
		MYSQL_QUERY(mysql, "SELECT LAST_INSERT_ID() LIMIT 1");
		proxy_res = mysql_store_result(mysql);
		while ((row = mysql_fetch_row(proxy_res))) {
			b = atoll(row[0]);
		}
		mysql_free_result(proxy_res);
		MYSQL_QUERY(mysql, "SELECT @@IDENTITY");
		proxy_res = mysql_store_result(mysql);
		while ((row = mysql_fetch_row(proxy_res))) {
			c = atoll(row[0]);
		}
		mysql_free_result(proxy_res);
		// the 3 queries above should all return the same result
		ok(a > 0 && a == b && b == c && a == mysql_insert_id(mysql), "LAST_INSERT_ID: %llu , LAST_INSERT_ID_LIMIT1: %llu , IDENTITY: %llu , mysql_insert_id: %llu", a, b, c, mysql_insert_id(mysql));
		last_id[i] = a;
	}

	for (int i = 1; i < NUM_CONNS ; i++) {
		ok(last_id[i-1] < last_id[i], "%llu < %llu" , last_id[i-1] , last_id[i]);
	}

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
	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		if (i == 0) {
			for (int j = 1 ; j < NUM_CONNS; j++) {
				std::string s = "KILL CONNECTION " + std::to_string(mythreadid[j]);
				diag("Running: %s", s.c_str());
				MYSQL_QUERY(mysql, s.c_str());
			}
			sleep(1);
		} else {
			int rc = run_q(mysql, "DO 1");
			ok(rc != 0, "Connection killed");
		}
	}

	return exit_status();
}
