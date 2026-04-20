#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"


/*
This test verifies that client connections are dropped because of:
- mysql-wait_timeout
- mysql-max_transaction_time
*/

const int NUM_CONNS = 5;


MYSQL * conns[NUM_CONNS];
unsigned long mythreadid[NUM_CONNS];

// Close any connection already stored in the global conns[] array. Used to
// release connections that are about to be overwritten (e.g. before the
// second create_connections() call) and on error paths so partially-opened
// batches don't leak.
static void close_all_conns() {
	for (auto& conn : conns) {
		if (conn) {
			mysql_close(conn);
			conn = nullptr;
		}
	}
}

int create_connections(CommandLine& cl) {
	for (auto& conn : conns) {
		MYSQL * mysql = mysql_init(nullptr);
		if (!mysql) {
			fprintf(stderr, "File %s, line %d, Error: mysql_init failed\n", __FILE__, __LINE__);
			close_all_conns();
			return exit_status();
		}

		if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			mysql_close(mysql);
			close_all_conns();
			return exit_status();
		}
		conn = mysql;
	}
	return 0;
}

int find_tids() {
	for (int i = 0; i < NUM_CONNS; i++) {
		MYSQL * mysql = conns[i];
		unsigned long tid = 0;  // initialize: avoid uninit read if loop empty
		MYSQL_ROW row;
		MYSQL_QUERY(mysql, "SELECT CONNECTION_ID()");
		MYSQL_RES * proxy_res = mysql_store_result(mysql);
		if (!proxy_res) {
			fprintf(stderr, "File %s, line %d, Error: mysql_store_result returned NULL: %s\n",
				__FILE__, __LINE__, mysql_error(mysql));
			return EXIT_FAILURE;
		}
		while ((row = mysql_fetch_row(proxy_res))) {
			if (row[0] != nullptr) { tid = atoll(row[0]); }
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
	np += NUM_CONNS ;	// to get connection id
	np += NUM_CONNS ;	// failed query on killed connection due to timeout
	np += NUM_CONNS ;	// to get connection id
	np += NUM_CONNS ;	// to run BEGIN
	np += NUM_CONNS ;	// to run first DO 1
	np += NUM_CONNS ;	// failed query on killed connection due transaction timeout

	plan(np);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}


	MYSQL* proxysql_admin = mysql_init(nullptr);
	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: mysql_init failed for 'proxysql_admin'\n",
			__FILE__, __LINE__);
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		mysql_close(proxysql_admin);
		return -1;
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-have_ssl='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-have_compress='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-auto_increment_delay_multiplex=10"); // to ensure multiplexing stays disabled
	MYSQL_QUERY(proxysql_admin, "SET mysql-wait_timeout=6000"); // to force a close
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	int rc = 0;
	rc = create_connections(cl);
	if (rc != 0) {
		mysql_close(proxysql_admin);
		return exit_status();
	}

	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		if (i == 0) {
			if (create_table_test_sbtest1(10,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
				close_all_conns();
				mysql_close(proxysql_admin);
				return exit_status();
			}
		} else {
			if (add_more_rows_test_sbtest1(10,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: add_more_rows_sbtest1() failed\n", __FILE__, __LINE__);
				close_all_conns();
				mysql_close(proxysql_admin);
				return exit_status();
			}
		}
	}

	rc = find_tids();
	if (rc != 0) {
		close_all_conns();
		mysql_close(proxysql_admin);
		return exit_status();
	}

	diag("Sleeping for 10 seconds");
	for (int i = 0; i < 10 ; i++) {
		fprintf(stderr,".");
		sleep(1);
	}
	fprintf(stderr,"\n");

	for (auto& conn : conns) {
		MYSQL * mysql = conn;
		int rc = run_q(mysql, "DO 1");
		ok(rc != 0, (rc == 0 ? "Connection still alive" : "Connection killed"));
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-wait_timeout=3600000"); // to not force a close on wait
	MYSQL_QUERY(proxysql_admin, "SET mysql-max_transaction_time=17000"); // to force a close on transaction
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// The first batch of conns was killed server-side via wait_timeout, but
	// the client-side MYSQL* structs still need to be released before the
	// next create_connections() overwrites the conns[] slots.
	close_all_conns();

	rc = create_connections(cl);
	if (rc != 0) {
		mysql_close(proxysql_admin);
		return exit_status();
	}

	rc = find_tids();
	if (rc != 0) {
		close_all_conns();
		mysql_close(proxysql_admin);
		return exit_status();
	}

	for (auto& conn : conns) {
		MYSQL * mysql = conn;
		int rc = run_q(mysql, "BEGIN");
		ok(rc == 0, "Running BEGIN on new connection");
	}

	diag("Sleeping for 12 seconds");
	for (int i = 0; i < 12 ; i++) {
		fprintf(stderr,".");
		sleep(1);
	}
	fprintf(stderr,"\n");

for (auto& conn : conns) {
		MYSQL * mysql = conn;
		int rc = run_q(mysql, "DO 1");
		ok(rc == 0, (rc == 0 ? "Connection still alive" : "Connection killed"));
	}

	diag("Sleeping for 12 seconds");
	for (int i = 0; i < 12 ; i++) {
		fprintf(stderr,".");
		sleep(1);
	}
	fprintf(stderr,"\n");

	for (auto& conn : conns) {
		MYSQL * mysql = conn;
		int rc = run_q(mysql, "DO 1");
		ok(rc != 0, (rc == 0 ? "Connection still alive" : "Connection killed"));
	}

	close_all_conns();
	mysql_close(proxysql_admin);
	return exit_status();
}
