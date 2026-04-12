#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "noise_utils.h"
#include "utils.h"


/*
This test verifies that client connections are dropped because of:
- mysql-wait_timeout
- mysql-max_transaction_time
*/

const int NUM_CONNS = 35;
const int RPI = 50;


MYSQL * conns[NUM_CONNS];
unsigned long mythreadid[NUM_CONNS];

// Close any connection already stored in the global conns[] array. Safe to
// call multiple times; nulls each slot so repeat calls are no-ops.
static void close_all_conns() {
	for (int i = 0; i < NUM_CONNS; i++) {
		if (conns[i]) {
			mysql_close(conns[i]);
			conns[i] = NULL;
		}
	}
}

int create_connections(CommandLine& cl) {
	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = mysql_init(NULL);
		if (!mysql) {
			fprintf(stderr, "File %s, line %d, Error: mysql_init failed\n", __FILE__, __LINE__);
			close_all_conns();
			return exit_status();
		}

		if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			mysql_close(mysql);
			close_all_conns();
			return exit_status();
		}
		conns[i] = mysql;
		mythreadid[i] =  mysql_thread_id(conns[i]);
	}
	return 0;
}


int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	spawn_internal_noise(cl, internal_noise_random_stats_poller);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});
	spawn_internal_noise(cl, internal_noise_pgsql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});

	int np = 0;
	np += 3; // for processlist
	np += NUM_CONNS ;	// to kill connections
	np += NUM_CONNS ;	// to run first DO 1
	np += 1; // for processlist
	np += NUM_CONNS ;	// to run BEGIN
	np += 1; // for processlist
	np += NUM_CONNS ;	// to run second DO 1
	np += 2; // to count rows
	np += NUM_CONNS ;	// to run third DO 1

	if (cl.use_noise) {
		plan(np + 3);
	} else {
		plan(np);
	}


	MYSQL* proxysql_admin = mysql_init(NULL);
	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: mysql_init failed for 'proxysql_admin'\n",
			__FILE__, __LINE__);
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		mysql_close(proxysql_admin);
		return -1;
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-have_ssl='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-have_compress='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-show_processlist_extended=1");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxysql_admin, "UPDATE mysql_users SET fast_forward=1");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL USERS TO RUNTIME");

	MYSQL_RES* proxy_res;
	int rc = 0;
	rc = create_connections(cl);
	if (rc != 0) {
		mysql_close(proxysql_admin);
		return exit_status();
	}


	rc = run_q(proxysql_admin, "SELECT * FROM stats_mysql_processlist");
	ok(rc == 0 , "SELECT FROM stats_mysql_processlist");
	proxy_res = mysql_store_result(proxysql_admin);
	mysql_free_result(proxy_res);

	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		if (i == 0) {
			if (create_table_test_sbtest1(RPI,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
				close_all_conns();
				mysql_close(proxysql_admin);
				return exit_status();
			}
		} else {
			if (add_more_rows_test_sbtest1(RPI,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: add_more_rows_sbtest1() failed\n", __FILE__, __LINE__);
				close_all_conns();
				mysql_close(proxysql_admin);
				return exit_status();
			}
		}
	}

	rc = run_q(proxysql_admin, "SHOW FULL PROCESSLIST");
	ok(rc == 0 , "SHOW FULL PROCESSLIST");
	proxy_res = mysql_store_result(proxysql_admin);
	mysql_free_result(proxy_res);


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

	MYSQL_QUERY(proxysql_admin, "SET mysql-show_processlist_extended=2");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Release the previous (now server-killed) batch before the next
	// create_connections() overwrites the conns[] slots.
	close_all_conns();

	rc = create_connections(cl);
	if (rc != 0) {
		mysql_close(proxysql_admin);
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

	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		int rc = run_q(mysql, "DO 1");
		ok(rc == 0, (rc == 0 ? "Connection still alive" : "Connection killed"));
	}

	int rows_read = 0;

	rc = run_q(conns[0], "SELECT * FROM test.sbtest1");
	ok(rc == 0 , "SELECT FROM test.sbtest1");
	proxy_res = mysql_store_result(conns[0]);
	if (proxy_res) {
		while (mysql_fetch_row(proxy_res)) {
			rows_read++;
		}
		mysql_free_result(proxy_res);
	} else {
		fprintf(stderr, "File %s, line %d, Error: mysql_store_result on conns[0] returned NULL: %s\n",
			__FILE__, __LINE__, mysql_error(conns[0]));
	}
	ok(rows_read == RPI*NUM_CONNS, "Rows expected: %u , received: %u" , RPI*NUM_CONNS , rows_read);

	// stress the system
	diag("Creating load");
	diag("note that this can be very network intensive, as there is no throttling");
	diag("this application is single threaded, yet app/proxysql/mysql can easily saturate 10Gbps");
	for (int j = 0 ; j<100 ; j++) {
		for (int i = 0; i < NUM_CONNS ; i++) {
			MYSQL * mysql = conns[i];
			std::string s = "SELECT * FROM test.sbtest1 WHERE id > " + std::to_string(rand()%rows_read) + " ORDER BY id"; // on average we will read half table
			MYSQL_QUERY(mysql, s.c_str());
			proxy_res = mysql_store_result(mysql);
			mysql_free_result(proxy_res);
		}
		fprintf(stderr,".");
	}
	fprintf(stderr,"\n");
	diag("Test completed");

	diag("Dropping all backends");
	MYSQL_QUERY(proxysql_admin, "UPDATE mysql_servers SET status='OFFLINE_HARD'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	diag("Waiting 10 seconds to make sure that MySQL_Thread::ProcessAllSessions_MaintenanceLoop() kills the connections");
	diag("We sleep because this is not a synchronous operation");
	for (int i = 0; i < 10 ; i++) {
		fprintf(stderr,".");
		sleep(1);
	}
	fprintf(stderr,"\n");

	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		int rc = run_q(mysql, "DO 1");
		ok(rc != 0, (rc == 0 ? "Connection still alive" : "Connection killed"));
	}

	close_all_conns();
	mysql_close(proxysql_admin);
	return exit_status();
}
