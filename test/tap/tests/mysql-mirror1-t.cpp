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
This app tests mirroring

This is a first application, as more complex test can be introduced,
for example monitoring mirroring variables and checking stats_mysql_query_rules

This test also triggers:
- logging events in eventslog_format 1 and 2
- logging in audit log
*/

const int NUM_CONNS = 15;
const int RPI = 20; // rows per insert

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

int main(int argc, char** argv) {
	CommandLine cl;

	int np = 0;
	np += 6;
	np += NUM_CONNS; // new admin connections

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
	MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_format=2");
	MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_filename=\"proxy-events-2f\"");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_query_rules");
	
	std::string s;
	s = "INSERT INTO mysql_query_rules (rule_id, active, username, match_digest, mirror_hostgroup, log) VALUES (1, 1, \"" + std::string(cl.username) + "\", \"^INSERT\", 0, 1)";
	diag("Running: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "INSERT INTO mysql_query_rules (rule_id, active, username, match_digest, mirror_hostgroup, log) VALUES (2, 1, \"" + std::string(cl.username) + "\", \"^SELECT\", 0, 1)";
	diag("Running: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	MYSQL_RES* proxy_res;
	int rc = 0;
	rc = create_connections(cl);
	if (rc != 0) {
		return exit_status();
	}


	rc = run_q(proxysql_admin, "SHOW FULL PROCESSLIST");
	ok(rc == 0 , "SHOW FULL PROCESSLIST");
	proxy_res = mysql_store_result(proxysql_admin);
	mysql_free_result(proxy_res);

	rc = run_q(proxysql_admin, "SHOW PROCESSLIST");
	ok(rc == 0 , "SHOW FULL PROCESSLIST");
	proxy_res = mysql_store_result(proxysql_admin);
	mysql_free_result(proxy_res);

	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		if (i == 0) {
			if (create_table_test_sbtest1(RPI,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
				return exit_status();
			}
		} else {
			if (add_more_rows_test_sbtest1(RPI,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: add_more_rows_sbtest1() failed\n", __FILE__, __LINE__);
				return exit_status();
			}
		}
	}
	int rows_read = 0;

	sleep(1); // some INSERT may still be running

	// at this point the table sbtest should have 600 rows:
	// 300 rows from normal insert, and 100 rows from mirror
	rc = run_q(conns[0], "SELECT * FROM test.sbtest1");
	ok(rc == 0 , "SELECT FROM test.sbtest1");
	MYSQL_ROW row;
	proxy_res = mysql_store_result(conns[0]);
	while ((row = mysql_fetch_row(proxy_res))) {
		rows_read++;
	}
	mysql_free_result(proxy_res);
	ok(rows_read == RPI*NUM_CONNS*2, "Rows expected: %u , received: %u" , RPI*NUM_CONNS*2 , rows_read);

	// switching logging format
	MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_format=1");
	MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_filename=\"proxy-event-1f\"");
	MYSQL_QUERY(proxysql_admin, "SET mysql-auditlog_filename=\"proxy-audit\"");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// re-establish all connections
	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		mysql_close(mysql);
	}
	rc = create_connections(cl);
	if (rc != 0) {
		return exit_status();
	}



	for (int i = 0 ; i < NUM_CONNS ; i++) {
		MYSQL* proxysql_admin = mysql_init(NULL); // local scope
		// Initialize connections
		if (!proxysql_admin) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return -1;
		}
		if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return -1;
		}
		rc = run_q(proxysql_admin, "SELECT * FROM stats_mysql_processlist");
		ok(rc == 0 , "SELECT FROM stats_mysql_processlist");
		proxy_res = mysql_store_result(proxysql_admin);
		mysql_free_result(proxy_res);
		mysql_close(proxysql_admin);
	}



	// create some load sending a lot of writes
	// this should add 20x15x10 = 3000 rows , but mirrored they will become 6000
	for (int j = 0 ; j<10 ; j++) {
		for (int i = 0; i < NUM_CONNS ; i++) {
			MYSQL * mysql = conns[i];
			if (add_more_rows_test_sbtest1(RPI,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: add_more_rows_sbtest1() failed\n", __FILE__, __LINE__);
				return exit_status();
			}
		}	
	}

	sleep(1); // some INSERT may still be running

	// at this point the table sbtest should have 6600 rows:
	// 3300 rows from normal insert, and 3300 rows from mirror
	// note that because mirror can lose packet, we allow some margin of error (20%)
	rows_read = 0;
	rc = run_q(conns[0], "SELECT * FROM test.sbtest1");
	ok(rc == 0 , "SELECT FROM test.sbtest1");
	proxy_res = mysql_store_result(conns[0]);
	while ((row = mysql_fetch_row(proxy_res))) {
		rows_read++;
	}
	mysql_free_result(proxy_res);
	ok(rows_read > (float)(RPI*NUM_CONNS*11*1.8) && rows_read <= RPI*NUM_CONNS*11*2, "Rows received: %u , expected between %u and %u" , rows_read , (int)((float)(RPI*NUM_CONNS*11*1.5)), RPI*NUM_CONNS*11*2);

	// stress the system
	diag("Creating load");
	diag("note that this can be very network intensive, as there is no throttling");
	diag("this application is single threaded, yet app/proxysql/mysql can easily saturate 10Gbps");
	for (int j = 0 ; j<200 ; j++) {
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

	mysql_close(proxysql_admin);
	return exit_status();
}
