#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <memory>
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

// Keep both the configured and running values, which need not be identical.
// MYSQL_QUERY returns from its caller on error, so restoration must also cover
// those exits and partially created connection batches.
class TimeoutFixture {
	MYSQL* admin;
	bool saved = false;

	bool query(const char* sql) {
		if (!mysql_query(admin, sql)) return true;
		diag("Fixture query failed: %s: %s", sql, mysql_error(admin));
		return false;
	}

public:
	explicit TimeoutFixture(MYSQL* conn) : admin(conn) {}
	TimeoutFixture(const TimeoutFixture&) = delete;
	TimeoutFixture& operator=(const TimeoutFixture&) = delete;
	bool save() {
		// The admin SQLite handle is shared; temp tables outlive a disconnect.
		if (!query("DROP TABLE IF EXISTS temp.kill_connection2_config") ||
			!query("DROP TABLE IF EXISTS temp.kill_connection2_runtime")) return false;
		if (!query("CREATE TEMPORARY TABLE kill_connection2_config AS SELECT * FROM global_variables "
			"WHERE variable_name IN ('mysql-have_ssl','mysql-have_compress',"
			"'mysql-auto_increment_delay_multiplex','mysql-wait_timeout','mysql-max_transaction_time')")) return false;
		if (!query("CREATE TEMPORARY TABLE kill_connection2_runtime AS SELECT * FROM runtime_global_variables "
			"WHERE variable_name IN ('mysql-have_ssl','mysql-have_compress',"
			"'mysql-auto_increment_delay_multiplex','mysql-wait_timeout','mysql-max_transaction_time')")) return false;
		saved = true;
		return true;
	}
	bool restore() {
		if (!saved) return true;
		bool good = true;
		for (const char* sql : {
			"UPDATE global_variables SET variable_value=(SELECT variable_value FROM kill_connection2_runtime v "
			"WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN "
			"(SELECT variable_name FROM kill_connection2_runtime)",
			"LOAD MYSQL VARIABLES TO RUNTIME",
			"UPDATE global_variables SET variable_value=(SELECT variable_value FROM kill_connection2_config v "
			"WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN "
			"(SELECT variable_name FROM kill_connection2_config)"
		}) {
			if (!query(sql)) good = false;
		}
		if (good) {
			saved = false;
			if (!query("DROP TABLE temp.kill_connection2_config")) good = false;
			if (!query("DROP TABLE temp.kill_connection2_runtime")) good = false;
		}
		return good;
	}
	~TimeoutFixture() {
		close_all_conns();
		restore();
	}
};

int create_connections(CommandLine& cl) {
	for (auto& conn : conns) {
		MYSQL * mysql = mysql_init(nullptr);
		if (!mysql) {
			fprintf(stderr, "File %s, line %d, Error: mysql_init failed\n", __FILE__, __LINE__);
			close_all_conns();
			return EXIT_FAILURE;
		}

		if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			mysql_close(mysql);
			close_all_conns();
			return EXIT_FAILURE;
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


	std::unique_ptr<MYSQL, decltype(&mysql_close)> admin_owner(mysql_init(nullptr), &mysql_close);
	MYSQL* proxysql_admin = admin_owner.get();
	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: mysql_init failed for 'proxysql_admin'\n",
			__FILE__, __LINE__);
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	TimeoutFixture fixture(proxysql_admin);
	if (!fixture.save()) return EXIT_FAILURE;

	MYSQL_QUERY(proxysql_admin, "SET mysql-have_ssl='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-have_compress='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-auto_increment_delay_multiplex=10"); // to ensure multiplexing stays disabled
	// Other connections are idle while Galera executes the fixture DDL/inserts.
	// Start the short timeout only once setup has finished on every connection.
	MYSQL_QUERY(proxysql_admin, "SET mysql-wait_timeout=3600000");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	int rc = 0;
	rc = create_connections(cl);
	if (rc != 0) {
		return exit_status();
	}

	for (int i = 0; i < NUM_CONNS ; i++) {
		MYSQL * mysql = conns[i];
		if (i == 0) {
			if (create_table_test_sbtest1(10,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
				close_all_conns();
				return exit_status();
			}
		} else {
			if (add_more_rows_test_sbtest1(10,mysql)) {
				fprintf(stderr, "File %s, line %d, Error: add_more_rows_sbtest1() failed\n", __FILE__, __LINE__);
				close_all_conns();
				return exit_status();
			}
		}
	}

	rc = find_tids();
	if (rc != 0) {
		close_all_conns();
		return exit_status();
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-wait_timeout=6000");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

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
		return exit_status();
	}

	rc = find_tids();
	if (rc != 0) {
		close_all_conns();
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
	return fixture.restore() ? exit_status() : EXIT_FAILURE;
}
