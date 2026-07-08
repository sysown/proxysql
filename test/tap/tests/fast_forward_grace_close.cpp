#include <algorithm>
/*
 * Fast Forward Grace Close Test
 *
 * This test validates the fast forward grace close feature in ProxySQL.
 * The feature prevents data loss by allowing pending client output buffers
 * to drain before closing sessions when the backend closes unexpectedly
 * in fast forward mode.
 *
 * Test Strategy:
 * - Generate a large binlog on the backend.
 * - Connect via ProxySQL and read the binlog in a throttled manner to trigger
 *   fast forward mode closure.
 * - Verify that the grace close logic allows buffers to drain without data loss.
 * - Really slow connection should fail
 */

#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctime>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#ifndef BINLOG_DUMP_NON_BLOCK
#define BINLOG_DUMP_NON_BLOCK 1
#endif // BINLOG_DUMP_NON_BLOCK

using std::string;

int main() {
	std::vector<long> target_times = {0, 1, 2, 3, 4, 5, 6, 7, /* 8, */ 20, 30, 60};
	plan(8 + target_times.size());

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// 1. Generate a large binlog file - MUST connect via ProxySQL
	MYSQL* proxysql_conn = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_conn, cl.host, cl.root_username, cl.root_password, "information_schema", cl.port, NULL, 0)) {
		diag("ProxySQL connection failed: %s", mysql_error(proxysql_conn));
		return -1;
	}
	ok(1, "Connected to ProxySQL for data generation");
	MYSQL_QUERY(proxysql_conn, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(proxysql_conn, "USE test");
	MYSQL_QUERY(proxysql_conn, "CREATE TABLE IF NOT EXISTS dummy_log_table (id INT PRIMARY KEY AUTO_INCREMENT, data LONGTEXT)");
	// Generate enough binlog data that the client's kernel recv buffer can
	// hold only a small fraction of it. For target_time > 8s, grace close
	// must fire before the full binlog (including the empty-event EOF marker)
	// has been delivered to the client's socket — otherwise the client sees
	// EOF anyway and the "expected FALSE" assertions flake. With autotuned
	// recv buffers that can grow to several MB on some kernels/runners, a
	// small binlog lets the EOF marker slip through during the 8s grace
	// window. 1000 x 50 KB = ~50 MB gives a comfortable multiple of any
	// realistic recv buffer.
	for (int i = 0; i < 1000; i++) {
		MYSQL_QUERY(proxysql_conn, "INSERT INTO dummy_log_table (data) VALUES (REPEAT('a', 1024*50))");
	}
	int rc = mysql_query(proxysql_conn, "FLUSH LOGS");
	ok(rc == 0, "Generated data and flushed logs on backend via ProxySQL");

	// 2. Configure ProxySQL Admin
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connection failed: %s", mysql_error(proxysql_admin));
		mysql_close(proxysql_conn);
		return -1;
	}
	ok(1, "Connected to ProxySQL admin");

	rc = mysql_query(proxysql_admin, "UPDATE global_variables SET variable_value='8000' WHERE variable_name='mysql-fast_forward_grace_close_ms'");
	ok(rc == 0, "Set mysql-fast_forward_grace_close_ms=8000");
	rc = mysql_query(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(rc == 0, "Loaded MYSQL variables to runtime");

	// 3. Get first binary log file name and its size
	// Use the size of the FIRST binlog file (the one we'll read), not the total
	// of all files. With dbdeployer, the binlog accumulates data from all earlier
	// tests, making total_bytes much larger than the first file we actually read.
	string binlog_file;
	long total_bytes = 0;
	if (mysql_query(proxysql_conn, "SHOW BINARY LOGS") == 0) {
		MYSQL_RES *res = mysql_store_result(proxysql_conn);
		if (res) {
			MYSQL_ROW row;
			while ((row = mysql_fetch_row(res))) {
				if (binlog_file.empty() && row[0]) {
					binlog_file = row[0];
					total_bytes = atol(row[1]);
				}
			}
			mysql_free_result(res);
		}
	}
	diag("Binlog file: %s, size: %ld bytes", binlog_file.c_str(), total_bytes);
	mysql_close(proxysql_conn);
	ok(!binlog_file.empty(), "Retrieved binary log: %s", binlog_file.c_str());

	// 5. Run iterations through ProxySQL
	for (int i = 0; i < target_times.size() ; i++) {
		MYSQL* binlog_conn = mysql_init(NULL);
		if (!mysql_real_connect(binlog_conn, cl.host, cl.root_username, cl.root_password, NULL, cl.port, NULL, 0)) {
			diag("Binlog connection failed: %s", mysql_error(binlog_conn));
			mysql_close(proxysql_admin);
			return -1;
		}

		MYSQL_QUERY(binlog_conn, "SET @source_binlog_checksum='NONE'");
		MYSQL_RPL rpl {};
		rpl.file_name = const_cast<char*>(binlog_file.c_str());
		rpl.start_position = 4;
		rpl.server_id = 12345;
		rpl.flags = BINLOG_DUMP_NON_BLOCK;
		int rc = mysql_binlog_open(binlog_conn, &rpl);
		if (rc != 0) {
			diag("mysql_binlog_open failed: %s", mysql_error(binlog_conn));
			mysql_close(binlog_conn);
			mysql_close(proxysql_admin);
			return -1;
		}

		long bytes_read = 0;
		time_t start_time = time(NULL);
		long target_rate = (i == 0) ? 0 : total_bytes / target_times[i];
		bool reached_EOF = false;

		while (true) {
			rc = mysql_binlog_fetch(binlog_conn, &rpl);
			if (rc != 0) break;
			bytes_read += rpl.size;
			if (target_rate > 0) {
				usleep((rpl.size * 1000000LL) / target_rate);
			}
			if (rpl.size == 0) {
				reached_EOF = true;
				break;
			}
		}
		if (target_times[i] <= 8) {
			ok(reached_EOF == true , "Reached EOF (Expected TRUE): %s", reached_EOF ? "TRUE" : "FALSE");
		} else {
			ok(reached_EOF == false , "Reached EOF (Expected FALSE): %s", reached_EOF ? "TRUE" : "FALSE");
		}
		mysql_binlog_close(binlog_conn, &rpl);
		mysql_close(binlog_conn);
	}

	// 8. Cleanup
	rc = mysql_query(proxysql_admin, "UPDATE global_variables SET variable_value='0' WHERE variable_name='mysql-fast_forward_grace_close_ms'");
	ok(rc == 0, "Reset mysql-fast_forward_grace_close_ms");
	rc = mysql_query(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(rc == 0, "Loaded MYSQL variables to runtime for cleanup");

	proxysql_conn = mysql_init(NULL);
	if (mysql_real_connect(proxysql_conn, cl.host, cl.root_username, cl.root_password, "test", cl.port, NULL, 0)) {
		MYSQL_QUERY(proxysql_conn, "DROP TABLE dummy_log_table");
		mysql_close(proxysql_conn);
	}
	
	mysql_close(proxysql_admin);

	return exit_status();
}
