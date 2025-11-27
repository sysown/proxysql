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

#if 0

// on the first iteration we used pv to throttle traffic
// Function to check if pv is available
bool is_pv_available() {
	return system("which pv > /dev/null 2>&1") == 0;
}
#endif // 0

int main() {
	// 0 means no limit
	// we skip 8 because or the edge
	std::vector<long> target_times = {0, 1, 2, 3, 4, 5, 6, 7, /* 8, */ 20, 30, 60};
	plan(8 + target_times.size());

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// 1. Generate a large binlog file
	MYSQL* backend_conn = mysql_init(NULL);
	if (!mysql_real_connect(backend_conn, cl.host, cl.mysql_username, cl.mysql_password, "information_schema", cl.port, NULL, 0)) {
		diag("Backend connection failed: %s", mysql_error(backend_conn));
		return -1;
	}
	ok(1, "Connected to backend server");
	MYSQL_QUERY(backend_conn, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(backend_conn, "USE test");
	MYSQL_QUERY(backend_conn, "CREATE TABLE IF NOT EXISTS dummy_log_table (id INT PRIMARY KEY AUTO_INCREMENT, data LONGTEXT)");
	MYSQL_QUERY(backend_conn, "INSERT INTO dummy_log_table (data) VALUES (REPEAT('a', 1024*50))");
	MYSQL_QUERY(backend_conn, "INSERT INTO dummy_log_table (data) VALUES (REPEAT('a', 1024*50))");
	MYSQL_QUERY(backend_conn, "INSERT INTO dummy_log_table (data) VALUES (REPEAT('a', 1024*50))");
	int rc = mysql_query(backend_conn, "FLUSH LOGS");
	ok(rc == 0, "Generated data and flushed logs on backend");

	// 2. Configure ProxySQL
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connection failed: %s", mysql_error(proxysql_admin));
		mysql_close(backend_conn);
		return -1;
	}
	ok(1, "Connected to ProxySQL admin");

	rc = mysql_query(proxysql_admin, "UPDATE global_variables SET variable_value='8000' WHERE variable_name='mysql-fast_forward_grace_close_ms'");
	ok(rc == 0, "Set mysql-fast_forward_grace_close_ms=8000");
//	rc = mysql_query(proxysql_admin, "SET mysql-have_ssl=0");
//	ok(rc == 0, "Set mysql-have_ssl=0");
	rc = mysql_query(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(rc == 0, "Loaded MYSQL variables to runtime");

	// 3. Get first binary log file name and estimate total bytes
	string binlog_file;
	long total_bytes = 0;
	if (mysql_query(backend_conn, "SHOW BINARY LOGS") == 0) {
		MYSQL_RES *res = mysql_store_result(backend_conn);
		if (res) {
			MYSQL_ROW row;
			while ((row = mysql_fetch_row(res))) {
				if (!binlog_file.empty() || row[0]) {
					if (binlog_file.empty()) {
						binlog_file = row[0];
					}
					total_bytes += atol(row[1]);
				}
			}
			mysql_free_result(res);
		}
	}
	mysql_close(backend_conn);
	ok(!binlog_file.empty(), "Retrieved first binary log file name: %s", binlog_file.c_str());
	diag("Estimated total bytes: %ld", total_bytes);

#if 0
	// 4. Check if pv is available
	if (!is_pv_available()) {
		diag("pv is not available, cannot run the test");
		mysql_close(proxysql_admin);
		return -1;
	}
	ok(1, "pv is available");
#endif // 0

	// 5. Run 5 iterations with different throttling using MariaDB RPL API
	for (int i = 0; i < target_times.size() ; i++) {
		// Connect for binlog reading
		MYSQL* binlog_conn = mysql_init(NULL);
		if (!mysql_real_connect(binlog_conn, cl.host, cl.mysql_username, cl.mysql_password, NULL, cl.port, NULL, 0)) {
			diag("Binlog connection failed for iteration %d: %s", i, mysql_error(binlog_conn));
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
			diag("mysql_binlog_open failed for iteration %d: %s", i, mysql_error(binlog_conn));
			mysql_close(binlog_conn);
			mysql_close(proxysql_admin);
			return -1;
		}
		diag("mysql_binlog_open succeeded for iteration %d", i);

		long bytes_read = 0;
		time_t start_time = time(NULL);
		long target_rate = (i == 0) ? 0 : total_bytes / target_times[i];
		bool reached_EOF = false;

		while (true) {
			rc = mysql_binlog_fetch(binlog_conn, &rpl);
			if (rc != 0) break;
			long tmp_bytes_read = bytes_read;
			bytes_read += rpl.size;
			const long chunk_size = 1024*1024;
			if (bytes_read/chunk_size > tmp_bytes_read/chunk_size) {
				diag("Bytes read: %ld", bytes_read);
			}
			if (target_rate > 0) {
				usleep((rpl.size * 1000000LL) / target_rate);
			}
			if (rpl.size == 0) {
				//when size is 0 , we reached EOF
				reached_EOF = true;
				break;
			}
		}
		if (target_times[i] <= 8) {
			ok(reached_EOF == true , "Reached EOF: %s . Total Bytes read: %ld", (reached_EOF == true ? "TRUE" : "FALSE") , bytes_read);
		} else {
			diag("Target time greater than grace time, it should fail -- Reached EOF should be FALSE");
			ok(reached_EOF == false , "Reached EOF: %s . Total Bytes read: %ld", (reached_EOF == true ? "TRUE" : "FALSE") , bytes_read);
		}
		time_t end_time = time(NULL);
		diag("Binlog fetch ended with rc=%d, error=%s", rc, (rc == 0 ? "None" : mysql_error(binlog_conn)));
		mysql_binlog_close(binlog_conn, &rpl);
		mysql_close(binlog_conn);

		long taken = (long)(end_time - start_time);
		char desc[50];
		if (i == 0) strcpy(desc, "no limit");
		else sprintf(desc, "target %ld s", target_times[i]);
		diag("Iteration %d (%s): time %ld seconds, bytes %ld", i, desc, taken, bytes_read);
		//ok(1, "Iteration %d completed", i);
	}

	// 8. Cleanup
	rc = mysql_query(proxysql_admin, "UPDATE global_variables SET variable_value='0' WHERE variable_name='mysql-fast_forward_grace_close_ms'");
	ok(rc == 0, "Reset mysql-fast_forward_grace_close_ms");
	rc = mysql_query(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(rc == 0, "Loaded MYSQL variables to runtime for cleanup");

	backend_conn = mysql_init(NULL);
	mysql_real_connect(backend_conn, cl.host, cl.username, cl.password, "test", cl.port, NULL, 0);
	MYSQL_QUERY(backend_conn, "DROP TABLE dummy_log_table");
	mysql_close(backend_conn);

	mysql_close(proxysql_admin);

	return exit_status();
}
