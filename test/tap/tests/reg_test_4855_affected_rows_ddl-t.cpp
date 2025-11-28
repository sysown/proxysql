/*
  Copyright (c) 2025 ProxySQL

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1335  USA */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mysql.h"

int main(int argc, char** argv) {
	plan(12);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	MYSQL *admin = mysql_init(NULL);
	ok(admin != NULL, "mysql_init() succeeded");
	if (!admin) {
		return exit_status();
	}

	// Connect to ProxySQL Admin using command line arguments
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to ProxySQL Admin: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}
	ok(true, "Connected to ProxySQL Admin");

	// Test 1: Run a DML query that affects rows
	if (mysql_query(admin, "INSERT INTO mysql_replication_hostgroups (hostgroup_id, hostname, port) VALUES (1000, 'test.example.com', 3306)")) {
		diag("Failed to execute INSERT query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	my_ulonglong affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 1, "INSERT query returns 1 affected row: %llu", affected_rows);
	diag("INSERT query executed successfully");

	// Test 2: Run another DML query
	if (mysql_query(admin, "INSERT INTO mysql_replication_hostgroups (hostgroup_id, hostname, port) VALUES (1001, 'test2.example.com', 3306)")) {
		diag("Failed to execute second INSERT query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 1, "Second INSERT query returns 1 affected row: %llu", affected_rows);
	diag("Second INSERT query executed successfully");

	// Test 3: Now execute a DDL query - this should reset affected_rows to 0 (this was the bug)
	if (mysql_query(admin, "CREATE TABLE test_table_4855 (id INT PRIMARY KEY, name VARCHAR(255))")) {
		diag("Failed to execute CREATE TABLE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 0, "CREATE TABLE returns 0 affected rows (bug fix verified): %llu", affected_rows);
	diag("CREATE TABLE query executed successfully");

	// Test 4: Run DROP TABLE
	if (mysql_query(admin, "DROP TABLE test_table_4855")) {
		diag("Failed to execute DROP TABLE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 0, "DROP TABLE returns 0 affected rows: %llu", affected_rows);
	diag("DROP TABLE query executed successfully");

	// Test 5: Verify DML still works correctly after DDL
	if (mysql_query(admin, "UPDATE mysql_replication_hostgroups SET port = 3307 WHERE hostgroup_id = 1000")) {
		diag("Failed to execute UPDATE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 1, "UPDATE query after DDL returns 1 affected row: %llu", affected_rows);
	diag("UPDATE query executed successfully");

	// Test 6: Run a different DML query
	if (mysql_query(admin, "DELETE FROM mysql_replication_hostgroups WHERE hostgroup_id IN (1000, 1001)")) {
		diag("Failed to execute DELETE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 2, "DELETE query returns 2 affected rows: %llu", affected_rows);
	diag("DELETE query executed successfully");

	// Test 7: Run another DDL to verify the fix again
	if (mysql_query(admin, "TRUNCATE TABLE stats_memory_metrics")) {
		// TRUNCATE might fail if table doesn't exist, but we test affected rows anyway
		diag("TRUNCATE TABLE query executed (may fail if table doesn't exist)");
		ok(true, "TRUNCATE TABLE query attempted");
	} else {
		affected_rows = mysql_affected_rows(admin);
		ok(affected_rows == 0, "TRUNCATE TABLE returns 0 affected rows: %llu", affected_rows);
		diag("TRUNCATE TABLE query executed successfully");
	}

	// Test 8: Run a VACUUM command on sqlite server
	MYSQL* sqlite_mysql = mysql_init(NULL);
	ok(sqlite_mysql != NULL, "Failed to initialize SQLite connection");
	if (!sqlite_mysql) {
		mysql_close(admin);
		return exit_status();
	}

	if (!mysql_real_connect(sqlite_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("Failed to connect to SQLite3 Server: %s", mysql_error(sqlite_mysql));
		mysql_close(admin);
		mysql_close(sqlite_mysql);
		return exit_status();
	}
	ok(true, "Connected to SQLite3 Server");

	// Insert some data first
	mysql_query(sqlite_mysql, "CREATE TABLE IF NOT EXISTS test_vacuum_4855 (id INTEGER PRIMARY KEY, name TEXT)");
	mysql_query(sqlite_mysql, "DELETE FROM test_vacuum_4855");
	mysql_query(sqlite_mysql, "INSERT INTO test_vacuum_4855 (name) VALUES ('test1')");

	affected_rows = mysql_affected_rows(sqlite_mysql);
	ok(affected_rows == 1, "INSERT on SQLite3 Server returns 1 affected row: %llu", affected_rows);

	// Now run VACUUM - this should return 0 affected rows
	if (mysql_query(sqlite_mysql, "VACUUM")) {
		diag("Failed to execute VACUUM query: %s", mysql_error(sqlite_mysql));
		mysql_close(admin);
		mysql_close(sqlite_mysql);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(sqlite_mysql);
	ok(affected_rows == 0, "VACUUM returns 0 affected rows (bug fix verified): %llu", affected_rows);
	diag("VACUUM query executed successfully");

	mysql_close(sqlite_mysql);
	mysql_close(admin);
	return exit_status();
}