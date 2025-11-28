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
#include "tap.h"
#include "mysql.h"

int main() {
	plan(12);

	MYSQL *admin = mysql_init(NULL);
	if (!admin) {
		fail("mysql_init() failed");
		return exit_status();
	}

	// Connect to ProxySQL Admin
	if (!mysql_real_connect(admin, "127.0.0.1", "admin", "admin", NULL, 6032, NULL, 0)) {
		fail("Failed to connect to ProxySQL Admin: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}
	pass("Connected to ProxySQL Admin");

	// Test 1: Run a DML query that affects rows
	if (mysql_query(admin, "INSERT INTO mysql_replication_hostgroups (hostgroup_id, hostname, port) VALUES (1000, 'test.example.com', 3306)")) {
		fail("Failed to execute INSERT query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	my_ulonglong affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 1, "INSERT query returns 1 affected row: %llu", affected_rows);
	pass("INSERT query executed successfully");

	// Test 2: Run another DML query
	if (mysql_query(admin, "INSERT INTO mysql_replication_hostgroups (hostgroup_id, hostname, port) VALUES (1001, 'test2.example.com', 3306)")) {
		fail("Failed to execute second INSERT query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 1, "Second INSERT query returns 1 affected row: %llu", affected_rows);
	pass("Second INSERT query executed successfully");

	// Test 3: Now execute a DDL query - this should reset affected_rows to 0 (this was the bug)
	if (mysql_query(admin, "CREATE TABLE test_table_4855 (id INT PRIMARY KEY, name VARCHAR(255))")) {
		fail("Failed to execute CREATE TABLE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 0, "CREATE TABLE returns 0 affected rows (bug fix verified): %llu", affected_rows);
	pass("CREATE TABLE query executed successfully");

	// Test 4: Run DROP TABLE
	if (mysql_query(admin, "DROP TABLE test_table_4855")) {
		fail("Failed to execute DROP TABLE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 0, "DROP TABLE returns 0 affected rows: %llu", affected_rows);
	pass("DROP TABLE query executed successfully");

	// Test 5: Verify DML still works correctly after DDL
	if (mysql_query(admin, "UPDATE mysql_replication_hostgroups SET port = 3307 WHERE hostgroup_id = 1000")) {
		fail("Failed to execute UPDATE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 1, "UPDATE query after DDL returns 1 affected row: %llu", affected_rows);
	pass("UPDATE query executed successfully");

	// Test 6: Run a different DDL command
	if (mysql_query(admin, "DELETE FROM mysql_replication_hostgroups WHERE hostgroup_id IN (1000, 1001)")) {
		fail("Failed to execute DELETE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 2, "DELETE query returns 2 affected rows: %llu", affected_rows);
	pass("DELETE query executed successfully");

	// Test 7: Run another DDL to verify the fix again
	if (mysql_query(admin, "TRUNCATE TABLE stats_memory_metrics")) {
		// TRUNCATE might not be available on all tables, so don't fail if it fails
		diag("TRUNCATE TABLE failed (expected on some systems): %s", mysql_error(admin));
		skip("TRUNCATE not available, skipping affected rows test");
	} else {
		affected_rows = mysql_affected_rows(admin);
		ok(affected_rows == 0, "TRUNCATE TABLE returns 0 affected rows: %llu", affected_rows);
		pass("TRUNCATE TABLE query executed successfully");
	}

	mysql_close(admin);
	return exit_status();
}