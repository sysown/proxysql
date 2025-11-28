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
	plan(14);

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

	// Clean up any existing test tables
	mysql_query(admin, "DROP TABLE IF EXISTS test_table_4855");
	mysql_query(admin, "DROP TABLE IF EXISTS test_table_4855_2");

	// Test 1: Run a DDL query - should return 0 affected rows (this was the bug)
	if (mysql_query(admin, "CREATE TABLE test_table_4855 (id INT PRIMARY KEY, name VARCHAR(255))")) {
		diag("Failed to execute CREATE TABLE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	my_ulonglong affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 0, "CREATE TABLE returns 0 affected rows (bug fix verified): %llu", affected_rows);
	diag("CREATE TABLE query executed successfully");

	// Test 2: Run a DML query that affects rows
	if (mysql_query(admin, "INSERT INTO test_table_4855 (id, name) VALUES (1, 'test1')")) {
		diag("Failed to execute INSERT query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 1, "INSERT query returns 1 affected row: %llu", affected_rows);
	diag("INSERT query executed successfully");

	// Test 3: Run another DML query
	if (mysql_query(admin, "INSERT INTO test_table_4855 (id, name) VALUES (2, 'test2')")) {
		diag("Failed to execute second INSERT query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 1, "Second INSERT query returns 1 affected row: %llu", affected_rows);
	diag("Second INSERT query executed successfully");

	// Test 4: Run another DDL query - should return 0 affected rows
	if (mysql_query(admin, "CREATE TABLE test_table_4855_2 (id INT PRIMARY KEY, value TEXT)")) {
		diag("Failed to execute second CREATE TABLE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 0, "Second CREATE TABLE returns 0 affected rows: %llu", affected_rows);
	diag("Second CREATE TABLE query executed successfully");

	// Test 5: Run an UPDATE query - should return correct affected rows
	if (mysql_query(admin, "UPDATE test_table_4855 SET name = 'updated' WHERE id = 1")) {
		diag("Failed to execute UPDATE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 1, "UPDATE query returns 1 affected row: %llu", affected_rows);
	diag("UPDATE query executed successfully");

	// Test 6: Run a DELETE query - should return correct affected rows
	if (mysql_query(admin, "DELETE FROM test_table_4855 WHERE id IN (1, 2)")) {
		diag("Failed to execute DELETE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 2, "DELETE query returns 2 affected rows: %llu", affected_rows);
	diag("DELETE query executed successfully");

	// Test 7: Run DROP TABLE - should return 0 affected rows
	if (mysql_query(admin, "DROP TABLE test_table_4855")) {
		diag("Failed to execute DROP TABLE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 0, "DROP TABLE returns 0 affected rows: %llu", affected_rows);
	diag("DROP TABLE query executed successfully");

	// Test 8: Run another DDL to verify the fix again (ALTER TABLE)
	if (mysql_query(admin, "ALTER TABLE test_table_4855_2 ADD COLUMN extra INTEGER")) {
		diag("Failed to execute ALTER TABLE query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 0, "ALTER TABLE returns 0 affected rows: %llu", affected_rows);
	diag("ALTER TABLE query executed successfully");

	// Test 9: Test with comments followed by DDL (this was mentioned in the issue)
	if (mysql_query(admin, "/* This is a comment */ CREATE TABLE test_table_4855 (id INT PRIMARY KEY)")) {
		diag("Failed to execute CREATE TABLE with comment: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 0, "CREATE TABLE with comment returns 0 affected rows: %llu", affected_rows);
	diag("CREATE TABLE with comment executed successfully");

	// Test 10: Insert data and run SELECT to verify normal operation
	if (mysql_query(admin, "INSERT INTO test_table_4855 (id) VALUES (1), (2), (3)")) {
		diag("Failed to execute INSERT with multiple values: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 3, "INSERT with multiple values returns 3 affected rows: %llu", affected_rows);
	diag("INSERT with multiple values executed successfully");

	// Test 11: Run VACUUM - should return 0 affected rows
	if (mysql_query(admin, "VACUUM")) {
		diag("Failed to execute VACUUM query: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 0, "VACUUM returns 0 affected rows: %llu", affected_rows);
	diag("VACUUM query executed successfully");

	// Test 12: Clean up - DROP remaining tables individually
	if (mysql_query(admin, "DROP TABLE IF EXISTS test_table_4855")) {
		diag("Failed to execute final DROP TABLE: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	affected_rows = mysql_affected_rows(admin);
	ok(affected_rows == 0, "Final DROP TABLE returns 0 affected rows: %llu", affected_rows);
	diag("Final DROP TABLE query executed successfully");

	// Additional cleanup without test assertion
	if (mysql_query(admin, "DROP TABLE IF EXISTS test_table_4855_2")) {
		diag("Failed to execute second DROP TABLE: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}
	diag("Additional cleanup DROP TABLE executed");
	mysql_close(admin);
	return exit_status();
}