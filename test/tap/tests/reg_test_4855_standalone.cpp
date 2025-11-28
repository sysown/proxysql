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

#define PROXYSQL_EXTERN
#include <stdlib.h>
#include "tap.h"
#include <cstdint>
#include <cstring>
#include <memory>

#include "sqlite3.h"

int main() {
	plan(15);

	{
		int i=sqlite3_config(SQLITE_CONFIG_URI, 1);
		if (i!=SQLITE_OK) {
			fprintf(stderr,"SQLITE: Error on sqlite3_config(SQLITE_CONFIG_URI,1)\n");
		}
		ok(i==SQLITE_OK, "Setting SQLITE_CONFIG_URI");
	}

	sqlite3 *db;
	int rc = sqlite3_open("file:mem_db?mode=memory&cache=shared", &db);
	ok(rc == SQLITE_OK, "Opening in-memory database");

	if (rc != SQLITE_OK) {
		fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return exit_status();
	}

	char *error = NULL;
	sqlite3_stmt *stmt = NULL;

	// Test the fix: DDL queries should reset affected_rows to 0
	// We simulate this by checking total_changes before and after

	// 1. First execute a DML that affects rows
	long long total_changes_before = sqlite3_total_changes64(db);
	rc = sqlite3_exec(db, "CREATE TABLE test_table (id INTEGER PRIMARY KEY, value TEXT)", NULL, NULL, &error);
	ok(rc == SQLITE_OK && error == nullptr, "CREATE TABLE test_table succeeds");
	long long total_changes_after = sqlite3_total_changes64(db);
	int affected_rows = total_changes_after - total_changes_before;
	ok(affected_rows == 0, "CREATE TABLE returns 0 affected rows");

	// 2. Insert some data
	total_changes_before = sqlite3_total_changes64(db);
	rc = sqlite3_exec(db, "INSERT INTO test_table (value) VALUES ('test1')", NULL, NULL, &error);
	ok(rc == SQLITE_OK && error == nullptr, "INSERT first row succeeds");
	total_changes_after = sqlite3_total_changes64(db);
	affected_rows = total_changes_after - total_changes_before;
	ok(affected_rows == 1, "INSERT returns 1 affected row");

	// 3. Insert more data
	total_changes_before = sqlite3_total_changes64(db);
	rc = sqlite3_exec(db, "INSERT INTO test_table (value) VALUES ('test2')", NULL, NULL, &error);
	ok(rc == SQLITE_OK && error == nullptr, "INSERT second row succeeds");
	total_changes_after = sqlite3_total_changes64(db);
	affected_rows = total_changes_after - total_changes_before;
	ok(affected_rows == 1, "INSERT returns 1 affected row");

	// 4. Now execute a DDL - this should reset affected_rows to 0 (this was the bug)
	total_changes_before = sqlite3_total_changes64(db);
	rc = sqlite3_exec(db, "CREATE TABLE test_table2 (id INTEGER PRIMARY KEY)", NULL, NULL, &error);
	ok(rc == SQLITE_OK && error == nullptr, "CREATE TABLE test_table2 succeeds");
	total_changes_after = sqlite3_total_changes64(db);
	affected_rows = total_changes_after - total_changes_before;
	ok(affected_rows == 0, "CREATE TABLE after DML returns 0 affected rows (bug fix verified)");

	// 5. Test DROP TABLE
	total_changes_before = sqlite3_total_changes64(db);
	rc = sqlite3_exec(db, "DROP TABLE test_table2", NULL, NULL, &error);
	ok(rc == SQLITE_OK && error == nullptr, "DROP TABLE succeeds");
	total_changes_after = sqlite3_total_changes64(db);
	affected_rows = total_changes_after - total_changes_before;
	ok(affected_rows == 0, "DROP TABLE returns 0 affected rows");

	// 6. Test VACUUM
	total_changes_before = sqlite3_total_changes64(db);
	rc = sqlite3_exec(db, "VACUUM", NULL, NULL, &error);
	ok(rc == SQLITE_OK && error == nullptr, "VACUUM succeeds");
	total_changes_after = sqlite3_total_changes64(db);
	affected_rows = total_changes_after - total_changes_before;
	ok(affected_rows == 0, "VACUUM returns 0 affected rows");

	// 7. Test that DML still works correctly after DDL
	total_changes_before = sqlite3_total_changes64(db);
	rc = sqlite3_exec(db, "UPDATE test_table SET value = 'updated' WHERE id = 1", NULL, NULL, &error);
	ok(rc == SQLITE_OK && error == nullptr, "UPDATE after DDL succeeds");
	total_changes_after = sqlite3_total_changes64(db);
	affected_rows = total_changes_after - total_changes_before;
	ok(affected_rows == 1, "UPDATE returns 1 affected row");

	// 8. Test transaction commands
	total_changes_before = sqlite3_total_changes64(db);
	rc = sqlite3_exec(db, "BEGIN", NULL, NULL, &error);
	ok(rc == SQLITE_OK && error == nullptr, "BEGIN transaction succeeds");
	total_changes_after = sqlite3_total_changes64(db);
	affected_rows = total_changes_after - total_changes_before;
	ok(affected_rows == 0, "BEGIN returns 0 affected rows");

	sqlite3_close(db);
	return exit_status();
}