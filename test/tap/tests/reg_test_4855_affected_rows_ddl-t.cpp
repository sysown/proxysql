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

#include "openssl/ssl.h"

#include "mysql.h"
#include "proxysql_structs.h"
#include "sqlite3db.h"
#include "MySQL_LDAP_Authentication.hpp"

MySQL_LDAP_Authentication* GloMyLdapAuth = nullptr;

int main() {
	SQLite3DB::LoadPlugin(NULL);
	plan(15);

	{
		int i=sqlite3_config(SQLITE_CONFIG_URI, 1);
		if (i!=SQLITE_OK) {
			fprintf(stderr,"SQLITE: Error on sqlite3_config(SQLITE_CONFIG_URI,1)\n");
		}
		ok(i==SQLITE_OK, "Setting SQLITE_CONFIG_URI");
	}

	SQLite3DB *db;
	db = new SQLite3DB();
	db->open((char *)"file:mem_db?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

	char *error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result *resultset = NULL;

	// Test the fix: DDL queries should reset affected_rows to 0

	// 1. First execute a DML that affects rows
	bool rc = db->execute_statement("CREATE TABLE test_table (id INTEGER PRIMARY KEY, value TEXT)", &error, &cols, &affected_rows, &resultset);
	ok(rc && error == nullptr, "CREATE TABLE test_table succeeds");
	ok(affected_rows == 0, "CREATE TABLE returns 0 affected rows");

	// 2. Insert some data
	error = NULL; cols = 0; affected_rows = 0; resultset = NULL;
	rc = db->execute_statement("INSERT INTO test_table (value) VALUES ('test1')", &error, &cols, &affected_rows, &resultset);
	ok(rc && error == nullptr, "INSERT first row succeeds");
	ok(affected_rows == 1, "INSERT returns 1 affected row");

	// 3. Insert more data
	error = NULL; cols = 0; affected_rows = 0; resultset = NULL;
	rc = db->execute_statement("INSERT INTO test_table (value) VALUES ('test2')", &error, &cols, &affected_rows, &resultset);
	ok(rc && error == nullptr, "INSERT second row succeeds");
	ok(affected_rows == 1, "INSERT returns 1 affected row");

	// 4. Now execute a DDL - this should reset affected_rows to 0 (this was the bug)
	error = NULL; cols = 0; affected_rows = 0; resultset = NULL;
	rc = db->execute_statement("CREATE TABLE test_table2 (id INTEGER PRIMARY KEY)", &error, &cols, &affected_rows, &resultset);
	ok(rc && error == nullptr, "CREATE TABLE test_table2 succeeds");
	ok(affected_rows == 0, "CREATE TABLE after DML returns 0 affected rows (bug fix verified)");

	// 5. Test DROP TABLE
	error = NULL; cols = 0; affected_rows = 0; resultset = NULL;
	rc = db->execute_statement("DROP TABLE test_table2", &error, &cols, &affected_rows, &resultset);
	ok(rc && error == nullptr, "DROP TABLE succeeds");
	ok(affected_rows == 0, "DROP TABLE returns 0 affected rows");

	// 6. Test VACUUM
	error = NULL; cols = 0; affected_rows = 0; resultset = NULL;
	rc = db->execute_statement("VACUUM", &error, &cols, &affected_rows, &resultset);
	ok(rc && error == nullptr, "VACUUM succeeds");
	ok(affected_rows == 0, "VACUUM returns 0 affected rows");

	// 7. Test that DML still works correctly after DDL
	error = NULL; cols = 0; affected_rows = 0; resultset = NULL;
	rc = db->execute_statement("UPDATE test_table SET value = 'updated' WHERE id = 1", &error, &cols, &affected_rows, &resultset);
	ok(rc && error == nullptr, "UPDATE after DDL succeeds");
	ok(affected_rows == 1, "UPDATE returns 1 affected row");

	// 8. Test transaction commands
	error = NULL; cols = 0; affected_rows = 0; resultset = NULL;
	rc = db->execute_statement("BEGIN", &error, &cols, &affected_rows, &resultset);
	ok(rc && error == nullptr, "BEGIN transaction succeeds");
	ok(affected_rows == 0, "BEGIN returns 0 affected rows");

	delete db;
	return exit_status();
}