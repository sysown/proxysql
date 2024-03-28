#define PROXYSQL_EXTERN
#define MAIN_PROXY_SQLITE3
#include <stdlib.h>
#include <cstdint>
#include <cstring>
#include <memory>

#include "openssl/ssl.h"

#include "mysql.h"
#include "proxysql_structs.h"
#include "sqlite3db.h"
#include "MySQL_LDAP_Authentication.hpp"

#include "tap.h"
#include "command_line.h"

CommandLine cl;

MySQL_LDAP_Authentication* GloMyLdapAuth = nullptr;

int main() {
	SQLite3DB::LoadPlugin(NULL);
	plan(9);

	{
		int i=sqlite3_config(SQLITE_CONFIG_URI, 1);
		if (i!=SQLITE_OK) {
			fprintf(stderr,"SQLITE: Error on sqlite3_config(SQLITE_CONFIG_URI,1)\n");
		}
		ok(i==SQLITE_OK, "Setting SQLITE_CONFIG_URI");
	}

	SQLite3DB *db;	// in memory
	db = new SQLite3DB();
	db->open((char *)"file:mem_db?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	bool rc=db->check_and_build_table((char*)"test", (char*)"CREATE TABLE TEST (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306)");
	ok(rc, "TEST table is created");
	rc=db->execute("INSERT INTO TEST (hostname, port) VALUES ('localhost', 6033)");
	ok(rc, "Row is inserted");

	// Execute statement and get a result set in std::unique_ptr. will be automatically destroyed later.yy
	std::unique_ptr<SQLite3_result> result = std::unique_ptr<SQLite3_result>(db->execute_statement("SELECT * FROM TEST"));
	ok(nullptr != result, "Query result is not empty");

	// Execute statement and gets number of columns and error message (error message should be empty)
	int cols=0;
	char *error=NULL;
	std::unique_ptr<SQLite3_result> result_2 = std::unique_ptr<SQLite3_result>(db->execute_statement("SELECT * FROM TEST", &error, &cols));
	ok(nullptr != result_2, "Query result is not empty");
	ok(cols == 2, "Query returns correct number of columns");
	ok(!error, "No error message expected");

	// Execute statement and gets number of columns and error message (error message should be empty)
	error=NULL;
	std::unique_ptr<SQLite3_result> result_3 = std::unique_ptr<SQLite3_result>(db->execute_statement("SELECT * FROM TEST1", &error));
	ok(nullptr == result_3, "Query result is empty");
	ok(error != NULL, "There is an error message expected");

	return exit_status();
}

