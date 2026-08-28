#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

/*
This test includes a lot of repetitive checks that could have been organized into functions.
But they have been left in this way to easily identify the failed check
*/


int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(48);

	// Verbose test header
	diag("================================================================================");
	diag("Test: sqlite_autocommit-t");
	diag("================================================================================");
	diag("This test verifies that ProxySQL correctly handles autocommit and transaction");
	diag("status flags when communicating with a SQLite3 backend server.");
	diag("%s", "");
	diag("Test scenarios:");
	diag("  - SET autocommit=0: Verify SERVER_STATUS_AUTOCOMMIT is cleared");
	diag("  - SET autocommit=1: Verify SERVER_STATUS_AUTOCOMMIT is set");
	diag("  - SELECT queries: Verify SERVER_STATUS_IN_TRANS is correctly set/cleared");
	diag("  - FOR UPDATE and LOCK IN SHARE MODE: Verify transaction state");
	diag("  - UPDATE queries: Verify transaction state during DML operations");
	diag("  - COMMIT: Verify transaction state is cleared after commit");
	diag("%s", "");
	diag("Connection parameters:");
	diag("  - Host: %s", cl.host);
	diag("  - Port: 6030 (SQLite3 Server)");
	diag("  - Username: %s", cl.username);
	diag("================================================================================");
	diag("%s", "");

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		diag("Failed to initialize MySQL handle");
		return exit_status();
	}

	diag("Attempting to connect to SQLite3 Server at %s:6030", cl.host);
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, 6030, NULL, 0)) {
		diag("Failed to connect to SQLite3 Server: Error: %s", mysql_error(mysql));
		diag("Connection details: host=%s, port=6030, username=%s", cl.host, cl.username);
		return exit_status();
	}
	diag("Successfully connected to SQLite3 Server");
	diag("%s", "");
	MYSQL_RES *res;
	if (create_table_test_sqlite_sbtest1(100,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}

	MYSQL_QUERY(mysql, "set autocommit=0");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	MYSQL_QUERY(mysql, "SELECT * FROM sbtest1 WHERE id=1");
	res = mysql_store_result(mysql);
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 1) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	mysql_free_result(res);
	MYSQL_QUERY(mysql, "COMMIT");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);

	MYSQL_QUERY(mysql, "set autocommit=0");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	MYSQL_QUERY(mysql, "SELECT * FROM sbtest1 WHERE id=2 FOR UPDATE");
	res = mysql_store_result(mysql);
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 1) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	mysql_free_result(res);
	MYSQL_QUERY(mysql, "COMMIT");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);

	MYSQL_QUERY(mysql, "set autocommit=0");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	MYSQL_QUERY(mysql, "SELECT * FROM sbtest1 WHERE id=2 LOCK IN SHARE MODE");
	res = mysql_store_result(mysql);
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 1) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	mysql_free_result(res);
	MYSQL_QUERY(mysql, "COMMIT");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	MYSQL_QUERY(mysql, "set autocommit=1");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	MYSQL_QUERY(mysql, "SELECT * FROM sbtest1 WHERE id=1");
	res = mysql_store_result(mysql);
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	mysql_free_result(res);
	MYSQL_QUERY(mysql, "COMMIT");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);

	MYSQL_QUERY(mysql, "set autocommit=1");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	MYSQL_QUERY(mysql, "SELECT * FROM sbtest1 WHERE id=2 FOR UPDATE");
	res = mysql_store_result(mysql);
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	mysql_free_result(res);
	MYSQL_QUERY(mysql, "COMMIT");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);

	MYSQL_QUERY(mysql, "set autocommit=1");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	MYSQL_QUERY(mysql, "SELECT * FROM sbtest1 WHERE id=2 LOCK IN SHARE MODE");
	res = mysql_store_result(mysql);
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	mysql_free_result(res);
	MYSQL_QUERY(mysql, "COMMIT");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);

	MYSQL_QUERY(mysql, "set autocommit=0");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	MYSQL_QUERY(mysql, "UPDATE sbtest1 SET k=k+1 WHERE id=2");
	res = mysql_store_result(mysql);
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 1) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	mysql_free_result(res);
	MYSQL_QUERY(mysql, "COMMIT");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);

	MYSQL_QUERY(mysql, "set autocommit=1");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	MYSQL_QUERY(mysql, "UPDATE sbtest1 SET k=k+1 WHERE id=2");
	res = mysql_store_result(mysql);
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	mysql_free_result(res);
	MYSQL_QUERY(mysql, "COMMIT");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 2) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);

	mysql_close(mysql);

	return exit_status();
}

