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

CommandLine cl;

/*
This test includes a lot of repetitive checks that could have been organized into functions.
But they have been left in this way to easily identify the failed check
*/


int main(int argc, char** argv) {

	plan(2 + 48);
	diag("Testing autocommit and transaction in SQLite3 Server");

	MYSQL* mysql = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	mysql_options(mysql, MYSQL_SET_CHARSET_NAME, "utf8");
	if (cl.use_ssl)
		mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, 6030, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
	}

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

