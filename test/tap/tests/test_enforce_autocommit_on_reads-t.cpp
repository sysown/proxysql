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

	plan(2+2 + 96);
	diag("Testing mysql-enforce_autocommit_on_reads");

	MYSQL* mysqladmin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysqladmin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysqladmin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysqladmin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysqladmin->net.compress, "Compression: (%d)", mysqladmin->net.compress);
	}

	MYSQL_QUERY(mysqladmin, "SET mysql-enforce_autocommit_on_reads=0");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	MYSQL* mysql = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
	}

	MYSQL_RES *res;
	if (create_table_test_sbtest1(100,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}
	diag("Waiting few seconds for replication...");
	sleep(2);
	MYSQL_QUERY(mysql, "USE test");


	MYSQL_QUERY(mysql, "set autocommit=0");
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
	MYSQL_QUERY(mysql, "SELECT * FROM sbtest1 WHERE id=1");
	res = mysql_store_result(mysql);
	ok(((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0) , "Line: %d: server_status: %u , AUTOCOMMIT %d", __LINE__ , mysql->server_status, mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	ok(((mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) , "Line: %d, server_status: %u , IN_TRANS = %d", __LINE__ , mysql->server_status,  mysql->server_status & SERVER_STATUS_IN_TRANS);
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



	MYSQL_QUERY(mysqladmin, "SET mysql-enforce_autocommit_on_reads=1");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

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


	MYSQL_QUERY(mysqladmin, "SET mysql-enforce_autocommit_on_reads=0");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	mysql_close(mysql);
	mysql_close(mysqladmin);

	return exit_status();
}

