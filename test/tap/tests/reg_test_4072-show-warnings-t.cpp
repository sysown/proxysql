/**
 * @file reg_test_4072-show-warnings-t.cpp
 * @brief This test will confirm ProxySQL does not crash if large records are fetched, having warning producing condition in the query.
 */

#include <stdio.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <mysql.h>
#include <mysql/mysqld_error.h>
#include "tap.h"
#include "command_line.h"
#include "utils.h" 

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(1);

	// Initialize Admin connection
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	// Connnect to ProxySQL Admin
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-log_mysql_warnings_enabled=1");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Initialize ProxySQL connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	// Connect to ProxySQL
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}
	MYSQL_QUERY(proxysql, "DROP DATABASE IF EXISTS testdb");
	MYSQL_QUERY(proxysql, "CREATE DATABASE testdb");
	MYSQL_QUERY(proxysql, "CREATE TABLE testdb.`tmp` ( " \
		"`id` bigint(20) NOT NULL AUTO_INCREMENT, " \
		"`text1` varchar(200) COLLATE utf8_bin NOT NULL, " \
		"`text2` varchar(200) COLLATE utf8_bin NOT NULL, " \
		"`time` datetime NOT NULL, " \
		"PRIMARY KEY(`id`,`time`) " \
		") ENGINE = InnoDB");

	diag("Inserting rows...");
	MYSQL_QUERY(proxysql, "INSERT INTO testdb.tmp(text1, text2, time) values('dummy text1', 'dummy text2', now())");

	for (int i = 0; i < 7; i++) {
		MYSQL_QUERY(proxysql, "INSERT INTO testdb.tmp(text1, text2, time) SELECT text1, text2, time FROM testdb.tmp");
	}

	std::this_thread::sleep_for(std::chrono::seconds(2));

	MYSQL_QUERY(proxysql, "SELECT COUNT(*) FROM testdb.tmp a JOIN testdb.tmp b JOIN testdb.tmp c");

	auto mysql_result = mysql_use_result(proxysql);

	if (!mysql_result) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}
	
	auto row = mysql_fetch_row(mysql_result);
	unsigned long add_row_count = strtoul(row[0], NULL, 0);

	if (mysql_result) {
		mysql_free_result(mysql_result);
		mysql_result = NULL;
	}

	diag("Done... Total rows to fetch:'%lu'", add_row_count);
	diag("Fetching all rows...");
	MYSQL_QUERY(proxysql, "SELECT a.* FROM testdb.tmp a JOIN testdb.tmp b JOIN testdb.tmp c WHERE 1/0 OR 1=1");

	mysql_result = mysql_use_result(proxysql);
		
	if (!mysql_result) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}

	unsigned long fetched_row_count = 0;

	while (row = mysql_fetch_row(mysql_result)) {
		fetched_row_count++;
		usleep(10);
	}
	
	int _errorno = mysql_errno(proxysql);
		
	if (_errorno) {
		diag("An error occurred. Error Code:%d, Message:%s", _errorno, mysql_error(proxysql));
		return exit_status();
	}

	if (mysql_result) {
		mysql_free_result(mysql_result);
		mysql_result = NULL;
	}

	diag("Done... Total rows fetched:'%lu'\n", fetched_row_count);
	ok(add_row_count == fetched_row_count, "All rows fetched");

	mysql_close(proxysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
