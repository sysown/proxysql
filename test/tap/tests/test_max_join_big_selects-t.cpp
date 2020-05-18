#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(10);
	diag("Testing session variables: max_join_size and sql_big_selects");

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}

	MYSQL_RES* result = NULL;
	std::string value;

	// Case 1: set sql_big_select=1
	MYSQL_QUERY(mysql, "set sql_big_selects=1");
	MYSQL_QUERY(mysql, "select /* 1 */ 1");
	result = mysql_store_result(mysql);
	mysql_free_result(result);

	show_variable(mysql, "sql_big_selects", value);
	ok(value == "ON", "Case 1: set sql_big_select=1. SQL_BIG_SELECTS should be initialized to ON. Actual value [%s]", value.c_str()); // ok_1

	// Case 2: setting max_join_size to value less than maximum should reset sql_big_selects to OFF
	MYSQL_QUERY(mysql, "set max_join_size=10000000");
	MYSQL_QUERY(mysql, "select /* 2 */ 1");
	result = mysql_store_result(mysql);
	mysql_free_result(result);

	show_variable(mysql, "sql_big_selects", value);
	ok(value == "OFF", "Case 2: setting max_join_size to value less than maximum should reset sql_big_selects to OFF. SQL_BIG_SELECTS should be initialized to OFF. Actual value [%s]", value.c_str()); // ok_2

	// Case 3 : setting max_join_size to max value should reset sql_big_selects to ON
	MYSQL_QUERY(mysql, "set sql_big_selects=0");
	MYSQL_QUERY(mysql, "select /* 3 */ 1");
	result = mysql_store_result(mysql);
	mysql_free_result(result);

	show_variable(mysql, "sql_big_selects", value);
	ok(value == "OFF", "SQL_BIG_SELECTS should be initialized to ON. Actual value [%s]", value.c_str()); // ok_3

	MYSQL_QUERY(mysql, "set max_join_size=18446744073709551615");
	MYSQL_QUERY(mysql, "select /* 4 */ 1");
	result = mysql_store_result(mysql);
	mysql_free_result(result);

	show_variable(mysql, "sql_big_selects", value);
	ok(value == "ON", "Case 3 : setting max_join_size to max value should reset sql_big_selects to ON. SQL_BIG_SELECTS should be initialized to ON. Actual value [%s]", value.c_str()); // ok_4

	// Case 4 : setting sql_big_selects for unchanged NOT maximum max_join_size
	MYSQL_QUERY(mysql, "set max_join_size=1844677");
	MYSQL_QUERY(mysql, "select /* 5 */ 1");
	result = mysql_store_result(mysql);
	mysql_free_result(result);

	show_variable(mysql, "sql_big_selects", value);
	ok(value == "OFF", "SQL_BIG_SELECTS should be initialized to OFF. Actual value [%s]", value.c_str()); // ok_5

	MYSQL_QUERY(mysql, "set sql_big_selects=0");
	MYSQL_QUERY(mysql, "select /* 6 */ 1");
	result = mysql_store_result(mysql);
	mysql_free_result(result);

	show_variable(mysql, "sql_big_selects", value);
	ok(value == "OFF", "SQL_BIG_SELECTS should be initialized to OFF. Actual value [%s]", value.c_str()); // ok_6

	MYSQL_QUERY(mysql, "set sql_big_selects=1");
	MYSQL_QUERY(mysql, "select /* 7 */ 1");
	result = mysql_store_result(mysql);
	mysql_free_result(result);

	show_variable(mysql, "sql_big_selects", value);
	ok(value == "ON", "SQL_BIG_SELECTS should be initialized to ON. Actual value [%s]", value.c_str()); // ok_7

	MYSQL_QUERY(mysql, "set sql_big_selects=0");
	MYSQL_QUERY(mysql, "select /* 8 */ 1");
	result = mysql_store_result(mysql);
	mysql_free_result(result);

	show_variable(mysql, "sql_big_selects", value);
	ok(value == "OFF", "Case 4 : setting sql_big_selects for unchanged NOT maximum max_join_size. SQL_BIG_SELECTS should be initialized to OFF. Actual value [%s]", value.c_str()); // ok_8

	// Case 5 : setting sql_big_selects for unchanged maximum max_join_size
	MYSQL_QUERY(mysql, "set max_join_size=18446744073709551615");
	MYSQL_QUERY(mysql, "select /* 9 */ 1");
	result = mysql_store_result(mysql);
	mysql_free_result(result);

	MYSQL_QUERY(mysql, "set sql_big_selects=1");
	MYSQL_QUERY(mysql, "select /* 10 */ 1");
	result = mysql_store_result(mysql);
	mysql_free_result(result);

	show_variable(mysql, "sql_big_selects", value);
	ok(value == "ON", "SQL_BIG_SELECTS should be initialized to ON. Actual value [%s]", value.c_str()); // ok_9

	MYSQL_QUERY(mysql, "set sql_big_selects=0");
	MYSQL_QUERY(mysql, "select /* 11 */ 1");
	result = mysql_store_result(mysql);
	mysql_free_result(result);

	show_variable(mysql, "sql_big_selects", value);
	ok(value == "OFF", "Case 5 : setting sql_big_selects for unchanged maximum max_join_size. SQL_BIG_SELECTS should be initialized to OFF. Actual value [%s]", value.c_str()); // ok_10

	mysql_close(mysql);

	return exit_status();
}

