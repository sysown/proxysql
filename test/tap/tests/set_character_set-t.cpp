#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(12);
	diag("Testing SET CHARACTER SET");

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();
	
	if (mysql_options(mysql, MYSQL_SET_CHARSET_NAME, "utf8")) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}

	if (mysql_query(mysql, "drop database if exists t1")) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (mysql_query(mysql, "create database t1 charset utf8")) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (mysql_query(mysql, "use t1")) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (mysql_query(mysql, "set names 'utf8'")) {
	    fprintf(stderr, "SET CHARACTER SET 'utf8': Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}

	std::string var_charset_client = "character_set_client";
	std::string var_charset_connection = "character_set_connection";
	std::string var_charset_results = "character_set_results";
	std::string var_charset_database = "character_set_database";
	std::string var_value;

	show_variable(mysql, var_charset_client, var_value);
	ok(var_value.compare("utf8") == 0, "Initial client character set. Actual %s", var_value.c_str()); // ok_1

	show_variable(mysql, var_charset_connection, var_value);
	ok(var_value.compare("utf8") == 0, "Initial connection character set. Actual %s", var_value.c_str()); // ok_2

	show_variable(mysql, var_charset_results, var_value);
	ok(var_value.compare("utf8") == 0, "Initial results character set. Actual %s", var_value.c_str()); // ok_3

	show_variable(mysql, var_charset_database, var_value);
	ok(var_value.compare("utf8") == 0, "Initial database character set. Actual %s", var_value.c_str()); // ok_4

	if (mysql_query(mysql, "set character set latin1")) {
	    fprintf(stderr, "SET CHARACTER SET : Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}

	show_variable(mysql, var_charset_client, var_value);
	ok(var_value.compare("latin1") == 0, "Client character set is changed. Actual %s", var_value.c_str()); // ok_5

	std::string db_charset_value;
	show_variable(mysql, var_charset_database, db_charset_value);

	show_variable(mysql, var_charset_database, var_value);
	ok(var_value.compare("utf8") == 0, "Database character set is not changed. Actual %s", var_value.c_str()); // ok_6

	show_variable(mysql, var_charset_connection, var_value);
	ok(var_value.compare(db_charset_value) == 0, "Connection character set same as database charset. Actual %s", var_value.c_str()); // ok_7

	show_variable(mysql, var_charset_results, var_value);
	ok(var_value.compare("latin1") == 0, "Results character set is changed. Actual %s", var_value.c_str()); // ok_8

	if (mysql_query(mysql, "set names latin1")) {
		fprintf(stderr, "SET NAMES : Error: %s\n",
				mysql_error(mysql));
		return exit_status();
	}

	show_variable(mysql, var_charset_client, var_value);
	ok(var_value.compare("latin1") == 0, "Client character set is correct. Actual %s", var_value.c_str()); // ok_9

	show_variable(mysql, var_charset_connection, var_value);
	ok(var_value.compare("latin1") == 0, "Set names changed connection character set. Actual %s", var_value.c_str()); // ok_10

	show_variable(mysql, var_charset_results, var_value);
	ok(var_value.compare("latin1") == 0, "Results character set is correct. Actual %s", var_value.c_str()); // ok_11

	show_variable(mysql, var_charset_database, var_value);
	ok(var_value.compare("utf8") == 0, "Database character set is not changed by set names. Actual %s", var_value.c_str()); // ok_12

	mysql_close(mysql);

	return exit_status();
}

