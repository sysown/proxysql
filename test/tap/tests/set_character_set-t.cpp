/**
 * @file set_character_set-t.cpp
 * @brief This test checks the proper behavior for 'SET CHARACTER SET'.
 * @details The test performs several 'SET' operations in sequence for testing the correct behavior
 *   for 'SET CHARACTER SET', this are:
 *
 *   1. SET NAMES 'utf8'.
 *   2. SET CHARACTER SET 'latin1'.
 *   3. SET NAMES 'latin1'.
 *
 *   After each of the operations several checks are performed for the following variables:
 *
 *   * character_set_client
 *   * character_set_connection
 *   * character_set_results
 *   * character_set_database
 *
 *   This checks are performed by means of the query:
 *
 *   ```
 *   SELECT variable_value FROM global_variables WHERE variable_name='%s'
 *   ```
 *
 *   For checking that this variables has changed or keep their values properly.
 *
 *   NOTE: After "SET CHARACTER SET 'latin1'" has been issued, no checks are performed for
 *   'character_set_connection' since, due to multiplexing and ProxySQL explicitely forgetting
 *   the value for 'character_set_connection' and 'collation_connection' (for more context
 *   see MySQL_Variables::client_set_value),the value for it is **unknown** and depends entirely
 *   of the backend connection selected. For more context see #3460.
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

int main(int argc, char** argv) {

	plan(2 + 11);
	diag("Testing SET CHARACTER SET");

	MYSQL* mysql = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	mysql_options(mysql, MYSQL_SET_CHARSET_NAME, "utf8");
	if (cl.use_ssl)
		mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
	}

	if (mysql_query(mysql, "drop database if exists test")) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (mysql_query(mysql, "create database test charset utf8")) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (mysql_query(mysql, "use test")) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (mysql_query(mysql, "set names 'utf8'")) {
		fprintf(stderr, "SET NAMES 'utf8': Error: %s\n", mysql_error(mysql));
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
		fprintf(stderr, "SET CHARACTER SET : Error: %s\n", mysql_error(mysql));
		return exit_status();
	}

	show_variable(mysql, var_charset_client, var_value);
	ok(var_value.compare("latin1") == 0, "Client character set is changed. Actual %s", var_value.c_str()); // ok_5

	std::string db_charset_value;
	show_variable(mysql, var_charset_database, db_charset_value);

	show_variable(mysql, var_charset_database, var_value);
	ok(var_value.compare("utf8") == 0, "Database character set is not changed. Actual %s", var_value.c_str()); // ok_6

	/*
	 * NOTE: This check was disabled because trying to check 'character_set_connection' after issuing 'SET CHARACTER SET',
	 * when multiplexing is enabled is invalid, since the value is unknown. Check file top for more details.
	 *
	 * show_variable(mysql, var_charset_connection, var_value);
	 * ok(var_value.compare(db_charset_value) == 0, "Connection character set same as database charset. Actual %s", var_value.c_str()); // ok_
	 */

	show_variable(mysql, var_charset_results, var_value);
	ok(var_value.compare("latin1") == 0, "Results character set is changed. Actual %s", var_value.c_str()); // ok_7

	if (mysql_query(mysql, "set names latin1")) {
		fprintf(stderr, "SET NAMES : Error: %s\n", mysql_error(mysql));
		return exit_status();
	}

	show_variable(mysql, var_charset_client, var_value);
	ok(var_value.compare("latin1") == 0, "Client character set is correct. Actual %s", var_value.c_str()); // ok_8

	show_variable(mysql, var_charset_connection, var_value);
	ok(var_value.compare("latin1") == 0, "Set names changed connection character set. Actual %s", var_value.c_str()); // ok_9

	show_variable(mysql, var_charset_results, var_value);
	ok(var_value.compare("latin1") == 0, "Results character set is correct. Actual %s", var_value.c_str()); // ok_10

	show_variable(mysql, var_charset_database, var_value);
	ok(var_value.compare("utf8") == 0, "Database character set is not changed by set names. Actual %s", var_value.c_str()); // ok_11

	mysql_close(mysql);

	return exit_status();
}

