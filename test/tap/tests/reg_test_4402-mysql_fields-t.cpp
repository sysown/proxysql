/**
 * @file reg_test_4402-mysql-fields-t.cpp
 * @brief This TAP test checks if the length of the column alias and table alias surpasses 250 characters, 
 *		should not impact MySQL field name length (MySQL_FIELD::name_length) and the MySQL field database length (MySQL_FIELD::db_length)
 */

#include <stdio.h>
#include <unistd.h>
#include <string>
#include <thread>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h" 

#define MYSQL_QUERY__(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			goto cleanup; \
		} \
	} while(0)

CommandLine cl;

std::string generate_random_string(size_t length) {
	std::srand(static_cast<unsigned int>(std::time(nullptr)));
	static const char characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static const int numCharacters = (sizeof(characters) - 1)/ sizeof(char);

	std::string randomString;
	randomString.reserve(length);

	for (size_t i = 0; i < length; ++i) {
		char randomChar = characters[std::rand() % numCharacters];
		randomString.push_back(randomChar);
	}

	return randomString;
}

int main(int argc, char** argv) {

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(256*2);

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

	MYSQL_QUERY__(proxysql, "DROP DATABASE IF EXISTS testdb");
	MYSQL_QUERY__(proxysql, "CREATE DATABASE testdb");

	diag("Creating echo_int function...");
	MYSQL_QUERY__(proxysql, "CREATE FUNCTION testdb.echo_int(N INT) RETURNS INT DETERMINISTIC RETURN N;");
	
	diag("Creating dummy_table...");
	MYSQL_QUERY__(proxysql, "CREATE TABLE testdb.dummy_table(data VARCHAR(10))");

	// wait for replication
	std::this_thread::sleep_for(std::chrono::seconds(2));
	
	// alias maximum length is 256.  
	// https://dev.mysql.com/doc/refman/8.2/en/identifier-length.html
	// https://mariadb.com/kb/en/identifier-names/#maximum-length
	for (unsigned int length = 1; length <= 256; length++) {

		// to check column alias issue:
		{
			// NOTE: The randomly generated string should be escaped \`\`, otherwise could collide
			// with SQL reserved words, causing an invalid test failure.
			const std::string& query = "SELECT testdb.echo_int(1) AS `" + generate_random_string(length) + "`";
			MYSQL_QUERY__(proxysql, query.c_str());

			MYSQL_RES* res = mysql_use_result(proxysql);
			if (!res) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
				return exit_status();
			}

			MYSQL_FIELD* field = mysql_fetch_fields(res);

			ok(field->name_length == length, "name_length: '%u'. Expected length: '%u'", field->name_length, length);

			if (res) {
				mysql_free_result(res);
				res = NULL;
			}
		}

		// to check table alias issue:
		{
			const std::string& query = "SELECT data FROM testdb.dummy_table AS " + generate_random_string(length);
			MYSQL_QUERY__(proxysql, query.c_str());

			MYSQL_RES* res = mysql_use_result(proxysql);
			if (!res) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
				return exit_status();
			}

			MYSQL_FIELD* field = mysql_fetch_fields(res);

			ok(field->db_length == (sizeof("testdb")-1), "db_length: '%u'. Expected length: '%u'", 
				field->db_length, (unsigned int)(sizeof("testdb")-1));

			if (res) {
				mysql_free_result(res);
				res = NULL;
			}
		}
	}
cleanup:
	mysql_query(proxysql, "DROP DATABASE IF EXISTS testdb");
	mysql_close(proxysql);

	return exit_status();
}
