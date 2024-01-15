/**
 * @file reg_test_1574-mariadb_read_stmt_execute_response-t.cpp
 * @brief This test is a regression test for issue #1574. In the fix for this issue some changes were
 * introduced into 'read_stmt_execute_response'. These modifications prevent 'mariadb client library'
 * from returning CR_NEW_STMT_METADATA in case 'stmt' and 'mysql' fields count doesn't match, instead,
 * replaces current stmt fields with the ones returned with the resulset.
 *
 * @details For checking that this behavior is correct, the test creates a fixed number of tables,
 * and prepares a query for all of them. Later the tables are altered, changing their number of
 * columns. Finally the statements are executed and the number of fields are check after the execute;
 * none error should take place during the executes and after each execute the number of fields
 * should match the new (altered) version of the table.
 *
 * @date 2021-02-15
 */

#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

CommandLine cl;

const int STRING_SIZE=32;
const int NUM_TEST_TABLES = 50;

int main(int argc, char** argv) {

	plan(50);

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	diag("Connecting to '%s@%s:%d'", cl.mysql_username, cl.mysql_host, cl.mysql_port);
//	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, 13306, NULL, 0)) {
	if (!mysql_real_connect(mysql, cl.mysql_host, cl.mysql_username, cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	MYSQL_QUERY(mysql, "CREATE DATABASE IF NOT EXISTS test");
	std::string create_table_query_t =
		"CREATE TEMPORARY TABLE IF NOT EXISTS test.reg_test_read_execute_response_1574_%d (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, `c2` varchar(32))";

	for (int i = 0; i < NUM_TEST_TABLES; i++) {
		std::string create_table_query (static_cast<std::size_t>(create_table_query_t.size() + 10), '\0');
		snprintf(&create_table_query[0], create_table_query.size(), create_table_query_t.c_str(), i);
		MYSQL_QUERY(mysql, create_table_query.c_str());
	}

	std::string select_query_t = "SELECT * FROM test.reg_test_read_execute_response_1574_%d";
	std::vector<MYSQL_STMT*> stmts {};

	// Initialize and prepare all the statements
	for (int i = 0; i < NUM_TEST_TABLES; i++) {
		MYSQL_STMT* stmt = mysql_stmt_init(mysql);
		if (!stmt) {
			ok(false, "mysql_stmt_init(), out of memory\n");
			return exit_status();
		}

		std::string select_query (static_cast<std::size_t>(select_query_t.size() + 10), '\0');
		snprintf(&select_query[0], select_query.size(), select_query_t.c_str(), i);

		// Prepare all the statements
		if (mysql_stmt_prepare(stmt, select_query.c_str(), strlen(select_query.c_str()))) {
			diag("select_query: %s", select_query.c_str());
			ok(false, "mysql_stmt_prepare at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
			mysql_close(mysql);
			mysql_library_end();
			return exit_status();
		}

		stmts.push_back(stmt);
	}

	// Alter the tables either dropping or adding columns
	for (int i = 0; i < NUM_TEST_TABLES; i++) {
		std::string alter_table_query_t {};

		if (i % 2 == 0) {
			alter_table_query_t = "ALTER TABLE test.reg_test_read_execute_response_1574_%d ADD c1 BIGINT AFTER id";
		} else {
			alter_table_query_t = "ALTER TABLE test.reg_test_read_execute_response_1574_%d DROP COLUMN c2";
		}

		std::string alter_table_query (static_cast<std::size_t>(alter_table_query_t.size() + 10), '\0');
		snprintf(&alter_table_query[0], alter_table_query.size(), alter_table_query_t.c_str(), i);

		MYSQL_QUERY(mysql, alter_table_query.c_str());
	}

	// Execute the prepared statement and check that the field count is correct after doing the execute
	for (int i = 0; i < NUM_TEST_TABLES; i++) {
		MYSQL_STMT* stmt = stmts[i];
		if (mysql_stmt_execute(stmt)) {
			ok(false, "mysql_stmt_execute at line %d failed: %s\n", __LINE__ , mysql_stmt_error(stmt));
		}

		int field_count = mysql_stmt_field_count(stmt);
		if (i % 2 == 0) {
			ok(field_count == 3, "Field count should be '3' in case of 'i %% 2' being '0'");
		} else {
			ok(field_count == 1, "Field count should be '1' in case of 'i %% 2' being '1'");
		}

		if (mysql_stmt_close(stmt))
		{
			ok(false, "mysql_stmt_close at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
			return exit_status();
		}
	}

	mysql_close(mysql);

	return exit_status();
}
