/**
 * @file reg_test_1574-stmt_metadata-t.cpp
 * @brief This test is a regression test for issue #1574.
 * @details The test checks that the metadata for a prepared statement is properly updated by ProxySQL
 *   after a single 'mysql_stmt_execute' and that the resulset received by the client is correct.
 *   The test performs the following actions:
 *     1. Prepares a prepared statement to 'SELECT *' from a table with only 2 columns.
 *     2. Runs an 'ALTER TABLE' on that table, adding a new column and inserts new data into it.
 *     3. Check the ProxySQL holds the old METADATA information in 'stats_mysql_prepared_statements_info'.
 *     4. Performs an execute of the prepared statement.
 *     5. Check the ProxySQL holds the new METADATA information in 'stats_mysql_prepared_statements_info'.
 *     6. Checks that the results retrieve from the execute holds the correct information.
 * @date 2021-02-15
 */

#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <time.h>
#include <iostream>

#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

const int STRING_SIZE=32;

int g_seed = 0;

inline int fastrand() {
	g_seed = (214013*g_seed+2531011);
	return (g_seed>>16)&0x7FFF;
}

void gen_random_str(char *s, const int len) {
	g_seed = time(NULL) ^ getpid() ^ pthread_self();
	static const char alphanum[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[fastrand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(3);

	MYSQL* proxysql_mysql = mysql_init(NULL);
	if (!proxysql_mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return exit_status();
	}

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return exit_status();
	}

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}

	MYSQL_QUERY(proxysql_mysql, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(proxysql_mysql, "DROP TABLE IF EXISTS test.reg_test_1574");
	MYSQL_QUERY(proxysql_mysql, "CREATE TABLE IF NOT EXISTS test.reg_test_1574 (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, `c2` varchar(32))");

	MYSQL_STMT *stmt = mysql_stmt_init(proxysql_mysql);
	if (!stmt) {
		ok(false, " mysql_stmt_init(), out of memory\n");
		return exit_status();
	}

	// Force the 'hostgroup' for the 'SELECT' query to avoid replication issues
	std::string query_t = "SELECT /* ;hostgroup=0,%s */ * FROM test.reg_test_1574";
	std::string query (static_cast<std::size_t>(query_t.size() + 20), '\0');

	std::string rnd_str(static_cast<std::size_t>(20), '\0');
	gen_random_str(&rnd_str[0], 20);

	snprintf(&query[0], query.size(), query_t.c_str(), rnd_str.c_str());

	if (mysql_stmt_prepare(stmt, query.c_str(), strlen(query.c_str()))) {
		ok(false, "mysql_stmt_prepare at line %d failed: %s\n", __LINE__ , mysql_error(proxysql_mysql));
		mysql_close(proxysql_mysql);
		mysql_library_end();
		return exit_status();
	}

	MYSQL_QUERY(proxysql_mysql, "ALTER TABLE test.reg_test_1574 ADD c1 BIGINT AFTER id");
	MYSQL_QUERY(proxysql_mysql, "INSERT INTO test.reg_test_1574 (c1,c2) VALUES (100, 'abcde')");

	// Check that ProxySQL cached metadata for the query has the old information
	std::string num_columns_query_t = "SELECT num_columns FROM stats.stats_mysql_prepared_statements_info WHERE query='%s'";
	std::string num_columns_query (static_cast<std::size_t>(num_columns_query_t.size() + query.size()), '\0');
	snprintf(&num_columns_query[0], num_columns_query.size(), num_columns_query_t.c_str(), query.c_str());

	// Admin query checking for old metadata number of columns
	MYSQL_QUERY(proxysql_admin, num_columns_query.c_str());
	MYSQL_RES* result = mysql_store_result(proxysql_admin);
	MYSQL_ROW row = mysql_fetch_row(result);
	int num_columns = atoi(row[0]);

	ok(num_columns == 2, "Number of 'num_columns' in prepared statement metadata *before* execute should be: (Exp '2' == Actual: %d)", num_columns);
	mysql_free_result(result);

	if (mysql_stmt_execute(stmt)) {
		ok(false, "mysql_stmt_execute at line %d failed: %s\n", __LINE__ , mysql_stmt_error(stmt));
	}

	// Admin query checking for new metadata number of columns
	MYSQL_QUERY(proxysql_admin, num_columns_query.c_str());
	result = mysql_store_result(proxysql_admin);
	row = mysql_fetch_row(result);
	num_columns = atoi(row[0]);

	ok(num_columns == 3, "Number of 'num_columns' in prepared statement metadata *after* execute should be: (Exp '3' == Actual: %d)", num_columns);
	mysql_free_result(result);

	MYSQL_BIND bind[3];
	int data_id;
	int64_t data_c1;
	char data_c2[STRING_SIZE];
	char is_null[3];
	long unsigned int length[3];
	char error[3];
	memset(bind, 0, sizeof(bind));

	bind[0].buffer_type = MYSQL_TYPE_LONG;
	bind[0].buffer = (char *)&data_id;
	bind[0].buffer_length = sizeof(int);
	bind[0].is_null = &is_null[0];
	bind[0].length = &length[0];

	bind[1].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[1].buffer = (char *)&data_c1;
	bind[1].buffer_length = sizeof(int64_t);
	bind[1].is_null = &is_null[1];
	bind[1].length = &length[1];

	bind[2].buffer_type = MYSQL_TYPE_STRING;
	bind[2].buffer = (char *)&data_c2;
	bind[2].buffer_length = STRING_SIZE;
	bind[2].is_null = &is_null[2];
	bind[2].length = &length[2];
	bind[2].error = &error[2];

	if (mysql_stmt_bind_result(stmt, bind)) {
		ok(false, "mysql_stmt_bind_result at line %d failed: %s\n", __LINE__ , mysql_stmt_error(stmt));
		return exit_status();
	}

	if (mysql_stmt_fetch(stmt)) {
		ok(false, "mysql_stmt_fetch at line %d failed: %s\n", __LINE__ , mysql_stmt_error(stmt));
		return exit_status();
	}

	bool data_match_expected =
		(data_id == static_cast<int64_t>(1)) &&
		(data_c1 == static_cast<int64_t>(100)) &&
		(strcmp(data_c2, "abcde") == 0);

	ok(
		data_match_expected,
		"Prepared statement result matches expected - Exp=(id:1, c1:100, c2:'abcde'), Act=(id:%d, c1:%d, c2:'%s')",
		data_id,
		data_c1,
		data_c2
	);

	mysql_stmt_close(stmt);
	mysql_close(proxysql_mysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
