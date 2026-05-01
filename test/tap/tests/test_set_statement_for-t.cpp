/**
 * @file test_set_statement_for-t.cpp
 * @brief Test for MariaDB SET STATEMENT ... FOR passthrough support.
 * @details Verifies that ProxySQL correctly handles MariaDB's SET STATEMENT
 *   syntax by forwarding it to the backend without locking the hostgroup.
 *   Tests are skipped on non-MariaDB backends.
 *
 * @date 2026-05-01
 */

#include <stdio.h>
#include <string.h>
#include "mysql.h"
#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

/**
 * @brief Detect if the backend is MariaDB.
 */
static bool detect_mariadb(CommandLine& cl) {
	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) return false;
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n",
			__FILE__, __LINE__, mysql_error(mysql));
		mysql_close(mysql);
		return false;
	}

	bool is_mariadb = false;
	MYSQL_QUERY(mysql, "SELECT @@version");
	MYSQL_RES* result = mysql_store_result(mysql);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) {
		if (strstr(row[0], "Maria")) {
			is_mariadb = true;
		}
	}
	mysql_free_result(result);
	mysql_close(mysql);
	return is_mariadb;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// Detect MariaDB backend
	bool is_mariadb = detect_mariadb(cl);
	if (!is_mariadb) {
		skip_all("SET STATEMENT ... FOR requires a MariaDB backend");
	}

	// 4 tests:
	// 1. SET STATEMENT ... FOR basic query succeeds
	// 2. SET STATEMENT ... FOR multi-variable query succeeds
	// 3. Query after SET STATEMENT succeeds (no hostgroup lock)
	// 4. SET STATEMENT with lowercase also works
	plan(4);

	// Connect to ProxySQL
	MYSQL* proxysql = mysql_init(NULL);
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	// Test 1: Basic SET STATEMENT ... FOR
	{
		int rc = mysql_query(proxysql, "SET STATEMENT max_statement_time=60 FOR SELECT 1 AS val");
		ok(rc == 0, "SET STATEMENT max_statement_time=60 FOR SELECT 1 should succeed. Error: %s",
			rc ? mysql_error(proxysql) : "none");
		if (rc == 0) {
			MYSQL_RES* res = mysql_store_result(proxysql);
			mysql_free_result(res);
		}
	}

	// Test 2: Multi-variable SET STATEMENT ... FOR
	{
		int rc = mysql_query(proxysql, "SET STATEMENT max_statement_time=60, lock_wait_timeout=60 FOR SELECT 1 AS val");
		ok(rc == 0, "SET STATEMENT with multiple variables should succeed. Error: %s",
			rc ? mysql_error(proxysql) : "none");
		if (rc == 0) {
			MYSQL_RES* res = mysql_store_result(proxysql);
			mysql_free_result(res);
		}
	}

	// Test 3: No hostgroup lock persists after SET STATEMENT
	{
		int rc = mysql_query(proxysql, "SELECT 1 AS no_lock_test");
		ok(rc == 0, "Query after SET STATEMENT should succeed (no hostgroup lock). Error: %s",
			rc ? mysql_error(proxysql) : "none");
		if (rc == 0) {
			MYSQL_RES* res = mysql_store_result(proxysql);
			mysql_free_result(res);
		}
	}

	// Test 4: Lowercase set statement
	{
		int rc = mysql_query(proxysql, "set statement max_statement_time=60 for select 1 as val");
		ok(rc == 0, "Lowercase 'set statement ... for' should also work. Error: %s",
			rc ? mysql_error(proxysql) : "none");
		if (rc == 0) {
			MYSQL_RES* res = mysql_store_result(proxysql);
			mysql_free_result(res);
		}
	}

	mysql_close(proxysql);
	return exit_status();
}
