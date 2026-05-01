/**
 * @file test_set_statement_for-t.cpp
 * @brief Test for MariaDB SET STATEMENT ... FOR passthrough support (issue #5686).
 * @details MariaDB supports the syntax:
 *
 *     SET STATEMENT var1=val1 [, var2=val2, ...] FOR <statement>
 *
 * This temporarily sets session variables for the duration of a single
 * statement. Prior to the fix, ProxySQL did not recognize this syntax,
 * causing it to invoke unable_to_parse_set_statement() which locks the
 * session to a single hostgroup. Subsequent queries to a different
 * hostgroup would then fail with error 9006.
 *
 * The fix detects "SET STATEMENT ... FOR" and forwards the query to
 * the backend as-is, without locking the hostgroup.
 *
 * This test verifies:
 *   - The SET STATEMENT ... FOR query itself succeeds
 *   - The query returns a valid result (the backend executed it)
 *   - No hostgroup lock persists after the query
 *   - Multiple variables in a single SET STATEMENT work
 *   - Case-insensitive matching works
 *
 * All tests are skipped on non-MariaDB backends.
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
 * @brief Detect if the backend behind ProxySQL is MariaDB.
 * @return 1 if MariaDB, 0 if not MariaDB, -1 on connection/query error.
 */
static int detect_mariadb(CommandLine& cl) {
	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) return -1;
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n",
			__FILE__, __LINE__, mysql_error(mysql));
		mysql_close(mysql);
		return -1;
	}

	int is_mariadb = 0;
	if (mysql_query(mysql, "SELECT @@version") != 0) {
		fprintf(stderr, "File %s, line %d, Error: %s\n",
			__FILE__, __LINE__, mysql_error(mysql));
		mysql_close(mysql);
		return -1;
	}
	MYSQL_RES* result = mysql_store_result(mysql);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) {
		if (strstr(row[0], "Maria")) {
			is_mariadb = 1;
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

	// SET STATEMENT ... FOR is a MariaDB-specific feature.
	// Skip all tests if the backend is not MariaDB, but fail on errors.
	int is_mariadb = detect_mariadb(cl);
	if (is_mariadb == -1) {
		diag("Error: Failed to connect to ProxySQL or query backend version.");
		return -1;
	}
	if (is_mariadb == 0) {
		skip_all("SET STATEMENT ... FOR requires a MariaDB backend");
	}

	plan(5);

	diag("=== Test: MariaDB SET STATEMENT ... FOR passthrough ===");
	diag("Issue #5686: ProxySQL should forward SET STATEMENT ... FOR");
	diag("to the backend without locking the hostgroup.");
	diag("");

	// Connect to ProxySQL
	MYSQL* proxysql = mysql_init(NULL);
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	// Test 1: Basic SET STATEMENT ... FOR - query should succeed
	diag("Test 1: Execute 'SET STATEMENT max_statement_time=60 FOR SELECT 1'");
	diag("  ProxySQL should forward this to MariaDB as-is.");
	{
		int rc = mysql_query(proxysql, "SET STATEMENT max_statement_time=60 FOR SELECT 1 AS val");
		ok(rc == 0, "SET STATEMENT max_statement_time=60 FOR SELECT 1 should succeed");
		if (rc != 0) {
			diag("  ERROR: %s", mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			MYSQL_ROW row = mysql_fetch_row(res);
			int rows = mysql_num_rows(res);
			diag("  Result: rows=%d, val=%s", rows, row ? row[0] : "NULL");
			ok(rows == 1 && row && strcmp(row[0], "1") == 0,
				"SET STATEMENT ... FOR should return the result from the inner SELECT");
			mysql_free_result(res);
		}
	}

	diag("");

	// Test 2: Multiple variables in SET STATEMENT
	diag("Test 2: Execute 'SET STATEMENT max_statement_time=60, lock_wait_timeout=60 FOR SELECT 1'");
	diag("  ProxySQL should handle multiple variables in a single SET STATEMENT.");
	{
		int rc = mysql_query(proxysql,
			"SET STATEMENT max_statement_time=60, lock_wait_timeout=60 FOR SELECT 1 AS val");
		ok(rc == 0, "SET STATEMENT with multiple variables should succeed");
		if (rc != 0) {
			diag("  ERROR: %s", mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			mysql_free_result(res);
		}
	}

	diag("");

	// Test 3: No hostgroup lock persists after SET STATEMENT
	diag("Test 3: Execute a plain SELECT after SET STATEMENT");
	diag("  Prior to the fix, unable_to_parse_set_statement() would lock the");
	diag("  hostgroup, causing subsequent queries to fail with error 9006.");
	{
		int rc = mysql_query(proxysql, "SELECT 1 AS no_lock_test");
		ok(rc == 0, "Plain SELECT after SET STATEMENT should succeed (no hostgroup lock)");
		if (rc != 0) {
			diag("  ERROR: %s (this indicates the hostgroup is still locked)", mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			mysql_free_result(res);
		}
	}

	diag("");

	// Test 4: Case-insensitive matching
	diag("Test 4: Execute 'set statement max_statement_time=60 for select 1'");
	diag("  ProxySQL detection should be case-insensitive.");
	{
		int rc = mysql_query(proxysql, "set statement max_statement_time=60 for select 1 as val");
		ok(rc == 0, "Lowercase 'set statement ... for' should also succeed");
		if (rc != 0) {
			diag("  ERROR: %s", mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			mysql_free_result(res);
		}
	}

	diag("");
	diag("=== All tests completed ===");

	mysql_close(proxysql);
	return exit_status();
}
