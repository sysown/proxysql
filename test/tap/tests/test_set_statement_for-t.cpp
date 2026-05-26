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
 *   - Whitespace tolerance after FOR (multi-line, tab, CRLF, multi-space)
 *
 * This test requires a MariaDB backend. It should only be registered in
 * TAP groups whose infra provides one (e.g. mariadb10-galera-*). The
 * earlier runtime self-skip on non-MariaDB backends has been removed —
 * if the test is misregistered into a MySQL group, that's a groups.json
 * bug and should surface as a loud failure, not a silent skip.
 *
 * @date 2026-05-01
 */

#include <stdio.h>
#include <string.h>
#include <vector>
#include "mysql.h"
#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(5 + 8);

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

	// Tests 5-8: whitespace tolerance after 'FOR'. The original PR #5708
	// detection used strcasestr(nq, " FOR "), which is a literal-substring
	// match requiring a space BOTH before and after 'FOR'. A mysql client
	// query typed across multiple lines (the customer-reported failure mode
	// of issue #5686 follow-up) has '\n' immediately after 'FOR' and the
	// detection misses; the SET parser then falls through to
	// unable_to_parse_set_statement() and locks the session to its default
	// hostgroup, surfacing as error 9006 on the next query that routes to
	// a different hostgroup. The fix uses the digest text (which is
	// whitespace-normalised) instead. These tests cover four common
	// post-'FOR' whitespace shapes that the original test missed.
	//
	// Each test: (a) the SET STATEMENT must succeed, (b) a plain SELECT
	// immediately afterwards must succeed (proving no hostgroup lock
	// persists). On the buggy code path, assertion (b) would manifest as
	// error 9006 on any test environment where the follow-up SELECT routes
	// to a different hostgroup than the session's default; on a single-
	// hostgroup environment it would manifest as the SET STATEMENT itself
	// silently going through a different parse path that may or may not
	// produce the expected backend response — either way, the assertions
	// below will fail loudly.

	struct ws_case_t {
		const char* label;
		const char* query;
	};
	std::vector<ws_case_t> ws_cases = {
		{ "newline after FOR",
		  "SET STATEMENT max_statement_time=60 FOR\n  SELECT 1 AS val" },
		{ "tab after FOR",
		  "SET STATEMENT max_statement_time=60 FOR\tSELECT 1 AS val" },
		{ "CRLF after FOR",
		  "SET STATEMENT max_statement_time=60 FOR\r\n  SELECT 1 AS val" },
		{ "multiple spaces after FOR",
		  "SET STATEMENT max_statement_time=60 FOR   SELECT 1 AS val" },
	};

	int idx = 5;
	for (const auto& c : ws_cases) {
		idx++;
		diag("Test %d: SET STATEMENT with %s", idx, c.label);
		int rc = mysql_query(proxysql, c.query);
		ok(rc == 0, "SET STATEMENT (%s) should succeed", c.label);
		if (rc != 0) {
			diag("  ERROR on SET STATEMENT: %s", mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			if (res) mysql_free_result(res);
		}
		// Follow-up plain SELECT to verify no hostgroup lock persists.
		// On the buggy code path, the SET STATEMENT would have triggered
		// unable_to_parse_set_statement() and locked the hostgroup; a
		// subsequent query that routes elsewhere would then fail with
		// error 9006 ("connection is locked to hostgroup X but trying
		// to reach hostgroup Y").
		rc = mysql_query(proxysql, "SELECT 2 AS no_lock_probe");
		ok(rc == 0, "follow-up SELECT after %s should succeed (no hostgroup lock)", c.label);
		if (rc != 0) {
			diag("  ERROR on follow-up SELECT: %s (this indicates the hostgroup was locked)",
				mysql_error(proxysql));
		} else {
			MYSQL_RES* res = mysql_store_result(proxysql);
			if (res) mysql_free_result(res);
		}
		diag("");
	}

	diag("=== All tests completed ===");

	mysql_close(proxysql);
	return exit_status();
}
