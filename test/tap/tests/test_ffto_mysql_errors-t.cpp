/**
 * @file test_ffto_mysql_errors-t.cpp
 * @brief FFTO E2E TAP test -- MySQL error recording in stats_mysql_errors.
 *
 * Validates that errors occurring during MySQL fast-forward sessions
 * are properly recorded in stats_mysql_errors with correct errno
 * and error message.
 *
 * @par Test scenarios
 *  1. Session is actually in fast_forward (extended_info)
 *  2. Syntax error -> errno 1064 recorded
 *  3. Table not found -> errno 1146 or 1109 recorded
 *  4. Recovery: successful query after error
 *  5. Error stats have count / message / errno
 */
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "ffto_mysql_helpers.h"

static constexpr int kPlannedTests = 8;

#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
	do { \
		diag(fmt, ##__VA_ARGS__); \
		int remaining = kPlannedTests - tests_last(); \
		if (remaining > 0) { \
			skip(remaining, "Skipping remaining assertions after setup failure"); \
		} \
		goto cleanup_label; \
	} while (0)

/**
 * @brief Check if a specific errno appears in stats_mysql_errors.
 * Polls up to 3 seconds. Returns true if found.
 * Table column is `errno` (not the in-memory label `err_no`).
 */
static bool verify_mysql_error(MYSQL* admin, int expected_errno, const char* expected_msg_substr) {
	char query[1024];
	snprintf(query, sizeof(query),
		"SELECT errno, last_error FROM stats_mysql_errors WHERE errno = %d",
		expected_errno);

	for (int attempt = 0; attempt < 30; attempt++) {
		if (mysql_query(admin, query) != 0) {
			diag("stats_mysql_errors query failed: %s", mysql_error(admin));
			usleep(100000);
			continue;
		}
		MYSQL_RES* res = mysql_store_result(admin);
		if (!res) { usleep(100000); continue; }
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row) {
			bool msg_ok = (expected_msg_substr == nullptr) ||
			              (row[1] && strstr(row[1], expected_msg_substr));
			if (!msg_ok) {
				diag("errno %d found but last_error='%s' missing substr '%s'",
					expected_errno, row[1] ? row[1] : "(null)", expected_msg_substr);
			}
			mysql_free_result(res);
			return msg_ok;
		}
		mysql_free_result(res);
		usleep(100000);
	}
	/* Dump table for diagnostics */
	if (mysql_query(admin, "SELECT errno, count_star, last_error FROM stats_mysql_errors") == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		MYSQL_ROW row;
		int n = 0;
		while (res && (row = mysql_fetch_row(res))) {
			diag("  stats_mysql_errors: errno=%s count=%s last_error=%s",
				row[0] ? row[0] : "NULL",
				row[1] ? row[1] : "NULL",
				row[2] ? row[2] : "NULL");
			n++;
		}
		if (res) mysql_free_result(res);
		if (n == 0) diag("  stats_mysql_errors is EMPTY");
	}
	return false;
}

/**
 * @brief Check if either of two valid errno values appears in stats_mysql_errors.
 * Polls both values in a single query so version-dependent server behavior does
 * not add an unnecessary timeout before checking the alternate errno.
 */
static bool verify_mysql_error_any(MYSQL* admin, int errno1, int errno2) {
	char query[1024];
	snprintf(query, sizeof(query),
		"SELECT errno FROM stats_mysql_errors WHERE errno IN (%d,%d) LIMIT 1",
		errno1, errno2);

	for (int attempt = 0; attempt < 30; attempt++) {
		if (mysql_query(admin, query) != 0) {
			diag("stats_mysql_errors query failed: %s", mysql_error(admin));
			usleep(100000);
			continue;
		}
		MYSQL_RES* res = mysql_store_result(admin);
		if (!res) { usleep(100000); continue; }
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row) {
			diag("Table-not-found errno recorded as %s", row[0]);
			mysql_free_result(res);
			return true;
		}
		mysql_free_result(res);
		usleep(100000);
	}
	return false;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("Failed to get env vars."); return -1; }

	diag("=== FFTO MySQL Error Recording Test ===");
	plan(kPlannedTests);

	MYSQL* admin = mysql_init(NULL);
	MYSQL* conn = NULL;
	/* Declare before any goto cleanup (C++ forbids jump over init). */
	bool is_ff = false;
	const char* user = NULL;
	const char* pass = NULL;

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
	                       NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connection failed"); return -1;
	}

	/* Use root (privileged TAP user) -- same as other FFTO mysql tests. */
	user = cl.root_username;
	pass = cl.root_password;

	if (ffto_mysql_enable_ff(admin, user) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "Failed to enable FFTO/fast_forward for '%s'", user);
	}

	if (ffto_mysql_reset_errors(admin) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "Failed to reset stats_mysql_errors");
	}

	/* Keep a query in flight so processlist can observe the session. */
	conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, cl.host, user, pass,
	                       "information_schema", cl.port, NULL, 0)) {
		FAIL_AND_SKIP_REMAINING(cleanup, "FF connection failed: %s", mysql_error(conn));
	}
	ok(conn != NULL, "Connected to MySQL via ProxySQL as '%s'", user);

	/* Force a backend connection so status becomes FAST_FORWARD. */
	if (mysql_query(conn, "DO 1") == 0) {
		/* DO returns OK without result set */
	} else {
		diag("DO 1 failed: %s", mysql_error(conn));
	}

	/* Hard gate: session must actually be in fast_forward. */
	is_ff = ffto_mysql_session_is_ff(admin, user);
	ok(is_ff, "Session for '%s' is in fast_forward (extended_info)", user);
	if (!is_ff) {
		FAIL_AND_SKIP_REMAINING(cleanup,
			"Session never entered fast_forward -- FFTO cannot record errors");
	}

	/* Scenario 1: Syntax error -> errno 1064 */
	diag("--- Scenario 1: syntax error ---");
	mysql_query(conn, "SELEC BAD SYNTAX");
	ok(verify_mysql_error(admin, 1064, "syntax"),
	   "Error 1064 recorded in stats_mysql_errors");

	/* Scenario 2: Table not found -> errno 1146 or 1109, depending on server version/context */
	diag("--- Scenario 2: table not found ---");
	mysql_query(conn, "SELECT * FROM nonexistent_table_ffto_test");
	ok(verify_mysql_error_any(admin, 1146, 1109),
	   "Table-not-found error (1146 or 1109) recorded in stats_mysql_errors");

	/* Scenario 3: Recovery -- successful query after errors */
	diag("--- Scenario 3: recovery after error ---");
	if (ffto_mysql_reset_digests(admin) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "Failed to reset digests");
	}
	if (mysql_query(conn, "SELECT 1") == 0) {
		MYSQL_RES* r = mysql_store_result(conn);
		if (r) mysql_free_result(r);
	}

	{
		bool found = false;
		for (int i = 0; i < 30; i++) {
			if (mysql_query(admin, "SELECT count_star FROM stats_mysql_query_digest "
			     "WHERE digest_text LIKE '%SELECT%'") != 0) { usleep(100000); continue; }
			MYSQL_RES* res = mysql_store_result(admin);
			MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
			if (row && atoi(row[0]) > 0) found = true;
			if (res) mysql_free_result(res);
			if (found) break;
			usleep(100000);
		}
		ok(found, "Recovery: SELECT 1 recorded in digest after errors");
	}

	{
		bool has_errors = false;
		if (mysql_query(admin, "SELECT count_star FROM stats_mysql_errors") == 0) {
			MYSQL_RES* res = mysql_store_result(admin);
			MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
			if (row && atoi(row[0]) > 0) has_errors = true;
			if (res) mysql_free_result(res);
		}
		ok(has_errors, "stats_mysql_errors has entries from FF session");
	}

	{
		bool has_msg = false;
		if (mysql_query(admin, "SELECT last_error FROM stats_mysql_errors LIMIT 1") == 0) {
			MYSQL_RES* res = mysql_store_result(admin);
			MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
			if (row && row[0] && strlen(row[0]) > 0) has_msg = true;
			if (res) mysql_free_result(res);
		}
		ok(has_msg, "stats_mysql_errors entries have non-empty error messages");
	}

	{
		bool has_errno = false;
		if (mysql_query(admin, "SELECT errno FROM stats_mysql_errors LIMIT 1") == 0) {
			MYSQL_RES* res = mysql_store_result(admin);
			MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
			if (row && atoi(row[0]) > 0) has_errno = true;
			if (res) mysql_free_result(res);
		}
		ok(has_errno, "stats_mysql_errors entries have non-zero errno");
	}

cleanup:
	if (conn) mysql_close(conn);
	if (admin) mysql_close(admin);
	return exit_status();
}
