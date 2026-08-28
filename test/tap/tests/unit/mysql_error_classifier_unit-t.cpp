/**
 * @file mysql_error_classifier_unit-t.cpp
 * @brief Unit tests for MySQL error classification.
 *
 * @see Phase 3.7 (GitHub issue #5495)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "MySQLErrorClassifier.h"

// ============================================================================
// 1. classify_mysql_error
// ============================================================================

static void test_retryable_errors() {
	// 1047 (WSREP not ready) with retry conditions met
	ok(classify_mysql_error(1047, 3, true, false, false) == MYSQL_ERROR_RETRY_ON_NEW_CONN,
		"1047: retryable when conditions met");
	// 1053 (server shutdown) with retry conditions met
	ok(classify_mysql_error(1053, 1, true, false, false) == MYSQL_ERROR_RETRY_ON_NEW_CONN,
		"1053: retryable when conditions met");
}

static void test_retryable_but_blocked() {
	// 1047 but no retries left
	ok(classify_mysql_error(1047, 0, true, false, false) == MYSQL_ERROR_REPORT_TO_CLIENT,
		"1047: not retried when retries=0");
	// 1047 but connection not reusable
	ok(classify_mysql_error(1047, 3, false, false, false) == MYSQL_ERROR_REPORT_TO_CLIENT,
		"1047: not retried when connection not reusable");
	// 1047 but in active transaction
	ok(classify_mysql_error(1047, 3, true, true, false) == MYSQL_ERROR_REPORT_TO_CLIENT,
		"1047: not retried during active transaction");
	// 1047 but multiplex disabled
	ok(classify_mysql_error(1047, 3, true, false, true) == MYSQL_ERROR_REPORT_TO_CLIENT,
		"1047: not retried when multiplex disabled");
}

static void test_non_retryable_errors() {
	// Common MySQL errors — always report to client
	ok(classify_mysql_error(1045, 3, true, false, false) == MYSQL_ERROR_REPORT_TO_CLIENT,
		"1045 (access denied): always report");
	ok(classify_mysql_error(1064, 3, true, false, false) == MYSQL_ERROR_REPORT_TO_CLIENT,
		"1064 (syntax error): always report");
	ok(classify_mysql_error(1146, 3, true, false, false) == MYSQL_ERROR_REPORT_TO_CLIENT,
		"1146 (table not found): always report");
	ok(classify_mysql_error(2006, 3, true, false, false) == MYSQL_ERROR_REPORT_TO_CLIENT,
		"2006 (gone away): always report");
	ok(classify_mysql_error(0, 3, true, false, false) == MYSQL_ERROR_REPORT_TO_CLIENT,
		"0 (no error): report");
}

// ============================================================================
// 2. can_retry_on_new_connection
// ============================================================================

static void test_retry_on_offline() {
	ok(can_retry_on_new_connection(true, 3, true, false, false, false) == true,
		"retry: server offline, all conditions met");
}

static void test_no_retry_server_online() {
	ok(can_retry_on_new_connection(false, 3, true, false, false, false) == false,
		"no retry: server is online");
}

static void test_no_retry_conditions() {
	ok(can_retry_on_new_connection(true, 0, true, false, false, false) == false,
		"no retry: no retries left");
	ok(can_retry_on_new_connection(true, 3, false, false, false, false) == false,
		"no retry: connection not reusable");
	ok(can_retry_on_new_connection(true, 3, true, true, false, false) == false,
		"no retry: active transaction");
	ok(can_retry_on_new_connection(true, 3, true, false, true, false) == false,
		"no retry: multiplex disabled");
	ok(can_retry_on_new_connection(true, 3, true, false, false, true) == false,
		"no retry: transfer already started");
}

int main() {
	plan(19);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_retryable_errors();       // 2
	test_retryable_but_blocked();  // 4
	test_non_retryable_errors();   // 5
	test_retry_on_offline();       // 1
	test_no_retry_server_online(); // 1
	test_no_retry_conditions();    // 5
	// Total: 1+2+4+5+1+1+5 = 19

	test_cleanup_minimal();
	return exit_status();
}
