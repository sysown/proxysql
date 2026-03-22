/**
 * @file pgsql_error_classifier_unit-t.cpp
 * @brief Unit tests for PgSQL error classification.
 *
 * @see Phase 3.10 (GitHub issue #5498)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQLErrorClassifier.h"

static void test_connection_errors() {
	ok(classify_pgsql_error("08000") == PGSQL_ERROR_RETRY,
		"08000 (connection exception): retryable");
	ok(classify_pgsql_error("08003") == PGSQL_ERROR_RETRY,
		"08003 (connection does not exist): retryable");
	ok(classify_pgsql_error("08006") == PGSQL_ERROR_RETRY,
		"08006 (connection failure): retryable");
}

static void test_transaction_errors() {
	ok(classify_pgsql_error("40001") == PGSQL_ERROR_RETRY,
		"40001 (serialization failure): retryable");
	ok(classify_pgsql_error("40P01") == PGSQL_ERROR_RETRY,
		"40P01 (deadlock detected): retryable");
}

static void test_resource_errors() {
	ok(classify_pgsql_error("53000") == PGSQL_ERROR_RETRY,
		"53000 (insufficient resources): retryable");
	ok(classify_pgsql_error("53300") == PGSQL_ERROR_RETRY,
		"53300 (too many connections): retryable");
}

static void test_fatal_errors() {
	ok(classify_pgsql_error("57000") == PGSQL_ERROR_FATAL,
		"57000 (operator intervention): fatal");
	ok(classify_pgsql_error("57P01") == PGSQL_ERROR_FATAL,
		"57P01 (admin shutdown): fatal");
	ok(classify_pgsql_error("57P02") == PGSQL_ERROR_FATAL,
		"57P02 (crash shutdown): fatal");
	ok(classify_pgsql_error("58000") == PGSQL_ERROR_FATAL,
		"58000 (system error): fatal");
	// 57014 is an exception — query_canceled is NOT fatal
	ok(classify_pgsql_error("57014") == PGSQL_ERROR_REPORT_TO_CLIENT,
		"57014 (query canceled): not fatal, report to client");
}

static void test_non_retryable_errors() {
	ok(classify_pgsql_error("42601") == PGSQL_ERROR_REPORT_TO_CLIENT,
		"42601 (syntax error): report");
	ok(classify_pgsql_error("42P01") == PGSQL_ERROR_REPORT_TO_CLIENT,
		"42P01 (undefined table): report");
	ok(classify_pgsql_error("23505") == PGSQL_ERROR_REPORT_TO_CLIENT,
		"23505 (unique violation): report");
	ok(classify_pgsql_error("23503") == PGSQL_ERROR_REPORT_TO_CLIENT,
		"23503 (foreign key violation): report");
	ok(classify_pgsql_error("22001") == PGSQL_ERROR_REPORT_TO_CLIENT,
		"22001 (string data right truncation): report");
}

static void test_edge_cases() {
	ok(classify_pgsql_error(nullptr) == PGSQL_ERROR_REPORT_TO_CLIENT,
		"null sqlstate: report");
	ok(classify_pgsql_error("") == PGSQL_ERROR_REPORT_TO_CLIENT,
		"empty sqlstate: report");
	ok(classify_pgsql_error("0") == PGSQL_ERROR_REPORT_TO_CLIENT,
		"single char sqlstate: report");
}

static void test_retry_conditions() {
	ok(pgsql_can_retry_error(PGSQL_ERROR_RETRY, 3, false) == true,
		"can retry: retryable + retries left + no txn");
	ok(pgsql_can_retry_error(PGSQL_ERROR_RETRY, 0, false) == false,
		"no retry: no retries left");
	ok(pgsql_can_retry_error(PGSQL_ERROR_RETRY, 3, true) == false,
		"no retry: in transaction");
	ok(pgsql_can_retry_error(PGSQL_ERROR_REPORT_TO_CLIENT, 3, false) == false,
		"no retry: non-retryable error");
	ok(pgsql_can_retry_error(PGSQL_ERROR_FATAL, 3, false) == false,
		"no retry: fatal error");
}

int main() {
	plan(26);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_connection_errors();    // 3
	test_transaction_errors();   // 2
	test_resource_errors();      // 2
	test_fatal_errors();         // 4
	test_non_retryable_errors(); // 5
	test_edge_cases();           // 3
	test_retry_conditions();     // 5
	// Total: 1+3+2+2+5+5+3+5 = 26

	test_cleanup_minimal();
	return exit_status();
}
