/**
 * @file PgSQLErrorClassifier.cpp
 * @brief Implementation of PgSQL error classification.
 *
 * @see PgSQLErrorClassifier.h
 * @see Phase 3.10 (GitHub issue #5498)
 */

#include "PgSQLErrorClassifier.h"
#include <cstring>

PgSQLErrorAction classify_pgsql_error(const char *sqlstate) {
	if (sqlstate == nullptr || strlen(sqlstate) < 2) {
		return PGSQL_ERROR_REPORT_TO_CLIENT;
	}

	// Classify by SQLSTATE class (first 2 characters)
	char cls[3] = {sqlstate[0], sqlstate[1], '\0'};

	// Connection exceptions — retryable
	if (strcmp(cls, "08") == 0) return PGSQL_ERROR_RETRY;

	// Transaction rollback (serialization failure, deadlock) — retryable
	if (strcmp(cls, "40") == 0) return PGSQL_ERROR_RETRY;

	// Insufficient resources (too many connections) — retryable
	if (strcmp(cls, "53") == 0) return PGSQL_ERROR_RETRY;

	// Operator intervention — mostly fatal, except query_canceled
	if (strcmp(cls, "57") == 0) {
		// 57014 = query_canceled — not fatal, report to client
		if (strlen(sqlstate) >= 5 && strncmp(sqlstate, "57014", 5) == 0) {
			return PGSQL_ERROR_REPORT_TO_CLIENT;
		}
		return PGSQL_ERROR_FATAL;  // admin_shutdown, crash_shutdown, etc.
	}

	// System error (I/O error) — fatal
	if (strcmp(cls, "58") == 0) return PGSQL_ERROR_FATAL;

	// Everything else (syntax, constraints, data, etc.) — report to client
	return PGSQL_ERROR_REPORT_TO_CLIENT;
}

bool pgsql_can_retry_error(
	PgSQLErrorAction action,
	int retries_remaining,
	bool in_transaction)
{
	if (action != PGSQL_ERROR_RETRY) {
		return false;
	}
	if (retries_remaining <= 0) {
		return false;
	}
	if (in_transaction) {
		return false;  // PgSQL transactions are atomic, can't retry mid-txn
	}
	return true;
}
