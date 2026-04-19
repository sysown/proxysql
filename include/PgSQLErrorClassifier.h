/**
 * @file PgSQLErrorClassifier.h
 * @brief Pure PgSQL error classification for retry decisions.
 *
 * Classifies PostgreSQL SQLSTATE error codes by class to determine
 * if a query error is retryable or fatal.
 *
 * @see Phase 3.10 (GitHub issue #5498)
 */

#ifndef PGSQL_ERROR_CLASSIFIER_H
#define PGSQL_ERROR_CLASSIFIER_H

/**
 * @brief Action to take after a PgSQL backend error.
 */
enum PgSQLErrorAction {
	PGSQL_ERROR_REPORT_TO_CLIENT,  ///< Send error to client, no retry.
	PGSQL_ERROR_RETRY,             ///< Retryable error (connection/server).
	PGSQL_ERROR_FATAL              ///< Fatal server state (shutdown/crash).
};

/**
 * @brief Classify a PgSQL SQLSTATE error code for retry eligibility.
 *
 * SQLSTATE classes (first 2 chars):
 * - "08" (connection exception): retryable
 * - "40" (transaction rollback, including serialization failure): retryable
 * - "53" (insufficient resources, e.g. too_many_connections): retryable
 * - "57" (operator intervention, e.g. admin_shutdown, crash_shutdown): fatal
 *        Exception: "57014" (query_canceled) is non-fatal
 * - "58" (system error, e.g. I/O error): fatal
 * - All others (syntax, constraint, etc.): report to client
 *
 * @param sqlstate  5-character SQLSTATE string (e.g., "08006", "42P01").
 * @return PgSQLErrorAction indicating what to do.
 */
PgSQLErrorAction classify_pgsql_error(const char *sqlstate);

/**
 * @brief Check if a PgSQL error is retryable given session conditions.
 *
 * Even if the error class is retryable, retry is blocked when:
 * - In an active transaction (PgSQL transactions are atomic)
 * - No retries remaining
 *
 * @param action              Result of classify_pgsql_error().
 * @param retries_remaining   Number of retries left.
 * @param in_transaction      Whether a transaction is in progress.
 * @return true if the error can be retried.
 */
bool pgsql_can_retry_error(
	PgSQLErrorAction action,
	int retries_remaining,
	bool in_transaction
);

#endif // PGSQL_ERROR_CLASSIFIER_H
