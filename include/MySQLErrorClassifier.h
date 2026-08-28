/**
 * @file MySQLErrorClassifier.h
 * @brief Pure MySQL error classification for retry decisions.
 *
 * Extracted from MySQL_Session handler_ProcessingQueryError_CheckBackendConnectionStatus()
 * and handler_minus1_HandleErrorCodes().
 *
 * @see Phase 3.7 (GitHub issue #5495)
 */

#ifndef MYSQL_ERROR_CLASSIFIER_H
#define MYSQL_ERROR_CLASSIFIER_H

/**
 * @brief Action to take after a MySQL backend query error.
 */
enum MySQLErrorAction {
	MYSQL_ERROR_RETRY_ON_NEW_CONN,   ///< Reconnect and retry on a new server.
	MYSQL_ERROR_REPORT_TO_CLIENT     ///< Send error to client, no retry.
};

/**
 * @brief Classify a MySQL error code to determine retry eligibility.
 *
 * Mirrors the logic in handler_minus1_HandleErrorCodes():
 * - Error 1047 (WSREP not ready): retryable if conditions permit
 * - Error 1053 (server shutdown): retryable if conditions permit
 * - Other errors: report to client
 *
 * Retry is only possible when:
 *   - query_retries_on_failure > 0
 *   - connection is reusable
 *   - no active transaction
 *   - multiplex not disabled
 *
 * @param error_code              MySQL error number.
 * @param retries_remaining       Number of retries left (> 0 to allow retry).
 * @param connection_reusable     Whether the connection can be reused.
 * @param in_active_transaction   Whether a transaction is in progress.
 * @param multiplex_disabled      Whether multiplexing is disabled.
 * @return MySQLErrorAction indicating what to do.
 */
MySQLErrorAction classify_mysql_error(
	unsigned int error_code,
	int retries_remaining,
	bool connection_reusable,
	bool in_active_transaction,
	bool multiplex_disabled
);

/**
 * @brief Check if a backend query can be retried on a new connection.
 *
 * Mirrors handler_ProcessingQueryError_CheckBackendConnectionStatus().
 * A retry is possible when the server is offline AND all retry
 * conditions are met.
 *
 * @param server_offline          Whether the backend server is offline.
 * @param retries_remaining       Number of retries left (> 0 to allow retry).
 * @param connection_reusable     Whether the connection can be reused.
 * @param in_active_transaction   Whether a transaction is in progress.
 * @param multiplex_disabled      Whether multiplexing is disabled.
 * @param transfer_started        Whether result transfer has already begun.
 * @return true if the query should be retried on a new connection.
 */
bool can_retry_on_new_connection(
	bool server_offline,
	int retries_remaining,
	bool connection_reusable,
	bool in_active_transaction,
	bool multiplex_disabled,
	bool transfer_started
);

#endif // MYSQL_ERROR_CLASSIFIER_H
