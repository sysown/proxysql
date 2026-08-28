/**
 * @file MySQLErrorClassifier.cpp
 * @brief Implementation of MySQL error classification.
 *
 * @see MySQLErrorClassifier.h
 * @see Phase 3.7 (GitHub issue #5495)
 */

#include "MySQLErrorClassifier.h"

MySQLErrorAction classify_mysql_error(
	unsigned int error_code,
	int retries_remaining,
	bool connection_reusable,
	bool in_active_transaction,
	bool multiplex_disabled)
{
	// Check if this error code is retryable
	bool retryable_error = false;
	switch (error_code) {
		case 1047:  // ER_UNKNOWN_COM_ERROR (WSREP not ready)
		case 1053:  // ER_SERVER_SHUTDOWN
			retryable_error = true;
			break;
		default:
			break;
	}

	if (!retryable_error) {
		return MYSQL_ERROR_REPORT_TO_CLIENT;
	}

	// Check retry conditions (mirrors handler_minus1_HandleErrorCodes)
	if (retries_remaining > 0
		&& connection_reusable
		&& !in_active_transaction
		&& !multiplex_disabled) {
		return MYSQL_ERROR_RETRY_ON_NEW_CONN;
	}

	return MYSQL_ERROR_REPORT_TO_CLIENT;
}

bool can_retry_on_new_connection(
	bool server_offline,
	int retries_remaining,
	bool connection_reusable,
	bool in_active_transaction,
	bool multiplex_disabled,
	bool transfer_started)
{
	if (!server_offline) {
		return false;  // server is fine, no retry needed
	}

	// Mirror handler_ProcessingQueryError_CheckBackendConnectionStatus
	if (retries_remaining > 0
		&& connection_reusable
		&& !in_active_transaction
		&& !multiplex_disabled
		&& !transfer_started) {
		return true;
	}

	return false;
}
