/**
 * @file TransactionState.h
 * @brief Pure transaction state tracking logic for unit testability.
 *
 * Extracted from MySQL_Session/PgSQL_Session transaction persistence
 * logic. The decision is identical for both protocols.
 *
 * @see Phase 3.8 (GitHub issue #5496)
 */

#ifndef TRANSACTION_STATE_H
#define TRANSACTION_STATE_H

/**
 * @brief Update transaction_persistent_hostgroup based on backend state.
 *
 * Mirrors the transaction persistence logic in MySQL_Session and
 * PgSQL_Session (near handler_rc0_Process_Resultset):
 * - When a transaction starts on a backend, lock to the current HG
 * - When a transaction ends, unlock (-1)
 *
 * @param transaction_persistent         Whether transaction persistence is enabled.
 * @param transaction_persistent_hostgroup Current persistent HG (-1 = none).
 * @param current_hostgroup              HG where the query executed.
 * @param backend_in_transaction         Whether the backend has an active transaction.
 * @return Updated transaction_persistent_hostgroup value.
 */
int update_transaction_persistent_hostgroup(
	bool transaction_persistent,
	int transaction_persistent_hostgroup,
	int current_hostgroup,
	bool backend_in_transaction
);

/**
 * @brief Check if a transaction has exceeded the maximum allowed time.
 *
 * @param transaction_started_at  Timestamp when transaction started, in microseconds (0 = none).
 * @param current_time            Current timestamp, in microseconds.
 * @param max_transaction_time_ms Maximum transaction time in milliseconds (0 or negative = no limit).
 * @return true if the transaction has exceeded the time limit.
 */
bool is_transaction_timed_out(
	unsigned long long transaction_started_at,
	unsigned long long current_time,
	int max_transaction_time_ms
);

#endif // TRANSACTION_STATE_H
