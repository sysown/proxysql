/**
 * @file TransactionState.cpp
 * @brief Implementation of pure transaction state tracking.
 *
 * @see TransactionState.h
 * @see Phase 3.8 (GitHub issue #5496)
 */

#include "TransactionState.h"

int update_transaction_persistent_hostgroup(
	bool transaction_persistent,
	int transaction_persistent_hostgroup,
	int current_hostgroup,
	bool backend_in_transaction)
{
	if (!transaction_persistent) {
		return -1;  // persistence disabled
	}

	if (transaction_persistent_hostgroup == -1) {
		// Not currently locked — lock if transaction just started
		if (backend_in_transaction) {
			return current_hostgroup;
		}
	} else {
		// Currently locked — unlock if transaction just ended
		if (!backend_in_transaction) {
			return -1;
		}
	}

	return transaction_persistent_hostgroup;  // no change
}

bool is_transaction_timed_out(
	unsigned long long transaction_started_at,
	unsigned long long current_time,
	int max_transaction_time_ms)
{
	if (transaction_started_at == 0) {
		return false;  // no active transaction
	}
	if (max_transaction_time_ms <= 0) {
		return false;  // no time limit
	}

	unsigned long long elapsed_ms = 0;
	if (current_time > transaction_started_at) {
		elapsed_ms = (current_time - transaction_started_at) / 1000;
		// transaction_started_at and current_time are in microseconds
	}

	return (elapsed_ms > (unsigned long long)max_transaction_time_ms);
}
