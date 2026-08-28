/**
 * @file transaction_state_unit-t.cpp
 * @brief Unit tests for transaction state tracking logic.
 *
 * @see Phase 3.8 (GitHub issue #5496)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "TransactionState.h"

// ============================================================================
// 1. update_transaction_persistent_hostgroup
// ============================================================================

static void test_persistence_disabled() {
	ok(update_transaction_persistent_hostgroup(false, -1, 5, true) == -1,
		"disabled: returns -1 even with active txn");
	ok(update_transaction_persistent_hostgroup(false, 3, 5, true) == -1,
		"disabled: clears existing lock");
}

static void test_txn_start_locks() {
	ok(update_transaction_persistent_hostgroup(true, -1, 5, true) == 5,
		"txn start: locks to current HG");
	ok(update_transaction_persistent_hostgroup(true, -1, 0, true) == 0,
		"txn start: locks to HG 0");
}

static void test_txn_end_unlocks() {
	ok(update_transaction_persistent_hostgroup(true, 5, 5, false) == -1,
		"txn end: unlocks when txn completes");
	ok(update_transaction_persistent_hostgroup(true, 3, 10, false) == -1,
		"txn end: unlocks regardless of current HG");
}

static void test_no_change() {
	// No txn, no existing lock → stays unlocked
	ok(update_transaction_persistent_hostgroup(true, -1, 5, false) == -1,
		"no change: no txn, stays unlocked");
	// Active txn, already locked → stays locked
	ok(update_transaction_persistent_hostgroup(true, 5, 5, true) == 5,
		"no change: already locked, stays locked");
	// Already locked on HG 5, txn still active on different current_hostgroup
	// → stays locked on original HG (doesn't change to new HG)
	ok(update_transaction_persistent_hostgroup(true, 5, 10, true) == 5,
		"no change: locked HG stays even if current_hostgroup differs");
}

static void test_txn_lifecycle() {
	int state = -1;
	// BEGIN
	state = update_transaction_persistent_hostgroup(true, state, 7, true);
	ok(state == 7, "lifecycle: BEGIN locks to HG 7");
	// Mid-transaction query
	state = update_transaction_persistent_hostgroup(true, state, 7, true);
	ok(state == 7, "lifecycle: mid-txn stays locked");
	// COMMIT
	state = update_transaction_persistent_hostgroup(true, state, 7, false);
	ok(state == -1, "lifecycle: COMMIT unlocks");
}

// ============================================================================
// 2. is_transaction_timed_out
// ============================================================================

static void test_timeout_exceeded() {
	// started 10s ago, limit 5s (in ms), times in microseconds
	ok(is_transaction_timed_out(1000000, 11000000, 5000) == true,
		"timeout: 10s elapsed > 5s limit");
}

static void test_timeout_not_exceeded() {
	ok(is_transaction_timed_out(1000000, 3000000, 5000) == false,
		"no timeout: 2s elapsed < 5s limit");
}

static void test_timeout_boundary() {
	// Exactly at limit: 5000ms elapsed, limit 5000ms → NOT timed out (needs >)
	ok(is_transaction_timed_out(1000000, 6000000, 5000) == false,
		"no timeout: elapsed == limit (strict > comparison)");
}

static void test_timeout_no_transaction() {
	ok(is_transaction_timed_out(0, 99000000, 5000) == false,
		"no timeout: no active transaction (started_at=0)");
}

static void test_timeout_no_limit() {
	ok(is_transaction_timed_out(1000000, 99000000, 0) == false,
		"no timeout: limit disabled (max=0)");
	ok(is_transaction_timed_out(1000000, 99000000, -1) == false,
		"no timeout: limit disabled (max=-1)");
}

int main() {
	plan(19);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_persistence_disabled();   // 2
	test_txn_start_locks();        // 2
	test_txn_end_unlocks();        // 2
	test_no_change();              // 3
	test_txn_lifecycle();          // 3
	test_timeout_exceeded();       // 1
	test_timeout_not_exceeded();   // 1
	test_timeout_boundary();       // 1
	test_timeout_no_transaction(); // 1
	test_timeout_no_limit();       // 2
	// Total: 1+2+2+2+3+3+1+1+1+1+2 = 19

	test_cleanup_minimal();
	return exit_status();
}
