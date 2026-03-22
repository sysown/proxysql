/**
 * @file hostgroup_routing_unit-t.cpp
 * @brief Unit tests for hostgroup routing decision logic.
 *
 * @see Phase 3.5 (GitHub issue #5493)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "HostgroupRouting.h"

static void test_basic_routing() {
	// No transaction, no lock → uses QP destination
	auto d = resolve_hostgroup_routing(0, 5, -1, -1, false, false);
	ok(d.target_hostgroup == 5, "basic: QP destination used");
	ok(d.error == false, "basic: no error");

	// QP destination -1 → uses default
	auto d2 = resolve_hostgroup_routing(0, -1, -1, -1, false, false);
	ok(d2.target_hostgroup == 0, "basic: default HG when QP=-1");
}

static void test_transaction_affinity() {
	// Transaction active → overrides QP destination
	auto d = resolve_hostgroup_routing(0, 5, 3, -1, false, false);
	ok(d.target_hostgroup == 3,
		"txn: transaction_persistent_hostgroup overrides QP");

	// Transaction + QP both set → transaction wins
	auto d2 = resolve_hostgroup_routing(0, 10, 7, -1, false, false);
	ok(d2.target_hostgroup == 7, "txn: transaction wins over QP");
}

static void test_locking_acquire() {
	// Lock enabled, lock_hostgroup=true, not yet locked → acquires lock
	auto d = resolve_hostgroup_routing(0, 5, -1, -1, true, true);
	ok(d.target_hostgroup == 5, "lock acquire: routes to QP dest");
	ok(d.new_locked_on_hostgroup == 5,
		"lock acquire: lock set to target HG");
	ok(d.error == false, "lock acquire: no error");
}

static void test_locking_enforce() {
	// Already locked on HG 5, QP routes to 5 → ok
	auto d = resolve_hostgroup_routing(0, 5, -1, 5, false, true);
	ok(d.target_hostgroup == 5, "lock enforce: same HG ok");
	ok(d.error == false, "lock enforce: no error on match");

	// Already locked on HG 5, QP routes to 10 → error
	auto d2 = resolve_hostgroup_routing(0, 10, -1, 5, false, true);
	ok(d2.error == true, "lock enforce: error on HG mismatch");
	ok(d2.target_hostgroup == 5,
		"lock enforce: stays on locked HG despite QP mismatch");
}

static void test_locking_disabled() {
	// Lock feature disabled → no locking even with flag
	auto d = resolve_hostgroup_routing(0, 5, -1, -1, true, false);
	ok(d.new_locked_on_hostgroup == -1,
		"lock disabled: no lock acquired");

	// Lock feature disabled → no enforcement even if locked state passed
	auto d2 = resolve_hostgroup_routing(0, 10, -1, 5, false, false);
	ok(d2.target_hostgroup == 10,
		"lock disabled: routes to QP dest ignoring lock");
	ok(d2.error == false, "lock disabled: no error");
}

static void test_transaction_plus_lock() {
	// Transaction active + locked on same HG → no error
	auto d = resolve_hostgroup_routing(0, 10, 3, 3, false, true);
	ok(d.target_hostgroup == 3,
		"txn+lock: transaction HG used");
	ok(d.error == false, "txn+lock: no error when txn matches lock");

	// Transaction active on HG 3 but locked on HG 5 → error (mismatch)
	auto d2 = resolve_hostgroup_routing(0, 10, 3, 5, false, true);
	ok(d2.error == true,
		"txn+lock: error when txn HG differs from lock HG");
}

static void test_edge_cases() {
	// default_hostgroup=-1 (shouldn't happen but handle gracefully)
	auto d = resolve_hostgroup_routing(-1, -1, -1, -1, false, false);
	ok(d.target_hostgroup == -1, "edge: negative defaults pass through");

	// All zeros
	auto d2 = resolve_hostgroup_routing(0, 0, -1, -1, false, false);
	ok(d2.target_hostgroup == 0, "edge: HG 0 is valid");
}

int main() {
	plan(21);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_basic_routing();            // 3
	test_transaction_affinity();     // 2
	test_locking_acquire();          // 3
	test_locking_enforce();          // 4
	test_locking_disabled();         // 3
	test_transaction_plus_lock();    // 3
	test_edge_cases();               // 2
	// Total: 1+3+2+3+4+3+3+2 = 21

	test_cleanup_minimal();
	return exit_status();
}
