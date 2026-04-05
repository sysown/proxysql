/**
 * @file monitor_health_unit-t.cpp
 * @brief Unit tests for monitor health state decision functions.
 *
 * Tests the pure functions extracted from MySQL_Monitor, MySrvC,
 * and MyHGC:
 *   - should_shun_on_connect_errors()
 *   - can_unshun_server()
 *   - should_shun_on_replication_lag()
 *   - can_recover_from_replication_lag()
 *
 * @see Phase 3.3 (GitHub issue #5491)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "MonitorHealthDecision.h"

// ============================================================================
// 1. should_shun_on_connect_errors
// ============================================================================

static void test_shun_connect_errors() {
	// shun_on_failures=5, connect_retries=3 → threshold = min(5, 3+1) = 4
	ok(should_shun_on_connect_errors(4, 5, 3) == true,
		"shun: errors=4 meets threshold min(5,4)=4");
	ok(should_shun_on_connect_errors(3, 5, 3) == false,
		"no shun: errors=3 below threshold 4");
	ok(should_shun_on_connect_errors(10, 5, 3) == true,
		"shun: errors=10 exceeds threshold");

	// shun_on_failures=2, connect_retries=10 → threshold = min(2, 11) = 2
	ok(should_shun_on_connect_errors(2, 2, 10) == true,
		"shun: errors=2 meets threshold min(2,11)=2");
	ok(should_shun_on_connect_errors(1, 2, 10) == false,
		"no shun: errors=1 below threshold 2");

	// Edge: shun_on_failures=1 → shun on first error
	ok(should_shun_on_connect_errors(1, 1, 0) == true,
		"shun: threshold=1, first error triggers shun");
	ok(should_shun_on_connect_errors(0, 1, 0) == false,
		"no shun: zero errors");
}

// ============================================================================
// 2. can_unshun_server
// ============================================================================

static void test_unshun_time_elapsed() {
	// Recovery after enough time: last_error=100, now=200, recovery=10s
	ok(can_unshun_server(100, 200, 10, 60000, false, 0, 0) == true,
		"unshun: 100s elapsed > 10s recovery");

	// Not enough time: last_error=100, now=105, recovery=10s
	ok(can_unshun_server(100, 105, 10, 60000, false, 0, 0) == false,
		"no unshun: 5s elapsed < 10s recovery");

	// Exactly at boundary: elapsed == recovery → should NOT unshun (needs >)
	ok(can_unshun_server(100, 110, 10, 60000, false, 0, 0) == false,
		"no unshun: elapsed == recovery (needs >)");
}

static void test_unshun_timeout_cap() {
	// recovery=30s, connect_timeout_max=10000ms → cap = 10000/1000-1 = 9s
	ok(can_unshun_server(100, 200, 30, 10000, false, 0, 0) == true,
		"unshun: capped to 9s, 100s elapsed is enough");

	// recovery=30s, connect_timeout_max=10000ms, but only 5s elapsed
	ok(can_unshun_server(100, 105, 30, 10000, false, 0, 0) == false,
		"no unshun: capped to 9s but only 5s elapsed");
}

static void test_unshun_kill_all_conns() {
	// kill_all=true, connections still active → cannot unshun
	ok(can_unshun_server(100, 200, 10, 60000, true, 5, 0) == false,
		"no unshun: kill_all=true, used=5");
	ok(can_unshun_server(100, 200, 10, 60000, true, 0, 3) == false,
		"no unshun: kill_all=true, free=3");

	// kill_all=true, all connections drained → can unshun
	ok(can_unshun_server(100, 200, 10, 60000, true, 0, 0) == true,
		"unshun: kill_all=true, all connections drained");

	// kill_all=false, connections exist → can still unshun
	ok(can_unshun_server(100, 200, 10, 60000, false, 10, 5) == true,
		"unshun: kill_all=false, connections don't matter");
}

static void test_unshun_recovery_disabled() {
	// recovery_time=0 → recovery disabled
	ok(can_unshun_server(100, 200, 0, 60000, false, 0, 0) == false,
		"no unshun: recovery disabled (recovery_time=0)");
}

static void test_unshun_clock_skew() {
	// current_time <= time_last_error → no recovery
	ok(can_unshun_server(200, 100, 10, 60000, false, 0, 0) == false,
		"no unshun: clock skew (current < last_error)");
	ok(can_unshun_server(100, 100, 10, 60000, false, 0, 0) == false,
		"no unshun: current == last_error");
}

static void test_unshun_max_wait_minimum() {
	// recovery=1s, timeout_max=500ms → cap = 500/1000-1 = -1 → clamped to 1
	ok(can_unshun_server(100, 103, 1, 500, false, 0, 0) == true,
		"unshun: max_wait clamped to 1s minimum, 3s elapsed");
}

// ============================================================================
// 3. should_shun_on_replication_lag
// ============================================================================

static void test_replication_lag_shun() {
	// lag=15, max=10, count=3, threshold=3 → shun
	ok(should_shun_on_replication_lag(15, 10, 3, 3) == true,
		"lag shun: lag=15 > max=10, count=3 meets threshold=3");

	// lag=15, max=10, count=2, threshold=3 → not yet
	ok(should_shun_on_replication_lag(15, 10, 2, 3) == false,
		"no lag shun: count=2 below threshold=3");

	// lag=5, max=10 → within bounds
	ok(should_shun_on_replication_lag(5, 10, 10, 1) == false,
		"no lag shun: lag=5 within max=10");

	// max_replication_lag=0 → check disabled
	ok(should_shun_on_replication_lag(100, 0, 10, 1) == false,
		"no lag shun: check disabled (max=0)");

	// lag=-1 (unknown) → don't shun
	ok(should_shun_on_replication_lag(-1, 10, 10, 1) == false,
		"no lag shun: lag unknown (-1)");

	// lag exactly at max → not shunned (needs >)
	ok(should_shun_on_replication_lag(10, 10, 5, 1) == false,
		"no lag shun: lag=10 == max=10 (needs >)");
}

// ============================================================================
// 4. can_recover_from_replication_lag
// ============================================================================

static void test_replication_lag_recovery() {
	// lag drops below max → recover
	ok(can_recover_from_replication_lag(5, 10) == true,
		"lag recover: lag=5 <= max=10");

	// lag exactly at max → recover
	ok(can_recover_from_replication_lag(10, 10) == true,
		"lag recover: lag=10 == max=10");

	// lag still above → don't recover
	ok(can_recover_from_replication_lag(15, 10) == false,
		"no lag recover: lag=15 > max=10");

	// unknown lag → don't recover
	ok(can_recover_from_replication_lag(-1, 10) == false,
		"no lag recover: lag unknown (-1)");
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(31);

	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_shun_connect_errors();        // 7
	test_unshun_time_elapsed();        // 3
	test_unshun_timeout_cap();         // 2
	test_unshun_kill_all_conns();      // 4
	test_unshun_recovery_disabled();   // 1
	test_unshun_clock_skew();          // 2
	test_unshun_max_wait_minimum();    // 1
	test_replication_lag_shun();       // 6
	test_replication_lag_recovery();   // 4
	// Total: 1+7+3+2+4+1+2+1+6+4 = 31

	test_cleanup_minimal();
	return exit_status();
}
