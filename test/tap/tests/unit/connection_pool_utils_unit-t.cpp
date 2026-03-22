/**
 * @file connection_pool_utils_unit-t.cpp
 * @brief Unit tests for connection-pool decision functions.
 *
 * Tests the three pure functions extracted from get_random_MyConn():
 *   - calculate_eviction_count()
 *   - should_throttle_connection_creation()
 *   - evaluate_pool_state()
 *
 * These functions are pure (no global state, no I/O) and are defined in
 * lib/MySrvConnList.cpp, declared in include/Base_HostGroups_Manager.h,
 * and linked via libproxysql.a.
 *
 * Tests cover:
 *   1. calculate_eviction_count — eviction threshold arithmetic
 *   2. should_throttle_connection_creation — throttle gate
 *   3. evaluate_pool_state — full decision logic (create/reuse/evict/warming)
 *
 * @note No running ProxySQL instance or backend database is required.
 * @see Phase 3.1 of the Unit Testing Milestone 3 (GitHub issue #5479)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "MySQL_HostGroups_Manager.h"


// ============================================================================
// Test: calculate_eviction_count
// ============================================================================

/**
 * @brief Tests for calculate_eviction_count().
 *
 * Eviction is triggered when total (free + used) >= (3 * max) / 4 and at
 * least one free connection exists.  When triggered, the count is always
 * at least 1.
 */
static void test_calculate_eviction_count() {
	// No free connections → no eviction regardless of totals
	ok(calculate_eviction_count(0, 100, 100) == 0,
		"conns_free=0: no eviction even when used is high");

	// Total well below 75% threshold → no eviction
	ok(calculate_eviction_count(5, 5, 100) == 0,
		"total=10 < 75 of 100: no eviction needed");

	// Total exactly at 75% threshold → eviction triggered (condition: pct <= total)
	unsigned int e_at = calculate_eviction_count(25, 50, 100);
	ok(e_at == 1,
		"total=75 == 75%% of 100: eviction triggered at threshold (got %u)", e_at);

	// Total slightly over 75% → evict 1
	ok(calculate_eviction_count(26, 50, 100) == 1,
		"total=76 > 75%% of 100: evict 1");

	// Total well over 75% → evict proportionally
	unsigned int e1 = calculate_eviction_count(50, 100, 100);
	ok(e1 == 75,
		"total=150, 75%%=75: evict 75 (got %u)", e1);

	// All connections free, over threshold
	unsigned int e2 = calculate_eviction_count(80, 0, 100);
	ok(e2 == 5,
		"conns_free=80, used=0, 75%%=75: evict 5 (got %u)", e2);

	// Edge: max_connections=0 → pct=0 → everything is over threshold
	unsigned int e3 = calculate_eviction_count(1, 0, 0);
	ok(e3 >= 1,
		"max_connections=0, conns_free=1: eviction triggered (got %u)", e3);

	// Edge: max_connections=1, one free connection → over 75% threshold
	unsigned int e4 = calculate_eviction_count(1, 0, 1);
	ok(e4 >= 1,
		"max_connections=1, conns_free=1: over 75%% threshold (got %u)", e4);

	// conns_free=1, conns_used=73, max=100 → total=74, pct=75 → 75 <= 74 is FALSE → no eviction
	ok(calculate_eviction_count(1, 73, 100) == 0,
		"total=74 < pct=75: no eviction");

	// conns_free=1, conns_used=74, max=100 → total=75, pct=75 → 75 <= 75 → evict at least 1
	unsigned int e_threshold = calculate_eviction_count(1, 74, 100);
	ok(e_threshold == 1,
		"total=75 == pct=75: eviction triggered at threshold (got %u)", e_threshold);
}


// ============================================================================
// Test: should_throttle_connection_creation
// ============================================================================

/**
 * @brief Tests for should_throttle_connection_creation().
 *
 * Returns true only when new_connections_now strictly exceeds the limit.
 */
static void test_should_throttle_connection_creation() {
	// Exactly at limit → not throttled (strictly greater-than semantics)
	ok(!should_throttle_connection_creation(100, 100),
		"new_conns==limit: not throttled");

	// One over limit → throttled
	ok(should_throttle_connection_creation(101, 100),
		"new_conns > limit: throttled");

	// Well below limit → not throttled
	ok(!should_throttle_connection_creation(0, 1000000),
		"new_conns=0: not throttled");

	// Zero limit, one connection → throttled
	ok(should_throttle_connection_creation(1, 0),
		"limit=0, new_conns=1: throttled");

	// Zero limit, zero connections → not throttled (0 is not > 0)
	ok(!should_throttle_connection_creation(0, 0),
		"limit=0, new_conns=0: not throttled");

	// Very large values
	ok(!should_throttle_connection_creation(999999, 1000000),
		"new_conns=999999, limit=1000000: not throttled");

	ok(should_throttle_connection_creation(1000001, 1000000),
		"new_conns=1000001, limit=1000000: throttled");
}


// ============================================================================
// Test: evaluate_pool_state — quality level decisions
// ============================================================================

/**
 * @brief Tests for evaluate_pool_state() quality-level create-vs-reuse logic.
 *
 * Quality 0 → create new; quality 1 → may create; quality 2/3 → reuse.
 */
static void test_evaluate_pool_state_quality_levels() {
	// Quality 0 (no match) → must create new
	ConnectionPoolDecision d0 = evaluate_pool_state(5, 5, 100, 0, false, 0);
	ok(d0.create_new_connection,
		"quality=0: create_new_connection=true");
	ok(!d0.needs_warming,
		"quality=0, warming off: needs_warming=false");

	// Quality 1 with conns_used > conns_free and room to grow → create new
	ConnectionPoolDecision d1a = evaluate_pool_state(3, 10, 100, 1, false, 0);
	ok(d1a.create_new_connection,
		"quality=1, used>free, room to grow: create_new=true");

	// Quality 1 with conns_used <= conns_free → reuse existing
	ConnectionPoolDecision d1b = evaluate_pool_state(10, 3, 100, 1, false, 0);
	ok(!d1b.create_new_connection,
		"quality=1, used<=free: create_new=false (reuse)");

	// Quality 1 with conns_used > conns_free but max_connections <= avg → reuse
	// conns_free=3, conns_used=10 → avg=6; max_connections=6 → 6 > 6 is FALSE → reuse
	ConnectionPoolDecision d1c = evaluate_pool_state(3, 10, 6, 1, false, 0);
	ok(!d1c.create_new_connection,
		"quality=1, used>free but max<=avg: create_new=false (reuse)");

	// Quality 2 → always reuse
	ConnectionPoolDecision d2 = evaluate_pool_state(5, 5, 100, 2, false, 0);
	ok(!d2.create_new_connection,
		"quality=2: create_new=false (reuse)");

	// Quality 3 → always reuse (perfect match)
	ConnectionPoolDecision d3 = evaluate_pool_state(5, 5, 100, 3, false, 0);
	ok(!d3.create_new_connection,
		"quality=3: create_new=false (perfect reuse)");
}


// ============================================================================
// Test: evaluate_pool_state — eviction
// ============================================================================

/**
 * @brief Tests for evaluate_pool_state() eviction logic.
 *
 * Eviction only applies when quality=0 (no good match found).
 */
static void test_evaluate_pool_state_eviction() {
	// Quality 0 with pool below 75% → no eviction
	ConnectionPoolDecision d_no_evict = evaluate_pool_state(5, 5, 100, 0, false, 0);
	ok(!d_no_evict.evict_connections,
		"quality=0, total=10 < 75: no eviction");
	ok(d_no_evict.num_to_evict == 0,
		"quality=0, total=10 < 75: num_to_evict=0");

	// Quality 0 with pool over 75% → eviction triggered
	ConnectionPoolDecision d_evict = evaluate_pool_state(10, 80, 100, 0, false, 0);
	ok(d_evict.evict_connections,
		"quality=0, total=90 > 75: eviction triggered");
	ok(d_evict.num_to_evict > 0,
		"quality=0, total=90 > 75: num_to_evict > 0 (got %u)", d_evict.num_to_evict);

	// Quality 2/3 never triggers eviction (just reuse)
	ConnectionPoolDecision d_q2 = evaluate_pool_state(10, 80, 100, 2, false, 0);
	ok(!d_q2.evict_connections,
		"quality=2: no eviction even when over 75%%");

	// Edge: max_connections=0
	ConnectionPoolDecision d_max0 = evaluate_pool_state(1, 0, 0, 0, false, 0);
	ok(d_max0.create_new_connection,
		"max_connections=0, quality=0: create_new=true");

	// Edge: max_connections=1, single free conn
	ConnectionPoolDecision d_max1 = evaluate_pool_state(1, 0, 1, 0, false, 0);
	ok(d_max1.create_new_connection,
		"max_connections=1, conns_free=1: create_new=true");
	ok(d_max1.evict_connections,
		"max_connections=1, conns_free=1: eviction triggered (over 75%%)");

	// Pool empty → quality=0 → create new but no eviction (nothing to evict)
	ConnectionPoolDecision d_empty = evaluate_pool_state(0, 0, 100, 0, false, 0);
	ok(d_empty.create_new_connection,
		"empty pool, quality=0: create_new=true");
	ok(!d_empty.evict_connections,
		"empty pool, quality=0: no eviction (nothing to evict)");
	ok(d_empty.num_to_evict == 0,
		"empty pool: num_to_evict=0");
}


// ============================================================================
// Test: evaluate_pool_state — connection warming
// ============================================================================

/**
 * @brief Tests for evaluate_pool_state() connection warming logic.
 *
 * When warming is enabled and total connections < (free_pct * max / 100),
 * needs_warming=true is returned and create_new_connection is forced true
 * regardless of quality level.
 */
static void test_evaluate_pool_state_warming() {
	// Warming disabled → no warming signal
	ConnectionPoolDecision d_no_warm = evaluate_pool_state(0, 0, 100, 3, false, 10);
	ok(!d_no_warm.needs_warming,
		"warming disabled: needs_warming=false");

	// Warming enabled, pool well below threshold → warming needed
	// free_connections_pct=10, max=100 → expected_warm=10; total=0 < 10
	ConnectionPoolDecision d_warm = evaluate_pool_state(0, 0, 100, 3, true, 10);
	ok(d_warm.needs_warming,
		"warming enabled, total=0 < expected=10: needs_warming=true");
	ok(d_warm.create_new_connection,
		"warming needed → create_new=true");

	// Warming enabled, pool meets threshold → no warming
	// free_connections_pct=10, max=100 → expected_warm=10; total=10 is NOT < 10
	ConnectionPoolDecision d_warm_met = evaluate_pool_state(5, 5, 100, 3, true, 10);
	ok(!d_warm_met.needs_warming,
		"warming enabled, total=10 >= expected=10: needs_warming=false");

	// Warming enabled, pool exceeds threshold → no warming
	ConnectionPoolDecision d_warm_over = evaluate_pool_state(20, 10, 100, 3, true, 10);
	ok(!d_warm_over.needs_warming,
		"warming enabled, total=30 > expected=10: needs_warming=false");

	// Warming overrides quality level: quality=3 (perfect match) but warming forces create
	ConnectionPoolDecision d_warm_q3 = evaluate_pool_state(2, 3, 100, 3, true, 10);
	ok(d_warm_q3.needs_warming && d_warm_q3.create_new_connection,
		"warming+quality=3, total=5 < expected=10: create_new=true (warming override)");

	// Warming with free_connections_pct=0 → expected_warm=0 → never triggers
	ConnectionPoolDecision d_warm_pct0 = evaluate_pool_state(0, 0, 100, 3, true, 0);
	ok(!d_warm_pct0.needs_warming,
		"warming, free_connections_pct=0: expected_warm=0, needs_warming=false");

	// Warming with max_connections=0 → expected_warm=0 → never triggers
	ConnectionPoolDecision d_warm_max0 = evaluate_pool_state(0, 0, 0, 3, true, 10);
	ok(!d_warm_max0.needs_warming,
		"warming, max_connections=0: expected_warm=0, needs_warming=false");
}


// ============================================================================
// Test: evaluate_pool_state — combined scenarios
// ============================================================================

/**
 * @brief Combined/integration tests for evaluate_pool_state().
 */
static void test_evaluate_pool_state_combined() {
	// Pool has perfect match → reuse even when near capacity
	ConnectionPoolDecision d_reuse = evaluate_pool_state(30, 60, 100, 3, false, 0);
	ok(!d_reuse.create_new_connection,
		"quality=3, near capacity: reuse (no create)");
	ok(!d_reuse.evict_connections,
		"quality=3: no eviction for reuse path");

	// Quality=1 at boundary: used==free (equal) → reuse (condition is strictly used>free)
	ConnectionPoolDecision d_q1_eq = evaluate_pool_state(5, 5, 100, 1, false, 0);
	ok(!d_q1_eq.create_new_connection,
		"quality=1, used==free: reuse (used not > free)");

	// Warming off, quality=0, heavily over threshold → large eviction
	ConnectionPoolDecision d_big_evict = evaluate_pool_state(100, 100, 100, 0, false, 0);
	ok(d_big_evict.evict_connections,
		"quality=0, total=200 >> 75: eviction");
	ok(d_big_evict.num_to_evict == 125,
		"quality=0, total=200, pct=75: evict 125 (got %u)", d_big_evict.num_to_evict);

	// Throttle limit exceeded → creation denied (tested separately above, confirm here)
	ok(should_throttle_connection_creation(1001, 1000),
		"throttle sanity check: 1001 > 1000 → throttled");
}


// ============================================================================
// Main
// ============================================================================

int main() {
	// Plan:
	//  calculate_eviction_count:         10 tests
	//  should_throttle:                   7 tests
	//  evaluate_pool_state/quality:       7 tests
	//  evaluate_pool_state/eviction:      11 tests
	//  evaluate_pool_state/warming:       8 tests
	//  evaluate_pool_state/combined:      6 tests
	// Total: 49 tests
	plan(49);

	test_init_minimal();

	test_calculate_eviction_count();
	test_should_throttle_connection_creation();
	test_evaluate_pool_state_quality_levels();
	test_evaluate_pool_state_eviction();
	test_evaluate_pool_state_warming();
	test_evaluate_pool_state_combined();

	test_cleanup_minimal();

	return exit_status();
}
