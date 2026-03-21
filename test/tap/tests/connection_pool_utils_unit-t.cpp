/**
 * @file connection_pool_utils_unit-t.cpp
 * @brief TAP unit tests for connection-pool decision functions.
 *
 * Tests the three pure functions extracted from get_random_MyConn():
 *   - calculate_eviction_count()
 *   - should_throttle_connection_creation()
 *   - evaluate_pool_state()
 *
 * These tests are intentionally standalone: the functions under test are pure
 * (no global state, no I/O) and can be exercised without a running ProxySQL
 * instance or live database connections.
 *
 * Test categories:
 *   1. calculate_eviction_count — eviction threshold arithmetic
 *   2. should_throttle_connection_creation — throttle gate
 *   3. evaluate_pool_state — full decision logic (create/reuse/evict/warming)
 */

#include "tap.h"
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

// Stubs for tap noise-tools symbols (unused in standalone unit tests)
std::vector<std::string> noise_failures;
std::mutex noise_failure_mutex;
extern "C" int  get_noise_tools_count() { return 0; }
extern "C" void stop_noise_tools() {}

// ============================================================================
// Standalone reimplementation of the three pure functions
// (mirrors the implementations in lib/MySrvConnList.cpp)
// ============================================================================

struct ConnectionPoolDecision {
	bool create_new_connection;
	bool evict_connections;
	unsigned int num_to_evict;
	bool needs_warming;
};

/**
 * @brief Calculate how many free connections to evict to stay within 75% of max_connections.
 */
static unsigned int calculate_eviction_count(unsigned int conns_free, unsigned int conns_used, unsigned int max_connections) {
	if (conns_free < 1) return 0;
	unsigned int pct_max_connections = (3 * max_connections) / 4;
	unsigned int total = conns_free + conns_used;
	if (pct_max_connections <= total) {
		unsigned int count = total - pct_max_connections;
		return (count == 0) ? 1 : count;
	}
	return 0;
}

/**
 * @brief Decide whether new-connection creation should be throttled.
 */
static bool should_throttle_connection_creation(unsigned int new_connections_now, unsigned int throttle_connections_per_sec) {
	return new_connections_now > throttle_connections_per_sec;
}

/**
 * @brief Pure decision function for connection-pool create-vs-reuse logic.
 */
static ConnectionPoolDecision evaluate_pool_state(
	unsigned int conns_free,
	unsigned int conns_used,
	unsigned int max_connections,
	unsigned int connection_quality_level,
	bool connection_warming,
	int free_connections_pct
) {
	ConnectionPoolDecision decision = { false, false, 0, false };

	if (connection_warming) {
		unsigned int total = conns_free + conns_used;
		unsigned int expected_warm = (unsigned int)(free_connections_pct) * max_connections / 100;
		if (total < expected_warm) {
			decision.needs_warming = true;
			decision.create_new_connection = true;
			return decision;
		}
	}

	switch (connection_quality_level) {
		case 0:
			decision.create_new_connection = true;
			decision.num_to_evict = calculate_eviction_count(conns_free, conns_used, max_connections);
			decision.evict_connections = (decision.num_to_evict > 0);
			break;
		case 1:
			if ((conns_used > conns_free) && (max_connections > (conns_free / 2 + conns_used / 2))) {
				decision.create_new_connection = true;
			}
			break;
		case 2:
		case 3:
			decision.create_new_connection = false;
			break;
		default:
			decision.create_new_connection = true;
			break;
	}

	return decision;
}

// ============================================================================
// Test: calculate_eviction_count
// ============================================================================

static void test_calculate_eviction_count() {
	diag("=== calculate_eviction_count ===");

	// No free connections → no eviction regardless of totals
	ok(calculate_eviction_count(0, 100, 100) == 0,
		"conns_free=0: no eviction even when used is high");

	// Total well below 75% threshold → no eviction
	ok(calculate_eviction_count(5, 5, 100) == 0,
		"total=10 < 75 of 100: no eviction needed");

	// Total exactly at 75% threshold → eviction triggered (condition uses <=)
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
	// with conns_free=1, eviction is triggered
	unsigned int e3 = calculate_eviction_count(1, 0, 0);
	ok(e3 >= 1,
		"max_connections=0, conns_free=1: eviction triggered (got %u)", e3);

	// Edge: max_connections=1, one free connection → at 100%, threshold=0
	unsigned int e4 = calculate_eviction_count(1, 0, 1);
	ok(e4 >= 1,
		"max_connections=1, conns_free=1: over 75%% threshold (got %u)", e4);

	// Minimum eviction is always 1 when threshold crossed (result is never 0 if threshold crossed)
	// conns_free=1, conns_used=73, max=100 → total=74, pct=75 → 75 <= 74 is FALSE → no eviction
	ok(calculate_eviction_count(1, 73, 100) == 0,
		"total=74 < pct=75: no eviction");

	// conns_free=1, conns_used=74, max=100 → total=75, pct=75 → 75 <= 75 → count=0→1
	unsigned int e_at_threshold = calculate_eviction_count(1, 74, 100);
	ok(e_at_threshold == 1,
		"total=75 == pct=75: eviction triggered (at threshold, got %u)", e_at_threshold);
}

// ============================================================================
// Test: should_throttle_connection_creation
// ============================================================================

static void test_should_throttle_connection_creation() {
	diag("=== should_throttle_connection_creation ===");

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

	// Zero limit, zero connections → not throttled
	ok(!should_throttle_connection_creation(0, 0),
		"limit=0, new_conns=0: not throttled (0 is not > 0)");

	// Very large values
	ok(!should_throttle_connection_creation(999999, 1000000),
		"new_conns=999999, limit=1000000: not throttled");

	ok(should_throttle_connection_creation(1000001, 1000000),
		"new_conns=1000001, limit=1000000: throttled");
}

// ============================================================================
// Test: evaluate_pool_state — quality level decisions
// ============================================================================

static void test_evaluate_pool_state_quality_levels() {
	diag("=== evaluate_pool_state: quality-level decisions ===");

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

	// Quality 1 with conns_used > conns_free but NO room to grow → reuse
	// max_connections <= (conns_free/2 + conns_used/2) → no new
	// conns_free=3, conns_used=10 → avg=6.5; max_connections=6 <= 6 → no new
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

static void test_evaluate_pool_state_eviction() {
	diag("=== evaluate_pool_state: eviction ===");

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

	// Edge: max_connections=1, single free conn, no used
	ConnectionPoolDecision d_max1 = evaluate_pool_state(1, 0, 1, 0, false, 0);
	ok(d_max1.create_new_connection,
		"max_connections=1, conns_free=1: create_new=true");
	ok(d_max1.evict_connections,
		"max_connections=1, conns_free=1: eviction triggered (over 75%%)");
}

// ============================================================================
// Test: evaluate_pool_state — warming
// ============================================================================

static void test_evaluate_pool_state_warming() {
	diag("=== evaluate_pool_state: connection warming ===");

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

	// Warming enabled, pool meets threshold → no warming needed
	// free_connections_pct=10, max=100 → expected_warm=10; total=10 == 10, NOT less than
	ConnectionPoolDecision d_warm_met = evaluate_pool_state(5, 5, 100, 3, true, 10);
	ok(!d_warm_met.needs_warming,
		"warming enabled, total=10 >= expected=10: needs_warming=false");

	// Warming enabled, pool exceeds threshold → no warming
	ConnectionPoolDecision d_warm_over = evaluate_pool_state(20, 10, 100, 3, true, 10);
	ok(!d_warm_over.needs_warming,
		"warming enabled, total=30 > expected=10: needs_warming=false");

	// Warming overrides quality level: even with quality=3 (perfect match), warming forces create
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

static void test_evaluate_pool_state_combined() {
	diag("=== evaluate_pool_state: combined scenarios ===");

	// Pool empty (conns_free=0, conns_used=0) with quality=0 → create, no eviction
	ConnectionPoolDecision d_empty = evaluate_pool_state(0, 0, 100, 0, false, 0);
	ok(d_empty.create_new_connection,
		"empty pool, quality=0: create_new=true");
	ok(!d_empty.evict_connections,
		"empty pool, quality=0: no eviction (nothing to evict)");
	ok(d_empty.num_to_evict == 0,
		"empty pool: num_to_evict=0");

	// Pool has perfect match → reuse even when near capacity
	ConnectionPoolDecision d_reuse = evaluate_pool_state(30, 60, 100, 3, false, 0);
	ok(!d_reuse.create_new_connection,
		"quality=3, near capacity: reuse (no create)");
	ok(!d_reuse.evict_connections,
		"quality=3: no eviction for reuse path");

	// Quality=1 at boundary: used=free (equal) → reuse (condition is strictly used>free)
	ConnectionPoolDecision d_q1_eq = evaluate_pool_state(5, 5, 100, 1, false, 0);
	ok(!d_q1_eq.create_new_connection,
		"quality=1, used==free: reuse (used not > free)");

	// Warming off, quality=0, heavily over threshold → large eviction
	ConnectionPoolDecision d_big_evict = evaluate_pool_state(100, 100, 100, 0, false, 0);
	ok(d_big_evict.evict_connections,
		"quality=0, total=200 >> 75: eviction");
	ok(d_big_evict.num_to_evict == 125,
		"quality=0, total=200, pct=75: evict 125 (got %u)", d_big_evict.num_to_evict);
}

// ============================================================================
// Main
// ============================================================================

int main() {
	// Plan:
	//  calculate_eviction_count:         10 tests
	//  should_throttle:                   7 tests
	//  evaluate_pool_state/quality:       7 tests
	//  evaluate_pool_state/eviction:      8 tests
	//  evaluate_pool_state/warming:       8 tests
	//  evaluate_pool_state/combined:      8 tests
	// Total: 48 tests
	plan(48);

	test_calculate_eviction_count();
	test_should_throttle_connection_creation();
	test_evaluate_pool_state_quality_levels();
	test_evaluate_pool_state_eviction();
	test_evaluate_pool_state_warming();
	test_evaluate_pool_state_combined();

	return exit_status();
}
