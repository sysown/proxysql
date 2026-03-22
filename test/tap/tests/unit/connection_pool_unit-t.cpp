/**
 * @file connection_pool_unit-t.cpp
 * @brief Unit tests for connection pool decision functions.
 *
 * Tests the pure functions extracted from get_random_MyConn():
 *   - calculate_eviction_count()
 *   - should_throttle_connection_creation()
 *   - evaluate_pool_state()
 *
 * These functions have no global state dependencies and are linked
 * from libproxysql.a via the unit test harness.
 *
 * @see Phase 3.1 (GitHub issue #5489)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "ConnectionPoolDecision.h"

// ============================================================================
// 1. calculate_eviction_count
// ============================================================================

static void test_eviction_below_threshold() {
	ok(calculate_eviction_count(10, 10, 100) == 0,
		"eviction: no eviction when total=20, below 75%% of 100");
}

static void test_eviction_at_threshold() {
	unsigned int c = calculate_eviction_count(50, 25, 100);
	ok(c >= 1, "eviction: at least 1 at 75%% threshold (got %u)", c);
}

static void test_eviction_above_threshold() {
	ok(calculate_eviction_count(60, 30, 100) == 15,
		"eviction: evict 15 when total=90, max=100");
}

static void test_eviction_no_free() {
	ok(calculate_eviction_count(0, 80, 100) == 0,
		"eviction: 0 when no free connections");
}

static void test_eviction_max_zero() {
	ok(calculate_eviction_count(5, 0, 0) >= 1,
		"eviction: evicts when max_connections=0");
}

static void test_eviction_max_one() {
	ok(calculate_eviction_count(1, 0, 1) >= 1,
		"eviction: evicts when max_connections=1");
}

// ============================================================================
// 2. should_throttle_connection_creation
// ============================================================================

static void test_throttle() {
	ok(should_throttle_connection_creation(0, 10) == false,
		"throttle: not throttled at 0/10");
	ok(should_throttle_connection_creation(10, 10) == false,
		"throttle: not throttled at limit");
	ok(should_throttle_connection_creation(11, 10) == true,
		"throttle: throttled above limit");
	ok(should_throttle_connection_creation(100, 0) == true,
		"throttle: throttled when limit=0");
}

// ============================================================================
// 3. evaluate_pool_state
// ============================================================================

static void test_pool_quality_0() {
	auto d = evaluate_pool_state(5, 5, 100, 0, false, 0);
	ok(d.create_new_connection == true,
		"pool q=0: creates new connection");
}

static void test_pool_quality_0_evict() {
	auto d = evaluate_pool_state(50, 30, 100, 0, false, 0);
	ok(d.create_new_connection == true, "pool q=0 full: creates");
	ok(d.evict_connections == true, "pool q=0 full: evicts");
	ok(d.num_to_evict > 0, "pool q=0 full: num_to_evict > 0");
}

static void test_pool_quality_1_create() {
	auto d = evaluate_pool_state(2, 10, 100, 1, false, 0);
	ok(d.create_new_connection == true,
		"pool q=1: creates when used > free");
}

static void test_pool_quality_1_reuse() {
	auto d = evaluate_pool_state(10, 5, 100, 1, false, 0);
	ok(d.create_new_connection == false,
		"pool q=1: reuses when free >= used");
}

static void test_pool_quality_2_3() {
	ok(evaluate_pool_state(10, 10, 100, 2, false, 0).create_new_connection == false,
		"pool q=2: reuses");
	ok(evaluate_pool_state(10, 10, 100, 3, false, 0).create_new_connection == false,
		"pool q=3: reuses");
}

static void test_pool_warming() {
	auto d = evaluate_pool_state(5, 5, 100, 3, true, 50);
	ok(d.needs_warming == true, "warming: below threshold");
	ok(d.create_new_connection == true, "warming: creates");

	auto d2 = evaluate_pool_state(30, 30, 100, 3, true, 10);
	ok(d2.needs_warming == false, "warming: above threshold");
}

static void test_pool_empty() {
	auto d = evaluate_pool_state(0, 0, 100, 0, false, 0);
	ok(d.create_new_connection == true, "empty pool: creates");
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(23);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_eviction_below_threshold();   // 1
	test_eviction_at_threshold();      // 1
	test_eviction_above_threshold();   // 1
	test_eviction_no_free();           // 1
	test_eviction_max_zero();          // 1
	test_eviction_max_one();           // 1
	test_throttle();                   // 4
	test_pool_quality_0();             // 1
	test_pool_quality_0_evict();       // 3
	test_pool_quality_1_create();      // 1
	test_pool_quality_1_reuse();       // 1
	test_pool_quality_2_3();           // 2
	test_pool_warming();               // 3
	test_pool_empty();                 // 1

	test_cleanup_minimal();
	return exit_status();
}
