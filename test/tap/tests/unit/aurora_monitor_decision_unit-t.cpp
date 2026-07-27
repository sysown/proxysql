/**
 * @file aurora_monitor_decision_unit-t.cpp
 * @brief Unit tests for Aurora monitor blue/green switchover decision logic.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "AuroraMonitorDecision.h"

/** @brief Test that no rejection occurs when no switchover is recorded. */
static void test_no_switchover_recorded() {
	ok(should_reject_pooled_connection(1000, 0) == false,
		"no rejection when no switchover recorded (switchover_time=0)");
	ok(should_reject_pooled_connection(0, 0) == false,
		"no rejection when both timestamps are zero");
}

/** @brief Test that newly created connections (checkout_time=0) are always accepted. */
static void test_newly_created_connection() {
	ok(should_reject_pooled_connection(0, 200) == false,
		"accept: newly created connection (checkout_time=0) even with active switchover");
	ok(should_reject_pooled_connection(0, 1000000) == false,
		"accept: newly created connection always passes regardless of switchover time");
}

/** @brief Test that connections checked out before switchover are rejected. */
static void test_connection_before_switchover() {
	ok(should_reject_pooled_connection(100, 200) == true,
		"reject: connection pooled at 100, switchover at 200");
	ok(should_reject_pooled_connection(199, 200) == true,
		"reject: connection pooled at 199, switchover at 200");
	ok(should_reject_pooled_connection(1, 1000000) == true,
		"reject: connection pooled long before switchover");
}

/** @brief Test that connections checked out after switchover are accepted. */
static void test_connection_after_switchover() {
	ok(should_reject_pooled_connection(200, 200) == false,
		"accept: connection pooled at same time as switchover");
	ok(should_reject_pooled_connection(201, 200) == false,
		"accept: connection pooled at 201, switchover at 200");
	ok(should_reject_pooled_connection(1000000, 200) == false,
		"accept: connection pooled long after switchover");
}

/** @brief Test rejection logic across multiple successive switchovers. */
static void test_multiple_switchovers() {
	ok(should_reject_pooled_connection(150, 100) == false,
		"accept: connection pooled after first switchover");
	ok(should_reject_pooled_connection(150, 200) == true,
		"reject: same connection is stale relative to second switchover");
}

/** @brief Entry point for aurora_monitor_decision unit tests. */
int main() {
	plan(13);

	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_no_switchover_recorded();      // 2
	test_newly_created_connection();    // 2
	test_connection_before_switchover(); // 3
	test_connection_after_switchover();  // 3
	test_multiple_switchovers();         // 2

	test_cleanup_minimal();
	return exit_status();
}
