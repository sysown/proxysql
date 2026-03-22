/**
 * @file pgsql_monitor_unit-t.cpp
 * @brief Unit tests for PgSQL monitor health decisions.
 *
 * @see Phase 3.9 (GitHub issue #5497)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQLMonitorDecision.h"

static void test_ping_shunning() {
	ok(pgsql_should_shun_on_ping_failure(3, 3) == true,
		"shun: failures=3 meets threshold=3");
	ok(pgsql_should_shun_on_ping_failure(5, 3) == true,
		"shun: failures=5 exceeds threshold=3");
	ok(pgsql_should_shun_on_ping_failure(2, 3) == false,
		"no shun: failures=2 below threshold=3");
	ok(pgsql_should_shun_on_ping_failure(0, 3) == false,
		"no shun: zero failures");
	ok(pgsql_should_shun_on_ping_failure(1, 1) == true,
		"shun: threshold=1, single failure");
	ok(pgsql_should_shun_on_ping_failure(10, 0) == false,
		"no shun: threshold=0 (disabled)");
}

static void test_readonly_offline() {
	ok(pgsql_should_offline_for_readonly(true, true) == true,
		"offline: read_only + writer HG");
	ok(pgsql_should_offline_for_readonly(true, false) == false,
		"not offline: read_only + reader HG");
	ok(pgsql_should_offline_for_readonly(false, true) == false,
		"not offline: not read_only + writer HG");
	ok(pgsql_should_offline_for_readonly(false, false) == false,
		"not offline: not read_only + reader HG");
}

int main() {
	plan(11);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_ping_shunning();       // 6
	test_readonly_offline();    // 4
	// Total: 1+6+4 = 11

	test_cleanup_minimal();
	return exit_status();
}
