/**
 * @file pgsql_monitor_unit-t.cpp
 * @brief Unit tests for PgSQL monitor health decisions.
 *
 * @see Phase 3.9 (GitHub issue #5497)
 * @see GitHub issue #6429 (64-bit monitor intervals)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQLMonitorDecision.h"

#include <climits>
#include <cstdint>

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

/**
 * @brief ms -> us conversion must not wrap for any admin-accepted interval
 *        (100 .. 604,800,000 ms). Values from 2,147,484 ms used to overflow
 *        an int32 (#6429).
 */
static void test_ms_to_us() {
	ok(pgsql_mon_ms_to_us(2147483) == 2147483000ULL,
		"ms_to_us: 2147483 ms (largest int32-safe) -> 2147483000 us");
	ok(pgsql_mon_ms_to_us(2147484) == 2147484000ULL,
		"ms_to_us: 2147484 ms (first int32 overflow) -> 2147484000 us");
	ok(pgsql_mon_ms_to_us(3600000) == 3600000000ULL,
		"ms_to_us: 3600000 ms (1h, was negative) -> 3600000000 us");
	ok(pgsql_mon_ms_to_us(4294968) == 4294968000ULL,
		"ms_to_us: 4294968 ms (was +704) -> 4294968000 us");
	ok(pgsql_mon_ms_to_us(536870912) == 536870912000ULL,
		"ms_to_us: 536870912 ms (was 0) -> 536870912000 us");
	ok(pgsql_mon_ms_to_us(604800000) == 604800000000ULL,
		"ms_to_us: 604800000 ms (7-day max, was negative) -> 604800000000 us");
	ok(pgsql_mon_ms_to_us(100) == 100000ULL,
		"ms_to_us: 100 ms (admin minimum) -> 100000 us");
	ok(pgsql_mon_ms_to_us(INT_MAX) == uint64_t(INT_MAX) * 1000ULL,
		"ms_to_us: INT_MAX ms does not wrap");
	ok(pgsql_mon_ms_to_us(0) == 0 && pgsql_mon_ms_to_us(-5) == 0,
		"ms_to_us: non-positive values -> 0");
}

/**
 * @brief Scheduling of the next check of one type. A due check must always
 *        move strictly into the future (or to 'disabled'), otherwise the
 *        scheduler busy-loops (#6429).
 */
static void test_next_check_at() {
	const uint64_t now = 1000000000ULL;

	ok(pgsql_mon_next_check_at(0, 0, now) == UINT64_MAX,
		"next_check_at: interval 0 on a due check -> UINT64_MAX (disabled)");
	ok(pgsql_mon_next_check_at(now, 0, now) == UINT64_MAX,
		"next_check_at: interval 0, next_at == now -> UINT64_MAX");
	ok(pgsql_mon_next_check_at(0, 604800000000ULL, now) == now + 604800000000ULL,
		"next_check_at: 7-day interval -> now + interval");
	ok(pgsql_mon_next_check_at(now - 5, pgsql_mon_ms_to_us(3600000), now)
			== now + 3600000000ULL,
		"next_check_at: 1h interval on an overdue check -> now + 1h");
	ok(pgsql_mon_next_check_at(now, 2000000ULL, now) == now + 2000000ULL,
		"next_check_at: check due exactly now is rescheduled");
	ok(pgsql_mon_next_check_at(now + 10, 2000000ULL, now) == now + 10,
		"next_check_at: check not yet due keeps its schedule");
	ok(pgsql_mon_next_check_at(now + 10, 0, now) == now + 10,
		"next_check_at: check not yet due keeps its schedule with interval 0");
	ok(pgsql_mon_next_check_at(0, pgsql_mon_ms_to_us(100), now) > now,
		"next_check_at: smallest admin interval still makes forward progress");
}

/**
 * @brief 'pgsql-monitor_history' floor computed in maint_monitor_table();
 *        the old int32 'interval * (max_failures + 1)' overflowed (#6429).
 */
static void test_min_history() {
	// default ping interval (8 s), 3 failures -> 32 s; history 600 s untouched
	ok(pgsql_mon_min_history_ms(600000, 8000000ULL, 3) == 600000,
		"min_history: history already large enough is kept");
	// 8 s * (1 + 1) = 16 s > 10 s history -> raised to 16000 ms
	ok(pgsql_mon_min_history_ms(10000, 8000000ULL, 1) == 16000,
		"min_history: history raised to interval * (max_failures + 1)");
	// 8 s * 269 = 2152 s; int32 math overflowed at max_failures >= 268
	ok(pgsql_mon_min_history_ms(600000, 8000000ULL, 268) == 2152000,
		"min_history: default interval with max_failures=268 does not overflow");
	// 3,000,000 ms * 1,000,001 exceeds INT_MAX ms -> clamped
	ok(pgsql_mon_min_history_ms(600000, 3000000000ULL, 1000000) == INT_MAX,
		"min_history: huge requirement clamped to INT_MAX");
	// intervals >= 1h never raise history (pre-existing behaviour)
	ok(pgsql_mon_min_history_ms(600000, 3600000000ULL, 3) == 600000,
		"min_history: interval >= 1h leaves history unchanged");
	ok(pgsql_mon_min_history_ms(600000, pgsql_mon_ms_to_us(604800000), 3) == 600000,
		"min_history: 7-day interval leaves history unchanged");
}

int main() {
	plan(34);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_ping_shunning();       // 6
	test_readonly_offline();    // 4
	test_ms_to_us();            // 9
	test_next_check_at();       // 8
	test_min_history();         // 6
	// Total: 1+6+4+9+8+6 = 34

	test_cleanup_minimal();
	return exit_status();
}
