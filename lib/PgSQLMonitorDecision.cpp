/**
 * @file PgSQLMonitorDecision.cpp
 * @brief Implementation of PgSQL monitor health decisions.
 *
 * @see PgSQLMonitorDecision.h
 * @see Phase 3.9 (GitHub issue #5497)
 */

#include "PgSQLMonitorDecision.h"

#include <climits>

bool pgsql_should_shun_on_ping_failure(
	unsigned int missed_heartbeats,
	unsigned int max_failures_threshold)
{
	if (max_failures_threshold == 0) {
		return false;  // shunning disabled
	}
	return (missed_heartbeats >= max_failures_threshold);
}

bool pgsql_should_offline_for_readonly(
	bool is_read_only,
	bool is_writer_hg)
{
	// A read-only server in a writer hostgroup should go OFFLINE_SOFT
	return (is_read_only && is_writer_hg);
}

uint64_t pgsql_mon_ms_to_us(int ms) {
	return ms <= 0 ? 0 : uint64_t(ms) * 1000ULL;
}

uint64_t pgsql_mon_next_check_at(uint64_t next_at, uint64_t interval_us, uint64_t intv_start) {
	if (next_at > intv_start) {
		return next_at;  // not due yet
	}
	return interval_us == 0 ? UINT64_MAX : intv_start + interval_us;
}

int pgsql_mon_min_history_ms(int history_ms, uint64_t interval_us, int max_failures) {
	if (interval_us >= uint64_t(3600000) * 1000) {
		return history_ms;
	}

	const uint64_t fails { max_failures < 0 ? 0 : uint64_t(max_failures) };
	uint64_t req_ms { interval_us * (fails + 1) / 1000 };
	if (req_ms > uint64_t(INT_MAX)) {
		req_ms = INT_MAX;
	}

	return int64_t(history_ms) < int64_t(req_ms) ? int(req_ms) : history_ms;
}
