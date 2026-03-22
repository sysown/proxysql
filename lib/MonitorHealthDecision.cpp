/**
 * @file MonitorHealthDecision.cpp
 * @brief Implementation of pure monitor health decision functions.
 *
 * These functions extract the decision logic from MySrvC::connect_error(),
 * MyHGC's unshun recovery loop, and MySQL_HostGroups_Manager's replication
 * lag check. They are intentionally free of global state and I/O.
 *
 * @see MonitorHealthDecision.h
 * @see Phase 3.3 (GitHub issue #5491)
 */

#include "MonitorHealthDecision.h"
#include <cstdint>

bool should_shun_on_connect_errors(
	unsigned int errors_this_second,
	int shun_on_failures,
	int connect_retries)
{
	// Mirror MySrvC::connect_error() threshold logic:
	// max_failures = min(shun_on_failures, connect_retries + 1)
	int connect_retries_plus_1 = connect_retries + 1;
	int max_failures = (shun_on_failures > connect_retries_plus_1)
		? connect_retries_plus_1
		: shun_on_failures;

	return (errors_this_second >= (unsigned int)max_failures);
}

bool can_unshun_server(
	time_t time_last_error,
	time_t current_time,
	int shun_recovery_time_sec,
	int connect_timeout_max_ms,
	bool kill_all_conns,
	unsigned int connections_used,
	unsigned int connections_free)
{
	if (shun_recovery_time_sec == 0) {
		return false;  // recovery disabled
	}

	// Mirror MyHGC recovery: compute max_wait_sec with timeout cap
	int max_wait_sec;
	if ((int64_t)shun_recovery_time_sec * 1000 >= connect_timeout_max_ms) {
		max_wait_sec = connect_timeout_max_ms / 1000 - 1;
	} else {
		max_wait_sec = shun_recovery_time_sec;
	}
	if (max_wait_sec < 1) {
		max_wait_sec = 1;
	}

	// Time check
	if (current_time <= time_last_error) {
		return false;
	}
	if ((current_time - time_last_error) <= max_wait_sec) {
		return false;
	}

	// Connection drain check for kill-all mode
	if (kill_all_conns) {
		if (connections_used != 0 || connections_free != 0) {
			return false;  // connections still draining
		}
	}

	return true;
}

bool should_shun_on_replication_lag(
	int current_lag,
	unsigned int max_replication_lag,
	unsigned int consecutive_count,
	int count_threshold)
{
	// Mirror MySQL_HostGroups_Manager replication lag logic
	if (current_lag < 0) {
		return false;  // lag unknown, don't shun
	}
	if (max_replication_lag == 0) {
		return false;  // lag check disabled
	}
	if (current_lag <= (int)max_replication_lag) {
		return false;  // within threshold
	}

	// Lag exceeds threshold — check consecutive count
	// The caller is expected to have incremented consecutive_count
	// before calling this function
	return (consecutive_count >= (unsigned int)count_threshold);
}

bool can_recover_from_replication_lag(
	int current_lag,
	unsigned int max_replication_lag)
{
	// Mirror MySQL_HostGroups_Manager unshun for replication lag:
	// recover when lag drops to <= max_replication_lag
	if (current_lag < 0) {
		return false;  // unknown lag, don't recover
	}
	return (current_lag <= (int)max_replication_lag);
}
