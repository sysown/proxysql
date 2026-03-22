/**
 * @file MonitorHealthDecision.h
 * @brief Pure decision functions for monitor health state transitions.
 *
 * Extracted from MySQL_Monitor, MySrvC, and MyHGC for unit testability.
 * These functions have no global state dependencies — all inputs are
 * passed as parameters.
 *
 * @see Phase 3.3 (GitHub issue #5491)
 */

#ifndef MONITOR_HEALTH_DECISION_H
#define MONITOR_HEALTH_DECISION_H

#include <ctime>

/**
 * @brief Determine if a server should be shunned based on connect errors.
 *
 * Mirrors the logic in MySrvC::connect_error() — a server is shunned
 * when errors in the current second reach min(shun_on_failures,
 * connect_retries_on_failure + 1).
 *
 * @param errors_this_second   Number of connect errors in the current second.
 * @param shun_on_failures     Config: mysql-shun_on_failures.
 * @param connect_retries      Config: mysql-connect_retries_on_failure.
 * @return true if the error count meets or exceeds the shunning threshold.
 */
bool should_shun_on_connect_errors(
	unsigned int errors_this_second,
	int shun_on_failures,
	int connect_retries
);

/**
 * @brief Determine if a shunned server can be brought back online.
 *
 * Mirrors the recovery logic in MyHGC's server scan loop. A server
 * can be unshunned when:
 *   1. Enough time has elapsed since the last detected error.
 *   2. If shunned_and_kill_all_connections is true, all connections
 *      (both used and free) must be fully drained first.
 *
 * @param time_last_error          Timestamp of the last detected error.
 * @param current_time             Current time.
 * @param shun_recovery_time_sec   Config: mysql-shun_recovery_time_sec.
 * @param connect_timeout_max_ms   Config: mysql-connect_timeout_server_max (milliseconds).
 * @param kill_all_conns           Whether shunned_and_kill_all_connections is set.
 * @param connections_used         Number of in-use connections.
 * @param connections_free         Number of idle connections.
 * @return true if the server can be unshunned.
 */
bool can_unshun_server(
	time_t time_last_error,
	time_t current_time,
	int shun_recovery_time_sec,
	int connect_timeout_max_ms,
	bool kill_all_conns,
	unsigned int connections_used,
	unsigned int connections_free
);

/**
 * @brief Determine if a server should be shunned for replication lag.
 *
 * Mirrors the replication lag check in MySQL_HostGroups_Manager.
 * A server is shunned when its replication lag exceeds max_replication_lag
 * for N consecutive checks (where N = monitor_replication_lag_count).
 *
 * @param current_lag          Measured replication lag in seconds (-1 = unknown).
 * @param max_replication_lag  Configured max lag threshold (0 = disabled).
 * @param consecutive_count    Number of consecutive checks exceeding threshold.
 * @param count_threshold      Config: mysql-monitor_replication_lag_count.
 * @return true if the server should be shunned for replication lag.
 */
bool should_shun_on_replication_lag(
	int current_lag,
	unsigned int max_replication_lag,
	unsigned int consecutive_count,
	int count_threshold
);

/**
 * @brief Determine if a server shunned for replication lag can be recovered.
 *
 * @param current_lag          Measured replication lag in seconds.
 * @param max_replication_lag  Configured max lag threshold.
 * @return true if the server's lag is now within acceptable bounds.
 *
 * @note Production code also has a special override path for
 *       current_lag == -2 with an override flag (see issue #959).
 *       That case is not covered by this simplified extraction.
 */
bool can_recover_from_replication_lag(
	int current_lag,
	unsigned int max_replication_lag
);

#endif // MONITOR_HEALTH_DECISION_H
