/**
 * @file PgSQLMonitorDecision.h
 * @brief Pure decision functions for PgSQL monitor health state.
 *
 * PgSQL monitor is simpler than MySQL — it uses ping failure
 * threshold directly with shun_and_killall() (always aggressive).
 * Unshunning follows the same time-based recovery as MySQL
 * (already covered by MonitorHealthDecision.h can_unshun_server).
 *
 * @see Phase 3.9 (GitHub issue #5497)
 */

#ifndef PGSQL_MONITOR_DECISION_H
#define PGSQL_MONITOR_DECISION_H

/**
 * @brief Determine if a PgSQL server should be shunned based on ping failures.
 *
 * PgSQL monitor shuns servers when they miss N consecutive heartbeats.
 * Unlike MySQL, PgSQL always uses aggressive shunning (kill all connections).
 *
 * @param missed_heartbeats      Number of consecutive missed pings.
 * @param max_failures_threshold Config: pgsql-monitor_ping_max_failures.
 * @return true if the server should be shunned.
 */
bool pgsql_should_shun_on_ping_failure(
	unsigned int missed_heartbeats,
	unsigned int max_failures_threshold
);

/**
 * @brief Determine if a PgSQL server's read-only status indicates it should
 *        be taken offline for a writer hostgroup.
 *
 * @param is_read_only  Whether the server reports read_only=true.
 * @param is_writer_hg  Whether this is a writer hostgroup.
 * @return true if the server should be set to OFFLINE_SOFT.
 */
bool pgsql_should_offline_for_readonly(
	bool is_read_only,
	bool is_writer_hg
);

#endif // PGSQL_MONITOR_DECISION_H
