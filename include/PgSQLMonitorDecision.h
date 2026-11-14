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

#include <cstdint>

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

/**
 * @brief Convert a 'pgsql-monitor_*' millisecond setting to microseconds.
 *
 * The conversion is done in 64 bits: admin accepts intervals of up to
 * 604,800,000 ms (7 days), and anything from 2,147,484 ms upwards would
 * overflow a 32-bit microsecond value (#6429).
 *
 * @param ms Setting value in milliseconds.
 * @return The value in microseconds, or 0 when 'ms' is not positive.
 */
uint64_t pgsql_mon_ms_to_us(int ms);

/**
 * @brief Compute when a monitor check type has to run next.
 *
 * A check that is not due yet ('next_at > intv_start') keeps its schedule.
 * A due check is rescheduled one interval after 'intv_start', or never
 * ('UINT64_MAX') when its interval is 0 (disabled).
 *
 * @param next_at     Current scheduled time of the check (µs).
 * @param interval_us Configured interval of the check (µs).
 * @param intv_start  Start of the current scheduling interval (µs).
 * @return The updated scheduled time of the check (µs).
 */
uint64_t pgsql_mon_next_check_at(uint64_t next_at, uint64_t interval_us, uint64_t intv_start);

/**
 * @brief Compute the 'pgsql-monitor_history' needed to keep enough ping
 *        history for 'ping_max_failures' consecutive failures.
 *
 * History is only raised (never lowered), only for intervals below 1 hour,
 * and the result is clamped to 'INT_MAX' ms.
 *
 * @param history_ms   Current 'pgsql-monitor_history' (ms).
 * @param interval_us  Ping interval (µs).
 * @param max_failures Config: pgsql-monitor_ping_max_failures.
 * @return The history value (ms) to use.
 */
int pgsql_mon_min_history_ms(int history_ms, uint64_t interval_us, int max_failures);

#endif // PGSQL_MONITOR_DECISION_H
