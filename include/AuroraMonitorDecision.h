/**
 * @file AuroraMonitorDecision.h
 * @brief Pure decision functions for Aurora monitor blue/green detection.
 *
 * Extracted from MySQL_Monitor_Connection_Pool for unit testability.
 * These functions have no global state dependencies.
 */

#ifndef __CLASS_AURORA_MONITOR_DECISION_H
#define __CLASS_AURORA_MONITOR_DECISION_H

/**
 * @brief Determine if a returned connection should be rejected based on
 *        switchover timing.
 *
 * A connection is considered stale (pre-switchover) if it was checked out
 * before the switchover was detected for its hostname.
 *
 * @param checkout_time    Monotonic timestamp when the connection was checked out or created.
 *                         0 means unknown (non-Aurora monitor thread); always accepted.
 * @param switchover_time  Timestamp when the switchover was detected for the hostname.
 *                         0 means no switchover recorded.
 * @return true if the connection should be rejected (stale), false if it can be re-pooled.
 */
inline bool should_reject_pooled_connection(
	unsigned long long checkout_time,
	unsigned long long switchover_time
) {
	if (switchover_time == 0) return false;
	if (checkout_time == 0) return false;
	return checkout_time < switchover_time;
}

#endif // __CLASS_AURORA_MONITOR_DECISION_H
