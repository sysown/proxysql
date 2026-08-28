/**
 * @file HostgroupRouting.h
 * @brief Pure hostgroup routing decision logic for unit testability.
 *
 * Extracted from MySQL_Session::get_pkts_from_client() and
 * PgSQL_Session::get_pkts_from_client(). The logic is identical
 * for both protocols.
 *
 * @see Phase 3.5 (GitHub issue #5493)
 */

#ifndef HOSTGROUP_ROUTING_H
#define HOSTGROUP_ROUTING_H

/**
 * @brief Result of a hostgroup routing decision.
 */
struct HostgroupRoutingDecision {
	int target_hostgroup;         ///< Resolved hostgroup to route to.
	int new_locked_on_hostgroup;  ///< Updated lock state (-1 = unlocked).
	bool error;                   ///< True if an illegal HG switch was attempted.
};

/**
 * @brief Resolve the target hostgroup given session state and QP output.
 *
 * Decision logic (mirrors get_pkts_from_client()):
 * 1. Start with default_hostgroup as the target
 * 2. If QP provides a destination (>= 0) and no transaction lock,
 *    use the QP destination
 * 3. If transaction_persistent_hostgroup >= 0, override with transaction HG
 * 4. If locking is enabled and lock_hostgroup flag is set, acquire lock
 * 5. If already locked, verify target matches lock (error if mismatch)
 *
 * @param default_hostgroup           Session's default hostgroup.
 * @param qpo_destination_hostgroup   Query Processor output destination (-1 = no override).
 * @param transaction_persistent_hostgroup Current transaction HG (-1 = none).
 * @param locked_on_hostgroup         Current lock state (-1 = unlocked).
 * @param lock_hostgroup_flag         Whether the QP wants to acquire a lock.
 * @param lock_enabled                Whether set_query_lock_on_hostgroup is enabled.
 * @return HostgroupRoutingDecision with resolved target and updated lock.
 */
HostgroupRoutingDecision resolve_hostgroup_routing(
	int default_hostgroup,
	int qpo_destination_hostgroup,
	int transaction_persistent_hostgroup,
	int locked_on_hostgroup,
	bool lock_hostgroup_flag,
	bool lock_enabled
);

#endif // HOSTGROUP_ROUTING_H
