/**
 * @file HostgroupRouting.cpp
 * @brief Implementation of pure hostgroup routing decision logic.
 *
 * Mirrors the routing block in get_pkts_from_client() (MySQL_Session.cpp
 * ~lines 5340-5377 and PgSQL_Session.cpp ~lines 2154-2189).
 *
 * @see HostgroupRouting.h
 * @see Phase 3.5 (GitHub issue #5493)
 */

#include "HostgroupRouting.h"

HostgroupRoutingDecision resolve_hostgroup_routing(
	int default_hostgroup,
	int qpo_destination_hostgroup,
	int transaction_persistent_hostgroup,
	int locked_on_hostgroup,
	bool lock_hostgroup_flag,
	bool lock_enabled)
{
	HostgroupRoutingDecision d;
	d.error = false;
	d.new_locked_on_hostgroup = locked_on_hostgroup;

	// Start with default hostgroup
	int current_hostgroup = default_hostgroup;

	// If QP provides a valid destination and no transaction lock, use it
	if (qpo_destination_hostgroup >= 0
		&& transaction_persistent_hostgroup == -1) {
		current_hostgroup = qpo_destination_hostgroup;
	}

	// Transaction affinity overrides everything
	if (transaction_persistent_hostgroup >= 0) {
		current_hostgroup = transaction_persistent_hostgroup;
	}

	// Hostgroup locking logic (algorithm introduced in 2.0.6)
	if (lock_enabled) {
		if (locked_on_hostgroup < 0) {
			// Not yet locked
			if (lock_hostgroup_flag) {
				// Acquire lock on the current (already resolved) hostgroup
				d.new_locked_on_hostgroup = current_hostgroup;
			}
		}
		if (d.new_locked_on_hostgroup >= 0) {
			// Already locked (or just acquired) — enforce
			if (current_hostgroup != d.new_locked_on_hostgroup) {
				d.error = true;
			}
			current_hostgroup = d.new_locked_on_hostgroup;
		}
	}

	d.target_hostgroup = current_hostgroup;
	return d;
}
