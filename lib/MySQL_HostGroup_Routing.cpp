#include "MySQL_HostGroup_Routing.h"

MySQL_Routing_Result resolve_hostgroup_routing(
	const MySQL_Routing_Session_State& sess_state,
	const MySQL_Routing_QPO_State& qpo_state,
	int set_query_lock_on_hostgroup
) {
	MySQL_Routing_Result result;
	result.new_current_hostgroup = sess_state.current_hostgroup;
	result.new_locked_on_hostgroup = sess_state.locked_on_hostgroup;
	result.lock_hostgroup = false;
	result.error = false;
	result.error_msg = "";

	// 1. Mirroring (highest priority)
	if (sess_state.mirror) {
		result.new_current_hostgroup = qpo_state.destination_hostgroup;
		return result;
	}

	// 2. SHOW WARNINGS / SHOW COUNT(*) WARNINGS
	if (qpo_state.is_show_warnings) {
		if (sess_state.warning_in_hg > -1) {
			result.new_current_hostgroup = sess_state.warning_in_hg;
		}
		return result;
	}

	// 3. LAST_INSERT_ID / @@IDENTITY
	if (qpo_state.is_last_insert_id) {
		if (sess_state.last_hg_affected_rows >= 0) {
			result.new_current_hostgroup = sess_state.last_hg_affected_rows;
			return result;
		}
	}

	// 4. Default routing from QPO
	if (qpo_state.destination_hostgroup >= 0) {
		if (sess_state.transaction_persistent_hostgroup == -1) {
			result.new_current_hostgroup = qpo_state.destination_hostgroup;
		}
	} else {
		// qpo_state.destination_hostgroup < 0 means no override from QPO
		if (sess_state.transaction_persistent_hostgroup == -1) {
			result.new_current_hostgroup = sess_state.default_hostgroup;
		}
	}

	// 5. Hostgroup Locking Decisions (mysql-set_query_lock_on_hostgroup)
	if (set_query_lock_on_hostgroup == 1) {
		// Algorithm introduced in ProxySQL 2.0.6
		if (result.new_locked_on_hostgroup < 0) {
			if (qpo_state.lock_hostgroup) {
				result.lock_hostgroup = true;
				result.new_locked_on_hostgroup = result.new_current_hostgroup;
			}
		}

		if (result.new_locked_on_hostgroup >= 0) {
			if (result.new_current_hostgroup != result.new_locked_on_hostgroup) {
				result.error = true;
				result.error_msg = "ProxySQL Error: connection is locked to hostgroup " + 
								   std::to_string(result.new_locked_on_hostgroup) + 
								   " but trying to reach hostgroup " + 
								   std::to_string(result.new_current_hostgroup);
				return result;
			}
		}
	}

	return result;
}
