#include "PgSQL_HostGroup_Routing.h"

PgSQL_Routing_Result resolve_pgsql_hostgroup_routing(
    const PgSQL_Routing_Session_State& sess_state,
    const PgSQL_Routing_QPO_State& qpo_state,
    int set_query_lock_on_hostgroup
) {
    PgSQL_Routing_Result result;
    result.new_current_hostgroup = sess_state.current_hostgroup;
    result.new_locked_on_hostgroup = sess_state.locked_on_hostgroup;
    result.lock_hostgroup = false;
    result.error = false;
    result.error_msg = "";

    // Default routing from QPO
    if (qpo_state.destination_hostgroup >= 0) {
        if (sess_state.transaction_persistent_hostgroup == -1) {
            result.new_current_hostgroup = qpo_state.destination_hostgroup;
        }
    }

    // Hostgroup Locking Decisions (pgsql-set_query_lock_on_hostgroup)
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
    } else {
        // Legacy behavior before 2.0.6
        if (sess_state.transaction_persistent_hostgroup == -1) {
            if (qpo_state.destination_hostgroup < 0) {
                result.new_current_hostgroup = sess_state.default_hostgroup;
            }
        }
    }

    return result;
}
