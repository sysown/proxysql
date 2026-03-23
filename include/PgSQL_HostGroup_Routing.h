#ifndef __PGSQL_HOSTGROUP_ROUTING_H
#define __PGSQL_HOSTGROUP_ROUTING_H

#include <string>

/**
 * @struct PgSQL_Routing_Session_State
 * @brief Represents the session state relevant for hostgroup routing decisions in PostgreSQL.
 */
struct PgSQL_Routing_Session_State {
    int current_hostgroup;
    int default_hostgroup;
    int locked_on_hostgroup;
    int transaction_persistent_hostgroup;
};

/**
 * @struct PgSQL_Routing_QPO_State
 * @brief Represents the Query Processor Output relevant for hostgroup routing decisions in PostgreSQL.
 */
struct PgSQL_Routing_QPO_State {
    int destination_hostgroup;
    bool lock_hostgroup; // Derived from query parsing
};

/**
 * @struct PgSQL_Routing_Result
 * @brief Represents the output of the hostgroup routing decision for PostgreSQL.
 */
struct PgSQL_Routing_Result {
    int new_current_hostgroup;
    int new_locked_on_hostgroup;
    bool lock_hostgroup;
    bool error;
    std::string error_msg;
};

/**
 * @brief Resolves the target hostgroup and locking decisions based on session and QPO state.
 * 
 * This is a pure function designed to be easily testable.
 * 
 * @param sess_state Current session state.
 * @param qpo_state Query Processor Output state.
 * @param set_query_lock_on_hostgroup Global configuration (pgsql-set_query_lock_on_hostgroup).
 * @return PgSQL_Routing_Result The routing decision.
 */
PgSQL_Routing_Result resolve_pgsql_hostgroup_routing(
    const PgSQL_Routing_Session_State& sess_state,
    const PgSQL_Routing_QPO_State& qpo_state,
    int set_query_lock_on_hostgroup
);

#endif // __PGSQL_HOSTGROUP_ROUTING_H
