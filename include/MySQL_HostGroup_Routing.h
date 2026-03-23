#ifndef __MYSQL_HOSTGROUP_ROUTING_H
#define __MYSQL_HOSTGROUP_ROUTING_H

#include <string>

/**
 * @struct MySQL_Routing_Session_State
 * @brief Represents the session state relevant for hostgroup routing decisions.
 */
struct MySQL_Routing_Session_State {
    int current_hostgroup;
    int default_hostgroup;
    int locked_on_hostgroup;
    int transaction_persistent_hostgroup;
    int last_HG_affected_rows;
    int warning_in_hg;
    bool autocommit;
    int autocommit_on_hostgroup;
    bool mirror;
};

/**
 * @struct MySQL_Routing_QPO_State
 * @brief Represents the Query Processor Output relevant for hostgroup routing decisions.
 */
struct MySQL_Routing_QPO_State {
    int destination_hostgroup;
    bool is_set_statement; // Derived from query parsing
    bool is_show_warnings; // Derived from query parsing
    bool is_last_insert_id; // Derived from query parsing
    bool is_version_query; // Derived from query parsing
};

/**
 * @struct MySQL_Routing_Result
 * @brief Represents the output of the hostgroup routing decision.
 */
struct MySQL_Routing_Result {
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
 * @param set_query_lock_on_hostgroup Global configuration (mysql-set_query_lock_on_hostgroup).
 * @return MySQL_Routing_Result The routing decision.
 */
MySQL_Routing_Result resolve_hostgroup_routing(
    const MySQL_Routing_Session_State& sess_state,
    const MySQL_Routing_QPO_State& qpo_state,
    int set_query_lock_on_hostgroup
);

#endif // __MYSQL_HOSTGROUP_ROUTING_H
