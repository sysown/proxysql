#ifndef MYSQL_HOSTGROUP_ROUTING_H
#define MYSQL_HOSTGROUP_ROUTING_H

#include <string>

/**
 * @struct MySQL_Routing_Session_State
 * @brief Represents the session state relevant for hostgroup routing decisions.
 */
struct MySQL_Routing_Session_State {
	int current_hostgroup{-1};
	int default_hostgroup{-1};
	int locked_on_hostgroup{-1};
	int transaction_persistent_hostgroup{-1};
	int last_hg_affected_rows{-1};
	int warning_in_hg{-1};
	bool autocommit{true};
	int autocommit_on_hostgroup{-1};
	bool mirror{false};
};

/**
 * @struct MySQL_Routing_QPO_State
 * @brief Represents the Query Processor Output relevant for hostgroup routing decisions.
 */
struct MySQL_Routing_QPO_State {
	int destination_hostgroup{-1};
	bool lock_hostgroup{false}; // Derived from query parsing or QPO
	bool is_show_warnings{false}; // Derived from query parsing
	bool is_last_insert_id{false}; // Derived from query parsing
	bool is_version_query{false}; // Derived from query parsing
};

/**
 * @struct MySQL_Routing_Result
 * @brief Represents the output of the hostgroup routing decision.
 */
struct MySQL_Routing_Result {
	int new_current_hostgroup{-1};
	int new_locked_on_hostgroup{-1};
	bool lock_hostgroup{false};
	bool error{false};
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

#endif // MYSQL_HOSTGROUP_ROUTING_H
