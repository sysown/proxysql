#ifndef CLUSTER_SIM_GROUPREP_UTILS
#define CLUSTER_SIM_GROUPREP_UTILS

#include <string>
#include <vector>
#include <tuple>
#include <utility>

#include "json.hpp"

#include "common_utils.h"

using group_replication_hostgroup_config =
	std::tuple<int, int, int, int, bool, int, int, int, std::string>;

std::pair<int,std::string> extract_group_replication_hostgroup_config(
	const json& replication_test_def,
	std::vector<group_replication_hostgroup_config>& out_hostgroups_configs
);

using grouprep_server_state = std::tuple<hostname, port, bool, bool, int, std::string>;
enum GROUPREP_SERVER_STATE {
	HOSTNAME,
	PORT,
	VIABLE_CANDIDATE,
	READ_ONLY,
	TRANSACTIONS_BEHIND,
	MEMBERS
};

enum class grouprep_state_id {
	init_state = 0,
	new_state = 1
};

std::pair<int,std::string> extract_grouprep_servers_state(
	const grouprep_state_id& state_id,
	const json& grouprep_test_def,
	std::vector<grouprep_server_state>& out_server_states
);

std::pair<int, std::string> prepare_mysql_group_replication_hostgroups(
	MYSQL* proxysql_admin,
	const std::vector<group_replication_hostgroup_config>& hostgroups_configs
);

std::pair<int, std::string> prepare_grouprep_cluster_state(
	MYSQL* proxysql_sqlite,
	const std::vector<grouprep_server_state>& servers,
	uint32_t cleanup = 0
);

/**
 * @brief Set times for 'mysql-monitor_groupreplication_healthcheck_interval'
 *   and 'mysql-monitor_groupreplication_healthcheck_timeout' for the
 *   simulation to be performed.
 *
 *   Note: these values are hardcoded; making them configurable is a future enhancement.
 *
 * @param proxysql_admin An already opened connection to ProxySQL admin.
 * @return A `std::pair` of kind `{ err_code, "err_msg" }`.
 */
std::pair<int, std::string> set_grouprep_monitor_check_times(MYSQL* proxysql_admin);

std::pair<int, std::string> get_grouprep_monitor_check_times(
	MYSQL* proxysql_admin,
	int& out_healthcheck_interval,
	int& out_healthcheck_timeout
);

cluster_state_changes grouprep_servers_state_diff(
	const std::vector<grouprep_server_state>& servers_state_p,
	const std::vector<grouprep_server_state>& servers_state_n
);

std::vector<grouprep_server_state> grouprep_update_cluster_state(
	const std::vector<grouprep_server_state>& servers_state_p,
	const std::vector<grouprep_server_state>& servers_state_n
);

#endif

