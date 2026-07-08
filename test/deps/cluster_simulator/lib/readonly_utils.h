#ifndef CLUSTER_SIM_READONLY_UTILS
#define CLUSTER_SIM_READONLY_UTILS

#include <string>
#include <vector>
#include <tuple>
#include <utility>

#include "json.hpp"

#include "common_utils.h"

using replication_hostgroup_config = std::tuple<int, int, std::string, std::string>;

std::pair<int,std::string> extract_replication_hostgroup_config(
	const json& replication_test_def,
	std::vector<replication_hostgroup_config>& out_hostgroups_configs
);

using readonly_server_state = std::tuple<hostname, port, bool>;

enum class readonly_state_id {
	init_state = 0,
	new_state = 1
};

std::pair<int,std::string> extract_readonly_servers_state(
	const readonly_state_id& state_id,
	const json& readonly_test_def,
	std::vector<readonly_server_state>& out_server_states
);

std::pair<int, std::string> prepare_mysql_replication_hostgroups(
	MYSQL* proxysql_admin,
	const std::vector<replication_hostgroup_config>& hostgroups_configs
);

std::pair<int, std::string> prepare_readonly_cluster_state(
	MYSQL* proxysql_sqlite,
	const std::vector<readonly_server_state>& servers,
	bool cleanup = false
);

/**
 * @brief Set times for 'mysql-monitor_read_only_interval' and
 *   'mysql-monitor_read_only_timeout' for the simulation to be
 *   performed.
 *
 *   Note: these values are hardcoded; making them configurable is a future enhancement.
 *
 * @param proxysql_admin An already opened connection to ProxySQL admin.
 * @return A `std::pair` of kind `{ err_code, "err_msg" }`.
 */
std::pair<int, std::string> set_readonly_monitor_check_times(MYSQL* proxysql_admin);

std::pair<int, std::string> get_readonly_monitor_check_times(
	MYSQL* proxysql_admin,
	int& out_healthcheck_interval,
	int& out_healthcheck_timeout
);

cluster_state_changes readonly_servers_state_diff(
	const std::vector<readonly_server_state>& servers_state_p,
	const std::vector<readonly_server_state>& servers_state_n
);

std::vector<readonly_server_state> readonly_update_cluster_state(
	const std::vector<readonly_server_state>& servers_state_p,
	const std::vector<readonly_server_state>& servers_state_n
);

#endif

