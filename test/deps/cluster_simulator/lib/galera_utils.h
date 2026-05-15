#ifndef CLUSTER_SIM_GALERA_UTILS
#define CLUSTER_SIM_GALERA_UTILS

#include <string>
#include <vector>
#include <tuple>
#include <utility>

#include "json.hpp"

#include "common_utils.h"

using nlohmann::json;

using galera_hostgroup_config = std::tuple<int, int, int, int, int, int, int, int, std::string>;

std::pair<int,std::string> extract_galera_hostgroup_config(
	const json& galera_test_def,
	std::vector<galera_hostgroup_config>& out_hostgroups_configs
);

std::pair<int, std::string> prepare_mysql_galera_hostgroups(
	MYSQL* proxysql_admin,
	const std::vector<galera_hostgroup_config>& hostgroups_configs
);

std::pair<int, std::string> get_current_mysql_galera_hostgroups(
	MYSQL* proxysql_admin,
	std::vector<galera_hostgroup_config>& out_cur_galera_hostgroups
);

bool compare_mysql_galera_hostgroups(
	const std::vector<galera_hostgroup_config>& galera_hostgroups_1,
	const std::vector<galera_hostgroup_config>& galera_hostgroups_2
);

/**
 * @brief Convenience alias to represent a 'galera server state'.
 */
using galera_server_state =
	std::tuple<
		int,
		hostname,
		int,
		int,
		int,
		int,
		int,
		std::string,
		int,
		std::string,
		std::string
	>;

/**
 * @brief Receive a table which should be populated, and the values to be inserted in that table.
 *
 * @param proxysql_admin
 * @param table
 * @param servers
 *
 * @return
 */
std::pair<int,std::string> prepare_galera_cluster_state(
	MYSQL* proxysql_sqlite,
	const std::vector<galera_server_state>& servers,
	bool cleanup = false
);

enum class galera_state_id {
	init_state = 0,
	new_state = 1
};

std::pair<int,std::string> extract_galera_servers_state(
	const galera_state_id& state_id,
	const json& galera_test_def,
	std::vector<galera_server_state>& out_server_states
);

std::pair<int, std::string> get_current_galera_servers_state(
	MYSQL* proxysql_admin,
	std::vector<galera_server_state>& out_cur_galera_servers_state
);

std::vector<galera_server_state> sort_galera_server_state(
	const std::vector<galera_server_state>& galera_servers_state
);

bool compare_galera_servers_state(
	const std::vector<galera_server_state>& galera_servers_state_1,
	const std::vector<galera_server_state>& galera_servers_state_2
);

std::vector<std::pair<column_id, std::string>> galera_state_members_diff(
	const galera_server_state& st1,
	const galera_server_state& st2
);

galera_server_state galera_update_state(
	const galera_server_state& st1,
	const galera_server_state& st2
);

std::vector<galera_server_state> galera_update_cluster_state(
	const std::vector<galera_server_state>& servers_state_p,
	const std::vector<galera_server_state>& servers_state_n
);

cluster_state_changes galera_servers_state_diff(
	const std::vector<galera_server_state>& servers_state_p,
	const std::vector<galera_server_state>& servers_state_n
);

/**
 * @brief Set 'mysql-monitor_galera_healthcheck_interval' to 200 and
 *  'mysql-monitor_galera_healthcheck_timeout' to 100, then 'LOAD MYSQL
 *  VARIABLES TO RUNTIME'.
 *
 *   Note: these values are hardcoded; making them configurable is a future enhancement.
 *
 * @param proxysql_admin An already opened connection to ProxySQL admin.
 *
 * @return A 'std::pair' of '{ err_code, "err_msg" }'.
 */
std::pair<int, std::string> set_galera_monitor_check_times(MYSQL* proxysql_admin);
/**
 * @brief Read the current 'mysql-monitor_galera_healthcheck_interval' and
 *  'mysql-monitor_galera_healthcheck_timeout' from 'global_variables'.
 *
 * @param proxysql_admin An already opened connection to ProxySQL admin.
 * @param out_healthcheck_interval Output parameter receiving the current interval (ms).
 * @param out_healthcheck_timeout Output parameter receiving the current timeout (ms).
 *
 * @return A 'std::pair' of '{ err_code, "err_msg" }'.
 */
std::pair<int, std::string> get_galera_monitor_check_times(
	MYSQL* proxysql_admin,
	int& out_healthcheck_interval,
	int& out_healthcheck_timeout
);

#endif
