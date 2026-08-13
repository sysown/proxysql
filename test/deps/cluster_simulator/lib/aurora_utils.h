#ifndef CLUSTER_SIM_AURORA_UTILS
#define CLUSTER_SIM_AURORA_UTILS

#include <string>
#include <vector>
#include <tuple>
#include <utility>

#include "json.hpp"

#include "common_utils.h"

/**
 * @brief Aurora hostgroup config.
 * @details Following config fields are not defined due to limitations:
 *  - *lag*: Simulator can't verify behaviors for config that involves a series of different monitoring
 *    measures. This would involve being able to provide a series of values to be read by monitor during the
 *    test scenario.
 */
struct aurora_hostgroup_config_t {
	int32_t writer_hostgroup;
	int32_t reader_hostgroup;
	int32_t active;
	std::string domain_name;
	int32_t max_lag_ms;
	int32_t check_interval_ms;
	int32_t writer_is_also_reader;
	int32_t new_reader_weight;
	int32_t add_lag_ms;
	int32_t min_lag_ms;
	int32_t autopurge_missing_checks;
	std::string comment;
};

std::pair<int,std::string> extract_aurora_hostgroup_config(
	const json& replication_test_def,
	std::vector<aurora_hostgroup_config_t>& out_hostgroups_configs
);

using aurora_server_state_t = std::tuple<hostname, std::string, std::string, int32_t>;
enum AURORA_SERVER_STATE {
	SERVER_ID,
	DOMAIN_NAME,
	SESSION_ID,
	REPLICA_LAG_IN_MILLISECONDS
};

enum class aurora_state_id {
	init_state = 0,
	new_state = 1
};

std::pair<int,std::string> extract_aurora_servers_state(
	const aurora_state_id& state_id,
	const json& aurora_test_def,
	std::vector<aurora_server_state_t>& out_server_states
);

std::pair<int, std::string> prepare_mysql_aurora_hostgroups(
	MYSQL* proxysql_admin,
	const std::vector<aurora_hostgroup_config_t>& hostgroups_configs
);

/**
 * Publishes ordinary Aurora JSON state through backend-address replica sets.
 * DOMAIN_NAME identifies the set, and CLUSTER_SIM_HOST_FILE resolves every
 * SERVER_ID + DOMAIN_NAME member hostname to its simulated backend address.
 */
std::pair<int, std::string> prepare_aurora_cluster_state(
	MYSQL* proxysql_sqlite,
	const std::vector<aurora_server_state_t>& servers,
	uint32_t cleanup = 0
);

/**
 * @brief Set times for 'mysql-monitor_auroralication_healthcheck_interval'
 *   and 'mysql-monitor_auroralication_healthcheck_timeout' for the
 *   simulation to be performed.
 *
 *   Note: these values are hardcoded; making them configurable is a future enhancement.
 *
 * @param proxysql_admin An already opened connection to ProxySQL admin.
 * @return A `std::pair` of kind `{ err_code, "err_msg" }`.
 */
std::pair<int, std::string> set_aurora_monitor_check_times(MYSQL* admin);

std::pair<int, std::string> get_aurora_monitor_check_times(
	MYSQL* admin, int& out_healthcheck_interval, int& out_healthcheck_timeout
);

cluster_state_changes aurora_servers_state_diff(
	const std::vector<aurora_server_state_t>& servers_state_p,
	const std::vector<aurora_server_state_t>& servers_state_n
);

std::vector<aurora_server_state_t> aurora_update_cluster_state(
	const std::vector<aurora_server_state_t>& servers_state_p,
	const std::vector<aurora_server_state_t>& servers_state_n
);

#endif
