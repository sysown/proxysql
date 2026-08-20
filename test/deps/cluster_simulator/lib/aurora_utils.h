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

/**
 * @brief Select how a simulator publication replaces Aurora replica state.
 */
enum class aurora_publication_mode {
	replace_sets,  ///< Replace only the replica sets present in the new state.
	replace_snapshot_retaining_backends,  ///< Replace all rows while retaining matching backend controls.
	reset_scenario  ///< Remove all Aurora rows and controls before publishing the new state.
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
 * @brief Publish ordinary Aurora state through backend-address replica sets.
 *
 * @details DOMAIN_NAME identifies the set, and CLUSTER_SIM_HOST_FILE resolves
 *   every SERVER_ID + DOMAIN_NAME member hostname to its simulated backend
 *   address. Publication is transactional. Snapshot replacement waits until
 *   every retained set has received an ordinary Aurora probe.
 *
 * @param proxysql_sqlite Connection to the simulator SQLite interface.
 * @param servers Aurora members grouped by DOMAIN_NAME.
 * @param mode State replacement policy for rows and backend controls.
 * @return Pair containing EXIT_SUCCESS and an empty message, or EXIT_FAILURE
 *   and a diagnostic message.
 */
std::pair<int, std::string> prepare_aurora_cluster_state(
	MYSQL* proxysql_sqlite,
	const std::vector<aurora_server_state_t>& servers,
	aurora_publication_mode mode = aurora_publication_mode::replace_sets
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

#endif
