#ifndef CLUSTER_SIM_REPLICATIONLAG_UTILS
#define CLUSTER_SIM_REPLICATIONLAG_UTILS

#include <string>
#include <vector>
#include <tuple>
#include <utility>

#include "json.hpp"

#include "common_utils.h"

using replicationlag_server_state = std::tuple<hostname, port, std::shared_ptr<int>>;

enum class replicationlag_state_id {
	init_state = 0,
	new_state = 1
};

std::pair<int,std::string> extract_replicationlag_servers_state(
	const replicationlag_state_id& state_id,
	const json& replicationlag_test_def,
	std::vector<replicationlag_server_state>& out_server_states
);

std::pair<int, std::string> prepare_replicationlag_cluster_state(
	MYSQL* proxysql_sqlite,
	const std::vector<replicationlag_server_state>& servers,
	bool cleanup = false
);


std::pair<int, std::string> set_replicationlag_monitor_check_times(MYSQL* proxysql_admin);

std::pair<int, std::string> get_replicationlag_monitor_check_times(
	MYSQL* proxysql_admin,
	int& out_healthcheck_interval,
	int& out_healthcheck_timeout
);

cluster_state_changes replicationlag_servers_state_diff(
	const std::vector<replicationlag_server_state>& servers_state_p,
	const std::vector<replicationlag_server_state>& servers_state_n
);

std::vector<replicationlag_server_state> replicationlag_update_cluster_state(
	const std::vector<replicationlag_server_state>& servers_state_p,
	const std::vector<replicationlag_server_state>& servers_state_n
);

#endif

