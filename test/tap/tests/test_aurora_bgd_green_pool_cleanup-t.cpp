/**
 * @file test_aurora_bgd_green_pool_cleanup-t.cpp
 * @brief Aurora BGD rollback and completion behavior for green status pools.
 */

#include <cstdlib>
#include <string>
#include <vector>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct GreenServer {
	int hostgroup;
	Aurora_BGD_Endpoint endpoint;
	string status;
	int route_hostgroup;
};

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_a() };
	Aurora_BGD_Test_Deployment extra { aurora_bgd_deployment_c_writer_only() };
	int writer_hostgroup { 2060 };
	int reader_hostgroup { 2061 };
	int green_writer_hostgroup { 2062 };
	int green_reader_hostgroup { 2063 };
	vector<GreenServer> servers {
		{ green_writer_hostgroup, deployment.target.members[0].endpoint, "ONLINE", 2064 },
		{ green_reader_hostgroup, deployment.target.members[1].endpoint, "SHUNNED", 2065 },
		{ green_reader_hostgroup, deployment.target.members[2].endpoint, "OFFLINE_SOFT", 2066 },
		{ green_reader_hostgroup, extra.target.members[0].endpoint, "OFFLINE_HARD", 2067 },
	};
	vector<int64_t> pools_before;
	vector<int64_t> pools_after;
};

int add_status_matrix(Context& context, TestState& state) {
	if (context.simulator.replica_update(
		state.extra.target.replica_set_id, state.extra.target.replica_rows(),
		state.extra.target.backends()) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	for (GreenServer& server : state.servers) {
		if (add_route(
			context.admin, server.hostgroup, server.endpoint.hostname,
			server.status, true, "Aurora BGD configured green status") != EXIT_SUCCESS
			|| add_route(
				context.admin, server.route_hostgroup, server.endpoint.hostname,
				"ONLINE", true, "Aurora BGD green pool route") != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

int create_green_pools(CommandLine& cl, Context& context, TestState& state) {
	state.pools_before.clear();
	for (GreenServer& server : state.servers) {
		if (set_default_hostgroup(context.admin, server.route_hostgroup) != EXIT_SUCCESS
			|| !route_to_backend(cl, context, server.endpoint.backend())) {
			return EXIT_FAILURE;
		}
		int64_t pool = pool_connections_for_hostname(
			context.admin, server.endpoint.hostname);
		if (pool < 1) {
			return EXIT_FAILURE;
		}
		state.pools_before.push_back(pool);
	}
	return set_default_hostgroup(context.admin, state.writer_hostgroup);
}

bool configured_rows_preserved(Context& context, TestState& state) {
	for (GreenServer& server : state.servers) {
		if (!server_count(
			context.admin, "mysql_servers", server.hostgroup,
			server.endpoint.hostname, 1, server.status)) {
			return false;
		}
	}
	return true;
}

int test_rollback_preserves_green_pools(
	CommandLine& cl, Context& context, TestState& state
) {
	if (publish_available(context, state.deployment) != EXIT_SUCCESS
		|| configure(
			context, state.deployment, state.writer_hostgroup, state.reader_hostgroup,
			state.green_writer_hostgroup, state.green_reader_hostgroup) != EXIT_SUCCESS
		|| add_status_matrix(context, state) != EXIT_SUCCESS
		|| create_green_pools(cl, context, state) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) != EXIT_SUCCESS
		|| publish_status(
			context, state.deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "SWITCHOVER_IN_PROGRESS",
			kWaitSeconds) != EXIT_SUCCESS
		|| publish_status(context, state.deployment, "AVAILABLE") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: failed to run the green-pool rollback lifecycle");
		return EXIT_FAILURE;
	}

	bool pools_preserved = state.pools_before.size() == state.servers.size();
	for (size_t i = 0; i < state.servers.size(); ++i) {
		pools_preserved = pools_preserved
			&& pool_connections_for_hostname(
				context.admin, state.servers[i].endpoint.hostname) >= state.pools_before[i];
	}
	ok(pools_preserved,
		"AVAILABLE rollback preserves all four green status pools for wHG 2060");
	ok(configured_rows_preserved(context, state),
		"AVAILABLE rollback preserves configured green rows and public statuses for wHG 2060");
	return EXIT_SUCCESS;
}

int test_successful_cleanup_drains_non_offline(
	Context& context, TestState& state
) {
	if (publish_status(
			context, state.deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "SWITCHOVER_IN_POST_PROCESSING",
			kWaitSeconds) != EXIT_SUCCESS
		|| publish_completed(context, state.deployment, state.deployment) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "SWITCHOVER_COMPLETED",
			kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: failed to complete the green-pool lifecycle");
		return EXIT_FAILURE;
	}

	bool drained = wait_for_hostname_pool_count(
		context.admin, state.servers[0].endpoint.hostname, "=0") == EXIT_SUCCESS
		&& wait_for_hostname_pool_count(
			context.admin, state.servers[1].endpoint.hostname, "=0") == EXIT_SUCCESS;
	ok(drained,
		"completion drains ONLINE and SHUNNED green pools for wHG 2060");
	ok(configured_rows_preserved(context, state),
		"completion retains configured green rows and public statuses for wHG 2060");
	return EXIT_SUCCESS;
}

int test_cleanup_preserves_offline_pools(Context& context, TestState& state) {
	state.pools_after.clear();
	for (GreenServer& server : state.servers) {
		state.pools_after.push_back(pool_connections_for_hostname(
			context.admin, server.endpoint.hostname));
	}
	bool offline_preserved = state.pools_before.size() == 4
		&& state.pools_after.size() == 4
		&& state.pools_after[2] >= state.pools_before[2]
		&& state.pools_after[3] >= state.pools_before[3];
	ok(offline_preserved,
		"completion preserves OFFLINE_SOFT and OFFLINE_HARD green pools for wHG 2060");
	return EXIT_SUCCESS;
}

int main() {
	plan(5);

	CommandLine cl {};
	Context context {};
	if (setup(cl, context) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};
	if (test_rollback_preserves_green_pools(cl, context, state) != EXIT_SUCCESS
		|| test_successful_cleanup_drains_non_offline(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_cleanup_preserves_offline_pools(context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the green-pool fixture");
	}
	return exit_status();
}
