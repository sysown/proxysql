/**
 * @file test_aurora_bgd_writer_switchover-t.cpp
 * @brief Aurora BGD writer behavior across the active switchover phases.
 */

#include <cstdlib>
#include <vector>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_a() };
	int writer_hostgroup { 2040 };
	int reader_hostgroup { 2041 };
	int green_writer_hostgroup { 2042 };
	int green_reader_hostgroup { 2043 };
	vector<int> route_hostgroups { 2044, 2045, 2046 };
};

int test_bgd_status_available(Context& context, TestState& state) {
	if (publish_available(context, state.deployment) != EXIT_SUCCESS
		|| configure(
			context, state.deployment, state.writer_hostgroup, state.reader_hostgroup,
			state.green_writer_hostgroup, state.green_reader_hostgroup) != EXIT_SUCCESS
		|| add_member_routes(
			context.admin, state.deployment, state.route_hostgroups) != EXIT_SUCCESS) {
		diag("Error: failed to configure the writer-switchover fixture");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"BGD status for wHG 2040 reports AVAILABLE");
	ok(writer_placement(
		context.admin, state.writer_hostgroup, state.reader_hostgroup,
		state.deployment.production.members.front().endpoint.hostname, false),
		"AVAILABLE keeps the source writer in hostgroup 2040");
	return EXIT_SUCCESS;
}

int test_switchover_initiated(Context& context, TestState& state) {
	if (publish_status(context, state.deployment, "SWITCHOVER_INITIATED") != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_INITIATED");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "SWITCHOVER_INITIATED", kWaitSeconds)
		== EXIT_SUCCESS,
		"BGD status for wHG 2040 reports SWITCHOVER_INITIATED");
	ok(writer_placement(
		context.admin, state.writer_hostgroup, state.reader_hostgroup,
		state.deployment.production.members.front().endpoint.hostname, false),
		"SWITCHOVER_INITIATED leaves source placement unchanged");
	return EXIT_SUCCESS;
}

int test_switchover_in_progress(Context& context, TestState& state) {
	if (publish_status(context, state.deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "SWITCHOVER_IN_PROGRESS", kWaitSeconds)
		== EXIT_SUCCESS,
		"BGD status for wHG 2040 reports SWITCHOVER_IN_PROGRESS");
	ok(writer_placement(
		context.admin, state.writer_hostgroup, state.reader_hostgroup,
		state.deployment.production.members.front().endpoint.hostname, true),
		"SWITCHOVER_IN_PROGRESS demotes the source writer to hostgroup 2041");
	ok(server_count(
		context.admin, "runtime_mysql_servers", state.reader_hostgroup,
		state.deployment.production.members[1].endpoint.hostname, 1, "ONLINE")
		&& server_count(
			context.admin, "runtime_mysql_servers", state.reader_hostgroup,
			state.deployment.production.members[2].endpoint.hostname, 1, "ONLINE"),
		"SWITCHOVER_IN_PROGRESS leaves source readers ONLINE in hostgroup 2041");
	return EXIT_SUCCESS;
}

int test_switchover_post_processing(
	CommandLine& cl, Context& context, TestState& state
) {
	if (!route_members(
			cl, context, state.deployment, state.route_hostgroups, false)) {
		diag("Error: failed to create the source-backed pre-cutover pools");
		return EXIT_FAILURE;
	}
	for (int hostgroup : state.route_hostgroups) {
		if (pool_connections(context.admin, hostgroup) < 1) {
			diag("Error: route hostgroup %d has no pre-cutover pool", hostgroup);
			return EXIT_FAILURE;
		}
	}

	if (publish_status(
		context, state.deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_POST_PROCESSING");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "SWITCHOVER_IN_POST_PROCESSING",
		kWaitSeconds) == EXIT_SUCCESS,
		"BGD status for wHG 2040 reports SWITCHOVER_IN_POST_PROCESSING");
	ok(writer_placement(
		context.admin, state.writer_hostgroup, state.reader_hostgroup,
		state.deployment.production.members.front().endpoint.hostname, false),
		"POST_PROCESSING restores canonical writer placement");

	bool pools_drained = true;
	for (int hostgroup : state.route_hostgroups) {
		pools_drained = pools_drained
			&& wait_for_pool_count(context.admin, hostgroup, "=0") == EXIT_SUCCESS;
	}
	ok(pools_drained, "POST_PROCESSING drains the pre-cutover member pools");
	ok(route_members(
		cl, context, state.deployment, state.route_hostgroups, true),
		"POST_PROCESSING routes every source hostname to its mapped target member");

	vector<int64_t> pool_counts;
	for (int hostgroup : state.route_hostgroups) {
		pool_counts.push_back(pool_connections(context.admin, hostgroup));
	}
	if (publish_status(
		context, state.deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS) {
		diag("Error: failed to repeat SWITCHOVER_IN_POST_PROCESSING");
		return EXIT_FAILURE;
	}
	usleep(300000);
	bool pools_preserved = true;
	for (size_t i = 0; i < state.route_hostgroups.size(); ++i) {
		pools_preserved = pools_preserved
			&& pool_connections(context.admin, state.route_hostgroups[i]) >= pool_counts[i];
	}
	ok(pools_preserved,
		"repeated POST_PROCESSING does not replay completed pool retirement");
	return EXIT_SUCCESS;
}

int main() {
	plan(12);

	CommandLine cl {};
	Context context {};
	if (setup(cl, context) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};
	if (test_bgd_status_available(context, state) != EXIT_SUCCESS
		|| test_switchover_initiated(context, state) != EXIT_SUCCESS
		|| test_switchover_in_progress(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_switchover_post_processing(cl, context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the writer-switchover fixture");
	}
	return exit_status();
}
