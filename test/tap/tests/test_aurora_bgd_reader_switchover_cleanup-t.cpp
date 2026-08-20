/**
 * @file test_aurora_bgd_reader_switchover_cleanup-t.cpp
 * @brief Aurora BGD immediate completion cleanup and topology-drain rearm.
 *
 * @details Redirects all mapped members in POST_PROCESSING, publishes the lone
 *   completed TARGET row, and verifies immediate routing cleanup. A later empty
 *   topology must release the completed latch.
 */

#include <cstdlib>
#include <vector>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_a() };
	int writer_hostgroup { 2070 };
	int reader_hostgroup { 2071 };
	int green_writer_hostgroup { 2072 };
	int green_reader_hostgroup { 2073 };
	vector<int> target_routes { 2074, 2075, 2076 };
	vector<int> source_routes { 2077, 2078, 2079 };
};

/** @brief Verify completion removes target pins and restores production routing. */
int test_completion_cleanup(
	CommandLine& cl, Context& context, TestState& state
) {
	if (publish_available(context, state.deployment) != EXIT_SUCCESS
		|| configure(
			context, state.deployment, state.writer_hostgroup, state.reader_hostgroup,
			state.green_writer_hostgroup, state.green_reader_hostgroup) != EXIT_SUCCESS
		|| add_member_routes(
			context.admin, state.deployment, state.target_routes) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) != EXIT_SUCCESS
		|| publish_status(
			context, state.deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "SWITCHOVER_IN_PROGRESS",
			kWaitSeconds) != EXIT_SUCCESS
		|| publish_status(
			context, state.deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "SWITCHOVER_IN_POST_PROCESSING",
			kWaitSeconds) != EXIT_SUCCESS
		|| !route_members(
			cl, context, state.deployment, state.target_routes, true)) {
		diag("Error: failed to reach POST_PROCESSING with target routes");
		return EXIT_FAILURE;
	}

	auto [sequence_rc, sequence] = context.simulator.replica_probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS
		|| publish_completed(context, state.deployment, state.deployment) != EXIT_SUCCESS) {
		diag("Error: failed to publish completion");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "SWITCHOVER_COMPLETED",
		kWaitSeconds) == EXIT_SUCCESS,
		"completion reports SWITCHOVER_COMPLETED for wHG 2070");
	ok(writer_placement(
		context.admin, state.writer_hostgroup, state.reader_hostgroup,
		state.deployment.production.members.front().endpoint.hostname, false),
		"completion restores canonical writer placement");

	if (add_member_routes(
		context.admin, state.deployment, state.source_routes) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(route_members(
		cl, context, state.deployment, state.source_routes, false),
		"completion removes writer and reader traffic pins");
	ok(ordinary_probe_reached(context, sequence, state.deployment),
		"completion resumes the ordinary Aurora probe");

	if (publish_completed(context, state.deployment, state.deployment) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	usleep(300000);
	ok(runtime_status_is(context.admin, state.writer_hostgroup, "SWITCHOVER_COMPLETED")
		&& route_members(cl, context, state.deployment, state.source_routes, false),
		"repeated completion preserves the completed cleanup result");
	return EXIT_SUCCESS;
}

/** @brief Verify an empty topology releases the completed latch to NONE. */
int test_topology_drain(Context& context, TestState& state) {
	if (context.simulator.topology_delete(
		aurora_bgd_topology_backends(state.deployment)) != EXIT_SUCCESS) {
		diag("Error: failed to publish empty topology");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "NONE", kWaitSeconds) == EXIT_SUCCESS,
		"successful empty topology rearms wHG 2070 to NONE");
	ok(server_count(
		context.admin, "runtime_mysql_servers", state.writer_hostgroup,
		state.deployment.production.members.front().endpoint.hostname, 1)
		&& server_count(
			context.admin, "runtime_mysql_servers", state.reader_hostgroup,
			state.deployment.production.members[1].endpoint.hostname, 1),
		"topology rearm retains configured source rows");
	return EXIT_SUCCESS;
}

int main() {
	plan(7);

	CommandLine cl {};
	Context context {};
	if (setup(cl, context) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};
	if (test_completion_cleanup(cl, context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_topology_drain(context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the completion-cleanup fixture");
	}
	return exit_status();
}
