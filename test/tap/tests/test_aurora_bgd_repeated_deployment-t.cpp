/**
 * @file test_aurora_bgd_repeated_deployment-t.cpp
 * @brief Reuse one Aurora worker for a later deployment fingerprint.
 *
 * @details Completes one deployment, drains its topology, then publishes a
 *   different target fingerprint on the same worker and verifies the new
 *   deployment can independently reach POST_PROCESSING.
 */

#include <cstdlib>
#include <vector>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

Aurora_BGD_Test_Deployment deployment_b() {
	Aurora_BGD_Test_Deployment deployment = aurora_bgd_deployment_a();
	deployment.name = "Aurora BGD deployment A second target";
	deployment.target_replica_set = "aurora-bgd-target-a-r2";
	deployment.target_topology_id = "aurora-bgd-target-a-r2";
	const vector<string> ids {
		"aurora-a-writer-green-r2",
		"aurora-a-reader-1-green-r2",
		"aurora-a-reader-2-green-r2",
	};
	const vector<string> ips { "127.0.11.31", "127.0.11.32", "127.0.11.33" };
	for (size_t i = 0; i < deployment.target.members.size(); ++i) {
		deployment.target.members[i].server_id = ids[i];
		deployment.target.members[i].endpoint.hostname = ids[i] + deployment.domain_name;
		deployment.target.members[i].endpoint.ip = ips[i];
	}
	deployment.target.replica_set_id = deployment.target_replica_set;
	deployment.target.serving_endpoints.clear();
	deployment.target.serving_endpoints.push_back(deployment.target_cluster_endpoint);
	for (Aurora_BGD_Member& member : deployment.target.members) {
		deployment.target.serving_endpoints.push_back(member.endpoint);
	}
	return deployment;
}

struct TestState {
	Aurora_BGD_Test_Deployment first { aurora_bgd_deployment_a() };
	Aurora_BGD_Test_Deployment second { deployment_b() };
	int writer_hostgroup { 2240 };
	int reader_hostgroup { 2241 };
	int green_writer_hostgroup { 2242 };
	int green_reader_hostgroup { 2243 };
	vector<int> routes { 2244, 2245, 2246 };
	vector<int> completion_routes { 2247, 2248, 2249 };
};

int complete_deployment(
	Context& context, Aurora_BGD_Test_Deployment& deployment, int writer_hostgroup
) {
	return publish_status(context, deployment, "SWITCHOVER_IN_PROGRESS") == EXIT_SUCCESS
				&& aurora_bgd_wait_for_status(
					context.admin, writer_hostgroup, "SWITCHOVER_IN_PROGRESS", kWaitSeconds)
					== EXIT_SUCCESS
			&& publish_status(
				context, deployment, "SWITCHOVER_IN_POST_PROCESSING") == EXIT_SUCCESS
			&& aurora_bgd_wait_for_status(
				context.admin, writer_hostgroup, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds)
				== EXIT_SUCCESS
				&& publish_completed(context, deployment, deployment) == EXIT_SUCCESS
				&& aurora_bgd_wait_for_status(
					context.admin, writer_hostgroup, "SWITCHOVER_COMPLETED", kWaitSeconds)
					== EXIT_SUCCESS
				? EXIT_SUCCESS : EXIT_FAILURE;
}

/** @brief Complete the first deployment and release its completed latch. */
int test_deployment_a(Context& context, TestState& state) {
	if (publish_available(context, state.first) != EXIT_SUCCESS
		|| configure(
			context, state.first, state.writer_hostgroup, state.reader_hostgroup,
			state.green_writer_hostgroup, state.green_reader_hostgroup) != EXIT_SUCCESS
			|| aurora_bgd_wait_for_status(
				context.admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds)
				!= EXIT_SUCCESS
				|| complete_deployment(
					context, state.first, state.writer_hostgroup) != EXIT_SUCCESS) {
		diag("Error: failed to complete deployment A");
		return EXIT_FAILURE;
	}
	ok(writer_placement(
		context.admin, state.writer_hostgroup, state.reader_hostgroup,
		state.first.production.members.front().endpoint.hostname, false),
		"deployment A completion latches and restores canonical writer placement");
	return EXIT_SUCCESS;
}

/** @brief Verify the rearmed worker accepts and redirects the second deployment. */
int test_deployment_b(
	CommandLine& cl, Context& context, TestState& state
) {
	auto [sequence_rc, sequence] = context.simulator.replica_probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS
		|| publish_available(context, state.second) != EXIT_SUCCESS
		|| add_member_routes(
			context.admin, state.second, state.routes) != EXIT_SUCCESS) {
		diag("Error: failed to publish deployment B");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS
		&& membership_probe_reached(context, sequence, state.second),
		"deployment B reuses wHG 2240 with only its new target membership");

	if (publish_status(
			context, state.second, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "SWITCHOVER_IN_POST_PROCESSING",
			kWaitSeconds) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(route_members(cl, context, state.second, state.routes, true),
		"deployment B POST_PROCESSING routes new connections to deployment B");

	if (publish_completed(context, state.second, state.second) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "SWITCHOVER_COMPLETED",
			kWaitSeconds) != EXIT_SUCCESS
		|| add_member_routes(
			context.admin, state.second, state.completion_routes) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(route_members(cl, context, state.second, state.completion_routes, false),
		"deployment B completion removes its pins without restoring deployment A's stale map");
	return EXIT_SUCCESS;
}

int main() {
	plan(4);

	CommandLine cl {};
	Context context {};
	if (setup(cl, context) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};
	if (test_deployment_a(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_deployment_b(cl, context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the repeated-deployment fixture");
	}
	return exit_status();
}
