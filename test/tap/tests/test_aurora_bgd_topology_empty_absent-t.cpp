/**
 * @file test_aurora_bgd_topology_empty_absent-t.cpp
 * @brief Aurora BGD cancellation on successful empty or absent topology.
 *
 * @details Starts independent deployments in IN_PROGRESS, then verifies both
 *   a successful empty result and a missing topology table cancel the active
 *   deployment, restore the writer, and resume ordinary Aurora probing.
 */

#include <cstdlib>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_b_writer_only() };
};

int prepare_in_progress(
	Context& context, TestState& state, int writer_hostgroup, int reader_hostgroup
) {
	return publish_available(context, state.deployment) == EXIT_SUCCESS
		&& configure(
			context, state.deployment, writer_hostgroup, reader_hostgroup,
			writer_hostgroup + 2, reader_hostgroup + 2) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			context.admin, writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS
		&& publish_status(
			context, state.deployment, "SWITCHOVER_IN_PROGRESS") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			context.admin, writer_hostgroup, "SWITCHOVER_IN_PROGRESS",
			kWaitSeconds) == EXIT_SUCCESS
		? EXIT_SUCCESS : EXIT_FAILURE;
}

/** @brief Verify an empty topology cancels an active deployment safely. */
int test_empty_before_completion(Context& context, TestState& state) {
	if (prepare_in_progress(context, state, 2160, 2161) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	auto [sequence_rc, sequence] = context.simulator.replica_probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS
		|| context.simulator.topology_delete(
			aurora_bgd_topology_backends(state.deployment)) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, 2160, "NONE", kWaitSeconds) == EXIT_SUCCESS
		&& writer_placement(
			context.admin, 2160, 2161,
			state.deployment.production.members.front().endpoint.hostname, false),
		"empty topology restores the source writer and sets wHG 2160 to NONE");
	ok(ordinary_probe_reached(context, sequence, state.deployment),
		"empty-topology cancellation resumes ordinary Aurora probing");
	return EXIT_SUCCESS;
}

/** @brief Verify a missing topology table cancels an active deployment safely. */
int test_absent_before_completion(Context& context, TestState& state) {
	if (reset(context) != EXIT_SUCCESS
		|| prepare_in_progress(context, state, 2170, 2171) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	auto [sequence_rc, sequence] = context.simulator.replica_probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS
		|| context.simulator.topology_drop(
			aurora_bgd_topology_backends(state.deployment)) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, 2170, "NONE", kWaitSeconds) == EXIT_SUCCESS
		&& writer_placement(
			context.admin, 2170, 2171,
			state.deployment.production.members.front().endpoint.hostname, false),
		"absent topology restores the source writer and sets wHG 2170 to NONE");
	ok(ordinary_probe_reached(context, sequence, state.deployment),
		"absent-topology cancellation resumes ordinary Aurora probing");
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
	if (test_empty_before_completion(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_absent_before_completion(context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the topology-empty/absent fixture");
	}
	return exit_status();
}
