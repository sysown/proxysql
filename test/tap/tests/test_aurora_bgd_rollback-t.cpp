/**
 * @file test_aurora_bgd_rollback-t.cpp
 * @brief Aurora BGD rollback from each active writer phase.
 *
 * @details Runs independent deployments through INITIATED, IN_PROGRESS, and
 *   POST_PROCESSING before publishing AVAILABLE again. Each case verifies only
 *   the routing and status effects that its phase must reverse.
 */

#include <cstdlib>
#include <vector>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_a() };
	vector<int> routes { 2154, 2155, 2156 };
};

int prepare_available(
	Context& context, TestState& state,
	int writer_hostgroup, int reader_hostgroup
) {
	return publish_available(context, state.deployment) == EXIT_SUCCESS
		&& configure(
			context, state.deployment, writer_hostgroup, reader_hostgroup,
			writer_hostgroup + 2, reader_hostgroup + 2) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			context.admin, writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS
		? EXIT_SUCCESS : EXIT_FAILURE;
}

/** @brief Verify INITIATED can return to AVAILABLE without routing changes. */
int test_initiated_rollback(Context& context, TestState& state) {
	if (prepare_available(context, state, 2130, 2131) != EXIT_SUCCESS
		|| publish_status(
			context, state.deployment, "SWITCHOVER_INITIATED") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, 2130, "SWITCHOVER_INITIATED", kWaitSeconds) != EXIT_SUCCESS
		|| publish_status(context, state.deployment, "AVAILABLE") != EXIT_SUCCESS) {
		diag("Error: failed to run INITIATED rollback");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, 2130, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"INITIATED rollback returns wHG 2130 to AVAILABLE");
	ok(writer_placement(
		context.admin, 2130, 2131,
		state.deployment.production.members.front().endpoint.hostname, false),
		"INITIATED rollback leaves canonical writer placement unchanged");
	return EXIT_SUCCESS;
}

/** @brief Verify IN_PROGRESS rollback restores canonical writer placement. */
int test_in_progress_rollback(Context& context, TestState& state) {
	if (reset(context) != EXIT_SUCCESS
		|| prepare_available(context, state, 2140, 2141) != EXIT_SUCCESS
		|| publish_status(
			context, state.deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, 2140, "SWITCHOVER_IN_PROGRESS", kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: failed to enter IN_PROGRESS rollback");
		return EXIT_FAILURE;
	}
	ok(writer_placement(
		context.admin, 2140, 2141,
		state.deployment.production.members.front().endpoint.hostname, true),
		"IN_PROGRESS demotes the source writer before rollback");
	auto [sequence_rc, sequence] = context.simulator.replica_probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS
		|| publish_status(context, state.deployment, "AVAILABLE") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, 2140, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS
		&& writer_placement(
			context.admin, 2140, 2141,
			state.deployment.production.members.front().endpoint.hostname, false),
		"IN_PROGRESS rollback restores AVAILABLE and canonical writer placement");
	ok(ordinary_probe_reached(context, sequence, state.deployment),
		"IN_PROGRESS rollback resumes the ordinary Aurora probe");
	return EXIT_SUCCESS;
}

/** @brief Verify POST_PROCESSING rollback removes every applied traffic pin. */
int test_post_processing_rollback(
	CommandLine& cl, Context& context, TestState& state
) {
	if (reset(context) != EXIT_SUCCESS
		|| prepare_available(context, state, 2150, 2151) != EXIT_SUCCESS
		|| add_member_routes(context.admin, state.deployment, state.routes) != EXIT_SUCCESS
		|| publish_status(
			context, state.deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, 2150, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds)
			!= EXIT_SUCCESS) {
		diag("Error: failed to enter POST_PROCESSING rollback");
		return EXIT_FAILURE;
	}
	ok(route_members(cl, context, state.deployment, state.routes, true),
		"POST_PROCESSING applies the complete target map before rollback");
	if (publish_status(context, state.deployment, "AVAILABLE") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, 2150, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS
		&& writer_placement(
			context.admin, 2150, 2151,
			state.deployment.production.members.front().endpoint.hostname, false),
		"POST_PROCESSING rollback restores AVAILABLE and canonical writer placement");
	ok(route_members(cl, context, state.deployment, state.routes, false),
		"POST_PROCESSING rollback removes every target traffic pin");
	return EXIT_SUCCESS;
}

int main() {
	plan(8);

	CommandLine cl {};
	Context context {};
	if (setup(cl, context) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};
	if (test_initiated_rollback(context, state) != EXIT_SUCCESS
		|| test_in_progress_rollback(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_post_processing_rollback(cl, context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the rollback fixture");
	}
	return exit_status();
}
