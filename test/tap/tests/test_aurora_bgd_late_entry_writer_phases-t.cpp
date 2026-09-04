/**
 * @file test_aurora_bgd_late_entry_writer_phases-t.cpp
 * @brief First observation of each active Aurora BGD writer phase.
 *
 * @details Starts independent workers directly in INITIATED, IN_PROGRESS, and
 *   POST_PROCESSING to verify phase-specific routing actions and the switch
 *   from ordinary production probes to target-membership probes.
 */

#include <cstdlib>
#include <vector>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment initiated { aurora_bgd_deployment_b_writer_only() };
	Aurora_BGD_Test_Deployment progress { aurora_bgd_deployment_b_writer_only() };
	Aurora_BGD_Test_Deployment post { aurora_bgd_deployment_a() };
	vector<int> post_routes { 2114, 2115, 2116 };
};

bool active_probe_policy(
	Context& context, uint64_t sequence, const string& target_replica_set
) {
	usleep(450000);
	auto [rc, logs] = context.simulator.replica_probe_log_since(sequence);
	if (rc != EXIT_SUCCESS) {
		return false;
	}
	bool membership_seen = false;
	for (const Aurora_Replica_Probe_Log& log : logs) {
		if (log.probe_kind == Aurora_Replica_Probe_Kind::ordinary) {
			return false;
		}
		membership_seen = membership_seen
			|| (log.probe_kind == Aurora_Replica_Probe_Kind::bgd_membership
				&& log.replica_set_id == target_replica_set);
	}
	return membership_seen;
}

/** @brief Verify direct INITIATED entry suspends ordinary production probing. */
int test_first_initiated(Context& context, TestState& state) {
	if (publish_initial(
			context, state.initiated, "SWITCHOVER_INITIATED") != EXIT_SUCCESS
		|| configure(context, state.initiated, 2090, 2091, 2092, 2093,
			false, 300) != EXIT_SUCCESS) {
		diag("Error: failed to configure INITIATED late entry");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, 2090, "SWITCHOVER_INITIATED", kWaitSeconds) == EXIT_SUCCESS,
		"first INITIATED observation reports SWITCHOVER_INITIATED for wHG 2090");
	ok(writer_placement(
		context.admin, 2090, 2091,
		state.initiated.production.members.front().endpoint.hostname, false),
		"first INITIATED observation leaves source placement unchanged");
	auto [sequence_rc, sequence] = context.simulator.replica_probe_log_last_sequence();
	ok(sequence_rc == EXIT_SUCCESS && active_probe_policy(
		context, sequence, state.initiated.target_replica_set),
		"first INITIATED observation reconstructs active target probing");
	return EXIT_SUCCESS;
}

/** @brief Verify direct IN_PROGRESS entry demotes the source writer. */
int test_first_in_progress(Context& context, TestState& state) {
	if (reset(context) != EXIT_SUCCESS
		|| publish_initial(
			context, state.progress, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| configure(context, state.progress, 2100, 2101, 2102, 2103,
			false, 300) != EXIT_SUCCESS) {
		diag("Error: failed to configure IN_PROGRESS late entry");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, 2100, "SWITCHOVER_IN_PROGRESS", kWaitSeconds) == EXIT_SUCCESS,
		"first IN_PROGRESS observation reports SWITCHOVER_IN_PROGRESS for wHG 2100");
	ok(writer_placement(
		context.admin, 2100, 2101,
		state.progress.production.members.front().endpoint.hostname, true),
		"first IN_PROGRESS observation demotes the source writer");
	return EXIT_SUCCESS;
}

/** @brief Verify direct POST_PROCESSING entry redirects every mapped member. */
int test_first_post_processing(
	CommandLine& cl, Context& context, TestState& state
) {
	if (reset(context) != EXIT_SUCCESS
		|| publish_initial(
			context, state.post, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| configure(context, state.post, 2110, 2111, 2112, 2113,
			false, 300) != EXIT_SUCCESS
		|| add_member_routes(
			context.admin, state.post, state.post_routes) != EXIT_SUCCESS) {
		diag("Error: failed to configure POST_PROCESSING late entry");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, 2110, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds)
		== EXIT_SUCCESS,
		"first POST_PROCESSING observation reports SWITCHOVER_IN_POST_PROCESSING for wHG 2110");
	ok(route_members(cl, context, state.post, state.post_routes, true),
		"first POST_PROCESSING observation reconstructs every target pin");
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
	if (test_first_initiated(context, state) != EXIT_SUCCESS
		|| test_first_in_progress(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_first_post_processing(cl, context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the late-entry writer-phase fixture");
	}
	return exit_status();
}
