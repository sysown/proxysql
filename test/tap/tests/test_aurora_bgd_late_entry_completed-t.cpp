/**
 * @file test_aurora_bgd_late_entry_completed-t.cpp
 * @brief First observation of Aurora BGD completion and later rearm.
 *
 * @details Starts a worker on a lone completed TARGET row, verifies the
 *   resulting cleanup is a routing no-op, then drains the topology and checks
 *   that discovery rearms for a later deployment.
 */

#include <cstdlib>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_b_writer_only() };
	int writer_hostgroup { 2120 };
	int reader_hostgroup { 2121 };
	int route_hostgroup { 2122 };
};

/** @brief Verify direct entry at completion preserves source routing and latches identity. */
int test_first_completed(
	CommandLine& cl, Context& context, TestState& state
) {
	if (context.simulator.replica_update(
			state.deployment.production.replica_set_id,
			state.deployment.production.replica_rows(),
			state.deployment.production.backends()) != EXIT_SUCCESS
		|| context.simulator.topology_update(
			aurora_bgd_topology_backends(state.deployment),
			aurora_bgd_completed_topology(state.deployment)) != EXIT_SUCCESS
		|| add_route(
			context.admin, state.route_hostgroup,
			state.deployment.production.members.front().endpoint.hostname) != EXIT_SUCCESS) {
		diag("Error: failed to publish direct-completion inputs");
		return EXIT_FAILURE;
	}
	auto [sequence_rc, sequence] = context.simulator.replica_probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS
		|| configure(
			context, state.deployment, state.writer_hostgroup, state.reader_hostgroup,
			-1, -1, true, 300) != EXIT_SUCCESS
		|| set_default_hostgroup(
			context.admin, state.route_hostgroup) != EXIT_SUCCESS) {
		diag("Error: failed to configure direct completion");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "SWITCHOVER_COMPLETED",
		kWaitSeconds) == EXIT_SUCCESS,
		"first COMPLETED observation reports SWITCHOVER_COMPLETED for wHG 2120");
	ok(writer_placement(
		context.admin, state.writer_hostgroup, state.reader_hostgroup,
		state.deployment.production.members.front().endpoint.hostname, false),
		"first COMPLETED observation leaves canonical writer placement unchanged");
	ok(route_to_backend(
		cl, context, state.deployment.production.members.front().endpoint.backend()),
		"first COMPLETED observation creates no target traffic pin");

	usleep(500000);
	auto [logs_rc, logs] = context.simulator.replica_probe_log_since(sequence);
	bool membership_seen = false;
	for (const Aurora_Replica_Probe_Log& log : logs) {
		membership_seen = membership_seen
			|| log.probe_kind == Aurora_Replica_Probe_Kind::bgd_membership;
	}
	ok(logs_rc == EXIT_SUCCESS && !membership_seen,
		"first COMPLETED observation does not replay target membership discovery");
	return EXIT_SUCCESS;
}

/** @brief Verify an empty topology releases the completed latch back to NONE. */
int test_completed_empty_topology(Context& context, TestState& state) {
	if (context.simulator.topology_delete(
		aurora_bgd_topology_backends(state.deployment)) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "NONE", kWaitSeconds) == EXIT_SUCCESS,
		"empty topology rearms the direct-completion latch to NONE");
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
	if (test_first_completed(cl, context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_completed_empty_topology(context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the late-entry completion fixture");
	}
	return exit_status();
}
