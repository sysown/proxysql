/**
 * @file test_aurora_bgd_topology_errors-t.cpp
 * @brief Aurora BGD state retention across generic metadata errors.
 *
 * @details Injects non-table-missing errors into topology and target-membership
 *   probes. Each case verifies the active phase and its already-applied routing
 *   effects remain unchanged until a valid observation arrives.
 */

#include <cstdlib>
#include <vector>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_a() };
	vector<int> routes { 2194, 2195, 2196 };
};

/** @brief Verify a generic topology error retains active state and writer placement. */
int test_generic_topology_error(Context& context, TestState& state) {
	if (publish_initial(
			context, state.deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| configure(context, state.deployment, 2180, 2181, 2182, 2183,
			false, 300) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, 2180, "SWITCHOVER_IN_PROGRESS", kWaitSeconds)
			!= EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	auto [sequence_rc, sequence] = context.simulator.probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS
		|| context.simulator.topology_error(
			aurora_bgd_topology_backends(state.deployment), 1205,
			"simulated topology timeout") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	auto [probe_rc, probe] = aurora_bgd_wait_for_topology_probe(
		context.simulator, sequence, state.deployment.target.backends(),
		BGD_Probe_Kind::metadata, kProbeTimeoutMs);
	(void)probe;
	ok(probe_rc == EXIT_SUCCESS
		&& runtime_status_is(context.admin, 2180, "SWITCHOVER_IN_PROGRESS")
		&& writer_placement(
			context.admin, 2180, 2181,
			state.deployment.production.members.front().endpoint.hostname, true),
		"generic topology errors retain active state and writer placement");
	return EXIT_SUCCESS;
}

/** @brief Verify a generic membership error retains post-processing traffic pins. */
int test_generic_membership_error(
	CommandLine& cl, Context& context, TestState& state
) {
	if (reset(context) != EXIT_SUCCESS
		|| publish_initial(
			context, state.deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| configure(context, state.deployment, 2190, 2191, 2192, 2193,
			false, 300) != EXIT_SUCCESS
		|| add_member_routes(context.admin, state.deployment, state.routes) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, 2190, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds)
			!= EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	auto [sequence_rc, sequence] = context.simulator.replica_probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS
		|| context.simulator.replica_error(
			state.deployment.target.backends(), 1205,
			"simulated membership timeout") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	auto [probe_rc, probe] = aurora_bgd_wait_for_replica_probe(
		context.simulator, sequence, state.deployment.target.backends(),
		Aurora_Replica_Probe_Kind::bgd_membership, kProbeTimeoutMs,
		state.deployment.target.replica_set_id);
	(void)probe;
	bool retained = probe_rc == EXIT_SUCCESS
		&& runtime_status_is(
			context.admin, 2190, "SWITCHOVER_IN_POST_PROCESSING")
		&& context.simulator.replica_update(
			state.deployment.target.replica_set_id,
			state.deployment.target.replica_rows(),
			state.deployment.target.backends()) == EXIT_SUCCESS
			&& route_members(cl, context, state.deployment, state.routes, true);
	ok(retained,
		"generic membership errors retain active state and recover target routing");
	return EXIT_SUCCESS;
}

int main() {
	plan(2);

	CommandLine cl {};
	Context context {};
	if (setup(cl, context) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};
	if (test_generic_topology_error(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_generic_membership_error(cl, context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the topology-error fixture");
	}
	return exit_status();
}
