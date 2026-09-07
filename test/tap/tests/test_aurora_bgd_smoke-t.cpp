/**
 * @file test_aurora_bgd_smoke-t.cpp
 * @brief Basic Aurora BGD AVAILABLE discovery.
 *
 * @details Publishes one valid deployment and verifies AVAILABLE state,
 *   continued ordinary production monitoring, target topology probing, and
 *   target-membership discovery.
 */

#include <cstdlib>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_a() };
	int writer_hostgroup { 2010 };
	int reader_hostgroup { 2011 };
	int green_writer_hostgroup { 2012 };
	int green_reader_hostgroup { 2013 };
};

/** @brief Verify AVAILABLE discovery and its production/topology probe policy. */
int test_available_topology(Context& context, TestState& state) {
	if (publish_available(context, state.deployment) != EXIT_SUCCESS
		|| configure(
			context, state.deployment, state.writer_hostgroup, state.reader_hostgroup,
			state.green_writer_hostgroup, state.green_reader_hostgroup) != EXIT_SUCCESS) {
		diag("Error: failed to publish or configure the smoke deployment");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS
		&& ordinary_probe_reached(context, 0, state.deployment),
		"AVAILABLE topology publishes AVAILABLE and keeps ordinary production probing active");

	auto [probe_rc, probe] = aurora_bgd_wait_for_topology_probe(
		context.simulator, 0, state.deployment.target.backends(),
		BGD_Probe_Kind::metadata, kProbeTimeoutMs);
	(void)probe;
	ok(probe_rc == EXIT_SUCCESS,
		"AVAILABLE discovery moves topology probing to a target member");
	return EXIT_SUCCESS;
}

/** @brief Verify AVAILABLE discovery probes the target membership set. */
int test_target_membership(Context& context, TestState& state) {
	ok(membership_probe_reached(context, 0, state.deployment),
		"AVAILABLE discovery probes the target replica set");
	return EXIT_SUCCESS;
}

int main() {
	plan(3);

	CommandLine cl {};
	Context context {};
	if (setup(cl, context) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};
	if (test_available_topology(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_target_membership(context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the Aurora BGD smoke fixture");
	}
	return exit_status();
}
