/**
 * @file test_aurora_bgd_concurrent_isolation-t.cpp
 * @brief Independent Aurora BGD state for three writer hostgroups.
 */

#include <cstdlib>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct Worker {
	Aurora_BGD_Test_Deployment deployment;
	int writer_hostgroup;
	int reader_hostgroup;
	int green_writer_hostgroup;
	int green_reader_hostgroup;
	int route_hostgroup;
};

struct TestState {
	Worker first { aurora_bgd_deployment_a(), 2250, 2251, 2252, 2253, 2254 };
	Worker second { aurora_bgd_deployment_b_writer_only(), 2260, 2261, 2262, 2263, 2264 };
	Worker third { aurora_bgd_deployment_c_writer_only(), 2270, 2271, 2272, 2273, 2274 };
};

int configure_available(Context& context, Worker& worker, bool use_ssl) {
	return publish_available(context, worker.deployment) == EXIT_SUCCESS
		&& configure(
			context, worker.deployment, worker.writer_hostgroup,
			worker.reader_hostgroup, worker.green_writer_hostgroup,
			worker.green_reader_hostgroup, false, 300, false, use_ssl) == EXIT_SUCCESS
		&& add_route(
			context.admin, worker.route_hostgroup,
			worker.deployment.production.members.front().endpoint.hostname) == EXIT_SUCCESS
		? EXIT_SUCCESS : EXIT_FAILURE;
}

bool worker_matches(
	Context& context, Worker& worker, const string& status, bool demoted
) {
	return runtime_status_is(context.admin, worker.writer_hostgroup, status)
		&& writer_placement(
			context.admin, worker.writer_hostgroup, worker.reader_hostgroup,
			worker.deployment.production.members.front().endpoint.hostname, demoted);
}

int test_three_workers_available(Context& context, TestState& state) {
	if (configure_available(context, state.first, false) != EXIT_SUCCESS
		|| configure_available(context, state.second, true) != EXIT_SUCCESS
		|| configure_available(context, state.third, false) != EXIT_SUCCESS) {
		diag("Error: failed to configure three Aurora BGD workers");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.first.writer_hostgroup, "AVAILABLE", kWaitSeconds)
		== EXIT_SUCCESS,
		"BGD wHG 2250 independently reaches AVAILABLE");
	ok(aurora_bgd_wait_for_status(
		context.admin, state.second.writer_hostgroup, "AVAILABLE", kWaitSeconds)
		== EXIT_SUCCESS,
		"BGD wHG 2260 independently reaches AVAILABLE");
	ok(aurora_bgd_wait_for_status(
		context.admin, state.third.writer_hostgroup, "AVAILABLE", kWaitSeconds)
		== EXIT_SUCCESS,
		"BGD wHG 2270 independently reaches AVAILABLE");
	return EXIT_SUCCESS;
}

int test_independent_phase_changes(
	CommandLine& cl, Context& context, TestState& state
) {
	if (publish_status(
			context, state.first.deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.first.writer_hostgroup, "SWITCHOVER_IN_PROGRESS",
			kWaitSeconds) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(worker_matches(context, state.first, "SWITCHOVER_IN_PROGRESS", true),
		"advancing wHG 2250 changes only its writer placement and state");
	ok(worker_matches(context, state.second, "AVAILABLE", false)
		&& worker_matches(context, state.third, "AVAILABLE", false),
		"advancing wHG 2250 leaves wHG 2260 and wHG 2270 unchanged");

	if (publish_status(
			context, state.second.deployment,
			"SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.second.writer_hostgroup,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) != EXIT_SUCCESS
		|| set_default_hostgroup(
			context.admin, state.second.route_hostgroup) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(route_to_backend(
		cl, context,
		state.second.deployment.target.members.front().endpoint.backend()),
		"advancing wHG 2260 applies only its own target pin");
	ok(worker_matches(context, state.first, "SWITCHOVER_IN_PROGRESS", true)
		&& worker_matches(context, state.third, "AVAILABLE", false),
		"advancing wHG 2260 preserves wHG 2250 progress and wHG 2270 availability");

	if (publish_status(
			context, state.third.deployment, "SWITCHOVER_INITIATED") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.third.writer_hostgroup, "SWITCHOVER_INITIATED",
			kWaitSeconds) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(worker_matches(context, state.third, "SWITCHOVER_INITIATED", false),
		"advancing wHG 2270 records INITIATED without changing writer placement");
	ok(worker_matches(context, state.first, "SWITCHOVER_IN_PROGRESS", true)
		&& worker_matches(
			context, state.second, "SWITCHOVER_IN_POST_PROCESSING", false),
		"advancing wHG 2270 preserves the independent states of wHG 2250 and wHG 2260");
	return EXIT_SUCCESS;
}

int main() {
	plan(9);

	CommandLine cl {};
	Context context {};
	if (setup(cl, context) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};
	if (test_three_workers_available(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_independent_phase_changes(cl, context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the concurrent-isolation fixture");
	}
	return exit_status();
}
