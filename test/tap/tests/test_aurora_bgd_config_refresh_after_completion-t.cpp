/**
 * @file test_aurora_bgd_config_refresh_after_completion-t.cpp
 * @brief Aurora BGD configuration refresh while completion is latched.
 */

#include <cstdlib>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_b_writer_only() };
	int writer_hostgroup { 2210 };
	int reader_hostgroup { 2211 };
};

int test_completed_latch(Context& context, TestState& state) {
	if (publish_available(context, state.deployment) != EXIT_SUCCESS
		|| configure(
				context, state.deployment, state.writer_hostgroup, state.reader_hostgroup,
				-1, -1, true, 300) != EXIT_SUCCESS
			|| aurora_bgd_wait_for_status(
				context.admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) != EXIT_SUCCESS
			|| publish_status(
				context, state.deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
			|| aurora_bgd_wait_for_status(
				context.admin, state.writer_hostgroup, "SWITCHOVER_IN_PROGRESS",
				kWaitSeconds) != EXIT_SUCCESS
			|| wait_for_writer_placement(
				context.admin, state.writer_hostgroup, state.reader_hostgroup,
				state.deployment.production.members.front().endpoint.hostname,
				true) != EXIT_SUCCESS
			|| publish_completed(context, state.deployment, state.deployment) != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "SWITCHOVER_COMPLETED",
		kWaitSeconds) == EXIT_SUCCESS
		&& writer_placement(
			context.admin, state.writer_hostgroup, state.reader_hostgroup,
			state.deployment.production.members.front().endpoint.hostname, false),
		"completion from IN_PROGRESS restores the writer and enters the terminal latch");
	return EXIT_SUCCESS;
}

int test_config_refresh_after_completion(Context& context, TestState& state) {
	if (aurora_bgd_execute_all(context.admin, {
		"UPDATE mysql_aws_aurora_hostgroups SET check_timeout_ms=950 "
			"WHERE writer_hostgroup=2210",
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(wait_for_cond(
		context.admin,
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_aurora_hostgroups "
		"WHERE writer_hostgroup=2210 AND check_timeout_ms=950 "
		"AND bgd_status='SWITCHOVER_COMPLETED'",
		kWaitSeconds) == EXIT_SUCCESS,
		"configuration refresh preserves the completed latch for wHG 2210");

	if (context.simulator.topology_delete(
		aurora_bgd_topology_backends(state.deployment)) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "NONE", kWaitSeconds) == EXIT_SUCCESS,
		"empty topology rearms the refreshed terminal worker to NONE");
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
	if (test_completed_latch(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_config_refresh_after_completion(context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the completion-refresh fixture");
	}
	return exit_status();
}
