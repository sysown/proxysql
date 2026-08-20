/**
 * @file test_aurora_bgd_disable_during_switchover-t.cpp
 * @brief Aurora BGD cleanup when the owning row is deactivated.
 *
 * @details Moves one deployment from AVAILABLE to IN_PROGRESS, deactivates
 *   its Aurora row, and verifies worker cleanup restores the source writer and
 *   removes the runtime deployment state.
 */

#include <cstdlib>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_b_writer_only() };
	int writer_hostgroup { 2220 };
	int reader_hostgroup { 2221 };
	int green_writer_hostgroup { 2222 };
	int green_reader_hostgroup { 2223 };
};

/** @brief Establish the deployment's AVAILABLE baseline. */
int test_bgd_status_available(Context& context, TestState& state) {
	if (publish_available(context, state.deployment) != EXIT_SUCCESS
		|| configure(
			context, state.deployment, state.writer_hostgroup, state.reader_hostgroup,
			state.green_writer_hostgroup, state.green_reader_hostgroup) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"BGD status for wHG 2220 reports AVAILABLE");
	return EXIT_SUCCESS;
}

/** @brief Enter IN_PROGRESS and verify source-writer demotion. */
int test_writer_switchover_in_progress(Context& context, TestState& state) {
	if (publish_status(
			context, state.deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "SWITCHOVER_IN_PROGRESS",
		kWaitSeconds) == EXIT_SUCCESS,
		"BGD status for wHG 2220 reports SWITCHOVER_IN_PROGRESS");
	ok(writer_placement(
		context.admin, state.writer_hostgroup, state.reader_hostgroup,
		state.deployment.production.members.front().endpoint.hostname, true),
		"SWITCHOVER_IN_PROGRESS demotes the source writer for wHG 2220");
	return EXIT_SUCCESS;
}

/** @brief Deactivate the row and verify the worker reverses its routing effect. */
int test_disable_during_switchover(Context& context, TestState& state) {
	if (aurora_bgd_execute_all(context.admin, {
		"UPDATE mysql_aws_aurora_hostgroups SET active=0 WHERE writer_hostgroup=2220",
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(writer_placement(
		context.admin, state.writer_hostgroup, state.reader_hostgroup,
		state.deployment.production.members.front().endpoint.hostname, false)
		&& wait_for_cond(
			context.admin,
			"SELECT COUNT(*)=1 FROM runtime_mysql_aws_aurora_hostgroups "
			"WHERE writer_hostgroup=2220 AND active=0 AND bgd_status='NONE'",
			kWaitSeconds) == EXIT_SUCCESS,
		"setting active=0 restores the source writer and publishes inactive NONE");
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
	if (test_bgd_status_available(context, state) != EXIT_SUCCESS
		|| test_writer_switchover_in_progress(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_disable_during_switchover(context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the disable-during-switchover fixture");
	}
	return exit_status();
}
