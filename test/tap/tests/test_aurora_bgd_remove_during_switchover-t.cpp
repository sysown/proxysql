/**
 * @file test_aurora_bgd_remove_during_switchover-t.cpp
 * @brief Aurora BGD cleanup when the owning row is deleted.
 *
 * @details Moves one deployment from AVAILABLE to IN_PROGRESS, deletes its
 *   Aurora configuration row, and verifies worker removal restores the source
 *   writer and removes runtime deployment state.
 */

#include <cstdlib>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_b_writer_only() };
	int writer_hostgroup { 2230 };
	int reader_hostgroup { 2231 };
	int green_writer_hostgroup { 2232 };
	int green_reader_hostgroup { 2233 };
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
		"BGD status for wHG 2230 reports AVAILABLE");
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
		"BGD status for wHG 2230 reports SWITCHOVER_IN_PROGRESS");
	ok(writer_placement(
		context.admin, state.writer_hostgroup, state.reader_hostgroup,
		state.deployment.production.members.front().endpoint.hostname, true),
		"SWITCHOVER_IN_PROGRESS demotes the source writer for wHG 2230");
	return EXIT_SUCCESS;
}

/** @brief Delete the owning row and verify worker teardown reverses routing effects. */
int test_remove_during_switchover(Context& context, TestState& state) {
	if (aurora_bgd_execute_all(context.admin, {
		"DELETE FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=2230",
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(writer_placement(
		context.admin, state.writer_hostgroup, state.reader_hostgroup,
		state.deployment.production.members.front().endpoint.hostname, false),
		"deleting BGD configuration restores the source writer to hostgroup 2230");
	ok(wait_for_cond(
		context.admin,
		"SELECT COUNT(*)=0 FROM runtime_mysql_aws_aurora_hostgroups "
		"WHERE writer_hostgroup=2230",
		kWaitSeconds) == EXIT_SUCCESS,
		"deleting wHG 2230 removes it from runtime_mysql_aws_aurora_hostgroups");
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
	if (test_bgd_status_available(context, state) != EXIT_SUCCESS
		|| test_writer_switchover_in_progress(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_remove_during_switchover(context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the remove-during-switchover fixture");
	}
	return exit_status();
}
