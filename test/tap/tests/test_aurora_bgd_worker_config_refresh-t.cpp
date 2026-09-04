/**
 * @file test_aurora_bgd_worker_config_refresh-t.cpp
 * @brief Aurora BGD active-worker refresh without FSM reset.
 *
 * @details Enters POST_PROCESSING, changes the explicit green hostgroups, and
 *   verifies the existing worker retains its deployment phase and traffic pins
 *   while applying the refreshed configuration in place.
 */

#include <cstdlib>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_b_writer_only() };
	int writer_hostgroup { 2200 };
	int reader_hostgroup { 2201 };
	int green_writer_hostgroup { 2202 };
	int green_reader_hostgroup { 2203 };
	int refreshed_green_writer_hostgroup { 2204 };
	int refreshed_green_reader_hostgroup { 2205 };
	int route_hostgroup { 2206 };
};

/** @brief Verify an active worker refreshes configuration without resetting its FSM. */
int test_active_worker_refresh(
	CommandLine& cl, Context& context, TestState& state
) {
	if (publish_available(context, state.deployment) != EXIT_SUCCESS
		|| configure(
			context, state.deployment, state.writer_hostgroup, state.reader_hostgroup,
			state.green_writer_hostgroup, state.green_reader_hostgroup,
			false, 300) != EXIT_SUCCESS
		|| add_route(
			context.admin, state.route_hostgroup,
			state.deployment.production.members.front().endpoint.hostname) != EXIT_SUCCESS) {
		diag("Error: failed to configure the worker-refresh fixture");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"worker-refresh scenario starts from AVAILABLE");

	if (publish_status(
			context, state.deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "SWITCHOVER_IN_POST_PROCESSING",
			kWaitSeconds) != EXIT_SUCCESS
		|| set_default_hostgroup(
			context.admin, state.route_hostgroup) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(route_to_backend(
		cl, context, state.deployment.target.members.front().endpoint.backend()),
		"POST_PROCESSING pins writer traffic before refresh");

	if (aurora_bgd_execute_all(context.admin, {
		"UPDATE mysql_servers SET weight=7,comment='Aurora BGD refreshed route' "
			"WHERE hostgroup_id=2206",
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.writer_hostgroup, "SWITCHOVER_IN_POST_PROCESSING",
		kWaitSeconds) == EXIT_SUCCESS
		&& route_to_backend(
			cl, context, state.deployment.target.members.front().endpoint.backend()),
		"an unrelated server reload preserves active state and the target pin");

	if (aurora_bgd_execute_all(context.admin, {
		"UPDATE mysql_aws_aurora_hostgroups SET green_writer_hostgroup=2204,"
			"green_reader_hostgroup=2205 WHERE writer_hostgroup=2200",
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	ok(wait_for_cond(
		context.admin,
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_aurora_hostgroups "
		"WHERE writer_hostgroup=2200 AND green_writer_hostgroup=2204 "
		"AND green_reader_hostgroup=2205 "
		"AND bgd_status='SWITCHOVER_IN_POST_PROCESSING'",
		kWaitSeconds) == EXIT_SUCCESS
		&& route_to_backend(
			cl, context, state.deployment.target.members.front().endpoint.backend()),
		"green-hostgroup refresh preserves cached membership, active state, and the target pin");
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
	test_active_worker_refresh(cl, context, state);

	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the worker-refresh fixture");
	}
	return exit_status();
}
