/**
 * @file test_aurora_bgd_reader_policy-t.cpp
 * @brief Aurora BGD mapped-reader eligibility and routing.
 *
 * @details Publishes a complete target membership, enters POST_PROCESSING,
 *   and verifies each configured production reader remains eligible while its
 *   hostname routes to the matched target reader.
 */

#include <cstdlib>
#include <vector>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_a() };
	int writer_hostgroup { 2050 };
	int reader_hostgroup { 2051 };
	int green_writer_hostgroup { 2052 };
	int green_reader_hostgroup { 2053 };
	vector<int> reader_routes { 2054, 2055 };
};

/** @brief Verify mapped readers stay ONLINE and route to their target counterparts. */
int test_mapped_readers(CommandLine& cl, Context& context, TestState& state) {
	if (publish_available(context, state.deployment) != EXIT_SUCCESS
		|| configure(
			context, state.deployment, state.writer_hostgroup, state.reader_hostgroup,
			state.green_writer_hostgroup, state.green_reader_hostgroup) != EXIT_SUCCESS
		|| add_route(
			context.admin, state.reader_routes[0],
			state.deployment.production.members[1].endpoint.hostname) != EXIT_SUCCESS
		|| add_route(
			context.admin, state.reader_routes[1],
			state.deployment.production.members[2].endpoint.hostname) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) != EXIT_SUCCESS
		|| publish_status(
			context, state.deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			context.admin, state.writer_hostgroup, "SWITCHOVER_IN_POST_PROCESSING",
			kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: failed to prepare the mapped-reader policy case");
		return EXIT_FAILURE;
	}

	ok(server_count(
		context.admin, "runtime_mysql_servers", state.reader_hostgroup,
		state.deployment.production.members[1].endpoint.hostname, 1, "ONLINE")
		&& server_count(
			context.admin, "runtime_mysql_servers", state.reader_hostgroup,
			state.deployment.production.members[2].endpoint.hostname, 1, "ONLINE"),
		"POST_PROCESSING keeps mapped source readers ONLINE in hostgroup 2051");

	bool routed = true;
	for (size_t i = 0; i < state.reader_routes.size(); ++i) {
		routed = routed
			&& set_default_hostgroup(context.admin, state.reader_routes[i]) == EXIT_SUCCESS
			&& route_to_backend(
				cl, context, state.deployment.target.members[i + 1].endpoint.backend());
	}
	ok(routed,
		"POST_PROCESSING routes each reader hostname to its mapped target reader");
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
	test_mapped_readers(cl, context, state);

	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the reader-policy fixture");
	}
	return exit_status();
}
