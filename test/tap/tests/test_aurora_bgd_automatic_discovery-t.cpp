/**
 * @file test_aurora_bgd_automatic_discovery-t.cpp
 * @brief Aurora BGD runtime derivation for NULL green hostgroups.
 */

#include <cstdlib>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment first { aurora_bgd_deployment_b_writer_only() };
	int first_writer_hostgroup { 2020 };
	int first_reader_hostgroup { 2021 };
	Aurora_BGD_Test_Deployment second { aurora_bgd_deployment_c_writer_only() };
	int second_writer_hostgroup { 2024 };
	int second_reader_hostgroup { 2025 };
};

bool runtime_row_stays_null(
	Context& context, int writer_hostgroup, int reader_hostgroup,
	const string& status
) {
	return scalar_is(
		context.admin,
		"SELECT COUNT(*) FROM runtime_mysql_aws_aurora_hostgroups WHERE writer_hostgroup=" +
		to_string(writer_hostgroup) + " AND reader_hostgroup=" + to_string(reader_hostgroup) +
		" AND green_writer_hostgroup IS NULL AND green_reader_hostgroup IS NULL "
		"AND bgd_status=" + aurora_bgd_sql_quote(status),
		"1");
}

bool persistent_row_stays_null(Context& context, int writer_hostgroup) {
	return scalar_is(
		context.admin,
		"SELECT COUNT(*) FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=" +
		to_string(writer_hostgroup) + " "
		"AND green_writer_hostgroup IS NULL AND green_reader_hostgroup IS NULL",
		"1");
}

int test_null_green_hostgroups(Context& context, TestState& state) {
	if (publish_available(context, state.first) != EXIT_SUCCESS
		|| configure(
			context, state.first, state.first_writer_hostgroup, state.first_reader_hostgroup,
			-1, -1, true) != EXIT_SUCCESS) {
		diag("Error: failed to configure NULL green hostgroups");
		return EXIT_FAILURE;
	}

	ok(wait_for_cond(
		context.admin,
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_aurora_hostgroups "
		"WHERE writer_hostgroup=2020 AND bgd_status='AVAILABLE'",
		kWaitSeconds) == EXIT_SUCCESS
		&& runtime_row_stays_null(context, 2020, 2021, "AVAILABLE"),
		"AVAILABLE admits BGD discovery while runtime green hostgroups remain NULL");
	ok(persistent_row_stays_null(context, 2020),
		"discovery keeps the user-created green hostgroups NULL");
	return EXIT_SUCCESS;
}

int test_absent_then_available(Context& context, TestState& state) {
	if (context.simulator.replica_update(
			state.second.production.replica_set_id,
			state.second.production.replica_rows(),
			state.second.production.backends()) != EXIT_SUCCESS
		|| context.simulator.replica_update(
			state.second.target.replica_set_id,
			state.second.target.replica_rows(),
			state.second.target.backends()) != EXIT_SUCCESS
		|| context.simulator.topology_update(
			aurora_bgd_topology_backends(state.second), {}) != EXIT_SUCCESS
		|| configure(
			context, state.second, state.second_writer_hostgroup, state.second_reader_hostgroup,
			-1, -1, true) != EXIT_SUCCESS) {
		diag("Error: failed to configure the absent-topology discovery case");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		context.admin, state.second_writer_hostgroup, "NONE", kWaitSeconds) == EXIT_SUCCESS
		&& persistent_row_stays_null(context, state.second_writer_hostgroup),
		"absent topology keeps one user-created row in NONE without persisting derived hostgroups");

	if (context.simulator.topology_update(
		aurora_bgd_topology_backends(state.second),
		aurora_bgd_available_topology(state.second)) != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology");
		return EXIT_FAILURE;
	}
	ok(aurora_bgd_wait_for_status(
		context.admin, state.second_writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS
		&& runtime_row_stays_null(context, 2024, 2025, "AVAILABLE")
		&& membership_probe_reached(context, 0, state.second),
		"AVAILABLE later discovers an internal target map without generating green hostgroups");
	return EXIT_SUCCESS;
}

int test_repeated_discovery(Context& context, TestState& state) {
	usleep(300000);
	ok(runtime_row_stays_null(context, 2024, 2025, "AVAILABLE")
		&& scalar_is(
			context.admin,
			"SELECT COUNT(*) FROM runtime_mysql_aws_aurora_hostgroups "
			"WHERE writer_hostgroup=2024",
			"1"),
		"repeated AVAILABLE polling keeps one runtime row with NULL green hostgroups");
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
	if (test_null_green_hostgroups(context, state) != EXIT_SUCCESS
		|| test_absent_then_available(context, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}
	test_repeated_discovery(context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the automatic-discovery fixture");
	}
	return exit_status();
}
