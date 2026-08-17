/**
 * @file test_aurora_bgd_probe_tls-t.cpp
 * @brief Aurora BGD topology and target-membership probe TLS policy.
 */

#include <cstdlib>

#include "aurora_bgd_scenario_tap.h"

using namespace aurora_bgd_scenario;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_b_writer_only() };
	int writer_hostgroup { 2030 };
	int reader_hostgroup { 2031 };
	int green_writer_hostgroup { 2032 };
	int green_reader_hostgroup { 2033 };
};

int test_tls_probe_policy(Context& context, TestState& state) {
	if (publish_available(context, state.deployment) != EXIT_SUCCESS
		|| configure(
			context, state.deployment, state.writer_hostgroup, state.reader_hostgroup,
			state.green_writer_hostgroup, state.green_reader_hostgroup,
			false, 100, false, true) != EXIT_SUCCESS) {
		diag("Error: failed to configure the TLS probe case");
		return EXIT_FAILURE;
	}

	auto [topology_rc, topology_probe] = context.simulator.wait_for_probe_log(
		0, state.deployment.production.members.front().endpoint.backend(),
		BGD_Probe_Kind::metadata, kProbeTimeoutMs, 1);
	(void)topology_probe;
	ok(topology_rc == EXIT_SUCCESS,
		"TLS Aurora rows use TLS topology probes");

	ok(membership_probe_reached(context, 0, state.deployment, 1),
		"TLS Aurora rows use TLS target-membership probes");
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
	test_tls_probe_policy(context, state);

exit_cleanup:
	if (cleanup(context) != EXIT_SUCCESS) {
		diag("Error: failed to clean the probe-TLS fixture");
	}
	return exit_status();
}
