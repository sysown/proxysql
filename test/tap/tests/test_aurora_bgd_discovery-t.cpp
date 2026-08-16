/**
 * @file test_aurora_bgd_discovery-t.cpp
 * @brief Aurora BGD AVAILABLE discovery, three probes, and fail-closed mapping.
 *
 * Steps:
 *
 * 1. Publish a complete SOURCE/TARGET deployment and verify AVAILABLE discovery.
 * 2. Verify topology and target-membership probes move to the selected target.
 * 3. Publish incomplete and inconsistent membership and retain the last complete map.
 * 4. Publish invalid topology rows and retain the last valid runtime state.
 * 5. Verify automatic discovery accepts a writer-only deployment.
 * 6. Verify topology and membership probes inherit TLS from the Aurora row.
 */

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "aurora_bgd_tap.h"
#include "command_line.h"
#include "utils.h"

using namespace std;

const uint32_t kWaitSeconds = 5;
const uint32_t kProbeTimeoutMs = 5000;

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_a() };
	int writer_hostgroup { 1510 };
	int reader_hostgroup { 1511 };
	int green_writer_hostgroup { 1512 };
	int green_reader_hostgroup { 1513 };
	Aurora_BGD_Test_Deployment writer_only { aurora_bgd_deployment_b_writer_only() };
	int writer_only_writer_hostgroup { 1520 };
	int writer_only_reader_hostgroup { 1521 };
	int tls_writer_hostgroup { 1525 };
	int tls_reader_hostgroup { 1526 };
	int tls_green_writer_hostgroup { 1527 };
	int tls_green_reader_hostgroup { 1528 };
};

int setup(CommandLine& cl, MYSQL*& admin, BGD_Simulator& sim) {
	if (cl.getEnv()) {
		diag("Error: failed to load TAP environment");
		return EXIT_FAILURE;
	}
	admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (admin == nullptr) {
		diag("Error: failed to connect to ProxySQL Admin");
		return EXIT_FAILURE;
	}
	char simulator_username[] = "aurora1";
	char simulator_password[] = "pass1"; // NOSONAR: fixed simulator fixture credential.
	if (sim.connect(cl.host, 3306, simulator_username, simulator_password) != EXIT_SUCCESS) {
		diag("Error: failed to connect to the shared AWS simulator");
		mysql_close(admin);
		admin = nullptr;
		return EXIT_FAILURE;
	}
	if (aurora_bgd_admin_cleanup(admin) != EXIT_SUCCESS || sim.cleanup() != EXIT_SUCCESS) {
		diag("Error: failed to clear prior Aurora BGD state");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int cleanup(MYSQL* admin, BGD_Simulator& sim) {
	int admin_rc = aurora_bgd_admin_cleanup(admin);
	int simulator_rc = sim.cleanup();
	if (admin) {
		mysql_close(admin);
	}
	return admin_rc == EXIT_SUCCESS && simulator_rc == EXIT_SUCCESS
		? EXIT_SUCCESS : EXIT_FAILURE;
}

int reset_scenario(MYSQL* admin, BGD_Simulator& sim) {
	return aurora_bgd_admin_cleanup(admin) == EXIT_SUCCESS
		&& sim.cleanup() == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

bool runtime_status_is(MYSQL* admin, int writer_hg, const string& status) {
	auto [rc, rows] = mysql_query_ext_rows(
		admin,
		"SELECT bgd_status FROM runtime_mysql_aws_aurora_hostgroups WHERE writer_hostgroup=" +
			to_string(writer_hg));
	return rc == EXIT_SUCCESS && rows.size() == 1 && rows.front().size() == 1
		&& rows.front().front() == status;
}

bool runtime_production_unchanged(MYSQL* admin, int writer_hg, int reader_hg, size_t members) {
	auto [rc, rows] = mysql_query_ext_rows(
		admin,
		"SELECT hostname FROM runtime_mysql_servers WHERE hostgroup_id IN (" +
			to_string(writer_hg) + "," + to_string(reader_hg) + ")");
	return rc == EXIT_SUCCESS && rows.size() == members;
}

bool retain_complete_target_after_membership(
	BGD_Simulator& sim,
	Aurora_BGD_Test_Deployment& deployment,
	const vector<Aurora_Replica_Row>& rows
) {
	auto [seq_rc, sequence] = sim.replica_probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS || sim.replica_update(
		deployment.target_replica_set, rows, deployment.target.backends()) != EXIT_SUCCESS) {
		return false;
	}

	vector<Endpoint> target_members;
	for (Aurora_BGD_Member& member : deployment.target.members) {
		target_members.push_back(member.endpoint.backend());
	}
	auto [first_rc, first_probe] = aurora_bgd_wait_for_replica_probe(
		sim, sequence, target_members, Aurora_Replica_Probe_Kind::bgd_membership,
		kProbeTimeoutMs, deployment.target_replica_set);
	if (first_rc != EXIT_SUCCESS) {
		return false;
	}
	auto [next_rc, next_probe] = aurora_bgd_wait_for_replica_probe(
		sim, first_probe.sequence_id, target_members,
		Aurora_Replica_Probe_Kind::bgd_membership,
		kProbeTimeoutMs, deployment.target_replica_set);
	return next_rc == EXIT_SUCCESS;
}

bool invalid_topology_retains_available(
	MYSQL* admin,
	BGD_Simulator& sim,
	Aurora_BGD_Test_Deployment& deployment,
	const vector<BGD_Topology_Row>& rows,
	int writer_hg
) {
	auto [seq_rc, sequence] = sim.probe_log_last_sequence();
	vector<Endpoint> target_members;
	for (Aurora_BGD_Member& member : deployment.target.members) {
		target_members.push_back(member.endpoint.backend());
	}
	if (seq_rc != EXIT_SUCCESS || sim.topology_update(
		aurora_bgd_topology_backends(deployment), rows) != EXIT_SUCCESS) {
		return false;
	}
	auto [probe_rc, probe] = aurora_bgd_wait_for_topology_probe(
		sim, sequence, target_members, BGD_Probe_Kind::metadata, kProbeTimeoutMs);
	return probe_rc == EXIT_SUCCESS && runtime_status_is(admin, writer_hg, "AVAILABLE");
}

/**
 * Discover a complete Aurora blue/green deployment.
 *
 * - Publish complete production and target membership.
 * - Verify the worker reaches AVAILABLE without interrupting ordinary Aurora probes.
 * - Verify topology discovery, target bootstrap, and steady probes use the expected endpoints.
 */
int test_available_discovery(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	Aurora_BGD_Test_Deployment& deployment = state.deployment;
	if (aurora_bgd_publish(sim, deployment) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.writer_hostgroup, state.reader_hostgroup,
			state.green_writer_hostgroup, state.green_reader_hostgroup, false) != EXIT_SUCCESS) {
		diag("Error: failed to publish or configure deployment A");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"valid SOURCE/TARGET topology publishes AVAILABLE");

	auto [logs_rc, logs] = sim.replica_probe_log_since(0);
	bool ordinary_seen = false;
	for (const Aurora_Replica_Probe_Log& log : logs) {
		if (log.probe_kind == Aurora_Replica_Probe_Kind::ordinary
			&& log.replica_set_id == deployment.blue_replica_set) {
			ordinary_seen = true;
		}
	}
	ok(logs_rc == EXIT_SUCCESS && ordinary_seen,
		"the existing worker continues ordinary Aurora probing in AVAILABLE");

	vector<Endpoint> blue_backends = deployment.production.backends();
	auto [topology_rc, topology_probe] = aurora_bgd_wait_for_topology_probe(
		sim, 0, blue_backends, BGD_Probe_Kind::metadata, kProbeTimeoutMs);
	ok(topology_rc == EXIT_SUCCESS,
		"topology discovery starts on a reachable production member");

	auto [bootstrap_rc, bootstrap_probe] = sim.wait_for_replica_probe_log(
		0, deployment.target_cluster_endpoint.backend(),
		Aurora_Replica_Probe_Kind::bgd_membership, kProbeTimeoutMs,
		0, deployment.target_replica_set);
	ok(bootstrap_rc == EXIT_SUCCESS,
		"TARGET cluster endpoint bootstraps target membership");

	vector<Endpoint> target_backends;
	for (Aurora_BGD_Member& member : deployment.target.members) {
		target_backends.push_back(member.endpoint.backend());
	}
	auto [target_topology_rc, target_topology_probe] = aurora_bgd_wait_for_topology_probe(
		sim, 0, target_backends, BGD_Probe_Kind::metadata, kProbeTimeoutMs);
	ok(target_topology_rc == EXIT_SUCCESS,
		"complete membership moves topology probes to target members");

	auto [target_membership_rc, target_membership_probe] = aurora_bgd_wait_for_replica_probe(
		sim, 0, target_backends, Aurora_Replica_Probe_Kind::bgd_membership,
		kProbeTimeoutMs, deployment.target_replica_set);
	ok(target_membership_rc == EXIT_SUCCESS,
		"complete membership moves membership probes to target members");
	return EXIT_SUCCESS;
}

/**
 * Retain the last complete target membership after unusable observations.
 *
 * - Publish incomplete, ambiguous, unresolved, and mismatched target snapshots.
 * - Ignore stale non-current rows.
 * - Verify the worker continues probing the last complete target selection.
 */
int test_target_membership_validation(BGD_Simulator& sim, TestState& state) {
	Aurora_BGD_Test_Deployment& deployment = state.deployment;
	vector<Aurora_Replica_Row> complete_rows = deployment.target.replica_rows();
	vector<Aurora_Replica_Row> incomplete_rows { complete_rows[0], complete_rows[1] };
	ok(retain_complete_target_after_membership(sim, deployment, incomplete_rows),
		"an incomplete target result retains the previous complete target selection");

	ok(retain_complete_target_after_membership(sim, deployment, {}),
		"an empty target result retains the previous complete target selection");

	vector<Aurora_Replica_Row> duplicate_writer_rows = complete_rows;
	duplicate_writer_rows[1].session_id = "MASTER_SESSION_ID";
	ok(retain_complete_target_after_membership(sim, deployment, duplicate_writer_rows),
		"multiple current target writers retain the previous complete snapshot");

	vector<Aurora_Replica_Row> unresolved_rows = complete_rows;
	unresolved_rows[2].server_id = "aurora-a-reader-2-green-missing";
	ok(retain_complete_target_after_membership(sim, deployment, unresolved_rows),
		"an unresolved target member retains the previous complete snapshot");

	vector<Aurora_Replica_Row> mismatched_session_rows = complete_rows;
	mismatched_session_rows[1].session_id = "reader-a-1-replaced";
	ok(retain_complete_target_after_membership(sim, deployment, mismatched_session_rows),
		"a reader SESSION_ID mismatch retains the previous complete snapshot");

	vector<Aurora_Replica_Row> stale_extra_rows = complete_rows;
	Aurora_Replica_Row stale_writer = complete_rows.front();
	stale_writer.server_id = "unrelated-stale-writer";
	stale_writer.is_current = false;
	stale_extra_rows.push_back(stale_writer);
	ok(retain_complete_target_after_membership(sim, deployment, stale_extra_rows),
		"IS_CURRENT=0 rows are excluded from the complete target snapshot");

	int restore_rc = sim.replica_update(
		deployment.target_replica_set, complete_rows, deployment.target.backends());
	if (restore_rc != EXIT_SUCCESS) {
		diag("Error: failed to restore complete target membership");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * Reject incomplete or unsupported topology observations.
 *
 * - Publish missing identity, SOURCE-only, mismatched-status, and unknown-status rows.
 * - Verify the last AVAILABLE state and production routing remain unchanged.
 */
int test_topology_validation(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	Aurora_BGD_Test_Deployment& deployment = state.deployment;
	vector<BGD_Topology_Row> valid_topology = aurora_bgd_available_topology(deployment);

	vector<BGD_Topology_Row> missing_identity = valid_topology;
	missing_identity[1].id.clear();
	ok(invalid_topology_retains_available(
		admin, sim, deployment, missing_identity, state.writer_hostgroup),
		"missing TARGET identity does not replace AVAILABLE");

	vector<BGD_Topology_Row> source_only { valid_topology.front() };
	ok(invalid_topology_retains_available(
		admin, sim, deployment, source_only, state.writer_hostgroup),
		"SOURCE-only topology does not replace AVAILABLE");

	vector<BGD_Topology_Row> target_only { valid_topology.back() };
	ok(invalid_topology_retains_available(
		admin, sim, deployment, target_only, state.writer_hostgroup),
		"TARGET-only topology is accepted only for SWITCHOVER_COMPLETED");

	vector<BGD_Topology_Row> duplicate_source = valid_topology;
	duplicate_source.push_back(valid_topology.front());
	ok(invalid_topology_retains_available(
		admin, sim, deployment, duplicate_source, state.writer_hostgroup),
		"duplicate SOURCE rows do not replace AVAILABLE");

	vector<BGD_Topology_Row> extra_role = valid_topology;
	BGD_Topology_Row observer = valid_topology.front();
	observer.role = "BLUE_GREEN_DEPLOYMENT_OBSERVER";
	extra_role.push_back(observer);
	ok(invalid_topology_retains_available(
		admin, sim, deployment, extra_role, state.writer_hostgroup),
		"an extra unsupported role does not replace AVAILABLE");

	vector<BGD_Topology_Row> invalid_port = valid_topology;
	invalid_port[1].port = 0;
	ok(invalid_topology_retains_available(
		admin, sim, deployment, invalid_port, state.writer_hostgroup),
		"a TARGET row with an invalid port does not replace AVAILABLE");

	vector<BGD_Topology_Row> empty_endpoint = valid_topology;
	empty_endpoint[1].endpoint.clear();
	ok(invalid_topology_retains_available(
		admin, sim, deployment, empty_endpoint, state.writer_hostgroup),
		"a TARGET row with an empty endpoint does not replace AVAILABLE");

	vector<BGD_Topology_Row> mismatched_status = valid_topology;
	mismatched_status[0].status = "SWITCHOVER_INITIATED";
	ok(invalid_topology_retains_available(
		admin, sim, deployment, mismatched_status, state.writer_hostgroup),
		"mismatched SOURCE/TARGET statuses do not replace AVAILABLE");

	vector<BGD_Topology_Row> unknown_status = valid_topology;
	unknown_status[0].status = "UNSUPPORTED_STATUS";
	unknown_status[1].status = "UNSUPPORTED_STATUS";
	ok(invalid_topology_retains_available(
		admin, sim, deployment, unknown_status, state.writer_hostgroup),
		"unsupported topology status is not copied into runtime state");

	ok(runtime_production_unchanged(
		admin, state.writer_hostgroup, state.reader_hostgroup,
		deployment.production.members.size()),
		"AVAILABLE discovery performs no production routing action");
	return EXIT_SUCCESS;
}

/** Configure SSL-enabled Aurora rows and verify both BGD probe types use TLS. */
int test_tls_probe_policy(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before the TLS scenario");
		return EXIT_FAILURE;
	}

	Aurora_BGD_Test_Deployment& deployment = state.writer_only;
	if (aurora_bgd_publish(sim, deployment) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.tls_writer_hostgroup, state.tls_reader_hostgroup,
			state.tls_green_writer_hostgroup, state.tls_green_reader_hostgroup,
			false, 100, false, true) != EXIT_SUCCESS) {
		diag("Error: failed to configure the TLS probe scenario");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.tls_writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"SSL-enabled Aurora rows reach AVAILABLE");

	auto [topology_rc, topology_probe] = sim.wait_for_probe_log(
		0, deployment.production.members.front().endpoint.backend(),
		BGD_Probe_Kind::metadata, kProbeTimeoutMs, 1);
	ok(topology_rc == EXIT_SUCCESS,
		"topology discovery uses TLS when the Aurora row enables SSL");

	vector<Endpoint> target_backends = deployment.target.backends();
	auto [membership_rc, membership_probe] = aurora_bgd_wait_for_replica_probe(
		sim, 0, target_backends, Aurora_Replica_Probe_Kind::bgd_membership,
		kProbeTimeoutMs, deployment.target_replica_set);
	ok(membership_rc == EXIT_SUCCESS && membership_probe.encrypted,
		"target-membership discovery uses TLS when the Aurora row enables SSL");
	return EXIT_SUCCESS;
}

/**
 * Discover a writer-only deployment without configured green hostgroups.
 *
 * - Reset the complete-cluster scenario.
 * - Configure automatic discovery with writer-only production and target membership.
 * - Verify the worker admits AVAILABLE and accepts the target snapshot.
 */
int test_writer_only_discovery(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset state before writer-only deployment");
		return EXIT_FAILURE;
	}

	Aurora_BGD_Test_Deployment& deployment = state.writer_only;
	if (aurora_bgd_publish(sim, deployment) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.writer_only_writer_hostgroup,
			state.writer_only_reader_hostgroup, -1, -1, true) != EXIT_SUCCESS) {
		diag("Error: failed to publish or configure writer-only deployment");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.writer_only_writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"auto-discovery admits a row without configured green hostgroups");

	vector<Endpoint> writer_target { deployment.target.members.front().endpoint.backend() };
	auto [probe_rc, probe] = aurora_bgd_wait_for_replica_probe(
		sim, 0, writer_target, Aurora_Replica_Probe_Kind::bgd_membership,
		kProbeTimeoutMs, deployment.target_replica_set);
	ok(probe_rc == EXIT_SUCCESS,
		"a writer-only production cluster accepts a writer-only target snapshot");
	return EXIT_SUCCESS;
}

int main() {
	plan(27);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};
	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: publish complete production and target membership.
	// ProxySQL: configure explicit Aurora BGD hostgroups 1510-1513.
	// Verify: discovery reaches AVAILABLE and hands probes to the selected target.
	if (test_available_discovery(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: replace complete target membership with unusable observations.
	// Verify: the worker retains its last complete target mapping.
	if (test_target_membership_validation(sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish incomplete and unsupported topology rows.
	// Verify: runtime state and production routing retain the last valid observation.
	if (test_topology_validation(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: configure automatic discovery for a writer-only deployment.
	// Verify: writer-only source and target snapshots are accepted.
	if (test_writer_only_discovery(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: configure SSL-enabled Aurora rows.
	// Verify: topology and target-membership probes both use TLS.
	if (test_tls_probe_policy(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean Aurora BGD discovery state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
