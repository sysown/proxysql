/**
 * @file test_aurora_bgd_discovery-t.cpp
 * @brief Aurora BGD AVAILABLE discovery, three probes, and fail-closed mapping.
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
	char simulator_password[] = "pass1";
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

int main() {
	plan(18);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};
	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	const int writer_hg = 1510;
	const int reader_hg = 1511;
	Aurora_BGD_Test_Deployment deployment = aurora_bgd_deployment_a();
	if (aurora_bgd_publish(sim, deployment) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(admin, deployment, writer_hg, reader_hg, 1512, 1513, false)
			!= EXIT_SUCCESS) {
		diag("Error: failed to publish or configure deployment A");
		cleanup(admin, sim);
		return exit_status();
	}

	ok(aurora_bgd_wait_for_status(admin, writer_hg, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"valid SOURCE/TARGET topology publishes AVAILABLE");

	{
		auto [rc, logs] = sim.replica_probe_log_since(0);
		bool ordinary_seen = false;
		for (const Aurora_Replica_Probe_Log& log : logs) {
			if (log.probe_kind == Aurora_Replica_Probe_Kind::ordinary
				&& log.replica_set_id == deployment.blue_replica_set) {
				ordinary_seen = true;
			}
		}
		ok(rc == EXIT_SUCCESS && ordinary_seen,
			"the existing worker continues ordinary Aurora probing in AVAILABLE");
	}

	vector<Endpoint> blue_backends = deployment.production.backends();
	{
		auto [rc, probe] = aurora_bgd_wait_for_topology_probe(
			sim, 0, blue_backends, BGD_Probe_Kind::metadata, kProbeTimeoutMs);
		ok(rc == EXIT_SUCCESS, "topology discovery starts on a reachable production member");
	}
	{
		auto [rc, probe] = sim.wait_for_replica_probe_log(
			0, deployment.target_cluster_endpoint.backend(),
			Aurora_Replica_Probe_Kind::bgd_membership, kProbeTimeoutMs,
			0, deployment.target_replica_set);
		ok(rc == EXIT_SUCCESS, "TARGET cluster endpoint bootstraps target membership");
	}

	vector<Endpoint> target_backends;
	for (Aurora_BGD_Member& member : deployment.target.members) {
		target_backends.push_back(member.endpoint.backend());
	}
	{
		auto [rc, probe] = aurora_bgd_wait_for_topology_probe(
			sim, 0, target_backends, BGD_Probe_Kind::metadata, kProbeTimeoutMs);
		ok(rc == EXIT_SUCCESS, "complete membership moves topology probes to target members");
	}
	{
		auto [rc, probe] = aurora_bgd_wait_for_replica_probe(
			sim, 0, target_backends, Aurora_Replica_Probe_Kind::bgd_membership,
			kProbeTimeoutMs, deployment.target_replica_set);
		ok(rc == EXIT_SUCCESS, "complete membership moves membership probes to target members");
	}

	vector<Aurora_Replica_Row> complete_rows = deployment.target.replica_rows();
	vector<Aurora_Replica_Row> incomplete_rows {complete_rows[0], complete_rows[1]};
	ok(retain_complete_target_after_membership(sim, deployment, incomplete_rows),
		"an incomplete target result retains the previous complete target selection");

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

	if (sim.replica_update(
		deployment.target_replica_set, complete_rows, deployment.target.backends()) != EXIT_SUCCESS) {
		diag("Error: failed to restore complete target membership");
		cleanup(admin, sim);
		return exit_status();
	}

	vector<BGD_Topology_Row> valid_topology = aurora_bgd_available_topology(deployment);
	vector<BGD_Topology_Row> missing_identity = valid_topology;
	missing_identity[1].id.clear();
	ok(invalid_topology_retains_available(admin, sim, deployment, missing_identity, writer_hg),
		"missing TARGET identity does not replace AVAILABLE");

	vector<BGD_Topology_Row> source_only {valid_topology.front()};
	ok(invalid_topology_retains_available(admin, sim, deployment, source_only, writer_hg),
		"SOURCE-only topology does not replace AVAILABLE");

	vector<BGD_Topology_Row> mismatched_status = valid_topology;
	mismatched_status[0].status = "SWITCHOVER_INITIATED";
	ok(invalid_topology_retains_available(admin, sim, deployment, mismatched_status, writer_hg),
		"mismatched SOURCE/TARGET statuses do not replace AVAILABLE");

	vector<BGD_Topology_Row> unknown_status = valid_topology;
	unknown_status[0].status = "UNSUPPORTED_STATUS";
	unknown_status[1].status = "UNSUPPORTED_STATUS";
	ok(invalid_topology_retains_available(admin, sim, deployment, unknown_status, writer_hg),
		"unsupported topology status is not copied into runtime state");

	ok(runtime_production_unchanged(admin, writer_hg, reader_hg, deployment.production.members.size()),
		"AVAILABLE discovery performs no production routing action");

	if (aurora_bgd_admin_cleanup(admin) != EXIT_SUCCESS || sim.cleanup() != EXIT_SUCCESS) {
		diag("Error: failed to reset state before writer-only deployment");
		cleanup(admin, sim);
		return exit_status();
	}

	Aurora_BGD_Test_Deployment writer_only = aurora_bgd_deployment_b_writer_only();
	if (aurora_bgd_publish(sim, writer_only) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(admin, writer_only, 1520, 1521, -1, -1, true)
			!= EXIT_SUCCESS) {
		diag("Error: failed to publish or configure writer-only deployment");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(aurora_bgd_wait_for_status(admin, 1520, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"auto-discovery admits a row without configured green hostgroups");
	{
		vector<Endpoint> writer_target {
			writer_only.target.members.front().endpoint.backend()
		};
		auto [rc, probe] = aurora_bgd_wait_for_replica_probe(
			sim, 0, writer_target, Aurora_Replica_Probe_Kind::bgd_membership,
			kProbeTimeoutMs, writer_only.target_replica_set);
		ok(rc == EXIT_SUCCESS, "a writer-only production cluster accepts a writer-only target snapshot");
	}

	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean Aurora BGD discovery state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
