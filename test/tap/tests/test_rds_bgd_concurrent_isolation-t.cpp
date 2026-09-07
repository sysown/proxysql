/**
 * @file test_rds_bgd_concurrent_isolation-t.cpp
 * @brief Isolating three concurrent BGD workers in hostgroups 1410-1433.
 *
 * Steps:
 *
 * 1. Configure three BGD rows with separate hostgroups, topology, and green
 *    metadata targets.
 * 2. Move each worker to a different writer-switchover phase and verify that
 *    the other two workers keep their status and blue-writer placement.
 * 3. Replace only cluster 1 green membership with a TLS-enabled deployment.
 * 4. Verify that cluster 1 uses the new target while clusters 2 and 3 keep
 *    their own phases, placement, metadata targets, and TLS values.
 */

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "command_line.h"
#include "rds_bgd_tap.h"
#include "utils.h"

const uint32_t kTimeoutSeconds = 3;
const uint32_t kProbeTimeoutMs = 3000;
const uint32_t kNegativeProbeTimeoutMs = 500;

struct TestState {
	RDS_BGD_Cluster cluster_1 { bgd_cluster_init() };
	RDS_BGD_Cluster cluster_1_b { bgd_cluster_1_deployment_b_init() };
	RDS_BGD_Cluster cluster_2 { bgd_cluster_2_init() };
	RDS_BGD_Cluster cluster_3 { bgd_cluster_3_init() };
	BGD_Hostgroups cluster_1_hg { 1410, 1411, 1412, 1413 };
	BGD_Hostgroups cluster_2_hg { 1420, 1421, 1422, 1423 };
	BGD_Hostgroups cluster_3_hg { 1430, 1431, 1432, 1433 };
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

	if (sim.connect(cl.host, 3306, cl.username, cl.password) != EXIT_SUCCESS) {
		diag("Error: failed to connect to the SQLite3-server simulator");
		mysql_close(admin);
		admin = nullptr;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int cleanup(MYSQL* admin, BGD_Simulator& sim) {
	int admin_rc = bgd_admin_cleanup(admin);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to clean ProxySQL BGD test state");
	}
	mysql_close(admin);

	int simulator_rc = sim.cleanup();
	if (simulator_rc != EXIT_SUCCESS) {
		diag("Error: failed to clean SQLite3-server simulator state");
	}

	if (admin_rc != EXIT_SUCCESS || simulator_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

vector<BGD_Topology_Row> topology_with_reader_pair(RDS_BGD_Cluster& cluster, string status) {
	vector<BGD_Topology_Row> rows = cluster.get_topology(status);
	rows.push_back({
		cluster.blue_readers[0].hostname,
		cluster.blue_readers[0].hostname,
		cluster.blue_readers[0].port,
		"BLUE_GREEN_DEPLOYMENT_SOURCE",
		status,
	});
	rows.push_back({
		cluster.green_readers[0].hostname,
		cluster.green_readers[0].hostname,
		cluster.green_readers[0].port,
		"BLUE_GREEN_DEPLOYMENT_TARGET",
		status,
	});
	return rows;
}

int configure_read_only_values(BGD_Simulator& sim, RDS_BGD_Cluster& cluster) {
	if (bgd_set_host_read_only_0(sim, cluster.blue_writer) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	if (bgd_set_host_read_only_0(sim, cluster.green_writer) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	if (bgd_set_host_read_only_1(sim, cluster.blue_readers[0]) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	if (bgd_set_host_read_only_1(sim, cluster.green_readers[0]) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int configure_available(
	MYSQL* admin, BGD_Simulator& sim, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg, int green_use_ssl)
{
	if (configure_read_only_values(sim, cluster) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<BGD_Topology_Row> topology = topology_with_reader_pair(cluster, "AVAILABLE");
	if (sim.topology_update(cluster.get_endpoints(), topology) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0] };
	int admin_rc = bgd_admin_setup(
		admin, cluster, hg, BGD_Admin_Mode::explicit_configuration,
		blue_servers, green_servers, 0, green_use_ssl
	);
	if (admin_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	return status_rc;
}

bool worker_matches(MYSQL* admin, BGD_Hostgroups& hg, RDS_BGD_Cluster& cluster, string status, bool demoted) {
	string writer_count = demoted ? "0" : "1";
	string reader_count = demoted ? "1" : "0";
	string query = "SELECT "
		"(SELECT COUNT(*) FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(hg.blue_writer) + " AND status=" + bgd_sql_quote(status) + ")=1 AND "
		"(SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hg.blue_writer) +
		" AND hostname=" + bgd_sql_quote(cluster.blue_writer.hostname) + " AND port=3306)=" + writer_count + " AND "
		"(SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hg.blue_reader) +
		" AND hostname=" + bgd_sql_quote(cluster.blue_writer.hostname) + " AND port=3306)=" + reader_count;

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool matches = rows[0][0] == "1";
	return matches;
}

bool runtime_green_membership_matches(
	MYSQL* admin, BGD_Hostgroups& hg, RDS_BGD_Cluster& present, RDS_BGD_Cluster& absent)
{
	string query = "SELECT "
		"(SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hg.green_writer) +
		" AND hostname=" + bgd_sql_quote(present.green_writer.hostname) + " AND port=3306 AND use_ssl=1)=1 AND "
		"(SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hg.green_reader) +
		" AND hostname=" + bgd_sql_quote(present.green_readers[0].hostname) + " AND port=3306 AND use_ssl=1)=1 AND "
		"(SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hg.green_writer) +
		" AND hostname=" + bgd_sql_quote(absent.green_writer.hostname) + " AND port=3306)=0 AND "
		"(SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hg.green_reader) +
		" AND hostname=" + bgd_sql_quote(absent.green_readers[0].hostname) + " AND port=3306)=0";

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool matches = rows[0][0] == "1";
	return matches;
}

int replace_cluster_1_green_membership(MYSQL* admin, TestState& state) {
	RDS_BGD_Cluster& old_deployment = state.cluster_1;
	RDS_BGD_Cluster& new_deployment = state.cluster_1_b;
	BGD_Hostgroups& hg = state.cluster_1_hg;

	vector<string> delete_queries {
		"DELETE FROM mysql_servers WHERE hostgroup_id=" + to_string(hg.green_writer) +
			" AND hostname=" + bgd_sql_quote(old_deployment.green_writer.hostname) + " AND port=3306",
		"DELETE FROM mysql_servers WHERE hostgroup_id=" + to_string(hg.green_reader) +
			" AND hostname=" + bgd_sql_quote(old_deployment.green_readers[0].hostname) + " AND port=3306",
	};
	if (execute_all(admin, delete_queries) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> green_servers { new_deployment.green_writer, new_deployment.green_readers[0] };
	if (bgd_admin_add_servers(admin, new_deployment, hg, green_servers, true, 1) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<string> load_queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int rc = execute_all(admin, load_queries);
	return rc;
}

/**
 * Start three BGD workers in AVAILABLE.
 *
 * - Configure hostgroups 1410-1413, 1420-1423, and 1430-1433.
 * - Use plaintext green metadata for clusters 1 and 3 and TLS for cluster 2.
 * - Verify that each BGD row reaches AVAILABLE through its own green writer.
 */
int test_three_workers_available(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before starting three BGD workers");
		return EXIT_FAILURE;
	}

	int cluster_1_rc = configure_available(admin, sim, state.cluster_1, state.cluster_1_hg, 0);
	if (cluster_1_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure AVAILABLE for BGD wHG 1410");
		return EXIT_FAILURE;
	}

	int cluster_2_rc = configure_available(admin, sim, state.cluster_2, state.cluster_2_hg, 1);
	if (cluster_2_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure AVAILABLE for BGD wHG 1420");
		return EXIT_FAILURE;
	}

	int cluster_3_rc = configure_available(admin, sim, state.cluster_3, state.cluster_3_hg, 0);
	if (cluster_3_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure AVAILABLE for BGD wHG 1430");
		return EXIT_FAILURE;
	}

	auto [cluster_1_probe_rc, cluster_1_probe] = sim.wait_for_probe_log(
		seq, state.cluster_1.green_writer.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0
	);
	if (cluster_1_probe_rc != EXIT_SUCCESS) {
		diag("Error: BGD wHG 1410 did not probe its plaintext green writer");
		return EXIT_FAILURE;
	}
	ok(true, "BGD wHG 1410 reports AVAILABLE from its own plaintext green writer");

	auto [cluster_2_probe_rc, cluster_2_probe] = sim.wait_for_probe_log(
		seq, state.cluster_2.green_writer.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, 1
	);
	if (cluster_2_probe_rc != EXIT_SUCCESS) {
		diag("Error: BGD wHG 1420 did not probe its TLS green writer");
		return EXIT_FAILURE;
	}
	ok(true, "BGD wHG 1420 reports AVAILABLE from its own TLS green writer");

	auto [cluster_3_probe_rc, cluster_3_probe] = sim.wait_for_probe_log(
		seq, state.cluster_3.green_writer.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0
	);
	if (cluster_3_probe_rc != EXIT_SUCCESS) {
		diag("Error: BGD wHG 1430 did not probe its plaintext green writer");
		return EXIT_FAILURE;
	}
	ok(true, "BGD wHG 1430 reports AVAILABLE from its own plaintext green writer");
	return EXIT_SUCCESS;
}

/**
 * Move each BGD worker to a different writer-switchover phase.
 *
 * - Move wHG 1410 to WRITER_SWITCHOVER_IN_PROGRESS.
 * - Move wHG 1420 to WRITER_SWITCHOVER_POST_PROCESSING.
 * - Move wHG 1430 to WRITER_SWITCHOVER_INITIATED.
 * - After each change, verify that the other two statuses and blue-writer
 *   placements remain unchanged.
 */
int test_independent_phase_changes(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	vector<BGD_Topology_Row> cluster_1_topology =
		topology_with_reader_pair(state.cluster_1, "SWITCHOVER_IN_PROGRESS");
	if (sim.topology_update(state.cluster_1.get_endpoints(), cluster_1_topology) != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_PROGRESS for BGD wHG 1410");
		return EXIT_FAILURE;
	}

	int cluster_1_status_rc =
		bgd_wait_for_status(admin, state.cluster_1_hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (cluster_1_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1410 did not reach WRITER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	int cluster_1_placement_rc = bgd_wait_for_server_placement(
		admin, state.cluster_1_hg.blue_writer, state.cluster_1_hg.blue_reader,
		state.cluster_1.blue_writer, true, kTimeoutSeconds
	);
	if (cluster_1_placement_rc != EXIT_SUCCESS) {
		diag("Error: BGD wHG 1410 did not move its blue writer to reader hostgroup 1411");
		return EXIT_FAILURE;
	}
	ok(true, "advancing wHG 1410 moves only its blue writer from hostgroup 1410 to 1411");

	bool cluster_2_available = worker_matches(admin, state.cluster_2_hg, state.cluster_2, "AVAILABLE", false);
	bool cluster_3_available = worker_matches(admin, state.cluster_3_hg, state.cluster_3, "AVAILABLE", false);
	ok(cluster_2_available && cluster_3_available,
		"advancing wHG 1410 leaves wHG 1420 and wHG 1430 in AVAILABLE with unchanged blue placement");

	vector<BGD_Topology_Row> cluster_2_topology =
		topology_with_reader_pair(state.cluster_2, "SWITCHOVER_IN_POST_PROCESSING");
	if (sim.topology_update(state.cluster_2.get_endpoints(), cluster_2_topology) != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_POST_PROCESSING for BGD wHG 1420");
		return EXIT_FAILURE;
	}

	int cluster_2_status_rc =
		bgd_wait_for_status(admin, state.cluster_2_hg, "WRITER_SWITCHOVER_POST_PROCESSING", kTimeoutSeconds);
	if (cluster_2_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1420 did not reach WRITER_SWITCHOVER_POST_PROCESSING");
		return EXIT_FAILURE;
	}

	int cluster_2_placement_rc = bgd_wait_for_server_placement(
		admin, state.cluster_2_hg.blue_writer, state.cluster_2_hg.blue_reader,
		state.cluster_2.blue_writer, false, kTimeoutSeconds
	);
	if (cluster_2_placement_rc != EXIT_SUCCESS) {
		diag("Error: BGD wHG 1420 did not retain its blue writer in hostgroup 1420");
		return EXIT_FAILURE;
	}
	ok(true, "advancing wHG 1420 applies post-processing only to its blue writer");

	bool cluster_1_in_progress =
		worker_matches(admin, state.cluster_1_hg, state.cluster_1, "WRITER_SWITCHOVER_IN_PROGRESS", true);
	bool cluster_3_still_available = worker_matches(admin, state.cluster_3_hg, state.cluster_3, "AVAILABLE", false);
	ok(cluster_1_in_progress && cluster_3_still_available,
		"advancing wHG 1420 preserves wHG 1410 progress and wHG 1430 availability");

	vector<BGD_Topology_Row> cluster_3_topology =
		topology_with_reader_pair(state.cluster_3, "SWITCHOVER_INITIATED");
	if (sim.topology_update(state.cluster_3.get_endpoints(), cluster_3_topology) != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_INITIATED for BGD wHG 1430");
		return EXIT_FAILURE;
	}

	int cluster_3_status_rc =
		bgd_wait_for_status(admin, state.cluster_3_hg, "WRITER_SWITCHOVER_INITIATED", kTimeoutSeconds);
	if (cluster_3_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1430 did not reach WRITER_SWITCHOVER_INITIATED");
		return EXIT_FAILURE;
	}

	int cluster_3_placement_rc = bgd_wait_for_server_placement(
		admin, state.cluster_3_hg.blue_writer, state.cluster_3_hg.blue_reader,
		state.cluster_3.blue_writer, false, kTimeoutSeconds
	);
	if (cluster_3_placement_rc != EXIT_SUCCESS) {
		diag("Error: BGD wHG 1430 did not retain its blue writer in hostgroup 1430");
		return EXIT_FAILURE;
	}
	ok(true, "advancing wHG 1430 records INITIATED without changing its blue writer placement");

	bool cluster_1_still_in_progress =
		worker_matches(admin, state.cluster_1_hg, state.cluster_1, "WRITER_SWITCHOVER_IN_PROGRESS", true);
	bool cluster_2_post = worker_matches(
		admin, state.cluster_2_hg, state.cluster_2, "WRITER_SWITCHOVER_POST_PROCESSING", false
	);
	ok(cluster_1_still_in_progress && cluster_2_post,
		"advancing wHG 1430 preserves wHG 1410 progress and wHG 1420 post-processing");
	return EXIT_SUCCESS;
}

/**
 * Refresh only cluster 1 green membership.
 *
 * - Replace cluster 1 green rows with TLS-enabled deployment B rows.
 * - Keep wHG 1410 in WRITER_SWITCHOVER_IN_PROGRESS.
 * - Verify that cluster 1 stops probing its removed target while clusters 2
 *   and 3 keep their status, placement, metadata target, and TLS value.
 */
int test_independent_config_refresh(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	if (configure_read_only_values(sim, state.cluster_1_b) != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated read_only values for cluster 1 deployment B");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before refreshing BGD wHG 1410");
		return EXIT_FAILURE;
	}

	int replace_rc = replace_cluster_1_green_membership(admin, state);
	if (replace_rc != EXIT_SUCCESS) {
		diag("Error: failed to replace green membership for BGD wHG 1410");
		return EXIT_FAILURE;
	}

	vector<BGD_Topology_Row> topology =
		topology_with_reader_pair(state.cluster_1_b, "SWITCHOVER_IN_PROGRESS");
	if (sim.topology_update(state.cluster_1_b.get_endpoints(), topology) != EXIT_SUCCESS) {
		diag("Error: failed to publish deployment B topology for BGD wHG 1410");
		return EXIT_FAILURE;
	}

	auto [cluster_1_probe_rc, cluster_1_probe] = sim.wait_for_probe_log(
		seq, state.cluster_1_b.green_writer.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, 1
	);
	if (cluster_1_probe_rc != EXIT_SUCCESS) {
		diag("Error: refreshed BGD wHG 1410 did not probe its TLS deployment B green writer");
		return EXIT_FAILURE;
	}

	int stale_probe_rc = bgd_expect_no_metadata_probe(
		sim, cluster_1_probe.sequence_id, state.cluster_1.green_writer.endpoint(), kNegativeProbeTimeoutMs
	);
	if (stale_probe_rc != EXIT_SUCCESS) {
		diag("Error: refreshed BGD wHG 1410 continued probing its removed green writer");
		return EXIT_FAILURE;
	}

	auto [cluster_2_probe_rc, cluster_2_probe] = sim.wait_for_probe_log(
		cluster_1_probe.sequence_id, state.cluster_2.green_writer.endpoint(),
		BGD_Probe_Kind::metadata, kProbeTimeoutMs, 1
	);
	if (cluster_2_probe_rc != EXIT_SUCCESS) {
		diag("Error: BGD wHG 1420 did not continue probing its TLS green writer");
		return EXIT_FAILURE;
	}

	auto [cluster_3_probe_rc, cluster_3_probe] = sim.wait_for_probe_log(
		cluster_1_probe.sequence_id, state.cluster_3.green_writer.endpoint(),
		BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0
	);
	if (cluster_3_probe_rc != EXIT_SUCCESS) {
		diag("Error: BGD wHG 1430 did not continue probing its plaintext green writer");
		return EXIT_FAILURE;
	}

	bool cluster_1_membership =
		runtime_green_membership_matches(admin, state.cluster_1_hg, state.cluster_1_b, state.cluster_1);
	bool cluster_1_phase =
		worker_matches(admin, state.cluster_1_hg, state.cluster_1_b, "WRITER_SWITCHOVER_IN_PROGRESS", true);
	bool cluster_2_phase =
		worker_matches(admin, state.cluster_2_hg, state.cluster_2, "WRITER_SWITCHOVER_POST_PROCESSING", false);
	bool cluster_3_phase =
		worker_matches(admin, state.cluster_3_hg, state.cluster_3, "WRITER_SWITCHOVER_INITIATED", false);
	ok(cluster_1_membership && cluster_1_phase && cluster_2_phase && cluster_3_phase,
		"refreshing wHG 1410 changes only its target while wHG 1420 and wHG 1430 keep their phases and probes");
	return EXIT_SUCCESS;
}

int main() {
	plan(10);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: publish separate AVAILABLE topology for clusters 1, 2, and 3.
	// ProxySQL: configure BGD wHGs 1410, 1420, and 1430 with distinct green targets and TLS values.
	// Verify: each BGD row reports AVAILABLE through its own configured green writer.
	if (test_three_workers_available(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish SWITCHOVER_IN_PROGRESS for wHG 1410, SWITCHOVER_IN_POST_PROCESSING for wHG 1420,
	// and SWITCHOVER_INITIATED for wHG 1430.
	// Verify: each BGD status and blue-writer placement changes without affecting the other two workers.
	if (test_independent_phase_changes(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: keep cluster 1 in progress with deployment B topology.
	// ProxySQL: replace only wHG 1410 green membership with TLS-enabled deployment B rows.
	// Verify: wHG 1410 uses the new target while wHGs 1420 and 1430 keep their phases, targets, and TLS.
	if (test_independent_config_refresh(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
