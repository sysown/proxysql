/**
 * @file test_rds_bgd_topology_empty_absent-t.cpp
 * @brief Empty and absent BGD topology before and after writer completion.
 *
 * Steps:
 *
 * 1. Delete topology rows during WRITER_SWITCHOVER_IN_PROGRESS and verify
 *    rollback through a successful metadata probe.
 * 2. Drop the topology table during WRITER_SWITCHOVER_IN_PROGRESS and verify
 *    rollback followed by a blue-writer table check.
 * 3. Delete topology rows during READER_SWITCHOVER_IN_PROGRESS and verify
 *    reader cleanup through a successful metadata probe.
 * 4. Drop the topology table during READER_SWITCHOVER_IN_PROGRESS and verify
 *    reader cleanup followed by a blue-writer table check.
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

struct TestState {
	RDS_BGD_Cluster empty_before { bgd_cluster_init() };
	BGD_Hostgroups empty_before_hg { 1100, 1101, 1102, 1103 };
	vector<Endpoint> empty_before_endpoints { empty_before.get_endpoints() };

	RDS_BGD_Cluster absent_before { bgd_cluster_2_init() };
	BGD_Hostgroups absent_before_hg { 1110, 1111, 1112, 1113 };
	vector<Endpoint> absent_before_endpoints { absent_before.get_endpoints() };

	RDS_BGD_Cluster empty_reader { bgd_cluster_3_init() };
	BGD_Hostgroups empty_reader_hg { 1120, 1121, 1122, 1123 };
	vector<Endpoint> empty_reader_endpoints { empty_reader.get_endpoints() };

	RDS_BGD_Cluster absent_reader { bgd_cluster_1_deployment_b_init() };
	BGD_Hostgroups absent_reader_hg { 1130, 1131, 1132, 1133 };
	vector<Endpoint> absent_reader_endpoints { absent_reader.get_endpoints() };
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

vector<BGD_Topology_Row> target_only_completed(RDS_BGD_Cluster& cluster) {
	vector<BGD_Topology_Row> rows {{
		cluster.green_writer.hostname,
		cluster.green_writer.hostname,
		cluster.green_writer.port,
		"BLUE_GREEN_DEPLOYMENT_TARGET",
		"SWITCHOVER_COMPLETED",
	}};
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

	if (bgd_set_host_read_only_1(sim, cluster.blue_readers[1]) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	if (bgd_set_host_read_only_1(sim, cluster.green_readers[0]) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

bool runtime_server_online(MYSQL* admin, int hostgroup, RDS_BGD_Host& host) {
	string query =
		"SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hostgroup) +
		" AND hostname=" + bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port) +
		" AND status='ONLINE'";

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool online = rows[0][0] == "1";
	return online;
}

int configure_bgd(MYSQL* admin, BGD_Simulator& sim, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg) {
	int read_only_rc = configure_read_only_values(sim, cluster);
	if (read_only_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated read_only values for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0] };
	int admin_rc = bgd_admin_setup(
		admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers, 0, 0
	);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int publish_topology(BGD_Simulator& sim, vector<Endpoint> endpoints, RDS_BGD_Cluster& cluster, string status) {
	vector<BGD_Topology_Row> topology = topology_with_reader_pair(cluster, status);

	int rc = sim.topology_update(endpoints, topology);
	return rc;
}

int enter_writer_switchover(MYSQL* admin, BGD_Simulator& sim, RDS_BGD_Cluster& cluster,
	BGD_Hostgroups& hg, vector<Endpoint> endpoints)
{
	int config_rc = configure_bgd(admin, sim, cluster, hg);
	if (config_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	int available_rc = publish_topology(sim, endpoints, cluster, "AVAILABLE");
	if (available_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}

	int available_status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (available_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG %d did not reach AVAILABLE", hg.blue_writer);
		return EXIT_FAILURE;
	}

	int progress_rc = publish_topology(sim, endpoints, cluster, "SWITCHOVER_IN_PROGRESS");
	if (progress_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_PROGRESS topology for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}

	int progress_status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (progress_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG %d did not reach WRITER_SWITCHOVER_IN_PROGRESS", hg.blue_writer);
		return EXIT_FAILURE;
	}

	int placement_rc =
		bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, true, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: blue writer for wHG %d did not move to its reader hostgroup", hg.blue_writer);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int enter_reader_switchover(MYSQL* admin, BGD_Simulator& sim, RDS_BGD_Cluster& cluster,
	BGD_Hostgroups& hg, vector<Endpoint> endpoints)
{
	int progress_rc = enter_writer_switchover(admin, sim, cluster, hg, endpoints);
	if (progress_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	int post_rc = publish_topology(sim, endpoints, cluster, "SWITCHOVER_IN_POST_PROCESSING");
	if (post_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_POST_PROCESSING topology for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}

	int post_status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_POST_PROCESSING", kTimeoutSeconds);
	if (post_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG %d did not reach WRITER_SWITCHOVER_POST_PROCESSING", hg.blue_writer);
		return EXIT_FAILURE;
	}

	int placement_rc =
		bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: blue writer for wHG %d did not return to its writer hostgroup", hg.blue_writer);
		return EXIT_FAILURE;
	}

	vector<BGD_Topology_Row> completed = target_only_completed(cluster);
	int completed_rc = sim.topology_update(endpoints, completed);
	if (completed_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish target-only SWITCHOVER_COMPLETED topology for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}

	int reader_status_rc = bgd_wait_for_status(admin, hg, "READER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (reader_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG %d did not reach READER_SWITCHOVER_IN_PROGRESS", hg.blue_writer);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int disable_bgd(MYSQL* admin, BGD_Hostgroups& hg) {
	string query =
		"UPDATE mysql_aws_rds_bgd_hostgroups SET active=0 WHERE writer_hostgroup=" +
		to_string(hg.blue_writer);
	vector<string> queries {
		query,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	return rc;
}

/**
 * Delete topology rows during writer switchover.
 *
 * - Reach WRITER_SWITCHOVER_IN_PROGRESS for wHG 1100.
 * - Delete every topology row while the topology table remains present.
 * - Verify BGD status NONE, restored blue-writer placement, and metadata
 *   telemetry from the pinned green writer.
 */
int test_empty_before_completion(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.empty_before;
	BGD_Hostgroups& hg = state.empty_before_hg;

	int progress_rc = enter_writer_switchover(admin, sim, cluster, hg, state.empty_before_endpoints);
	if (progress_rc != EXIT_SUCCESS) {
		diag("Error: failed to reach writer switchover for wHG 1100");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before empty topology for wHG 1100");
		return EXIT_FAILURE;
	}

	int empty_rc = sim.topology_delete(state.empty_before_endpoints);
	if (empty_rc != EXIT_SUCCESS) {
		diag("Error: failed to delete topology rows for wHG 1100");
		return EXIT_FAILURE;
	}

	int none_rc = bgd_wait_for_status(admin, hg, "NONE", kTimeoutSeconds);
	if (none_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1100 did not reach NONE after empty topology");
		return EXIT_FAILURE;
	}

	int placement_rc =
		bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: empty topology did not restore the blue writer for wHG 1100");
		return EXIT_FAILURE;
	}

	ok(true, "empty topology restores the blue writer and sets BGD status for wHG 1100 to NONE");

	auto [probe_rc, probe] =
		sim.wait_for_probe_log(seq, cluster.green_writer.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: empty topology for wHG 1100 was not observed through green-writer metadata");
		return EXIT_FAILURE;
	}

	ok(true, "empty topology for wHG 1100 is observed through a successful green-writer metadata probe");

	int disable_rc = disable_bgd(admin, hg);
	if (disable_rc != EXIT_SUCCESS) {
		diag("Error: failed to stop wHG 1100 before the next topology scenario");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * Drop the topology table during writer switchover.
 *
 * - Reach WRITER_SWITCHOVER_IN_PROGRESS for wHG 1110.
 * - Drop the topology table on the simulated blue and green endpoints.
 * - Verify BGD status NONE, restored blue-writer placement, and a new
 *   blue-writer table-check probe.
 */
int test_absent_before_completion(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.absent_before;
	BGD_Hostgroups& hg = state.absent_before_hg;

	int progress_rc = enter_writer_switchover(admin, sim, cluster, hg, state.absent_before_endpoints);
	if (progress_rc != EXIT_SUCCESS) {
		diag("Error: failed to reach writer switchover for wHG 1110");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before absent topology for wHG 1110");
		return EXIT_FAILURE;
	}

	int absent_rc = sim.topology_drop(state.absent_before_endpoints);
	if (absent_rc != EXIT_SUCCESS) {
		diag("Error: failed to drop the topology table for wHG 1110");
		return EXIT_FAILURE;
	}

	int none_rc = bgd_wait_for_status(admin, hg, "NONE", kTimeoutSeconds);
	if (none_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1110 did not reach NONE after absent topology");
		return EXIT_FAILURE;
	}

	int placement_rc =
		bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: absent topology did not restore the blue writer for wHG 1110");
		return EXIT_FAILURE;
	}

	ok(true, "absent topology restores the blue writer and sets BGD status for wHG 1110 to NONE");

	auto [probe_rc, probe] =
		sim.wait_for_probe_log(seq, cluster.blue_writer.endpoint(), BGD_Probe_Kind::table_check, kProbeTimeoutMs, 0);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: absent topology for wHG 1110 did not return to blue-writer table checks");
		return EXIT_FAILURE;
	}

	ok(true, "absent topology for wHG 1110 returns probing to the blue-writer table check");

	int disable_rc = disable_bgd(admin, hg);
	if (disable_rc != EXIT_SUCCESS) {
		diag("Error: failed to stop wHG 1110 before the next topology scenario");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * Delete topology rows during reader switchover.
 *
 * - Reach READER_SWITCHOVER_IN_PROGRESS for wHG 1120.
 * - Delete every topology row while the topology table remains present.
 * - Verify BGD status NONE, restored blue-reader routing, retained green
 *   rows, and metadata telemetry from the pinned green writer.
 */
int test_empty_during_reader_switchover(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.empty_reader;
	BGD_Hostgroups& hg = state.empty_reader_hg;

	int reader_rc = enter_reader_switchover(admin, sim, cluster, hg, state.empty_reader_endpoints);
	if (reader_rc != EXIT_SUCCESS) {
		diag("Error: failed to reach reader switchover for wHG 1120");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before empty topology for wHG 1120");
		return EXIT_FAILURE;
	}

	int empty_rc = sim.topology_delete(state.empty_reader_endpoints);
	if (empty_rc != EXIT_SUCCESS) {
		diag("Error: failed to delete topology rows for wHG 1120");
		return EXIT_FAILURE;
	}

	int none_rc = bgd_wait_for_status(admin, hg, "NONE", kTimeoutSeconds);
	if (none_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1120 did not reach NONE after empty topology");
		return EXIT_FAILURE;
	}

	bool blue_reader_online = runtime_server_online(admin, hg.blue_reader, cluster.blue_readers[1]);
	bool green_writer_online = runtime_server_online(admin, hg.green_writer, cluster.green_writer);
	bool green_reader_online = runtime_server_online(admin, hg.green_reader, cluster.green_readers[0]);
	ok(blue_reader_online && green_writer_online && green_reader_online,
		"empty topology completes reader cleanup for wHG 1120 and retains configured green rows");

	auto [probe_rc, probe] =
		sim.wait_for_probe_log(seq, cluster.green_writer.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: empty topology for wHG 1120 was not observed through green-writer metadata");
		return EXIT_FAILURE;
	}

	ok(true, "reader cleanup for wHG 1120 starts from a successful green-writer metadata probe");

	int disable_rc = disable_bgd(admin, hg);
	if (disable_rc != EXIT_SUCCESS) {
		diag("Error: failed to stop wHG 1120 before the next topology scenario");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * Drop the topology table during reader switchover.
 *
 * - Reach READER_SWITCHOVER_IN_PROGRESS for wHG 1130.
 * - Drop the topology table on the simulated blue and green endpoints.
 * - Verify BGD status NONE, restored blue-reader routing, retained green
 *   rows, and a new blue-writer table-check probe.
 */
int test_absent_during_reader_switchover(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.absent_reader;
	BGD_Hostgroups& hg = state.absent_reader_hg;

	int reader_rc = enter_reader_switchover(admin, sim, cluster, hg, state.absent_reader_endpoints);
	if (reader_rc != EXIT_SUCCESS) {
		diag("Error: failed to reach reader switchover for wHG 1130");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before absent topology for wHG 1130");
		return EXIT_FAILURE;
	}

	int absent_rc = sim.topology_drop(state.absent_reader_endpoints);
	if (absent_rc != EXIT_SUCCESS) {
		diag("Error: failed to drop the topology table for wHG 1130");
		return EXIT_FAILURE;
	}

	int none_rc = bgd_wait_for_status(admin, hg, "NONE", kTimeoutSeconds);
	if (none_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1130 did not reach NONE after absent topology");
		return EXIT_FAILURE;
	}

	bool blue_reader_online = runtime_server_online(admin, hg.blue_reader, cluster.blue_readers[1]);
	bool green_writer_online = runtime_server_online(admin, hg.green_writer, cluster.green_writer);
	bool green_reader_online = runtime_server_online(admin, hg.green_reader, cluster.green_readers[0]);
	ok(blue_reader_online && green_writer_online && green_reader_online,
		"absent topology completes reader cleanup for wHG 1130 and retains configured green rows");

	auto [probe_rc, probe] =
		sim.wait_for_probe_log(seq, cluster.blue_writer.endpoint(), BGD_Probe_Kind::table_check, kProbeTimeoutMs, 0);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: absent topology for wHG 1130 did not return to blue-writer table checks");
		return EXIT_FAILURE;
	}

	ok(true, "reader cleanup for wHG 1130 returns probing to the blue-writer table check");
	return EXIT_SUCCESS;
}

int main() {
	plan(8);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: publish SWITCHOVER_IN_PROGRESS, then delete all topology rows.
	// Verify: wHG 1100 reaches NONE, restores its blue writer, and records green-writer metadata.
	if (test_empty_before_completion(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish SWITCHOVER_IN_PROGRESS, then drop the topology table.
	// Verify: wHG 1110 reaches NONE, restores its blue writer, and returns to blue-writer table checks.
	if (test_absent_before_completion(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish target-only SWITCHOVER_COMPLETED, then delete all topology rows.
	// Verify: wHG 1120 completes reader cleanup through successful green-writer metadata.
	if (test_empty_during_reader_switchover(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish target-only SWITCHOVER_COMPLETED, then drop the topology table.
	// Verify: wHG 1130 completes reader cleanup and returns to blue-writer table checks.
	if (test_absent_during_reader_switchover(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
