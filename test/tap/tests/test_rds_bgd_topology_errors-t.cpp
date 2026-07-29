/**
 * @file test_rds_bgd_topology_errors-t.cpp
 * @brief BGD metadata error 1146 and generic metadata-error handling.
 *
 * Steps:
 *
 * 1. Return metadata error 1146 during WRITER_SWITCHOVER_IN_PROGRESS and
 *    verify rollback followed by blue-writer table checks.
 * 2. Return metadata error 1146 during READER_SWITCHOVER_IN_PROGRESS and
 *    verify reader cleanup followed by blue-writer table checks.
 * 3. Return a generic metadata error during WRITER_SWITCHOVER_IN_PROGRESS and
 *    verify that the active status and blue-writer demotion remain unchanged.
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
const uint32_t kNegativeProbeTimeoutMs = 800;

struct TestState {
	RDS_BGD_Cluster before_completion { bgd_cluster_init() };
	BGD_Hostgroups before_completion_hg { 1140, 1141, 1142, 1143 };
	vector<Endpoint> before_completion_endpoints { before_completion.get_endpoints() };

	RDS_BGD_Cluster reader_switchover { bgd_cluster_2_init() };
	BGD_Hostgroups reader_switchover_hg { 1150, 1151, 1152, 1153 };
	vector<Endpoint> reader_switchover_endpoints { reader_switchover.get_endpoints() };

	RDS_BGD_Cluster generic_error { bgd_cluster_3_init() };
	BGD_Hostgroups generic_error_hg { 1160, 1161, 1162, 1163 };
	vector<Endpoint> generic_error_endpoints { generic_error.get_endpoints() };
};

int setup(CommandLine& cl, MYSQL*& admin, RDS_BGD_Simulator& sim) {
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

int cleanup(MYSQL* admin, RDS_BGD_Simulator& sim) {
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

vector<RDS_BGD_Topology_Row> topology_with_reader_pair(RDS_BGD_Cluster& cluster, string status) {
	vector<RDS_BGD_Topology_Row> rows = cluster.get_topology(status);
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

vector<RDS_BGD_Topology_Row> target_only_completed(RDS_BGD_Cluster& cluster) {
	vector<RDS_BGD_Topology_Row> rows {{
		cluster.green_writer.hostname,
		cluster.green_writer.hostname,
		cluster.green_writer.port,
		"BLUE_GREEN_DEPLOYMENT_TARGET",
		"SWITCHOVER_COMPLETED",
	}};
	return rows;
}

int configure_read_only_values(RDS_BGD_Simulator& sim, RDS_BGD_Cluster& cluster) {
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

int configure_bgd(MYSQL* admin, RDS_BGD_Simulator& sim, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg) {
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

int publish_topology(RDS_BGD_Simulator& sim, vector<Endpoint> endpoints, RDS_BGD_Cluster& cluster, string status) {
	vector<RDS_BGD_Topology_Row> topology = topology_with_reader_pair(cluster, status);

	int rc = sim.topology_update(endpoints, topology);
	return rc;
}

int enter_writer_switchover(MYSQL* admin, RDS_BGD_Simulator& sim, RDS_BGD_Cluster& cluster,
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

int enter_reader_switchover(MYSQL* admin, RDS_BGD_Simulator& sim, RDS_BGD_Cluster& cluster,
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

	vector<RDS_BGD_Topology_Row> completed = target_only_completed(cluster);
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

int wait_for_metadata_error(RDS_BGD_Simulator& sim, uint64_t sequence, RDS_BGD_Cluster& cluster,
	int error_number, string error_message, RDS_BGD_Probe_Log& probe)
{
	vector<Endpoint> green_endpoint { cluster.green_writer.endpoint() };
	int error_rc = sim.topology_error(green_endpoint, error_number, error_message);
	if (error_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	auto [probe_rc, metadata_probe] =
		sim.wait_for_probe_log(sequence, cluster.green_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	if (probe_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	probe = metadata_probe;
	return EXIT_SUCCESS;
}

int wait_for_blue_table_check(RDS_BGD_Simulator& sim, uint64_t sequence, RDS_BGD_Cluster& cluster) {
	vector<Endpoint> blue_endpoint { cluster.blue_writer.endpoint() };
	int drop_rc = sim.topology_drop(blue_endpoint);
	if (drop_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	auto [probe_rc, probe] =
		sim.wait_for_probe_log(sequence, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::table_check, kProbeTimeoutMs, 0);
	return probe_rc;
}

/**
 * Return metadata error 1146 before writer completion.
 *
 * - Reach WRITER_SWITCHOVER_IN_PROGRESS for wHG 1140.
 * - Return error 1146 from the pinned green-writer metadata probe.
 * - Verify BGD status NONE, restored blue-writer placement, and a subsequent
 *   blue-writer table check.
 */
int test_error_1146_before_completion(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.before_completion;
	BGD_Hostgroups& hg = state.before_completion_hg;

	int progress_rc = enter_writer_switchover(admin, sim, cluster, hg, state.before_completion_endpoints);
	if (progress_rc != EXIT_SUCCESS) {
		diag("Error: failed to reach writer switchover for wHG 1140");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before metadata error 1146 for wHG 1140");
		return EXIT_FAILURE;
	}

	RDS_BGD_Probe_Log metadata {};
	int metadata_rc =
		wait_for_metadata_error(sim, seq, cluster, 1146, "Table 'mysql.rds_topology' doesn't exist", metadata);
	if (metadata_rc != EXIT_SUCCESS) {
		diag("Error: wHG 1140 did not observe metadata error 1146 on the green writer");
		return EXIT_FAILURE;
	}

	int none_rc = bgd_wait_for_status(admin, hg, "NONE", kTimeoutSeconds);
	if (none_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1140 did not reach NONE after metadata error 1146");
		return EXIT_FAILURE;
	}

	int placement_rc =
		bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: metadata error 1146 did not restore the blue writer for wHG 1140");
		return EXIT_FAILURE;
	}

	ok(true, "metadata error 1146 restores the blue writer and sets BGD status for wHG 1140 to NONE");

	int table_rc = wait_for_blue_table_check(sim, metadata.sequence_id, cluster);
	if (table_rc != EXIT_SUCCESS) {
		diag("Error: wHG 1140 did not return to blue-writer table checks after metadata error 1146");
		return EXIT_FAILURE;
	}

	ok(true, "metadata error 1146 returns wHG 1140 from green metadata to blue-writer table checks");
	return EXIT_SUCCESS;
}

/**
 * Return metadata error 1146 during reader switchover.
 *
 * - Reach READER_SWITCHOVER_IN_PROGRESS for wHG 1150.
 * - Return error 1146 from the pinned green-writer metadata probe.
 * - Verify BGD status NONE, restored blue-reader routing, retained green rows,
 *   and a subsequent blue-writer table check.
 */
int test_error_1146_during_reader_switchover(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.reader_switchover;
	BGD_Hostgroups& hg = state.reader_switchover_hg;

	int reader_rc = enter_reader_switchover(admin, sim, cluster, hg, state.reader_switchover_endpoints);
	if (reader_rc != EXIT_SUCCESS) {
		diag("Error: failed to reach reader switchover for wHG 1150");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before metadata error 1146 for wHG 1150");
		return EXIT_FAILURE;
	}

	RDS_BGD_Probe_Log metadata {};
	int metadata_rc =
		wait_for_metadata_error(sim, seq, cluster, 1146, "Table 'mysql.rds_topology' doesn't exist", metadata);
	if (metadata_rc != EXIT_SUCCESS) {
		diag("Error: wHG 1150 did not observe metadata error 1146 on the green writer");
		return EXIT_FAILURE;
	}

	int none_rc = bgd_wait_for_status(admin, hg, "NONE", kTimeoutSeconds);
	if (none_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1150 did not reach NONE after metadata error 1146");
		return EXIT_FAILURE;
	}

	bool blue_reader_online = runtime_server_online(admin, hg.blue_reader, cluster.blue_readers[1]);
	bool green_writer_online = runtime_server_online(admin, hg.green_writer, cluster.green_writer);
	bool green_reader_online = runtime_server_online(admin, hg.green_reader, cluster.green_readers[0]);
	ok(blue_reader_online && green_writer_online && green_reader_online,
		"metadata error 1146 completes reader cleanup for wHG 1150 and retains configured green rows");

	int table_rc = wait_for_blue_table_check(sim, metadata.sequence_id, cluster);
	if (table_rc != EXIT_SUCCESS) {
		diag("Error: wHG 1150 did not return to blue-writer table checks after metadata error 1146");
		return EXIT_FAILURE;
	}

	ok(true, "metadata error 1146 returns wHG 1150 from green metadata to blue-writer table checks");
	return EXIT_SUCCESS;
}

/**
 * Return a generic metadata error before writer completion.
 *
 * - Reach WRITER_SWITCHOVER_IN_PROGRESS for wHG 1160.
 * - Return error 1105 from the pinned green-writer metadata probe.
 * - Verify that table checking does not restart and that the in-progress
 *   status and blue-writer demotion remain unchanged.
 */
int test_generic_metadata_error(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.generic_error;
	BGD_Hostgroups& hg = state.generic_error_hg;

	int progress_rc = enter_writer_switchover(admin, sim, cluster, hg, state.generic_error_endpoints);
	if (progress_rc != EXIT_SUCCESS) {
		diag("Error: failed to reach writer switchover for wHG 1160");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before generic metadata error for wHG 1160");
		return EXIT_FAILURE;
	}

	RDS_BGD_Probe_Log metadata {};
	int metadata_rc = wait_for_metadata_error(sim, seq, cluster, 1105, "simulated generic metadata failure", metadata);
	if (metadata_rc != EXIT_SUCCESS) {
		diag("Error: wHG 1160 did not observe the generic metadata error on the green writer");
		return EXIT_FAILURE;
	}

	int no_table_rc =
		bgd_expect_no_table_check(sim, metadata.sequence_id, state.generic_error_endpoints, kNegativeProbeTimeoutMs);
	if (no_table_rc != EXIT_SUCCESS) {
		diag("Error: generic metadata error restarted table checking for wHG 1160");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: generic metadata error changed BGD status for wHG 1160");
		return EXIT_FAILURE;
	}

	int placement_rc =
		bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, true, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: generic metadata error changed blue-writer placement for wHG 1160");
		return EXIT_FAILURE;
	}

	ok(true, "generic metadata error keeps wHG 1160 in progress with the blue writer in hostgroup 1161");
	return EXIT_SUCCESS;
}

int main() {
	plan(5);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	RDS_BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: return metadata error 1146 during SWITCHOVER_IN_PROGRESS.
	// Verify: wHG 1140 reaches NONE, restores its blue writer, and returns to blue-writer table checks.
	if (test_error_1146_before_completion(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: return metadata error 1146 during READER_SWITCHOVER_IN_PROGRESS.
	// Verify: wHG 1150 completes reader cleanup and returns to blue-writer table checks.
	if (test_error_1146_during_reader_switchover(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: return generic metadata error 1105 during SWITCHOVER_IN_PROGRESS.
	// Verify: wHG 1160 remains in progress with its blue writer in reader hostgroup 1161.
	if (test_generic_metadata_error(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
