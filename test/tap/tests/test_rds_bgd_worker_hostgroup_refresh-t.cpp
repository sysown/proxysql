/**
 * @file test_rds_bgd_worker_hostgroup_refresh-t.cpp
 * @brief Refreshing hostgroups and the mapped blue writer during writer switchover.
 *
 * Steps:
 *
 * 1. Configure BGD hostgroups 1380-1383 and reach
 *    `WRITER_SWITCHOVER_IN_PROGRESS`.
 * 2. Change the reader and green hostgroups to 1384-1386.
 * 3. Verify that the BGD status remains in progress and runtime placement
 *    moves to the configured reader hostgroup.
 * 4. Verify metadata probes use TLS configured only in the refreshed green
 *    hostgroups.
 * 5. Move a blue reader into writer hostgroup 1380 and publish topology that
 *    maps it to a different green target.
 * 6. Verify that the previous writer returns to hostgroup 1380, the newly
 *    mapped writer moves to hostgroup 1384, uses TLS from green writer
 *    hostgroup 1385, and stops probing the stale target.
 */

#include <cerrno>
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
	RDS_BGD_Cluster cluster { bgd_cluster_3_init() };
	BGD_Hostgroups hostgroups { 1380, 1381, 1382, 1383 };
	BGD_Hostgroups refreshed_hostgroups { 1380, 1384, 1385, 1386 };
	vector<Endpoint> topology_endpoints { cluster.get_endpoints() };
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

vector<BGD_Topology_Row> topology_with_reader_as_writer(RDS_BGD_Cluster& cluster) {
	RDS_BGD_Host& blue_writer = cluster.blue_readers[0];
	RDS_BGD_Host& green_writer = cluster.green_readers[0];

	vector<BGD_Topology_Row> rows {
		{ blue_writer.hostname, blue_writer.hostname, blue_writer.port,
			"BLUE_GREEN_DEPLOYMENT_SOURCE", "SWITCHOVER_IN_PROGRESS" },
		{ green_writer.hostname, green_writer.hostname, green_writer.port,
			"BLUE_GREEN_DEPLOYMENT_TARGET", "SWITCHOVER_IN_PROGRESS" },
	};
	return rows;
}

/**
 * Refresh the reader and green hostgroups during writer switchover.
 *
 * - Configure BGD hostgroups 1380-1383.
 * - Publish `SWITCHOVER_IN_PROGRESS` and require the blue writer in hostgroup
 *   1381.
 * - Change the reader and green hostgroups to 1384-1386.
 * - Verify that `WRITER_SWITCHOVER_IN_PROGRESS` is preserved.
 * - Verify writer placement in hostgroup 1384.
 * - Verify metadata probes use TLS from green hostgroups 1385 and 1386.
 */
int test_hostgroup_refresh(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;
	BGD_Hostgroups& refreshed_hg = state.refreshed_hostgroups;

	// Set read_only=0 for the simulated blue and green writers.
	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated writer read_only values");
		return EXIT_FAILURE;
	}

	// Publish SWITCHOVER_IN_PROGRESS topology.
	vector<BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "SWITCHOVER_IN_PROGRESS");
	int topology_rc = sim.topology_update(state.topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_PROGRESS topology");
		return EXIT_FAILURE;
	}

	// Configure mysql_servers and mysql_aws_rds_bgd_hostgroups.
	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0], cluster.green_readers[1] };

	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers, 0, 0);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups 1380-1383");
		return EXIT_FAILURE;
	}

	// Require the in-progress status and blue-writer demotion before changing hostgroups.
	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1380 did not reach WRITER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, true, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: blue writer did not move from hostgroup 1380 to 1381");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before refreshing hostgroups");
		return EXIT_FAILURE;
	}

	// Move blue readers and TLS-enabled green servers into the refreshed hostgroups.
	string update_replication =
		"UPDATE mysql_replication_hostgroups SET reader_hostgroup=" + to_string(refreshed_hg.blue_reader) +
		" WHERE writer_hostgroup=" + to_string(refreshed_hg.blue_writer);
	string move_blue =
		"UPDATE mysql_servers SET hostgroup_id=" + to_string(refreshed_hg.blue_reader) +
		" WHERE hostgroup_id=" + to_string(hg.blue_reader);
	string move_green_writer =
		"UPDATE mysql_servers SET hostgroup_id=" + to_string(refreshed_hg.green_writer) + ",use_ssl=1" +
		" WHERE hostgroup_id=" + to_string(hg.green_writer);
	string move_green_readers =
		"UPDATE mysql_servers SET hostgroup_id=" + to_string(refreshed_hg.green_reader) + ",use_ssl=1" +
		" WHERE hostgroup_id=" + to_string(hg.green_reader);
	string update_bgd =
		"UPDATE mysql_aws_rds_bgd_hostgroups SET reader_hostgroup=" + to_string(refreshed_hg.blue_reader) +
		",green_writer_hostgroup=" + to_string(refreshed_hg.green_writer) +
		",green_reader_hostgroup=" + to_string(refreshed_hg.green_reader) +
		" WHERE writer_hostgroup=" + to_string(refreshed_hg.blue_writer);
	vector<string> queries {
		update_replication,
		move_blue,
		move_green_writer,
		move_green_readers,
		update_bgd,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int refresh_rc = execute_all(admin, queries);
	if (refresh_rc != EXIT_SUCCESS) {
		diag("Error: failed to refresh BGD hostgroups from 1381-1383 to 1384-1386");
		return EXIT_FAILURE;
	}

	// Verify that the runtime BGD status is preserved.
	int refreshed_status_rc = bgd_wait_for_status(admin, refreshed_hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (refreshed_status_rc != EXIT_SUCCESS) {
		diag("Error: hostgroup refresh did not preserve WRITER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	ok(true, "BGD status for wHG 1380 remains WRITER_SWITCHOVER_IN_PROGRESS after hostgroup refresh");

	// Verify that the blue writer uses the refreshed reader hostgroup.
	int refreshed_placement_rc = bgd_wait_for_server_placement(
		admin, refreshed_hg.blue_writer, refreshed_hg.blue_reader, cluster.blue_writer, true, kTimeoutSeconds
	);
	if (refreshed_placement_rc != EXIT_SUCCESS) {
		diag("Error: blue writer did not move from reader hostgroup 1381 to 1384");
		return EXIT_FAILURE;
	}

	ok(true, "hostgroup refresh moves the demoted blue writer from hostgroup 1381 to 1384");

	// Require TLS from the green writer row in refreshed green writer hostgroup 1385.
	auto [probe_rc, probe] = sim.wait_for_probe_log(
		seq, cluster.green_writer.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, 1
	);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: metadata probe did not use TLS from green writer hostgroup 1385");
		return EXIT_FAILURE;
	}

	ok(true, "hostgroup refresh uses TLS from the green writer in hostgroup 1385");
	return EXIT_SUCCESS;
}

/**
 * Refresh the mapped blue writer during writer switchover.
 *
 * - Move the first blue reader from hostgroup 1384 to writer hostgroup 1380.
 * - Publish `SWITCHOVER_IN_PROGRESS` topology that maps it to the first green
 *   reader.
 * - Move that green target from reader hostgroup 1386 to writer hostgroup
 *   1385.
 * - Verify that the previous writer returns to hostgroup 1380.
 * - Verify that the newly mapped writer moves to hostgroup 1384.
 * - Verify that metadata probing uses TLS from the new green writer target.
 */
int test_mapped_writer_refresh(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.refreshed_hostgroups;
	RDS_BGD_Host& previous_writer = cluster.blue_writer;
	RDS_BGD_Host& mapped_writer = cluster.blue_readers[0];
	RDS_BGD_Host& mapped_target = cluster.green_readers[0];

	// Publish topology that maps the first blue reader to the first green reader.
	vector<BGD_Topology_Row> topology = topology_with_reader_as_writer(cluster);
	int topology_rc = sim.topology_update(state.topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_PROGRESS topology for the new mapped writer");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before changing the mapped writer");
		return EXIT_FAILURE;
	}

	// Move the new blue/green writer pair into writer hostgroups 1380 and 1385.
	string move_writer =
		"UPDATE mysql_servers SET hostgroup_id=" + to_string(hg.blue_writer) +
		" WHERE hostgroup_id=" + to_string(hg.blue_reader) +
		" AND hostname=" + bgd_sql_quote(mapped_writer.hostname) +
		" AND port=" + to_string(mapped_writer.port);
	string move_target =
		"UPDATE mysql_servers SET hostgroup_id=" + to_string(hg.green_writer) +
		" WHERE hostgroup_id=" + to_string(hg.green_reader) +
		" AND hostname=" + bgd_sql_quote(mapped_target.hostname) +
		" AND port=" + to_string(mapped_target.port);
	vector<string> queries {
		move_writer,
		move_target,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int refresh_rc = execute_all(admin, queries);
	if (refresh_rc != EXIT_SUCCESS) {
		diag("Error: failed to move the new mapped writer pair into hostgroups 1380 and 1385");
		return EXIT_FAILURE;
	}

	// Require the preserved BGD status and the new target metadata probe.
	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: mapped-writer refresh did not preserve WRITER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	auto [probe_rc, probe] = sim.wait_for_probe_log(
		seq, mapped_target.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, 1
	);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: metadata probing did not use TLS from green writer hostgroup 1385");
		return EXIT_FAILURE;
	}

	// Verify that the previous writer was restored to writer hostgroup 1380.
	int previous_writer_rc = bgd_wait_for_server_placement(
		admin, hg.blue_writer, hg.blue_reader, previous_writer, false, kTimeoutSeconds
	);
	if (previous_writer_rc != EXIT_SUCCESS) {
		diag("Error: previous blue writer was not restored to hostgroup 1380");
		return EXIT_FAILURE;
	}

	ok(true, "mapped-writer refresh restores the previous blue writer from hostgroup 1384 to 1380");

	// Verify that the newly mapped writer was demoted to reader hostgroup 1384.
	int mapped_writer_rc = bgd_wait_for_server_placement(
		admin, hg.blue_writer, hg.blue_reader, mapped_writer, true, kTimeoutSeconds
	);
	if (mapped_writer_rc != EXIT_SUCCESS) {
		diag("Error: newly mapped writer did not move to reader hostgroup 1384");
		return EXIT_FAILURE;
	}

	ok(true, "mapped-writer refresh moves the new blue writer from hostgroup 1380 to 1384");

	// Verify that the previous green target receives no metadata probes after the new target.
	int stale_probe_rc =
		bgd_expect_no_metadata_probe(sim, probe.sequence_id, cluster.green_writer.endpoint(), kNegativeProbeTimeoutMs);
	if (stale_probe_rc != EXIT_SUCCESS) {
		diag("Error: previous green target continued receiving metadata probes");
		return EXIT_FAILURE;
	}

	ok(true, "mapped-writer refresh uses TLS from hostgroup 1385 and stops probing the previous target");
	return EXIT_SUCCESS;
}

int main() {
	plan(6);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: publish SWITCHOVER_IN_PROGRESS for the blue/green writers.
	// ProxySQL: configure BGD hostgroups 1380-1383, then change reader/green hostgroups to 1384-1386.
	// Verify: BGD status stays in progress, writer placement uses 1384, and target probing uses TLS from 1385.
	if (test_hostgroup_refresh(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish SWITCHOVER_IN_PROGRESS with the first reader pair as the writer pair.
	// ProxySQL: move the first blue reader from hostgroup 1384 to writer hostgroup 1380.
	// Verify: the previous writer is restored, the new writer is demoted, and probing uses TLS from hostgroup 1385.
	if (test_mapped_writer_refresh(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
