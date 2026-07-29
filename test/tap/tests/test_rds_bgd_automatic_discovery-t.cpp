/**
 * @file test_rds_bgd_automatic_discovery-t.cpp
 * @brief Automatic BGD row creation from AVAILABLE topology.
 *
 * Steps:
 *
 * 1. Publish AVAILABLE topology before loading blue hostgroups 810 and 811.
 * 2. Verify one runtime-only BGD row with derived blue hostgroups and NULL
 *    green hostgroups.
 * 3. Load blue hostgroups 820 and 821 while topology is absent.
 * 4. Verify no BGD row exists until AVAILABLE topology is published.
 * 5. Verify repeated discovery keeps one runtime-only BGD row.
 */

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "command_line.h"
#include "rds_bgd_tap.h"
#include "utils.h"

// Automatic discovery is asynchronous and starts after the monitor observes the
// runtime server. Allow the monitor and the BGD worker to become ready on slower CI runners.
const uint32_t kTimeoutSeconds = 15;
const uint32_t kProbeTimeoutMs = 3000;

struct TestState {
	RDS_BGD_Cluster topology_first { bgd_cluster_init() };
	RDS_BGD_Cluster absent_first { bgd_cluster_2_init() };
	BGD_Hostgroups topology_first_hg { 810, 811, 812, 813 };
	BGD_Hostgroups absent_first_hg { 820, 821, 822, 823 };
	vector<Endpoint> topology_first_endpoints { topology_first.get_endpoints() };
	vector<Endpoint> absent_first_endpoints { absent_first.get_endpoints() };
	uint64_t absent_available_sequence { 0 };
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

bool runtime_auto_row_matches(MYSQL* admin, BGD_Hostgroups& hg) {
	string query =
		"SELECT COUNT(*) FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(hg.blue_writer) + " AND reader_hostgroup=" + to_string(hg.blue_reader) +
		" AND green_writer_hostgroup IS NULL AND green_reader_hostgroup IS NULL AND auto_generated=1";

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool matches = rows[0][0] == "1";
	return matches;
}

bool runtime_bgd_row_absent(MYSQL* admin, int writer_hostgroup) {
	string query =
		"SELECT COUNT(*) FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(writer_hostgroup);

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool absent = rows[0][0] == "0";
	return absent;
}

bool persistent_bgd_row_absent(MYSQL* admin, int writer_hostgroup) {
	string query =
		"SELECT COUNT(*) FROM mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(writer_hostgroup);

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool absent = rows[0][0] == "0";
	return absent;
}

bool runtime_bgd_row_count_matches(MYSQL* admin, int writer_hostgroup, int expected_count) {
	string query =
		"SELECT COUNT(*) FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(writer_hostgroup);

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool matches = rows[0][0] == to_string(expected_count);
	return matches;
}

/**
 * Discover a deployment whose AVAILABLE topology exists before its blue writer.
 *
 * - Set read_only=0 for both simulated writers.
 * - Publish AVAILABLE topology before loading blue hostgroups 810 and 811.
 * - Verify one auto-generated runtime row with NULL green hostgroups.
 * - Verify automatic discovery does not create a persistent BGD row.
 */
int test_topology_before_writer(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.topology_first;
	BGD_Hostgroups& hg = state.topology_first_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure topology-first simulated writers");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.topology_first_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish topology-first AVAILABLE topology");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer };
	vector<RDS_BGD_Host> green_servers {};
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::automatic, blue_servers, green_servers, 0, 0);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure automatic discovery for blue hostgroups 810 and 811");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 810 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	bool row_matches = runtime_auto_row_matches(admin, hg);
	ok(row_matches, "automatic discovery derives hostgroups 810 and 811 with NULL green hostgroups");

	bool persistent_absent = persistent_bgd_row_absent(admin, hg.blue_writer);
	ok(persistent_absent, "automatic discovery keeps wHG 810 out of mysql_aws_rds_bgd_hostgroups");
	return EXIT_SUCCESS;
}

/**
 * Start automatic discovery while topology is absent.
 *
 * - Set read_only=0 for both simulated writers.
 * - Remove topology for blue hostgroups 820 and 821.
 * - Load the blue writer and wait for the absent-table metadata probe.
 * - Verify no runtime or persistent BGD row is created.
 * - Publish AVAILABLE topology and verify automatic row creation.
 */
int test_topology_absent_then_available(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.absent_first;
	BGD_Hostgroups& hg = state.absent_first_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure topology-absent simulated writers");
		return EXIT_FAILURE;
	}

	int drop_rc = sim.topology_drop(state.absent_first_endpoints);
	if (drop_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish absent topology for blue hostgroups 820 and 821");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before topology-absent discovery");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers {};
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::automatic, blue_servers, green_servers, 0, 0);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure automatic discovery for blue hostgroups 820 and 821");
		return EXIT_FAILURE;
	}

	auto [absent_probe_rc, absent_probe] =
		sim.wait_for_probe_log(seq, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	if (absent_probe_rc != EXIT_SUCCESS) {
		diag("Error: automatic discovery did not issue the absent-table metadata probe");
		return EXIT_FAILURE;
	}

	bool runtime_absent = runtime_bgd_row_absent(admin, hg.blue_writer);
	bool persistent_absent = persistent_bgd_row_absent(admin, hg.blue_writer);
	ok(runtime_absent && persistent_absent, "absent topology creates no runtime or persistent BGD row for wHG 820");

	auto [available_seq_rc, available_seq] = sim.probe_log_last_sequence();
	if (available_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before AVAILABLE topology");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.absent_first_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG 820");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 820 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	auto [green_probe_rc, green_probe] =
		sim.wait_for_probe_log(available_seq, cluster.green_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	if (green_probe_rc != EXIT_SUCCESS) {
		diag("Error: wHG 820 did not probe the AVAILABLE green writer");
		return EXIT_FAILURE;
	}

	state.absent_available_sequence = green_probe.sequence_id;
	bool row_matches = runtime_auto_row_matches(admin, hg);
	ok(row_matches, "AVAILABLE topology creates the derived automatic BGD row for wHG 820");
	return EXIT_SUCCESS;
}

/**
 * Observe steady metadata polling after automatic discovery reaches AVAILABLE.
 *
 * - Wait for another green-writer metadata probe.
 * - Verify runtime contains one auto-generated BGD row.
 * - Verify the automatic row remains absent from persistent configuration.
 */
int test_repeated_discovery(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.absent_first;
	BGD_Hostgroups& hg = state.absent_first_hg;

	auto [probe_rc, probe] = sim.wait_for_probe_log(
		state.absent_available_sequence, cluster.green_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: automatic wHG 820 did not continue green-writer metadata polling");
		return EXIT_FAILURE;
	}

	bool one_runtime_row = runtime_bgd_row_count_matches(admin, hg.blue_writer, 1);
	bool persistent_absent = persistent_bgd_row_absent(admin, hg.blue_writer);
	ok(one_runtime_row && persistent_absent, "steady metadata polling keeps one runtime-only BGD row for wHG 820");
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

	// Simulator: publish AVAILABLE topology before configuring blue hostgroups 810 and 811.
	// ProxySQL: enable automatic discovery and load only the blue writer.
	// Verify: one runtime-only auto-generated row uses derived blue hostgroups and NULL green hostgroups.
	if (test_topology_before_writer(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish absent topology, then AVAILABLE topology for the second deployment.
	// ProxySQL: load blue hostgroups 820 and 821 while topology is absent.
	// Verify: no row exists while absent; AVAILABLE creates one auto-generated runtime row.
	if (test_topology_absent_then_available(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: allow another table-check for the AVAILABLE deployment.
	// Verify: repeated discovery keeps one runtime-only BGD row for wHG 820.
	if (test_repeated_discovery(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
