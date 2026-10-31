/**
 * @file test_rds_bgd_late_entry_completed-t.cpp
 * @brief Starting a BGD worker from target-only SWITCHOVER_COMPLETED.
 *
 * Steps:
 *
 * 1. Publish target-only SWITCHOVER_COMPLETED before configuring wHG 1200.
 * 2. Verify the first observation enters READER_SWITCHOVER_IN_PROGRESS
 *    without rebuilding writer-switchover routing or placement.
 * 3. Establish green writer/reader pools.
 * 4. Publish empty topology and verify status NONE and green-pool cleanup.
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
const uint32_t kNoProbeTimeoutMs = 1200;

struct TestState {
	RDS_BGD_Cluster cluster { bgd_cluster_1_deployment_b_init() };
	BGD_Hostgroups hostgroups { 1200, 1201, 1202, 1203 };
	vector<Endpoint> topology_endpoints { cluster.get_endpoints() };
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

int wait_for_blue_writer(RDS_BGD_Simulator& sim, uint64_t sequence, RDS_BGD_Cluster& cluster) {
	auto [probe_rc, probe] =
		sim.wait_for_probe_log(sequence, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	return probe_rc;
}

bool runtime_server_match(MYSQL* admin, int hostgroup, RDS_BGD_Host& host, string status) {
	string query =
		"SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hostgroup) +
		" AND hostname=" + bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port) +
		" AND status=" + bgd_sql_quote(status);

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool matches = rows[0][0] == "1";
	return matches;
}

int set_default_hostgroup(MYSQL* admin, int hostgroup) {
	vector<string> queries {
		"UPDATE mysql_users SET default_hostgroup=" + to_string(hostgroup) + " WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	return rc;
}

rc_t<string> connect_and_echo(CommandLine& cl) {
	MYSQL* client = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (client == nullptr) {
		rc_t<string> result { EXIT_FAILURE, {} };
		return result;
	}

	rc_t<string> result = bgd_backend_ip_echo(client);
	mysql_close(client);
	return result;
}

int wait_for_green_pool_drain(MYSQL* admin, BGD_Hostgroups& hg) {
	string query =
		"SELECT "
		"(SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_mysql_connection_pool WHERE hostgroup=" +
		to_string(hg.green_writer) + ")=0 AND "
		"(SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_mysql_connection_pool WHERE hostgroup=" +
		to_string(hg.green_reader) + ")=0";

	int rc = bgd_wait_for_condition(admin, query, kTimeoutSeconds);
	return rc;
}

/**
 * Start wHG 1200 from target-only SWITCHOVER_COMPLETED.
 *
 * - Publish SWITCHOVER_COMPLETED before configuring the BGD row.
 * - Verify READER_SWITCHOVER_IN_PROGRESS and a blue metadata probe.
 * - Verify no direct green metadata probe, blue routing remains active, and
 *   the blue writer is not demoted.
 * - Establish green writer/reader pools for terminal cleanup.
 */
int test_first_completed(CommandLine& cl, MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	int read_only_rc = configure_read_only_values(sim, cluster);
	if (read_only_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated read_only values for wHG 1200");
		return EXIT_FAILURE;
	}

	auto [publish_seq_rc, publish_seq] = sim.probe_log_last_sequence();
	if (publish_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the first COMPLETED probe sequence");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> topology = target_only_completed(cluster);
	int topology_rc = sim.topology_update(state.topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish target-only SWITCHOVER_COMPLETED topology");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0] };
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups 1200-1203");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "READER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1200 did not reach READER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	int blue_probe_rc = wait_for_blue_writer(sim, publish_seq, cluster);
	if (blue_probe_rc != EXIT_SUCCESS) {
		diag("Error: first COMPLETED observation did not probe the blue writer");
		return EXIT_FAILURE;
	}

	ok(true, "first SWITCHOVER_COMPLETED observation reports READER_SWITCHOVER_IN_PROGRESS for wHG 1200");

	int no_green_rc = bgd_expect_no_metadata_probe(sim, publish_seq, cluster.green_writer.endpoint(), kNoProbeTimeoutMs);
	if (no_green_rc != EXIT_SUCCESS) {
		diag("Error: first COMPLETED observation rebuilt a direct green metadata probe");
		return EXIT_FAILURE;
	}

	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: first COMPLETED observation changed blue-writer placement");
		return EXIT_FAILURE;
	}

	auto [blue_echo_rc, blue_echo] = connect_and_echo(cl);
	bool blue_routing = blue_echo_rc == EXIT_SUCCESS && blue_echo.find(cluster.blue_writer.ip) != string::npos;
	bool reader_online = runtime_server_match(admin, hg.blue_reader, cluster.blue_readers[1], "ONLINE");
	ok(blue_routing && reader_online,
		"first SWITCHOVER_COMPLETED observation keeps blue routing without writer-phase pins or demotion");

	int writer_hg_rc = set_default_hostgroup(admin, hg.green_writer);
	if (writer_hg_rc != EXIT_SUCCESS) {
		diag("Error: failed to route the test user through green writer hostgroup 1202");
		return EXIT_FAILURE;
	}

	int writer_echo_rc = connect_and_echo(cl).first;
	if (writer_echo_rc != EXIT_SUCCESS) {
		diag("Error: failed to establish a green-writer pool before terminal cleanup");
		return EXIT_FAILURE;
	}

	int reader_hg_rc = set_default_hostgroup(admin, hg.green_reader);
	if (reader_hg_rc != EXIT_SUCCESS) {
		diag("Error: failed to route the test user through green reader hostgroup 1203");
		return EXIT_FAILURE;
	}

	int reader_echo_rc = connect_and_echo(cl).first;
	if (reader_echo_rc != EXIT_SUCCESS) {
		diag("Error: failed to establish a green-reader pool before terminal cleanup");
		return EXIT_FAILURE;
	}

	int restore_hg_rc = set_default_hostgroup(admin, hg.blue_writer);
	if (restore_hg_rc != EXIT_SUCCESS) {
		diag("Error: failed to restore the test user to blue writer hostgroup 1200");
		return EXIT_FAILURE;
	}

	auto [writer_pool_rc, writer_pool] = bgd_connection_pool_count(admin, hg.green_writer);
	auto [reader_pool_rc, reader_pool] = bgd_connection_pool_count(admin, hg.green_reader);
	if (writer_pool_rc != EXIT_SUCCESS || writer_pool < 1 || reader_pool_rc != EXIT_SUCCESS || reader_pool < 1) {
		diag("Error: green pools are empty before terminal completed cleanup");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/**
 * Publish empty topology during direct-entry reader switchover.
 *
 * - Remove the simulated topology after first-observation COMPLETED.
 * - Verify BGD status NONE.
 * - Verify eligible green writer/reader pools are drained.
 * - Verify blue-writer and blue-reader placement remains available.
 */
int test_completed_empty_topology(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	int topology_rc = sim.topology_delete(state.topology_endpoints);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish empty topology for wHG 1200");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "NONE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1200 did not reach NONE after empty topology");
		return EXIT_FAILURE;
	}

	int drain_rc = wait_for_green_pool_drain(admin, hg);
	if (drain_rc != EXIT_SUCCESS) {
		diag("Error: empty topology did not drain green pools for hostgroups 1202-1203");
		return EXIT_FAILURE;
	}

	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: empty topology changed blue-writer placement for wHG 1200");
		return EXIT_FAILURE;
	}

	bool reader_online = runtime_server_match(admin, hg.blue_reader, cluster.blue_readers[1], "ONLINE");
	ok(reader_online, "empty topology reaches NONE, drains green pools, and keeps blue hostgroups 1200-1201 available");
	return EXIT_SUCCESS;
}

int main() {
	plan(3);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	RDS_BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: publish target-only SWITCHOVER_COMPLETED before wHG 1200 is configured.
	// Verify: first observation enters READER_SWITCHOVER_IN_PROGRESS without green pins or writer demotion.
	// Client: establish green writer/reader pools for terminal cleanup.
	if (test_first_completed(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish empty topology during READER_SWITCHOVER_IN_PROGRESS.
	// Verify: BGD status reaches NONE and green writer/reader pools are drained.
	// Verify: blue writer and reader hostgroups remain available.
	if (test_completed_empty_topology(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
