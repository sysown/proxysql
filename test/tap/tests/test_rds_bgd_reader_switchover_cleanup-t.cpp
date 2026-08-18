/**
 * @file test_rds_bgd_reader_switchover_cleanup-t.cpp
 * @brief BGD reader switchover and terminal empty-topology cleanup.
 *
 * Steps:
 *
 * 1. Configure hostgroups 980-983 and advance through writer post-processing.
 * 2. Publish target-only SWITCHOVER_COMPLETED and verify
 *    READER_SWITCHOVER_IN_PROGRESS with green rows retained.
 * 3. Repeat the completed observation and verify the reader phase is stable.
 * 4. Publish empty topology and verify NONE, restored blue-reader routing,
 *    blue-IP probing, green-pool drain, and retained green rows.
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
	RDS_BGD_Cluster cluster { bgd_cluster_init() };
	BGD_Hostgroups hostgroups { 980, 981, 982, 983 };
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
	vector<RDS_BGD_Topology_Row> rows {
		{
			cluster.green_writer.hostname,
			cluster.green_writer.hostname,
			cluster.green_writer.port,
			"BLUE_GREEN_DEPLOYMENT_TARGET",
			"SWITCHOVER_COMPLETED",
		},
	};
	return rows;
}

int set_default_hostgroup(MYSQL* admin, int hostgroup) {
	vector<string> queries {
		"UPDATE mysql_users SET default_hostgroup=" + to_string(hostgroup) + " WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	return rc;
}

int create_pool(CommandLine& cl) {
	MYSQL* client = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (client == nullptr) {
		return EXIT_FAILURE;
	}

	rc_t<string> echo = bgd_backend_ip_echo(client);
	mysql_close(client);
	return echo.first;
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

bool green_rows_online(MYSQL* admin, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg) {
	bool writer_online = runtime_server_online(admin, hg.green_writer, cluster.green_writer);
	bool reader_online = runtime_server_online(admin, hg.green_reader, cluster.green_readers[0]);
	bool rows_online = writer_online && reader_online;
	return rows_online;
}

int advance_to_post_processing(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	vector<RDS_BGD_Topology_Row> available = topology_with_reader_pair(cluster, "AVAILABLE");
	int available_rc = sim.topology_update(state.topology_endpoints, available);
	if (available_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	int available_status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (available_status_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> in_progress = topology_with_reader_pair(cluster, "SWITCHOVER_IN_PROGRESS");
	int progress_rc = sim.topology_update(state.topology_endpoints, in_progress);
	if (progress_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	int progress_status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (progress_status_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> post_processing = topology_with_reader_pair(cluster, "SWITCHOVER_IN_POST_PROCESSING");
	int post_rc = sim.topology_update(state.topology_endpoints, post_processing);
	if (post_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	int post_status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_POST_PROCESSING", kTimeoutSeconds);
	if (post_status_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * Enter reader switchover after writer post-processing.
 *
 * - Configure hostgroups 980-983 with one mapped reader pair.
 * - Create pools in green writer and reader hostgroups.
 * - Advance through writer post-processing.
 * - Publish target-only SWITCHOVER_COMPLETED twice.
 * - Verify READER_SWITCHOVER_IN_PROGRESS and retained green rows.
 */
int test_reader_switchover_in_progress(CommandLine& cl, MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	int blue_writer_rc = bgd_set_host_read_only_0(sim, cluster.blue_writer);
	if (blue_writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=0 for the simulated blue writer");
		return EXIT_FAILURE;
	}

	int green_writer_rc = bgd_set_host_read_only_0(sim, cluster.green_writer);
	if (green_writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=0 for the simulated green writer");
		return EXIT_FAILURE;
	}

	int blue_reader_rc = bgd_set_host_read_only_1(sim, cluster.blue_readers[0]);
	if (blue_reader_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=1 for the simulated blue reader");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0] };
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers, 0, 0);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups 980-983");
		return EXIT_FAILURE;
	}

	int green_writer_hg_rc = set_default_hostgroup(admin, hg.green_writer);
	if (green_writer_hg_rc != EXIT_SUCCESS) {
		diag("Error: failed to route the test user through green writer hostgroup 982");
		return EXIT_FAILURE;
	}

	int green_writer_pool_rc = create_pool(cl);
	if (green_writer_pool_rc != EXIT_SUCCESS) {
		diag("Error: failed to create a green-writer pool before reader cleanup");
		return EXIT_FAILURE;
	}

	int green_reader_hg_rc = set_default_hostgroup(admin, hg.green_reader);
	if (green_reader_hg_rc != EXIT_SUCCESS) {
		diag("Error: failed to route the test user through green reader hostgroup 983");
		return EXIT_FAILURE;
	}

	int green_reader_pool_rc = create_pool(cl);
	if (green_reader_pool_rc != EXIT_SUCCESS) {
		diag("Error: failed to create a green-reader pool before reader cleanup");
		return EXIT_FAILURE;
	}

	int restore_hg_rc = set_default_hostgroup(admin, hg.blue_writer);
	if (restore_hg_rc != EXIT_SUCCESS) {
		diag("Error: failed to restore testuser to blue writer hostgroup 980");
		return EXIT_FAILURE;
	}

	int post_rc = advance_to_post_processing(admin, sim, state);
	if (post_rc != EXIT_SUCCESS) {
		diag("Error: failed to reach WRITER_SWITCHOVER_POST_PROCESSING before reader switchover");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> completed = target_only_completed(cluster);
	int completed_rc = sim.topology_update(state.topology_endpoints, completed);
	if (completed_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish target-only SWITCHOVER_COMPLETED topology");
		return EXIT_FAILURE;
	}

	int reader_status_rc = bgd_wait_for_status(admin, hg, "READER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (reader_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 980 did not reach READER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	ok(true, "target-only SWITCHOVER_COMPLETED sets BGD status for wHG 980 to READER_SWITCHOVER_IN_PROGRESS");

	bool rows_online = green_rows_online(admin, cluster, hg);
	ok(rows_online, "READER_SWITCHOVER_IN_PROGRESS retains configured green writer and reader rows");

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the repeated reader-switchover probe sequence");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> repeated_completed = target_only_completed(cluster);
	int repeat_rc = sim.topology_update(state.topology_endpoints, repeated_completed);
	if (repeat_rc != EXIT_SUCCESS) {
		diag("Error: failed to repeat target-only SWITCHOVER_COMPLETED topology");
		return EXIT_FAILURE;
	}

	auto [probe_rc, probe] =
		sim.wait_for_probe_log(seq, cluster.green_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: BGD did not observe repeated target-only SWITCHOVER_COMPLETED topology");
		return EXIT_FAILURE;
	}

	int repeat_status_rc = bgd_wait_for_status(admin, hg, "READER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (repeat_status_rc != EXIT_SUCCESS) {
		diag("Error: repeated completion changed BGD status for wHG 980");
		return EXIT_FAILURE;
	}

	bool repeated_rows_online = green_rows_online(admin, cluster, hg);
	ok(repeated_rows_online, "repeated SWITCHOVER_COMPLETED preserves reader switchover and green rows");
	return EXIT_SUCCESS;
}

/**
 * Complete reader cleanup with present-but-empty topology.
 *
 * - Delete every topology row while the topology table remains present.
 * - Verify BGD status NONE and restored blue-reader routing.
 * - Verify metadata probing returns from the green pin to the blue writer.
 * - Verify green pools drain while configured green rows remain ONLINE.
 */
int test_reader_switchover_cleanup(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	auto [green_writer_pool_before_rc, green_writer_pool_before] = bgd_connection_pool_count(admin, hg.green_writer);
	auto [green_reader_pool_before_rc, green_reader_pool_before] = bgd_connection_pool_count(admin, hg.green_reader);
	if (green_writer_pool_before_rc != EXIT_SUCCESS || green_reader_pool_before_rc != EXIT_SUCCESS ||
		green_writer_pool_before < 1 || green_reader_pool_before < 1) {
		diag("Error: green writer or reader pool is empty before reader cleanup");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before empty topology");
		return EXIT_FAILURE;
	}

	int empty_rc = sim.topology_delete(state.topology_endpoints);
	if (empty_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish present-but-empty topology");
		return EXIT_FAILURE;
	}

	int none_rc = bgd_wait_for_status(admin, hg, "NONE", kTimeoutSeconds);
	if (none_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 980 did not reach NONE");
		return EXIT_FAILURE;
	}

	ok(true, "present-but-empty topology sets BGD status for wHG 980 to NONE");

	bool unmatched_reader_online = runtime_server_online(admin, hg.blue_reader, cluster.blue_readers[1]);
	ok(unmatched_reader_online, "reader cleanup restores the unmatched blue reader in hostgroup 981");

	auto [green_probe_rc, green_probe] =
		sim.wait_for_probe_log(seq, cluster.green_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	if (green_probe_rc != EXIT_SUCCESS) {
		diag("Error: reader cleanup did not observe empty topology through the green pin");
		return EXIT_FAILURE;
	}

	auto [blue_probe_rc, blue_probe] =
		sim.wait_for_probe_log(green_probe.sequence_id, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	if (blue_probe_rc != EXIT_SUCCESS) {
		diag("Error: metadata probing did not return to the blue writer after reader cleanup");
		return EXIT_FAILURE;
	}

	bool probe_order = green_probe.sequence_id < blue_probe.sequence_id;
	ok(probe_order, "reader cleanup removes the green pin and resumes blue-writer metadata probing");

	auto [green_writer_pool_rc, green_writer_pool] = bgd_connection_pool_count(admin, hg.green_writer);
	auto [green_reader_pool_rc, green_reader_pool] = bgd_connection_pool_count(admin, hg.green_reader);
	if (green_writer_pool_rc != EXIT_SUCCESS || green_reader_pool_rc != EXIT_SUCCESS) {
		diag("Error: failed to read green pools after reader cleanup");
		return EXIT_FAILURE;
	}

	ok(green_writer_pool == 0 && green_reader_pool == 0, "reader cleanup drains eligible green writer and reader pools");

	bool rows_online = green_rows_online(admin, cluster, hg);
	ok(rows_online, "reader cleanup retains configured green writer and reader rows as ONLINE");
	return EXIT_SUCCESS;
}

int main() {
	plan(8);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	RDS_BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// ProxySQL: configure hostgroups 980-983 and establish green writer/reader pools.
	// Simulator: advance through writer post-processing, then publish target-only SWITCHOVER_COMPLETED twice.
	// Verify: BGD remains in READER_SWITCHOVER_IN_PROGRESS and green rows remain ONLINE.
	if (test_reader_switchover_in_progress(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: delete all rows while keeping the topology table present.
	// Verify: BGD reaches NONE, blue-reader routing and blue probing resume, green pools drain, and rows remain.
	if (test_reader_switchover_cleanup(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
