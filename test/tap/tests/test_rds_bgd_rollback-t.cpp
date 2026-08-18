/**
 * @file test_rds_bgd_rollback-t.cpp
 * @brief Returning from writer switchover to AVAILABLE.
 *
 * Steps:
 *
 * 1. Enter SWITCHOVER_INITIATED with a monitor-created green writer.
 * 2. Return to AVAILABLE and verify blue-writer placement, read_only
 *    processing, and the monitor-created green writer.
 * 3. Enter SWITCHOVER_IN_PROGRESS with explicit green servers and pools.
 * 4. Return to AVAILABLE and verify blue routing without removing explicit
 *    green servers or draining their pools.
 * 5. Repeat AVAILABLE and verify that rollback remains stable.
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

struct GreenRows {
	vector<mysql_res_row> admin_writer {};
	vector<mysql_res_row> runtime_writer {};
	vector<mysql_res_row> admin_reader {};
	vector<mysql_res_row> runtime_reader {};
};

struct TestState {
	RDS_BGD_Cluster initiated_cluster { bgd_cluster_init() };
	BGD_Hostgroups initiated_hg { 980, 981, 982, 983 };
	vector<Endpoint> initiated_endpoints { initiated_cluster.get_endpoints() };

	RDS_BGD_Cluster progress_cluster { bgd_cluster_2_init() };
	BGD_Hostgroups progress_hg { 990, 991, 992, 993 };
	vector<Endpoint> progress_endpoints { progress_cluster.get_endpoints() };
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

	return EXIT_SUCCESS;
}

int publish_topology(RDS_BGD_Simulator& sim, vector<Endpoint> endpoints, RDS_BGD_Cluster& cluster, string status) {
	vector<RDS_BGD_Topology_Row> topology = topology_with_reader_pair(cluster, status);

	int rc = sim.topology_update(endpoints, topology);
	return rc;
}

int wait_for_green_writer(RDS_BGD_Simulator& sim, uint64_t sequence, RDS_BGD_Cluster& cluster) {
	auto [probe_rc, probe] =
		sim.wait_for_probe_log(sequence, cluster.green_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	return probe_rc;
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

int64_t last_read_only_log_time(MYSQL* admin, RDS_BGD_Host& host) {
	string query =
		"SELECT COALESCE(MAX(time_start_us),0) FROM mysql_server_read_only_log WHERE hostname=" +
		bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port);

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return -1;
	}

	int64_t time = strtoll(rows[0][0].c_str(), nullptr, 10);
	return time;
}

int wait_for_read_only_log(MYSQL* admin, RDS_BGD_Host& host, int64_t baseline) {
	string query =
		"SELECT COUNT(*)>0 FROM mysql_server_read_only_log WHERE hostname=" +
		bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port) +
		" AND time_start_us>" + to_string(baseline);

	int rc = bgd_wait_for_condition(admin, query, kTimeoutSeconds);
	return rc;
}

rc_t<vector<mysql_res_row>> server_row_snapshot(MYSQL* admin, string table, int hostgroup, RDS_BGD_Host& host) {
	string query =
		"SELECT hostgroup_id,hostname,port,status,use_ssl,weight,max_connections FROM " + table +
		" WHERE hostgroup_id=" + to_string(hostgroup) +
		" AND hostname=" + bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port);

	rc_t<vector<mysql_res_row>> result = mysql_query_ext_rows(admin, query);
	return result;
}

bool server_row_matches(MYSQL* admin, string table, int hostgroup, RDS_BGD_Host& host, vector<mysql_res_row> expected) {
	auto [rc, rows] = server_row_snapshot(admin, table, hostgroup, host);
	if (rc != EXIT_SUCCESS) {
		return false;
	}

	bool matches = rows == expected;
	return matches;
}

rc_t<GreenRows> green_rows_snapshot(MYSQL* admin, BGD_Hostgroups& hg, RDS_BGD_Cluster& cluster, bool include_reader) {
	GreenRows rows {};

	auto [admin_writer_rc, admin_writer] = server_row_snapshot(admin, "mysql_servers", hg.green_writer, cluster.green_writer);
	if (admin_writer_rc != EXIT_SUCCESS) {
		return { EXIT_FAILURE, {} };
	}
	rows.admin_writer = admin_writer;

	auto [runtime_writer_rc, runtime_writer] =
		server_row_snapshot(admin, "runtime_mysql_servers", hg.green_writer, cluster.green_writer);
	if (runtime_writer_rc != EXIT_SUCCESS) {
		return { EXIT_FAILURE, {} };
	}
	rows.runtime_writer = runtime_writer;

	if (include_reader) {
		auto [admin_reader_rc, admin_reader] =
			server_row_snapshot(admin, "mysql_servers", hg.green_reader, cluster.green_readers[0]);
		if (admin_reader_rc != EXIT_SUCCESS) {
			return { EXIT_FAILURE, {} };
		}
		rows.admin_reader = admin_reader;

		auto [runtime_reader_rc, runtime_reader] =
			server_row_snapshot(admin, "runtime_mysql_servers", hg.green_reader, cluster.green_readers[0]);
		if (runtime_reader_rc != EXIT_SUCCESS) {
			return { EXIT_FAILURE, {} };
		}
		rows.runtime_reader = runtime_reader;
	}

	return { EXIT_SUCCESS, rows };
}

bool green_rows_match(MYSQL* admin, BGD_Hostgroups& hg, RDS_BGD_Cluster& cluster, GreenRows& expected, bool include_reader) {
	bool admin_writer = server_row_matches(admin, "mysql_servers", hg.green_writer, cluster.green_writer, expected.admin_writer);
	bool runtime_writer =
		server_row_matches(admin, "runtime_mysql_servers", hg.green_writer, cluster.green_writer, expected.runtime_writer);

	bool admin_reader = true;
	bool runtime_reader = true;
	if (include_reader) {
		admin_reader =
			server_row_matches(admin, "mysql_servers", hg.green_reader, cluster.green_readers[0], expected.admin_reader);
		runtime_reader = server_row_matches(
			admin, "runtime_mysql_servers", hg.green_reader, cluster.green_readers[0], expected.runtime_reader
		);
	}

	bool matches = admin_writer && runtime_writer && admin_reader && runtime_reader;
	return matches;
}

/**
 * Return from SWITCHOVER_INITIATED to AVAILABLE.
 *
 * - Configure BGD without a green mysql_servers row and let the worker create
 *   the green writer in runtime.
 * - Publish SWITCHOVER_INITIATED, then return to AVAILABLE.
 * - Verify blue-writer placement and normal read_only processing are restored.
 * - Repeat AVAILABLE and verify the monitor-created green writer remains.
 */
int test_initiated_rollback(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.initiated_cluster;
	BGD_Hostgroups& hg = state.initiated_hg;

	int read_only_rc = configure_read_only_values(sim, cluster);
	if (read_only_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated read_only values for wHG 980");
		return EXIT_FAILURE;
	}

	int available_topology_rc = publish_topology(sim, state.initiated_endpoints, cluster, "AVAILABLE");
	if (available_topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG 980");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups 980-983");
		return EXIT_FAILURE;
	}

	int available_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (available_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 980 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	auto [created_rc, created_rows] = green_rows_snapshot(admin, hg, cluster, false);
	if (created_rc != EXIT_SUCCESS || !created_rows.admin_writer.empty() || created_rows.runtime_writer.size() != 1) {
		diag("Error: the green writer was not created only in runtime hostgroup 982");
		return EXIT_FAILURE;
	}

	int initiated_topology_rc = publish_topology(sim, state.initiated_endpoints, cluster, "SWITCHOVER_INITIATED");
	if (initiated_topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_INITIATED topology for wHG 980");
		return EXIT_FAILURE;
	}

	int initiated_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_INITIATED", kTimeoutSeconds);
	if (initiated_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 980 did not reach WRITER_SWITCHOVER_INITIATED");
		return EXIT_FAILURE;
	}

	int64_t read_only_baseline = last_read_only_log_time(admin, cluster.blue_readers[0]);
	if (read_only_baseline < 0) {
		diag("Error: failed to read the blue-reader read_only log baseline");
		return EXIT_FAILURE;
	}

	auto [return_seq_rc, return_seq] = sim.probe_log_last_sequence();
	if (return_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the AVAILABLE rollback probe sequence");
		return EXIT_FAILURE;
	}

	int return_topology_rc = publish_topology(sim, state.initiated_endpoints, cluster, "AVAILABLE");
	if (return_topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to return wHG 980 topology to AVAILABLE");
		return EXIT_FAILURE;
	}

	int returned_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (returned_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 980 did not return to AVAILABLE");
		return EXIT_FAILURE;
	}

	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: initiated rollback did not restore the blue writer to hostgroup 980");
		return EXIT_FAILURE;
	}

	int probe_rc = wait_for_green_writer(sim, return_seq, cluster);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: initiated rollback did not resume green-writer probing");
		return EXIT_FAILURE;
	}

	ok(true, "returning from SWITCHOVER_INITIATED restores the blue writer to hostgroup 980");

	int reader_update_rc = bgd_set_host_read_only_0(sim, cluster.blue_readers[0]);
	if (reader_update_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=0 for the simulated blue reader");
		return EXIT_FAILURE;
	}

	int reader_log_rc = wait_for_read_only_log(admin, cluster.blue_readers[0], read_only_baseline);
	if (reader_log_rc != EXIT_SUCCESS) {
		diag("Error: read_only monitoring remained suppressed after initiated rollback");
		return EXIT_FAILURE;
	}

	ok(true, "returning to AVAILABLE restores normal read_only monitoring");

	auto [repeat_seq_rc, repeat_seq] = sim.probe_log_last_sequence();
	if (repeat_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the repeated AVAILABLE probe sequence");
		return EXIT_FAILURE;
	}

	int repeat_topology_rc = publish_topology(sim, state.initiated_endpoints, cluster, "AVAILABLE");
	if (repeat_topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to repeat AVAILABLE topology for wHG 980");
		return EXIT_FAILURE;
	}

	int repeat_status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (repeat_status_rc != EXIT_SUCCESS) {
		diag("Error: repeated AVAILABLE did not keep BGD status for wHG 980");
		return EXIT_FAILURE;
	}

	int repeat_placement_rc =
		bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (repeat_placement_rc != EXIT_SUCCESS) {
		diag("Error: repeated AVAILABLE changed blue-writer placement for wHG 980");
		return EXIT_FAILURE;
	}

	int repeat_probe_rc = wait_for_green_writer(sim, repeat_seq, cluster);
	if (repeat_probe_rc != EXIT_SUCCESS) {
		diag("Error: repeated AVAILABLE did not probe the green writer");
		return EXIT_FAILURE;
	}

	bool created_rows_match = green_rows_match(admin, hg, cluster, created_rows, false);
	ok(created_rows_match, "repeated AVAILABLE keeps the monitor-created green writer in runtime hostgroup 982");
	return EXIT_SUCCESS;
}

/**
 * Return from SWITCHOVER_IN_PROGRESS to AVAILABLE.
 *
 * - Configure explicit green writer/reader rows and establish their pools.
 * - Enter SWITCHOVER_IN_PROGRESS and require blue-writer demotion.
 * - Return to AVAILABLE and verify blue routing is restored.
 * - Verify explicit green rows and pools remain unchanged.
 * - Repeat AVAILABLE and verify rollback remains stable.
 */
int test_in_progress_rollback(CommandLine& cl, MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.progress_cluster;
	BGD_Hostgroups& hg = state.progress_hg;

	int read_only_rc = configure_read_only_values(sim, cluster);
	if (read_only_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated read_only values for wHG 990");
		return EXIT_FAILURE;
	}

	int available_topology_rc = publish_topology(sim, state.progress_endpoints, cluster, "AVAILABLE");
	if (available_topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG 990");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0] };
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups 990-993");
		return EXIT_FAILURE;
	}

	int available_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (available_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 990 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	auto [green_rows_rc, green_rows] = green_rows_snapshot(admin, hg, cluster, true);
	if (green_rows_rc != EXIT_SUCCESS || green_rows.admin_writer.size() != 1 ||
		green_rows.runtime_writer.size() != 1 || green_rows.admin_reader.size() != 1 ||
		green_rows.runtime_reader.size() != 1) {
		diag("Error: failed to snapshot explicit green servers for wHG 990");
		return EXIT_FAILURE;
	}

	int writer_hg_rc = set_default_hostgroup(admin, hg.green_writer);
	if (writer_hg_rc != EXIT_SUCCESS) {
		diag("Error: failed to route the test user through green writer hostgroup 992");
		return EXIT_FAILURE;
	}

	int writer_echo_rc = connect_and_echo(cl).first;
	if (writer_echo_rc != EXIT_SUCCESS) {
		diag("Error: failed to establish a green-writer connection pool");
		return EXIT_FAILURE;
	}

	int reader_hg_rc = set_default_hostgroup(admin, hg.green_reader);
	if (reader_hg_rc != EXIT_SUCCESS) {
		diag("Error: failed to route the test user through green reader hostgroup 993");
		return EXIT_FAILURE;
	}

	int reader_echo_rc = connect_and_echo(cl).first;
	if (reader_echo_rc != EXIT_SUCCESS) {
		diag("Error: failed to establish a green-reader connection pool");
		return EXIT_FAILURE;
	}

	int restore_hg_rc = set_default_hostgroup(admin, hg.blue_writer);
	if (restore_hg_rc != EXIT_SUCCESS) {
		diag("Error: failed to restore the test user to blue writer hostgroup 990");
		return EXIT_FAILURE;
	}

	auto [writer_pool_rc, writer_pool] = bgd_connection_pool_count(admin, hg.green_writer);
	auto [reader_pool_rc, reader_pool] = bgd_connection_pool_count(admin, hg.green_reader);
	if (writer_pool_rc != EXIT_SUCCESS || writer_pool < 1 || reader_pool_rc != EXIT_SUCCESS || reader_pool < 1) {
		diag("Error: failed to establish green pools before in-progress rollback");
		return EXIT_FAILURE;
	}

	int initiated_topology_rc = publish_topology(sim, state.progress_endpoints, cluster, "SWITCHOVER_INITIATED");
	if (initiated_topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_INITIATED topology for wHG 990");
		return EXIT_FAILURE;
	}

	int initiated_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_INITIATED", kTimeoutSeconds);
	if (initiated_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 990 did not reach WRITER_SWITCHOVER_INITIATED");
		return EXIT_FAILURE;
	}

	int progress_topology_rc = publish_topology(sim, state.progress_endpoints, cluster, "SWITCHOVER_IN_PROGRESS");
	if (progress_topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_PROGRESS topology for wHG 990");
		return EXIT_FAILURE;
	}

	int progress_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (progress_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 990 did not reach WRITER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	int demotion_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, true, kTimeoutSeconds);
	if (demotion_rc != EXIT_SUCCESS) {
		diag("Error: the blue writer did not move to reader hostgroup 991");
		return EXIT_FAILURE;
	}

	auto [return_seq_rc, return_seq] = sim.probe_log_last_sequence();
	if (return_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the in-progress rollback probe sequence");
		return EXIT_FAILURE;
	}

	int return_topology_rc = publish_topology(sim, state.progress_endpoints, cluster, "AVAILABLE");
	if (return_topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to return wHG 990 topology to AVAILABLE");
		return EXIT_FAILURE;
	}

	int returned_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (returned_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 990 did not return to AVAILABLE");
		return EXIT_FAILURE;
	}

	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: in-progress rollback did not restore the blue writer to hostgroup 990");
		return EXIT_FAILURE;
	}

	int probe_rc = wait_for_green_writer(sim, return_seq, cluster);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: in-progress rollback did not resume green-writer probing");
		return EXIT_FAILURE;
	}

	auto [blue_echo_rc, blue_echo] = connect_and_echo(cl);
	bool blue_routing = blue_echo_rc == EXIT_SUCCESS && blue_echo.find(cluster.blue_writer.ip) != string::npos;
	ok(blue_routing, "returning from SWITCHOVER_IN_PROGRESS restores routing through blue writer hostgroup 990");

	bool rows_match = green_rows_match(admin, hg, cluster, green_rows, true);
	ok(rows_match, "in-progress rollback keeps explicit green servers in Admin and runtime hostgroups 992-993");

	auto [post_writer_pool_rc, post_writer_pool] = bgd_connection_pool_count(admin, hg.green_writer);
	auto [post_reader_pool_rc, post_reader_pool] = bgd_connection_pool_count(admin, hg.green_reader);
	bool pools_match = post_writer_pool_rc == EXIT_SUCCESS && post_writer_pool >= writer_pool &&
		post_reader_pool_rc == EXIT_SUCCESS && post_reader_pool >= reader_pool;
	ok(pools_match, "in-progress rollback does not drain green writer and reader pools");

	auto [repeat_seq_rc, repeat_seq] = sim.probe_log_last_sequence();
	if (repeat_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the repeated AVAILABLE probe sequence for wHG 990");
		return EXIT_FAILURE;
	}

	int repeat_topology_rc = publish_topology(sim, state.progress_endpoints, cluster, "AVAILABLE");
	if (repeat_topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to repeat AVAILABLE topology for wHG 990");
		return EXIT_FAILURE;
	}

	int repeat_status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (repeat_status_rc != EXIT_SUCCESS) {
		diag("Error: repeated AVAILABLE did not keep BGD status for wHG 990");
		return EXIT_FAILURE;
	}

	int repeat_placement_rc =
		bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (repeat_placement_rc != EXIT_SUCCESS) {
		diag("Error: repeated AVAILABLE changed blue-writer placement for wHG 990");
		return EXIT_FAILURE;
	}

	int repeat_probe_rc = wait_for_green_writer(sim, repeat_seq, cluster);
	if (repeat_probe_rc != EXIT_SUCCESS) {
		diag("Error: repeated AVAILABLE did not probe the green writer for wHG 990");
		return EXIT_FAILURE;
	}

	auto [repeat_writer_pool_rc, repeat_writer_pool] = bgd_connection_pool_count(admin, hg.green_writer);
	auto [repeat_reader_pool_rc, repeat_reader_pool] = bgd_connection_pool_count(admin, hg.green_reader);
	bool repeat_rows = green_rows_match(admin, hg, cluster, green_rows, true);
	bool repeat_pools = repeat_writer_pool_rc == EXIT_SUCCESS && repeat_writer_pool >= writer_pool &&
		repeat_reader_pool_rc == EXIT_SUCCESS && repeat_reader_pool >= reader_pool;
	ok(repeat_rows && repeat_pools, "repeated AVAILABLE keeps blue placement, explicit green servers, and green pools");
	return EXIT_SUCCESS;
}

int main() {
	plan(7);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	RDS_BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: publish AVAILABLE, SWITCHOVER_INITIATED, then AVAILABLE for a monitor-created green writer.
	// Verify: blue writer returns to hostgroup 980 and normal read_only monitoring resumes.
	// Verify: repeated AVAILABLE keeps the monitor-created green writer in runtime hostgroup 982.
	if (test_initiated_rollback(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish AVAILABLE, SWITCHOVER_INITIATED, SWITCHOVER_IN_PROGRESS, then AVAILABLE.
	// ProxySQL: configure explicit green servers and establish green writer/reader pools.
	// Verify: blue routing returns without removing green servers or draining their pools.
	if (test_in_progress_rollback(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
