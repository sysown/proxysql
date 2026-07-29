/**
 * @file test_rds_bgd_writer_switchover-t.cpp
 * @brief BGD writer switchover from AVAILABLE through POST_PROCESSING.
 *
 * Steps:
 *
 * 1. Configure BGD hostgroups 970-973 and reach AVAILABLE.
 * 2. Publish SWITCHOVER_INITIATED and verify read-only placement suppression.
 * 3. Publish SWITCHOVER_IN_PROGRESS and verify blue-writer demotion.
 * 4. Create a blue-writer pool through normal routing hostgroup 974.
 * 5. Publish SWITCHOVER_IN_POST_PROCESSING and verify writer restoration,
 *    blue-pool drain, and green backend routing.
 * 6. Create a post-cutover pool and verify repeated POST_PROCESSING does not
 *    drain it again.
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
const uint32_t kReadOnlyObservationMs = 500;

struct TestState {
	RDS_BGD_Cluster cluster { bgd_cluster_init() };
	BGD_Hostgroups hostgroups { 970, 971, 972, 973 };
	int pool_hostgroup { 974 };
	vector<Endpoint> topology_endpoints { cluster.get_endpoints() };
	int64_t reader_log_baseline { -1 };
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

int wait_for_green_observation(RDS_BGD_Simulator& sim, uint64_t sequence, RDS_BGD_Cluster& cluster) {
	auto [probe_rc, probe] =
		sim.wait_for_probe_log(sequence, cluster.green_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	return probe_rc;
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

bool server_match_count(MYSQL* admin, int hostgroup, RDS_BGD_Host& host, int expected_count) {
	string query =
		"SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hostgroup) +
		" AND hostname=" + bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port);

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool matches = rows[0][0] == to_string(expected_count);
	return matches;
}

int wait_for_blue_writer_pool_drain(MYSQL* admin, RDS_BGD_Cluster& cluster) {
	string query =
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0)=0 FROM stats_mysql_connection_pool WHERE srv_host=" +
		bgd_sql_quote(cluster.blue_writer.hostname);

	int rc = bgd_wait_for_condition(admin, query, kTimeoutSeconds);
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

int set_default_hostgroup(MYSQL* admin, int hostgroup) {
	vector<string> queries {
		"UPDATE mysql_users SET default_hostgroup=" + to_string(hostgroup) + " WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	return rc;
}

int create_blue_writer_pool(CommandLine& cl, MYSQL* admin, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;

	string add_server =
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,comment) VALUES (" +
		to_string(state.pool_hostgroup) + "," + bgd_sql_quote(cluster.blue_writer.hostname) +
		"," + to_string(cluster.blue_writer.port) + ",'ONLINE','BGD TAP blue pool router')";
	vector<string> queries {
		add_server,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int server_rc = execute_all(admin, queries);
	if (server_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure blue-pool routing hostgroup 974");
		return EXIT_FAILURE;
	}

	int user_rc = set_default_hostgroup(admin, state.pool_hostgroup);
	if (user_rc != EXIT_SUCCESS) {
		diag("Error: failed to route testuser through blue-pool hostgroup 974");
		return EXIT_FAILURE;
	}

	auto [echo_rc, echo] = connect_and_echo(cl);
	if (echo_rc != EXIT_SUCCESS || echo.find(cluster.blue_writer.ip) == string::npos) {
		diag("Error: failed to create a blue-writer connection through hostgroup 974");
		return EXIT_FAILURE;
	}

	int restore_rc = set_default_hostgroup(admin, state.hostgroups.blue_writer);
	if (restore_rc != EXIT_SUCCESS) {
		diag("Error: failed to restore testuser to writer hostgroup 970");
		return EXIT_FAILURE;
	}

	string query =
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0)>=1 FROM stats_mysql_connection_pool WHERE hostgroup=" +
		to_string(state.pool_hostgroup) + " AND srv_host=" + bgd_sql_quote(cluster.blue_writer.hostname);

	int pool_rc = bgd_wait_for_condition(admin, query, kTimeoutSeconds);
	return pool_rc;
}

/**
 * Configure wHG 970 and reach AVAILABLE.
 *
 * - Set writer read_only=0 and reader read_only=1 values.
 * - Publish AVAILABLE topology with one reader pair.
 * - Configure mysql_servers and mysql_aws_rds_bgd_hostgroups.
 * - Verify BGD status AVAILABLE.
 */
int test_bgd_status_available(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
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

	int blue_reader_0_rc = bgd_set_host_read_only_1(sim, cluster.blue_readers[0]);
	if (blue_reader_0_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=1 for the first simulated blue reader");
		return EXIT_FAILURE;
	}

	int blue_reader_1_rc = bgd_set_host_read_only_1(sim, cluster.blue_readers[1]);
	if (blue_reader_1_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=1 for the second simulated blue reader");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> topology = topology_with_reader_pair(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG 970");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0] };
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers, 0, 0);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups 970-973");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 970 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	ok(true, "BGD status for wHG 970 reports AVAILABLE");
	return EXIT_SUCCESS;
}

/**
 * Enter writer switchover initiated.
 *
 * - Publish SWITCHOVER_INITIATED.
 * - Verify WRITER_SWITCHOVER_INITIATED.
 * - Change simulated blue writer/reader read_only values.
 * - Verify BGD suppresses their normal placement changes.
 */
int test_switchover_initiated(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the SWITCHOVER_INITIATED probe sequence");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> topology = topology_with_reader_pair(cluster, "SWITCHOVER_INITIATED");
	int topology_rc = sim.topology_update(state.topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_INITIATED topology");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_INITIATED", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 970 did not reach WRITER_SWITCHOVER_INITIATED");
		return EXIT_FAILURE;
	}

	ok(true, "BGD status for wHG 970 reports WRITER_SWITCHOVER_INITIATED");

	int64_t writer_baseline = last_read_only_log_time(admin, cluster.blue_writer);
	state.reader_log_baseline = last_read_only_log_time(admin, cluster.blue_readers[0]);

	int writer_ro_rc = bgd_set_host_read_only_1(sim, cluster.blue_writer);
	if (writer_ro_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=1 for the simulated blue writer");
		return EXIT_FAILURE;
	}

	int reader_ro_rc = bgd_set_host_read_only_0(sim, cluster.blue_readers[0]);
	if (reader_ro_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=0 for the simulated blue reader");
		return EXIT_FAILURE;
	}

	auto [suppression_seq_rc, suppression_seq] = sim.probe_log_last_sequence();
	if (suppression_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the initiated suppression probe sequence");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> repeat_topology = topology_with_reader_pair(cluster, "SWITCHOVER_INITIATED");
	int repeat_rc = sim.topology_update(state.topology_endpoints, repeat_topology);
	if (repeat_rc != EXIT_SUCCESS) {
		diag("Error: failed to repeat SWITCHOVER_INITIATED topology");
		return EXIT_FAILURE;
	}

	int observation_rc = wait_for_green_observation(sim, suppression_seq, cluster);
	if (observation_rc != EXIT_SUCCESS) {
		diag("Error: BGD did not observe repeated SWITCHOVER_INITIATED topology");
		return EXIT_FAILURE;
	}

	int writer_suppression_rc =
		bgd_expect_no_read_only_log(admin, cluster.blue_writer, writer_baseline, kReadOnlyObservationMs);
	if (writer_suppression_rc != EXIT_SUCCESS) {
		diag("Error: blue-writer read_only monitoring was not suppressed during SWITCHOVER_INITIATED");
		return EXIT_FAILURE;
	}

	int reader_suppression_rc =
		bgd_expect_no_read_only_log(admin, cluster.blue_readers[0], state.reader_log_baseline, kReadOnlyObservationMs);
	if (reader_suppression_rc != EXIT_SUCCESS) {
		diag("Error: blue-reader read_only monitoring was not suppressed during SWITCHOVER_INITIATED");
		return EXIT_FAILURE;
	}

	bool writer_in_writer_hg = server_match_count(admin, hg.blue_writer, cluster.blue_writer, 1);
	bool writer_absent_reader_hg = server_match_count(admin, hg.blue_reader, cluster.blue_writer, 0);
	bool reader_in_reader_hg = server_match_count(admin, hg.blue_reader, cluster.blue_readers[0], 1);
	bool reader_absent_writer_hg = server_match_count(admin, hg.blue_writer, cluster.blue_readers[0], 0);
	ok(writer_in_writer_hg && writer_absent_reader_hg && reader_in_reader_hg && reader_absent_writer_hg,
		"SWITCHOVER_INITIATED suppresses blue writer and reader placement changes");
	return EXIT_SUCCESS;
}

/**
 * Enter writer switchover in progress.
 *
 * - Publish SWITCHOVER_IN_PROGRESS.
 * - Verify WRITER_SWITCHOVER_IN_PROGRESS.
 * - Verify the blue writer moves from hostgroup 970 to 971.
 * - Verify the mapped blue reader remains suppressed in hostgroup 971.
 */
int test_switchover_in_progress(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	vector<RDS_BGD_Topology_Row> topology = topology_with_reader_pair(cluster, "SWITCHOVER_IN_PROGRESS");
	int topology_rc = sim.topology_update(state.topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_PROGRESS topology");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 970 did not reach WRITER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	ok(true, "BGD status for wHG 970 reports WRITER_SWITCHOVER_IN_PROGRESS");

	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, true, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: blue writer did not move from hostgroup 970 to 971");
		return EXIT_FAILURE;
	}

	ok(true, "SWITCHOVER_IN_PROGRESS moves the blue writer from hostgroup 970 to 971");

	int reader_suppression_rc =
		bgd_expect_no_read_only_log(admin, cluster.blue_readers[0], state.reader_log_baseline, kReadOnlyObservationMs);
	if (reader_suppression_rc != EXIT_SUCCESS) {
		diag("Error: blue-reader read_only monitoring was not suppressed during SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	bool reader_in_reader_hg = server_match_count(admin, hg.blue_reader, cluster.blue_readers[0], 1);
	bool reader_absent_writer_hg = server_match_count(admin, hg.blue_writer, cluster.blue_readers[0], 0);
	ok(reader_in_reader_hg && reader_absent_writer_hg,
		"SWITCHOVER_IN_PROGRESS keeps the mapped blue reader suppressed in hostgroup 971");
	return EXIT_SUCCESS;
}

/**
 * Enter writer switchover post-processing.
 *
 * - Create a blue-writer pool through normal routing hostgroup 974.
 * - Publish SWITCHOVER_IN_POST_PROCESSING.
 * - Verify WRITER_SWITCHOVER_POST_PROCESSING.
 * - Verify writer restoration, blue-pool drain, and green backend routing.
 * - Repeat POST_PROCESSING and verify the post-cutover pool is not drained.
 */
int test_switchover_post_processing(CommandLine& cl, MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	int blue_pool_rc = create_blue_writer_pool(cl, admin, state);
	if (blue_pool_rc != EXIT_SUCCESS) {
		diag("Error: failed to establish the blue-writer pool before SWITCHOVER_IN_POST_PROCESSING");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> topology = topology_with_reader_pair(cluster, "SWITCHOVER_IN_POST_PROCESSING");
	int topology_rc = sim.topology_update(state.topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_POST_PROCESSING topology");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_POST_PROCESSING", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 970 did not reach WRITER_SWITCHOVER_POST_PROCESSING");
		return EXIT_FAILURE;
	}

	ok(true, "BGD status for wHG 970 reports WRITER_SWITCHOVER_POST_PROCESSING");

	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: blue writer did not return from hostgroup 971 to 970");
		return EXIT_FAILURE;
	}

	int reader_suppression_rc =
		bgd_expect_no_read_only_log(admin, cluster.blue_readers[0], state.reader_log_baseline, kReadOnlyObservationMs);
	if (reader_suppression_rc != EXIT_SUCCESS) {
		diag("Error: blue-reader read_only monitoring was not suppressed during SWITCHOVER_IN_POST_PROCESSING");
		return EXIT_FAILURE;
	}

	bool reader_in_reader_hg = server_match_count(admin, hg.blue_reader, cluster.blue_readers[0], 1);
	bool reader_absent_writer_hg = server_match_count(admin, hg.blue_writer, cluster.blue_readers[0], 0);
	ok(reader_in_reader_hg && reader_absent_writer_hg,
		"POST_PROCESSING restores the blue writer to hostgroup 970 and keeps the reader in 971");

	int pool_drain_rc = wait_for_blue_writer_pool_drain(admin, cluster);
	if (pool_drain_rc != EXIT_SUCCESS) {
		diag("Error: POST_PROCESSING did not drain the old blue-writer pool");
		return EXIT_FAILURE;
	}

	ok(true, "POST_PROCESSING drains the old blue-writer connection pool");

	auto [echo_rc, echo] = connect_and_echo(cl);
	if (echo_rc != EXIT_SUCCESS) {
		diag("Error: failed to connect through wHG 970 after POST_PROCESSING");
		return EXIT_FAILURE;
	}

	bool green_routing = echo.find(cluster.green_writer.ip) != string::npos;
	ok(green_routing, "POST_PROCESSING routes the blue writer hostname to the green backend IP");

	auto [pool_before_rc, pool_before] = bgd_connection_pool_count(admin, hg.blue_writer, cluster.blue_writer.hostname);
	if (pool_before_rc != EXIT_SUCCESS || pool_before < 1) {
		diag("Error: failed to establish the post-cutover pool before repeated POST_PROCESSING");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the repeated POST_PROCESSING probe sequence");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> repeat_topology = topology_with_reader_pair(cluster, "SWITCHOVER_IN_POST_PROCESSING");
	int repeat_rc = sim.topology_update(state.topology_endpoints, repeat_topology);
	if (repeat_rc != EXIT_SUCCESS) {
		diag("Error: failed to repeat SWITCHOVER_IN_POST_PROCESSING topology");
		return EXIT_FAILURE;
	}

	int observation_rc = wait_for_green_observation(sim, seq, cluster);
	if (observation_rc != EXIT_SUCCESS) {
		diag("Error: BGD did not observe repeated POST_PROCESSING topology");
		return EXIT_FAILURE;
	}

	auto [pool_after_rc, pool_after] = bgd_connection_pool_count(admin, hg.blue_writer, cluster.blue_writer.hostname);
	if (pool_after_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the pool after repeated POST_PROCESSING");
		return EXIT_FAILURE;
	}

	ok(pool_after >= pool_before, "repeated POST_PROCESSING does not drain the post-cutover connection pool");
	return EXIT_SUCCESS;
}

int main() {
	plan(11);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	RDS_BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: set writer/reader read_only values and publish AVAILABLE topology.
	// ProxySQL: configure BGD hostgroups 970-973.
	// Verify: BGD status for wHG 970 reports AVAILABLE.
	if (test_bgd_status_available(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish SWITCHOVER_INITIATED and reverse one blue writer/reader read_only pair.
	// Verify: BGD status is WRITER_SWITCHOVER_INITIATED and placement changes remain suppressed.
	if (test_switchover_initiated(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish SWITCHOVER_IN_PROGRESS topology.
	// Verify: BGD status for wHG 970 reports WRITER_SWITCHOVER_IN_PROGRESS.
	// Verify: the blue writer moves from hostgroup 970 to 971.
	// Verify: the mapped blue reader remains suppressed in hostgroup 971.
	if (test_switchover_in_progress(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: create a blue-writer pool through normal routing hostgroup 974.
	// Simulator: publish SWITCHOVER_IN_POST_PROCESSING twice.
	// Verify: writer placement is restored, the old pool drains, and routing reaches the green IP.
	// Verify: repeated POST_PROCESSING preserves a connection created after cutover.
	if (test_switchover_post_processing(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
