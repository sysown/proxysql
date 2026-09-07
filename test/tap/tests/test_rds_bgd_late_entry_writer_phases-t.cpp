/**
 * @file test_rds_bgd_late_entry_writer_phases-t.cpp
 * @brief Starting a BGD worker from each writer switchover phase.
 *
 * Steps:
 *
 * 1. Start wHG 1170 when topology already reports SWITCHOVER_INITIATED and
 *    verify read_only suppression without blue-writer demotion.
 * 2. Start wHG 1180 when topology already reports SWITCHOVER_IN_PROGRESS and
 *    verify prerequisite construction before blue-writer demotion.
 * 3. Create a blue-writer pool, then start wHG 1190 when topology already
 *    reports SWITCHOVER_IN_POST_PROCESSING.
 * 4. Verify green routing, blue-pool drain, writer placement, and reader
 *    read_only suppression from the first POST_PROCESSING observation.
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
	RDS_BGD_Cluster initiated_cluster { bgd_cluster_init() };
	BGD_Hostgroups initiated_hg { 1170, 1171, 1172, 1173 };
	vector<Endpoint> initiated_endpoints { initiated_cluster.get_endpoints() };

	RDS_BGD_Cluster progress_cluster { bgd_cluster_2_init() };
	BGD_Hostgroups progress_hg { 1180, 1181, 1182, 1183 };
	vector<Endpoint> progress_endpoints { progress_cluster.get_endpoints() };

	RDS_BGD_Cluster post_cluster { bgd_cluster_3_init() };
	BGD_Hostgroups post_hg { 1190, 1191, 1192, 1193 };
	vector<Endpoint> post_endpoints { post_cluster.get_endpoints() };
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

	if (bgd_set_host_read_only_1(sim, cluster.blue_readers[1]) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	if (bgd_set_host_read_only_1(sim, cluster.green_readers[0]) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int publish_topology(BGD_Simulator& sim, vector<Endpoint> endpoints, RDS_BGD_Cluster& cluster, string status) {
	vector<BGD_Topology_Row> topology = topology_with_reader_pair(cluster, status);

	int rc = sim.topology_update(endpoints, topology);
	return rc;
}

int wait_for_green_writer(BGD_Simulator& sim, uint64_t sequence, RDS_BGD_Cluster& cluster) {
	auto [probe_rc, probe] =
		sim.wait_for_probe_log(sequence, cluster.green_writer.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
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

int wait_for_blue_writer_pool_drain(MYSQL* admin, RDS_BGD_Cluster& cluster) {
	string query =
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0)=0 FROM stats_mysql_connection_pool WHERE srv_host=" +
		bgd_sql_quote(cluster.blue_writer.hostname);

	int rc = bgd_wait_for_condition(admin, query, kTimeoutSeconds);
	return rc;
}

int configure_servers_without_worker(MYSQL* admin, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg) {
	vector<string> config_queries {
		"INSERT INTO mysql_replication_hostgroups(writer_hostgroup,reader_hostgroup) VALUES (" +
			to_string(hg.blue_writer) + "," + to_string(hg.blue_reader) + ")",
		"SET mysql-monitor_username='testuser'",
		"SET mysql-monitor_password='testuser'",
		"SET mysql-monitor_enabled='true'",
		"SET mysql-monitor_read_only_interval=100",
		"SET mysql-monitor_aws_rds_topology_discovery_interval=1",
		"SET mysql-aws_blue_green_deployment_auto_discovery='false'",
		"UPDATE mysql_users SET default_hostgroup=" + to_string(hg.blue_writer) + " WHERE username='testuser'",
	};

	int config_rc = execute_all(admin, config_queries);
	if (config_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	int blue_rc = bgd_admin_add_servers(admin, cluster, hg, blue_servers, false, 0);
	if (blue_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0] };
	int green_rc = bgd_admin_add_servers(admin, cluster, hg, green_servers, true, 0);
	if (green_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<string> load_queries {
		"LOAD MYSQL VARIABLES TO RUNTIME",
		"LOAD MYSQL USERS TO RUNTIME",
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int load_rc = execute_all(admin, load_queries);
	if (load_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int enable_bgd_worker(MYSQL* admin, BGD_Hostgroups& hg) {
	string insert_bgd =
		"INSERT INTO mysql_aws_rds_bgd_hostgroups("
		"writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,"
		"active,writer_is_also_reader,check_interval_ms,check_timeout_ms,comment) VALUES (" +
		to_string(hg.blue_writer) + "," + to_string(hg.blue_reader) + "," +
		to_string(hg.green_writer) + "," + to_string(hg.green_reader) +
		",1,0,100,800,'BGD TAP late writer phase')";
	vector<string> queries {
		insert_bgd,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	return rc;
}

/**
 * Start wHG 1170 from SWITCHOVER_INITIATED.
 *
 * - Publish SWITCHOVER_INITIATED before configuring the BGD row.
 * - Verify WRITER_SWITCHOVER_INITIATED without blue-writer demotion.
 * - Change simulated writer/reader read_only values.
 * - Verify read_only monitoring is suppressed for deployment members.
 */
int test_first_initiated(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.initiated_cluster;
	BGD_Hostgroups& hg = state.initiated_hg;

	int read_only_rc = configure_read_only_values(sim, cluster);
	if (read_only_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated read_only values for wHG 1170");
		return EXIT_FAILURE;
	}

	auto [publish_seq_rc, publish_seq] = sim.probe_log_last_sequence();
	if (publish_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the first INITIATED probe sequence");
		return EXIT_FAILURE;
	}

	int topology_rc = publish_topology(sim, state.initiated_endpoints, cluster, "SWITCHOVER_INITIATED");
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_INITIATED topology for wHG 1170");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0] };
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups 1170-1173");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_INITIATED", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1170 did not reach WRITER_SWITCHOVER_INITIATED");
		return EXIT_FAILURE;
	}

	int probe_rc = wait_for_green_writer(sim, publish_seq, cluster);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: first INITIATED observation did not probe the green writer");
		return EXIT_FAILURE;
	}

	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: first INITIATED observation changed blue-writer placement");
		return EXIT_FAILURE;
	}

	ok(true, "first SWITCHOVER_INITIATED observation keeps the blue writer in hostgroup 1170");

	int64_t writer_log = last_read_only_log_time(admin, cluster.blue_writer);
	int64_t reader_log = last_read_only_log_time(admin, cluster.blue_readers[0]);
	if (writer_log < 0 || reader_log < 0) {
		diag("Error: failed to read INITIATED read_only log baselines");
		return EXIT_FAILURE;
	}

	auto [suppression_seq_rc, suppression_seq] = sim.probe_log_last_sequence();
	if (suppression_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the INITIATED suppression probe sequence");
		return EXIT_FAILURE;
	}

	int writer_update_rc = bgd_set_host_read_only_1(sim, cluster.blue_writer);
	if (writer_update_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=1 for the simulated blue writer");
		return EXIT_FAILURE;
	}

	int reader_update_rc = bgd_set_host_read_only_0(sim, cluster.blue_readers[0]);
	if (reader_update_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=0 for the simulated blue reader");
		return EXIT_FAILURE;
	}

	int suppression_probe_rc = wait_for_green_writer(sim, suppression_seq, cluster);
	if (suppression_probe_rc != EXIT_SUCCESS) {
		diag("Error: INITIATED suppression check did not observe the green writer");
		return EXIT_FAILURE;
	}

	int writer_suppression_rc =
		bgd_expect_no_read_only_log(admin, cluster.blue_writer, writer_log, kReadOnlyObservationMs);
	if (writer_suppression_rc != EXIT_SUCCESS) {
		diag("Error: blue-writer read_only monitoring was not suppressed on first SWITCHOVER_INITIATED observation");
		return EXIT_FAILURE;
	}

	int reader_suppression_rc =
		bgd_expect_no_read_only_log(admin, cluster.blue_readers[0], reader_log, kReadOnlyObservationMs);
	if (reader_suppression_rc != EXIT_SUCCESS) {
		diag("Error: blue-reader read_only monitoring was not suppressed on first SWITCHOVER_INITIATED observation");
		return EXIT_FAILURE;
	}

	bool reader_online = runtime_server_match(admin, hg.blue_reader, cluster.blue_readers[0], "ONLINE");
	ok(reader_online, "first SWITCHOVER_INITIATED observation suppresses writer and reader read_only placement changes");
	return EXIT_SUCCESS;
}

/**
 * Start wHG 1180 from SWITCHOVER_IN_PROGRESS.
 *
 * - Publish SWITCHOVER_IN_PROGRESS before configuring the BGD row.
 * - Verify WRITER_SWITCHOVER_IN_PROGRESS and blue-writer demotion.
 * - Change the simulated blue-reader read_only value.
 * - Verify read_only monitoring remains suppressed after demotion.
 */
int test_first_in_progress(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.progress_cluster;
	BGD_Hostgroups& hg = state.progress_hg;

	int read_only_rc = configure_read_only_values(sim, cluster);
	if (read_only_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated read_only values for wHG 1180");
		return EXIT_FAILURE;
	}

	auto [publish_seq_rc, publish_seq] = sim.probe_log_last_sequence();
	if (publish_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the first IN_PROGRESS probe sequence");
		return EXIT_FAILURE;
	}

	int topology_rc = publish_topology(sim, state.progress_endpoints, cluster, "SWITCHOVER_IN_PROGRESS");
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_PROGRESS topology for wHG 1180");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0] };
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups 1180-1183");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1180 did not reach WRITER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	int probe_rc = wait_for_green_writer(sim, publish_seq, cluster);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: first IN_PROGRESS observation did not probe the green writer");
		return EXIT_FAILURE;
	}

	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, true, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: first IN_PROGRESS observation did not demote the blue writer");
		return EXIT_FAILURE;
	}

	ok(true, "first SWITCHOVER_IN_PROGRESS observation moves the blue writer from hostgroup 1180 to 1181");

	int64_t reader_log = last_read_only_log_time(admin, cluster.blue_readers[0]);
	if (reader_log < 0) {
		diag("Error: failed to read the IN_PROGRESS blue-reader log baseline");
		return EXIT_FAILURE;
	}

	auto [suppression_seq_rc, suppression_seq] = sim.probe_log_last_sequence();
	if (suppression_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the IN_PROGRESS suppression probe sequence");
		return EXIT_FAILURE;
	}

	int reader_update_rc = bgd_set_host_read_only_0(sim, cluster.blue_readers[0]);
	if (reader_update_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=0 for the simulated blue reader");
		return EXIT_FAILURE;
	}

	int suppression_probe_rc = wait_for_green_writer(sim, suppression_seq, cluster);
	if (suppression_probe_rc != EXIT_SUCCESS) {
		diag("Error: IN_PROGRESS suppression check did not observe the green writer");
		return EXIT_FAILURE;
	}

	int reader_suppression_rc =
		bgd_expect_no_read_only_log(admin, cluster.blue_readers[0], reader_log, kReadOnlyObservationMs);
	if (reader_suppression_rc != EXIT_SUCCESS) {
		diag("Error: blue-reader read_only monitoring was not suppressed on first SWITCHOVER_IN_PROGRESS observation");
		return EXIT_FAILURE;
	}

	bool reader_online = runtime_server_match(admin, hg.blue_reader, cluster.blue_readers[0], "ONLINE");
	ok(reader_online, "first SWITCHOVER_IN_PROGRESS observation suppresses blue-reader read_only placement changes");
	return EXIT_SUCCESS;
}

/**
 * Start wHG 1190 from SWITCHOVER_IN_POST_PROCESSING.
 *
 * - Publish POST_PROCESSING and create a blue-writer pool before enabling BGD.
 * - Verify WRITER_SWITCHOVER_POST_PROCESSING and restored blue-writer placement.
 * - Verify the old blue pool drains and new connections route to green.
 * - Verify mapped blue readers remain under read_only suppression.
 */
int test_first_post_processing(CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.post_cluster;
	BGD_Hostgroups& hg = state.post_hg;

	int read_only_rc = configure_read_only_values(sim, cluster);
	if (read_only_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated read_only values for wHG 1190");
		return EXIT_FAILURE;
	}

	auto [publish_seq_rc, publish_seq] = sim.probe_log_last_sequence();
	if (publish_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the first POST_PROCESSING probe sequence");
		return EXIT_FAILURE;
	}

	int topology_rc = publish_topology(sim, state.post_endpoints, cluster, "SWITCHOVER_IN_POST_PROCESSING");
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_POST_PROCESSING topology for wHG 1190");
		return EXIT_FAILURE;
	}

	int servers_rc = configure_servers_without_worker(admin, cluster, hg);
	if (servers_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure hostgroups 1190-1193 without a BGD worker");
		return EXIT_FAILURE;
	}

	auto [blue_echo_rc, blue_echo] = connect_and_echo(cl);
	if (blue_echo_rc != EXIT_SUCCESS || blue_echo.find(cluster.blue_writer.ip) == string::npos) {
		diag("Error: failed to establish the pre-worker blue-writer pool");
		return EXIT_FAILURE;
	}

	auto [pool_before_rc, pool_before] = bgd_connection_pool_count(admin, hg.blue_writer, cluster.blue_writer.hostname);
	if (pool_before_rc != EXIT_SUCCESS || pool_before < 1) {
		diag("Error: blue-writer pool is empty before enabling wHG 1190");
		return EXIT_FAILURE;
	}

	int worker_rc = enable_bgd_worker(admin, hg);
	if (worker_rc != EXIT_SUCCESS) {
		diag("Error: failed to enable BGD worker for wHG 1190");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_POST_PROCESSING", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1190 did not reach WRITER_SWITCHOVER_POST_PROCESSING");
		return EXIT_FAILURE;
	}

	int probe_rc = wait_for_green_writer(sim, publish_seq, cluster);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: first POST_PROCESSING observation did not probe the green writer");
		return EXIT_FAILURE;
	}

	ok(true, "first POST_PROCESSING observation reports WRITER_SWITCHOVER_POST_PROCESSING for wHG 1190");

	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: first POST_PROCESSING observation did not keep the blue writer in hostgroup 1190");
		return EXIT_FAILURE;
	}

	int drain_rc = wait_for_blue_writer_pool_drain(admin, cluster);
	if (drain_rc != EXIT_SUCCESS) {
		diag("Error: first POST_PROCESSING observation did not drain the old blue-writer pool");
		return EXIT_FAILURE;
	}

	auto [green_echo_rc, green_echo] = connect_and_echo(cl);
	bool green_routing = green_echo_rc == EXIT_SUCCESS && green_echo.find(cluster.green_writer.ip) != string::npos;
	ok(green_routing,
		"first POST_PROCESSING observation restores hostgroup 1190, drains its blue pool, and routes to green");

	int64_t reader_log = last_read_only_log_time(admin, cluster.blue_readers[0]);
	if (reader_log < 0) {
		diag("Error: failed to read the POST_PROCESSING blue-reader log baseline");
		return EXIT_FAILURE;
	}

	auto [suppression_seq_rc, suppression_seq] = sim.probe_log_last_sequence();
	if (suppression_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the POST_PROCESSING suppression probe sequence");
		return EXIT_FAILURE;
	}

	int reader_update_rc = bgd_set_host_read_only_0(sim, cluster.blue_readers[0]);
	if (reader_update_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=0 for the simulated blue reader");
		return EXIT_FAILURE;
	}

	int suppression_probe_rc = wait_for_green_writer(sim, suppression_seq, cluster);
	if (suppression_probe_rc != EXIT_SUCCESS) {
		diag("Error: POST_PROCESSING suppression check did not observe the green writer");
		return EXIT_FAILURE;
	}

	int reader_suppression_rc =
		bgd_expect_no_read_only_log(admin, cluster.blue_readers[0], reader_log, kReadOnlyObservationMs);
	if (reader_suppression_rc != EXIT_SUCCESS) {
		diag("Error: blue-reader read_only monitoring was not suppressed on first POST_PROCESSING observation");
		return EXIT_FAILURE;
	}

	bool reader_online = runtime_server_match(admin, hg.blue_reader, cluster.blue_readers[0], "ONLINE");
	ok(reader_online, "first POST_PROCESSING observation keeps the mapped blue reader ONLINE in hostgroup 1191");
	return EXIT_SUCCESS;
}

int main() {
	plan(7);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: publish SWITCHOVER_INITIATED before wHG 1170 is configured.
	// Verify: first observation reports WRITER_SWITCHOVER_INITIATED without writer demotion.
	// Verify: writer and reader read_only placement changes are suppressed.
	if (test_first_initiated(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish SWITCHOVER_IN_PROGRESS before wHG 1180 is configured.
	// Verify: first observation reports WRITER_SWITCHOVER_IN_PROGRESS and moves the writer to hostgroup 1181.
	// Verify: blue-reader read_only placement changes are suppressed.
	if (test_first_in_progress(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish SWITCHOVER_IN_POST_PROCESSING before wHG 1190 is configured.
	// Client: create a blue-writer pool before enabling the BGD worker.
	// Verify: first observation drains the pool, routes to green, restores writer placement, and retains reader placement.
	if (test_first_post_processing(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
