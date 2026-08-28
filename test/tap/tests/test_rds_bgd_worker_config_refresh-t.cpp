/**
 * @file test_rds_bgd_worker_config_refresh-t.cpp
 * @brief Refreshing an active BGD worker after server and scalar configuration changes.
 *
 * Steps:
 *
 * 1. Configure BGD hostgroups 1370-1373 and reach `AVAILABLE`.
 * 2. Change `weight` and `comment` and verify that discovery does not restart.
 * 3. Change green-writer TLS and verify that metadata probes use the new value.
 * 4. Replace green-reader membership and verify that discovery does not restart.
 * 5. Move the green writer offline and online and verify that direct metadata
 *    probing stops and resumes without a table-check restart.
 * 6. Change `check_interval_ms` and verify the metadata probe cadence.
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
const uint32_t kRefreshedCheckIntervalMs = 1000;
const uint32_t kMinimumProbeIntervalMs = 500;
const uint32_t kMaximumProbeIntervalMs = 1500;

struct TestState {
	RDS_BGD_Cluster cluster { bgd_cluster_2_init() };
	BGD_Hostgroups hostgroups { 1370, 1371, 1372, 1373 };
	vector<Endpoint> topology_endpoints { cluster.get_endpoints() };
	uint64_t available_probe_sequence { 0 };
	string topology_discovery_interval {};
	bool topology_discovery_interval_saved { false };
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

int restore_topology_discovery_interval(MYSQL* admin, TestState& state) {
	if (!state.topology_discovery_interval_saved) {
		return EXIT_SUCCESS;
	}

	vector<string> queries {
		"SET mysql-monitor_aws_rds_topology_discovery_interval=" + state.topology_discovery_interval,
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	return rc;
}

int cleanup(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	int admin_rc = bgd_admin_cleanup(admin);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to clean ProxySQL BGD test state");
	}

	int discovery_rc = restore_topology_discovery_interval(admin, state);
	if (discovery_rc != EXIT_SUCCESS) {
		diag("Error: failed to restore mysql-monitor_aws_rds_topology_discovery_interval");
	}
	mysql_close(admin);

	int simulator_rc = sim.cleanup();
	if (simulator_rc != EXIT_SUCCESS) {
		diag("Error: failed to clean SQLite3-server simulator state");
	}

	if (admin_rc != EXIT_SUCCESS || discovery_rc != EXIT_SUCCESS || simulator_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int disable_topology_discovery_probes(MYSQL* admin, TestState& state) {
	string query =
		"SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='mysql-monitor_aws_rds_topology_discovery_interval'";

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		diag("Error: failed to read mysql-monitor_aws_rds_topology_discovery_interval");
		return EXIT_FAILURE;
	}

	state.topology_discovery_interval = rows[0][0];
	state.topology_discovery_interval_saved = true;

	vector<string> queries {
		"SET mysql-monitor_aws_rds_topology_discovery_interval=0",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};

	int disable_rc = execute_all(admin, queries);
	if (disable_rc != EXIT_SUCCESS) {
		diag("Error: failed to disable automatic AWS topology discovery");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int wait_for_server_status(MYSQL* admin, int hostgroup, RDS_BGD_Host& host, string status) {
	string query =
		"SELECT COUNT(*)=1 FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hostgroup) +
		" AND hostname=" + bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port) +
		" AND status=" + bgd_sql_quote(status);

	int rc = bgd_wait_for_condition(admin, query, kTimeoutSeconds);
	return rc;
}

/**
 * Configure BGD hostgroups 1370-1373 and change ignored server fields.
 *
 * - Set `read_only=0` for the simulated blue and green writers.
 * - Publish `AVAILABLE` topology and configure the explicit BGD row.
 * - Verify that the runtime BGD row reaches `AVAILABLE`.
 * - Change blue-writer `weight` and `comment`.
 * - Verify that the active worker does not restart with a table check.
 */
int test_irrelevant_server_fields(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	// Set read_only=0 for the simulated blue and green writers.
	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated writer read_only values");
		return EXIT_FAILURE;
	}

	// Publish AVAILABLE topology.
	vector<RDS_BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology");
		return EXIT_FAILURE;
	}

	// Configure mysql_servers and mysql_aws_rds_bgd_hostgroups.
	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0] };

	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers, 0, 0);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure mysql_servers and mysql_aws_rds_bgd_hostgroups");
		return EXIT_FAILURE;
	}

	// Disable automatic AWS topology discovery so its metadata queries are not
	// mistaken for probes from the explicitly configured BGD worker.
	int discovery_rc = disable_topology_discovery_probes(admin, state);
	if (discovery_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	// Wait for the runtime BGD row to report AVAILABLE.
	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: runtime BGD status did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	ok(true, "BGD status for wHG 1370 reports AVAILABLE");

	// Record a green metadata probe before changing ignored server fields.
	auto [probe_seq_rc, probe_seq] = sim.probe_log_last_sequence();
	if (probe_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before the AVAILABLE metadata probe");
		return EXIT_FAILURE;
	}

	auto [probe_rc, probe] = sim.wait_for_probe_log(
		probe_seq, cluster.green_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0
	);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: green writer did not receive the AVAILABLE metadata probe");
		return EXIT_FAILURE;
	}
	state.available_probe_sequence = probe.sequence_id;

	// Change weight and comment, which are not BGD worker inputs.
	string update_server =
		"UPDATE mysql_servers SET weight=weight+7,comment='BGD TAP ignored fields' WHERE hostgroup_id=" +
		to_string(hg.blue_writer) + " AND hostname=" + bgd_sql_quote(cluster.blue_writer.hostname) +
		" AND port=" + to_string(cluster.blue_writer.port);
	vector<string> queries {
		update_server,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int update_rc = execute_all(admin, queries);
	if (update_rc != EXIT_SUCCESS) {
		diag("Error: failed to update blue-writer weight and comment");
		return EXIT_FAILURE;
	}

	int no_table_rc = bgd_expect_no_table_check(sim, state.available_probe_sequence, state.topology_endpoints, kNegativeProbeTimeoutMs);
	if (no_table_rc != EXIT_SUCCESS) {
		diag("Error: weight or comment change restarted BGD discovery");
		return EXIT_FAILURE;
	}

	ok(true, "weight and comment changes do not restart BGD discovery for wHG 1370");
	return EXIT_SUCCESS;
}

/**
 * Refresh green-writer TLS for writer hostgroup 1370.
 *
 * - Set `use_ssl=1` on the configured green writer.
 * - Load `mysql_servers` to runtime.
 * - Verify that the next green-writer metadata probe uses TLS.
 * - Verify that discovery does not restart.
 */
int test_tls_refresh(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	// Record the probe sequence before changing green-writer TLS.
	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before the TLS refresh");
		return EXIT_FAILURE;
	}

	// Set use_ssl=1 on the green writer and load mysql_servers to runtime.
	string update_tls =
		"UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id=" + to_string(hg.green_writer) +
		" AND hostname=" + bgd_sql_quote(cluster.green_writer.hostname) +
		" AND port=" + to_string(cluster.green_writer.port);
	vector<string> queries {
		update_tls,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int update_rc = execute_all(admin, queries);
	if (update_rc != EXIT_SUCCESS) {
		diag("Error: failed to set use_ssl=1 for the green writer");
		return EXIT_FAILURE;
	}

	// Wait for the active worker to use TLS without starting a table check.
	auto [probe_rc, probe] = sim.wait_for_probe_log(
		seq, cluster.green_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 1
	);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: green-writer metadata probe did not use TLS after refresh");
		return EXIT_FAILURE;
	}

	int no_table_rc = bgd_expect_no_table_check(sim, seq, state.topology_endpoints, kNegativeProbeTimeoutMs);
	if (no_table_rc != EXIT_SUCCESS) {
		diag("Error: TLS refresh restarted BGD discovery");
		return EXIT_FAILURE;
	}

	ok(true, "use_ssl=1 refreshes green-writer metadata probes without a table-check restart");
	return EXIT_SUCCESS;
}

/**
 * Replace green-reader membership for writer hostgroup 1370.
 *
 * - Add the second green reader to hostgroup 1373.
 * - Delete the first green reader from hostgroup 1373.
 * - Verify that discovery does not restart.
 */
int test_green_membership_refresh(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	// Record the probe sequence before changing green-reader membership.
	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before the membership refresh");
		return EXIT_FAILURE;
	}

	// Replace the first green reader with the second green reader.
	string add_reader =
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,use_ssl,comment) VALUES (" +
		to_string(hg.green_reader) + "," + bgd_sql_quote(cluster.green_readers[1].hostname) +
		"," + to_string(cluster.green_readers[1].port) + ",'ONLINE',0,'BGD TAP green reader')";
	string delete_reader =
		"DELETE FROM mysql_servers WHERE hostgroup_id=" + to_string(hg.green_reader) +
		" AND hostname=" + bgd_sql_quote(cluster.green_readers[0].hostname) +
		" AND port=" + to_string(cluster.green_readers[0].port);
	vector<string> queries {
		add_reader,
		delete_reader,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int update_rc = execute_all(admin, queries);
	if (update_rc != EXIT_SUCCESS) {
		diag("Error: failed to replace green-reader membership");
		return EXIT_FAILURE;
	}

	int no_table_rc = bgd_expect_no_table_check(sim, seq, state.topology_endpoints, kNegativeProbeTimeoutMs);
	if (no_table_rc != EXIT_SUCCESS) {
		diag("Error: green-reader membership refresh restarted BGD discovery");
		return EXIT_FAILURE;
	}

	ok(true, "green-reader membership refresh does not restart BGD discovery for wHG 1370");
	return EXIT_SUCCESS;
}

/**
 * Refresh green-writer eligibility for writer hostgroup 1370.
 *
 * - Move the green writer to `OFFLINE_SOFT`.
 * - Verify that direct metadata probing stops without a table-check restart.
 * - Return the green writer to `ONLINE`.
 * - Verify that TLS metadata probing resumes without a table-check restart.
 */
int test_server_eligibility_refresh(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	// Record the probe sequence before changing green-writer eligibility.
	auto [refresh_seq_rc, refresh_seq] = sim.probe_log_last_sequence();
	if (refresh_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before the OFFLINE_SOFT refresh");
		return EXIT_FAILURE;
	}

	// Move the green writer to OFFLINE_SOFT.
	string set_offline =
		"UPDATE mysql_servers SET status='OFFLINE_SOFT' WHERE hostgroup_id=" + to_string(hg.green_writer) +
		" AND hostname=" + bgd_sql_quote(cluster.green_writer.hostname) +
		" AND port=" + to_string(cluster.green_writer.port);
	vector<string> offline_queries {
		set_offline,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int offline_rc = execute_all(admin, offline_queries);
	if (offline_rc != EXIT_SUCCESS) {
		diag("Error: failed to set the green writer OFFLINE_SOFT");
		return EXIT_FAILURE;
	}

	int status_rc = wait_for_server_status(admin, hg.green_writer, cluster.green_writer, "OFFLINE_SOFT");
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: runtime green writer did not reach OFFLINE_SOFT");
		return EXIT_FAILURE;
	}

	// Wait for the worker to apply the refreshed server list and return to its eligible blue writer.
	auto [blue_probe_rc, blue_probe] = sim.wait_for_probe_log(
		refresh_seq, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0
	);
	if (blue_probe_rc != EXIT_SUCCESS) {
		diag("Error: OFFLINE_SOFT refresh did not return metadata probing to the blue writer");
		return EXIT_FAILURE;
	}

	int no_metadata_rc =
		bgd_expect_no_metadata_probe(sim, blue_probe.sequence_id, cluster.green_writer.endpoint(), kNegativeProbeTimeoutMs);
	if (no_metadata_rc != EXIT_SUCCESS) {
		diag("Error: OFFLINE_SOFT green writer continued receiving metadata probes");
		return EXIT_FAILURE;
	}

	int offline_no_table_rc =
		bgd_expect_no_table_check(sim, refresh_seq, state.topology_endpoints, kNegativeProbeTimeoutMs);
	if (offline_no_table_rc != EXIT_SUCCESS) {
		diag("Error: OFFLINE_SOFT refresh restarted BGD discovery");
		return EXIT_FAILURE;
	}

	ok(true, "OFFLINE_SOFT stops green-writer metadata probes without a table-check restart");

	// Return the green writer to ONLINE.
	auto [online_seq_rc, online_seq] = sim.probe_log_last_sequence();
	if (online_seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before the ONLINE refresh");
		return EXIT_FAILURE;
	}

	string set_online =
		"UPDATE mysql_servers SET status='ONLINE' WHERE hostgroup_id=" + to_string(hg.green_writer) +
		" AND hostname=" + bgd_sql_quote(cluster.green_writer.hostname) +
		" AND port=" + to_string(cluster.green_writer.port);
	vector<string> online_queries {
		set_online,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int online_rc = execute_all(admin, online_queries);
	if (online_rc != EXIT_SUCCESS) {
		diag("Error: failed to return the green writer to ONLINE");
		return EXIT_FAILURE;
	}

	auto [probe_rc, probe] = sim.wait_for_probe_log(
		online_seq, cluster.green_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 1
	);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: ONLINE green writer did not resume TLS metadata probes");
		return EXIT_FAILURE;
	}

	int online_no_table_rc = bgd_expect_no_table_check(sim, online_seq, state.topology_endpoints, kNegativeProbeTimeoutMs);
	if (online_no_table_rc != EXIT_SUCCESS) {
		diag("Error: ONLINE refresh restarted BGD discovery");
		return EXIT_FAILURE;
	}

	ok(true, "ONLINE resumes green-writer TLS metadata probes without a table-check restart");
	return EXIT_SUCCESS;
}

/**
 * Refresh the configured polling interval for writer hostgroup 1370.
 *
 * - Set `check_interval_ms=1000`.
 * - Load the BGD configuration to runtime.
 * - Publish empty topology so the worker uses its configured baseline interval.
 * - Verify that the next metadata probe occurs between 500 and 1500 milliseconds.
 * - Verify that the configuration refresh does not restart with a table check.
 */
int test_check_interval_refresh(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	// Record the probe sequence before changing check_interval_ms.
	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before the check_interval_ms refresh");
		return EXIT_FAILURE;
	}

	// Set check_interval_ms=1000 and load the BGD configuration to runtime.
	string update_bgd =
		"UPDATE mysql_aws_rds_bgd_hostgroups SET check_interval_ms=" +
		to_string(kRefreshedCheckIntervalMs) + " WHERE writer_hostgroup=" +
		to_string(hg.blue_writer);
	vector<string> queries {
		update_bgd,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int update_rc = execute_all(admin, queries);
	if (update_rc != EXIT_SUCCESS) {
		diag("Error: failed to update check_interval_ms");
		return EXIT_FAILURE;
	}

	// Publish empty topology so the worker leaves AVAILABLE and uses check_interval_ms.
	int topology_rc = sim.topology_delete(state.topology_endpoints);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish empty topology before checking the probe interval");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "NONE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status did not reach NONE before checking the probe interval");
		return EXIT_FAILURE;
	}

	auto [baseline_rc, baseline] = sim.probe_log_last_sequence();
	if (baseline_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence after BGD reached NONE");
		return EXIT_FAILURE;
	}

	// Consume the immediate refresh probe and the first blue probe after the worker reaches NONE.
	auto [first_rc, first_probe] =
		sim.wait_for_probe_log(baseline, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, -1);
	if (first_rc != EXIT_SUCCESS) {
		diag("Error: failed to observe the first blue metadata probe after the check_interval_ms refresh");
		return EXIT_FAILURE;
	}

	auto [settled_rc, settled_probe] =
		sim.wait_for_probe_log(first_probe.sequence_id, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, -1);
	if (settled_rc != EXIT_SUCCESS) {
		diag("Error: failed to observe the settled blue metadata probe after the check_interval_ms refresh");
		return EXIT_FAILURE;
	}

	// Measure the steady-state interval between consecutive blue metadata probes.
	unsigned long long interval_start = monotonic_time();
	auto [next_rc, next_probe] = sim.wait_for_probe_log(
		settled_probe.sequence_id, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kMaximumProbeIntervalMs, -1
	);
	if (next_rc != EXIT_SUCCESS) {
		diag("Error: metadata probing did not occur within 1.5 times check_interval_ms");
		return EXIT_FAILURE;
	}

	unsigned long long elapsed_ms = (monotonic_time() - interval_start) / 1000;
	if (elapsed_ms < kMinimumProbeIntervalMs) {
		diag("Error: consecutive metadata probes occurred before half of check_interval_ms elapsed");
		return EXIT_FAILURE;
	}

	int no_table_rc = bgd_expect_no_table_check(sim, seq, state.topology_endpoints, kNegativeProbeTimeoutMs);
	if (no_table_rc != EXIT_SUCCESS) {
		diag("Error: check_interval_ms refresh restarted discovery");
		return EXIT_FAILURE;
	}

	ok(true, "check_interval_ms=1000 schedules the next metadata probe between 500 and 1500 milliseconds");
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

	// Simulator: set blue/green writers to read_only=0 and publish AVAILABLE topology.
	// ProxySQL: configure BGD hostgroups 1370-1373, then change blue-writer weight and comment.
	// Verify: BGD reaches AVAILABLE and ignored fields do not start a new table check.
	if (test_irrelevant_server_fields(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: set use_ssl=1 for the green writer in hostgroup 1372.
	// Verify: the next green-writer metadata probe uses TLS without restarting discovery.
	if (test_tls_refresh(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: replace the green reader in hostgroup 1373 and load mysql_servers to runtime.
	// Verify: green-reader membership refresh does not restart BGD discovery.
	if (test_green_membership_refresh(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: move the green writer OFFLINE_SOFT and then ONLINE.
	// Verify: direct metadata probes stop and resume without a table-check restart.
	if (test_server_eligibility_refresh(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: set check_interval_ms=1000 for wHG 1370 and publish empty topology.
	// Verify: metadata probing follows the configured interval without restarting discovery.
	if (test_check_interval_refresh(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim, state) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
