/**
 * @file test_rds_bgd_smoke-t.cpp
 * @brief Explicitly configured BGD worker reaching AVAILABLE and probing the green writer.
 *
 * Steps:
 *
 * 1. Set read_only=0 for the blue and green writers and publish AVAILABLE topology.
 * 2. Configure BGD hostgroups 10-40 with the blue writer in hostgroup 10.
 * 3. Verify BGD status AVAILABLE and a plaintext metadata probe to the green writer.
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
	BGD_Hostgroups hostgroups { 10, 20, 30, 40 };
	vector<Endpoint> topology_endpoints { cluster.get_writers() };
	uint64_t probe_sequence { 0 };
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

int configure_explicit_bgd(MYSQL* admin, TestState& state) {
	RDS_BGD_Host& writer = state.cluster.blue_writer;
	BGD_Hostgroups& hg = state.hostgroups;

	string add_replication_hostgroups =
		"INSERT INTO mysql_replication_hostgroups(writer_hostgroup,reader_hostgroup) VALUES (" +
		to_string(hg.blue_writer) + "," + to_string(hg.blue_reader) + ")";
	string add_bgd_hostgroups =
		"INSERT INTO mysql_aws_rds_bgd_hostgroups("
		"writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,"
		"active,writer_is_also_reader,check_interval_ms,check_timeout_ms,comment) VALUES (" +
		to_string(hg.blue_writer) + "," + to_string(hg.blue_reader) + "," +
		to_string(hg.green_writer) + "," + to_string(hg.green_reader) +
		",1,0,100,800,'BGD simulator smoke test')";
	string add_blue_writer =
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,use_ssl,comment) VALUES (" +
		to_string(hg.blue_writer) + "," + bgd_sql_quote(writer.hostname) + "," +
		to_string(writer.port) + ",0,'blue writer')";
	vector<string> queries {
		add_replication_hostgroups,
		add_bgd_hostgroups,
		add_blue_writer,
		"SET mysql-monitor_username='testuser'",
		"SET mysql-monitor_password='testuser'",
		"SET mysql-monitor_enabled='true'",
		"SET mysql-aws_blue_green_deployment_auto_discovery='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	return rc;
}

/**
 * Publish AVAILABLE topology for writable blue and green writers.
 *
 * - Set read_only=0 for both simulated writers.
 * - Record the probe sequence before publishing topology.
 * - Publish AVAILABLE topology to the blue and green writer endpoints.
 */
int publish_available_topology(BGD_Simulator& sim, TestState& state) {
	int writer_rc = bgd_set_writer_read_only_0(sim, state.cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=0 for the simulated writers");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before publishing AVAILABLE topology");
		return EXIT_FAILURE;
	}
	state.probe_sequence = seq;

	vector<BGD_Topology_Row> topology = state.cluster.get_topology("AVAILABLE");
	int topology_rc = sim.topology_update(state.topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology");
		return EXIT_FAILURE;
	}

	ok(true, "simulator publishes AVAILABLE topology to the blue and green writers");
	return EXIT_SUCCESS;
}

/**
 * Configure an explicit BGD worker for writer hostgroup 10.
 *
 * - Insert mysql_replication_hostgroups and mysql_aws_rds_bgd_hostgroups rows.
 * - Insert the blue writer in mysql_servers hostgroup 10.
 * - Verify that the runtime BGD status reaches AVAILABLE.
 */
int configure_bgd_available(MYSQL* admin, TestState& state) {
	int config_rc = configure_explicit_bgd(admin, state);
	if (config_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure mysql_servers and mysql_aws_rds_bgd_hostgroups");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, state.hostgroups, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 10 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	ok(true, "BGD status for wHG 10 reports AVAILABLE");
	return EXIT_SUCCESS;
}

/**
 * Verify the AVAILABLE worker probes the green writer.
 *
 * - Wait for a metadata probe after the topology publication sequence.
 * - Require the probe on the green writer IP without TLS.
 */
int test_plaintext_green_writer_probe(BGD_Simulator& sim, TestState& state) {
	auto [probe_rc, probe] = sim.wait_for_probe_log(
		state.probe_sequence, state.cluster.green_writer.endpoint(),
		BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0
	);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: green writer did not receive a plaintext metadata probe");
		return EXIT_FAILURE;
	}

	ok(true, "BGD worker probes the green writer IP over plaintext");
	return EXIT_SUCCESS;
}

int main() {
	plan(3);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: set blue/green writer read_only=0 and publish AVAILABLE topology.
	// Verify: topology publication succeeds for both writer endpoints.
	if (publish_available_topology(sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: configure mysql_servers and mysql_aws_rds_bgd_hostgroups for wHG 10.
	// Verify: BGD status for wHG 10 reports AVAILABLE.
	if (configure_bgd_available(admin, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: run the explicitly configured BGD worker without TLS.
	// Verify: the green writer IP receives a plaintext metadata probe.
	if (test_plaintext_green_writer_probe(sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
