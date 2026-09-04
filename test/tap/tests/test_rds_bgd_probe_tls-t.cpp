/**
 * @file test_rds_bgd_probe_tls-t.cpp
 * @brief Selecting BGD metadata targets and their TLS values.
 *
 * Steps:
 *
 * 1. Configure a plaintext blue reader before a TLS blue writer and verify
 *    automatic discovery uses the matched writer TLS.
 * 2. Configure an exact TLS TARGET beside a plaintext distractor and verify
 *    the recorded TARGET is selected.
 * 3. Leave green writer hostgroup 962 empty, set use_ssl=1 defaults, and
 *    verify the created TARGET row and metadata probe use TLS.
 * 4. Verify table-check, blue metadata, and green metadata probe order.
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
const uint32_t kNegativeProbeTimeoutMs = 1200;

struct TestState {
	RDS_BGD_Cluster automatic { bgd_cluster_init() };
	RDS_BGD_Cluster explicit_target { bgd_cluster_2_init() };
	RDS_BGD_Cluster distractor { bgd_cluster_1_deployment_b_init() };
	RDS_BGD_Cluster created_target { bgd_cluster_3_init() };
	BGD_Hostgroups automatic_hg { 940, 941, 942, 943 };
	BGD_Hostgroups explicit_target_hg { 950, 951, 952, 953 };
	BGD_Hostgroups created_target_hg { 960, 961, 962, 963 };
	vector<Endpoint> automatic_endpoints { automatic.get_endpoints() };
	vector<Endpoint> explicit_target_endpoints { explicit_target.get_endpoints() };
	vector<Endpoint> created_target_endpoints { created_target.get_endpoints() };
};

struct ProbeChain {
	BGD_Probe_Log table;
	BGD_Probe_Log blue;
	BGD_Probe_Log green;
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
	vector<string> attribute_queries {
		"DELETE FROM mysql_hostgroup_attributes",
		"LOAD MYSQL SERVERS TO RUNTIME",
	};
	int attribute_rc = execute_all(admin, attribute_queries);
	if (attribute_rc != EXIT_SUCCESS) {
		diag("Error: failed to clean BGD TLS hostgroup attributes");
	}

	int admin_rc = bgd_admin_cleanup(admin);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to clean ProxySQL BGD test state");
	}
	mysql_close(admin);

	int simulator_rc = sim.cleanup();
	if (simulator_rc != EXIT_SUCCESS) {
		diag("Error: failed to clean SQLite3-server simulator state");
	}

	if (attribute_rc != EXIT_SUCCESS || admin_rc != EXIT_SUCCESS || simulator_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int wait_for_probe_chain(BGD_Simulator& sim, uint64_t sequence, RDS_BGD_Cluster& cluster,
	int blue_use_ssl, int green_use_ssl, ProbeChain& chain)
{
	auto [table_rc, table] =
		sim.wait_for_probe_log(sequence, cluster.blue_writer.endpoint(), BGD_Probe_Kind::table_check, kProbeTimeoutMs, blue_use_ssl);
	if (table_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	auto [blue_rc, blue] =
		sim.wait_for_probe_log(table.sequence_id, cluster.blue_writer.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, blue_use_ssl);
	if (blue_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	auto [green_rc, green] =
		sim.wait_for_probe_log(blue.sequence_id, cluster.green_writer.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, green_use_ssl);
	if (green_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	chain = { table, blue, green };
	return EXIT_SUCCESS;
}

bool probe_chain_ordered(ProbeChain& chain) {
	bool ordered =
		chain.table.sequence_id < chain.blue.sequence_id &&
		chain.blue.sequence_id < chain.green.sequence_id &&
		chain.table.probe_kind == BGD_Probe_Kind::table_check &&
		chain.blue.probe_kind == BGD_Probe_Kind::metadata &&
		chain.green.probe_kind == BGD_Probe_Kind::metadata;
	return ordered;
}

bool runtime_server_tls_matches(MYSQL* admin, int hostgroup, RDS_BGD_Host& host, int use_ssl) {
	string query =
		"SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hostgroup) +
		" AND hostname=" + bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port) +
		" AND use_ssl=" + to_string(use_ssl);

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool matches = rows[0][0] == "1";
	return matches;
}

/**
 * Select the automatic blue writer when a reader appears first.
 *
 * - Load a blue reader with use_ssl=0 before the blue writer with use_ssl=1.
 * - Publish AVAILABLE topology.
 * - Verify table-check and blue metadata use the writer with TLS.
 * - Verify the mapped green writer metadata probe also uses TLS.
 */
int test_automatic_writer_tls(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.automatic;
	BGD_Hostgroups& hg = state.automatic_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure automatic TLS simulated writers");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> no_servers {};
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::automatic, no_servers, no_servers, 0, 0);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure automatic TLS discovery for hostgroups 940-943");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> reader { cluster.blue_readers[0] };
	int reader_rc = bgd_admin_add_servers(admin, cluster, hg, reader, false, 0);
	if (reader_rc != EXIT_SUCCESS) {
		diag("Error: failed to load the plaintext blue reader in hostgroup 941");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> writer { cluster.blue_writer };
	int server_writer_rc = bgd_admin_add_servers(admin, cluster, hg, writer, false, 1);
	if (server_writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to load the TLS blue writer in hostgroup 940");
		return EXIT_FAILURE;
	}

	vector<string> load_queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_rc = execute_all(admin, load_queries);
	if (load_rc != EXIT_SUCCESS) {
		diag("Error: failed to load automatic TLS server rows");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the automatic TLS probe sequence");
		return EXIT_FAILURE;
	}

	vector<BGD_Topology_Row> topology = cluster.get_topology("AVAILABLE");
	int topology_rc = sim.topology_update(state.automatic_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish automatic AVAILABLE topology");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 940 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	ProbeChain chain {};
	int chain_rc = wait_for_probe_chain(sim, seq, cluster, 1, 1, chain);
	if (chain_rc != EXIT_SUCCESS) {
		diag("Error: automatic TLS probe chain did not complete");
		return EXIT_FAILURE;
	}

	bool writer_tls = runtime_server_tls_matches(admin, hg.blue_writer, cluster.blue_writer, 1);
	bool selected_writer = chain.table.backend.host == cluster.blue_writer.ip && chain.blue.backend.host == cluster.blue_writer.ip;
	ok(writer_tls && selected_writer && chain.table.encrypted && chain.blue.encrypted,
		"automatic discovery selects the TLS writer in hostgroup 940 instead of the plaintext reader");

	bool green_target = chain.green.backend.host == cluster.green_writer.ip && chain.green.encrypted;
	bool ordered = probe_chain_ordered(chain);
	ok(green_target && ordered, "automatic probes run table-check, blue metadata, then TLS green metadata in order");
	return EXIT_SUCCESS;
}

/**
 * Select the exact explicit TARGET beside a valid-looking distractor.
 *
 * - Configure the exact green writer with use_ssl=1.
 * - Configure a different green writer hostname with use_ssl=0 in hostgroup 952.
 * - Publish AVAILABLE topology for the exact deployment.
 * - Verify the exact TARGET and TLS value are used in probe order.
 */
int test_explicit_target_tls(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.explicit_target;
	RDS_BGD_Cluster& distractor = state.distractor;
	BGD_Hostgroups& hg = state.explicit_target_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure explicit TLS simulated writers");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer };
	vector<RDS_BGD_Host> no_green_servers {};
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration,
		blue_servers, no_green_servers, 0, 0);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure explicit TLS hostgroups 950-953");
		return EXIT_FAILURE;
	}

	string distractor_query =
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,use_ssl,comment) VALUES (" +
		to_string(hg.green_writer) + "," + bgd_sql_quote(distractor.green_writer.hostname) +
		",3306,'ONLINE',0,'BGD TAP TLS distractor')";
	string target_query =
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,use_ssl,comment) VALUES (" +
		to_string(hg.green_writer) + "," + bgd_sql_quote(cluster.green_writer.hostname) +
		",3306,'ONLINE',1,'BGD TAP exact TARGET')";
	vector<string> target_queries {
		distractor_query,
		target_query,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};
	int target_rc = execute_all(admin, target_queries);
	if (target_rc != EXIT_SUCCESS) {
		diag("Error: failed to load exact and distractor TARGET rows in hostgroup 952");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the explicit TLS probe sequence");
		return EXIT_FAILURE;
	}

	vector<Endpoint> topology_endpoints = state.explicit_target_endpoints;
	vector<Endpoint> distractor_endpoints = distractor.get_endpoints();
	topology_endpoints.insert(topology_endpoints.end(), distractor_endpoints.begin(), distractor_endpoints.end());
	vector<BGD_Topology_Row> topology = cluster.get_topology("AVAILABLE");
	int topology_rc = sim.topology_update(topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish explicit AVAILABLE topology");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 950 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	ProbeChain chain {};
	int chain_rc = wait_for_probe_chain(sim, seq, cluster, 0, 1, chain);
	if (chain_rc != EXIT_SUCCESS) {
		diag("Error: explicit TLS probe chain did not complete");
		return EXIT_FAILURE;
	}

	bool exact_target =
		chain.green.backend.host == cluster.green_writer.ip &&
		chain.green.backend.host != distractor.green_writer.ip &&
		chain.green.encrypted;
	int no_distractor_rc = bgd_expect_no_metadata_probe(sim, seq, distractor.green_writer.endpoint(), kNegativeProbeTimeoutMs);
	if (no_distractor_rc != EXIT_SUCCESS) {
		diag("Error: explicit discovery probed the plaintext green-writer distractor");
		return EXIT_FAILURE;
	}

	ok(exact_target, "explicit discovery selects only the exact TLS TARGET and rejects the plaintext distractor");

	bool ordered = probe_chain_ordered(chain);
	bool blue_plaintext = !chain.table.encrypted && !chain.blue.encrypted;
	ok(ordered && blue_plaintext, "explicit probes run plaintext table-check, blue metadata, then TLS TARGET metadata");
	return EXIT_SUCCESS;
}

/**
 * Apply green hostgroup TLS defaults when ProxySQL creates the TARGET row.
 *
 * - Leave green writer hostgroup 962 empty.
 * - Configure servers_defaults use_ssl=1.
 * - Publish AVAILABLE topology.
 * - Verify the created TARGET runtime row and metadata probe use TLS.
 */
int test_created_target_tls(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.created_target;
	BGD_Hostgroups& hg = state.created_target_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure created-TARGET simulated writers");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer };
	vector<RDS_BGD_Host> no_green_servers {};
	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration,
		blue_servers, no_green_servers, 0, 0);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure created-TARGET hostgroups 960-963");
		return EXIT_FAILURE;
	}

	string defaults_query =
		"INSERT INTO mysql_hostgroup_attributes(hostgroup_id,servers_defaults) VALUES (" +
		to_string(hg.green_writer) + ",' {\"use_ssl\":1 }')";
	vector<string> defaults_queries {
		defaults_query,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};
	int defaults_rc = execute_all(admin, defaults_queries);
	if (defaults_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure TLS defaults for green writer hostgroup 962");
		return EXIT_FAILURE;
	}

	string empty_query =
		"SELECT COUNT(*)=0 FROM mysql_servers WHERE hostgroup_id=" +
		to_string(hg.green_writer);
	int empty_rc = bgd_wait_for_condition(admin, empty_query, kTimeoutSeconds);
	if (empty_rc != EXIT_SUCCESS) {
		diag("Error: green writer hostgroup 962 was not empty before discovery");
		return EXIT_FAILURE;
	}

	ok(true, "green writer hostgroup 962 starts empty with use_ssl=1 defaults");

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the created-TARGET probe sequence");
		return EXIT_FAILURE;
	}

	vector<BGD_Topology_Row> topology = cluster.get_topology("AVAILABLE");
	int topology_rc = sim.topology_update(state.created_target_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish created-TARGET AVAILABLE topology");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 960 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	string created_query =
		"SELECT COUNT(*)=1 FROM runtime_mysql_servers WHERE hostgroup_id=962 AND hostname=" +
		bgd_sql_quote(cluster.green_writer.hostname) + " AND port=3306 AND use_ssl=1";
	int created_rc = bgd_wait_for_condition(admin, created_query, kTimeoutSeconds);
	if (created_rc != EXIT_SUCCESS) {
		diag("Error: discovery did not create the TLS TARGET row in hostgroup 962");
		return EXIT_FAILURE;
	}

	bool runtime_tls = runtime_server_tls_matches(admin, hg.green_writer, cluster.green_writer, 1);
	ok(runtime_tls, "AVAILABLE creates the TARGET runtime row with hostgroup 962 TLS defaults");

	ProbeChain chain {};
	int chain_rc = wait_for_probe_chain(sim, seq, cluster, 0, 1, chain);
	if (chain_rc != EXIT_SUCCESS) {
		diag("Error: created-TARGET TLS probe chain did not complete");
		return EXIT_FAILURE;
	}

	bool green_tls = chain.green.backend.host == cluster.green_writer.ip && chain.green.encrypted;
	bool ordered = probe_chain_ordered(chain);
	ok(green_tls && ordered, "created TARGET probes run table-check, blue metadata, then TLS green metadata");
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

	// ProxySQL: load a plaintext reader before the TLS writer in automatic hostgroups 940 and 941.
	// Simulator: publish AVAILABLE topology.
	// Verify: table-check and metadata probes select the writer and use TLS.
	if (test_automatic_writer_tls(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: load an exact TLS TARGET and plaintext distractor into green writer hostgroup 952.
	// Simulator: publish AVAILABLE for the exact TARGET deployment.
	// Verify: metadata probing selects the exact TARGET and preserves probe order.
	if (test_explicit_target_tls(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: leave hostgroup 962 empty and configure use_ssl=1 server defaults.
	// Simulator: publish AVAILABLE topology.
	// Verify: ProxySQL creates and probes the TARGET row with TLS.
	if (test_created_target_tls(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
