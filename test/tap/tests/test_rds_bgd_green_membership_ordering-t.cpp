/**
 * @file test_rds_bgd_green_membership_ordering-t.cpp
 * @brief Loading configured green membership at three supported times.
 *
 * Steps:
 *
 * 1. Load green membership for hostgroups 862 and 863 before AVAILABLE.
 * 2. Load green membership for hostgroups 872 and 873 after discovery.
 * 3. Start wHG 880 against absent topology, then load green membership for
 *    hostgroups 882 and 883 before publishing AVAILABLE.
 * 4. Verify all three orders produce complete runtime green membership.
 */

#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include "command_line.h"
#include "rds_bgd_tap.h"
#include "utils.h"

const uint32_t kTimeoutSeconds = 3;
const uint32_t kProbeTimeoutMs = 3000;

struct TestState {
	RDS_BGD_Cluster before_available { bgd_cluster_3_init() };
	RDS_BGD_Cluster after_discovery { bgd_cluster_1_deployment_b_init() };
	RDS_BGD_Cluster after_worker_start { bgd_cluster_init() };
	BGD_Hostgroups before_available_hg { 860, 861, 862, 863 };
	BGD_Hostgroups after_discovery_hg { 870, 871, 872, 873 };
	BGD_Hostgroups after_worker_start_hg { 880, 881, 882, 883 };
	vector<Endpoint> before_available_endpoints { before_available.get_endpoints() };
	vector<Endpoint> after_discovery_endpoints { after_discovery.get_endpoints() };
	vector<Endpoint> after_worker_start_endpoints { after_worker_start.get_endpoints() };
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

int configure_monitor(MYSQL* admin, BGD_Hostgroups& hg) {
	vector<string> queries {
		"INSERT INTO mysql_replication_hostgroups(writer_hostgroup,reader_hostgroup) VALUES (" +
			to_string(hg.blue_writer) + "," + to_string(hg.blue_reader) + ")",
		"SET mysql-monitor_username='testuser'",
		"SET mysql-monitor_password='testuser'",
		"SET mysql-monitor_enabled='true'",
		"SET mysql-monitor_read_only_interval=100",
		"SET mysql-monitor_aws_rds_topology_discovery_interval=1",
		"SET mysql-aws_blue_green_deployment_auto_discovery='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	return rc;
}

int insert_explicit_bgd_row(MYSQL* admin, BGD_Hostgroups& hg, string comment) {
	string query =
		"INSERT INTO mysql_aws_rds_bgd_hostgroups("
		"writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,"
		"active,writer_is_also_reader,check_interval_ms,check_timeout_ms,comment) VALUES (" +
		to_string(hg.blue_writer) + "," + to_string(hg.blue_reader) + "," +
		to_string(hg.green_writer) + "," + to_string(hg.green_reader) +
		",1,0,100,800," + bgd_sql_quote(comment) + ")";

	int rc = mysql_query(admin, query.c_str());
	if (rc != 0) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int add_blue_servers(MYSQL* admin, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg) {
	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	int add_rc = bgd_admin_add_servers(admin, cluster, hg, blue_servers, false, 0);
	if (add_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<string> queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_rc = execute_all(admin, queries);
	if (load_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int add_green_servers(MYSQL* admin, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg) {
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0], cluster.green_readers[1] };
	int add_rc = bgd_admin_add_servers(admin, cluster, hg, green_servers, true, 0);
	if (add_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<string> queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_rc = execute_all(admin, queries);
	if (load_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

bool runtime_green_membership_matches(MYSQL* admin, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg) {
	vector<int> hostgroups { hg.green_writer, hg.green_reader };
	auto [rc, rows] = bgd_runtime_servers(admin, hostgroups);
	if (rc != EXIT_SUCCESS || rows.size() != 3) {
		return false;
	}

	vector<pair<int, string>> expected {
		{ hg.green_writer, cluster.green_writer.hostname },
		{ hg.green_reader, cluster.green_readers[0].hostname },
		{ hg.green_reader, cluster.green_readers[1].hostname },
	};

	for (pair<int, string>& server : expected) {
		bool found = false;
		for (mysql_res_row& row : rows) {
			if (row.size() == 5 && row[0] == to_string(server.first) && row[1] == server.second) {
				found = true;
				break;
			}
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

/**
 * Load complete green membership before the first AVAILABLE observation.
 *
 * - Configure wHG 860 and all blue/green mysql_servers rows.
 * - Publish AVAILABLE topology after all membership exists.
 * - Verify runtime hostgroups 862 and 863 contain the configured green set.
 */
int test_green_before_available(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.before_available;
	BGD_Hostgroups& hg = state.before_available_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure green-before-AVAILABLE simulated writers");
		return EXIT_FAILURE;
	}

	int monitor_rc = configure_monitor(admin, hg);
	if (monitor_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure monitoring for wHG 860");
		return EXIT_FAILURE;
	}

	int row_rc = insert_explicit_bgd_row(admin, hg, "green membership before AVAILABLE");
	if (row_rc != EXIT_SUCCESS) {
		diag("Error: failed to insert the explicit BGD row for wHG 860");
		return EXIT_FAILURE;
	}

	int blue_rc = add_blue_servers(admin, cluster, hg);
	if (blue_rc != EXIT_SUCCESS) {
		diag("Error: failed to load blue membership for wHG 860");
		return EXIT_FAILURE;
	}

	int green_rc = add_green_servers(admin, cluster, hg);
	if (green_rc != EXIT_SUCCESS) {
		diag("Error: failed to load green membership for hostgroups 862 and 863");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.before_available_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG 860");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 860 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	bool membership_matches = runtime_green_membership_matches(admin, cluster, hg);
	ok(membership_matches, "green membership loaded before AVAILABLE appears in hostgroups 862 and 863");
	return EXIT_SUCCESS;
}

/**
 * Load green membership after the explicit worker discovers AVAILABLE.
 *
 * - Publish AVAILABLE and start wHG 870 with blue membership only.
 * - Load the configured green writer/readers into hostgroups 872 and 873.
 * - Verify runtime_mysql_servers contains the complete green membership after
 *   the worker observes the configuration change.
 */
int test_green_after_discovery(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.after_discovery;
	BGD_Hostgroups& hg = state.after_discovery_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure green-after-discovery simulated writers");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.after_discovery_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG 870");
		return EXIT_FAILURE;
	}

	int monitor_rc = configure_monitor(admin, hg);
	if (monitor_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure monitoring for wHG 870");
		return EXIT_FAILURE;
	}

	int row_rc = insert_explicit_bgd_row(admin, hg, "green membership after discovery");
	if (row_rc != EXIT_SUCCESS) {
		diag("Error: failed to insert the explicit BGD row for wHG 870");
		return EXIT_FAILURE;
	}

	int blue_rc = add_blue_servers(admin, cluster, hg);
	if (blue_rc != EXIT_SUCCESS) {
		diag("Error: failed to load blue membership for wHG 870");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 870 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before loading hostgroups 872 and 873");
		return EXIT_FAILURE;
	}

	int green_rc = add_green_servers(admin, cluster, hg);
	if (green_rc != EXIT_SUCCESS) {
		diag("Error: failed to load green membership for hostgroups 872 and 873");
		return EXIT_FAILURE;
	}

	auto [probe_rc, probe] =
		sim.wait_for_probe_log(seq, cluster.green_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: wHG 870 did not probe the green writer after membership load");
		return EXIT_FAILURE;
	}

	bool membership_matches = runtime_green_membership_matches(admin, cluster, hg);
	ok(membership_matches, "green membership loaded after discovery appears in hostgroups 872 and 873");
	return EXIT_SUCCESS;
}

/**
 * Start an explicit worker before topology and green membership exist.
 *
 * - Start wHG 880 with blue membership against absent topology.
 * - Load green membership into hostgroups 882 and 883.
 * - Publish AVAILABLE and verify complete runtime green membership.
 */
int test_green_after_worker_start(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.after_worker_start;
	BGD_Hostgroups& hg = state.after_worker_start_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure green-after-worker-start simulated writers");
		return EXIT_FAILURE;
	}

	int drop_rc = sim.topology_drop(state.after_worker_start_endpoints);
	if (drop_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish absent topology for wHG 880");
		return EXIT_FAILURE;
	}

	int monitor_rc = configure_monitor(admin, hg);
	if (monitor_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure monitoring for wHG 880");
		return EXIT_FAILURE;
	}

	int row_rc = insert_explicit_bgd_row(admin, hg, "green membership after worker start");
	if (row_rc != EXIT_SUCCESS) {
		diag("Error: failed to insert the explicit BGD row for wHG 880");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before starting wHG 880");
		return EXIT_FAILURE;
	}

	int blue_rc = add_blue_servers(admin, cluster, hg);
	if (blue_rc != EXIT_SUCCESS) {
		diag("Error: failed to load blue membership for wHG 880");
		return EXIT_FAILURE;
	}

	auto [start_rc, start_probe] =
		sim.wait_for_probe_log(seq, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::table_check, kProbeTimeoutMs, 0);
	if (start_rc != EXIT_SUCCESS) {
		diag("Error: wHG 880 did not start the blue table-check probe");
		return EXIT_FAILURE;
	}

	int green_rc = add_green_servers(admin, cluster, hg);
	if (green_rc != EXIT_SUCCESS) {
		diag("Error: failed to load green membership for hostgroups 882 and 883");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.after_worker_start_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG 880");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 880 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	bool membership_matches = runtime_green_membership_matches(admin, cluster, hg);
	ok(membership_matches, "green membership loaded after worker start appears in hostgroups 882 and 883");
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

	// ProxySQL: load wHG 860 and complete blue/green membership before AVAILABLE.
	// Simulator: publish AVAILABLE topology after membership exists.
	// Verify: runtime_mysql_servers contains the configured green writer/readers in hostgroups 862 and 863.
	if (test_green_before_available(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish AVAILABLE topology and start wHG 870 with blue membership.
	// ProxySQL: load green writer/readers into hostgroups 872 and 873 after discovery.
	// Verify: runtime_mysql_servers converges on complete green membership.
	if (test_green_after_discovery(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: start wHG 880 against absent topology, then load green hostgroups 882 and 883.
	// Simulator: publish AVAILABLE after the worker and green membership exist.
	// Verify: runtime_mysql_servers converges on complete green membership.
	if (test_green_after_worker_start(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
