/**
 * @file test_rds_bgd_explicit_startup-t.cpp
 * @brief Starting an explicit BGD worker after both required inputs exist.
 *
 * Steps:
 *
 * 1. Load the BGD row for hostgroups 840-843 before loading its servers.
 * 2. Verify no table-check occurs until an eligible blue server is loaded.
 * 3. Load servers for hostgroups 850-853 before loading their BGD row.
 * 4. Verify no table-check occurs until the explicit BGD row is loaded.
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
const uint32_t kNegativeProbeTimeoutMs = 800;

struct TestState {
	RDS_BGD_Cluster row_first { bgd_cluster_init() };
	RDS_BGD_Cluster servers_first { bgd_cluster_2_init() };
	BGD_Hostgroups row_first_hg { 840, 841, 842, 843 };
	BGD_Hostgroups servers_first_hg { 850, 851, 852, 853 };
	vector<Endpoint> row_first_endpoints { row_first.get_endpoints() };
	vector<Endpoint> servers_first_endpoints { servers_first.get_endpoints() };
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

int add_cluster_servers(MYSQL* admin, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg) {
	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	int blue_rc = bgd_admin_add_servers(admin, cluster, hg, blue_servers, false, 0);
	if (blue_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0], cluster.green_readers[1] };
	int green_rc = bgd_admin_add_servers(admin, cluster, hg, green_servers, true, 0);
	if (green_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<string> queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_rc = execute_all(admin, queries);
	if (load_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

bool runtime_membership_matches(MYSQL* admin, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg) {
	vector<int> hostgroups { hg.blue_writer, hg.blue_reader, hg.green_writer, hg.green_reader };
	auto [rc, rows] = bgd_runtime_servers(admin, hostgroups);
	if (rc != EXIT_SUCCESS || rows.size() != 6) {
		return false;
	}

	vector<pair<int, string>> expected {
		{ hg.blue_writer, cluster.blue_writer.hostname },
		{ hg.blue_reader, cluster.blue_readers[0].hostname },
		{ hg.blue_reader, cluster.blue_readers[1].hostname },
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
 * Load the explicit BGD row before any eligible blue server.
 *
 * - Publish AVAILABLE topology for hostgroups 840-843.
 * - Load the explicit BGD row without mysql_servers membership.
 * - Verify no table-check probe starts.
 * - Load all servers and verify AVAILABLE with explicit runtime membership.
 */
int test_bgd_row_before_servers(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.row_first;
	BGD_Hostgroups& hg = state.row_first_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure row-first simulated writers");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.row_first_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for hostgroups 840-843");
		return EXIT_FAILURE;
	}

	int monitor_rc = configure_monitor(admin, hg);
	if (monitor_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure monitoring for hostgroups 840-843");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before loading wHG 840");
		return EXIT_FAILURE;
	}

	int row_rc = insert_explicit_bgd_row(admin, hg, "BGD row before servers");
	if (row_rc != EXIT_SUCCESS) {
		diag("Error: failed to insert the explicit BGD row for wHG 840");
		return EXIT_FAILURE;
	}

	vector<string> load_queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_row_rc = execute_all(admin, load_queries);
	if (load_row_rc != EXIT_SUCCESS) {
		diag("Error: failed to load wHG 840 before its servers");
		return EXIT_FAILURE;
	}

	int no_probe_rc = bgd_expect_no_table_check(sim, seq, state.row_first_endpoints, kNegativeProbeTimeoutMs);
	if (no_probe_rc != EXIT_SUCCESS) {
		diag("Error: wHG 840 started before an eligible blue server existed");
		return EXIT_FAILURE;
	}

	ok(true, "wHG 840 does not start before an eligible blue server exists");

	int servers_rc = add_cluster_servers(admin, cluster, hg);
	if (servers_rc != EXIT_SUCCESS) {
		diag("Error: failed to load servers for hostgroups 840-843");
		return EXIT_FAILURE;
	}

	auto [probe_rc, probe] =
		sim.wait_for_probe_log(seq, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::table_check, kProbeTimeoutMs, 0);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: loading the blue writer did not start the wHG 840 table check");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 840 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	bool membership_matches = runtime_membership_matches(admin, cluster, hg);
	ok(membership_matches, "loading servers starts wHG 840 with explicit runtime membership");
	return EXIT_SUCCESS;
}

/**
 * Load all servers before their explicit BGD row.
 *
 * - Publish AVAILABLE topology for hostgroups 850-853.
 * - Load mysql_servers membership without a BGD row.
 * - Verify no table-check probe starts.
 * - Load the explicit row and verify AVAILABLE with explicit membership.
 */
int test_servers_before_bgd_row(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.servers_first;
	BGD_Hostgroups& hg = state.servers_first_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure servers-first simulated writers");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.servers_first_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for hostgroups 850-853");
		return EXIT_FAILURE;
	}

	int monitor_rc = configure_monitor(admin, hg);
	if (monitor_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure monitoring for hostgroups 850-853");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before loading hostgroups 850-853");
		return EXIT_FAILURE;
	}

	int servers_rc = add_cluster_servers(admin, cluster, hg);
	if (servers_rc != EXIT_SUCCESS) {
		diag("Error: failed to load servers before wHG 850");
		return EXIT_FAILURE;
	}

	int no_probe_rc = bgd_expect_no_table_check(sim, seq, state.servers_first_endpoints, kNegativeProbeTimeoutMs);
	if (no_probe_rc != EXIT_SUCCESS) {
		diag("Error: servers in hostgroups 850-853 started without an explicit BGD row");
		return EXIT_FAILURE;
	}

	ok(true, "servers in hostgroups 850-853 do not start without an explicit BGD row");

	int row_rc = insert_explicit_bgd_row(admin, hg, "servers before BGD row");
	if (row_rc != EXIT_SUCCESS) {
		diag("Error: failed to insert the explicit BGD row for wHG 850");
		return EXIT_FAILURE;
	}

	vector<string> load_queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_row_rc = execute_all(admin, load_queries);
	if (load_row_rc != EXIT_SUCCESS) {
		diag("Error: failed to load the explicit BGD row for wHG 850");
		return EXIT_FAILURE;
	}

	auto [probe_rc, probe] =
		sim.wait_for_probe_log(seq, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::table_check, kProbeTimeoutMs, 0);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: loading wHG 850 did not start the blue table check");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 850 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	bool membership_matches = runtime_membership_matches(admin, cluster, hg);
	ok(membership_matches, "loading wHG 850 starts the worker with explicit runtime membership");
	return EXIT_SUCCESS;
}

int main() {
	plan(4);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	RDS_BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: publish AVAILABLE topology for hostgroups 840-843.
	// ProxySQL: load the explicit BGD row before loading mysql_servers.
	// Verify: no table-check starts until eligible blue membership exists.
	if (test_bgd_row_before_servers(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish AVAILABLE topology for hostgroups 850-853.
	// ProxySQL: load mysql_servers before loading the explicit BGD row.
	// Verify: no table-check starts until wHG 850 is loaded.
	if (test_servers_before_bgd_row(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
