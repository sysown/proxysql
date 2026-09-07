/**
 * @file test_rds_bgd_configuration_persistence-t.cpp
 * @brief BGD runtime and persistent configuration ownership.
 *
 * Steps:
 *
 * 1. Convert an auto-generated row for wHG 890 into explicit configuration.
 * 2. Verify persistent BGD rows reject NULL green hostgroups and accept a
 *    complete row.
 * 3. SAVE runtime BGD state and verify only the explicit row is persisted.
 * 4. Run automatic discovery beside administrator-owned configuration and
 *    verify its BGD row and green-server status remain unchanged.
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

struct TestState {
	RDS_BGD_Cluster conversion { bgd_cluster_2_init() };
	RDS_BGD_Cluster explicit_save { bgd_cluster_3_init() };
	RDS_BGD_Cluster automatic_save { bgd_cluster_1_deployment_b_init() };
	RDS_BGD_Cluster admin_owned { bgd_cluster_init() };
	BGD_Hostgroups conversion_hg { 890, 891, 892, 893 };
	BGD_Hostgroups valid_hg { 910, 911, 912, 913 };
	BGD_Hostgroups explicit_save_hg { 920, 921, 922, 923 };
	BGD_Hostgroups automatic_save_hg { 930, 931, 932, 933 };
	BGD_Hostgroups admin_owned_hg { 1310, 1311, 1312, 1313 };
	vector<Endpoint> conversion_endpoints { conversion.get_endpoints() };
	vector<Endpoint> explicit_save_endpoints { explicit_save.get_endpoints() };
	vector<Endpoint> automatic_save_endpoints { automatic_save.get_endpoints() };
	vector<Endpoint> admin_owned_endpoints { admin_owned.get_endpoints() };
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

int configure_monitor(MYSQL* admin, BGD_Hostgroups& hg, bool automatic) {
	string automatic_value = automatic ? "true" : "false";
	vector<string> queries {
		"INSERT INTO mysql_replication_hostgroups(writer_hostgroup,reader_hostgroup) VALUES (" +
			to_string(hg.blue_writer) + "," + to_string(hg.blue_reader) + ")",
		"SET mysql-monitor_username='testuser'",
		"SET mysql-monitor_password='testuser'",
		"SET mysql-monitor_enabled='true'",
		"SET mysql-monitor_read_only_interval=100",
		"SET mysql-monitor_aws_rds_topology_discovery_interval=1",
		"SET mysql-aws_blue_green_deployment_auto_discovery='" + automatic_value + "'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	return rc;
}

int insert_explicit_bgd_row(MYSQL* admin, BGD_Hostgroups& hg, const string& comment, int active = 1) {
	string query =
		"INSERT INTO mysql_aws_rds_bgd_hostgroups("
		"writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,"
		"active,writer_is_also_reader,check_interval_ms,check_timeout_ms,comment) VALUES (" +
		to_string(hg.blue_writer) + "," + to_string(hg.blue_reader) + "," +
		to_string(hg.green_writer) + "," + to_string(hg.green_reader) + "," +
		to_string(active) + ",0,100,800," + bgd_sql_quote(comment) + ")";

	int rc = mysql_query(admin, query.c_str());
	if (rc != 0) {
		diag("Error: failed to insert mysql_aws_rds_bgd_hostgroups row for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int add_all_servers(MYSQL* admin, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg) {
	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	int blue_rc = bgd_admin_add_servers(admin, cluster, hg, blue_servers, false, 0);
	if (blue_rc != EXIT_SUCCESS) {
		diag("Error: failed to add blue servers for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0], cluster.green_readers[1] };
	int green_rc = bgd_admin_add_servers(admin, cluster, hg, green_servers, true, 0);
	if (green_rc != EXIT_SUCCESS) {
		diag("Error: failed to add green servers for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}

	vector<string> load_queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_rc = execute_all(admin, load_queries);
	if (load_rc != EXIT_SUCCESS) {
		diag("Error: failed to load servers for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

bool persistent_bgd_row_matches(MYSQL* admin, BGD_Hostgroups& hg) {
	string query =
		"SELECT writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup "
		"FROM mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" + to_string(hg.blue_writer);

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 4) {
		return false;
	}

	bool matches =
		rows[0][0] == to_string(hg.blue_writer) &&
		rows[0][1] == to_string(hg.blue_reader) &&
		rows[0][2] == to_string(hg.green_writer) &&
		rows[0][3] == to_string(hg.green_reader);
	return matches;
}

bool persistent_bgd_row_absent(MYSQL* admin, int writer_hostgroup) {
	string query =
		"SELECT COUNT(*) FROM mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(writer_hostgroup);

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool absent = rows[0][0] == "0";
	return absent;
}

bool runtime_explicit_bgd_row_matches(MYSQL* admin, BGD_Hostgroups& hg) {
	string query =
		"SELECT COUNT(*) FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(hg.blue_writer) + " AND reader_hostgroup=" + to_string(hg.blue_reader) +
		" AND green_writer_hostgroup=" + to_string(hg.green_writer) +
		" AND green_reader_hostgroup=" + to_string(hg.green_reader) + " AND auto_generated=0";

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		return false;
	}

	bool matches = rows[0][0] == "1";
	return matches;
}

rc_t<vector<mysql_res_row>> bgd_admin_snapshot(MYSQL* admin, int writer_hostgroup) {
	string query =
		"SELECT writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,"
		"active,writer_is_also_reader,check_interval_ms,check_timeout_ms,comment "
		"FROM mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" + to_string(writer_hostgroup);

	rc_t<vector<mysql_res_row>> result = mysql_query_ext_rows(admin, query);
	return result;
}

rc_t<vector<mysql_res_row>> runtime_bgd_ownership_snapshot(MYSQL* admin, int writer_hostgroup) {
	string query =
		"SELECT green_writer_hostgroup,green_reader_hostgroup,active,auto_generated "
		"FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" + to_string(writer_hostgroup);

	rc_t<vector<mysql_res_row>> result = mysql_query_ext_rows(admin, query);
	return result;
}

rc_t<vector<mysql_res_row>> green_server_snapshot(MYSQL* admin, const string& table, BGD_Hostgroups& hg) {
	string query =
		"SELECT hostgroup_id,hostname,port,status,use_ssl,weight,max_connections FROM " + table +
		" WHERE hostgroup_id IN (" + to_string(hg.green_writer) + "," + to_string(hg.green_reader) +
		") ORDER BY hostgroup_id,hostname,port";

	rc_t<vector<mysql_res_row>> result = mysql_query_ext_rows(admin, query);
	return result;
}

/**
 * Convert the automatic runtime row for wHG 890 to explicit configuration.
 *
 * - Enable automatic discovery with only the blue writer configured.
 * - Verify the runtime row has NULL green hostgroups and auto_generated=1.
 * - Disable automatic discovery and load explicit hostgroups 890-893.
 * - Verify explicit values replace the automatic row and persist.
 */
int test_automatic_to_explicit(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.conversion;
	BGD_Hostgroups& hg = state.conversion_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure automatic-conversion simulated writers");
		return EXIT_FAILURE;
	}

	vector<BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.conversion_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG 890");
		return EXIT_FAILURE;
	}

	int monitor_rc = configure_monitor(admin, hg, true);
	if (monitor_rc != EXIT_SUCCESS) {
		diag("Error: failed to enable automatic discovery for wHG 890");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer };
	int server_rc = bgd_admin_add_servers(admin, cluster, hg, blue_servers, false, 0);
	if (server_rc != EXIT_SUCCESS) {
		diag("Error: failed to add the blue writer for wHG 890");
		return EXIT_FAILURE;
	}

	vector<string> load_server_queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_server_rc = execute_all(admin, load_server_queries);
	if (load_server_rc != EXIT_SUCCESS) {
		diag("Error: failed to load the blue writer for wHG 890");
		return EXIT_FAILURE;
	}

	string automatic_query =
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=890 "
		"AND auto_generated=1 AND green_writer_hostgroup IS NULL AND green_reader_hostgroup IS NULL";
	int automatic_rc = bgd_wait_for_condition(admin, automatic_query, kTimeoutSeconds);
	if (automatic_rc != EXIT_SUCCESS) {
		diag("Error: automatic discovery did not create the nullable runtime row for wHG 890");
		return EXIT_FAILURE;
	}

	ok(true, "automatic discovery records NULL green hostgroups for wHG 890");

	vector<string> disable_queries {
		"SET mysql-aws_blue_green_deployment_auto_discovery='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};
	int disable_rc = execute_all(admin, disable_queries);
	if (disable_rc != EXIT_SUCCESS) {
		diag("Error: failed to disable automatic discovery before converting wHG 890");
		return EXIT_FAILURE;
	}

	int row_rc = insert_explicit_bgd_row(admin, hg, "converted automatic BGD row");
	if (row_rc != EXIT_SUCCESS) {
		diag("Error: failed to insert explicit configuration for wHG 890");
		return EXIT_FAILURE;
	}

	vector<string> load_row_queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_row_rc = execute_all(admin, load_row_queries);
	if (load_row_rc != EXIT_SUCCESS) {
		diag("Error: failed to load explicit configuration for wHG 890");
		return EXIT_FAILURE;
	}

	string explicit_query =
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=890 "
		"AND auto_generated=0 AND green_writer_hostgroup=892 AND green_reader_hostgroup=893";
	int explicit_rc = bgd_wait_for_condition(admin, explicit_query, kTimeoutSeconds);
	if (explicit_rc != EXIT_SUCCESS) {
		diag("Error: explicit configuration did not replace the automatic row for wHG 890");
		return EXIT_FAILURE;
	}

	bool runtime_matches = runtime_explicit_bgd_row_matches(admin, hg);
	bool persistent_matches = persistent_bgd_row_matches(admin, hg);
	ok(runtime_matches && persistent_matches, "explicit hostgroups 890-893 replace and persist the automatic row");
	return EXIT_SUCCESS;
}

/**
 * Validate persistent green-hostgroup requirements.
 *
 * - Attempt persistent rows with a NULL green writer or reader hostgroup.
 * - Verify both invalid rows are rejected.
 * - Load a complete row for hostgroups 910-913.
 * - Verify it exists in persistent and runtime configuration.
 */
int test_persistent_row_validation(MYSQL* admin, TestState& state) {
	string null_writer_query =
		"INSERT INTO mysql_aws_rds_bgd_hostgroups("
		"writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup) "
		"VALUES (900,901,NULL,903)";
	int null_writer_rc = mysql_query(admin, null_writer_query.c_str());
	bool null_writer_absent = persistent_bgd_row_absent(admin, 900);
	ok(null_writer_rc != 0 && null_writer_absent, "persistent BGD configuration rejects a NULL green writer hostgroup");

	string null_reader_query =
		"INSERT INTO mysql_aws_rds_bgd_hostgroups("
		"writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup) "
		"VALUES (904,905,906,NULL)";
	int null_reader_rc = mysql_query(admin, null_reader_query.c_str());
	bool null_reader_absent = persistent_bgd_row_absent(admin, 904);
	ok(null_reader_rc != 0 && null_reader_absent, "persistent BGD configuration rejects a NULL green reader hostgroup");

	BGD_Hostgroups& hg = state.valid_hg;
	int monitor_rc = configure_monitor(admin, hg, false);
	if (monitor_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure monitoring for hostgroups 910-913");
		return EXIT_FAILURE;
	}

	int row_rc = insert_explicit_bgd_row(admin, hg, "valid persistent BGD row");
	if (row_rc != EXIT_SUCCESS) {
		diag("Error: failed to insert valid persistent BGD row for hostgroups 910-913");
		return EXIT_FAILURE;
	}

	vector<string> load_queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_rc = execute_all(admin, load_queries);
	if (load_rc != EXIT_SUCCESS) {
		diag("Error: failed to load valid BGD row for hostgroups 910-913");
		return EXIT_FAILURE;
	}

	bool persistent_matches = persistent_bgd_row_matches(admin, hg);
	bool runtime_matches = runtime_explicit_bgd_row_matches(admin, hg);
	ok(persistent_matches && runtime_matches, "complete persistent BGD configuration loads hostgroups 910-913");
	return EXIT_SUCCESS;
}

/**
 * Save explicit and automatic runtime rows back to persistent configuration.
 *
 * - Run explicit wHG 920 and automatic wHG 930 together.
 * - Remove the persistent explicit row.
 * - Execute SAVE MYSQL SERVERS FROM RUNTIME.
 * - Verify SAVE restores wHG 920 and skips auto-generated wHG 930.
 */
int test_save_from_runtime(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& explicit_cluster = state.explicit_save;
	RDS_BGD_Cluster& automatic_cluster = state.automatic_save;
	BGD_Hostgroups& explicit_hg = state.explicit_save_hg;
	BGD_Hostgroups& automatic_hg = state.automatic_save_hg;

	int explicit_writer_rc = bgd_set_writer_read_only_0(sim, explicit_cluster);
	if (explicit_writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure explicit SAVE simulated writers");
		return EXIT_FAILURE;
	}

	int automatic_writer_rc = bgd_set_writer_read_only_0(sim, automatic_cluster);
	if (automatic_writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure automatic SAVE simulated writers");
		return EXIT_FAILURE;
	}

	vector<BGD_Topology_Row> explicit_topology = bgd_topology_with_readers(explicit_cluster, "AVAILABLE");
	int explicit_topology_rc = sim.topology_update(state.explicit_save_endpoints, explicit_topology);
	if (explicit_topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG 920");
		return EXIT_FAILURE;
	}

	vector<BGD_Topology_Row> automatic_topology = bgd_topology_with_readers(automatic_cluster, "AVAILABLE");
	int automatic_topology_rc = sim.topology_update(state.automatic_save_endpoints, automatic_topology);
	if (automatic_topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG 930");
		return EXIT_FAILURE;
	}

	int monitor_rc = configure_monitor(admin, explicit_hg, true);
	if (monitor_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure SAVE monitoring for wHG 920");
		return EXIT_FAILURE;
	}

	int explicit_row_rc = insert_explicit_bgd_row(admin, explicit_hg, "explicit SAVE row");
	if (explicit_row_rc != EXIT_SUCCESS) {
		diag("Error: failed to insert explicit SAVE row for wHG 920");
		return EXIT_FAILURE;
	}

	int explicit_servers_rc = add_all_servers(admin, explicit_cluster, explicit_hg);
	if (explicit_servers_rc != EXIT_SUCCESS) {
		diag("Error: failed to load servers for wHG 920");
		return EXIT_FAILURE;
	}

	string replication_query =
		"INSERT INTO mysql_replication_hostgroups(writer_hostgroup,reader_hostgroup) VALUES (" +
		to_string(automatic_hg.blue_writer) + "," + to_string(automatic_hg.blue_reader) + ")";
	vector<string> automatic_config_queries { replication_query };
	int automatic_config_rc = execute_all(admin, automatic_config_queries);
	if (automatic_config_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure replication hostgroups 930 and 931");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> automatic_blue_servers { automatic_cluster.blue_writer };
	int automatic_server_rc = bgd_admin_add_servers(admin, automatic_cluster, automatic_hg, automatic_blue_servers, false, 0);
	if (automatic_server_rc != EXIT_SUCCESS) {
		diag("Error: failed to add the automatic blue writer for wHG 930");
		return EXIT_FAILURE;
	}

	vector<string> load_queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_rc = execute_all(admin, load_queries);
	if (load_rc != EXIT_SUCCESS) {
		diag("Error: failed to load explicit and automatic SAVE scenarios");
		return EXIT_FAILURE;
	}

	string explicit_runtime_query =
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_rds_bgd_hostgroups "
		"WHERE writer_hostgroup=920 AND auto_generated=0";
	int explicit_runtime_rc = bgd_wait_for_condition(admin, explicit_runtime_query, kTimeoutSeconds);
	if (explicit_runtime_rc != EXIT_SUCCESS) {
		diag("Error: explicit wHG 920 did not reach runtime before SAVE");
		return EXIT_FAILURE;
	}

	string automatic_runtime_query =
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_rds_bgd_hostgroups "
		"WHERE writer_hostgroup=930 AND auto_generated=1";
	int automatic_runtime_rc = bgd_wait_for_condition(admin, automatic_runtime_query, kTimeoutSeconds);
	if (automatic_runtime_rc != EXIT_SUCCESS) {
		diag("Error: automatic wHG 930 did not reach runtime before SAVE");
		return EXIT_FAILURE;
	}

	string delete_query =
		"DELETE FROM mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(explicit_hg.blue_writer);
	vector<string> save_queries {
		delete_query,
		"SAVE MYSQL SERVERS FROM RUNTIME",
	};
	int save_rc = execute_all(admin, save_queries);
	if (save_rc != EXIT_SUCCESS) {
		diag("Error: failed to save runtime BGD rows to persistent configuration");
		return EXIT_FAILURE;
	}

	bool explicit_persisted = persistent_bgd_row_matches(admin, explicit_hg);
	bool automatic_absent = persistent_bgd_row_absent(admin, automatic_hg.blue_writer);
	ok(explicit_persisted && automatic_absent, "SAVE restores explicit wHG 920 and skips auto-generated wHG 930");
	return EXIT_SUCCESS;
}

/**
 * Run automatic discovery beside administrator-owned BGD and server rows.
 *
 * - Configure inactive explicit hostgroups 1310-1313.
 * - Set the configured green writer to SHUNNED.
 * - Enable automatic discovery and publish AVAILABLE topology.
 * - Verify the BGD row and green-server status remain unchanged.
 */
int test_admin_server_status_preserved(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.admin_owned;
	BGD_Hostgroups& hg = state.admin_owned_hg;

	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure administrator-owned simulated writers");
		return EXIT_FAILURE;
	}

	int monitor_rc = configure_monitor(admin, hg, false);
	if (monitor_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure monitoring for administrator-owned wHG 1310");
		return EXIT_FAILURE;
	}

	int row_rc = insert_explicit_bgd_row(admin, hg, "administrator-owned inactive BGD row", 0);
	if (row_rc != EXIT_SUCCESS) {
		diag("Error: failed to insert administrator-owned wHG 1310");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0] };
	int blue_rc = bgd_admin_add_servers(admin, cluster, hg, blue_servers, false, 0);
	if (blue_rc != EXIT_SUCCESS) {
		diag("Error: failed to load administrator-owned blue servers");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> green_servers { cluster.green_writer };
	int green_rc = bgd_admin_add_servers(admin, cluster, hg, green_servers, true, 0);
	if (green_rc != EXIT_SUCCESS) {
		diag("Error: failed to load administrator-owned green writer");
		return EXIT_FAILURE;
	}

	string shun_query =
		"UPDATE mysql_servers SET status='SHUNNED' WHERE hostgroup_id=" +
		to_string(hg.green_writer) + " AND hostname=" + bgd_sql_quote(cluster.green_writer.hostname) +
		" AND port=3306";
	vector<string> ownership_queries {
		shun_query,
		"LOAD MYSQL SERVERS TO RUNTIME",
		"SET mysql-aws_blue_green_deployment_auto_discovery='true'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};
	int ownership_rc = execute_all(admin, ownership_queries);
	if (ownership_rc != EXIT_SUCCESS) {
		diag("Error: failed to enable automatic discovery beside administrator-owned wHG 1310");
		return EXIT_FAILURE;
	}

	auto [bgd_before_rc, bgd_before] = bgd_admin_snapshot(admin, hg.blue_writer);
	auto [runtime_bgd_before_rc, runtime_bgd_before] = runtime_bgd_ownership_snapshot(admin, hg.blue_writer);
	auto [admin_before_rc, admin_before] = green_server_snapshot(admin, "mysql_servers", hg);
	auto [runtime_before_rc, runtime_before] = green_server_snapshot(admin, "runtime_mysql_servers", hg);
	if (bgd_before_rc != EXIT_SUCCESS || runtime_bgd_before_rc != EXIT_SUCCESS ||
		admin_before_rc != EXIT_SUCCESS || runtime_before_rc != EXIT_SUCCESS) {
		diag("Error: failed to snapshot administrator-owned BGD and green rows");
		return EXIT_FAILURE;
	}

	bool explicit_runtime_bgd =
		runtime_bgd_before.size() == 1 &&
		runtime_bgd_before[0].size() == 4 &&
		runtime_bgd_before[0][0] == "1312" &&
		runtime_bgd_before[0][1] == "1313" &&
		runtime_bgd_before[0][2] == "0" &&
		runtime_bgd_before[0][3] == "0";
	if (!explicit_runtime_bgd) {
		diag("Error: runtime BGD row does not contain the administrator-owned hostgroups and flags");
		return EXIT_FAILURE;
	}

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before administrator-owned discovery");
		return EXIT_FAILURE;
	}

	vector<BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.admin_owned_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology beside administrator-owned wHG 1310");
		return EXIT_FAILURE;
	}

	auto [probe_rc, probe] =
		sim.wait_for_probe_log(seq, cluster.blue_writer.endpoint(), BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0);
	if (probe_rc != EXIT_SUCCESS) {
		diag("Error: automatic discovery did not probe beside administrator-owned wHG 1310");
		return EXIT_FAILURE;
	}

	auto [bgd_after_rc, bgd_after] = bgd_admin_snapshot(admin, hg.blue_writer);
	auto [runtime_bgd_after_rc, runtime_bgd_after] = runtime_bgd_ownership_snapshot(admin, hg.blue_writer);
	auto [admin_after_rc, admin_after] = green_server_snapshot(admin, "mysql_servers", hg);
	auto [runtime_after_rc, runtime_after] = green_server_snapshot(admin, "runtime_mysql_servers", hg);
	if (bgd_after_rc != EXIT_SUCCESS || runtime_bgd_after_rc != EXIT_SUCCESS ||
		admin_after_rc != EXIT_SUCCESS || runtime_after_rc != EXIT_SUCCESS) {
		diag("Error: failed to read administrator-owned rows after discovery");
		return EXIT_FAILURE;
	}

	bool bgd_unchanged = bgd_before == bgd_after;
	bool runtime_bgd_unchanged = runtime_bgd_before == runtime_bgd_after;
	bool admin_servers_unchanged = admin_before == admin_after;
	bool runtime_servers_unchanged = runtime_before == runtime_after;
	ok(bgd_unchanged && runtime_bgd_unchanged && admin_servers_unchanged && runtime_servers_unchanged,
		"automatic discovery preserves administrator-owned wHG 1310 and its SHUNNED green writer");
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

	// Simulator: publish AVAILABLE topology for the blue writer in wHG 890.
	// ProxySQL: create an automatic row, disable discovery, and load explicit hostgroups 890-893.
	// Verify: explicit green hostgroups replace the nullable automatic row and persist.
	if (test_automatic_to_explicit(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: insert two BGD rows with one NULL green hostgroup, then one complete row.
	// Verify: invalid rows are rejected and complete hostgroups 910-913 load as explicit configuration.
	if (test_persistent_row_validation(admin, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: run explicit wHG 920 and auto-generated wHG 930, then SAVE runtime state.
	// Verify: SAVE persists only the explicit BGD row.
	if (test_save_from_runtime(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: configure inactive administrator-owned wHG 1310 with a SHUNNED green writer.
	// Simulator: publish AVAILABLE while automatic discovery is enabled.
	// Verify: the BGD row and green-server status remain unchanged.
	if (test_admin_server_status_preserved(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
