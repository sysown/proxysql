/**
 * @file test_rds_bgd_green_pool_cleanup-t.cpp
 * @brief BGD rollback and successful cleanup for public green-server statuses.
 *
 * Steps:
 *
 * 1. Configure ONLINE, SHUNNED, OFFLINE_SOFT, and OFFLINE_HARD green rows and
 *    establish one causal connection pool for each hostname.
 * 2. Roll back SWITCHOVER_IN_PROGRESS to AVAILABLE and verify that every
 *    green pool and configured status is preserved.
 * 3. Complete writer and reader switchover, then publish empty topology.
 * 4. Verify that cleanup drains ONLINE and SHUNNED pools, preserves
 *    OFFLINE_SOFT and OFFLINE_HARD pools, and retains all configured rows.
 */

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "command_line.h"
#include "rds_bgd_tap.h"
#include "utils.h"

const uint32_t kTimeoutSeconds = 3;
const int kRouterHostgroup = 1350;

struct GreenServer {
	int hostgroup;
	RDS_BGD_Host host;
	string status;
};

struct TestState {
	RDS_BGD_Cluster cluster { bgd_cluster_3_init() };
	RDS_BGD_Cluster extra { bgd_cluster_1_deployment_b_init() };
	BGD_Hostgroups hostgroups { 1300, 1301, 1302, 1303 };
	vector<Endpoint> topology_endpoints { cluster.get_endpoints() };
	vector<GreenServer> servers {
		{ hostgroups.green_writer, cluster.green_writer, "ONLINE" },
		{ hostgroups.green_reader, cluster.green_readers[0], "SHUNNED" },
		{ hostgroups.green_reader, cluster.green_readers[1], "OFFLINE_SOFT" },
		{ hostgroups.green_reader, extra.green_readers[0], "OFFLINE_HARD" },
	};
	vector<int64_t> pool_before {};
	vector<int64_t> pool_after {};
	vector<mysql_res_row> admin_snapshot {};
	vector<mysql_res_row> runtime_snapshot {};

	TestState() {
		topology_endpoints.push_back(extra.green_readers[0].endpoint());
	}
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

vector<BGD_Topology_Row> topology_with_readers(RDS_BGD_Cluster& cluster, string status) {
	vector<BGD_Topology_Row> rows = cluster.get_topology(status);
	for (RDS_BGD_Host& host : cluster.blue_readers) {
		rows.push_back({
			host.hostname,
			host.hostname,
			host.port,
			"BLUE_GREEN_DEPLOYMENT_SOURCE",
			status,
		});
	}
	for (RDS_BGD_Host& host : cluster.green_readers) {
		rows.push_back({
			host.hostname,
			host.hostname,
			host.port,
			"BLUE_GREEN_DEPLOYMENT_TARGET",
			status,
		});
	}
	return rows;
}

vector<BGD_Topology_Row> target_only_completed(RDS_BGD_Cluster& cluster) {
	vector<BGD_Topology_Row> rows {{
		cluster.green_writer.hostname,
		cluster.green_writer.hostname,
		cluster.green_writer.port,
		"BLUE_GREEN_DEPLOYMENT_TARGET",
		"SWITCHOVER_COMPLETED",
	}};
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

	return EXIT_SUCCESS;
}

int add_server(MYSQL* admin, int hostgroup, RDS_BGD_Host& host, string status) {
	string query =
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,use_ssl,comment) VALUES (" +
		to_string(hostgroup) + "," + bgd_sql_quote(host.hostname) + "," + to_string(host.port) +
		"," + bgd_sql_quote(status) + ",0," + bgd_sql_quote("BGD TAP pool " + host.ip) + ")";

	int rc = mysql_query(admin, query.c_str());
	if (rc != 0) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int set_server_status(MYSQL* admin, GreenServer& server) {
	string query =
		"UPDATE mysql_servers SET status=" + bgd_sql_quote(server.status) +
		" WHERE hostgroup_id=" + to_string(server.hostgroup) +
		" AND hostname=" + bgd_sql_quote(server.host.hostname) +
		" AND port=" + to_string(server.host.port);

	int rc = mysql_query(admin, query.c_str());
	if (rc != 0) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int set_default_hostgroup(MYSQL* admin, int hostgroup) {
	vector<string> queries {
		"UPDATE mysql_users SET default_hostgroup=" + to_string(hostgroup) + " WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	return rc;
}

int create_pool(CommandLine& cl, MYSQL* admin, int hostgroup) {
	int user_rc = set_default_hostgroup(admin, hostgroup);
	if (user_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	MYSQL* client = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (client == nullptr) {
		return EXIT_FAILURE;
	}

	auto [echo_rc, echo] = bgd_backend_ip_echo(client);
	mysql_close(client);
	return echo_rc;
}

rc_t<int64_t> pool_for_hostname(MYSQL* admin, string hostname) {
	string query =
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_mysql_connection_pool WHERE srv_host=" +
		bgd_sql_quote(hostname);

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		rc_t<int64_t> result { EXIT_FAILURE, 0 };
		return result;
	}

	int64_t count = strtoll(rows[0][0].c_str(), nullptr, 10);
	rc_t<int64_t> result { EXIT_SUCCESS, count };
	return result;
}

rc_t<vector<mysql_res_row>> green_snapshot(MYSQL* admin, string table, BGD_Hostgroups& hg) {
	string query =
		"SELECT hostgroup_id,hostname,port,status,use_ssl,weight,max_connections FROM " + table +
		" WHERE hostgroup_id IN (" + to_string(hg.green_writer) + "," + to_string(hg.green_reader) +
		") ORDER BY hostgroup_id,hostname,port";

	rc_t<vector<mysql_res_row>> result = mysql_query_ext_rows(admin, query);
	return result;
}

int read_pools(MYSQL* admin, vector<GreenServer>& servers, vector<int64_t>& pools) {
	pools.clear();
	for (GreenServer& server : servers) {
		auto [pool_rc, pool] = pool_for_hostname(admin, server.host.hostname);
		if (pool_rc != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}
		pools.push_back(pool);
	}
	return EXIT_SUCCESS;
}

bool all_pools_nonzero(vector<int64_t>& pools) {
	if (pools.size() != 4) {
		return false;
	}

	for (int64_t pool : pools) {
		if (pool < 1) {
			return false;
		}
	}
	return true;
}

int configure_status_matrix(CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	int read_only_rc = configure_read_only_values(sim, cluster);
	if (read_only_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated read_only values for wHG 1300");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0], cluster.green_readers[1] };
	int admin_rc = bgd_admin_setup(
		admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers, 0, 0
	);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups 1300-1303");
		return EXIT_FAILURE;
	}

	int extra_rc = add_server(admin, hg.green_reader, state.extra.green_readers[0], "ONLINE");
	if (extra_rc != EXIT_SUCCESS) {
		diag("Error: failed to add the OFFLINE_HARD green reader to hostgroup 1303");
		return EXIT_FAILURE;
	}

	for (size_t i = 0; i < state.servers.size(); ++i) {
		int router_rc = add_server(admin, kRouterHostgroup + static_cast<int>(i), state.servers[i].host, "ONLINE");
		if (router_rc != EXIT_SUCCESS) {
			diag("Error: failed to add pool-router row for green status index %zu", i);
			return EXIT_FAILURE;
		}
	}

	for (GreenServer& server : state.servers) {
		int status_rc = set_server_status(admin, server);
		if (status_rc != EXIT_SUCCESS) {
			diag("Error: failed to set %s for green server %s", server.status.c_str(), server.host.hostname.c_str());
			return EXIT_FAILURE;
		}
	}

	vector<string> load_queries { "LOAD MYSQL SERVERS TO RUNTIME" };
	int load_rc = execute_all(admin, load_queries);
	if (load_rc != EXIT_SUCCESS) {
		diag("Error: failed to load the green status matrix to runtime");
		return EXIT_FAILURE;
	}

	auto [admin_snapshot_rc, admin_snapshot] = green_snapshot(admin, "mysql_servers", hg);
	if (admin_snapshot_rc != EXIT_SUCCESS || admin_snapshot.size() != 4) {
		diag("Error: failed to snapshot four persistent green status rows");
		return EXIT_FAILURE;
	}
	state.admin_snapshot = admin_snapshot;

	auto [runtime_snapshot_rc, runtime_snapshot] = green_snapshot(admin, "runtime_mysql_servers", hg);
	if (runtime_snapshot_rc != EXIT_SUCCESS || runtime_snapshot.size() != 3) {
		diag("Error: failed to snapshot ONLINE, SHUNNED, and OFFLINE_SOFT runtime rows");
		return EXIT_FAILURE;
	}
	state.runtime_snapshot = runtime_snapshot;

	for (size_t i = 0; i < state.servers.size(); ++i) {
		int pool_rc = create_pool(cl, admin, kRouterHostgroup + static_cast<int>(i));
		if (pool_rc != EXIT_SUCCESS) {
			diag("Error: failed to create causal pool for green status index %zu", i);
			return EXIT_FAILURE;
		}
	}

	int user_rc = set_default_hostgroup(admin, hg.blue_writer);
	if (user_rc != EXIT_SUCCESS) {
		diag("Error: failed to restore testuser to writer hostgroup 1300");
		return EXIT_FAILURE;
	}

	int pools_rc = read_pools(admin, state.servers, state.pool_before);
	if (pools_rc != EXIT_SUCCESS || !all_pools_nonzero(state.pool_before)) {
		diag("Error: every green status must have a nonzero pool before lifecycle changes");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int publish_topology(BGD_Simulator& sim, TestState& state, string status) {
	vector<BGD_Topology_Row> topology = topology_with_readers(state.cluster, status);

	int rc = sim.topology_update(state.topology_endpoints, topology);
	return rc;
}

bool snapshots_match(MYSQL* admin, TestState& state) {
	auto [admin_rc, admin_rows] = green_snapshot(admin, "mysql_servers", state.hostgroups);
	auto [runtime_rc, runtime_rows] = green_snapshot(admin, "runtime_mysql_servers", state.hostgroups);
	if (admin_rc != EXIT_SUCCESS || runtime_rc != EXIT_SUCCESS) {
		return false;
	}

	bool matches = admin_rows == state.admin_snapshot && runtime_rows == state.runtime_snapshot;
	return matches;
}

/**
 * Roll back writer switchover with four green status pools.
 *
 * - Configure ONLINE, SHUNNED, OFFLINE_SOFT, and OFFLINE_HARD green rows.
 * - Establish a nonzero causal pool for every green hostname.
 * - Publish AVAILABLE, SWITCHOVER_IN_PROGRESS, then AVAILABLE.
 * - Verify rollback preserves every green pool and exact configured row.
 */
int test_rollback_preserves_green_pools(CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	int config_rc = configure_status_matrix(cl, admin, sim, state);
	if (config_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	int available_rc = publish_topology(sim, state, "AVAILABLE");
	if (available_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology for wHG 1300");
		return EXIT_FAILURE;
	}

	int available_status_rc = bgd_wait_for_status(admin, state.hostgroups, "AVAILABLE", kTimeoutSeconds);
	if (available_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1300 did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	int progress_rc = publish_topology(sim, state, "SWITCHOVER_IN_PROGRESS");
	if (progress_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_PROGRESS topology for wHG 1300");
		return EXIT_FAILURE;
	}

	int progress_status_rc =
		bgd_wait_for_status(admin, state.hostgroups, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (progress_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1300 did not reach WRITER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	int rollback_rc = publish_topology(sim, state, "AVAILABLE");
	if (rollback_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish rollback AVAILABLE topology for wHG 1300");
		return EXIT_FAILURE;
	}

	int rollback_status_rc = bgd_wait_for_status(admin, state.hostgroups, "AVAILABLE", kTimeoutSeconds);
	if (rollback_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1300 did not return to AVAILABLE");
		return EXIT_FAILURE;
	}

	vector<int64_t> pools_after_rollback {};
	int pools_rc = read_pools(admin, state.servers, pools_after_rollback);
	if (pools_rc != EXIT_SUCCESS || pools_after_rollback.size() != state.pool_before.size()) {
		diag("Error: failed to read green pools after rollback");
		return EXIT_FAILURE;
	}

	bool pools_preserved = true;
	for (size_t i = 0; i < state.pool_before.size(); ++i) {
		if (pools_after_rollback[i] < state.pool_before[i]) {
			pools_preserved = false;
		}
	}
	ok(pools_preserved, "AVAILABLE rollback preserves all four green status pools for wHG 1300");

	bool rows_preserved = snapshots_match(admin, state);
	ok(rows_preserved, "AVAILABLE rollback preserves the configured green rows and public statuses for wHG 1300");
	return EXIT_SUCCESS;
}

/**
 * Complete reader cleanup and drain eligible green pools.
 *
 * - Publish POST_PROCESSING and target-only SWITCHOVER_COMPLETED.
 * - Require every green pool to remain nonzero immediately before cleanup.
 * - Delete topology rows and verify that ONLINE and SHUNNED pools drain.
 */
int test_successful_cleanup_drains_non_offline(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	int post_rc = publish_topology(sim, state, "SWITCHOVER_IN_POST_PROCESSING");
	if (post_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_POST_PROCESSING topology for wHG 1300");
		return EXIT_FAILURE;
	}

	int post_status_rc =
		bgd_wait_for_status(admin, state.hostgroups, "WRITER_SWITCHOVER_POST_PROCESSING", kTimeoutSeconds);
	if (post_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1300 did not reach WRITER_SWITCHOVER_POST_PROCESSING");
		return EXIT_FAILURE;
	}

	vector<BGD_Topology_Row> completed = target_only_completed(state.cluster);
	int completed_rc = sim.topology_update(state.topology_endpoints, completed);
	if (completed_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish target-only SWITCHOVER_COMPLETED topology for wHG 1300");
		return EXIT_FAILURE;
	}

	int reader_status_rc =
		bgd_wait_for_status(admin, state.hostgroups, "READER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (reader_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1300 did not reach READER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	int baseline_rc = read_pools(admin, state.servers, state.pool_before);
	if (baseline_rc != EXIT_SUCCESS || !all_pools_nonzero(state.pool_before)) {
		diag("Error: every green status must have a nonzero pool immediately before reader cleanup");
		return EXIT_FAILURE;
	}

	int empty_rc = sim.topology_delete(state.topology_endpoints);
	if (empty_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish empty topology for wHG 1300");
		return EXIT_FAILURE;
	}

	int none_rc = bgd_wait_for_status(admin, state.hostgroups, "NONE", kTimeoutSeconds);
	if (none_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1300 did not reach NONE during reader cleanup");
		return EXIT_FAILURE;
	}

	int pools_rc = read_pools(admin, state.servers, state.pool_after);
	if (pools_rc != EXIT_SUCCESS || state.pool_after.size() != 4) {
		diag("Error: failed to read green pools after reader cleanup");
		return EXIT_FAILURE;
	}

	bool non_offline_drained = state.pool_after[0] == 0 && state.pool_after[1] == 0;
	ok(non_offline_drained, "reader cleanup drains ONLINE and SHUNNED green pools for wHG 1300");
	return EXIT_SUCCESS;
}

/**
 * Preserve offline pools and configured green rows during successful cleanup.
 *
 * - Compare OFFLINE_SOFT and OFFLINE_HARD pools with their causal baselines.
 * - Verify persistent and runtime green rows still match their pre-lifecycle
 *   snapshots.
 */
int test_cleanup_preserves_offline_pools(MYSQL* admin, TestState& state) {
	if (state.pool_before.size() != 4 || state.pool_after.size() != 4) {
		diag("Error: green pool baselines are incomplete after reader cleanup");
		return EXIT_FAILURE;
	}

	bool offline_pools_preserved =
		state.pool_after[2] == state.pool_before[2] &&
		state.pool_after[3] == state.pool_before[3];
	ok(offline_pools_preserved, "reader cleanup preserves OFFLINE_SOFT and OFFLINE_HARD green pools for wHG 1300");

	bool rows_preserved = snapshots_match(admin, state);
	ok(rows_preserved, "reader cleanup retains all configured green rows and public statuses for wHG 1300");
	return EXIT_SUCCESS;
}

int main() {
	plan(5);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// ProxySQL: configure four public green statuses and establish one causal pool for each hostname.
	// Simulator: publish AVAILABLE, SWITCHOVER_IN_PROGRESS, then AVAILABLE.
	// Verify: rollback preserves all four pools and exact configured green rows.
	if (test_rollback_preserves_green_pools(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish POST_PROCESSING, target-only SWITCHOVER_COMPLETED, then empty topology.
	// Verify: reader cleanup drains ONLINE and SHUNNED green pools.
	if (test_successful_cleanup_drains_non_offline(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Verify: reader cleanup preserves OFFLINE_SOFT/OFFLINE_HARD pools and configured green rows.
	if (test_cleanup_preserves_offline_pools(admin, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
