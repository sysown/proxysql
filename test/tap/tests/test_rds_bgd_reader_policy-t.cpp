/**
 * @file test_rds_bgd_reader_policy-t.cpp
 * @brief BGD matched-reader, offline-reader, and writer-fallback routing.
 *
 * Steps:
 *
 * 1. Publish SWITCHOVER_IN_POST_PROCESSING with one mapped and one unmapped
 *    blue reader.
 * 2. Verify that the mapped blue reader remains ONLINE and reader traffic
 *    reaches its green target instead of the unmapped blue reader.
 * 3. Publish SWITCHOVER_IN_POST_PROCESSING without reader pairs while both
 *    blue readers are OFFLINE_SOFT or OFFLINE_HARD, then verify that they do
 *    not trigger writer fallback.
 * 4. Make one blue reader ONLINE but omit it from topology and verify that
 *    writer fallback keeps the reader hostgroup routable.
 */

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "command_line.h"
#include "rds_bgd_tap.h"
#include "utils.h"

const uint32_t kTimeoutSeconds = 3;

struct TestState {
	RDS_BGD_Cluster matched { bgd_cluster_init() };
	BGD_Hostgroups matched_hg { 1280, 1281, 1282, 1283 };
	vector<Endpoint> matched_endpoints { matched.get_endpoints() };

	RDS_BGD_Cluster fallback { bgd_cluster_2_init() };
	BGD_Hostgroups fallback_hg { 1290, 1291, 1292, 1293 };
	vector<Endpoint> fallback_endpoints { fallback.get_endpoints() };
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

vector<BGD_Topology_Row> topology_with_reader_pairs(RDS_BGD_Cluster& cluster, string status, size_t pairs) {
	vector<BGD_Topology_Row> rows = cluster.get_topology(status);
	for (size_t i = 0; i < pairs; ++i) {
		rows.push_back({
			cluster.blue_readers[i].hostname,
			cluster.blue_readers[i].hostname,
			cluster.blue_readers[i].port,
			"BLUE_GREEN_DEPLOYMENT_SOURCE",
			status,
		});
		rows.push_back({
			cluster.green_readers[i].hostname,
			cluster.green_readers[i].hostname,
			cluster.green_readers[i].port,
			"BLUE_GREEN_DEPLOYMENT_TARGET",
			status,
		});
	}
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

int configure_bgd(
	MYSQL* admin, BGD_Simulator& sim, RDS_BGD_Cluster& cluster, BGD_Hostgroups& hg, size_t green_reader_count)
{
	int read_only_rc = configure_read_only_values(sim, cluster);
	if (read_only_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated read_only values for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer };
	for (size_t i = 0; i < green_reader_count; ++i) {
		green_servers.push_back(cluster.green_readers[i]);
	}

	int admin_rc = bgd_admin_setup(
		admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers, 0, 0
	);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups for wHG %d", hg.blue_writer);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int publish_post_processing(
	BGD_Simulator& sim, vector<Endpoint> endpoints, RDS_BGD_Cluster& cluster, size_t pairs)
{
	vector<BGD_Topology_Row> topology =
		topology_with_reader_pairs(cluster, "SWITCHOVER_IN_POST_PROCESSING", pairs);

	int rc = sim.topology_update(endpoints, topology);
	return rc;
}

int wait_for_reader_online(MYSQL* admin, BGD_Hostgroups& hg, RDS_BGD_Host& host) {
	string query =
		"SELECT COUNT(*)=1 FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hg.blue_reader) +
		" AND hostname=" + bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port) +
		" AND status='ONLINE'";

	int rc = bgd_wait_for_condition(admin, query, kTimeoutSeconds);
	return rc;
}

int wait_for_writer_reader_membership(MYSQL* admin, BGD_Hostgroups& hg, RDS_BGD_Cluster& cluster, int expected) {
	string query =
		"SELECT COUNT(*)=" + to_string(expected) +
		" FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(hg.blue_reader) +
		" AND hostname=" + bgd_sql_quote(cluster.blue_writer.hostname) +
		" AND port=" + to_string(cluster.blue_writer.port);

	int rc = bgd_wait_for_condition(admin, query, kTimeoutSeconds);
	return rc;
}

int set_blue_reader_statuses(MYSQL* admin, BGD_Hostgroups& hg, RDS_BGD_Cluster& cluster,
	string first_status, string second_status)
{
	string first_query =
		"UPDATE mysql_servers SET status=" + bgd_sql_quote(first_status) +
		" WHERE hostgroup_id=" + to_string(hg.blue_reader) +
		" AND hostname=" + bgd_sql_quote(cluster.blue_readers[0].hostname) +
		" AND port=" + to_string(cluster.blue_readers[0].port);
	string second_query =
		"UPDATE mysql_servers SET status=" + bgd_sql_quote(second_status) +
		" WHERE hostgroup_id=" + to_string(hg.blue_reader) +
		" AND hostname=" + bgd_sql_quote(cluster.blue_readers[1].hostname) +
		" AND port=" + to_string(cluster.blue_readers[1].port);
	vector<string> queries {
		first_query,
		second_query,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	return rc;
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

/**
 * Apply reader matching during SWITCHOVER_IN_POST_PROCESSING.
 *
 * - Configure blue readers 0 and 1 in hostgroup 1281.
 * - Publish SWITCHOVER_IN_POST_PROCESSING topology with a pair only for blue
 *   reader 0.
 * - Verify that the mapped reader remains ONLINE.
 * - Route a client through hostgroup 1281 and verify that it reaches the
 *   mapped green reader instead of the unmapped blue reader.
 */
int test_matched_unmatched_readers(CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.matched;
	BGD_Hostgroups& hg = state.matched_hg;

	int config_rc = configure_bgd(admin, sim, cluster, hg, 1);
	if (config_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure matched-reader scenario for wHG 1280");
		return EXIT_FAILURE;
	}

	// Prefer the unmapped reader heavily so a routing check fails if BGD leaves it eligible.
	string mapped_weight =
		"UPDATE mysql_servers SET weight=1 WHERE hostgroup_id=" + to_string(hg.blue_reader) +
		" AND hostname=" + bgd_sql_quote(cluster.blue_readers[0].hostname);
	string unmapped_weight =
		"UPDATE mysql_servers SET weight=1000000 WHERE hostgroup_id=" + to_string(hg.blue_reader) +
		" AND hostname=" + bgd_sql_quote(cluster.blue_readers[1].hostname);
	vector<string> weight_queries {
		mapped_weight,
		unmapped_weight,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int weight_rc = execute_all(admin, weight_queries);
	if (weight_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure deterministic reader weights in hostgroup 1281");
		return EXIT_FAILURE;
	}

	int topology_rc = publish_post_processing(sim, state.matched_endpoints, cluster, 1);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish one-pair SWITCHOVER_IN_POST_PROCESSING topology for wHG 1280");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_POST_PROCESSING", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1280 did not reach WRITER_SWITCHOVER_POST_PROCESSING");
		return EXIT_FAILURE;
	}

	int matched_rc = wait_for_reader_online(admin, hg, cluster.blue_readers[0]);
	if (matched_rc != EXIT_SUCCESS) {
		diag("Error: mapped blue reader did not remain ONLINE in hostgroup 1281");
		return EXIT_FAILURE;
	}

	ok(true, "SWITCHOVER_IN_POST_PROCESSING keeps the mapped blue reader ONLINE in hostgroup 1281");

	int user_rc = set_default_hostgroup(admin, hg.blue_reader);
	if (user_rc != EXIT_SUCCESS) {
		diag("Error: failed to route testuser through reader hostgroup 1281");
		return EXIT_FAILURE;
	}

	auto [echo_rc, echo] = connect_and_echo(cl);
	if (echo_rc != EXIT_SUCCESS) {
		diag("Error: failed to connect through reader hostgroup 1281");
		return EXIT_FAILURE;
	}

	bool mapped_reader_routing = echo.find(cluster.green_readers[0].ip) != string::npos;
	ok(mapped_reader_routing, "SWITCHOVER_IN_POST_PROCESSING routes hostgroup 1281 through the mapped green reader");
	return EXIT_SUCCESS;
}

/**
 * Exclude offline blue readers from writer-fallback calculation.
 *
 * - Configure both blue readers in hostgroup 1291 as OFFLINE_SOFT and
 *   OFFLINE_HARD.
 * - Publish SWITCHOVER_IN_POST_PROCESSING topology without reader pairs.
 * - Verify that the blue writer is not added to reader hostgroup 1291.
 */
int test_offline_blue_servers(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.fallback;
	BGD_Hostgroups& hg = state.fallback_hg;

	int config_rc = configure_bgd(admin, sim, cluster, hg, 0);
	if (config_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure offline-reader scenario for wHG 1290");
		return EXIT_FAILURE;
	}

	int offline_rc = set_blue_reader_statuses(admin, hg, cluster, "OFFLINE_SOFT", "OFFLINE_HARD");
	if (offline_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure OFFLINE_SOFT and OFFLINE_HARD blue readers in hostgroup 1291");
		return EXIT_FAILURE;
	}

	int topology_rc = publish_post_processing(sim, state.fallback_endpoints, cluster, 0);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish writer-only SWITCHOVER_IN_POST_PROCESSING topology for wHG 1290");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_POST_PROCESSING", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1290 did not reach WRITER_SWITCHOVER_POST_PROCESSING");
		return EXIT_FAILURE;
	}

	int writer_absent_rc = wait_for_writer_reader_membership(admin, hg, cluster, 0);
	if (writer_absent_rc != EXIT_SUCCESS) {
		diag("Error: offline blue readers incorrectly triggered writer fallback in hostgroup 1291");
		return EXIT_FAILURE;
	}

	ok(true, "OFFLINE_SOFT and OFFLINE_HARD blue readers do not trigger writer fallback in hostgroup 1291");
	return EXIT_SUCCESS;
}

/**
 * Route the reader hostgroup through writer fallback.
 *
 * - Make blue reader 0 ONLINE and publish SWITCHOVER_IN_POST_PROCESSING
 *   without reader pairs.
 * - Verify that the blue writer is added to reader hostgroup 1291.
 * - Connect through hostgroup 1291 and verify routing reaches the green writer
 *   IP pinned for the blue writer hostname.
 */
int test_writer_reader_fallback(CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.fallback;
	BGD_Hostgroups& hg = state.fallback_hg;

	int online_rc = set_blue_reader_statuses(admin, hg, cluster, "ONLINE", "OFFLINE_HARD");
	if (online_rc != EXIT_SUCCESS) {
		diag("Error: failed to make one blue reader eligible for writer fallback");
		return EXIT_FAILURE;
	}

	int topology_rc = publish_post_processing(sim, state.fallback_endpoints, cluster, 0);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish writer-only SWITCHOVER_IN_POST_PROCESSING topology for wHG 1290");
		return EXIT_FAILURE;
	}

	int writer_present_rc = wait_for_writer_reader_membership(admin, hg, cluster, 1);
	if (writer_present_rc != EXIT_SUCCESS) {
		diag("Error: writer fallback did not add the blue writer to reader hostgroup 1291");
		return EXIT_FAILURE;
	}

	int user_rc = set_default_hostgroup(admin, hg.blue_reader);
	if (user_rc != EXIT_SUCCESS) {
		diag("Error: failed to route testuser through reader hostgroup 1291");
		return EXIT_FAILURE;
	}

	auto [echo_rc, echo] = connect_and_echo(cl);
	if (echo_rc != EXIT_SUCCESS) {
		diag("Error: failed to connect through writer fallback in reader hostgroup 1291");
		return EXIT_FAILURE;
	}

	bool green_writer_routing = echo.find(cluster.green_writer.ip) != string::npos;
	ok(green_writer_routing, "writer fallback keeps hostgroup 1291 routable through the green writer IP");
	return EXIT_SUCCESS;
}

int main() {
	plan(4);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: publish SWITCHOVER_IN_POST_PROCESSING with one reader pair for wHG 1280.
	// Verify: only the mapped blue reader remains ONLINE in reader hostgroup 1281.
	if (test_matched_unmatched_readers(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: configure both blue readers in hostgroup 1291 as OFFLINE_SOFT and OFFLINE_HARD.
	// Simulator: publish SWITCHOVER_IN_POST_PROCESSING without reader pairs.
	// Verify: offline blue readers do not add the blue writer to reader hostgroup 1291.
	if (test_offline_blue_servers(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: make one blue reader ONLINE.
	// Simulator: publish SWITCHOVER_IN_POST_PROCESSING without reader pairs.
	// Verify: writer fallback keeps reader hostgroup 1291 routable through the green writer IP.
	if (test_writer_reader_fallback(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
