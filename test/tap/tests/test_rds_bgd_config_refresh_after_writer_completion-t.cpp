/**
 * @file test_rds_bgd_config_refresh_after_writer_completion-t.cpp
 * @brief BGD configuration refresh during reader switchover.
 *
 * Steps:
 *
 * 1. Configure BGD hostgroups 1360-1363 and reach
 *    WRITER_SWITCHOVER_IN_PROGRESS.
 * 2. Publish target-only SWITCHOVER_COMPLETED and verify
 *    READER_SWITCHOVER_IN_PROGRESS.
 * 3. Change check_timeout_ms in mysql_aws_rds_bgd_hostgroups and load the
 *    configuration to runtime.
 * 4. Verify that the refresh performs a blue table check before blue metadata
 *    and republishes READER_SWITCHOVER_IN_PROGRESS.
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
	RDS_BGD_Cluster cluster { bgd_cluster_3_init() };
	BGD_Hostgroups hostgroups { 1360, 1361, 1362, 1363 };
	vector<Endpoint> topology_endpoints { cluster.get_endpoints() };
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

vector<RDS_BGD_Topology_Row> topology_with_readers(RDS_BGD_Cluster& cluster, string status) {
	vector<RDS_BGD_Topology_Row> rows = cluster.get_topology(status);
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

vector<RDS_BGD_Topology_Row> target_only_completed(RDS_BGD_Cluster& cluster) {
	vector<RDS_BGD_Topology_Row> rows {{
		cluster.green_writer.hostname,
		cluster.green_writer.hostname,
		cluster.green_writer.port,
		"BLUE_GREEN_DEPLOYMENT_TARGET",
		"SWITCHOVER_COMPLETED",
	}};
	return rows;
}

int configure_read_only_values(RDS_BGD_Simulator& sim, RDS_BGD_Cluster& cluster) {
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

/**
 * Reach reader switchover before changing the BGD configuration.
 *
 * - Publish SWITCHOVER_IN_PROGRESS before loading BGD hostgroups 1360-1363.
 * - Require WRITER_SWITCHOVER_IN_PROGRESS.
 * - Publish target-only SWITCHOVER_COMPLETED.
 * - Verify BGD status READER_SWITCHOVER_IN_PROGRESS.
 */
int test_reader_switchover_in_progress(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	int read_only_rc = configure_read_only_values(sim, cluster);
	if (read_only_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated read_only values for wHG 1360");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> progress = topology_with_readers(cluster, "SWITCHOVER_IN_PROGRESS");
	int topology_rc = sim.topology_update(state.topology_endpoints, progress);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_PROGRESS topology for wHG 1360");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0] };
	int admin_rc = bgd_admin_setup(
		admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers, 0, 0
	);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure BGD hostgroups 1360-1363");
		return EXIT_FAILURE;
	}

	int progress_status_rc =
		bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (progress_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1360 did not reach WRITER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	vector<RDS_BGD_Topology_Row> completed = target_only_completed(cluster);
	int completed_rc = sim.topology_update(state.topology_endpoints, completed);
	if (completed_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish target-only SWITCHOVER_COMPLETED topology for wHG 1360");
		return EXIT_FAILURE;
	}

	int reader_status_rc =
		bgd_wait_for_status(admin, hg, "READER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (reader_status_rc != EXIT_SUCCESS) {
		diag("Error: BGD status for wHG 1360 did not reach READER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	ok(true, "target-only SWITCHOVER_COMPLETED sets BGD status for wHG 1360 to READER_SWITCHOVER_IN_PROGRESS");
	return EXIT_SUCCESS;
}

/**
 * Refresh the BGD configuration during reader switchover.
 *
 * - Change check_timeout_ms for wHG 1360 and load it to runtime.
 * - Verify that the refresh starts with a blue-writer table check.
 * - Verify that blue-writer metadata follows the table check.
 * - Verify BGD status returns to READER_SWITCHOVER_IN_PROGRESS.
 */
int test_config_refresh_after_writer_completion(MYSQL* admin, RDS_BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	auto [seq_rc, seq] = sim.probe_log_last_sequence();
	if (seq_rc != EXIT_SUCCESS) {
		diag("Error: failed to read the probe sequence before refreshing wHG 1360");
		return EXIT_FAILURE;
	}

	string update_query =
		"UPDATE mysql_aws_rds_bgd_hostgroups SET check_timeout_ms=950 WHERE writer_hostgroup=" +
		to_string(hg.blue_writer);
	vector<string> queries {
		update_query,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};
	int refresh_rc = execute_all(admin, queries);
	if (refresh_rc != EXIT_SUCCESS) {
		diag("Error: failed to refresh check_timeout_ms for wHG 1360");
		return EXIT_FAILURE;
	}

	auto [table_rc, table] =
		sim.wait_for_probe_log(seq, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::table_check, kProbeTimeoutMs, 0);
	if (table_rc != EXIT_SUCCESS) {
		diag("Error: post-completion refresh did not start with a blue-writer table check for wHG 1360");
		return EXIT_FAILURE;
	}

	auto [blue_rc, blue] = sim.wait_for_probe_log(
		table.sequence_id, cluster.blue_writer.endpoint(), RDS_BGD_Probe_Kind::metadata, kProbeTimeoutMs, 0
	);
	if (blue_rc != EXIT_SUCCESS) {
		diag("Error: post-completion refresh did not probe blue-writer metadata for wHG 1360");
		return EXIT_FAILURE;
	}

	bool probe_order = table.sequence_id < blue.sequence_id;
	ok(probe_order, "post-completion refresh checks the table before blue-writer metadata for wHG 1360");

	int status_rc =
		bgd_wait_for_status(admin, hg, "READER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: refreshed wHG 1360 did not republish READER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	ok(true, "post-completion refresh republishes READER_SWITCHOVER_IN_PROGRESS for wHG 1360");
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

	// Simulator: publish SWITCHOVER_IN_PROGRESS, then target-only SWITCHOVER_COMPLETED.
	// ProxySQL: configure BGD hostgroups 1360-1363.
	// Verify: BGD status for wHG 1360 reports READER_SWITCHOVER_IN_PROGRESS.
	if (test_reader_switchover_in_progress(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: change check_timeout_ms and load the BGD configuration to runtime.
	// Verify: refresh runs blue table check, then blue metadata, and republishes READER_SWITCHOVER_IN_PROGRESS.
	if (test_config_refresh_after_writer_completion(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
