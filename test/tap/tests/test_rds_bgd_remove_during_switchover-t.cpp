/**
 * @file test_rds_bgd_remove_during_switchover-t.cpp
 * @brief Removing BGD configuration during writer switchover.
 *
 * Steps:
 *
 * 1. Configure BGD hostgroups 1350-1353 and reach `AVAILABLE`.
 * 2. Publish `SWITCHOVER_IN_PROGRESS` and verify that the blue writer moves
 *    from hostgroup 1350 to hostgroup 1351.
 * 3. Delete writer hostgroup 1350 from `mysql_aws_rds_bgd_hostgroups`.
 * 4. Verify that the blue writer returns to hostgroup 1350 and the runtime BGD
 *    row is removed.
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
	RDS_BGD_Cluster cluster { bgd_cluster_init() };
	BGD_Hostgroups hostgroups { 1350, 1351, 1352, 1353 };
	vector<Endpoint> topology_endpoints { cluster.get_endpoints() };
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

int wait_for_bgd_row_absent(MYSQL* admin, BGD_Hostgroups& hg) {
	string query =
		"SELECT COUNT(*)=0 FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(hg.blue_writer);

	int rc = bgd_wait_for_condition(admin, query, kTimeoutSeconds);
	return rc;
}

/**
 * Configure BGD hostgroups 1350-1353.
 *
 * - Set `read_only=0` for the simulated blue and green writers.
 * - Publish `AVAILABLE` topology.
 * - Configure `mysql_servers` and `mysql_aws_rds_bgd_hostgroups`.
 * - Verify that the runtime BGD row reaches `AVAILABLE`.
 */
int test_bgd_status_available(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	// Set read_only=0 for the simulated blue and green writers.
	int writer_rc = bgd_set_writer_read_only_0(sim, cluster);
	if (writer_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure simulated writer read_only values");
		return EXIT_FAILURE;
	}

	// Publish AVAILABLE topology.
	vector<BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "AVAILABLE");
	int topology_rc = sim.topology_update(state.topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish AVAILABLE topology");
		return EXIT_FAILURE;
	}

	// Configure mysql_servers and mysql_aws_rds_bgd_hostgroups.
	vector<RDS_BGD_Host> blue_servers { cluster.blue_writer, cluster.blue_readers[0], cluster.blue_readers[1] };
	vector<RDS_BGD_Host> green_servers { cluster.green_writer, cluster.green_readers[0], cluster.green_readers[1] };

	int admin_rc = bgd_admin_setup(admin, cluster, hg, BGD_Admin_Mode::explicit_configuration, blue_servers, green_servers, 0, 0);
	if (admin_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure mysql_servers and mysql_aws_rds_bgd_hostgroups");
		return EXIT_FAILURE;
	}

	// Wait for the runtime BGD row to report AVAILABLE.
	int status_rc = bgd_wait_for_status(admin, hg, "AVAILABLE", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: runtime BGD status did not reach AVAILABLE");
		return EXIT_FAILURE;
	}

	ok(true, "BGD status for wHG 1350 reports AVAILABLE");
	return EXIT_SUCCESS;
}

/**
 * Move the BGD row for writer hostgroup 1350 into writer switchover.
 *
 * - Publish `SWITCHOVER_IN_PROGRESS`.
 * - Verify `WRITER_SWITCHOVER_IN_PROGRESS`.
 * - Verify that the blue writer moves to the blue reader hostgroup.
 */
int test_writer_switchover_in_progress(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	// Publish SWITCHOVER_IN_PROGRESS and wait for the runtime BGD status.
	vector<BGD_Topology_Row> topology = bgd_topology_with_readers(cluster, "SWITCHOVER_IN_PROGRESS");
	int topology_rc = sim.topology_update(state.topology_endpoints, topology);
	if (topology_rc != EXIT_SUCCESS) {
		diag("Error: failed to publish SWITCHOVER_IN_PROGRESS topology");
		return EXIT_FAILURE;
	}

	int status_rc = bgd_wait_for_status(admin, hg, "WRITER_SWITCHOVER_IN_PROGRESS", kTimeoutSeconds);
	if (status_rc != EXIT_SUCCESS) {
		diag("Error: runtime BGD status did not reach WRITER_SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	ok(true, "BGD status for wHG 1350 reports WRITER_SWITCHOVER_IN_PROGRESS");

	// Verify the blue writer was moved from the writer to the reader hostgroup.
	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, true, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: blue writer did not move to the blue reader hostgroup");
		return EXIT_FAILURE;
	}

	ok(true, "SWITCHOVER_IN_PROGRESS moves the blue writer from hostgroup 1350 to 1351");
	return EXIT_SUCCESS;
}

/**
 * Remove BGD configuration during writer switchover.
 *
 * - Delete writer hostgroup 1350 from `mysql_aws_rds_bgd_hostgroups`.
 * - Load the configuration to runtime without changing `mysql_servers`.
 * - Verify that the blue writer returns to hostgroup 1350.
 * - Verify that the runtime BGD row for writer hostgroup 1350 is removed.
 */
int test_remove_during_switchover(MYSQL* admin, TestState& state) {
	RDS_BGD_Cluster& cluster = state.cluster;
	BGD_Hostgroups& hg = state.hostgroups;

	// Delete the BGD row without changing mysql_servers or the configured hostgroups.
	string delete_bgd = "DELETE FROM mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(hg.blue_writer);
	vector<string> queries {
		delete_bgd,
		"LOAD MYSQL SERVERS TO RUNTIME",
	};

	int rc = execute_all(admin, queries);
	if (rc != EXIT_SUCCESS) {
		diag("Error: failed to delete and load the BGD configuration");
		return EXIT_FAILURE;
	}

	// Wait until deleting the row restores the blue writer to its writer hostgroup.
	int placement_rc = bgd_wait_for_server_placement(admin, hg.blue_writer, hg.blue_reader, cluster.blue_writer, false, kTimeoutSeconds);
	if (placement_rc != EXIT_SUCCESS) {
		diag("Error: blue writer did not return to the blue writer hostgroup");
		return EXIT_FAILURE;
	}

	// Wait until the deleted BGD row is absent from runtime.
	int row_rc = wait_for_bgd_row_absent(admin, hg);
	if (row_rc != EXIT_SUCCESS) {
		diag("Error: deleted BGD configuration remains in the runtime table");
		return EXIT_FAILURE;
	}

	ok(true, "deleting BGD configuration restores the blue writer from hostgroup 1351 to 1350");
	ok(true, "deleting wHG 1350 removes it from runtime_mysql_aws_rds_bgd_hostgroups");
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

	// Simulator: set the blue/green writers to read_only=0 and publish AVAILABLE topology.
	// ProxySQL: update mysql_servers and mysql_aws_rds_bgd_hostgroups with BGD configuration.
	// Verify: runtime_mysql_aws_rds_bgd_hostgroups status reports AVAILABLE.
	if (test_bgd_status_available(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish SWITCHOVER_IN_PROGRESS topology.
	// Verify: runtime_mysql_aws_rds_bgd_hostgroups status reports WRITER_SWITCHOVER_IN_PROGRESS.
	// Verify: runtime_mysql_servers moves the blue writer from writer hostgroup to reader hostgroup.
	if (test_writer_switchover_in_progress(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: delete wHG 1350 from mysql_aws_rds_bgd_hostgroups without changing mysql_servers.
	// Verify: the blue writer returns to hostgroup 1350 and the runtime BGD row is absent.
	if (test_remove_during_switchover(admin, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean the BGD TAP state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
