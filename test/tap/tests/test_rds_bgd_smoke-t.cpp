/**
 * @file test_rds_bgd_smoke-t.cpp
 * @brief Smoke test for TAP-controlled AWS RDS BGD simulation.
 *
 * Test steps:
 * 1. Connect to ProxySQL Admin and the SQLite3-server simulator.
 * 2. Configure both simulated writers as writable.
 * 3. Publish an AVAILABLE topology on the blue and green writer IPs.
 * 4. Configure ProxySQL with the blue writer and BGD hostgroups.
 * 5. Verify that ProxySQL reaches AVAILABLE and probes the green writer IP.
 */

#include <cstdlib>
#include <string>
#include <vector>

#include "rds_bgd_tap.h"
#include "command_line.h"
#include "utils.h"

int configure_proxysql_for_bgd(MYSQL* admin, RDS_BGD_Cluster& cluster) {
	RDS_BGD_Host& writer = cluster.blue_writer;
	return execute_all(admin, {
		"DELETE FROM mysql_servers",
		"DELETE FROM mysql_replication_hostgroups",
		"DELETE FROM mysql_aws_rds_bgd_hostgroups",
		"INSERT INTO mysql_replication_hostgroups(writer_hostgroup,reader_hostgroup) "
			"VALUES (10,20)",
		"INSERT INTO mysql_aws_rds_bgd_hostgroups("
			"writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,"
			"active,writer_is_also_reader,check_interval_ms,check_timeout_ms,comment) "
			"VALUES (10,20,30,40,1,0,100,800,'BGD simulator smoke test')",
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,use_ssl,comment) VALUES (10,'" +
			writer.hostname + "'," + std::to_string(writer.port) + ",0,'blue writer')",
		"SET mysql-monitor_username='testuser'",
		"SET mysql-monitor_password='testuser'",
		"SET mysql-monitor_enabled='true'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
		"LOAD MYSQL SERVERS TO RUNTIME",
	});
}

int main() {
	plan(3);

	CommandLine cl {};
	if (cl.getEnv()) {
		BAIL_OUT("failed to load TAP environment");
	}

	MYSQL* admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (admin == nullptr) {
		BAIL_OUT("failed to connect to ProxySQL Admin");
	}

	RDS_BGD_Simulator sim {};
	if (sim.connect(cl.host, 3306, cl.username, cl.password) != EXIT_SUCCESS) {
		mysql_close(admin);
		BAIL_OUT("failed to connect to the SQLite3-server simulator");
	}

	// Initialize the test cluster and make both simulated writers writable.
	RDS_BGD_Cluster cluster = bgd_cluster_init();
	for (Endpoint& writer : cluster.get_writer_hosts()) {
		if (sim.read_only_update(writer, false) != EXIT_SUCCESS) {
			mysql_close(admin);
			BAIL_OUT("failed to configure writer read_only state");
		}
	}

	// Record the last probe sequence before enabling BGD monitoring.
	auto [rc, last_seq] = sim.probe_log_last_sequence();
	if (rc != EXIT_SUCCESS) {
		mysql_close(admin);
		BAIL_OUT("failed to read the last BGD probe-log sequence");
	}

	// Publish the AVAILABLE topology on both simulated writer IPs.
	rc = sim.topology_update(cluster.get_writers(), cluster.get_topology("AVAILABLE"));
	ok(rc == EXIT_SUCCESS, "publish AVAILABLE topology to both writer IPs");
	if (rc != EXIT_SUCCESS) {
		mysql_close(admin);
		BAIL_OUT("failed to publish BGD topology");
	}

	// Configure ProxySQL with the blue writer and BGD hostgroups.
	if (configure_proxysql_for_bgd(admin, cluster) != EXIT_SUCCESS) {
		mysql_close(admin);
		BAIL_OUT("failed to configure ProxySQL for BGD monitoring");
	}

	// Wait for topology discovery to place the BGD hostgroups in AVAILABLE.
	rc = wait_for_cond(
		admin,
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_rds_bgd_hostgroups "
		"WHERE writer_hostgroup=10 AND status='AVAILABLE'",
		3);
	ok(rc == EXIT_SUCCESS, "ProxySQL enters the AVAILABLE BGD state");

	// Verify that ProxySQL probes metadata directly on the green writer IP.
	auto [probe_rc, green_probe] = sim.wait_for_probe_log(
		last_seq, cluster.green_writer.endpoint(),
		RDS_BGD_Probe_Kind::metadata, 3000, 0);
	ok(probe_rc == EXIT_SUCCESS, "ProxySQL probes topology directly on the green writer IP over plaintext");

	mysql_close(admin);
	return exit_status();
}
