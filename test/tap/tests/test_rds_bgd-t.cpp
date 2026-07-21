#include <cstdlib>
#include <string>
#include <vector>

#include "command_line.h"
#include "rds_bgd_simulator.h"
#include "tap.h"
#include "utils.h"

namespace {

int execute_all(MYSQL* admin, const std::vector<std::string>& queries) {
	for (const std::string& query : queries) {
		if (mysql_query(admin, query.c_str()) != 0) {
			diag(
				"Admin query failed (%u): %s; query: %s",
				mysql_errno(admin), mysql_error(admin), query.c_str());
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

int configure_proxysql_for_bgd(
	MYSQL* admin, const RDS_BGD_Cluster& cluster)
{
	const RDS_BGD_Host& writer = cluster.blue_writer();
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

}  // namespace

int main() {
	plan(3);

	CommandLine cl {};
	if (cl.getEnv()) {
		BAIL_OUT("failed to load TAP environment");
	}

	MYSQL* admin = init_mysql_conn(
		cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (admin == nullptr) {
		BAIL_OUT("failed to connect to ProxySQL Admin");
	}

	RDS_BGD_Simulator simulator {};
	if (simulator.connect(
			cl.host, 3306, cl.username, cl.password) != EXIT_SUCCESS) {
		mysql_close(admin);
		BAIL_OUT("failed to connect to the SQLite3-server simulator");
	}

	const RDS_BGD_Cluster& cluster = rds_bgd_test_cluster();
	const RDS_BGD_Host* writers[] = {
		&cluster.blue_writer(),
		&cluster.green_writer(),
	};
	for (const RDS_BGD_Host* writer : writers) {
		if (simulator.read_only_update(
				{ writer->hostname, writer->port }, false) != EXIT_SUCCESS) {
			mysql_close(admin);
			BAIL_OUT("failed to configure writer read_only state");
		}
	}

	const rc_t<uint64_t> mark = simulator.probe_log_last_sequence();
	if (mark.first != EXIT_SUCCESS) {
		mysql_close(admin);
		BAIL_OUT("failed to read the BGD probe-log watermark");
	}

	const int update_rc = simulator.topology_update(
		cluster.get_writers(), cluster.get_topology("AVAILABLE"));
	ok(update_rc == EXIT_SUCCESS, "publish AVAILABLE topology to both writer IPs");
	if (update_rc != EXIT_SUCCESS) {
		mysql_close(admin);
		BAIL_OUT("failed to publish BGD topology");
	}

	if (configure_proxysql_for_bgd(admin, cluster) != EXIT_SUCCESS) {
		mysql_close(admin);
		BAIL_OUT("failed to configure ProxySQL for BGD monitoring");
	}

	const int status_rc = wait_for_cond(
		admin,
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_rds_bgd_hostgroups "
		"WHERE writer_hostgroup=10 AND status='AVAILABLE'",
		10);
	ok(status_rc == EXIT_SUCCESS, "ProxySQL enters the AVAILABLE BGD state");

	const rc_t<RDS_BGD_Probe_Log> green_probe = simulator.wait_for_probe_log(
		mark.second,
		cluster.green_writer().endpoint(),
		RDS_BGD_Probe_Kind::metadata,
		10000,
		0);
	ok(
		green_probe.first == EXIT_SUCCESS,
		"ProxySQL probes topology directly on the green writer IP over plaintext");

	mysql_close(admin);
	return exit_status();
}
