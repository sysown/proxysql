#ifndef TAP_TESTS_RDS_BGD_TAP_H
#define TAP_TESTS_RDS_BGD_TAP_H

#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <string>
#include <vector>

#include "rds_bgd_simulator.h"
#include "tap.h"

using namespace std;

inline int execute_all(MYSQL* admin, vector<string> queries);

inline RDS_BGD_Cluster bgd_cluster_init() {
	RDS_BGD_Cluster cluster {
		{ "db-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.11", 3306 },
		{ "db-1-green-iqu47r.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.14", 3306 },
		{
			{ "db-1-reader-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.12", 3306 },
			{ "db-1-reader-2.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.13", 3306 },
		},
		{
			{ "db-1-reader-1-green-dlzky7.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.15", 3306 },
			{ "db-1-reader-2-green-3fpjuu.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.16", 3306 },
		},
	};
	return cluster;
}

inline RDS_BGD_Cluster bgd_cluster_1_deployment_b_init() {
	RDS_BGD_Cluster cluster {
		{ "db-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.11", 3306 },
		{ "db-1-green-s7m2kx.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.17", 3306 },
		{
			{ "db-1-reader-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.12", 3306 },
			{ "db-1-reader-2.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.13", 3306 },
		},
		{
			{ "db-1-reader-1-green-v4n8qp.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.18", 3306 },
			{ "db-1-reader-2-green-w6h3rz.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.19", 3306 },
		},
	};
	return cluster;
}

inline RDS_BGD_Cluster bgd_cluster_2_init() {
	RDS_BGD_Cluster cluster {
		{ "db-2.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.20", 3306 },
		{ "db-2-green-iqu47r.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.23", 3306 },
		{
			{ "db-2-reader-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.21", 3306 },
			{ "db-2-reader-2.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.22", 3306 },
		},
		{
			{ "db-2-reader-1-green-dlzky7.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.24", 3306 },
			{ "db-2-reader-2-green-3fpjuu.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.25", 3306 },
		},
	};
	return cluster;
}

inline RDS_BGD_Cluster bgd_cluster_3_init() {
	RDS_BGD_Cluster cluster {
		{ "db-3.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.26", 3306 },
		{ "db-3-green-iqu47r.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.29", 3306 },
		{
			{ "db-3-reader-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.27", 3306 },
			{ "db-3-reader-2.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.28", 3306 },
		},
		{
			{ "db-3-reader-1-green-dlzky7.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.30", 3306 },
			{ "db-3-reader-2-green-3fpjuu.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.31", 3306 },
		},
	};
	return cluster;
}

enum class BGD_Admin_Mode {
	automatic,
	explicit_configuration,
};

struct BGD_Hostgroups {
	int blue_writer;
	int blue_reader;
	int green_writer;
	int green_reader;
};

inline vector<RDS_BGD_Topology_Row> bgd_topology_with_readers(RDS_BGD_Cluster& cluster, string status) {
	vector<RDS_BGD_Topology_Row> rows = cluster.get_topology(status);
	for (RDS_BGD_Host& host : cluster.blue_readers) {
		rows.push_back({ host.hostname, host.hostname, host.port, "BLUE_GREEN_DEPLOYMENT_SOURCE", status });
	}
	for (RDS_BGD_Host& host : cluster.green_readers) {
		rows.push_back({ host.hostname, host.hostname, host.port, "BLUE_GREEN_DEPLOYMENT_TARGET", status });
	}
	return rows;
}

inline int bgd_set_writer_read_only_0(RDS_BGD_Simulator& sim, RDS_BGD_Cluster& cluster) {
	if (sim.read_only_update(cluster.blue_writer.host_endpoint(), false) != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=0 for the simulated blue writer");
		return EXIT_FAILURE;
	}

	if (sim.read_only_update(cluster.green_writer.host_endpoint(), false) != EXIT_SUCCESS) {
		diag("Error: failed to set read_only=0 for the simulated green writer");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

inline int bgd_set_host_read_only_0(RDS_BGD_Simulator& sim, RDS_BGD_Host& host) {
	int rc = sim.read_only_update(host.host_endpoint(), false);
	return rc;
}

inline int bgd_set_host_read_only_1(RDS_BGD_Simulator& sim, RDS_BGD_Host& host) {
	int rc = sim.read_only_update(host.host_endpoint(), true);
	return rc;
}

inline string bgd_sql_quote(string value) {
	string quoted { "'" };
	for (char c : value) {
		quoted += c;
		if (c == '\'') {
			quoted += '\'';
		}
	}
	quoted += '\'';
	return quoted;
}

inline int bgd_admin_cleanup(MYSQL* admin) {
	vector<string> config_queries {
		"SET mysql-aws_blue_green_deployment_auto_discovery='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
		"DELETE FROM mysql_aws_rds_bgd_hostgroups",
		"LOAD MYSQL SERVERS TO RUNTIME",
	};
	int config_rc = execute_all(admin, config_queries);

	vector<string> state_queries {
		"DELETE FROM mysql_servers",
		"DELETE FROM mysql_replication_hostgroups",
		"UPDATE mysql_users SET default_hostgroup=0 WHERE username='testuser'",
		"LOAD MYSQL SERVERS TO RUNTIME",
		"LOAD MYSQL USERS TO RUNTIME",
	};
	int state_rc = execute_all(admin, state_queries);

	if (config_rc != EXIT_SUCCESS || state_rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

inline int bgd_admin_add_servers(
	MYSQL* admin, RDS_BGD_Cluster cluster, BGD_Hostgroups hostgroups,
	vector<RDS_BGD_Host> hosts, bool green, int use_ssl)
{
	vector<string> queries {};
	for (RDS_BGD_Host& host : hosts) {
		int hostgroup = hostgroups.blue_reader;
		if (!green && host.hostname == cluster.blue_writer.hostname) {
			hostgroup = hostgroups.blue_writer;
		} else if (green && host.hostname == cluster.green_writer.hostname) {
			hostgroup = hostgroups.green_writer;
		} else if (green) {
			hostgroup = hostgroups.green_reader;
		}

		string color = green ? "green " : "blue ";
		string comment = bgd_sql_quote("BGD TAP " + color + host.ip);
		string query =
			"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,use_ssl,comment) VALUES (" +
			to_string(hostgroup) + "," + bgd_sql_quote(host.hostname) + "," +
			to_string(host.port) + ",'ONLINE'," + to_string(use_ssl) + "," +
			comment + ")";
		queries.push_back(query);
	}

	int rc = execute_all(admin, queries);
	return rc;
}

inline int bgd_admin_setup(
	MYSQL* admin, RDS_BGD_Cluster cluster, BGD_Hostgroups hostgroups,
	BGD_Admin_Mode mode, vector<RDS_BGD_Host> blue_hosts,
	vector<RDS_BGD_Host> green_hosts = {}, int blue_use_ssl = 0, int green_use_ssl = 0)
{
	string auto_discovery = mode == BGD_Admin_Mode::automatic ? "true" : "false";
	vector<string> queries {
		"INSERT INTO mysql_replication_hostgroups(writer_hostgroup,reader_hostgroup) VALUES (" +
			to_string(hostgroups.blue_writer) + "," + to_string(hostgroups.blue_reader) + ")",
		"SET mysql-monitor_username='testuser'",
		"SET mysql-monitor_password='testuser'",
		"SET mysql-monitor_enabled='true'",
		"SET mysql-monitor_read_only_interval=100",
		"SET mysql-monitor_aws_rds_topology_discovery_interval=1",
		"SET mysql-aws_blue_green_deployment_auto_discovery='" + auto_discovery + "'",
		"UPDATE mysql_users SET default_hostgroup=" + to_string(hostgroups.blue_writer) +
			" WHERE username='testuser'",
	};

	if (mode == BGD_Admin_Mode::explicit_configuration) {
		string bgd_query =
			"INSERT INTO mysql_aws_rds_bgd_hostgroups("
			"writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,"
			"active,writer_is_also_reader,check_interval_ms,check_timeout_ms,comment) VALUES (" +
			to_string(hostgroups.blue_writer) + "," + to_string(hostgroups.blue_reader) + "," +
			to_string(hostgroups.green_writer) + "," + to_string(hostgroups.green_reader) +
			",1,0,100,800,'BGD TAP explicit configuration')";
		queries.push_back(bgd_query);
	}

	int config_rc = execute_all(admin, queries);
	if (config_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure ProxySQL BGD variables and hostgroups");
		return EXIT_FAILURE;
	}

	int blue_rc = bgd_admin_add_servers(admin, cluster, hostgroups, blue_hosts, false, blue_use_ssl);
	if (blue_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure blue servers");
		return EXIT_FAILURE;
	}

	int green_rc = bgd_admin_add_servers(admin, cluster, hostgroups, green_hosts, true, green_use_ssl);
	if (green_rc != EXIT_SUCCESS) {
		diag("Error: failed to configure green servers");
		return EXIT_FAILURE;
	}

	vector<string> load_queries {
		"LOAD MYSQL VARIABLES TO RUNTIME",
		"LOAD MYSQL USERS TO RUNTIME",
		"LOAD MYSQL SERVERS TO RUNTIME",
	};
	int load_rc = execute_all(admin, load_queries);
	if (load_rc != EXIT_SUCCESS) {
		diag("Error: failed to load ProxySQL BGD configuration to runtime");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

inline rc_t<vector<mysql_res_row>> bgd_runtime_rows(MYSQL* admin, int writer_hostgroup) {
	string query =
		"SELECT writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,"
		"auto_generated,status FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(writer_hostgroup);

	rc_t<vector<mysql_res_row>> result = mysql_query_ext_rows(admin, query);
	return result;
}

inline rc_t<vector<mysql_res_row>> bgd_runtime_servers(MYSQL* admin, vector<int> hostgroups) {
	string predicate {};
	for (size_t i = 0; i < hostgroups.size(); ++i) {
		if (i != 0) {
			predicate += ",";
		}
		predicate += to_string(hostgroups[i]);
	}

	string query =
		"SELECT hostgroup_id,hostname,port,status,use_ssl FROM runtime_mysql_servers WHERE hostgroup_id IN (" +
		predicate + ") ORDER BY hostgroup_id,hostname,port";

	rc_t<vector<mysql_res_row>> result = mysql_query_ext_rows(admin, query);
	return result;
}

inline rc_t<int64_t> bgd_connection_pool_count(MYSQL* admin, int hostgroup, string hostname = "") {
	string query =
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_mysql_connection_pool WHERE hostgroup=" +
		to_string(hostgroup);
	if (!hostname.empty()) {
		query += " AND srv_host=" + bgd_sql_quote(hostname);
	}

	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		rc_t<int64_t> result { EXIT_FAILURE, 0 };
		return result;
	}

	int64_t count = strtoll(rows[0][0].c_str(), nullptr, 10);
	rc_t<int64_t> result { EXIT_SUCCESS, count };
	return result;
}

inline rc_t<string> bgd_backend_ip_echo(MYSQL* proxy) {
	string query = "SELECT @@version_comment LIMIT 1";

	auto [rc, rows] = mysql_query_ext_rows(proxy, query);
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
		rc_t<string> result { EXIT_FAILURE, {} };
		return result;
	}

	rc_t<string> result { EXIT_SUCCESS, rows[0][0] };
	return result;
}

inline rc_t<uint64_t> bgd_probe_count_since(
	RDS_BGD_Simulator& sim, uint64_t sequence, Endpoint backend, RDS_BGD_Probe_Kind kind)
{
	auto [rc, logs] = sim.probe_log_since(sequence);
	if (rc != EXIT_SUCCESS) {
		rc_t<uint64_t> result { EXIT_FAILURE, 0 };
		return result;
	}

	uint64_t count = 0;
	for (const RDS_BGD_Probe_Log& log : logs) {
		bool backend_matches =
			log.backend.host == backend.host &&
			log.backend.port == backend.port;
		bool kind_matches = log.probe_kind == kind;
		if (backend_matches && kind_matches) {
			++count;
		}
	}

	rc_t<uint64_t> result { EXIT_SUCCESS, count };
	return result;
}

inline void bgd_diag_runtime_state(MYSQL* admin) {
	const string runtime_query =
		"SELECT writer_hostgroup,reader_hostgroup,IFNULL(green_writer_hostgroup,'NULL'),"
		"IFNULL(green_reader_hostgroup,'NULL'),auto_generated,status "
		"FROM runtime_mysql_aws_rds_bgd_hostgroups ORDER BY writer_hostgroup";
	auto [runtime_rc, runtime_rows] = mysql_query_ext_rows(admin, runtime_query);
	if (runtime_rc != EXIT_SUCCESS) {
		diag("RDS BGD diagnostic query failed with error %d", runtime_rc);
	} else if (runtime_rows.empty()) {
		diag("RDS BGD runtime hostgroup table is empty");
	} else {
		diag("RDS BGD runtime hostgroup rows:");
		for (const mysql_res_row& row : runtime_rows) {
			string row_text {};
			for (size_t i = 0; i < row.size(); ++i) {
				if (i != 0) {
					row_text += ",";
				}
				row_text += row[i];
			}
			diag("  %s", row_text.c_str());
		}
	}

	const string monitor_query =
		"SELECT hostname,port,IFNULL(read_only,'NULL'),IFNULL(error,'') FROM mysql_server_read_only_log "
		"ORDER BY time_start_us DESC LIMIT 10";
	auto [monitor_rc, monitor_rows] = mysql_query_ext_rows(admin, monitor_query);
	if (monitor_rc != EXIT_SUCCESS) {
		diag("RDS read_only diagnostic query failed with error %d", monitor_rc);
	} else if (monitor_rows.empty()) {
		diag("RDS read_only log has no rows");
	} else {
		diag("Latest RDS read_only monitor rows:");
		for (const mysql_res_row& row : monitor_rows) {
			string row_text {};
			for (size_t i = 0; i < row.size(); ++i) {
				if (i != 0) {
					row_text += ",";
				}
				row_text += row[i];
			}
			diag("  %s", row_text.c_str());
		}
	}
}

inline int bgd_wait_for_condition(MYSQL* admin, string query, uint32_t timeout_seconds) {
	int rc = wait_for_cond(admin, query, timeout_seconds);
	if (rc != EXIT_SUCCESS) {
		diag("RDS BGD wait timed out or failed for condition: %s", query.c_str());
		bgd_diag_runtime_state(admin);
	}
	return rc;
}

inline int bgd_wait_for_status(MYSQL* admin, BGD_Hostgroups& hostgroups, string status, uint32_t timeout_seconds) {
	string query =
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE writer_hostgroup=" +
		to_string(hostgroups.blue_writer) + " AND status=" + bgd_sql_quote(status);

	int rc = bgd_wait_for_condition(admin, query, timeout_seconds);
	return rc;
}

inline int bgd_wait_for_server_placement(
	MYSQL* admin, int writer_hostgroup, int reader_hostgroup, RDS_BGD_Host& host,
	bool in_reader_hostgroup, uint32_t timeout_seconds)
{
	string writer_count = in_reader_hostgroup ? "0" : "1";
	string reader_count = in_reader_hostgroup ? "1" : "0";

	string query = "SELECT "
		"(SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(writer_hostgroup) +
		" AND hostname=" + bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port) + ")=" +
		writer_count + " AND " +
		"(SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(reader_hostgroup) +
		" AND hostname=" + bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port) + ")=" +
		reader_count;

	int rc = bgd_wait_for_condition(admin, query, timeout_seconds);
	return rc;
}

inline rc_t<RDS_BGD_Probe_Log> bgd_wait_for_probe_from_backends(
	RDS_BGD_Simulator& sim, uint64_t sequence, vector<Endpoint> backends,
	RDS_BGD_Probe_Kind kind, uint32_t timeout_ms, int encrypted = -1)
{
	uint64_t deadline = monotonic_time() + static_cast<uint64_t>(timeout_ms) * 1000;
	do {
		auto [rc, logs] = sim.probe_log_since(sequence);
		if (rc != EXIT_SUCCESS) {
			rc_t<RDS_BGD_Probe_Log> result { EXIT_FAILURE, {} };
			return result;
		}

		for (const RDS_BGD_Probe_Log& log : logs) {
			for (const Endpoint& backend : backends) {
				bool backend_matches =
					log.backend.host == backend.host &&
					log.backend.port == backend.port;
				bool kind_matches = log.probe_kind == kind;
				bool encryption_matches =
					encrypted < 0 ||
					log.encrypted == (encrypted != 0);
				if (backend_matches && kind_matches && encryption_matches) {
					rc_t<RDS_BGD_Probe_Log> result { EXIT_SUCCESS, log };
					return result;
				}
			}
		}

		usleep(50000);
	} while (monotonic_time() < deadline);

	rc_t<RDS_BGD_Probe_Log> result { ETIMEDOUT, {} };
	return result;
}

/**
 * Verify that a configuration change does not restart BGD discovery.
 *
 * The expected result is ETIMEDOUT because no table-check probe should appear
 * after the given sequence.
 */
inline int bgd_expect_no_table_check(
	RDS_BGD_Simulator& sim, uint64_t sequence, vector<Endpoint> backends, uint32_t timeout_ms)
{
	auto [probe_rc, probe] = bgd_wait_for_probe_from_backends(
		sim, sequence, backends, RDS_BGD_Probe_Kind::table_check, timeout_ms
	);

	if (probe_rc == ETIMEDOUT) {
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

/**
 * Verify that one endpoint does not receive metadata probes.
 *
 * The expected result is ETIMEDOUT because no metadata probe should reach the
 * endpoint after the given sequence.
 */
inline int bgd_expect_no_metadata_probe(
	RDS_BGD_Simulator& sim, uint64_t sequence, Endpoint backend, uint32_t timeout_ms)
{
	vector<Endpoint> backends { backend };

	auto [probe_rc, probe] = bgd_wait_for_probe_from_backends(
		sim, sequence, backends, RDS_BGD_Probe_Kind::metadata, timeout_ms
	);

	if (probe_rc == ETIMEDOUT) {
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

/**
 * Verify that none of the supplied endpoints receives a metadata probe.
 *
 * The expected result is ETIMEDOUT because no metadata probe should reach any
 * endpoint after the given sequence.
 */
inline int bgd_expect_no_metadata_probe_from_backends(
	RDS_BGD_Simulator& sim, uint64_t sequence, vector<Endpoint> backends, uint32_t timeout_ms)
{
	auto [probe_rc, probe] = bgd_wait_for_probe_from_backends(
		sim, sequence, backends, RDS_BGD_Probe_Kind::metadata, timeout_ms
	);

	if (probe_rc == ETIMEDOUT) {
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

/**
 * Verify that read_only monitoring remains suppressed for the full observation window.
 *
 * The helper fails immediately if a new read_only log row appears after the
 * supplied baseline.
 */
inline int bgd_expect_no_read_only_log(MYSQL* admin, RDS_BGD_Host& host, int64_t baseline, uint32_t timeout_ms) {
	if (baseline < 0) {
		return EXIT_FAILURE;
	}

	uint64_t deadline = monotonic_time() + static_cast<uint64_t>(timeout_ms) * 1000;
	do {
		string query =
			"SELECT COUNT(*) FROM mysql_server_read_only_log WHERE hostname=" +
			bgd_sql_quote(host.hostname) + " AND port=" + to_string(host.port) +
			" AND time_start_us>" + to_string(baseline);

		auto [rc, rows] = mysql_query_ext_rows(admin, query);
		if (rc != EXIT_SUCCESS || rows.size() != 1 || rows[0].size() != 1) {
			return EXIT_FAILURE;
		}

		if (rows[0][0] != "0") {
			return EXIT_FAILURE;
		}

		usleep(50000);
	} while (monotonic_time() < deadline);

	return EXIT_SUCCESS;
}

inline int execute_all(MYSQL* admin, vector<string> queries) {
	for (string& query : queries) {
		if (mysql_query(admin, query.c_str()) != 0) {
			diag("Error: Admin query failed (%u): %s; query: %s",
				mysql_errno(admin), mysql_error(admin), query.c_str());
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

#endif  // TAP_TESTS_RDS_BGD_TAP_H
