#ifndef TAP_TESTS_AURORA_BGD_TAP_H
#define TAP_TESTS_AURORA_BGD_TAP_H

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>

#include "aurora_bgd_simulator.h"
#include "tap.h"

using std::move;
using std::string;
using std::to_string;
using std::vector;

/**
 * @brief Complete simulator fixture for one Aurora blue/green deployment.
 */
struct Aurora_BGD_Test_Deployment {
	string name;                                      ///< Human-readable fixture name.
	string domain_name;                               ///< Domain appended to member identifiers.
	string blue_replica_set;                          ///< Production simulator membership identity.
	string target_replica_set;                        ///< Target simulator membership identity.
	Aurora_BGD_Endpoint target_cluster_endpoint;      ///< Target cluster topology endpoint.
	Aurora_BGD_Membership_Set production;             ///< Production membership and serving backends.
	Aurora_BGD_Membership_Set target;                 ///< Target membership and serving backends.
	string source_topology_id;                        ///< SOURCE topology row identifier.
	string target_topology_id;                        ///< TARGET topology row identifier.
};

/**
 * @brief Build one Aurora member fixture with stable default metrics.
 *
 * @param server_id Aurora member identifier.
 * @param session_id Writer or reader session identity.
 * @param endpoint Hostname and fixed simulator address.
 * @param current Whether the member belongs to current membership.
 * @return Initialized member fixture.
 */
inline Aurora_BGD_Member aurora_bgd_member(
	string server_id, string session_id, Aurora_BGD_Endpoint endpoint, bool current = true
) {
	Aurora_BGD_Member member;
	member.server_id = move(server_id);
	member.session_id = move(session_id);
	member.endpoint = move(endpoint);
	member.last_update_timestamp = "2099-01-01 00:00:00";
	member.is_current = current;
	return member;
}

/**
 * @brief Build the primary three-member Aurora BGD fixture.
 * @return Deployment A with one writer and two readers per environment.
 */
inline Aurora_BGD_Test_Deployment aurora_bgd_deployment_a() {
	Aurora_BGD_Test_Deployment deployment;
	deployment.name = "Aurora BGD deployment A";
	deployment.domain_name = ".a1.us-east-1.rds.amazonaws.com";
	deployment.blue_replica_set = "aurora-bgd-blue-a";
	deployment.target_replica_set = "aurora-bgd-target-a";
	deployment.source_topology_id = "aurora-bgd-source-a";
	deployment.target_topology_id = "aurora-bgd-target-a";
	deployment.target_cluster_endpoint = {
		"aurora-a-green.cluster-a1.us-east-1.rds.amazonaws.com", "127.0.11.20", 3306
	};
	deployment.production = {
		deployment.blue_replica_set,
		{
			aurora_bgd_member("aurora-a-writer", "MASTER_SESSION_ID",
				{"aurora-a-writer.a1.us-east-1.rds.amazonaws.com", "127.0.11.11", 3306}),
			aurora_bgd_member("aurora-a-reader-1", "reader-a-1",
				{"aurora-a-reader-1.a1.us-east-1.rds.amazonaws.com", "127.0.11.12", 3306}),
			aurora_bgd_member("aurora-a-reader-2", "reader-a-2",
				{"aurora-a-reader-2.a1.us-east-1.rds.amazonaws.com", "127.0.11.13", 3306}),
		},
		{}
	};
	for (Aurora_BGD_Member& member : deployment.production.members) {
		deployment.production.serving_endpoints.push_back(member.endpoint);
	}
	deployment.target = {
		deployment.target_replica_set,
		{
			aurora_bgd_member("aurora-a-writer-green-k7m2", "MASTER_SESSION_ID",
				{"aurora-a-writer-green-k7m2.a1.us-east-1.rds.amazonaws.com", "127.0.11.21", 3306}),
			aurora_bgd_member("aurora-a-reader-1-green-p4q8", "reader-a-1",
				{"aurora-a-reader-1-green-p4q8.a1.us-east-1.rds.amazonaws.com", "127.0.11.22", 3306}),
			aurora_bgd_member("aurora-a-reader-2-green-v9n3", "reader-a-2",
				{"aurora-a-reader-2-green-v9n3.a1.us-east-1.rds.amazonaws.com", "127.0.11.23", 3306}),
		},
		{deployment.target_cluster_endpoint}
	};
	for (Aurora_BGD_Member& member : deployment.target.members) {
		deployment.target.serving_endpoints.push_back(member.endpoint);
	}
	return deployment;
}

/**
 * @brief Build an independent writer-only Aurora BGD fixture.
 * @return Deployment B with one member per environment.
 */
inline Aurora_BGD_Test_Deployment aurora_bgd_deployment_b_writer_only() {
	Aurora_BGD_Test_Deployment deployment;
	deployment.name = "Aurora BGD deployment B writer-only";
	deployment.domain_name = ".b1.us-east-1.rds.amazonaws.com";
	deployment.blue_replica_set = "aurora-bgd-blue-b";
	deployment.target_replica_set = "aurora-bgd-target-b";
	deployment.source_topology_id = "aurora-bgd-source-b";
	deployment.target_topology_id = "aurora-bgd-target-b";
	deployment.target_cluster_endpoint = {
		"aurora-b-green.cluster-b1.us-east-1.rds.amazonaws.com", "127.0.12.20", 3306
	};
	deployment.production = {
		deployment.blue_replica_set,
		{
			aurora_bgd_member("aurora-b-writer", "MASTER_SESSION_ID",
				{"aurora-b-writer.b1.us-east-1.rds.amazonaws.com", "127.0.12.11", 3306}),
		},
		{}
	};
	deployment.production.serving_endpoints.push_back(deployment.production.members.front().endpoint);
	deployment.target = {
		deployment.target_replica_set,
		{
			aurora_bgd_member("aurora-b-writer-green-h2s6", "MASTER_SESSION_ID",
				{"aurora-b-writer-green-h2s6.b1.us-east-1.rds.amazonaws.com", "127.0.12.21", 3306}),
		},
		{deployment.target_cluster_endpoint}
	};
	deployment.target.serving_endpoints.push_back(deployment.target.members.front().endpoint);
	return deployment;
}

/**
 * @brief Build a writer-only fixture whose production identifier contains `green`.
 * @return Deployment C with one member per environment.
 */
inline Aurora_BGD_Test_Deployment aurora_bgd_deployment_c_writer_only() {
	Aurora_BGD_Test_Deployment deployment;
	deployment.name = "Aurora BGD deployment C writer-only";
	deployment.domain_name = ".c1.us-east-1.rds.amazonaws.com";
	deployment.blue_replica_set = "aurora-bgd-blue-c";
	deployment.target_replica_set = "aurora-bgd-target-c";
	deployment.source_topology_id = "aurora-bgd-source-c";
	deployment.target_topology_id = "aurora-bgd-target-c";
	deployment.target_cluster_endpoint = {
		"aurora-c-green.cluster-c1.us-east-1.rds.amazonaws.com", "127.0.13.20", 3306
	};
	deployment.production = {
		deployment.blue_replica_set,
		{
			aurora_bgd_member("aurora-c-green-writer", "MASTER_SESSION_ID",
				{"aurora-c-green-writer.c1.us-east-1.rds.amazonaws.com", "127.0.13.11", 3306}),
		},
		{}
	};
	deployment.production.serving_endpoints.push_back(deployment.production.members.front().endpoint);
	deployment.target = {
		deployment.target_replica_set,
		{
			aurora_bgd_member("aurora-c-green-writer-green-m5n9", "MASTER_SESSION_ID",
				{"aurora-c-green-writer-green-m5n9.c1.us-east-1.rds.amazonaws.com", "127.0.13.21", 3306}),
		},
		{deployment.target_cluster_endpoint}
	};
	deployment.target.serving_endpoints.push_back(deployment.target.members.front().endpoint);
	return deployment;
}

inline string aurora_bgd_sql_quote(const string& value) {
	string quoted {"'"};
	for (char c : value) {
		quoted += c;
		if (c == '\'') {
			quoted += '\'';
		}
	}
	quoted += '\'';
	return quoted;
}

inline int aurora_bgd_execute_all(MYSQL* admin, const vector<string>& queries) {
	for (const string& query : queries) {
		if (mysql_query(admin, query.c_str()) != 0) {
			diag("Aurora BGD admin query failed: %s; query: %s", mysql_error(admin), query.c_str());
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

inline int aurora_bgd_admin_cleanup(MYSQL* admin) {
	return aurora_bgd_execute_all(admin, {
		"SET mysql-aws_blue_green_deployment_auto_discovery='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
		"DELETE FROM mysql_aws_aurora_hostgroups",
		"DELETE FROM mysql_servers",
		"UPDATE mysql_users SET default_hostgroup=0 WHERE username='testuser'",
		"LOAD MYSQL SERVERS TO RUNTIME",
		"LOAD MYSQL USERS TO RUNTIME",
	});
}

/**
 * @brief Configure ProxySQL for one simulated Aurora deployment.
 *
 * @details Installs monitor credentials, the Aurora hostgroup row, production
 *   servers, and the test user's default route, then loads each module to runtime.
 *
 * @param admin ProxySQL Admin connection.
 * @param deployment Deployment fixture to configure.
 * @param writer_hg Production writer hostgroup.
 * @param reader_hg Production reader hostgroup.
 * @param green_writer_hg Explicit green writer hostgroup, or -1 for NULL.
 * @param green_reader_hg Explicit green reader hostgroup, or -1 for NULL.
 * @param auto_discovery Whether Aurora BGD auto-discovery is enabled.
 * @param check_interval_ms Aurora monitor interval.
 * @param writer_is_also_reader Whether the writer also belongs to the reader hostgroup.
 * @param use_ssl Whether configured production members use TLS.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
inline int aurora_bgd_admin_setup(
	MYSQL* admin, Aurora_BGD_Test_Deployment& deployment,
	int writer_hg, int reader_hg, int green_writer_hg, int green_reader_hg,
	bool auto_discovery, int check_interval_ms = 100,
	bool writer_is_also_reader = false, bool use_ssl = false
) {
	vector<string> queries {
		"SET mysql-monitor_username='aurora1'",
		"SET mysql-monitor_password='pass1'",
		"SET mysql-monitor_enabled='true'",
		"SET mysql-aws_blue_green_deployment_auto_discovery='" +
			string(auto_discovery ? "true" : "false") + "'",
		"UPDATE mysql_users SET default_hostgroup=" + to_string(writer_hg) +
			" WHERE username='testuser'",
	};

	string green_columns = green_writer_hg >= 0
		? to_string(green_writer_hg) + "," + to_string(green_reader_hg)
		: "NULL,NULL";
	queries.push_back(
		"INSERT INTO mysql_aws_aurora_hostgroups("
		"writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,"
		"active,aurora_port,domain_name,max_lag_ms,check_interval_ms,check_timeout_ms,"
		"writer_is_also_reader,new_reader_weight,add_lag_ms,min_lag_ms,lag_num_checks,"
		"autopurge_missing_checks,comment) VALUES (" +
		to_string(writer_hg) + "," + to_string(reader_hg) + "," + green_columns +
		",1," + to_string(deployment.production.members.front().endpoint.port) + "," +
		aurora_bgd_sql_quote(deployment.domain_name) +
		",200," + to_string(check_interval_ms) + ",800," +
		to_string(writer_is_also_reader ? 1 : 0) +
		",1,30,30,1,0," + aurora_bgd_sql_quote(deployment.name) + ")");

	for (Aurora_BGD_Member& member : deployment.production.members) {
		const int hostgroup = member.session_id == "MASTER_SESSION_ID" ? writer_hg : reader_hg;
		queries.push_back(
			"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,use_ssl,comment) VALUES (" +
			to_string(hostgroup) + "," + aurora_bgd_sql_quote(member.endpoint.hostname) +
			"," + to_string(member.endpoint.port) +
			",'ONLINE'," + string(use_ssl ? "1" : "0") +
			",'Aurora BGD production member')");
	}
	queries.push_back("LOAD MYSQL VARIABLES TO RUNTIME");
	queries.push_back("LOAD MYSQL SERVERS TO RUNTIME");
	queries.push_back("LOAD MYSQL USERS TO RUNTIME");
	return aurora_bgd_execute_all(admin, queries);
}

/**
 * @brief Build the two-row AVAILABLE topology for a deployment.
 * @param deployment Deployment fixture.
 * @return SOURCE and TARGET topology rows.
 */
inline vector<BGD_Topology_Row> aurora_bgd_available_topology(
	Aurora_BGD_Test_Deployment& deployment
) {
	return {
		{
			deployment.source_topology_id,
			deployment.production.members.front().endpoint.hostname,
			deployment.production.members.front().endpoint.port,
			"BLUE_GREEN_DEPLOYMENT_SOURCE",
			"AVAILABLE",
		},
		{
			deployment.target_topology_id,
			deployment.target_cluster_endpoint.hostname,
			deployment.target_cluster_endpoint.port,
			"BLUE_GREEN_DEPLOYMENT_TARGET",
			"AVAILABLE",
		},
	};
}

/**
 * @brief Build an active two-row topology with one shared status.
 * @param deployment Deployment fixture.
 * @param status AWS switchover status assigned to both rows.
 * @return SOURCE and TARGET topology rows.
 */
inline vector<BGD_Topology_Row> aurora_bgd_topology(
	Aurora_BGD_Test_Deployment& deployment, const string& status
) {
	vector<BGD_Topology_Row> rows = aurora_bgd_available_topology(deployment);
	for (BGD_Topology_Row& row : rows) {
		row.status = status;
	}
	return rows;
}

/**
 * @brief Build the lone TARGET row used for completed Aurora switchovers.
 * @param deployment Deployment fixture.
 * @return One SWITCHOVER_COMPLETED target row.
 */
inline vector<BGD_Topology_Row> aurora_bgd_completed_topology(
	Aurora_BGD_Test_Deployment& deployment
) {
	return {
		{
			deployment.target_topology_id,
			deployment.target_cluster_endpoint.hostname,
			deployment.target_cluster_endpoint.port,
			"BLUE_GREEN_DEPLOYMENT_TARGET",
			"SWITCHOVER_COMPLETED",
		},
	};
}

/**
 * @brief Collect every production and target backend eligible for topology probes.
 * @param deployment Deployment fixture.
 * @return Simulator backend endpoints without altering fixture order.
 */
inline vector<Endpoint> aurora_bgd_topology_backends(Aurora_BGD_Test_Deployment& deployment) {
	vector<Endpoint> backends = deployment.production.backends();
	vector<Endpoint> target_backends = deployment.target.backends();
	backends.insert(backends.end(), target_backends.begin(), target_backends.end());
	return backends;
}

/**
 * @brief Publish both membership sets and the AVAILABLE topology.
 * @param sim Connected shared AWS simulator.
 * @param deployment Deployment fixture to publish.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
inline int aurora_bgd_publish(
	BGD_Simulator& sim, Aurora_BGD_Test_Deployment& deployment
) {
	if (sim.replica_update(
		deployment.production.replica_set_id,
		deployment.production.replica_rows(),
		deployment.production.backends()) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	if (sim.replica_update(
		deployment.target.replica_set_id,
		deployment.target.replica_rows(),
		deployment.target.backends()) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return sim.topology_update(
		aurora_bgd_topology_backends(deployment),
		aurora_bgd_available_topology(deployment));
}

static const char kAuroraBGDRouteProbeQuery[] =
	"SELECT SERVER_ID,"
	"IF("
		"SESSION_ID = 'MASTER_SESSION_ID' AND "
		"SERVER_ID <> (SELECT SERVER_ID FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS WHERE SESSION_ID = 'MASTER_SESSION_ID' ORDER BY LAST_UPDATE_TIMESTAMP DESC LIMIT 1), "
		"'probably_former_MASTER_SESSION_ID', SESSION_ID"
	") SESSION_ID, "
	"LAST_UPDATE_TIMESTAMP, "
	"IF(SESSION_ID = 'MASTER_SESSION_ID', 0, REPLICA_LAG_IN_MILLISECONDS) AS REPLICA_LAG_IN_MILLISECONDS, "
	"CPU "
	"FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS WHERE"
	" ( "
	"(REPLICA_LAG_IN_MILLISECONDS >= 0 AND REPLICA_LAG_IN_MILLISECONDS <= 600000)"
	" OR SESSION_ID = 'MASTER_SESSION_ID'"
	" ) "
	"AND LAST_UPDATE_TIMESTAMP > NOW() - INTERVAL 180 SECOND"
	" ORDER BY SERVER_ID";

inline bool aurora_bgd_routing_probe_reached(
	BGD_Simulator& sim, uint64_t sequence, const Endpoint& expected_backend
) {
	// Client-route fixtures use TLS while Aurora monitor fixtures use plaintext,
	// so a background monitor probe cannot satisfy this client-query assertion.
	auto [rc, log] = sim.wait_for_replica_probe_log(
		sequence, expected_backend, Aurora_Replica_Probe_Kind::ordinary,
		1000, 1);
	return rc == EXIT_SUCCESS;
}

inline int aurora_bgd_wait_for_status(
	MYSQL* admin, int writer_hg, const string& status, uint32_t timeout_seconds
) {
	string query =
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_aurora_hostgroups WHERE writer_hostgroup=" +
		to_string(writer_hg) + " AND bgd_status=" + aurora_bgd_sql_quote(status);
	return wait_for_cond(admin, query, timeout_seconds);
}

inline rc_t<BGD_Probe_Log> aurora_bgd_wait_for_topology_probe(
	BGD_Simulator& sim, uint64_t sequence, const vector<Endpoint>& backends,
	BGD_Probe_Kind kind, uint32_t timeout_ms
) {
	const uint64_t deadline = monotonic_time() + static_cast<uint64_t>(timeout_ms) * 1000;
	do {
		auto [rc, logs] = sim.probe_log_since(sequence);
		if (rc != EXIT_SUCCESS) {
			return {EXIT_FAILURE, {}};
		}
		for (const BGD_Probe_Log& log : logs) {
			for (const Endpoint& backend : backends) {
				if (log.backend.host == backend.host && log.backend.port == backend.port
					&& log.probe_kind == kind) {
					return {EXIT_SUCCESS, log};
				}
			}
		}
		usleep(50000);
	} while (monotonic_time() < deadline);
	return {ETIMEDOUT, {}};
}

inline rc_t<Aurora_Replica_Probe_Log> aurora_bgd_wait_for_replica_probe(
	BGD_Simulator& sim, uint64_t sequence, const vector<Endpoint>& backends,
	Aurora_Replica_Probe_Kind kind, uint32_t timeout_ms, const string& replica_set = ""
) {
	const uint64_t deadline = monotonic_time() + static_cast<uint64_t>(timeout_ms) * 1000;
	do {
		auto [rc, logs] = sim.replica_probe_log_since(sequence);
		if (rc != EXIT_SUCCESS) {
			return {EXIT_FAILURE, {}};
		}
		for (const Aurora_Replica_Probe_Log& log : logs) {
			for (const Endpoint& backend : backends) {
				if (log.backend.host == backend.host && log.backend.port == backend.port
					&& log.probe_kind == kind
					&& (replica_set.empty() || log.replica_set_id == replica_set)) {
					return {EXIT_SUCCESS, log};
				}
			}
		}
		usleep(50000);
	} while (monotonic_time() < deadline);
	return {ETIMEDOUT, {}};
}

#endif  // TAP_TESTS_AURORA_BGD_TAP_H
