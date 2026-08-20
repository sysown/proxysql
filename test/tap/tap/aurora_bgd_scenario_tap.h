#ifndef TAP_TESTS_AURORA_BGD_SCENARIO_TAP_H
#define TAP_TESTS_AURORA_BGD_SCENARIO_TAP_H

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "aurora_bgd_tap.h"
#include "command_line.h"
#include "utils.h"

namespace aurora_bgd_scenario {

using std::string;
using std::to_string;
using std::vector;

const uint32_t kWaitSeconds = 5;
const uint32_t kProbeTimeoutMs = 5000;

/**
 * @brief Connections shared by one focused Aurora BGD TAP scenario.
 */
struct Context {
	MYSQL* admin { nullptr };  ///< ProxySQL Admin connection owned by the scenario.
	BGD_Simulator simulator;   ///< Connected shared AWS simulator controller.
};

inline bool scalar_is(MYSQL* admin, const string& query, const string& expected) {
	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	return rc == EXIT_SUCCESS && rows.size() == 1 && rows.front().size() == 1
		&& rows.front().front() == expected;
}

/**
 * @brief Connect a scenario to ProxySQL and reset shared Aurora simulator state.
 * @param cl TAP environment and connection options.
 * @param context Receives the Admin and simulator connections.
 * @return EXIT_SUCCESS when the isolated fixture is ready.
 */
inline int setup(CommandLine& cl, Context& context) {
	if (cl.getEnv()) {
		diag("Error: failed to load TAP environment");
		return EXIT_FAILURE;
	}
	context.admin = init_mysql_conn(
		cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (context.admin == nullptr) {
		diag("Error: failed to connect to ProxySQL Admin");
		return EXIT_FAILURE;
	}
	char simulator_username[] = "aurora1";
	char simulator_password[] = "pass1"; // NOSONAR: fixed simulator fixture credential.
	if (context.simulator.connect(
		cl.host, 3306, simulator_username, simulator_password) != EXIT_SUCCESS) {
		diag("Error: failed to connect to the shared AWS simulator");
		mysql_close(context.admin);
		context.admin = nullptr;
		return EXIT_FAILURE;
	}
	if (aurora_bgd_admin_cleanup(context.admin) != EXIT_SUCCESS
			|| context.simulator.cleanup() != EXIT_SUCCESS) {
		diag("Error: failed to clear prior Aurora BGD state");
		mysql_close(context.admin);
		context.admin = nullptr;
		return EXIT_FAILURE;
	}
	int user_rc = aurora_bgd_execute_all(context.admin, {
		"DELETE FROM mysql_users WHERE username='testuser'",
		"INSERT INTO mysql_users(username,password,active,default_hostgroup,transaction_persistent) "
			"VALUES ('testuser','testuser',1,0,1)",
		"LOAD MYSQL USERS TO RUNTIME",
	});
	if (user_rc != EXIT_SUCCESS) {
		mysql_close(context.admin);
		context.admin = nullptr;
	}
	return user_rc;
}

/**
 * @brief Remove runtime configuration and simulator state between scenarios.
 * @param context Active scenario context.
 * @return EXIT_SUCCESS when both stores were cleared.
 */
inline int reset(Context& context) {
	return aurora_bgd_admin_cleanup(context.admin) == EXIT_SUCCESS
		&& context.simulator.cleanup() == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * @brief Reset a scenario, remove its test user, and close the Admin connection.
 * @param context Active scenario context.
 * @return EXIT_SUCCESS when every cleanup operation succeeds.
 */
inline int cleanup(Context& context) {
	int reset_rc = reset(context);
	int user_rc = context.admin == nullptr ? EXIT_FAILURE : aurora_bgd_execute_all(context.admin, {
		"DELETE FROM mysql_users WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	});
	if (context.admin != nullptr) {
		mysql_close(context.admin);
		context.admin = nullptr;
	}
	return reset_rc == EXIT_SUCCESS && user_rc == EXIT_SUCCESS
		? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * @brief Configure one deployment through the common Aurora Admin fixture.
 * @param context Active scenario context.
 * @param deployment Deployment fixture to configure.
 * @param writer_hostgroup Production writer hostgroup.
 * @param reader_hostgroup Production reader hostgroup.
 * @param green_writer_hostgroup Explicit green writer hostgroup, or -1 for NULL.
 * @param green_reader_hostgroup Explicit green reader hostgroup, or -1 for NULL.
 * @param automatic Whether BGD auto-discovery is enabled.
 * @param check_interval_ms Aurora monitor interval.
 * @param writer_is_also_reader Whether the writer also belongs to the reader hostgroup.
 * @param use_ssl Whether configured production members use TLS.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
inline int configure(
	Context& context, Aurora_BGD_Test_Deployment& deployment,
	int writer_hostgroup, int reader_hostgroup,
	int green_writer_hostgroup, int green_reader_hostgroup,
	bool automatic = false, int check_interval_ms = 100,
	bool writer_is_also_reader = false, bool use_ssl = false
) {
	return aurora_bgd_admin_setup(
		context.admin, deployment, writer_hostgroup, reader_hostgroup,
		green_writer_hostgroup, green_reader_hostgroup, automatic,
		check_interval_ms, writer_is_also_reader, use_ssl);
}

/**
 * @brief Publish both membership sets and the AVAILABLE topology.
 * @param context Active scenario context.
 * @param deployment Deployment fixture to publish.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
inline int publish_available(
	Context& context, Aurora_BGD_Test_Deployment& deployment
) {
	return aurora_bgd_publish(context.simulator, deployment);
}

/**
 * @brief Replace the published topology phase for a deployment.
 * @param context Active scenario context.
 * @param deployment Deployment fixture whose backends serve the topology.
 * @param status AWS topology status assigned to SOURCE and TARGET rows.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
inline int publish_status(
	Context& context, Aurora_BGD_Test_Deployment& deployment, const string& status
) {
	return context.simulator.topology_update(
		aurora_bgd_topology_backends(deployment),
		aurora_bgd_topology(deployment, status));
}

/**
 * @brief Publish production and target membership with an initial topology phase.
 * @param context Active scenario context.
 * @param deployment Deployment fixture to publish.
 * @param status Initial AWS topology status.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
inline int publish_initial(
	Context& context, Aurora_BGD_Test_Deployment& deployment,
	const string& status
) {
	return context.simulator.replica_update(
			deployment.production.replica_set_id,
			deployment.production.replica_rows(), deployment.production.backends()) == EXIT_SUCCESS
		&& context.simulator.replica_update(
			deployment.target.replica_set_id,
			deployment.target.replica_rows(), deployment.target.backends()) == EXIT_SUCCESS
		&& context.simulator.topology_update(
			aurora_bgd_topology_backends(deployment),
			aurora_bgd_topology(deployment, status)) == EXIT_SUCCESS
		? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * @brief Publish completion while retaining another deployment's serving backends.
 * @param context Active scenario context.
 * @param serving_deployment Fixture whose backends receive the topology response.
 * @param completed_deployment Fixture providing the completed target identity.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
inline int publish_completed(
	Context& context, Aurora_BGD_Test_Deployment& serving_deployment,
	Aurora_BGD_Test_Deployment& completed_deployment
) {
	return context.simulator.topology_update(
		aurora_bgd_topology_backends(serving_deployment),
		aurora_bgd_completed_topology(completed_deployment));
}

inline bool runtime_status_is(
	MYSQL* admin, int writer_hostgroup, const string& status
) {
	return scalar_is(
		admin,
		"SELECT COUNT(*) FROM runtime_mysql_aws_aurora_hostgroups WHERE writer_hostgroup=" +
			to_string(writer_hostgroup) + " AND bgd_status=" + aurora_bgd_sql_quote(status),
		"1");
}

inline bool server_count(
	MYSQL* admin, const string& table, int hostgroup, const string& hostname,
	int expected, const string& status = ""
) {
	string query =
		"SELECT COUNT(*) FROM " + table + " WHERE hostgroup_id=" +
		to_string(hostgroup) + " AND hostname=" + aurora_bgd_sql_quote(hostname);
	if (!status.empty()) {
		query += " AND status=" + aurora_bgd_sql_quote(status);
	}
	return scalar_is(admin, query, to_string(expected));
}

inline int wait_for_writer_placement(
	MYSQL* admin, int writer_hostgroup, int reader_hostgroup,
	const string& hostname, bool demoted
) {
	string query =
		"SELECT ((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		to_string(writer_hostgroup) + " AND hostname=" + aurora_bgd_sql_quote(hostname) +
		")=" + (demoted ? "0" : "1") + ") AND "
		"((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		to_string(reader_hostgroup) + " AND hostname=" + aurora_bgd_sql_quote(hostname) +
		")=" + (demoted ? "1" : "0") + ")";
	return wait_for_cond(admin, query, kWaitSeconds);
}

inline bool writer_placement(
	MYSQL* admin, int writer_hostgroup, int reader_hostgroup,
	const string& hostname, bool demoted
) {
	return wait_for_writer_placement(
		admin, writer_hostgroup, reader_hostgroup, hostname, demoted) == EXIT_SUCCESS;
}

inline int set_default_hostgroup(MYSQL* admin, int hostgroup) {
	return aurora_bgd_execute_all(admin, {
		"UPDATE mysql_users SET default_hostgroup=" + to_string(hostgroup) +
			" WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	});
}

inline int add_route(
	MYSQL* admin, int hostgroup, const string& hostname,
	const string& status = "ONLINE", bool use_ssl = true,
	const string& comment = "Aurora BGD scenario route"
) {
	return aurora_bgd_execute_all(admin, {
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,use_ssl,comment) VALUES (" +
			to_string(hostgroup) + "," + aurora_bgd_sql_quote(hostname) +
			",3306," + aurora_bgd_sql_quote(status) + "," +
			string(use_ssl ? "1" : "0") + "," + aurora_bgd_sql_quote(comment) + ")",
		"LOAD MYSQL SERVERS TO RUNTIME",
	});
}

inline int add_member_routes(
	MYSQL* admin, Aurora_BGD_Test_Deployment& deployment,
	const vector<int>& hostgroups
) {
	if (hostgroups.size() != deployment.production.members.size()) {
		diag("Member-route hostgroup count does not match production membership");
		return EXIT_FAILURE;
	}
	vector<string> queries;
	for (size_t i = 0; i < hostgroups.size(); ++i) {
		queries.push_back(
			"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,use_ssl,comment) VALUES (" +
			to_string(hostgroups[i]) + "," +
			aurora_bgd_sql_quote(deployment.production.members[i].endpoint.hostname) +
			",3306,'ONLINE',1,'Aurora BGD scenario member route')");
	}
	queries.push_back("LOAD MYSQL SERVERS TO RUNTIME");
	return aurora_bgd_execute_all(admin, queries);
}

inline bool route_to_backend(
	CommandLine& cl, Context& context, const Endpoint& expected_backend
) {
	auto [sequence_rc, sequence] = context.simulator.replica_probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS) {
		return false;
	}
	MYSQL* client = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (client == nullptr) {
		return false;
	}
	auto [query_rc, rows] = mysql_query_ext_rows(client, kAuroraBGDRouteProbeQuery);
	(void)rows;
	if (query_rc != EXIT_SUCCESS) {
		diag("Backend routing query failed with MySQL error %d: %s",
			mysql_errno(client), mysql_error(client));
		mysql_close(client);
		return false;
	}
	mysql_close(client);
	return aurora_bgd_routing_probe_reached(
		context.simulator, sequence, expected_backend);
}

inline bool route_members(
	CommandLine& cl, Context& context, Aurora_BGD_Test_Deployment& deployment,
	const vector<int>& hostgroups, bool target
) {
	if (hostgroups.size() != deployment.production.members.size()) {
		return false;
	}
	for (size_t i = 0; i < hostgroups.size(); ++i) {
		if (set_default_hostgroup(context.admin, hostgroups[i]) != EXIT_SUCCESS) {
			return false;
		}
		const Endpoint expected = target
			? deployment.target.members[i].endpoint.backend()
			: deployment.production.members[i].endpoint.backend();
		if (!route_to_backend(cl, context, expected)) {
			return false;
		}
	}
	return true;
}

inline int64_t pool_connections(MYSQL* admin, int hostgroup) {
	auto [rc, rows] = mysql_query_ext_rows(
		admin,
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_mysql_connection_pool "
		"WHERE hostgroup=" + to_string(hostgroup));
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows.front().size() != 1) {
		return -1;
	}
	return strtoll(rows.front().front().c_str(), nullptr, 10);
}

inline int64_t pool_connections_for_hostname(MYSQL* admin, const string& hostname) {
	auto [rc, rows] = mysql_query_ext_rows(
		admin,
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_mysql_connection_pool "
		"WHERE srv_host=" + aurora_bgd_sql_quote(hostname));
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows.front().size() != 1) {
		return -1;
	}
	return strtoll(rows.front().front().c_str(), nullptr, 10);
}

inline int wait_for_hostname_pool_count(
	MYSQL* admin, const string& hostname, const string& comparison
) {
	return wait_for_cond(
		admin,
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0)" + comparison +
			" FROM stats_mysql_connection_pool WHERE srv_host=" +
			aurora_bgd_sql_quote(hostname),
		kWaitSeconds);
}

inline int wait_for_pool_count(
	MYSQL* admin, int hostgroup, const string& comparison
) {
	return wait_for_cond(
		admin,
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0)" + comparison +
			" FROM stats_mysql_connection_pool WHERE hostgroup=" + to_string(hostgroup),
		kWaitSeconds);
}

inline bool ordinary_probe_reached(
	Context& context, uint64_t sequence,
	Aurora_BGD_Test_Deployment& deployment, int encrypted = -1
) {
	for (Aurora_BGD_Member& member : deployment.production.members) {
		auto [rc, log] = context.simulator.wait_for_replica_probe_log(
			sequence, member.endpoint.backend(), Aurora_Replica_Probe_Kind::ordinary,
			kProbeTimeoutMs, encrypted, deployment.production.replica_set_id);
		if (rc == EXIT_SUCCESS) {
			return true;
		}
	}
	return false;
}

inline bool membership_probe_reached(
	Context& context, uint64_t sequence,
	Aurora_BGD_Test_Deployment& deployment, int encrypted = -1
) {
	for (Aurora_BGD_Member& member : deployment.target.members) {
		auto [rc, log] = context.simulator.wait_for_replica_probe_log(
			sequence, member.endpoint.backend(), Aurora_Replica_Probe_Kind::bgd_membership,
			kProbeTimeoutMs, encrypted, deployment.target.replica_set_id);
		if (rc == EXIT_SUCCESS) {
			return true;
		}
	}
	return false;
}

} // namespace aurora_bgd_scenario

#endif // TAP_TESTS_AURORA_BGD_SCENARIO_TAP_H
