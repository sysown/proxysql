/**
 * @file test_aurora_bgd_active-t.cpp
 * @brief Aurora BGD active-state probe suspension and routing behavior.
 */

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "aurora_bgd_tap.h"
#include "command_line.h"
#include "utils.h"

using namespace std;

const uint32_t kWaitSeconds = 5;
const uint32_t kProbeTimeoutMs = 5000;
const char kOrdinaryAuroraQuery[] =
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
	char simulator_username[] = "aurora1";
	char simulator_password[] = "pass1";
	if (sim.connect(cl.host, 3306, simulator_username, simulator_password) != EXIT_SUCCESS) {
		diag("Error: failed to connect to the shared AWS simulator");
		mysql_close(admin);
		admin = nullptr;
		return EXIT_FAILURE;
	}
	if (aurora_bgd_admin_cleanup(admin) != EXIT_SUCCESS || sim.cleanup() != EXIT_SUCCESS) {
		diag("Error: failed to clear prior Aurora BGD state");
		return EXIT_FAILURE;
	}
	if (aurora_bgd_execute_all(admin, {
		"DELETE FROM mysql_users WHERE username='testuser'",
		"INSERT INTO mysql_users(username,password,active,default_hostgroup,transaction_persistent) "
			"VALUES ('testuser','testuser',1,0,1)",
		"LOAD MYSQL USERS TO RUNTIME",
	}) != EXIT_SUCCESS) {
		diag("Error: failed to configure the routing test user");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int cleanup(MYSQL* admin, BGD_Simulator& sim) {
	int admin_rc = aurora_bgd_admin_cleanup(admin);
	int user_rc = admin == nullptr ? EXIT_FAILURE : aurora_bgd_execute_all(admin, {
		"DELETE FROM mysql_users WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	});
	int simulator_rc = sim.cleanup();
	if (admin) {
		mysql_close(admin);
	}
	return admin_rc == EXIT_SUCCESS && user_rc == EXIT_SUCCESS && simulator_rc == EXIT_SUCCESS
		? EXIT_SUCCESS : EXIT_FAILURE;
}

bool runtime_server_count(
	MYSQL* admin, int hostgroup, const string& hostname, int expected,
	const string& status = ""
) {
	string query =
		"SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		to_string(hostgroup) + " AND hostname=" + aurora_bgd_sql_quote(hostname);
	if (!status.empty()) {
		query += " AND status=" + aurora_bgd_sql_quote(status);
	}
	auto [rc, rows] = mysql_query_ext_rows(admin, query);
	return rc == EXIT_SUCCESS && rows.size() == 1 && rows.front().size() == 1
		&& rows.front().front() == to_string(expected);
}

int wait_for_writer_placement(
	MYSQL* admin, int writer_hg, int reader_hg, const string& hostname,
	bool demoted
) {
	string query =
		"SELECT ((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		to_string(writer_hg) + " AND hostname=" + aurora_bgd_sql_quote(hostname) +
		")=" + (demoted ? "0" : "1") + ") AND "
		"((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		to_string(reader_hg) + " AND hostname=" + aurora_bgd_sql_quote(hostname) +
		")=" + (demoted ? "1" : "0") + ")";
	return wait_for_cond(admin, query, kWaitSeconds);
}

int publish_status(
	BGD_Simulator& sim, Aurora_BGD_Test_Deployment& deployment,
	const string& status
) {
	return sim.topology_update(
		aurora_bgd_topology_backends(deployment),
		aurora_bgd_topology(deployment, status));
}

bool fast_membership_without_ordinary(
	BGD_Simulator& sim, uint64_t sequence, const string& target_replica_set,
	uint32_t observation_ms, uint64_t minimum_membership_probes
) {
	usleep(observation_ms * 1000);
	auto [rc, logs] = sim.replica_probe_log_since(sequence);
	if (rc != EXIT_SUCCESS) {
		return false;
	}
	uint64_t membership_probes = 0;
	for (const Aurora_Replica_Probe_Log& log : logs) {
		if (log.probe_kind == Aurora_Replica_Probe_Kind::ordinary) {
			return false;
		}
		if (log.probe_kind == Aurora_Replica_Probe_Kind::bgd_membership
			&& log.replica_set_id == target_replica_set) {
			membership_probes++;
		}
	}
	return membership_probes >= minimum_membership_probes;
}

int add_member_routes(
	MYSQL* admin, Aurora_BGD_Test_Deployment& deployment,
	const vector<int>& route_hgs
) {
	vector<string> queries;
	for (size_t i = 0; i < deployment.production.members.size(); ++i) {
		queries.push_back(
			"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,comment) VALUES (" +
			to_string(route_hgs[i]) + "," +
			aurora_bgd_sql_quote(deployment.production.members[i].endpoint.hostname) +
			",3306,'ONLINE','Aurora BGD member route')");
	}
	queries.push_back("LOAD MYSQL SERVERS TO RUNTIME");
	return aurora_bgd_execute_all(admin, queries);
}

int set_default_hostgroup(MYSQL* admin, int hostgroup) {
	return aurora_bgd_execute_all(admin, {
		"UPDATE mysql_users SET default_hostgroup=" + to_string(hostgroup) +
			" WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	});
}

bool route_to_expected_backend(
	CommandLine& cl, BGD_Simulator& sim, const Endpoint& expected_backend
) {
	auto [sequence_rc, sequence] = sim.replica_probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS) {
		return false;
	}
	MYSQL* client = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (client == nullptr) {
		return false;
	}
	auto [rc, rows] = mysql_query_ext_rows(client, kOrdinaryAuroraQuery);
	(void)rows;
	if (rc != EXIT_SUCCESS) {
		diag("Backend routing query failed with MySQL error %d: %s", rc, mysql_error(client));
	}
	mysql_close(client);
	if (rc != EXIT_SUCCESS) {
		return false;
	}

	auto [logs_rc, logs] = sim.replica_probe_log_since(sequence);
	if (logs_rc != EXIT_SUCCESS) {
		return false;
	}
	const Aurora_Replica_Probe_Log* routed_probe = nullptr;
	for (const Aurora_Replica_Probe_Log& log : logs) {
		if (log.probe_kind == Aurora_Replica_Probe_Kind::ordinary) {
			routed_probe = &log;
		}
	}
	if (routed_probe == nullptr
		|| routed_probe->backend.host != expected_backend.host
		|| routed_probe->backend.port != expected_backend.port) {
		diag(
			"Ordinary Aurora query reached %s:%d; expected %s:%d",
			routed_probe ? routed_probe->backend.host.c_str() : "<none>",
			routed_probe ? routed_probe->backend.port : 0,
			expected_backend.host.c_str(), expected_backend.port);
		return false;
	}
	return true;
}

bool route_members_to_expected_ips(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim,
	Aurora_BGD_Test_Deployment& deployment,
	const vector<int>& route_hgs, bool target
) {
	for (size_t i = 0; i < route_hgs.size(); ++i) {
		if (set_default_hostgroup(admin, route_hgs[i]) != EXIT_SUCCESS) {
			return false;
		}
		Endpoint expected_backend = target
			? deployment.target.members[i].endpoint.backend()
			: deployment.production.members[i].endpoint.backend();
		if (!route_to_expected_backend(cl, sim, expected_backend)) {
			return false;
		}
	}
	return true;
}

int64_t member_route_pool_count(MYSQL* admin, const vector<int>& route_hgs) {
	string hostgroups;
	for (int hostgroup : route_hgs) {
		if (!hostgroups.empty()) {
			hostgroups += ",";
		}
		hostgroups += to_string(hostgroup);
	}
	auto [rc, rows] = mysql_query_ext_rows(
		admin,
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_mysql_connection_pool "
		"WHERE hostgroup IN (" + hostgroups + ")");
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows.front().size() != 1) {
		return -1;
	}
	return strtoll(rows.front().front().c_str(), nullptr, 10);
}

int wait_for_member_route_pool_count(
	MYSQL* admin, const vector<int>& route_hgs, const string& comparison
) {
	string hostgroups;
	for (int hostgroup : route_hgs) {
		if (!hostgroups.empty()) {
			hostgroups += ",";
		}
		hostgroups += to_string(hostgroup);
	}
	return wait_for_cond(
		admin,
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0)" + comparison +
		" FROM stats_mysql_connection_pool WHERE hostgroup IN (" + hostgroups + ")",
		kWaitSeconds);
}

int main() {
	plan(20);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};
	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	const int writer_hg = 1530;
	const int reader_hg = 1531;
	const vector<int> route_hgs {1534, 1535, 1536};
	Aurora_BGD_Test_Deployment deployment = aurora_bgd_deployment_a();
	if (aurora_bgd_publish(sim, deployment) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, writer_hg, reader_hg, 1532, 1533, false, 1000, false)
			!= EXIT_SUCCESS
		|| add_member_routes(admin, deployment, route_hgs) != EXIT_SUCCESS) {
		diag("Error: failed to configure the active switchover scenario");
		cleanup(admin, sim);
		return exit_status();
	}

	ok(aurora_bgd_wait_for_status(admin, writer_hg, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"active scenario starts from a complete AVAILABLE snapshot");

	if (publish_status(sim, deployment, "SWITCHOVER_INITIATED") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, writer_hg, "SWITCHOVER_INITIATED", kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: worker did not enter SWITCHOVER_INITIATED");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(true, "INITIATED is published");
	ok(wait_for_writer_placement(
		admin, writer_hg, reader_hg,
		deployment.production.members.front().endpoint.hostname, false) == EXIT_SUCCESS,
		"INITIATED does not change writer placement");

	auto [active_seq_rc, active_sequence] = sim.replica_probe_log_last_sequence();
	ok(active_seq_rc == EXIT_SUCCESS && fast_membership_without_ordinary(
		sim, active_sequence, deployment.target_replica_set, 650, 3),
		"INITIATED uses fast membership probes and suspends the ordinary Aurora query");

	vector<Aurora_Replica_Row> competing_source = deployment.production.replica_rows();
	competing_source[0].session_id = "source-observed-reader";
	competing_source[1].session_id = "MASTER_SESSION_ID";
	auto [source_change_rc, source_change_sequence] = sim.replica_probe_log_last_sequence();
	if (source_change_rc != EXIT_SUCCESS || sim.replica_update(
		deployment.blue_replica_set, competing_source, deployment.production.backends())
		!= EXIT_SUCCESS) {
		diag("Error: failed to publish the competing source role observation");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(fast_membership_without_ordinary(
		sim, source_change_sequence, deployment.target_replica_set, 350, 2),
		"changed source roles cannot compete while production probing is suspended");

	if (publish_status(sim, deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, writer_hg, "SWITCHOVER_IN_PROGRESS", kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: worker did not enter SWITCHOVER_IN_PROGRESS");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(true, "IN_PROGRESS is published");
	ok(wait_for_writer_placement(
		admin, writer_hg, reader_hg,
		deployment.production.members.front().endpoint.hostname, true) == EXIT_SUCCESS,
		"IN_PROGRESS demotes the snapshotted production writer");
	ok(runtime_server_count(
		admin, writer_hg, deployment.production.members[1].endpoint.hostname, 0)
		&& runtime_server_count(
			admin, reader_hg, deployment.production.members[1].endpoint.hostname, 1, "ONLINE"),
		"the competing source observation does not promote a reader");

	auto [repeat_progress_rc, repeat_progress_sequence] = sim.replica_probe_log_last_sequence();
	if (repeat_progress_rc != EXIT_SUCCESS
		|| publish_status(sim, deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS) {
		diag("Error: failed to repeat SWITCHOVER_IN_PROGRESS");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(fast_membership_without_ordinary(
		sim, repeat_progress_sequence, deployment.target_replica_set, 350, 2)
		&& wait_for_writer_placement(
			admin, writer_hg, reader_hg,
			deployment.production.members.front().endpoint.hostname, true) == EXIT_SUCCESS,
		"repeated IN_PROGRESS retains the one demotion and active probe policy");

	ok(route_members_to_expected_ips(cl, admin, sim, deployment, route_hgs, false)
		&& member_route_pool_count(admin, route_hgs)
			>= static_cast<int64_t>(route_hgs.size()),
		"all member routes use source IPs and hold pre-cutover pools");

	if (publish_status(sim, deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, writer_hg, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: worker did not enter SWITCHOVER_IN_POST_PROCESSING");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(true, "POST_PROCESSING is published without a target-writability gate");
	ok(wait_for_writer_placement(
		admin, writer_hg, reader_hg,
		deployment.production.members.front().endpoint.hostname, false) == EXIT_SUCCESS,
		"POST_PROCESSING restores the canonical writer placement");
	ok(runtime_server_count(
		admin, reader_hg, deployment.production.members[1].endpoint.hostname, 1, "ONLINE")
		&& runtime_server_count(
			admin, reader_hg, deployment.production.members[2].endpoint.hostname, 1, "ONLINE"),
		"POST_PROCESSING leaves canonical readers ONLINE and eligible");
	ok(wait_for_member_route_pool_count(admin, route_hgs, "=0") == EXIT_SUCCESS,
		"POST_PROCESSING retires the pre-cutover member pools");
	ok(route_members_to_expected_ips(cl, admin, sim, deployment, route_hgs, true),
		"POST_PROCESSING pins every production hostname to its cached target IP");

	const int64_t target_pool_count = member_route_pool_count(admin, route_hgs);
	auto [repeat_post_rc, repeat_post_sequence] = sim.probe_log_last_sequence();
	if (target_pool_count < static_cast<int64_t>(route_hgs.size())
		|| repeat_post_rc != EXIT_SUCCESS
		|| publish_status(sim, deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS) {
		diag("Error: failed to prepare repeated POST_PROCESSING");
		cleanup(admin, sim);
		return exit_status();
	}
	vector<Endpoint> target_backends = deployment.target.backends();
	auto [repeat_probe_rc, repeat_probe] = aurora_bgd_wait_for_topology_probe(
		sim, repeat_post_sequence, target_backends, BGD_Probe_Kind::metadata,
		kProbeTimeoutMs);
	ok(repeat_probe_rc == EXIT_SUCCESS
		&& member_route_pool_count(admin, route_hgs) >= target_pool_count,
		"repeated POST_PROCESSING does not replay completed member retirement");

	auto [post_seq_rc, post_sequence] = sim.replica_probe_log_last_sequence();
	ok(post_seq_rc == EXIT_SUCCESS && fast_membership_without_ordinary(
		sim, post_sequence, deployment.target_replica_set, 350, 2),
		"POST_PROCESSING keeps fast BGD probes without ordinary Aurora queries");

	if (aurora_bgd_admin_cleanup(admin) != EXIT_SUCCESS || sim.cleanup() != EXIT_SUCCESS) {
		diag("Error: failed to reset before the incomplete-snapshot scenario");
		cleanup(admin, sim);
		return exit_status();
	}

	const int gated_writer_hg = 1540;
	const int gated_reader_hg = 1541;
	const int gated_route_hg = 1544;
	Aurora_BGD_Test_Deployment gated = aurora_bgd_deployment_b_writer_only();
	vector<Aurora_Replica_Row> invalid_target = gated.target.replica_rows();
	invalid_target.front().server_id = "unpaired-target-writer";
	if (sim.replica_update(
		gated.blue_replica_set, gated.production.replica_rows(), gated.production.backends())
		!= EXIT_SUCCESS
		|| sim.replica_update(
			gated.target_replica_set, invalid_target, gated.target.backends())
			!= EXIT_SUCCESS
		|| sim.topology_update(
			aurora_bgd_topology_backends(gated), aurora_bgd_available_topology(gated))
			!= EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, gated, gated_writer_hg, gated_reader_hg, 1542, 1543, false, 1000, false)
			!= EXIT_SUCCESS
		|| add_member_routes(admin, gated, {gated_route_hg}) != EXIT_SUCCESS) {
		diag("Error: failed to configure incomplete target membership");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(aurora_bgd_wait_for_status(
		admin, gated_writer_hg, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"an incomplete target snapshot can publish AVAILABLE without routing");
	if (publish_status(sim, gated, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, gated_writer_hg, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds)
			!= EXIT_SUCCESS) {
		diag("Error: incomplete scenario did not publish POST_PROCESSING");
		cleanup(admin, sim);
		return exit_status();
	}
	const int gated_default_rc = set_default_hostgroup(admin, gated_route_hg);
	ok(gated_default_rc == EXIT_SUCCESS && route_to_expected_backend(
		cl, sim, gated.production.members.front().endpoint.backend()),
		"POST_PROCESSING leaves routing unchanged without a complete target snapshot");

	auto [gated_refresh_seq_rc, gated_refresh_sequence] = sim.replica_probe_log_last_sequence();
	if (gated_refresh_seq_rc != EXIT_SUCCESS || sim.replica_update(
		gated.target_replica_set, gated.target.replica_rows(), gated.target.backends())
		!= EXIT_SUCCESS) {
		diag("Error: failed to restore complete target membership");
		cleanup(admin, sim);
		return exit_status();
	}
	auto [gated_probe_rc, gated_probe] = aurora_bgd_wait_for_replica_probe(
		sim, gated_refresh_sequence, gated.target.backends(),
		Aurora_Replica_Probe_Kind::bgd_membership,
		kProbeTimeoutMs, gated.target_replica_set);
	bool gated_target_routing = false;
	if (gated_probe_rc == EXIT_SUCCESS
		&& wait_for_member_route_pool_count(admin, {gated_route_hg}, "=0") == EXIT_SUCCESS
		&& set_default_hostgroup(admin, gated_route_hg) == EXIT_SUCCESS) {
		gated_target_routing = route_to_expected_backend(
			cl, sim, gated.target.members.front().endpoint.backend());
	}
	ok(gated_target_routing,
		"repeated POST_PROCESSING applies routing after membership becomes complete");

	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean Aurora BGD active-state test data");
		return EXIT_FAILURE;
	}
	return exit_status();
}
