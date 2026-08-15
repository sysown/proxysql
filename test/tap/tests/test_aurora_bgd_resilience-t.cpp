/**
 * @file test_aurora_bgd_resilience-t.cpp
 * @brief Aurora BGD rollback, error retention, and active-state late entry.
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
		return EXIT_FAILURE;
	}
	admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (admin == nullptr) {
		return EXIT_FAILURE;
	}
	char username[] = "aurora1";
	char password[] = "pass1";
	if (sim.connect(cl.host, 3306, username, password) != EXIT_SUCCESS
		|| aurora_bgd_admin_cleanup(admin) != EXIT_SUCCESS
		|| sim.cleanup() != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return aurora_bgd_execute_all(admin, {
		"DELETE FROM mysql_users WHERE username='testuser'",
		"INSERT INTO mysql_users(username,password,active,default_hostgroup,transaction_persistent) "
			"VALUES ('testuser','testuser',1,0,1)",
		"LOAD MYSQL USERS TO RUNTIME",
	});
}

int reset_scenario(MYSQL* admin, BGD_Simulator& sim) {
	return aurora_bgd_admin_cleanup(admin) == EXIT_SUCCESS
		&& sim.cleanup() == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

int cleanup(MYSQL* admin, BGD_Simulator& sim) {
	int reset_rc = reset_scenario(admin, sim);
	int user_rc = aurora_bgd_execute_all(admin, {
		"DELETE FROM mysql_users WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	});
	mysql_close(admin);
	return reset_rc == EXIT_SUCCESS && user_rc == EXIT_SUCCESS
		? EXIT_SUCCESS : EXIT_FAILURE;
}

int publish_initial(
	BGD_Simulator& sim, Aurora_BGD_Test_Deployment& deployment, const string& status
) {
	return sim.replica_update(
			deployment.production.replica_set_id,
			deployment.production.replica_rows(), deployment.production.backends()) == EXIT_SUCCESS
		&& sim.replica_update(
			deployment.target.replica_set_id,
			deployment.target.replica_rows(), deployment.target.backends()) == EXIT_SUCCESS
		&& sim.topology_update(
			aurora_bgd_topology_backends(deployment),
			aurora_bgd_topology(deployment, status)) == EXIT_SUCCESS
		? EXIT_SUCCESS : EXIT_FAILURE;
}

int publish_status(
	BGD_Simulator& sim, Aurora_BGD_Test_Deployment& deployment, const string& status
) {
	return sim.topology_update(
		aurora_bgd_topology_backends(deployment),
		aurora_bgd_topology(deployment, status));
}

int set_default_hostgroup(MYSQL* admin, int hostgroup) {
	return aurora_bgd_execute_all(admin, {
		"UPDATE mysql_users SET default_hostgroup=" + to_string(hostgroup) +
			" WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	});
}

bool writer_placement(
	MYSQL* admin, int writer_hg, int reader_hg, const string& hostname, bool demoted
) {
	string query =
		"SELECT ((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		to_string(writer_hg) + " AND hostname=" + aurora_bgd_sql_quote(hostname) +
		")=" + (demoted ? "0" : "1") + ") AND "
		"((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		to_string(reader_hg) + " AND hostname=" + aurora_bgd_sql_quote(hostname) +
		")=" + (demoted ? "1" : "0") + ")";
	return wait_for_cond(admin, query, kWaitSeconds) == EXIT_SUCCESS;
}

bool active_probe_policy(
	BGD_Simulator& sim, uint64_t sequence, const string& target_replica_set,
	uint32_t observation_ms
) {
	usleep(observation_ms * 1000);
	auto [rc, logs] = sim.replica_probe_log_since(sequence);
	if (rc != EXIT_SUCCESS) {
		return false;
	}
	bool membership = false;
	for (const Aurora_Replica_Probe_Log& log : logs) {
		if (log.probe_kind == Aurora_Replica_Probe_Kind::ordinary) {
			return false;
		}
		membership |= log.probe_kind == Aurora_Replica_Probe_Kind::bgd_membership
			&& log.replica_set_id == target_replica_set;
	}
	return membership;
}

bool wait_for_ordinary_probe(
	BGD_Simulator& sim, uint64_t sequence, Aurora_BGD_Test_Deployment& deployment
) {
	auto [rc, log] = aurora_bgd_wait_for_replica_probe(
		sim, sequence, deployment.production.backends(),
		Aurora_Replica_Probe_Kind::ordinary, kProbeTimeoutMs);
	return rc == EXIT_SUCCESS;
}

int add_routes(
	MYSQL* admin, Aurora_BGD_Test_Deployment& deployment,
	const vector<int>& route_hgs, int green_writer_hg
) {
	vector<string> queries;
	for (size_t i = 0; i < route_hgs.size(); ++i) {
		queries.push_back(
			"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,comment) VALUES (" +
			to_string(route_hgs[i]) + "," +
			aurora_bgd_sql_quote(deployment.production.members[i].endpoint.hostname) +
			",3306,'ONLINE','Aurora BGD rollback route')");
	}
	queries.push_back(
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,comment) VALUES (" +
		to_string(green_writer_hg) + "," +
		aurora_bgd_sql_quote(deployment.target.members.front().endpoint.hostname) +
		",3306,'ONLINE','Aurora BGD rollback green pool')");
	queries.push_back("LOAD MYSQL SERVERS TO RUNTIME");
	return aurora_bgd_execute_all(admin, queries);
}

bool route_to_backend(CommandLine& cl, BGD_Simulator& sim, const Endpoint& expected) {
	auto [sequence_rc, sequence] = sim.replica_probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS) {
		return false;
	}
	MYSQL* client = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (client == nullptr) {
		return false;
	}
	auto [query_rc, rows] = mysql_query_ext_rows(client, kOrdinaryAuroraQuery);
	(void)rows;
	mysql_close(client);
	if (query_rc != EXIT_SUCCESS) {
		return false;
	}
	auto [logs_rc, logs] = sim.replica_probe_log_since(sequence);
	if (logs_rc != EXIT_SUCCESS) {
		return false;
	}
	for (const Aurora_Replica_Probe_Log& log : logs) {
		if (log.probe_kind == Aurora_Replica_Probe_Kind::ordinary
			&& log.backend.host == expected.host && log.backend.port == expected.port) {
			return true;
		}
	}
	return false;
}

bool route_members(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim,
	Aurora_BGD_Test_Deployment& deployment, const vector<int>& route_hgs, bool target
) {
	for (size_t i = 0; i < route_hgs.size(); ++i) {
		if (set_default_hostgroup(admin, route_hgs[i]) != EXIT_SUCCESS) {
			return false;
		}
		Endpoint expected = target
			? deployment.target.members[i].endpoint.backend()
			: deployment.production.members[i].endpoint.backend();
		if (!route_to_backend(cl, sim, expected)) {
			return false;
		}
	}
	return true;
}

int64_t pool_count(MYSQL* admin, int hostgroup) {
	auto [rc, rows] = mysql_query_ext_rows(
		admin, "SELECT COALESCE(SUM(ConnUsed+ConnFree),0) "
		"FROM stats_mysql_connection_pool WHERE hostgroup=" + to_string(hostgroup));
	return rc == EXIT_SUCCESS && rows.size() == 1 && rows.front().size() == 1
		? strtoll(rows.front().front().c_str(), nullptr, 10) : -1;
}

int main() {
	plan(20);
	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};
	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	Aurora_BGD_Test_Deployment initiated = aurora_bgd_deployment_b_writer_only();
	const int initiated_writer_hg = 1590;
	const int initiated_reader_hg = 1591;
	if (publish_initial(sim, initiated, "SWITCHOVER_INITIATED") != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, initiated, initiated_writer_hg, initiated_reader_hg,
			1592, 1593, false, 300, false) != EXIT_SUCCESS) {
		diag("Error: failed to configure INITIATED late entry");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(aurora_bgd_wait_for_status(
		admin, initiated_writer_hg, "SWITCHOVER_INITIATED", kWaitSeconds) == EXIT_SUCCESS,
		"late entry at INITIATED publishes the observed state");
	ok(writer_placement(
		admin, initiated_writer_hg, initiated_reader_hg,
		initiated.production.members.front().endpoint.hostname, false),
		"late INITIATED entry leaves writer placement unchanged");
	auto [initiated_seq_rc, initiated_sequence] = sim.replica_probe_log_last_sequence();
	ok(initiated_seq_rc == EXIT_SUCCESS && active_probe_policy(
		sim, initiated_sequence, initiated.target_replica_set, 450),
		"late INITIATED entry reconstructs fast membership probing");
	auto [topology_error_seq_rc, topology_error_sequence] = sim.probe_log_last_sequence();
	auto topology_error_seen = topology_error_seq_rc == EXIT_SUCCESS
		&& sim.topology_error(
			aurora_bgd_topology_backends(initiated), 1205, "simulated topology timeout")
			== EXIT_SUCCESS
		&& aurora_bgd_wait_for_topology_probe(
			sim, topology_error_sequence, initiated.target.backends(),
			BGD_Probe_Kind::metadata, kProbeTimeoutMs).first == EXIT_SUCCESS;
	ok(topology_error_seen && aurora_bgd_wait_for_status(
		admin, initiated_writer_hg, "SWITCHOVER_INITIATED", 1) == EXIT_SUCCESS,
		"topology errors retain the active state");
	if (publish_status(sim, initiated, "SWITCHOVER_INITIATED") != EXIT_SUCCESS) {
		diag("Error: failed to restore topology after error");
		cleanup(admin, sim);
		return exit_status();
	}
	auto [membership_error_seq_rc, membership_error_sequence] =
		sim.replica_probe_log_last_sequence();
	auto membership_error_seen = membership_error_seq_rc == EXIT_SUCCESS
		&& sim.replica_error(
			initiated.target.backends(), 1205, "simulated membership timeout") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_replica_probe(
			sim, membership_error_sequence, initiated.target.backends(),
			Aurora_Replica_Probe_Kind::bgd_membership, kProbeTimeoutMs).first == EXIT_SUCCESS;
	ok(membership_error_seen && aurora_bgd_wait_for_status(
		admin, initiated_writer_hg, "SWITCHOVER_INITIATED", 1) == EXIT_SUCCESS,
		"membership errors retain the last complete state");
	if (sim.replica_update(
		initiated.target.replica_set_id, initiated.target.replica_rows(),
		initiated.target.backends()) != EXIT_SUCCESS
		|| publish_status(sim, initiated, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, initiated_writer_hg, "SWITCHOVER_IN_PROGRESS", kWaitSeconds)
			!= EXIT_SUCCESS) {
		diag("Error: failed to advance to IN_PROGRESS");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(writer_placement(
		admin, initiated_writer_hg, initiated_reader_hg,
		initiated.production.members.front().endpoint.hostname, true),
		"IN_PROGRESS demotes the reconstructed production writer");
	ok(publish_status(sim, initiated, "SWITCHOVER_INITIATED") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, initiated_writer_hg, "SWITCHOVER_INITIATED", kWaitSeconds)
			== EXIT_SUCCESS
		&& writer_placement(
			admin, initiated_writer_hg, initiated_reader_hg,
			initiated.production.members.front().endpoint.hostname, false),
		"a backward status rolls back writer placement before entering the earlier state");
	auto [ordinary_seq_rc, ordinary_sequence] = sim.replica_probe_log_last_sequence();
	ok(sim.topology_delete(aurora_bgd_topology_backends(initiated)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, initiated_writer_hg, "NONE", kWaitSeconds) == EXIT_SUCCESS,
		"a successful empty topology cancels the active deployment");
	ok(ordinary_seq_rc == EXIT_SUCCESS
		&& wait_for_ordinary_probe(sim, ordinary_sequence, initiated),
		"cancellation resumes ordinary production probing");
	ok(publish_status(sim, initiated, "AVAILABLE") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, initiated_writer_hg, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"the worker admits a repeated deployment after cancellation");

	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before IN_PROGRESS late entry");
		cleanup(admin, sim);
		return exit_status();
	}
	Aurora_BGD_Test_Deployment progress = aurora_bgd_deployment_b_writer_only();
	if (publish_initial(sim, progress, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(admin, progress, 1600, 1601, 1602, 1603, false, 300, false)
			!= EXIT_SUCCESS) {
		diag("Error: failed to configure IN_PROGRESS late entry");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(aurora_bgd_wait_for_status(admin, 1600, "SWITCHOVER_IN_PROGRESS", kWaitSeconds)
		== EXIT_SUCCESS
		&& writer_placement(
			admin, 1600, 1601, progress.production.members.front().endpoint.hostname, true),
		"late entry at IN_PROGRESS reconstructs and demotes the writer");
	ok(sim.topology_drop(aurora_bgd_topology_backends(progress)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(admin, 1600, "NONE", kWaitSeconds) == EXIT_SUCCESS
		&& writer_placement(
			admin, 1600, 1601, progress.production.members.front().endpoint.hostname, false),
		"confirmed topology absence rolls back IN_PROGRESS to NONE");

	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before POST_PROCESSING late entry");
		cleanup(admin, sim);
		return exit_status();
	}
	Aurora_BGD_Test_Deployment post = aurora_bgd_deployment_a();
	const vector<int> route_hgs {1614, 1615, 1616};
	if (publish_initial(sim, post, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(admin, post, 1610, 1611, 1612, 1613, false, 300, false)
			!= EXIT_SUCCESS
		|| add_routes(admin, post, route_hgs, 1612) != EXIT_SUCCESS) {
		diag("Error: failed to configure POST_PROCESSING late entry");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(aurora_bgd_wait_for_status(
		admin, 1610, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"late entry at POST_PROCESSING reconstructs the active phase");
	ok(route_members(cl, admin, sim, post, route_hgs, true),
		"late POST_PROCESSING entry reconstructs and applies every target pin");
	ok(set_default_hostgroup(admin, 1612) == EXIT_SUCCESS
		&& route_to_backend(cl, sim, post.target.members.front().endpoint.backend())
		&& pool_count(admin, 1612) >= 1,
		"a configured green pool is established before rollback");
	auto [post_error_seq_rc, post_error_sequence] = sim.probe_log_last_sequence();
	bool post_error_seen = post_error_seq_rc == EXIT_SUCCESS
		&& sim.topology_error(
			aurora_bgd_topology_backends(post), 1205, "simulated post timeout") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_topology_probe(
			sim, post_error_sequence, post.target.backends(),
			BGD_Probe_Kind::metadata, kProbeTimeoutMs).first == EXIT_SUCCESS;
	ok(post_error_seen && aurora_bgd_wait_for_status(
		admin, 1610, "SWITCHOVER_IN_POST_PROCESSING", 1) == EXIT_SUCCESS
		&& route_members(cl, admin, sim, post, route_hgs, true),
		"topology errors do not roll back applied POST_PROCESSING pins");
	if (publish_status(sim, post, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS) {
		diag("Error: failed to restore POST_PROCESSING topology");
		cleanup(admin, sim);
		return exit_status();
	}
	auto [post_membership_seq_rc, post_membership_sequence] =
		sim.replica_probe_log_last_sequence();
	bool post_membership_error = post_membership_seq_rc == EXIT_SUCCESS
		&& sim.replica_error(post.target.backends(), 1205, "simulated post membership timeout")
			== EXIT_SUCCESS
		&& aurora_bgd_wait_for_replica_probe(
			sim, post_membership_sequence, post.target.backends(),
			Aurora_Replica_Probe_Kind::bgd_membership, kProbeTimeoutMs).first == EXIT_SUCCESS;
	ok(post_membership_error
		&& sim.replica_update(
			post.target.replica_set_id, post.target.replica_rows(), post.target.backends())
			== EXIT_SUCCESS
		&& route_members(cl, admin, sim, post, route_hgs, true),
		"membership errors retain the last complete mapped routing");
	ok(publish_status(sim, post, "AVAILABLE") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(admin, 1610, "AVAILABLE", kWaitSeconds)
			== EXIT_SUCCESS,
		"a backward POST_PROCESSING status completes rollback before AVAILABLE");
	ok(writer_placement(
		admin, 1610, 1611, post.production.members.front().endpoint.hostname, false)
		&& route_members(cl, admin, sim, post, route_hgs, false),
		"rollback removes pins and restores canonical writer and member routing");
	ok(pool_count(admin, 1612) >= 1,
		"rollback preserves configured green pools instead of draining them");

	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean Aurora BGD resilience test data");
		return EXIT_FAILURE;
	}
	return exit_status();
}
