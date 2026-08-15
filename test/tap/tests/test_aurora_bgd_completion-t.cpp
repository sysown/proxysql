/**
 * @file test_aurora_bgd_completion-t.cpp
 * @brief Aurora BGD completion cleanup and terminal-latch behavior.
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

int publish_status(
	BGD_Simulator& sim, Aurora_BGD_Test_Deployment& deployment, const string& status
) {
	return sim.topology_update(
		aurora_bgd_topology_backends(deployment),
		aurora_bgd_topology(deployment, status));
}

int publish_completed(
	BGD_Simulator& sim, Aurora_BGD_Test_Deployment& serving_deployment,
	Aurora_BGD_Test_Deployment& completed_deployment
) {
	return sim.topology_update(
		aurora_bgd_topology_backends(serving_deployment),
		aurora_bgd_completed_topology(completed_deployment));
}

int set_default_hostgroup(MYSQL* admin, int hostgroup) {
	return aurora_bgd_execute_all(admin, {
		"UPDATE mysql_users SET default_hostgroup=" + to_string(hostgroup) +
			" WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	});
}

int add_route(
	MYSQL* admin, int hostgroup, const string& hostname, const string& status = "ONLINE"
) {
	return aurora_bgd_execute_all(admin, {
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,comment) VALUES (" +
			to_string(hostgroup) + "," + aurora_bgd_sql_quote(hostname) +
			",3306," + aurora_bgd_sql_quote(status) + ",'Aurora BGD completion route')",
		"LOAD MYSQL SERVERS TO RUNTIME",
	});
}

int add_member_routes(
	MYSQL* admin, Aurora_BGD_Test_Deployment& deployment, const vector<int>& hostgroups
) {
	vector<string> queries;
	for (size_t i = 0; i < hostgroups.size(); ++i) {
		queries.push_back(
			"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,comment) VALUES (" +
			to_string(hostgroups[i]) + "," +
			aurora_bgd_sql_quote(deployment.production.members[i].endpoint.hostname) +
			",3306,'ONLINE','Aurora BGD completion member route')");
	}
	queries.push_back("LOAD MYSQL SERVERS TO RUNTIME");
	return aurora_bgd_execute_all(admin, queries);
}

int add_green_servers(
	MYSQL* admin, Aurora_BGD_Test_Deployment& deployment,
	int green_writer_hg, int green_reader_hg
) {
	vector<string> queries;
	for (size_t i = 0; i < deployment.target.members.size(); ++i) {
		const int hostgroup = i == 0 ? green_writer_hg : green_reader_hg;
		const string status = i + 1 == deployment.target.members.size()
			? "OFFLINE_SOFT" : "ONLINE";
		queries.push_back(
			"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,comment) VALUES (" +
			to_string(hostgroup) + "," +
			aurora_bgd_sql_quote(deployment.target.members[i].endpoint.hostname) +
			",3306," + aurora_bgd_sql_quote(status) +
			",'Aurora BGD configured green member')");
	}
	queries.push_back("LOAD MYSQL SERVERS TO RUNTIME");
	return aurora_bgd_execute_all(admin, queries);
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
	auto [query_rc, rows] = mysql_query_ext_rows(client, kOrdinaryAuroraQuery);
	(void)rows;
	if (query_rc != EXIT_SUCCESS) {
		diag("Backend routing query failed with MySQL error %d: %s",
			mysql_errno(client), mysql_error(client));
	}
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
			&& log.backend.host == expected_backend.host
			&& log.backend.port == expected_backend.port) {
			return true;
		}
	}
	return false;
}

bool route_members(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim,
	Aurora_BGD_Test_Deployment& deployment, const vector<int>& hostgroups, bool target
) {
	for (size_t i = 0; i < hostgroups.size(); ++i) {
		if (set_default_hostgroup(admin, hostgroups[i]) != EXIT_SUCCESS) {
			return false;
		}
		const Endpoint expected = target
			? deployment.target.members[i].endpoint.backend()
			: deployment.production.members[i].endpoint.backend();
		if (!route_to_expected_backend(cl, sim, expected)) {
			return false;
		}
	}
	return true;
}

int64_t pool_count(MYSQL* admin, int hostgroup) {
	auto [rc, rows] = mysql_query_ext_rows(
		admin,
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_mysql_connection_pool "
		"WHERE hostgroup=" + to_string(hostgroup));
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows.front().size() != 1) {
		return -1;
	}
	return strtoll(rows.front().front().c_str(), nullptr, 10);
}

int wait_for_pool_count(MYSQL* admin, int hostgroup, const string& comparison) {
	return wait_for_cond(
		admin,
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0)" + comparison +
		" FROM stats_mysql_connection_pool WHERE hostgroup=" + to_string(hostgroup),
		kWaitSeconds);
}

bool server_count(
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

int wait_for_writer_policy(
	MYSQL* admin, int writer_hg, int reader_hg, const string& hostname,
	bool writer_is_also_reader
) {
	return wait_for_cond(
		admin,
		"SELECT ((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		to_string(writer_hg) + " AND hostname=" + aurora_bgd_sql_quote(hostname) +
		")=1) AND ((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		to_string(reader_hg) + " AND hostname=" + aurora_bgd_sql_quote(hostname) +
		")=" + (writer_is_also_reader ? "1" : "0") + ")",
		kWaitSeconds);
}

int wait_for_writer_demotion(
	MYSQL* admin, int writer_hg, int reader_hg, const string& hostname
) {
	return wait_for_cond(
		admin,
		"SELECT ((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		to_string(writer_hg) + " AND hostname=" + aurora_bgd_sql_quote(hostname) +
		")=0) AND ((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		to_string(reader_hg) + " AND hostname=" + aurora_bgd_sql_quote(hostname) +
		")=1)",
		kWaitSeconds);
}

bool completion_probe_policy(
	BGD_Simulator& sim, uint64_t sequence,
	Aurora_BGD_Test_Deployment& deployment, uint32_t observation_ms
) {
	usleep(observation_ms * 1000);
	auto [rc, logs] = sim.replica_probe_log_since(sequence);
	if (rc != EXIT_SUCCESS) {
		return false;
	}
	bool ordinary_on_production = false;
	for (const Aurora_Replica_Probe_Log& log : logs) {
		if (log.probe_kind == Aurora_Replica_Probe_Kind::bgd_membership) {
			return false;
		}
		if (log.probe_kind != Aurora_Replica_Probe_Kind::ordinary) {
			continue;
		}
		for (const Endpoint& backend : deployment.production.backends()) {
			ordinary_on_production |= log.backend.host == backend.host
				&& log.backend.port == backend.port;
		}
	}
	return ordinary_on_production;
}

bool wait_for_topology_observation(
	BGD_Simulator& sim, uint64_t sequence, Aurora_BGD_Test_Deployment& deployment
) {
	auto [rc, probe] = aurora_bgd_wait_for_topology_probe(
		sim, sequence, deployment.production.backends(),
		BGD_Probe_Kind::metadata, kProbeTimeoutMs);
	return rc == EXIT_SUCCESS;
}

int main() {
	plan(28);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};
	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	// Completion from IN_PROGRESS reconciles the writer without replaying POST_PROCESSING.
	Aurora_BGD_Test_Deployment progress = aurora_bgd_deployment_b_writer_only();
	const int progress_writer_hg = 1550;
	const int progress_reader_hg = 1551;
	if (aurora_bgd_publish(sim, progress) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, progress, progress_writer_hg, progress_reader_hg,
			1552, 1553, false, 300, false) != EXIT_SUCCESS) {
		diag("Error: failed to configure completion-from-IN_PROGRESS scenario");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(aurora_bgd_wait_for_status(
		admin, progress_writer_hg, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"completion-from-IN_PROGRESS scenario reaches AVAILABLE");
	if (publish_status(sim, progress, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, progress_writer_hg, "SWITCHOVER_IN_PROGRESS", kWaitSeconds)
			!= EXIT_SUCCESS) {
		diag("Error: failed to reach IN_PROGRESS");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(wait_for_writer_demotion(
		admin, progress_writer_hg, progress_reader_hg,
		progress.production.members.front().endpoint.hostname) == EXIT_SUCCESS,
		"IN_PROGRESS demotes the writer before completion");
	if (publish_completed(sim, progress, progress) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, progress_writer_hg, "SWITCHOVER_COMPLETED", kWaitSeconds)
			!= EXIT_SUCCESS) {
		diag("Error: failed to enter the completed latch from IN_PROGRESS");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(true, "TARGET-only completion publishes SWITCHOVER_COMPLETED");
	ok(wait_for_writer_policy(
		admin, progress_writer_hg, progress_reader_hg,
		progress.production.members.front().endpoint.hostname, false) == EXIT_SUCCESS,
		"completion restores the demoted writer without replaying POST_PROCESSING");
	auto [progress_replica_seq_rc, progress_replica_sequence] =
		sim.replica_probe_log_last_sequence();
	ok(progress_replica_seq_rc == EXIT_SUCCESS && completion_probe_policy(
		sim, progress_replica_sequence, progress, 750),
		"completion resumes ordinary production probing and stops membership probing");
	auto [repeat_progress_seq_rc, repeat_progress_sequence] = sim.probe_log_last_sequence();
	bool repeated_progress = repeat_progress_seq_rc == EXIT_SUCCESS
		&& publish_completed(sim, progress, progress) == EXIT_SUCCESS
		&& wait_for_topology_observation(sim, repeat_progress_sequence, progress);
	ok(repeated_progress && wait_for_writer_policy(
		admin, progress_writer_hg, progress_reader_hg,
		progress.production.members.front().endpoint.hostname, false) == EXIT_SUCCESS,
		"repeated completion is a no-op while latched");
	auto [error_seq_rc, error_sequence] = sim.probe_log_last_sequence();
	bool error_retained = error_seq_rc == EXIT_SUCCESS
		&& sim.topology_error(
			aurora_bgd_topology_backends(progress), 1205, "simulated completion timeout")
			== EXIT_SUCCESS
		&& wait_for_topology_observation(sim, error_sequence, progress);
	ok(error_retained && aurora_bgd_wait_for_status(
		admin, progress_writer_hg, "SWITCHOVER_COMPLETED", 1) == EXIT_SUCCESS,
		"topology query errors retain the completed latch");
	ok(sim.topology_drop(aurora_bgd_topology_backends(progress)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, progress_writer_hg, "NONE", kWaitSeconds) == EXIT_SUCCESS,
		"confirmed topology absence releases the completed latch to NONE");

	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before POST_PROCESSING completion scenario");
		cleanup(admin, sim);
		return exit_status();
	}

	// Completion after POST_PROCESSING removes pins and drains configured green pools once.
	Aurora_BGD_Test_Deployment post = aurora_bgd_deployment_a();
	const int post_writer_hg = 1560;
	const int post_reader_hg = 1561;
	const int green_writer_hg = 1562;
	const int green_reader_hg = 1563;
	const vector<int> route_hgs {1564, 1565, 1566};
	if (aurora_bgd_publish(sim, post) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, post, post_writer_hg, post_reader_hg,
			green_writer_hg, green_reader_hg, false, 300, true) != EXIT_SUCCESS
		|| add_green_servers(admin, post, green_writer_hg, green_reader_hg) != EXIT_SUCCESS
		|| add_member_routes(admin, post, route_hgs) != EXIT_SUCCESS) {
		diag("Error: failed to configure POST_PROCESSING completion scenario");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(aurora_bgd_wait_for_status(
		admin, post_writer_hg, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"POST_PROCESSING completion scenario reaches AVAILABLE");
	if (publish_status(sim, post, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, post_writer_hg, "SWITCHOVER_IN_PROGRESS", kWaitSeconds)
			!= EXIT_SUCCESS
		|| publish_status(sim, post, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, post_writer_hg, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds)
			!= EXIT_SUCCESS) {
		diag("Error: failed to advance through POST_PROCESSING");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(true, "active deployment advances through POST_PROCESSING");
	ok(route_members(cl, admin, sim, post, route_hgs, true),
		"POST_PROCESSING routes every production member to its target IP");
	const int64_t target_route_pool = pool_count(admin, route_hgs.front());
	bool green_pool_ready = set_default_hostgroup(admin, green_writer_hg) == EXIT_SUCCESS
		&& route_to_expected_backend(cl, sim, post.target.members.front().endpoint.backend())
		&& pool_count(admin, green_writer_hg) >= 1;
	ok(target_route_pool >= 1 && green_pool_ready,
		"pre-completion target and configured-green pools are established");
	if (publish_completed(sim, post, post) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, post_writer_hg, "SWITCHOVER_COMPLETED", kWaitSeconds)
			!= EXIT_SUCCESS) {
		diag("Error: failed to complete the POST_PROCESSING scenario");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(true, "completion after POST_PROCESSING enters the terminal latch");
	ok(wait_for_writer_policy(
		admin, post_writer_hg, post_reader_hg,
		post.production.members.front().endpoint.hostname, true) == EXIT_SUCCESS,
		"completion preserves canonical writer_is_also_reader placement");
	ok(pool_count(admin, route_hgs.front()) >= target_route_pool,
		"completion does not repeat retirement of post-cutover production pools");
	ok(wait_for_pool_count(admin, green_writer_hg, "=0") == EXIT_SUCCESS,
		"completion drains eligible configured-green pools immediately");
	ok(server_count(
		admin, green_reader_hg,
		post.target.members.back().endpoint.hostname, 1, "OFFLINE_SOFT"),
		"completion preserves configured green rows and OFFLINE status");
	const int post_completion_route_hg = 1567;
	ok(add_route(
		admin, post_completion_route_hg,
		post.production.members.front().endpoint.hostname) == EXIT_SUCCESS
		&& set_default_hostgroup(admin, post_completion_route_hg) == EXIT_SUCCESS
		&& route_to_expected_backend(
			cl, sim, post.production.members.front().endpoint.backend()),
		"completion removes the production traffic pin without DNS verification");
	auto [post_replica_seq_rc, post_replica_sequence] = sim.replica_probe_log_last_sequence();
	ok(post_replica_seq_rc == EXIT_SUCCESS && completion_probe_policy(
		sim, post_replica_sequence, post, 750),
		"the completed latch uses configured cadence and canonical production probes");
	bool recreated_green_pool = set_default_hostgroup(admin, green_writer_hg) == EXIT_SUCCESS
		&& route_to_expected_backend(cl, sim, post.target.members.front().endpoint.backend())
		&& pool_count(admin, green_writer_hg) >= 1;
	auto [same_completed_seq_rc, same_completed_sequence] = sim.probe_log_last_sequence();
	bool same_completion_seen = same_completed_seq_rc == EXIT_SUCCESS
		&& publish_completed(sim, post, post) == EXIT_SUCCESS
		&& wait_for_topology_observation(sim, same_completed_sequence, post);
	ok(recreated_green_pool && same_completion_seen && pool_count(admin, green_writer_hg) >= 1,
		"repeated completion does not drain a pool created while latched");
	auto [latched_error_seq_rc, latched_error_sequence] = sim.probe_log_last_sequence();
	bool latched_error_seen = latched_error_seq_rc == EXIT_SUCCESS
		&& sim.topology_error(
			aurora_bgd_topology_backends(post), 1205, "simulated latched timeout")
			== EXIT_SUCCESS
		&& wait_for_topology_observation(sim, latched_error_sequence, post);
	ok(latched_error_seen && aurora_bgd_wait_for_status(
		admin, post_writer_hg, "SWITCHOVER_COMPLETED", 1) == EXIT_SUCCESS
		&& pool_count(admin, green_writer_hg) >= 1,
		"query errors neither release the latch nor repeat completion cleanup");
	Aurora_BGD_Test_Deployment different = aurora_bgd_deployment_b_writer_only();
	auto [different_seq_rc, different_sequence] = sim.probe_log_last_sequence();
	bool different_seen = different_seq_rc == EXIT_SUCCESS
		&& publish_completed(sim, post, different) == EXIT_SUCCESS
		&& wait_for_topology_observation(sim, different_sequence, post);
	ok(different_seen && wait_for_pool_count(admin, green_writer_hg, "=0") == EXIT_SUCCESS,
		"a different completed deployment fingerprint rearms and runs its cleanup");
	bool second_green_pool = set_default_hostgroup(admin, green_writer_hg) == EXIT_SUCCESS
		&& route_to_expected_backend(cl, sim, post.target.members.front().endpoint.backend());
	auto [repeat_different_seq_rc, repeat_different_sequence] = sim.probe_log_last_sequence();
	bool repeated_different = repeat_different_seq_rc == EXIT_SUCCESS
		&& publish_completed(sim, post, different) == EXIT_SUCCESS
		&& wait_for_topology_observation(sim, repeat_different_sequence, post);
	ok(second_green_pool && repeated_different && pool_count(admin, green_writer_hg) >= 1,
		"the new fingerprint is retained and its repeated completion is a no-op");
	ok(sim.topology_delete(aurora_bgd_topology_backends(post)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, post_writer_hg, "NONE", kWaitSeconds) == EXIT_SUCCESS,
		"successful empty topology releases the rearmed completed latch");

	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before direct-completion scenario");
		cleanup(admin, sim);
		return exit_status();
	}

	// A first observation at completion has no target map and does not replay prior phases.
	Aurora_BGD_Test_Deployment direct = aurora_bgd_deployment_b_writer_only();
	if (sim.replica_update(
		direct.blue_replica_set, direct.production.replica_rows(),
		direct.production.backends()) != EXIT_SUCCESS
		|| sim.topology_update(
			aurora_bgd_topology_backends(direct),
			aurora_bgd_completed_topology(direct)) != EXIT_SUCCESS) {
		diag("Error: failed to publish direct completion inputs");
		cleanup(admin, sim);
		return exit_status();
	}
	auto [direct_seq_rc, direct_sequence] = sim.replica_probe_log_last_sequence();
	if (aurora_bgd_admin_setup(
		admin, direct, 1580, 1581, -1, -1, true, 300, false) != EXIT_SUCCESS) {
		diag("Error: failed to configure direct completion");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(aurora_bgd_wait_for_status(
		admin, 1580, "SWITCHOVER_COMPLETED", kWaitSeconds) == EXIT_SUCCESS,
		"late entry directly at completion enters the terminal latch");
	ok(wait_for_writer_policy(
		admin, 1580, 1581,
		direct.production.members.front().endpoint.hostname, false) == EXIT_SUCCESS,
		"direct completion leaves canonical writer placement unchanged");
	auto [direct_logs_rc, direct_logs] = sim.replica_probe_log_since(direct_sequence);
	bool direct_membership_probe = false;
	for (const Aurora_Replica_Probe_Log& log : direct_logs) {
		direct_membership_probe |=
			log.probe_kind == Aurora_Replica_Probe_Kind::bgd_membership;
	}
	ok(direct_seq_rc == EXIT_SUCCESS && direct_logs_rc == EXIT_SUCCESS
		&& !direct_membership_probe,
		"direct completion does not manufacture target membership or replay active phases");
	ok(sim.topology_delete(aurora_bgd_topology_backends(direct)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(admin, 1580, "NONE", kWaitSeconds) == EXIT_SUCCESS,
		"direct-completion latch rearms only after topology drain");

	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean Aurora BGD completion test data");
		return EXIT_FAILURE;
	}
	return exit_status();
}
