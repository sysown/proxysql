/**
 * @file test_aurora_bgd_active-t.cpp
 * @brief Aurora BGD active-state probe suspension and routing behavior.
 *
 * Steps:
 *
 * 1. Configure a complete deployment and reach AVAILABLE.
 * 2. Enter INITIATED and verify placement suppression and fast target probing.
 * 3. Enter IN_PROGRESS and verify one writer demotion with source routing intact.
 * 4. Enter POST_PROCESSING and verify restoration, pool retirement, and target pins.
 * 5. Complete a previously incomplete target snapshot during POST_PROCESSING.
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

struct TestState {
	Aurora_BGD_Test_Deployment deployment { aurora_bgd_deployment_a() };
	int writer_hostgroup { 1530 };
	int reader_hostgroup { 1531 };
	int green_writer_hostgroup { 1532 };
	int green_reader_hostgroup { 1533 };
	vector<int> route_hostgroups { 1534, 1535, 1536 };
	Aurora_BGD_Test_Deployment gated { aurora_bgd_deployment_b_writer_only() };
	int gated_writer_hostgroup { 1540 };
	int gated_reader_hostgroup { 1541 };
	int gated_green_writer_hostgroup { 1542 };
	int gated_green_reader_hostgroup { 1543 };
	int gated_route_hostgroup { 1544 };
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

int reset_scenario(MYSQL* admin, BGD_Simulator& sim) {
	return aurora_bgd_admin_cleanup(admin) == EXIT_SUCCESS
		&& sim.cleanup() == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
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

/** Configure the active switchover scenario and reach AVAILABLE. */
int test_bgd_status_available(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	Aurora_BGD_Test_Deployment& deployment = state.deployment;
	if (aurora_bgd_publish(sim, deployment) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.writer_hostgroup, state.reader_hostgroup,
			state.green_writer_hostgroup, state.green_reader_hostgroup,
			false, 1000, false) != EXIT_SUCCESS
		|| add_member_routes(admin, deployment, state.route_hostgroups) != EXIT_SUCCESS) {
		diag("Error: failed to configure the active switchover scenario");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"active scenario starts from a complete AVAILABLE snapshot");
	return EXIT_SUCCESS;
}

/**
 * Enter SWITCHOVER_INITIATED.
 *
 * - Keep canonical writer placement unchanged.
 * - Replace ordinary Aurora probes with fast target-membership probes.
 * - Ignore a competing production role observation.
 */
int test_switchover_initiated(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	Aurora_BGD_Test_Deployment& deployment = state.deployment;
	if (publish_status(sim, deployment, "SWITCHOVER_INITIATED") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup, "SWITCHOVER_INITIATED", kWaitSeconds)
			!= EXIT_SUCCESS) {
		diag("Error: worker did not enter SWITCHOVER_INITIATED");
		return EXIT_FAILURE;
	}

	ok(true, "INITIATED is published");
	ok(wait_for_writer_placement(
		admin, state.writer_hostgroup, state.reader_hostgroup,
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
		return EXIT_FAILURE;
	}
	ok(fast_membership_without_ordinary(
		sim, source_change_sequence, deployment.target_replica_set, 350, 2),
		"changed source roles cannot compete while production probing is suspended");
	return EXIT_SUCCESS;
}

/**
 * Enter SWITCHOVER_IN_PROGRESS.
 *
 * - Demote the snapshotted production writer exactly once.
 * - Keep the competing source reader out of the writer hostgroup.
 * - Preserve source-backed routing pools.
 */
int test_switchover_in_progress(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	Aurora_BGD_Test_Deployment& deployment = state.deployment;
	if (publish_status(sim, deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup, "SWITCHOVER_IN_PROGRESS", kWaitSeconds)
			!= EXIT_SUCCESS) {
		diag("Error: worker did not enter SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}

	ok(true, "IN_PROGRESS is published");
	ok(wait_for_writer_placement(
		admin, state.writer_hostgroup, state.reader_hostgroup,
		deployment.production.members.front().endpoint.hostname, true) == EXIT_SUCCESS,
		"IN_PROGRESS demotes the snapshotted production writer");
	ok(runtime_server_count(
		admin, state.writer_hostgroup, deployment.production.members[1].endpoint.hostname, 0)
		&& runtime_server_count(
			admin, state.reader_hostgroup,
			deployment.production.members[1].endpoint.hostname, 1, "ONLINE"),
		"the competing source observation does not promote a reader");

	auto [repeat_progress_rc, repeat_progress_sequence] = sim.replica_probe_log_last_sequence();
	if (repeat_progress_rc != EXIT_SUCCESS
		|| publish_status(sim, deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS) {
		diag("Error: failed to repeat SWITCHOVER_IN_PROGRESS");
		return EXIT_FAILURE;
	}
	ok(fast_membership_without_ordinary(
		sim, repeat_progress_sequence, deployment.target_replica_set, 350, 2)
		&& wait_for_writer_placement(
			admin, state.writer_hostgroup, state.reader_hostgroup,
			deployment.production.members.front().endpoint.hostname, true) == EXIT_SUCCESS,
		"repeated IN_PROGRESS retains the one demotion and active probe policy");

	ok(route_members_to_expected_ips(
		cl, admin, sim, deployment, state.route_hostgroups, false)
		&& member_route_pool_count(admin, state.route_hostgroups)
			>= static_cast<int64_t>(state.route_hostgroups.size()),
		"all member routes use source IPs and hold pre-cutover pools");
	return EXIT_SUCCESS;
}

/**
 * Enter SWITCHOVER_IN_POST_PROCESSING.
 *
 * - Restore canonical placement and keep readers eligible.
 * - Retire pre-cutover pools and pin every production hostname to its target IP.
 * - Avoid replaying retirement on repeated POST_PROCESSING.
 */
int test_switchover_post_processing(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	Aurora_BGD_Test_Deployment& deployment = state.deployment;
	if (publish_status(sim, deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds)
			!= EXIT_SUCCESS) {
		diag("Error: worker did not enter SWITCHOVER_IN_POST_PROCESSING");
		return EXIT_FAILURE;
	}

	ok(true, "POST_PROCESSING is published without a target-writability gate");
	ok(wait_for_writer_placement(
		admin, state.writer_hostgroup, state.reader_hostgroup,
		deployment.production.members.front().endpoint.hostname, false) == EXIT_SUCCESS,
		"POST_PROCESSING restores the canonical writer placement");
	ok(runtime_server_count(
		admin, state.reader_hostgroup,
		deployment.production.members[1].endpoint.hostname, 1, "ONLINE")
		&& runtime_server_count(
			admin, state.reader_hostgroup,
			deployment.production.members[2].endpoint.hostname, 1, "ONLINE"),
		"POST_PROCESSING leaves canonical readers ONLINE and eligible");
	ok(wait_for_member_route_pool_count(
		admin, state.route_hostgroups, "=0") == EXIT_SUCCESS,
		"POST_PROCESSING retires the pre-cutover member pools");
	ok(route_members_to_expected_ips(
		cl, admin, sim, deployment, state.route_hostgroups, true),
		"POST_PROCESSING pins every production hostname to its cached target IP");

	const int64_t target_pool_count = member_route_pool_count(admin, state.route_hostgroups);
	auto [repeat_post_rc, repeat_post_sequence] = sim.probe_log_last_sequence();
	if (target_pool_count < static_cast<int64_t>(state.route_hostgroups.size())
		|| repeat_post_rc != EXIT_SUCCESS
		|| publish_status(sim, deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS) {
		diag("Error: failed to prepare repeated POST_PROCESSING");
		return EXIT_FAILURE;
	}
	vector<Endpoint> target_backends = deployment.target.backends();
	auto [repeat_probe_rc, repeat_probe] = aurora_bgd_wait_for_topology_probe(
		sim, repeat_post_sequence, target_backends, BGD_Probe_Kind::metadata,
		kProbeTimeoutMs);
	ok(repeat_probe_rc == EXIT_SUCCESS
		&& member_route_pool_count(admin, state.route_hostgroups) >= target_pool_count,
		"repeated POST_PROCESSING does not replay completed member retirement");

	auto [post_seq_rc, post_sequence] = sim.replica_probe_log_last_sequence();
	ok(post_seq_rc == EXIT_SUCCESS && fast_membership_without_ordinary(
		sim, post_sequence, deployment.target_replica_set, 350, 2),
		"POST_PROCESSING keeps fast BGD probes without ordinary Aurora queries");
	return EXIT_SUCCESS;
}

/**
 * Complete target membership after entering POST_PROCESSING.
 *
 * - Leave routing unchanged while the target snapshot is incomplete.
 * - Publish complete membership.
 * - Apply target routing on the next POST_PROCESSING observation.
 */
int test_post_processing_after_membership_completion(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before the incomplete-snapshot scenario");
		return EXIT_FAILURE;
	}

	Aurora_BGD_Test_Deployment& deployment = state.gated;
	vector<Aurora_Replica_Row> invalid_target = deployment.target.replica_rows();
	invalid_target.front().server_id = "unpaired-target-writer";
	if (sim.replica_update(
		deployment.blue_replica_set, deployment.production.replica_rows(),
		deployment.production.backends()) != EXIT_SUCCESS
		|| sim.replica_update(
			deployment.target_replica_set, invalid_target, deployment.target.backends())
			!= EXIT_SUCCESS
		|| sim.topology_update(
			aurora_bgd_topology_backends(deployment),
			aurora_bgd_available_topology(deployment)) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.gated_writer_hostgroup,
			state.gated_reader_hostgroup, state.gated_green_writer_hostgroup,
			state.gated_green_reader_hostgroup, false, 1000, false) != EXIT_SUCCESS
		|| add_member_routes(
			admin, deployment, { state.gated_route_hostgroup }) != EXIT_SUCCESS) {
		diag("Error: failed to configure incomplete target membership");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.gated_writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"an incomplete target snapshot can publish AVAILABLE without routing");
	if (publish_status(sim, deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, state.gated_writer_hostgroup,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: incomplete scenario did not publish POST_PROCESSING");
		return EXIT_FAILURE;
	}

	int default_rc = set_default_hostgroup(admin, state.gated_route_hostgroup);
	ok(default_rc == EXIT_SUCCESS && route_to_expected_backend(
		cl, sim, deployment.production.members.front().endpoint.backend()),
		"POST_PROCESSING leaves routing unchanged without a complete target snapshot");

	auto [refresh_seq_rc, refresh_sequence] = sim.replica_probe_log_last_sequence();
	if (refresh_seq_rc != EXIT_SUCCESS || sim.replica_update(
		deployment.target_replica_set, deployment.target.replica_rows(),
		deployment.target.backends()) != EXIT_SUCCESS) {
		diag("Error: failed to restore complete target membership");
		return EXIT_FAILURE;
	}
	auto [probe_rc, probe] = aurora_bgd_wait_for_replica_probe(
		sim, refresh_sequence, deployment.target.backends(),
		Aurora_Replica_Probe_Kind::bgd_membership,
		kProbeTimeoutMs, deployment.target_replica_set);
	bool target_routing = false;
	if (probe_rc == EXIT_SUCCESS
		&& wait_for_member_route_pool_count(
			admin, { state.gated_route_hostgroup }, "=0") == EXIT_SUCCESS
		&& set_default_hostgroup(admin, state.gated_route_hostgroup) == EXIT_SUCCESS) {
		target_routing = route_to_expected_backend(
			cl, sim, deployment.target.members.front().endpoint.backend());
	}
	ok(target_routing,
		"repeated POST_PROCESSING applies routing after membership becomes complete");
	return EXIT_SUCCESS;
}

int main() {
	plan(20);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: publish a complete deployment.
	// ProxySQL: configure Aurora BGD and per-member routing hostgroups.
	// Verify: the worker reaches AVAILABLE.
	if (test_bgd_status_available(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish INITIATED and a competing production role observation.
	// Verify: placement is suppressed and only fast target membership remains active.
	if (test_switchover_initiated(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish IN_PROGRESS twice.
	// Verify: the snapshotted writer is demoted once and source routes remain active.
	if (test_switchover_in_progress(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish POST_PROCESSING twice.
	// Verify: canonical placement, target pins, and one-time pool retirement.
	if (test_switchover_post_processing(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: enter POST_PROCESSING with incomplete membership, then complete it.
	// Verify: routing changes only after a complete target map exists.
	if (test_post_processing_after_membership_completion(cl, admin, sim, state)
		!= EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean Aurora BGD active-state test data");
		return EXIT_FAILURE;
	}
	return exit_status();
}
