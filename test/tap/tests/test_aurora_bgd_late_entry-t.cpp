/**
 * @file test_aurora_bgd_late_entry-t.cpp
 * @brief Aurora BGD reconstruction from first observations in active states.
 *
 * Steps:
 *
 * 1. Start a worker from SWITCHOVER_INITIATED and reconstruct active probing.
 * 2. Start a worker from SWITCHOVER_IN_PROGRESS and reconstruct writer demotion.
 * 3. Recover late IN_PROGRESS entry when the first ordinary probe fails.
 * 4. Start a worker from POST_PROCESSING and reconstruct every target pin.
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
	Aurora_BGD_Test_Deployment initiated { aurora_bgd_deployment_b_writer_only() };
	int initiated_writer_hostgroup { 1590 };
	int initiated_reader_hostgroup { 1591 };
	int initiated_green_writer_hostgroup { 1592 };
	int initiated_green_reader_hostgroup { 1593 };
	Aurora_BGD_Test_Deployment progress { aurora_bgd_deployment_b_writer_only() };
	int progress_writer_hostgroup { 1600 };
	int progress_reader_hostgroup { 1601 };
	int progress_green_writer_hostgroup { 1602 };
	int progress_green_reader_hostgroup { 1603 };
	Aurora_BGD_Test_Deployment post { aurora_bgd_deployment_a() };
	int post_writer_hostgroup { 1610 };
	int post_reader_hostgroup { 1611 };
	int post_green_writer_hostgroup { 1612 };
	int post_green_reader_hostgroup { 1613 };
	vector<int> post_route_hostgroups { 1614, 1615, 1616 };
};

int setup(CommandLine& cl, MYSQL*& admin, BGD_Simulator& sim) {
	if (cl.getEnv()) {
		return EXIT_FAILURE;
	}
	admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (admin == nullptr) {
		return EXIT_FAILURE;
	}
	char username[] = "aurora1";
	char password[] = "pass1"; // NOSONAR: fixed simulator fixture credential.
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

bool route_to_backend(
	CommandLine& cl, BGD_Simulator& sim, const Endpoint& expected,
	const Aurora_BGD_Membership_Set& expected_membership
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
	mysql_close(client);
	if (query_rc != EXIT_SUCCESS
		|| !aurora_bgd_result_matches_membership(rows, expected_membership)) {
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
		const Aurora_BGD_Membership_Set& expected_membership = target
			? deployment.target : deployment.production;
		if (!route_to_backend(cl, sim, expected, expected_membership)) {
			return false;
		}
	}
	return true;
}

/**
 * Start a worker from SWITCHOVER_INITIATED.
 *
 * - Publish INITIATED before the worker exists.
 * - Keep canonical writer placement.
 * - Reconstruct fast target-membership probing.
 */
int test_first_initiated(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	Aurora_BGD_Test_Deployment& deployment = state.initiated;
	if (publish_initial(sim, deployment, "SWITCHOVER_INITIATED") != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.initiated_writer_hostgroup,
			state.initiated_reader_hostgroup, state.initiated_green_writer_hostgroup,
			state.initiated_green_reader_hostgroup, false, 300, false) != EXIT_SUCCESS) {
		diag("Error: failed to configure INITIATED late entry");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.initiated_writer_hostgroup,
		"SWITCHOVER_INITIATED", kWaitSeconds) == EXIT_SUCCESS,
		"late entry at INITIATED publishes the observed state");
	ok(writer_placement(
		admin, state.initiated_writer_hostgroup, state.initiated_reader_hostgroup,
		deployment.production.members.front().endpoint.hostname, false),
		"late INITIATED entry leaves writer placement unchanged");
	auto [sequence_rc, sequence] = sim.replica_probe_log_last_sequence();
	ok(sequence_rc == EXIT_SUCCESS && active_probe_policy(
		sim, sequence, deployment.target_replica_set, 450),
		"late INITIATED entry reconstructs fast membership probing");
	return EXIT_SUCCESS;
}

/**
 * Start a worker from SWITCHOVER_IN_PROGRESS.
 *
 * - Publish IN_PROGRESS before the worker exists.
 * - Reconstruct the source snapshot.
 * - Demote the production writer immediately.
 */
int test_first_in_progress(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before IN_PROGRESS late entry");
		return EXIT_FAILURE;
	}

	Aurora_BGD_Test_Deployment& deployment = state.progress;
	if (publish_initial(sim, deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.progress_writer_hostgroup,
			state.progress_reader_hostgroup, state.progress_green_writer_hostgroup,
			state.progress_green_reader_hostgroup, false, 300, false) != EXIT_SUCCESS) {
		diag("Error: failed to configure IN_PROGRESS late entry");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.progress_writer_hostgroup,
		"SWITCHOVER_IN_PROGRESS", kWaitSeconds) == EXIT_SUCCESS
		&& writer_placement(
			admin, state.progress_writer_hostgroup, state.progress_reader_hostgroup,
			deployment.production.members.front().endpoint.hostname, true),
		"late entry at IN_PROGRESS reconstructs and demotes the writer");
	return EXIT_SUCCESS;
}

/**
 * Reconstruct IN_PROGRESS while the first ordinary Aurora query is failing.
 *
 * The fixed production membership comes from the configured/runtime hostgroups,
 * so entering an active phase never depends on a successful cutover-time query.
 */
int test_first_in_progress_after_ordinary_error(
	MYSQL* admin, BGD_Simulator& sim, TestState& state
) {
	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before failed-probe late entry");
		return EXIT_FAILURE;
	}

	Aurora_BGD_Test_Deployment& deployment = state.progress;
	if (publish_initial(sim, deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| sim.replica_error(
			deployment.production.backends(), 1205,
			"simulated initial ordinary Aurora timeout") != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.progress_writer_hostgroup,
			state.progress_reader_hostgroup, state.progress_green_writer_hostgroup,
			state.progress_green_reader_hostgroup, false, 300, false) != EXIT_SUCCESS) {
		diag("Error: failed to configure failed-probe IN_PROGRESS late entry");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.progress_writer_hostgroup,
		"SWITCHOVER_IN_PROGRESS", kWaitSeconds) == EXIT_SUCCESS
		&& writer_placement(
			admin, state.progress_writer_hostgroup, state.progress_reader_hostgroup,
			deployment.production.members.front().endpoint.hostname, true),
		"late IN_PROGRESS entry reconstructs and demotes after an initial ordinary-query failure");
	return EXIT_SUCCESS;
}

/**
 * Reconstruct POST_PROCESSING after a non-empty but partial ordinary result.
 *
 * The configured/runtime hostgroups define the complete production membership,
 * so a writer-only observation cannot make a writer-only target map actionable.
 */
int test_first_post_processing_after_partial_ordinary(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state
) {
	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before partial-probe late entry");
		return EXIT_FAILURE;
	}

	Aurora_BGD_Test_Deployment& deployment = state.post;
	vector<Aurora_Replica_Row> partial_production = deployment.production.replica_rows();
	partial_production.resize(1);
	vector<Aurora_Replica_Row> partial_target = deployment.target.replica_rows();
	partial_target.resize(1);
	if (sim.replica_update(
		deployment.production.replica_set_id, partial_production,
		deployment.production.backends()) != EXIT_SUCCESS
		|| sim.replica_update(
			deployment.target.replica_set_id, partial_target,
			deployment.target.backends()) != EXIT_SUCCESS
		|| sim.topology_update(
			aurora_bgd_topology_backends(deployment),
			aurora_bgd_topology(deployment, "SWITCHOVER_IN_POST_PROCESSING"))
			!= EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.post_writer_hostgroup,
			state.post_reader_hostgroup, state.post_green_writer_hostgroup,
			state.post_green_reader_hostgroup, false, 300, false) != EXIT_SUCCESS
		|| add_routes(
			admin, deployment, state.post_route_hostgroups,
			state.post_green_writer_hostgroup) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, state.post_writer_hostgroup,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: failed to configure partial-probe POST_PROCESSING late entry");
		return EXIT_FAILURE;
	}

	auto [partial_seq_rc, partial_sequence] = sim.replica_probe_log_last_sequence();
	bool partial_map_blocked = partial_seq_rc == EXIT_SUCCESS
		&& sim.replica_update(
			deployment.production.replica_set_id,
			deployment.production.replica_rows(), deployment.production.backends())
			== EXIT_SUCCESS;
	if (partial_map_blocked) {
		auto [partial_probe_rc, partial_probe] = aurora_bgd_wait_for_replica_probe(
			sim, partial_sequence, deployment.target.backends(),
			Aurora_Replica_Probe_Kind::bgd_membership, 5000,
			deployment.target.replica_set_id);
		partial_map_blocked = partial_probe_rc == EXIT_SUCCESS
			&& route_members(
				cl, admin, sim, deployment, state.post_route_hostgroups, false);
	}
	ok(partial_map_blocked,
		"a partial initial ordinary result cannot authorize partial target routing");

	auto [complete_seq_rc, complete_sequence] = sim.replica_probe_log_last_sequence();
	bool complete_map_applied = complete_seq_rc == EXIT_SUCCESS
		&& sim.replica_update(
			deployment.target.replica_set_id, deployment.target.replica_rows(),
			deployment.target.backends()) == EXIT_SUCCESS;
	if (complete_map_applied) {
		auto [complete_probe_rc, complete_probe] = aurora_bgd_wait_for_replica_probe(
			sim, complete_sequence, deployment.target.backends(),
			Aurora_Replica_Probe_Kind::bgd_membership, 5000,
			deployment.target.replica_set_id);
		complete_map_applied = complete_probe_rc == EXIT_SUCCESS
			&& route_members(
				cl, admin, sim, deployment, state.post_route_hostgroups, true);
	}
	ok(complete_map_applied,
		"complete target membership routes every configured production member");
	return EXIT_SUCCESS;
}

/**
 * Start a worker from SWITCHOVER_IN_POST_PROCESSING.
 *
 * - Publish POST_PROCESSING before the worker exists.
 * - Reconstruct the complete target map.
 * - Apply every production-to-target traffic pin.
 */
int test_first_post_processing(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before POST_PROCESSING late entry");
		return EXIT_FAILURE;
	}

	Aurora_BGD_Test_Deployment& deployment = state.post;
	if (publish_initial(sim, deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.post_writer_hostgroup,
			state.post_reader_hostgroup, state.post_green_writer_hostgroup,
			state.post_green_reader_hostgroup, false, 300, false) != EXIT_SUCCESS
		|| add_routes(
			admin, deployment, state.post_route_hostgroups,
			state.post_green_writer_hostgroup) != EXIT_SUCCESS) {
		diag("Error: failed to configure POST_PROCESSING late entry");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.post_writer_hostgroup,
		"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"late entry at POST_PROCESSING reconstructs the active phase");
	ok(route_members(
		cl, admin, sim, deployment, state.post_route_hostgroups, true),
		"late POST_PROCESSING entry reconstructs and applies every target pin");
	return EXIT_SUCCESS;
}

int main() {
	plan(9);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: make INITIATED the first observed deployment state.
	// Verify: canonical placement and fast target probing are reconstructed.
	if (test_first_initiated(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: make IN_PROGRESS the first observed deployment state.
	// Verify: the worker reconstructs and demotes the production writer.
	if (test_first_in_progress(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: fail the initial ordinary query while publishing IN_PROGRESS.
	// Verify: configured production membership still permits immediate demotion.
	if (test_first_in_progress_after_ordinary_error(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: return only the writer from the first ordinary and target probes.
	// Verify: configured production membership blocks partial routing, then accepts the full map.
	if (test_first_post_processing_after_partial_ordinary(cl, admin, sim, state)
		!= EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: make POST_PROCESSING the first observed deployment state.
	// Verify: the worker reconstructs and applies every target pin.
	if (test_first_post_processing(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean Aurora BGD late-entry test data");
		return EXIT_FAILURE;
	}
	return exit_status();
}
