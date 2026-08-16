/**
 * @file test_aurora_bgd_error_recovery-t.cpp
 * @brief Aurora BGD active-state error retention, rollback, and cancellation.
 *
 * Steps:
 *
 * 1. Verify topology and membership errors retain INITIATED and POST_PROCESSING effects.
 * 2. Move backward from IN_PROGRESS and restore canonical writer placement.
 * 3. Cancel an active deployment through empty or absent topology and resume ordinary probes.
 * 4. Roll back POST_PROCESSING pins while preserving configured green pools.
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
		diag("Error: failed to load TAP environment");
		return EXIT_FAILURE;
	}
	admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (admin == nullptr) {
		diag("Error: failed to connect to ProxySQL Admin");
		return EXIT_FAILURE;
	}
	char username[] = "aurora1";
	char password[] = "pass1"; // NOSONAR: fixed simulator fixture credential.
	if (sim.connect(cl.host, 3306, username, password) != EXIT_SUCCESS
		|| aurora_bgd_admin_cleanup(admin) != EXIT_SUCCESS
		|| sim.cleanup() != EXIT_SUCCESS) {
		diag("Error: failed to initialize the shared AWS simulator");
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
			"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,use_ssl,comment) VALUES (" +
			to_string(route_hgs[i]) + "," +
			aurora_bgd_sql_quote(deployment.production.members[i].endpoint.hostname) +
			",3306,'ONLINE',1,'Aurora BGD rollback route')");
	}
	queries.push_back(
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,use_ssl,comment) VALUES (" +
		to_string(green_writer_hg) + "," +
		aurora_bgd_sql_quote(deployment.target.members.front().endpoint.hostname) +
		",3306,'ONLINE',1,'Aurora BGD rollback green pool')");
	queries.push_back("LOAD MYSQL SERVERS TO RUNTIME");
	return aurora_bgd_execute_all(admin, queries);
}

bool route_to_backend(
	CommandLine& cl, BGD_Simulator& sim, const Endpoint& expected
) {
	auto [sequence_rc, sequence] = sim.replica_probe_log_last_sequence();
	if (sequence_rc != EXIT_SUCCESS) {
		return false;
	}
	MYSQL* client = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (client == nullptr) {
		return false;
	}
	auto [query_rc, rows] = mysql_query_ext_rows(client, kAuroraBGDRouteProbeQuery);
	(void)rows;
	mysql_close(client);
	return query_rc == EXIT_SUCCESS
		&& aurora_bgd_routing_probe_reached(sim, sequence, expected);
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

bool observe_two_topology_responses(
	BGD_Simulator& sim, uint64_t sequence, const vector<Endpoint>& backends
) {
	auto [first_rc, first] = aurora_bgd_wait_for_topology_probe(
		sim, sequence, backends, BGD_Probe_Kind::metadata, kProbeTimeoutMs);
	if (first_rc != EXIT_SUCCESS) {
		return false;
	}
	auto [second_rc, second] = aurora_bgd_wait_for_topology_probe(
		sim, first.sequence_id, backends, BGD_Probe_Kind::metadata, kProbeTimeoutMs);
	return second_rc == EXIT_SUCCESS;
}

bool observe_two_membership_responses(
	BGD_Simulator& sim, uint64_t sequence,
	const vector<Endpoint>& backends, const string& replica_set
) {
	auto [first_rc, first] = aurora_bgd_wait_for_replica_probe(
		sim, sequence, backends, Aurora_Replica_Probe_Kind::bgd_membership,
		kProbeTimeoutMs, replica_set);
	if (first_rc != EXIT_SUCCESS) {
		return false;
	}
	auto [second_rc, second] = aurora_bgd_wait_for_replica_probe(
		sim, first.sequence_id, backends, Aurora_Replica_Probe_Kind::bgd_membership,
		kProbeTimeoutMs, replica_set);
	return second_rc == EXIT_SUCCESS;
}

/** Retain INITIATED across topology and membership query errors. */
int test_initiated_error_retention(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	Aurora_BGD_Test_Deployment& deployment = state.initiated;
	if (publish_initial(sim, deployment, "SWITCHOVER_INITIATED") != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.initiated_writer_hostgroup,
			state.initiated_reader_hostgroup, state.initiated_green_writer_hostgroup,
			state.initiated_green_reader_hostgroup, false, 300, false) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, state.initiated_writer_hostgroup,
			"SWITCHOVER_INITIATED", kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: failed to configure INITIATED error retention");
		return EXIT_FAILURE;
	}

	auto [topology_seq_rc, topology_sequence] = sim.probe_log_last_sequence();
	bool topology_error_seen = topology_seq_rc == EXIT_SUCCESS
		&& sim.topology_error(
			aurora_bgd_topology_backends(deployment), 1205,
			"simulated topology timeout") == EXIT_SUCCESS
		&& observe_two_topology_responses(
			sim, topology_sequence, deployment.target.backends());
	ok(topology_error_seen && aurora_bgd_wait_for_status(
		admin, state.initiated_writer_hostgroup, "SWITCHOVER_INITIATED", 1)
		== EXIT_SUCCESS,
		"topology errors retain the active state");
	if (publish_status(sim, deployment, "SWITCHOVER_INITIATED") != EXIT_SUCCESS) {
		diag("Error: failed to restore topology after error");
		return EXIT_FAILURE;
	}

	auto [membership_seq_rc, membership_sequence] = sim.replica_probe_log_last_sequence();
	bool membership_error_seen = membership_seq_rc == EXIT_SUCCESS
		&& sim.replica_error(
			deployment.target.backends(), 1205,
			"simulated membership timeout") == EXIT_SUCCESS
		&& observe_two_membership_responses(
			sim, membership_sequence, deployment.target.backends(),
			deployment.target_replica_set);
	ok(membership_error_seen && aurora_bgd_wait_for_status(
		admin, state.initiated_writer_hostgroup, "SWITCHOVER_INITIATED", 1)
		== EXIT_SUCCESS,
		"membership errors retain the last complete state");
	return EXIT_SUCCESS;
}

/** Roll back IN_PROGRESS through an earlier status, then cancel and rearm. */
int test_initiated_rollback_and_cancellation(
	MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	Aurora_BGD_Test_Deployment& deployment = state.initiated;
	if (sim.replica_update(
		deployment.target.replica_set_id, deployment.target.replica_rows(),
		deployment.target.backends()) != EXIT_SUCCESS
		|| publish_status(sim, deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, state.initiated_writer_hostgroup,
			"SWITCHOVER_IN_PROGRESS", kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: failed to advance to IN_PROGRESS");
		return EXIT_FAILURE;
	}
	ok(writer_placement(
		admin, state.initiated_writer_hostgroup, state.initiated_reader_hostgroup,
		deployment.production.members.front().endpoint.hostname, true),
		"IN_PROGRESS demotes the reconstructed production writer");
	ok(publish_status(sim, deployment, "SWITCHOVER_INITIATED") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.initiated_writer_hostgroup,
			"SWITCHOVER_INITIATED", kWaitSeconds) == EXIT_SUCCESS
		&& writer_placement(
			admin, state.initiated_writer_hostgroup, state.initiated_reader_hostgroup,
			deployment.production.members.front().endpoint.hostname, false),
		"a backward status rolls back writer placement before entering the earlier state");

	auto [ordinary_seq_rc, ordinary_sequence] = sim.replica_probe_log_last_sequence();
	ok(sim.topology_delete(aurora_bgd_topology_backends(deployment)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.initiated_writer_hostgroup, "NONE", kWaitSeconds) == EXIT_SUCCESS,
		"a successful empty topology cancels the active deployment");
	ok(ordinary_seq_rc == EXIT_SUCCESS
		&& wait_for_ordinary_probe(sim, ordinary_sequence, deployment),
		"cancellation resumes ordinary production probing");
	ok(publish_status(sim, deployment, "AVAILABLE") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.initiated_writer_hostgroup, "AVAILABLE", kWaitSeconds)
			== EXIT_SUCCESS,
		"the worker admits a repeated deployment after cancellation");
	return EXIT_SUCCESS;
}

/** Roll back a first IN_PROGRESS observation after confirmed topology absence. */
int test_in_progress_topology_absence(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before IN_PROGRESS rollback");
		return EXIT_FAILURE;
	}
	Aurora_BGD_Test_Deployment& deployment = state.progress;
	if (publish_initial(sim, deployment, "SWITCHOVER_IN_PROGRESS") != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.progress_writer_hostgroup,
			state.progress_reader_hostgroup, state.progress_green_writer_hostgroup,
			state.progress_green_reader_hostgroup, false, 300, false) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, state.progress_writer_hostgroup,
			"SWITCHOVER_IN_PROGRESS", kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: failed to configure IN_PROGRESS rollback");
		return EXIT_FAILURE;
	}
	ok(sim.topology_drop(aurora_bgd_topology_backends(deployment)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.progress_writer_hostgroup, "NONE", kWaitSeconds) == EXIT_SUCCESS
		&& writer_placement(
			admin, state.progress_writer_hostgroup, state.progress_reader_hostgroup,
			deployment.production.members.front().endpoint.hostname, false),
		"confirmed topology absence rolls back IN_PROGRESS to NONE");
	return EXIT_SUCCESS;
}

/** Retain POST_PROCESSING pins across topology and membership query errors. */
int test_post_processing_error_retention(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before POST_PROCESSING error retention");
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
			state.post_green_writer_hostgroup) != EXIT_SUCCESS
		|| aurora_bgd_wait_for_status(
			admin, state.post_writer_hostgroup,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) != EXIT_SUCCESS) {
		diag("Error: failed to configure POST_PROCESSING error retention");
		return EXIT_FAILURE;
	}

	auto [topology_seq_rc, topology_sequence] = sim.probe_log_last_sequence();
	bool topology_error_seen = topology_seq_rc == EXIT_SUCCESS
		&& sim.topology_error(
			aurora_bgd_topology_backends(deployment), 1205,
			"simulated post timeout") == EXIT_SUCCESS
		&& observe_two_topology_responses(
			sim, topology_sequence, deployment.target.backends());
	ok(topology_error_seen && aurora_bgd_wait_for_status(
		admin, state.post_writer_hostgroup,
		"SWITCHOVER_IN_POST_PROCESSING", 1) == EXIT_SUCCESS
		&& route_members(
			cl, admin, sim, deployment, state.post_route_hostgroups, true),
		"topology errors do not roll back applied POST_PROCESSING pins");
	if (publish_status(sim, deployment, "SWITCHOVER_IN_POST_PROCESSING") != EXIT_SUCCESS) {
		diag("Error: failed to restore POST_PROCESSING topology");
		return EXIT_FAILURE;
	}

	auto [membership_seq_rc, membership_sequence] = sim.replica_probe_log_last_sequence();
	bool membership_error_seen = membership_seq_rc == EXIT_SUCCESS
		&& sim.replica_error(
			deployment.target.backends(), 1205,
			"simulated post membership timeout") == EXIT_SUCCESS
		&& observe_two_membership_responses(
			sim, membership_sequence, deployment.target.backends(),
			deployment.target_replica_set);
	ok(membership_error_seen
		&& sim.replica_update(
			deployment.target.replica_set_id, deployment.target.replica_rows(),
			deployment.target.backends()) == EXIT_SUCCESS
		&& route_members(
			cl, admin, sim, deployment, state.post_route_hostgroups, true),
		"membership errors retain the last complete mapped routing");
	return EXIT_SUCCESS;
}

/** Roll back POST_PROCESSING pins while preserving configured green pools. */
int test_post_processing_rollback(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	Aurora_BGD_Test_Deployment& deployment = state.post;
	ok(set_default_hostgroup(admin, state.post_green_writer_hostgroup) == EXIT_SUCCESS
		&& route_to_backend(
			cl, sim, deployment.target.members.front().endpoint.backend())
		&& pool_count(admin, state.post_green_writer_hostgroup) >= 1,
		"a configured green pool is established before rollback");
	ok(publish_status(sim, deployment, "AVAILABLE") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.post_writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"a backward POST_PROCESSING status completes rollback before AVAILABLE");
	ok(writer_placement(
		admin, state.post_writer_hostgroup, state.post_reader_hostgroup,
		deployment.production.members.front().endpoint.hostname, false)
		&& route_members(
			cl, admin, sim, deployment, state.post_route_hostgroups, false),
		"rollback removes pins and restores canonical writer and member routing");
	ok(pool_count(admin, state.post_green_writer_hostgroup) >= 1,
		"rollback preserves configured green pools instead of draining them");
	return EXIT_SUCCESS;
}

int main() {
	plan(14);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: inject topology and membership errors during INITIATED.
	// Verify: the active state and last complete membership are retained.
	if (test_initiated_error_retention(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: move backward from IN_PROGRESS, then publish empty topology.
	// Verify: placement rolls back, ordinary probes resume, and the worker rearms.
	if (test_initiated_rollback_and_cancellation(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: make IN_PROGRESS the first observation, then confirm absence.
	// Verify: the worker returns to NONE and restores the writer.
	if (test_in_progress_topology_absence(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: inject topology and membership errors during POST_PROCESSING.
	// Verify: the applied target pins and last complete map remain active.
	if (test_post_processing_error_retention(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish AVAILABLE after POST_PROCESSING.
	// Verify: pins and placement roll back without draining configured green pools.
	if (test_post_processing_rollback(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean Aurora BGD error-recovery test data");
		return EXIT_FAILURE;
	}
	return exit_status();
}
