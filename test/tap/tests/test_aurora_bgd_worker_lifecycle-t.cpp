/**
 * @file test_aurora_bgd_worker_lifecycle-t.cpp
 * @brief Aurora BGD worker refresh, deactivation, and terminal rearming.
 *
 * Steps:
 *
 * 1. Refresh server, variable, and green-hostgroup configuration during POST_PROCESSING.
 * 2. Deactivate the owning row and restore canonical production routing.
 * 3. Refresh a completed worker without releasing its terminal latch.
 * 4. Rearm the completed worker after a successful topology drain.
 */

#include <cstdint>
#include <cstdlib>
#include <string>

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
	Aurora_BGD_Test_Deployment reload { aurora_bgd_deployment_a() };
	int reload_writer_hostgroup { 1620 };
	int reload_reader_hostgroup { 1621 };
	int reload_green_writer_hostgroup { 1622 };
	int reload_green_reader_hostgroup { 1623 };
	int reload_route_hostgroup { 1624 };
	int refreshed_green_writer_hostgroup { 1626 };
	int refreshed_green_reader_hostgroup { 1627 };
	Aurora_BGD_Test_Deployment terminal { aurora_bgd_deployment_b_writer_only() };
	int terminal_writer_hostgroup { 1630 };
	int terminal_reader_hostgroup { 1631 };
	int terminal_green_writer_hostgroup { 1632 };
	int terminal_green_reader_hostgroup { 1633 };
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

int add_writer_route(
	MYSQL* admin, Aurora_BGD_Test_Deployment& deployment, int hostgroup
) {
	return aurora_bgd_execute_all(admin, {
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,comment) VALUES (" +
			to_string(hostgroup) + "," +
			aurora_bgd_sql_quote(deployment.production.members.front().endpoint.hostname) +
			",3306,'ONLINE','Aurora BGD lifecycle route')",
		"LOAD MYSQL SERVERS TO RUNTIME",
	});
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

bool route_writer(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim,
	Aurora_BGD_Test_Deployment& deployment, int route_hg, bool target
) {
	if (set_default_hostgroup(admin, route_hg) != EXIT_SUCCESS) {
		return false;
	}
	const Endpoint expected = target
		? deployment.target.members.front().endpoint.backend()
		: deployment.production.members.front().endpoint.backend();
	const Aurora_BGD_Membership_Set& expected_membership = target
		? deployment.target : deployment.production;
	return route_to_backend(cl, sim, expected, expected_membership);
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

bool wait_for_inactive_none(MYSQL* admin, int writer_hg) {
	return wait_for_cond(
		admin,
		"SELECT COUNT(*)=1 FROM runtime_mysql_aws_aurora_hostgroups WHERE writer_hostgroup=" +
			to_string(writer_hg) + " AND active=0 AND bgd_status='NONE'",
		kWaitSeconds) == EXIT_SUCCESS;
}

/**
 * Refresh an active worker without resetting its FSM or traffic pins.
 *
 * - Reload unrelated server and monitor-variable configuration.
 * - Refresh green staging hostgroups.
 * - Preserve POST_PROCESSING status, cached membership, and target routing.
 */
int test_active_worker_refresh(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	Aurora_BGD_Test_Deployment& deployment = state.reload;
	if (aurora_bgd_publish(sim, deployment) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.reload_writer_hostgroup,
			state.reload_reader_hostgroup, state.reload_green_writer_hostgroup,
			state.reload_green_reader_hostgroup, false, 300) != EXIT_SUCCESS
		|| add_writer_route(
			admin, deployment, state.reload_route_hostgroup) != EXIT_SUCCESS) {
		diag("Error: failed to configure the active reload scenario");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.reload_writer_hostgroup, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"reload scenario starts from AVAILABLE");
	ok(publish_status(sim, deployment, "SWITCHOVER_IN_POST_PROCESSING") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.reload_writer_hostgroup,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS
		&& route_writer(
			cl, admin, sim, deployment, state.reload_route_hostgroup, true),
		"active reload scenario pins writer traffic to the target");
	ok(aurora_bgd_execute_all(
		admin, { "LOAD MYSQL SERVERS TO RUNTIME" }) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.reload_writer_hostgroup,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"an unrelated server reload preserves active FSM status");
	ok(route_writer(
		cl, admin, sim, deployment, state.reload_route_hostgroup, true),
		"an unrelated server reload preserves the applied traffic pin");
	ok(aurora_bgd_execute_all(admin, {
		"SET mysql-aws_blue_green_deployment_auto_discovery='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	}) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.reload_writer_hostgroup,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"disabling auto-discovery does not abort an admitted deployment");
	ok(route_writer(
		cl, admin, sim, deployment, state.reload_route_hostgroup, true),
		"a variable refresh preserves cached membership and target routing");
	ok(aurora_bgd_execute_all(admin, {
		"UPDATE mysql_aws_aurora_hostgroups SET green_writer_hostgroup=" +
			to_string(state.refreshed_green_writer_hostgroup) +
			",green_reader_hostgroup=" +
			to_string(state.refreshed_green_reader_hostgroup) +
			" WHERE writer_hostgroup=" + to_string(state.reload_writer_hostgroup),
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) == EXIT_SUCCESS
		&& wait_for_cond(
			admin,
			"SELECT COUNT(*)=1 FROM runtime_mysql_aws_aurora_hostgroups "
			"WHERE writer_hostgroup=" + to_string(state.reload_writer_hostgroup) +
			" AND green_writer_hostgroup=" +
			to_string(state.refreshed_green_writer_hostgroup) +
			" AND green_reader_hostgroup=" +
			to_string(state.refreshed_green_reader_hostgroup) +
			" AND bgd_status='SWITCHOVER_IN_POST_PROCESSING'",
			kWaitSeconds) == EXIT_SUCCESS,
		"green hostgroup changes refresh staging references without resetting the FSM");
	ok(route_writer(
		cl, admin, sim, deployment, state.reload_route_hostgroup, true),
		"green hostgroup refresh preserves applied pins and cached target IPs");
	return EXIT_SUCCESS;
}

/**
 * Deactivate an active worker.
 *
 * - Stop the worker after publishing NONE.
 * - Restore canonical writer placement and production routing.
 * - Preserve administrator-owned configuration and server rows.
 */
int test_active_worker_deactivation(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	Aurora_BGD_Test_Deployment& deployment = state.reload;
	ok(aurora_bgd_execute_all(admin, {
		"UPDATE mysql_aws_aurora_hostgroups SET active=0 WHERE writer_hostgroup=" +
			to_string(state.reload_writer_hostgroup),
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) == EXIT_SUCCESS && wait_for_inactive_none(admin, state.reload_writer_hostgroup),
		"deactivating the owning row stops the worker after publishing NONE");
	ok(writer_placement(
		admin, state.reload_writer_hostgroup, state.reload_reader_hostgroup,
		deployment.production.members.front().endpoint.hostname, false),
		"worker teardown restores canonical writer placement");
	ok(route_writer(
		cl, admin, sim, deployment, state.reload_route_hostgroup, false),
		"worker teardown removes the applied traffic pin");
	ok(wait_for_cond(
		admin,
		"SELECT ((SELECT COUNT(*) FROM mysql_aws_aurora_hostgroups "
		"WHERE writer_hostgroup=" + to_string(state.reload_writer_hostgroup) +
		" AND active=0)=1) AND "
		"((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostname=" +
			aurora_bgd_sql_quote(deployment.production.members.front().endpoint.hostname) +
		")>=1)",
		kWaitSeconds) == EXIT_SUCCESS,
		"teardown preserves user configuration and server rows");
	return EXIT_SUCCESS;
}

/**
 * Refresh and rearm a worker in the completed latch.
 *
 * - Change configured green hostgroups and monitor variables.
 * - Preserve SWITCHOVER_COMPLETED across the refresh.
 * - Release the latch only after a successful topology drain.
 */
int test_terminal_worker_refresh(MYSQL* admin, BGD_Simulator& sim, TestState& state) {
	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before terminal reload scenario");
		return EXIT_FAILURE;
	}

	Aurora_BGD_Test_Deployment& deployment = state.terminal;
	if (aurora_bgd_publish(sim, deployment) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, deployment, state.terminal_writer_hostgroup,
			state.terminal_reader_hostgroup, -1, -1, true, 300) != EXIT_SUCCESS) {
		diag("Error: failed to configure the terminal reload scenario");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.terminal_writer_hostgroup, "AVAILABLE", kWaitSeconds)
		== EXIT_SUCCESS,
		"terminal reload scenario starts from AVAILABLE");
	ok(sim.topology_update(
		aurora_bgd_topology_backends(deployment),
		aurora_bgd_completed_topology(deployment)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.terminal_writer_hostgroup,
			"SWITCHOVER_COMPLETED", kWaitSeconds) == EXIT_SUCCESS,
		"direct completion enters the terminal latch");
	ok(aurora_bgd_execute_all(admin, {
		"UPDATE mysql_aws_aurora_hostgroups SET green_writer_hostgroup=" +
			to_string(state.terminal_green_writer_hostgroup) +
			",green_reader_hostgroup=" +
			to_string(state.terminal_green_reader_hostgroup) +
			" WHERE writer_hostgroup=" + to_string(state.terminal_writer_hostgroup),
		"LOAD MYSQL SERVERS TO RUNTIME",
		"SET mysql-aws_blue_green_deployment_auto_discovery='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	}) == EXIT_SUCCESS
		&& wait_for_cond(
			admin,
			"SELECT COUNT(*)=1 FROM runtime_mysql_aws_aurora_hostgroups "
			"WHERE writer_hostgroup=" + to_string(state.terminal_writer_hostgroup) +
			" AND green_writer_hostgroup=" +
			to_string(state.terminal_green_writer_hostgroup) +
			" AND green_reader_hostgroup=" +
			to_string(state.terminal_green_reader_hostgroup) +
			" AND bgd_status='SWITCHOVER_COMPLETED'",
			kWaitSeconds) == EXIT_SUCCESS,
		"configuration and variable refresh preserve the terminal latch");
	ok(sim.topology_delete(aurora_bgd_topology_backends(deployment)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.terminal_writer_hostgroup, "NONE", kWaitSeconds) == EXIT_SUCCESS,
		"a successful topology drain rearms a refreshed terminal worker");
	return EXIT_SUCCESS;
}

int main() {
	plan(16);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// ProxySQL: reload server, variable, and hostgroup configuration during POST_PROCESSING.
	// Verify: the active FSM, cached target map, and applied pin remain intact.
	if (test_active_worker_refresh(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: deactivate the owning Aurora BGD row.
	// Verify: the worker stops and restores production routing without deleting configuration.
	if (test_active_worker_deactivation(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: refresh configuration while a worker is latched at completion.
	// Verify: the terminal state survives refresh and rearms after topology drain.
	if (test_terminal_worker_refresh(admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean Aurora BGD worker-lifecycle test data");
		return EXIT_FAILURE;
	}
	return exit_status();
}
