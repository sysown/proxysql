/**
 * @file test_aurora_bgd_concurrent_isolation-t.cpp
 * @brief Isolation across three concurrent Aurora BGD workers.
 *
 * Steps:
 *
 * 1. Configure three deployments with independent workers and route hostgroups.
 * 2. Enter POST_PROCESSING on all workers and verify each owns its target pin.
 * 3. Deactivate one worker without changing the other two.
 * 4. Complete and remove different workers without leaking lifecycle effects.
 */

#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>

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
	Aurora_BGD_Test_Deployment deployment_a { aurora_bgd_deployment_a() };
	int writer_hostgroup_a { 1640 };
	int reader_hostgroup_a { 1641 };
	int green_writer_hostgroup_a { 1642 };
	int green_reader_hostgroup_a { 1643 };
	int route_hostgroup_a { 1644 };
	int post_completion_route_hostgroup_a { 1645 };
	Aurora_BGD_Test_Deployment deployment_b { aurora_bgd_deployment_b_writer_only() };
	int writer_hostgroup_b { 1650 };
	int reader_hostgroup_b { 1651 };
	int route_hostgroup_b { 1654 };
	Aurora_BGD_Test_Deployment deployment_c { aurora_bgd_deployment_c_writer_only() };
	int writer_hostgroup_c { 1660 };
	int reader_hostgroup_c { 1661 };
	int route_hostgroup_c { 1664 };
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

int cleanup(MYSQL* admin, BGD_Simulator& sim) {
	int admin_rc = aurora_bgd_admin_cleanup(admin);
	int user_rc = aurora_bgd_execute_all(admin, {
		"DELETE FROM mysql_users WHERE username='testuser'",
		"LOAD MYSQL USERS TO RUNTIME",
	});
	int simulator_rc = sim.cleanup();
	mysql_close(admin);
	return admin_rc == EXIT_SUCCESS && user_rc == EXIT_SUCCESS
		&& simulator_rc == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
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
			",3306,'ONLINE','Aurora BGD concurrent route')",
		"LOAD MYSQL SERVERS TO RUNTIME",
	});
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
	return route_to_backend(cl, sim, expected);
}

bool wait_for_writer_route(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim,
	Aurora_BGD_Test_Deployment& deployment, int route_hg, bool target
) {
	if (set_default_hostgroup(admin, route_hg) != EXIT_SUCCESS) {
		return false;
	}
	const Endpoint expected = target
		? deployment.target.members.front().endpoint.backend()
		: deployment.production.members.front().endpoint.backend();
	for (uint32_t elapsed_ms = 0; elapsed_ms < kWaitSeconds * 1000; elapsed_ms += 100) {
		if (route_to_backend(cl, sim, expected)) {
			return true;
		}
		usleep(100000);
	}
	return false;
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

bool wait_for_runtime_row_absent(MYSQL* admin, int writer_hg) {
	return wait_for_cond(
		admin,
		"SELECT COUNT(*)=0 FROM runtime_mysql_aws_aurora_hostgroups WHERE writer_hostgroup=" +
			to_string(writer_hg),
		kWaitSeconds) == EXIT_SUCCESS;
}

/** Configure three workers and move each independently to POST_PROCESSING. */
int test_three_workers_post_processing(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	if (aurora_bgd_publish(sim, state.deployment_a) != EXIT_SUCCESS
		|| aurora_bgd_publish(sim, state.deployment_b) != EXIT_SUCCESS
		|| aurora_bgd_publish(sim, state.deployment_c) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, state.deployment_a, state.writer_hostgroup_a,
			state.reader_hostgroup_a, state.green_writer_hostgroup_a,
			state.green_reader_hostgroup_a, false, 300) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, state.deployment_b, state.writer_hostgroup_b,
			state.reader_hostgroup_b, -1, -1, true, 300) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(
			admin, state.deployment_c, state.writer_hostgroup_c,
			state.reader_hostgroup_c, -1, -1, true, 300) != EXIT_SUCCESS
		|| add_writer_route(
			admin, state.deployment_a, state.route_hostgroup_a) != EXIT_SUCCESS
		|| add_writer_route(
			admin, state.deployment_b, state.route_hostgroup_b) != EXIT_SUCCESS
		|| add_writer_route(
			admin, state.deployment_c, state.route_hostgroup_c) != EXIT_SUCCESS) {
		diag("Error: failed to configure three concurrent deployments");
		return EXIT_FAILURE;
	}

	ok(aurora_bgd_wait_for_status(
		admin, state.writer_hostgroup_a, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup_b, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup_c, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"three writer hostgroups discover deployments independently");
	ok(publish_status(
		sim, state.deployment_a, "SWITCHOVER_IN_POST_PROCESSING") == EXIT_SUCCESS
		&& publish_status(
			sim, state.deployment_b, "SWITCHOVER_IN_POST_PROCESSING") == EXIT_SUCCESS
		&& publish_status(
			sim, state.deployment_c, "SWITCHOVER_IN_POST_PROCESSING") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup_a,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup_b,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup_c,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"three workers enter POST_PROCESSING without sharing FSM state");
	ok(route_writer(
		cl, admin, sim, state.deployment_a, state.route_hostgroup_a, true),
		"deployment A owns its target pin");
	ok(route_writer(
		cl, admin, sim, state.deployment_b, state.route_hostgroup_b, true),
		"deployment B owns its target pin");
	ok(route_writer(
		cl, admin, sim, state.deployment_c, state.route_hostgroup_c, true),
		"deployment C owns its target pin");
	return EXIT_SUCCESS;
}

/** Deactivate deployment B without changing deployments A or C. */
int test_deactivate_one_worker(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	ok(aurora_bgd_execute_all(admin, {
		"UPDATE mysql_aws_aurora_hostgroups SET active=0 WHERE writer_hostgroup=" +
			to_string(state.writer_hostgroup_b),
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) == EXIT_SUCCESS
		&& wait_for_inactive_none(admin, state.writer_hostgroup_b)
		&& aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup_a,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup_c,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"deactivating deployment B cleans only its worker state");
	ok(writer_placement(
		admin, state.writer_hostgroup_b, state.reader_hostgroup_b,
		state.deployment_b.production.members.front().endpoint.hostname, false)
		&& route_writer(
			cl, admin, sim, state.deployment_b, state.route_hostgroup_b, false),
		"deployment B teardown restores only its production routing");
	ok(route_writer(
		cl, admin, sim, state.deployment_a, state.route_hostgroup_a, true)
		&& route_writer(
			cl, admin, sim, state.deployment_c, state.route_hostgroup_c, true),
		"deployment B teardown leaves A and C pins intact");
	return EXIT_SUCCESS;
}

/** Complete deployment A and remove deployment C without cross-worker effects. */
int test_complete_and_remove_independent_workers(
	CommandLine& cl, MYSQL* admin, BGD_Simulator& sim, TestState& state)
{
	ok(sim.topology_update(
		aurora_bgd_topology_backends(state.deployment_a),
		aurora_bgd_completed_topology(state.deployment_a)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup_a,
			"SWITCHOVER_COMPLETED", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, state.writer_hostgroup_c,
			"SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"completing deployment A leaves deployment C active");
	ok(add_writer_route(
		admin, state.deployment_a, state.post_completion_route_hostgroup_a)
		== EXIT_SUCCESS
		&& route_writer(
			cl, admin, sim, state.deployment_a,
			state.post_completion_route_hostgroup_a, false)
		&& route_writer(
			cl, admin, sim, state.deployment_c, state.route_hostgroup_c, true),
		"deployment A cleanup removes only its pin");
	ok(aurora_bgd_execute_all(admin, {
		"DELETE FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=" +
			to_string(state.writer_hostgroup_c),
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) == EXIT_SUCCESS
		&& wait_for_runtime_row_absent(admin, state.writer_hostgroup_c)
		&& writer_placement(
			admin, state.writer_hostgroup_c, state.reader_hostgroup_c,
			state.deployment_c.production.members.front().endpoint.hostname, false)
		&& wait_for_writer_route(
			cl, admin, sim, state.deployment_c, state.route_hostgroup_c, false),
		"removing deployment C safely restores its production routing");
	ok(aurora_bgd_wait_for_status(
		admin, state.writer_hostgroup_a,
		"SWITCHOVER_COMPLETED", kWaitSeconds) == EXIT_SUCCESS
		&& route_writer(
			cl, admin, sim, state.deployment_a,
			state.post_completion_route_hostgroup_a, false),
		"deployment C removal leaves deployment A terminal state unchanged");
	return EXIT_SUCCESS;
}

int main() {
	plan(12);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};

	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	TestState state {};

	// Simulator: publish three independent deployments and POST_PROCESSING states.
	// Verify: each worker owns only its target pin and FSM state.
	if (test_three_workers_post_processing(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// ProxySQL: deactivate deployment B.
	// Verify: only deployment B returns to production routing.
	if (test_deactivate_one_worker(cl, admin, sim, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator and ProxySQL: complete A and remove C.
	// Verify: their cleanup effects remain isolated from each other.
	if (test_complete_and_remove_independent_workers(cl, admin, sim, state)
		!= EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean Aurora BGD concurrent-isolation test data");
		return EXIT_FAILURE;
	}
	return exit_status();
}
