/**
 * @file test_aurora_bgd_lifecycle-t.cpp
 * @brief Aurora BGD reload, worker removal, and concurrent-cluster behavior.
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

int main() {
	plan(28);
	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator sim {};
	if (setup(cl, admin, sim) != EXIT_SUCCESS) {
		return exit_status();
	}

	Aurora_BGD_Test_Deployment reload = aurora_bgd_deployment_a();
	if (aurora_bgd_publish(sim, reload) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(admin, reload, 1620, 1621, 1622, 1623, false, 300)
			!= EXIT_SUCCESS
		|| add_writer_route(admin, reload, 1624) != EXIT_SUCCESS) {
		diag("Error: failed to configure the active reload scenario");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(aurora_bgd_wait_for_status(admin, 1620, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"reload scenario starts from AVAILABLE");
	ok(publish_status(sim, reload, "SWITCHOVER_IN_POST_PROCESSING") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, 1620, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS
		&& route_writer(cl, admin, sim, reload, 1624, true),
		"active reload scenario pins writer traffic to the target");
	ok(aurora_bgd_execute_all(admin, {"LOAD MYSQL SERVERS TO RUNTIME"}) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, 1620, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"an unrelated server reload preserves active FSM status");
	ok(route_writer(cl, admin, sim, reload, 1624, true),
		"an unrelated server reload preserves the applied traffic pin");
	ok(aurora_bgd_execute_all(admin, {
		"SET mysql-aws_blue_green_deployment_auto_discovery='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	}) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, 1620, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"disabling auto-discovery does not abort an admitted deployment");
	ok(route_writer(cl, admin, sim, reload, 1624, true),
		"a variable refresh preserves cached membership and target routing");
	ok(aurora_bgd_execute_all(admin, {
		"UPDATE mysql_aws_aurora_hostgroups SET green_writer_hostgroup=1626,"
			"green_reader_hostgroup=1627 WHERE writer_hostgroup=1620",
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) == EXIT_SUCCESS
		&& wait_for_cond(
			admin,
			"SELECT COUNT(*)=1 FROM runtime_mysql_aws_aurora_hostgroups "
			"WHERE writer_hostgroup=1620 AND green_writer_hostgroup=1626 "
			"AND green_reader_hostgroup=1627 "
			"AND bgd_status='SWITCHOVER_IN_POST_PROCESSING'",
			kWaitSeconds) == EXIT_SUCCESS,
		"green hostgroup changes refresh staging references without resetting the FSM");
	ok(route_writer(cl, admin, sim, reload, 1624, true),
		"green hostgroup refresh preserves applied pins and cached target IPs");
	ok(aurora_bgd_execute_all(admin, {
		"UPDATE mysql_aws_aurora_hostgroups SET active=0 WHERE writer_hostgroup=1620",
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) == EXIT_SUCCESS && wait_for_inactive_none(admin, 1620),
		"deactivating the owning row stops the worker after publishing NONE");
	ok(writer_placement(
		admin, 1620, 1621, reload.production.members.front().endpoint.hostname, false),
		"worker teardown restores canonical writer placement");
	ok(route_writer(cl, admin, sim, reload, 1624, false),
		"worker teardown removes the applied traffic pin");
	ok(wait_for_cond(
		admin,
		"SELECT ((SELECT COUNT(*) FROM mysql_aws_aurora_hostgroups "
		"WHERE writer_hostgroup=1620 AND active=0)=1) AND "
		"((SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostname=" +
			aurora_bgd_sql_quote(reload.production.members.front().endpoint.hostname) + ")>=1)",
		kWaitSeconds) == EXIT_SUCCESS,
		"teardown preserves user configuration and server rows");

	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before terminal reload scenario");
		cleanup(admin, sim);
		return exit_status();
	}
	Aurora_BGD_Test_Deployment terminal = aurora_bgd_deployment_b_writer_only();
	if (aurora_bgd_publish(sim, terminal) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(admin, terminal, 1630, 1631, -1, -1, true, 300)
			!= EXIT_SUCCESS) {
		diag("Error: failed to configure the terminal reload scenario");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(aurora_bgd_wait_for_status(admin, 1630, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"terminal reload scenario starts from AVAILABLE");
	ok(sim.topology_update(
		aurora_bgd_topology_backends(terminal), aurora_bgd_completed_topology(terminal))
			== EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, 1630, "SWITCHOVER_COMPLETED", kWaitSeconds) == EXIT_SUCCESS,
		"direct completion enters the terminal latch");
	ok(aurora_bgd_execute_all(admin, {
		"UPDATE mysql_aws_aurora_hostgroups SET green_writer_hostgroup=1632,"
			"green_reader_hostgroup=1633 WHERE writer_hostgroup=1630",
		"LOAD MYSQL SERVERS TO RUNTIME",
		"SET mysql-aws_blue_green_deployment_auto_discovery='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	}) == EXIT_SUCCESS
		&& wait_for_cond(
			admin,
			"SELECT COUNT(*)=1 FROM runtime_mysql_aws_aurora_hostgroups "
			"WHERE writer_hostgroup=1630 AND green_writer_hostgroup=1632 "
			"AND green_reader_hostgroup=1633 AND bgd_status='SWITCHOVER_COMPLETED'",
			kWaitSeconds) == EXIT_SUCCESS,
		"configuration and variable refresh preserve the terminal latch");
	ok(sim.topology_delete(aurora_bgd_topology_backends(terminal)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(admin, 1630, "NONE", kWaitSeconds) == EXIT_SUCCESS,
		"a successful topology drain rearms a refreshed terminal worker");

	if (reset_scenario(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to reset before concurrent scenario");
		cleanup(admin, sim);
		return exit_status();
	}
	Aurora_BGD_Test_Deployment concurrent_a = aurora_bgd_deployment_a();
	Aurora_BGD_Test_Deployment concurrent_b = aurora_bgd_deployment_b_writer_only();
	Aurora_BGD_Test_Deployment concurrent_c = aurora_bgd_deployment_c_writer_only();
	if (aurora_bgd_publish(sim, concurrent_a) != EXIT_SUCCESS
		|| aurora_bgd_publish(sim, concurrent_b) != EXIT_SUCCESS
		|| aurora_bgd_publish(sim, concurrent_c) != EXIT_SUCCESS
		|| aurora_bgd_admin_setup(admin, concurrent_a, 1640, 1641, 1642, 1643, false, 300)
			!= EXIT_SUCCESS
		|| aurora_bgd_admin_setup(admin, concurrent_b, 1650, 1651, -1, -1, true, 300)
			!= EXIT_SUCCESS
		|| aurora_bgd_admin_setup(admin, concurrent_c, 1660, 1661, -1, -1, true, 300)
			!= EXIT_SUCCESS
		|| add_writer_route(admin, concurrent_a, 1644) != EXIT_SUCCESS
		|| add_writer_route(admin, concurrent_b, 1654) != EXIT_SUCCESS
		|| add_writer_route(admin, concurrent_c, 1664) != EXIT_SUCCESS) {
		diag("Error: failed to configure three concurrent deployments");
		cleanup(admin, sim);
		return exit_status();
	}
	ok(aurora_bgd_wait_for_status(admin, 1640, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(admin, 1650, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(admin, 1660, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"three writer hostgroups discover deployments independently");
	ok(publish_status(sim, concurrent_a, "SWITCHOVER_IN_POST_PROCESSING") == EXIT_SUCCESS
		&& publish_status(sim, concurrent_b, "SWITCHOVER_IN_POST_PROCESSING") == EXIT_SUCCESS
		&& publish_status(sim, concurrent_c, "SWITCHOVER_IN_POST_PROCESSING") == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, 1640, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, 1650, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, 1660, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"three workers enter POST_PROCESSING without sharing FSM state");
	ok(route_writer(cl, admin, sim, concurrent_a, 1644, true),
		"deployment A owns its target pin");
	ok(route_writer(cl, admin, sim, concurrent_b, 1654, true),
		"deployment B owns its target pin");
	ok(route_writer(cl, admin, sim, concurrent_c, 1664, true),
		"deployment C owns its target pin");
	ok(aurora_bgd_execute_all(admin, {
		"UPDATE mysql_aws_aurora_hostgroups SET active=0 WHERE writer_hostgroup=1650",
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) == EXIT_SUCCESS
		&& wait_for_inactive_none(admin, 1650)
		&& aurora_bgd_wait_for_status(
			admin, 1640, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, 1660, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"deactivating deployment B cleans only its worker state");
	ok(writer_placement(
		admin, 1650, 1651, concurrent_b.production.members.front().endpoint.hostname, false)
		&& route_writer(cl, admin, sim, concurrent_b, 1654, false),
		"deployment B teardown restores only its production routing");
	ok(route_writer(cl, admin, sim, concurrent_a, 1644, true)
		&& route_writer(cl, admin, sim, concurrent_c, 1664, true),
		"deployment B teardown leaves A and C pins intact");
	ok(sim.topology_update(
		aurora_bgd_topology_backends(concurrent_a),
		aurora_bgd_completed_topology(concurrent_a)) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, 1640, "SWITCHOVER_COMPLETED", kWaitSeconds) == EXIT_SUCCESS
		&& aurora_bgd_wait_for_status(
			admin, 1660, "SWITCHOVER_IN_POST_PROCESSING", kWaitSeconds) == EXIT_SUCCESS,
		"completing deployment A leaves deployment C active");
	ok(add_writer_route(admin, concurrent_a, 1645) == EXIT_SUCCESS
		&& route_writer(cl, admin, sim, concurrent_a, 1645, false)
		&& route_writer(cl, admin, sim, concurrent_c, 1664, true),
		"deployment A cleanup removes only its pin");
	ok(aurora_bgd_execute_all(admin, {
		"DELETE FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=1660",
		"LOAD MYSQL SERVERS TO RUNTIME",
	}) == EXIT_SUCCESS
		&& wait_for_runtime_row_absent(admin, 1660)
		&& writer_placement(
			admin, 1660, 1661,
			concurrent_c.production.members.front().endpoint.hostname, false)
		&& wait_for_writer_route(cl, admin, sim, concurrent_c, 1664, false),
		"removing deployment C safely restores its production routing");
	ok(aurora_bgd_wait_for_status(
		admin, 1640, "SWITCHOVER_COMPLETED", kWaitSeconds) == EXIT_SUCCESS
		&& route_writer(cl, admin, sim, concurrent_a, 1645, false),
		"deployment C removal leaves deployment A terminal state unchanged");

	if (cleanup(admin, sim) != EXIT_SUCCESS) {
		diag("Error: failed to clean Aurora BGD lifecycle test data");
		return EXIT_FAILURE;
	}
	return exit_status();
}
