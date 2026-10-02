/**
 * Regression #6389: disabling PostgreSQL monitoring must not permanently stop
 * its scheduler. Exercise real connect/ping checks across repeated toggles.
 * Also run this test against a ProxySQL instance started with monitoring off.
 */
#include "command_line.h"
#include "libpq-fe.h"
#include "pgsql_mock_backend.h"
#include "tap.h"
#include <chrono>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

using Clock = std::chrono::steady_clock;

static std::string query(PGconn *conn, const std::string &sql) {
	PGresult *res = PQexec(conn, sql.c_str());
	if (PQresultStatus(res) != PGRES_TUPLES_OK && PQresultStatus(res) != PGRES_COMMAND_OK)
		BAIL_OUT("admin query failed: %s", PQresultErrorMessage(res));
	std::string value = PQntuples(res) ? PQgetvalue(res, 0, 0) : "";
	PQclear(res);
	return value;
}

static long counter(PGconn *admin, const char *name) {
	return std::stol(
		query(admin, "SELECT Variable_Value FROM stats_pgsql_global WHERE Variable_Name='" +
						 std::string(name) + "'"));
}

static bool wait_active(PGconn *admin) {
	const long connect = counter(admin, "PgSQL_Monitor_connect_check_OK");
	const long ping = counter(admin, "PgSQL_Monitor_ping_check_OK");
	const auto deadline = Clock::now() + std::chrono::seconds(10);
	do {
		if (counter(admin, "PgSQL_Monitor_connect_check_OK") > connect &&
			counter(admin, "PgSQL_Monitor_ping_check_OK") > ping)
			return true;
		usleep(100000);
	} while (Clock::now() < deadline);
	return false;
}

static long total_checks(PGconn *admin) {
	return std::stol(query(admin,
						   "SELECT SUM(CAST(Variable_Value AS INTEGER)) FROM stats_pgsql_global "
						   "WHERE Variable_Name IN "
						   "('PgSQL_Monitor_connect_check_OK','PgSQL_Monitor_connect_check_ERR',"
						   "'PgSQL_Monitor_ping_check_OK','PgSQL_Monitor_ping_check_ERR')"));
}

static bool wait_stopped(PGconn *admin) {
	// Allow in-flight work to finish, then require a sustained quiet period
	// longer than the configured intervals. Count failures as work too.
	long previous = total_checks(admin);
	auto quiet_since = Clock::now();
	const auto deadline = quiet_since + std::chrono::seconds(10);
	do {
		usleep(100000);
		const long current = total_checks(admin);
		if (current != previous) {
			previous = current;
			quiet_since = Clock::now();
		}
		if (Clock::now() - quiet_since >= std::chrono::seconds(2))
			return true;
	} while (Clock::now() < deadline);
	return false;
}

int main() {
	alarm(120);
	CommandLine cl;
	if (cl.getEnv())
		return EXIT_FAILURE;
	const std::string port = std::to_string(cl.pgsql_admin_port);
	const char *keys[] = {"host", "port", "user", "password", "sslmode", "connect_timeout",
						  nullptr};
	const char *values[] = {cl.pgsql_admin_host,
							port.c_str(),
							cl.admin_username,
							cl.admin_password,
							"disable",
							"5",
							nullptr};
	PGconn *admin = PQconnectdbParams(keys, values, 0);
	if (PQstatus(admin) != CONNECTION_OK)
		BAIL_OUT("admin connect: %s", PQerrorMessage(admin));
	plan(10);

	const std::vector<std::string> names = {"monitor_enabled", "monitor_connect_interval",
											"monitor_ping_interval", "monitor_threads"};
	std::vector<std::pair<std::string, std::string>> saved;
	for (const auto &name : names)
		saved.emplace_back(name, query(admin, "SELECT variable_value FROM global_variables WHERE "
											  "variable_name='pgsql-" +
												  name + "'"));
	query(admin, "SET pgsql-monitor_connect_interval=100");
	query(admin, "SET pgsql-monitor_ping_interval=100");
	query(admin, "SET pgsql-monitor_enabled=true");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	ok(wait_active(admin), "connect and ping checks run after enabling "
						   "monitoring (including startup disabled)");

	for (int cycle = 1; cycle <= 3; ++cycle) {
		query(admin, "SET pgsql-monitor_enabled=false");
		query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
		ok(wait_stopped(admin), "cycle %d: monitoring becomes idle while disabled", cycle);
		// Changing configuration while disabled must be picked up on resume.
		query(admin, "SET pgsql-monitor_connect_interval=" + std::to_string(100 * cycle));
		query(admin, "SET pgsql-monitor_ping_interval=" + std::to_string(100 * cycle));
		query(admin, "SET pgsql-monitor_enabled=true");
		query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
		ok(wait_active(admin), "cycle %d: successful connect and ping checks resume", cycle);
	}

	// A long schedule must not delay observing configuration/disable changes.
	query(admin, "SET pgsql-monitor_connect_interval=60000");
	query(admin, "SET pgsql-monitor_ping_interval=60000");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	usleep(1000000);

	// Hold one worker in PQgetResult: EmptyQueryResponse without ReadyForQuery
	// must not prevent disable/re-enable from completing.
	query(admin, "SET pgsql-monitor_enabled=false");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	if (!wait_stopped(admin))
		BAIL_OUT("monitor did not stop before stalled-backend scenario");
	PgSQL_Mock_Backend mock;
	if (!mock.start())
		BAIL_OUT("mock could not listen");
	auto script = pgmb_script_accept_trust();
	script.push_back(step_expect_query());
	script.push_back(step_send(std::string("I\0\0\0\4", 5)));
	script.push_back(step_expect_message()); // Wait until monitor closes the socket.
	mock.set_script(script);
	const std::string host = pgmb_local_ip_towards(cl.pgsql_host, cl.pgsql_port);
	if (host.empty())
		BAIL_OUT("cannot discover mock address");
	query(admin, "INSERT INTO pgsql_servers(hostgroup_id,hostname,port) VALUES(6389,'" + host +
					 "'," + std::to_string(mock.port()) + ")");
	query(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	query(admin, "SET pgsql-monitor_connect_interval=100");
	query(admin, "SET pgsql-monitor_ping_interval=100");
	query(admin, "SET pgsql-monitor_threads=1");
	query(admin, "SET pgsql-monitor_enabled=true");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	const auto stalled_deadline = Clock::now() + std::chrono::seconds(10);
	while (mock.queries_observed() == 0 && Clock::now() < stalled_deadline)
		usleep(100000);
	ok(mock.queries_observed() > 0, "monitor sent a ping to the backend withholding ReadyForQuery");
	query(admin, "SET pgsql-monitor_enabled=false");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	// Keep disabled long enough for the scheduler to observe the transition.
	wait_stopped(admin);
	query(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=6389");
	query(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	query(admin, "SET pgsql-monitor_enabled=true");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	ok(wait_active(admin), "monitor resumes even when a previous worker was stalled in libpq");
	mock.stop();

	// Restore the original worker count through a new enabled period too.
	query(admin, "SET pgsql-monitor_enabled=false");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	if (!wait_stopped(admin))
		BAIL_OUT("monitor did not stop before restoration");
	query(admin, "SET pgsql-monitor_threads='" + saved.back().second + "'");
	// Check restoration before putting the original (possibly long) intervals
	// back.
	query(admin, "SET pgsql-monitor_enabled='" + saved.front().second + "'");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	const bool enabled = saved.front().second == "true";
	ok(enabled ? wait_active(admin) : wait_stopped(admin), "original monitor state is restored");
	for (const auto &setting : saved)
		query(admin, "SET pgsql-" + setting.first + "='" + setting.second + "'");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	PQfinish(admin);
	return exit_status();
}
