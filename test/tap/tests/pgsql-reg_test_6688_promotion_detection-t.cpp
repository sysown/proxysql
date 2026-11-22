/**
 * Regression coverage for #6688: the PgSQL monitor must follow a backend's role
 * change (primary <-> standby) through pgsql_replication_hostgroups, moving the
 * server between the writer and the reader hostgroup without any manual change.
 *
 * Until this test, no CI-run test exercised a role change: the pgsql17-repl
 * infra has no streaming replication, and the infras that do replicate either
 * are not run by CI or run only non-gating suites. A real pg_promote() would
 * also be destructive for the shared backend, so the role change is simulated:
 *
 *   The read_only check runs "SELECT pg_is_in_recovery()" unqualified. A
 *   role-level search_path of "<schema>, pg_catalog" makes that resolve to
 *   <schema>.pg_is_in_recovery() for the monitor user only (an explicit
 *   pg_catalog entry later in the path loses to the earlier schema). The
 *   override returns the value stored in a one-row table, so the test can flip
 *   what the monitor sees while every other user keeps the real function.
 *
 * Steps (dedicated hostgroups, the backend already used by ProxySQL):
 *   1. backend reports primary  -> server is in the writer hostgroup
 *   2. backend reports standby  -> server leaves the writer hostgroup, joins the reader one
 *   3. backend reports primary  -> server is back in the writer hostgroup (the "promotion")
 *
 * The DNS stall described in #6688 (monitor blocked inside libpq's synchronous
 * hostname resolution) is not covered here: reproducing it needs a resolver
 * that fails slowly, which the shared infra cannot provide deterministically.
 */
#include "command_line.h"
#include "libpq-fe.h"
#include "tap.h"
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

static const int WRITER_HG = 66880;
static const int READER_HG = 66881;
static const char SCHEMA[] = "proxysql_tap_6688";
// Upper bound for a role change to show up in runtime_pgsql_servers. With a 1 s
// read_only interval the change is normally applied within ~2 s.
static const int ROLE_CHANGE_TIMEOUT_S = 20;

static CommandLine cl;

// State needed to undo the test's changes, also from the atexit() handler
// (BAIL_OUT() exits): a leftover override would fake pg_is_in_recovery() for the
// monitor in every later test of the group.
static std::string g_mon_user;
static std::vector<std::pair<std::string, std::string>> g_saved_vars;
static bool g_admin_dirty = false;
static bool g_backend_dirty = false;

static PGconn *connect_to(const char *host, int port, const char *user, const char *pass,
						  const char *dbname) {
	const std::string port_s = std::to_string(port);
	const char *keys[] = {"host", "port", "user", "password", "dbname", "sslmode", "connect_timeout",
						  nullptr};
	const char *values[] = {host, port_s.c_str(), user, pass, dbname, "disable", "5", nullptr};
	PGconn *conn = PQconnectdbParams(keys, values, 0);
	if (PQstatus(conn) != CONNECTION_OK)
		BAIL_OUT("connect to %s:%d as '%s': %s", host, port, user, PQerrorMessage(conn));
	return conn;
}

static std::string query(PGconn *conn, const std::string &sql) {
	PGresult *res = PQexec(conn, sql.c_str());
	if (PQresultStatus(res) != PGRES_TUPLES_OK && PQresultStatus(res) != PGRES_COMMAND_OK)
		BAIL_OUT("query failed: '%s': %s", sql.c_str(), PQresultErrorMessage(res));
	std::string value = PQntuples(res) ? PQgetvalue(res, 0, 0) : "";
	PQclear(res);
	return value;
}

static std::string quote_ident(PGconn *conn, const std::string &s) {
	char *q = PQescapeIdentifier(conn, s.c_str(), s.size());
	std::string r = q;
	PQfreemem(q);
	return r;
}

static std::string quote_literal(PGconn *conn, const std::string &s) {
	char *q = PQescapeLiteral(conn, s.c_str(), s.size());
	std::string r = q;
	PQfreemem(q);
	return r;
}

/** Runs a statement and ignores failures; used only on the cleanup path. */
static void exec_quiet(PGconn *conn, const std::string &sql) {
	PQclear(PQexec(conn, sql.c_str()));
}

/** Closes the monitor's backend sessions so its pool reconnects and picks up the role's search_path. */
static void kill_monitor_sessions(PGconn *backend, const std::string &mon_user) {
	query(backend, "SELECT COUNT(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename=" +
					   quote_literal(backend, mon_user) + " AND application_name='ProxySQL-Monitor'");
}

/** Removes the override; safe to call when it does not exist. Never bails out. */
static void drop_override(PGconn *backend, const std::string &mon_user) {
	exec_quiet(backend, "ALTER ROLE " + quote_ident(backend, mon_user) + " RESET search_path");
	exec_quiet(backend, std::string("DROP SCHEMA IF EXISTS ") + SCHEMA + " CASCADE");
	exec_quiet(backend, "SELECT COUNT(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename=" +
							quote_literal(backend, mon_user) + " AND application_name='ProxySQL-Monitor'");
}

static void create_override(PGconn *backend, const std::string &mon_user) {
	const std::string role = quote_ident(backend, mon_user);
	query(backend, std::string("CREATE SCHEMA ") + SCHEMA);
	query(backend, std::string("CREATE TABLE ") + SCHEMA + ".state (in_recovery boolean NOT NULL)");
	query(backend, std::string("INSERT INTO ") + SCHEMA + ".state VALUES (false)");
	query(backend, std::string("CREATE FUNCTION ") + SCHEMA +
					   ".pg_is_in_recovery() RETURNS boolean LANGUAGE sql STABLE AS "
					   "'SELECT in_recovery FROM " + SCHEMA + ".state'");
	query(backend, std::string("GRANT USAGE ON SCHEMA ") + SCHEMA + " TO " + role);
	query(backend, std::string("GRANT SELECT ON ") + SCHEMA + ".state TO " + role);
	query(backend, "ALTER ROLE " + role + " SET search_path = " + SCHEMA + ", pg_catalog");
	kill_monitor_sessions(backend, mon_user);
}

/** Undoes every change the test made, on fresh connections. Idempotent; never bails out. */
static void cleanup() {
	const std::string hgs = std::to_string(WRITER_HG) + "," + std::to_string(READER_HG);
	if (g_admin_dirty) {
		const std::string port_s = std::to_string(cl.pgsql_admin_port);
		const char *keys[] = {"host", "port", "user", "password", "dbname", "sslmode", "connect_timeout",
							  nullptr};
		const char *values[] = {cl.pgsql_admin_host, port_s.c_str(), cl.admin_username,
								cl.admin_password, "admin", "disable", "5", nullptr};
		PGconn *admin = PQconnectdbParams(keys, values, 0);
		if (PQstatus(admin) == CONNECTION_OK) {
			exec_quiet(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id IN (" + hgs + ")");
			exec_quiet(admin, "DELETE FROM pgsql_replication_hostgroups WHERE writer_hostgroup=" +
								  std::to_string(WRITER_HG));
			exec_quiet(admin, "LOAD PGSQL SERVERS TO RUNTIME");
			for (const auto &v : g_saved_vars)
				exec_quiet(admin, "SET " + v.first + "='" + v.second + "'");
			exec_quiet(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
			g_admin_dirty = false;
		} else {
			diag("cleanup: admin connect failed: %s", PQerrorMessage(admin));
		}
		PQfinish(admin);
	}
	if (g_backend_dirty) {
		const std::string port_s = std::to_string(cl.pgsql_server_port);
		const char *keys[] = {"host", "port", "user", "password", "dbname", "sslmode", "connect_timeout",
							  nullptr};
		const char *values[] = {cl.pgsql_server_host, port_s.c_str(), cl.pgsql_server_username,
								cl.pgsql_server_password, "postgres", "disable", "5", nullptr};
		PGconn *backend = PQconnectdbParams(keys, values, 0);
		if (PQstatus(backend) == CONNECTION_OK) {
			drop_override(backend, g_mon_user);
			g_backend_dirty = false;
		} else {
			diag("cleanup: backend connect failed: %s", PQerrorMessage(backend));
		}
		PQfinish(backend);
	}
}

static void set_in_recovery(PGconn *backend, bool in_recovery) {
	query(backend, std::string("UPDATE ") + SCHEMA + ".state SET in_recovery=" +
					   (in_recovery ? "true" : "false"));
}

/** Hostgroups (sorted) the test server currently has in runtime, e.g. "66880" or "66881". */
static std::string runtime_hgs(PGconn *admin, const std::string &host, const std::string &port) {
	PGresult *res = PQexec(admin, ("SELECT hostgroup_id FROM runtime_pgsql_servers WHERE hostname='" +
								   host + "' AND port=" + port + " AND hostgroup_id IN (" +
								   std::to_string(WRITER_HG) + "," + std::to_string(READER_HG) +
								   ") ORDER BY hostgroup_id").c_str());
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
		BAIL_OUT("runtime_pgsql_servers query failed: %s", PQresultErrorMessage(res));
	std::string hgs;
	for (int i = 0; i < PQntuples(res); i++)
		hgs += std::string(i ? "," : "") + PQgetvalue(res, i, 0);
	PQclear(res);
	return hgs;
}

/** Waits until the server's runtime hostgroups are one of 'accepted'; 'last' gets the final value. */
static bool wait_hgs(PGconn *admin, const std::string &host, const std::string &port,
					 const std::vector<std::string> &accepted, std::string &last) {
	for (int i = 0; i < ROLE_CHANGE_TIMEOUT_S * 10; i++) {
		last = runtime_hgs(admin, host, port);
		for (const auto &a : accepted)
			if (last == a)
				return true;
		usleep(100000);
	}
	return false;
}

int main() {
	alarm(300);
	if (cl.getEnv())
		return EXIT_FAILURE;

	PGconn *admin = connect_to(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username,
							   cl.admin_password, "admin");
	PGconn *backend = connect_to(cl.pgsql_server_host, cl.pgsql_server_port,
								 cl.pgsql_server_username, cl.pgsql_server_password, "postgres");

	const std::string mon_user = query(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-monitor_username'");
	const std::string mon_pass = query(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-monitor_password'");
	if (mon_user.empty())
		BAIL_OUT("pgsql-monitor_username is empty");
	// The override goes on the monitor role; on a superuser it would also change
	// what every other session of that user sees.
	if (query(backend, "SELECT rolsuper::text FROM pg_roles WHERE rolname=" +
						   quote_literal(backend, mon_user)) != "false")
		BAIL_OUT("monitor user '%s' is missing or is a superuser; refusing to override its search_path",
				 mon_user.c_str());

	// The backend ProxySQL already reaches; the test reaches the same backend
	// through TAP_PGSQLSERVER_* (single-backend infra).
	const std::string host = query(admin,
		"SELECT hostname FROM runtime_pgsql_servers WHERE port<>0 ORDER BY hostgroup_id LIMIT 1");
	const std::string port = query(admin,
		"SELECT port FROM runtime_pgsql_servers WHERE port<>0 ORDER BY hostgroup_id LIMIT 1");
	if (host.empty())
		BAIL_OUT("no pgsql backend configured");

	const std::string hgs = std::to_string(WRITER_HG) + "," + std::to_string(READER_HG);
	if (query(admin, "SELECT COUNT(*) FROM pgsql_servers WHERE hostgroup_id IN (" + hgs + ")") != "0" ||
		query(admin, "SELECT COUNT(*) FROM pgsql_replication_hostgroups WHERE writer_hostgroup IN (" +
						 hgs + ") OR reader_hostgroup IN (" + hgs + ")") != "0")
		BAIL_OUT("hostgroups %s are already configured; refusing to overwrite them", hgs.c_str());

	plan(5);

	g_mon_user = mon_user;
	g_saved_vars = {{"pgsql-monitor_enabled", ""}, {"pgsql-monitor_read_only_interval", ""}};
	for (auto &v : g_saved_vars)
		v.second = query(admin, "SELECT variable_value FROM global_variables WHERE variable_name='" +
									v.first + "'");
	atexit(cleanup);

	// Leftovers of a run killed before its cleanup (e.g. by the alarm) would
	// make the first step meaningless.
	g_backend_dirty = true;
	drop_override(backend, mon_user);
	create_override(backend, mon_user);

	{
		PGconn *mon = connect_to(cl.pgsql_server_host, cl.pgsql_server_port, mon_user.c_str(),
								 mon_pass.c_str(), "postgres");
		const std::string before = query(mon, "SELECT pg_is_in_recovery()::text");
		PQfinish(mon);
		set_in_recovery(backend, true);
		mon = connect_to(cl.pgsql_server_host, cl.pgsql_server_port, mon_user.c_str(),
						 mon_pass.c_str(), "postgres");
		const std::string after = query(mon, "SELECT pg_is_in_recovery()::text");
		PQfinish(mon);
		set_in_recovery(backend, false);
		ok(before == "false" && after == "true",
		   "the monitor user sees the simulated pg_is_in_recovery() (got '%s' then '%s')",
		   before.c_str(), after.c_str());
	}

	g_admin_dirty = true;
	query(admin, "SET pgsql-monitor_enabled=true");
	query(admin, "SET pgsql-monitor_read_only_interval=1000");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	query(admin, "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,comment) VALUES (" +
					 std::to_string(WRITER_HG) + ",'" + host + "'," + port + ",'reg_test_6688')");
	query(admin, "INSERT INTO pgsql_replication_hostgroups (writer_hostgroup,reader_hostgroup,check_type,"
				 "comment) VALUES (" + std::to_string(WRITER_HG) + "," + std::to_string(READER_HG) +
				 ",'read_only','reg_test_6688')");
	query(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	const std::string writer = std::to_string(WRITER_HG);
	const std::string reader = std::to_string(READER_HG);
	std::string last;

	ok(wait_hgs(admin, host, port, {writer}, last),
	   "primary: %s:%s is in the writer hostgroup only (runtime hostgroups: '%s')",
	   host.c_str(), port.c_str(), last.c_str());

	// Wait for a read_only check that ran with the override in place, so the
	// next steps measure the reaction to the flip and not pool reconnection.
	const std::string log_cond = "hostname='" + host + "' AND port=" + port;
	const std::string base_ts = query(admin,
		"SELECT COALESCE(MAX(time_start_us),0) FROM monitor.pgsql_server_read_only_log WHERE " + log_cond);
	bool fresh = false;
	for (int i = 0; i < ROLE_CHANGE_TIMEOUT_S * 10 && !fresh; i++) {
		fresh = query(admin, "SELECT COUNT(*) FROM monitor.pgsql_server_read_only_log WHERE " + log_cond +
								 " AND time_start_us>" + base_ts + " AND read_only=0") != "0";
		if (!fresh)
			usleep(100000);
	}
	ok(fresh, "the monitor keeps running read_only checks on %s:%s", host.c_str(), port.c_str());

	set_in_recovery(backend, true);
	ok(wait_hgs(admin, host, port, {reader}, last),
	   "standby: %s:%s moved to the reader hostgroup and left the writer one (runtime hostgroups: '%s')",
	   host.c_str(), port.c_str(), last.c_str());

	// A promoted server is added to the writer hostgroup; it may stay in the
	// reader hostgroup as well (as with pg_promote() on a real standby).
	set_in_recovery(backend, false);
	ok(wait_hgs(admin, host, port, {writer, writer + "," + reader}, last),
	   "promoted: %s:%s is back in the writer hostgroup (runtime hostgroups: '%s')",
	   host.c_str(), port.c_str(), last.c_str());

	PQfinish(backend);
	PQfinish(admin);
	cleanup();
	return exit_status();
}
