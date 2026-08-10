/**
 * @file pgsql_max_connections_cap_violation-t.cpp
 * @brief Regression for the per-server `max_connections` cap on the PgSQL path.
 *
 * All four scenario conns connect through the proxy as cl.pgsql_username
 * ('testuser'). Conn 3's `SET bytea_output='escape'` is the case-1
 * trigger: bytea_output is in the dynamic tracked-vars set, so a free
 * conn carrying var_hash[BYTEA_OUTPUT]!=default makes
 * requires_RESETTING_CONNECTION() return true (PgSQL_Connection.cpp:2010-2042).
 * That puts the matcher at quality=1 and the competitive-pool branch
 * of evaluate_pool_state (PgSQL_HostGroups_Manager.cpp:2379-2381)
 * sets create_new_connection=true -- the exact path the fix patches.
 *
 * Connection helper follows the canonical pgsql-test pattern (see
 * pgsql-set_parameter_validation_test-t.cpp,
 * pgsql-query_cancel_session_termination_test-t.cpp,
 * pgsql-query_cache_test-t.cpp): a `PGConnPtr` smart pointer alias and
 * a `createNewConnection(ConnType, ...)` helper that maps each
 * `ConnType` to the appropriate (host, port, user, password) tuple
 * from `CommandLine cl`. We extend the enum with `BACKEND_DIRECT` for
 * the side-channel observer that bypasses proxysql and connects
 * straight to the chosen physical PG backend as the configured
 * superuser (cl.pgsql_server_*).
 *
 * Setup avoids baseline contamination via "drain-by-reinsert":
 *   1. Disable monitor; sleep `pgsql-monitor_ping_interval + 1s` so any
 *      in-flight monitor activity has fully drained.
 *   2. Find the test user's default hostgroup `hg` and pick the first
 *      server in it as the target.
 *   3. DELETE pgsql_query_rules so SELECT 1 isn't redirected to a read
 *      hostgroup.
 *   4. DELETE FROM pgsql_servers (all rows); LOAD PGSQL SERVERS TO RUNTIME.
 *      ProxySQL's commit() (lib/PgSQL_HostGroups_Manager.cpp:1362)
 *      destroys every Free conn to every removed server; backend pgsql
 *      ends those sessions when proxysql closes the sockets.
 *   5. INSERT only the target back, with status='ONLINE',
 *      max_connections=3; LOAD. Fresh PgSQL_SrvC, empty pool, only one
 *      server in the hostgroup.
 *   6. Open the BACKEND_DIRECT observer and assert that
 *      `count(*) FROM pg_stat_activity WHERE usename='<testuser>'`
 *      equals 0. The observer connects as the superuser
 *      (cl.pgsql_server_username), naturally excluded by the usename
 *      filter.
 *
 * Scenario:
 *   1. Conn 1 (BACKEND): BEGIN -- pinned, Used=1.
 *   2. Conn 2 (BACKEND): BEGIN -- pinned, Used=2.
 *   3. Conn 3 (BACKEND): BEGIN; SET bytea_output='escape';
 *      SELECT 1; COMMIT; close. The SET persists past COMMIT (PG SET
 *      is non-transactional). Backend conn returns to Free with
 *      var_hash[BYTEA_OUTPUT] non-default. Used=2, Free=1, alive=3.
 *   4. Conn 4 (BACKEND): BEGIN; SELECT 1; COMMIT. No SET. Matcher
 *      walks Free, finds conn 3's polluted conn ->
 *      requires_RESETTING_CONNECTION -> quality=1 -> case-1 +
 *      create_new in the competitive-pool branch. With Used+Free=3=max:
 *        - Pre-fix: opens new without removing the misfit -> alive=4.
 *        - Post-fix: deletes the misfit free conn first -> alive=3.
 *      The BEGIN ... COMMIT wrappers pin conn 3 / conn 4 to a single
 *      backend conn each so multiplexing doesn't split queries across
 *      backend conns and the SET lands on the conn that returns to Free.
 *
 * Verification: observer counts the same filter while conn 4 is still
 * open; assert `alive <= MAX_CONN`.
 *
 * Cleanup: close client conns and exit. We never SAVE TO DISK any
 * runtime state we modified (monitor, query rules, pgsql_servers).
 * proxysql-tester.py runs LOAD PGSQL {SERVERS,USERS,VARIABLES,QUERY RULES}
 * FROM DISK + LOAD ... TO RUNTIME before each test, which restores the
 * original on-disk state. The test never touches `pgsql_users`.
 *
 * `stats_pgsql_connection_pool` is deliberately not used at all:
 * reading it runs a side-effect cleanup loop in `SQL3_Connection_Pool`
 * that drops Free conns of non-ONLINE servers and trims overshoots,
 * masking the bug.
 */

#include <chrono>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "libpq-fe.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

using std::string;

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
	ADMIN,           // proxysql admin (PgSQL protocol port)
	BACKEND,         // proxy frontend as cl.pgsql_username
	BACKEND_DIRECT   // direct-to-PG observer (target host:port as cl.pgsql_server_*)
};

static constexpr int MAX_CONN = 3;

struct SrvRow {
	int    hg;
	string host;
	int    port;
	string status;
	int    max_connections;
};

/**
 * Canonical pgsql connection helper (see pgsql-set_parameter_validation_test-t.cpp,
 * pgsql-query_cancel_session_termination_test-t.cpp, pgsql-query_cache_test-t.cpp).
 * Extended with `BACKEND_DIRECT` for the observer that connects straight
 * to a specific physical PG backend, bypassing proxysql; for that mode
 * the caller passes `direct_host` / `direct_port`.
 */
static PGConnPtr createNewConnection(ConnType conn_type,
                                     const string& options = "",
                                     bool with_ssl = false,
                                     const char* direct_host = nullptr,
                                     int direct_port = 0)
{
	const char* host = nullptr;
	int port = 0;
	const char* username = nullptr;
	const char* password = nullptr;
	const char* label = nullptr;

	switch (conn_type) {
	case ADMIN:
		host = cl.pgsql_admin_host;
		port = cl.pgsql_admin_port;
		username = cl.admin_username;
		password = cl.admin_password;
		label = "Admin";
		break;
	case BACKEND:
		host = cl.pgsql_host;
		port = cl.pgsql_port;
		username = cl.pgsql_username;
		password = cl.pgsql_password;
		label = "Backend";
		break;
	case BACKEND_DIRECT:
		host = direct_host;
		port = direct_port;
		username = cl.pgsql_server_username;
		password = cl.pgsql_server_password;
		label = "Backend-Direct";
		break;
	}

	std::stringstream ss;
	ss << "host=" << host << " port=" << port;
	ss << " user=" << username << " password=" << password;
	ss << (with_ssl ? " sslmode=require" : " sslmode=disable");
	if (options.empty() == false) {
		ss << " options='" << options << "'";
	}

	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Connection to '%s' failed: %s", label, PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

// ----- query helpers -----

static bool exec_ok(PGconn* c, const string& q) {
	PGresult* r = PQexec(c, q.c_str());
	bool ok_status = r && (PQresultStatus(r) == PGRES_COMMAND_OK ||
	                       PQresultStatus(r) == PGRES_TUPLES_OK);
	if (!ok_status && r)
		diag("query failed: %s -- %s", q.c_str(), PQresultErrorMessage(r));
	if (r) PQclear(r);
	return ok_status;
}

static int query_one_int(PGconn* c, const string& q) {
	PGresult* r = PQexec(c, q.c_str());
	int v = -1;
	if (r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1)
		v = atoi(PQgetvalue(r, 0, 0));
	if (r) PQclear(r);
	return v;
}

static string query_one_str(PGconn* c, const string& q) {
	PGresult* r = PQexec(c, q.c_str());
	string v;
	if (r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1)
		v = PQgetvalue(r, 0, 0);
	if (r) PQclear(r);
	return v;
}

// ----- targeting helpers -----

static std::vector<SrvRow> load_servers(PGconn* admin, const string& where) {
	std::vector<SrvRow> rows;
	string q = "SELECT hostgroup_id, hostname, port, status, max_connections "
	           "FROM pgsql_servers " + where + " ORDER BY hostgroup_id, hostname, port";
	PGresult* r = PQexec(admin, q.c_str());
	if (r && PQresultStatus(r) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(r); i++) {
			SrvRow s;
			s.hg              = atoi(PQgetvalue(r, i, 0));
			s.host            = PQgetvalue(r, i, 1);
			s.port            = atoi(PQgetvalue(r, i, 2));
			s.status          = PQgetvalue(r, i, 3);
			s.max_connections = atoi(PQgetvalue(r, i, 4));
			rows.push_back(s);
		}
	}
	if (r) PQclear(r);
	return rows;
}

/**
 * Count proxy-owned backend sessions for cl.pgsql_username on the
 * target backend. The observer connects as cl.pgsql_server_username
 * ('postgres'), naturally excluded by the usename filter.
 */
static int count_test_backends(const SrvRow& target) {
	PGConnPtr c = createNewConnection(BACKEND_DIRECT, "", false,
		target.host.c_str(), target.port);
	if (!c) return -1;
	return query_one_int(c.get(),
		string("SELECT count(*) FROM pg_stat_activity "
			"WHERE usename='") + cl.pgsql_username + "'");
}

// ----- main -----

int main() {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	plan(6);

	PGConnPtr admin = createNewConnection(ADMIN);
	ok(admin != nullptr, "connected to ProxySQL admin (port %d)",
		cl.pgsql_admin_port);
	if (!admin) return exit_status();

	// Disable monitor for the duration of the test. We never SAVE TO DISK
	// here; proxysql-tester.py reloads pgsql-monitor_enabled from disk
	// before the next test runs, which restores the original value.
	exec_ok(admin.get(), "SET pgsql-monitor_enabled='false'");
	exec_ok(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");

	// Wait for any in-flight monitor activity to drain. After LOAD PGSQL
	// VARIABLES the monitor thread observes the disabled flag on its
	// next loop iteration; the longest sleep between iterations is
	// pgsql-monitor_ping_interval. Sleeping that interval + 1s grace
	// guarantees no thread that was already mid-iteration can still
	// fire a backend ping after this point. Pings use the monitor user
	// (filtered out by count_test_backends) so this is defensive against
	// any misconfig where monitor_username overlaps the test user.
	{
		const string ping_str = query_one_str(admin.get(),
			"SELECT variable_value FROM global_variables "
			"WHERE variable_name='pgsql-monitor_ping_interval'");
		const int ping_ms = ping_str.empty() ? 10000 : std::stoi(ping_str);
		diag("quiescing monitor: sleep %d ms (pgsql-monitor_ping_interval + 1s grace)",
			ping_ms + 1000);
		std::this_thread::sleep_for(std::chrono::milliseconds(ping_ms + 1000));
	}

	// Discover the test user's default hostgroup.
	int hg = query_one_int(admin.get(),
		string("SELECT default_hostgroup FROM pgsql_users WHERE username='") +
		cl.pgsql_username + "' LIMIT 1");
	ok(hg >= 0, "discovered hostgroup for '%s' (hg=%d)", cl.pgsql_username, hg);
	if (hg < 0) return exit_status();

	// Pick the target = first server in the user's default hostgroup.
	std::vector<SrvRow> hg_servers = load_servers(admin.get(),
		"WHERE hostgroup_id=" + std::to_string(hg));
	ok(!hg_servers.empty(),
		"hostgroup %d has at least one server (got %zu)",
		hg, hg_servers.size());
	if (hg_servers.empty()) return exit_status();

	const SrvRow target = hg_servers.front();
	diag("targeting backend %s:%d in hg=%d", target.host.c_str(), target.port, hg);

	// DELETE all query rules so our SELECT 1 isn't redirected to a read
	// hostgroup. We never SAVE TO DISK here; proxysql-tester.py reloads
	// pgsql_query_rules from disk before the next test, which puts the
	// original ruleset back.
	exec_ok(admin.get(), "DELETE FROM pgsql_query_rules");
	exec_ok(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");

	// Drain-by-reinsert: DELETE every pgsql_servers row, then LOAD.
	// ProxySQL's commit() treats every row as removed and destroys every
	// Free conn to those servers, ending the backend sessions cleanly.
	exec_ok(admin.get(), "DELETE FROM pgsql_servers");
	exec_ok(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME");

	// Re-INSERT only the target with the test cap. Fresh empty pool.
	exec_ok(admin.get(),
		"INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, "
		"max_connections) VALUES (" + std::to_string(hg) + ", '" +
		target.host + "', " + std::to_string(target.port) +
		", 'ONLINE', " + std::to_string(MAX_CONN) + ")");
	exec_ok(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME");

	std::this_thread::sleep_for(std::chrono::milliseconds(300));

	// Baseline-sanity: the drain ended every proxysql-managed session for
	// this user on the target. Anything still present is foreign and
	// would invalidate the absolute invariant below.
	int baseline = count_test_backends(target);
	ok(baseline == 0,
		"baseline after drain on %s:%d for user '%s' = %d (expect 0)",
		target.host.c_str(), target.port, cl.pgsql_username, baseline);

	// Conn 1: BEGIN -- pins the conn (Used=1).
	PGConnPtr c1 = createNewConnection(BACKEND);
	bool c1_ok = c1 && exec_ok(c1.get(), "BEGIN");
	// Conn 2: BEGIN -- pins the conn (Used=2).
	PGConnPtr c2 = createNewConnection(BACKEND);
	bool c2_ok = c2 && exec_ok(c2.get(), "BEGIN");
	ok(c1_ok && c2_ok, "two BEGIN-locked conns established as '%s'",
		cl.pgsql_username);

	// Conn 3: BEGIN; SET bytea_output='escape'; SELECT 1; COMMIT; close.
	// The transaction wrapper pins to one backend conn so the SET lands
	// on the conn that returns to Free. PG SET is non-transactional and
	// persists past COMMIT.
	{
		PGConnPtr c3 = createNewConnection(BACKEND);
		if (c3) {
			exec_ok(c3.get(), "BEGIN");
			exec_ok(c3.get(), "SET bytea_output='escape'");
			exec_ok(c3.get(), "SELECT 1");
			exec_ok(c3.get(), "COMMIT");
		}
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(300));

	// Conn 4: BEGIN; SELECT 1; COMMIT -- no SET. Matcher finds polluted
	// Free conn, quality=1, case-1 + create_new. BEGIN pins to write hg.
	int after_victim = -1;
	{
		PGConnPtr c4 = createNewConnection(BACKEND);
		if (c4) {
			exec_ok(c4.get(), "BEGIN");
			exec_ok(c4.get(), "SELECT 1");
			std::this_thread::sleep_for(std::chrono::milliseconds(300));
			after_victim = count_test_backends(target);
			exec_ok(c4.get(), "COMMIT");
		}
	}

	diag("after victim: alive=%d baseline=%d (max=%d)",
		after_victim, baseline, MAX_CONN);

	// With baseline=0 by construction, alive_after_victim is exactly the
	// count of OUR conns still alive on the backend. Patched: 3 (case-1
	// swap evicted conn 3's backend session). Pre-fix: 4 (conn 3 leaked
	// into Free, backend session still alive).
	ok(after_victim > 0 && after_victim <= MAX_CONN,
		"INVARIANT: backend session count <= max_connections "
		"(alive=%d, max=%d). Pre-fix this FAILS at alive=max+1: case 1 + "
		"create_new leaks the misfit Free conn while adding a new one to Used.",
		after_victim, MAX_CONN);

	c1.reset();
	c2.reset();
	return exit_status();
}
