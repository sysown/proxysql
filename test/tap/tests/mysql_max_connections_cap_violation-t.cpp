/**
 * @file mysql_max_connections_cap_violation-t.cpp
 * @brief Regression for the per-server `max_connections` cap on the MySQL path.
 *
 *   - conns 1-3: cl.username  ('testuser', frontend=1 in mysql_users)
 *   - conn 4   : cl.root_username ('root',  frontend=1 in mysql_users) -- the
 *                user mismatch with conns 1-3 is what fires the matcher's
 *                requires_CHANGE_USER -> quality 1 -> case-1 + create_new path
 *                that the cap-violation fix patches.
 *
 * Setup avoids baseline contamination via "drain-by-reinsert":
 *   1. Disable monitor; sleep `mysql-monitor_ping_interval + 1s` so any
 *      in-flight monitor activity has fully drained.
 *   2. Find the test user's default hostgroup `hg` and pick the first
 *      server in it as the target.
 *   3. DELETE mysql_query_rules so SELECT 1 isn't redirected to a read
 *      hostgroup.
 *   4. DELETE FROM mysql_servers (all rows); LOAD MYSQL SERVERS TO RUNTIME.
 *      ProxySQL's commit() (lib/MySQL_HostGroups_Manager.cpp -- mirror
 *      of the pgsql commit path at PgSQL_HostGroups_Manager.cpp:1362)
 *      destroys every Free conn to every removed server; backend mysqld
 *      ends those sessions when proxysql closes the sockets.
 *   5. INSERT only the target back, with status='ONLINE',
 *      max_connections=3; LOAD. Fresh MySQL_SrvC, empty pool, only one
 *      server in the hostgroup.
 *   6. Open the direct-to-backend observer (cl.mysql_*) and assert that
 *        count(*) FROM information_schema.processlist
 *          WHERE user IN ('<testuser>','root') AND id != CONNECTION_ID()
 *      equals 0. The `id != CONNECTION_ID()` filter excludes the
 *      observer's own session (the observer connects as 'root' direct
 *      to the backend; `CONNECTION_ID()` direct-to-backend is NOT
 *      intercepted by proxysql -- the interceptor at
 *      lib/MySQL_Session.cpp:7266 only fires for the proxy frontend).
 *
 * Scenario:
 *   1. Conn 1 (cl.username) BEGIN -- pinned, Used=1.
 *   2. Conn 2 (cl.username) BEGIN -- pinned, Used=2.
 *   3. Conn 3 (cl.username) SELECT 1, close -- backend conn returns to
 *      Free, tagged user=cl.username. Used=2, Free=1, alive=3.
 *   4. Conn 4 (cl.root_username) BEGIN; SELECT 1; ROLLBACK; close --
 *      different user vs the lone Free conn -> requires_CHANGE_USER true
 *      -> quality 1 -> case-1 + create_new. With Used+Free=3=max:
 *        - Pre-fix: opens new without removing the misfit -> alive=4.
 *        - Post-fix: deletes the misfit free conn, then opens new ->
 *          alive=3.
 *      BEGIN ... ROLLBACK pins conn 4 to the write hostgroup so a stray
 *      query rule (if any survived the DELETE) can't redirect SELECT 1.
 *
 * Verification: observer counts the same filter while conn 4 is still
 * open; assert `alive <= MAX_CONN`.
 *
 * Cleanup: close client conns and exit. We never SAVE TO DISK any
 * runtime state we modified (monitor, query rules, mysql_servers).
 * proxysql-tester.py runs LOAD MYSQL {SERVERS,USERS,VARIABLES,QUERY RULES}
 * FROM DISK + LOAD ... TO RUNTIME before each test, which restores the
 * original on-disk state. The test never touches `mysql_users`.
 *
 * `stats_mysql_connection_pool` is deliberately not used at all:
 * reading it runs a side-effect cleanup loop in `SQL3_Connection_Pool`
 * that trims overshoots and would mask the bug.
 */

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

using std::string;

CommandLine cl;

static constexpr int MAX_CONN = 3;

struct SrvRow {
	int    hg;
	string host;
	int    port;
	string status;
	int    max_connections;
};

// ----- libmysql helpers -----

static MYSQL* open_conn(const char* host, int port,
                        const char* user, const char* pass,
                        const char* label)
{
	MYSQL* m = mysql_init(NULL);
	if (!m) return nullptr;
	if (!mysql_real_connect(m, host, user, pass, NULL, port, NULL, 0)) {
		diag("Connection to %s (%s:%d user=%s) failed: %s",
		     label, host, port, user, mysql_error(m));
		mysql_close(m);
		return nullptr;
	}
	return m;
}

static bool exec_ok(MYSQL* m, const string& q) {
	if (mysql_query(m, q.c_str()) != 0) {
		diag("query failed: %s -- %s", q.c_str(), mysql_error(m));
		return false;
	}
	while (MYSQL_RES* r = mysql_store_result(m)) mysql_free_result(r);
	return true;
}

static int query_one_int(MYSQL* m, const string& q) {
	if (mysql_query(m, q.c_str()) != 0) return -1;
	MYSQL_RES* r = mysql_store_result(m);
	if (!r) return -1;
	int v = -1;
	if (auto row = mysql_fetch_row(r)) v = atoi(row[0]);
	mysql_free_result(r);
	return v;
}

static string query_one_str(MYSQL* m, const string& q) {
	if (mysql_query(m, q.c_str()) != 0) return "";
	MYSQL_RES* r = mysql_store_result(m);
	if (!r) return "";
	string v;
	if (auto row = mysql_fetch_row(r)) v = row[0] ? row[0] : "";
	mysql_free_result(r);
	return v;
}

// ----- targeting helpers -----

static std::vector<SrvRow> load_servers(MYSQL* admin, const string& where) {
	std::vector<SrvRow> rows;
	string q = "SELECT hostgroup_id, hostname, port, status, max_connections "
	           "FROM mysql_servers " + where + " ORDER BY hostgroup_id, hostname, port";
	if (mysql_query(admin, q.c_str()) != 0) return rows;
	MYSQL_RES* r = mysql_store_result(admin);
	if (!r) return rows;
	while (MYSQL_ROW row = mysql_fetch_row(r)) {
		SrvRow s;
		s.hg              = atoi(row[0]);
		s.host            = row[1];
		s.port            = atoi(row[2]);
		s.status          = row[3];
		s.max_connections = atoi(row[4]);
		rows.push_back(s);
	}
	mysql_free_result(r);
	return rows;
}

/**
 * Count proxy-owned backend sessions for our two test users on the
 * target backend, EXCLUDING the observer's own session (which is also
 * a 'root' session opened direct-to-backend by this function).
 *
 * direct-to-backend CONNECTION_ID() is NOT intercepted by proxysql --
 * the interceptor (lib/MySQL_Session.cpp:7266) only fires when the
 * client connects to proxysql's frontend.
 */
static int count_test_backends(const SrvRow& target) {
	MYSQL* m = open_conn(target.host.c_str(), target.port,
		cl.mysql_username, cl.mysql_password,
		"MySQL-direct (root observer)");
	if (!m) return -1;
	int n = query_one_int(m,
		string("SELECT COUNT(*) FROM information_schema.processlist "
			"WHERE user IN ('") + cl.username + "', '" + cl.root_username +
		"') AND id != CONNECTION_ID()");
	mysql_close(m);
	return n;
}

// ----- main -----

int main() {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	plan(6);

	MYSQL* admin = open_conn(cl.host, cl.admin_port,
		cl.admin_username, cl.admin_password, "ProxySQL admin");
	ok(admin != nullptr, "connected to ProxySQL admin (port %d)", cl.admin_port);
	if (!admin) return exit_status();

	// Disable monitor for the duration of the test. We never SAVE TO DISK
	// here; proxysql-tester.py reloads mysql-monitor_enabled from disk
	// before the next test runs, which restores the original value.
	exec_ok(admin, "SET mysql-monitor_enabled='false'");
	exec_ok(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Wait for any in-flight monitor activity to drain. After LOAD MYSQL
	// VARIABLES the monitor thread observes the disabled flag on its
	// next loop iteration; the longest sleep between iterations is
	// mysql-monitor_ping_interval. Sleeping that interval + 1s grace
	// guarantees no thread that was already mid-iteration can still
	// fire a backend ping after this point. Pings use the monitor user
	// (filtered out by count_test_backends) so this is defensive against
	// any misconfig where monitor_username overlaps the test user.
	{
		const string ping_str = query_one_str(admin,
			"SELECT variable_value FROM global_variables "
			"WHERE variable_name='mysql-monitor_ping_interval'");
		const int ping_ms = ping_str.empty() ? 10000 : std::stoi(ping_str);
		diag("quiescing monitor: sleep %d ms (mysql-monitor_ping_interval + 1s grace)",
			ping_ms + 1000);
		std::this_thread::sleep_for(std::chrono::milliseconds(ping_ms + 1000));
	}

	// Discover the test user's default hostgroup.
	int hg = query_one_int(admin,
		string("SELECT default_hostgroup FROM mysql_users WHERE username='") +
		cl.username + "' LIMIT 1");
	ok(hg >= 0, "discovered hostgroup for '%s' (hg=%d)", cl.username, hg);
	if (hg < 0) { mysql_close(admin); return exit_status(); }

	// Pick the target = first server in the user's default hostgroup.
	std::vector<SrvRow> hg_servers = load_servers(admin,
		"WHERE hostgroup_id=" + std::to_string(hg));
	ok(!hg_servers.empty(),
		"hostgroup %d has at least one server (got %zu)",
		hg, hg_servers.size());
	if (hg_servers.empty()) { mysql_close(admin); return exit_status(); }

	const SrvRow target = hg_servers.front();
	diag("targeting backend %s:%d in hg=%d", target.host.c_str(), target.port, hg);

	// DELETE all query rules so our SELECT 1 isn't redirected to a read
	// hostgroup. We never SAVE TO DISK here; proxysql-tester.py reloads
	// mysql_query_rules from disk before the next test, which puts the
	// original ruleset back.
	exec_ok(admin, "DELETE FROM mysql_query_rules");
	exec_ok(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	// Drain-by-reinsert: DELETE every mysql_servers row, then LOAD.
	// ProxySQL's commit() treats every row as removed and destroys every
	// Free conn to those servers, ending the backend sessions cleanly.
	exec_ok(admin, "DELETE FROM mysql_servers");
	exec_ok(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Re-INSERT only the target with the test cap. Fresh empty pool.
	exec_ok(admin,
		"INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, "
		"max_connections) VALUES (" + std::to_string(hg) + ", '" +
		target.host + "', " + std::to_string(target.port) +
		", 'ONLINE', " + std::to_string(MAX_CONN) + ")");
	exec_ok(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	std::this_thread::sleep_for(std::chrono::milliseconds(300));

	// Baseline-sanity: the drain ended every proxysql-managed session for
	// these users on the target. Anything still present is foreign and
	// would invalidate the absolute invariant below.
	int baseline = count_test_backends(target);
	ok(baseline == 0,
		"baseline after drain on %s:%d for users {'%s','%s'} = %d (expect 0)",
		target.host.c_str(), target.port, cl.username, cl.root_username,
		baseline);

	// Conn 1: BEGIN -- pins the conn (Used=1).
	MYSQL* c1 = open_conn(cl.host, cl.port, cl.username, cl.password,
		"proxy as test user (c1)");
	bool c1_ok = c1 && exec_ok(c1, "BEGIN");
	// Conn 2: BEGIN -- pins the conn (Used=2).
	MYSQL* c2 = open_conn(cl.host, cl.port, cl.username, cl.password,
		"proxy as test user (c2)");
	bool c2_ok = c2 && exec_ok(c2, "BEGIN");
	ok(c1_ok && c2_ok, "two BEGIN-locked conns established as '%s'", cl.username);

	// Conn 3: short-lived as cl.username -- closes -> backend conn returns
	// to ConnectionsFree tagged with cl.username. Used=2, Free=1, alive=3.
	{
		MYSQL* c3 = open_conn(cl.host, cl.port, cl.username, cl.password,
			"proxy as test user (c3)");
		if (c3) { exec_ok(c3, "SELECT 1"); mysql_close(c3); }
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(300));

	// Conn 4: as cl.root_username -- user mismatch with the lone Free conn
	// drives the matcher to quality=1 -> case 1 + create_new path. The
	// BEGIN ... ROLLBACK wrapper pins to the write hostgroup so SELECT 1
	// can't get redirected even if a stray rule sneaks in.
	int after_victim = -1;
	{
		MYSQL* c4 = open_conn(cl.host, cl.port,
			cl.root_username, cl.root_password,
			"proxy as root (c4)");
		if (c4) {
			exec_ok(c4, "BEGIN");
			exec_ok(c4, "SELECT 1");
			std::this_thread::sleep_for(std::chrono::milliseconds(300));
			after_victim = count_test_backends(target);
			exec_ok(c4, "ROLLBACK");
			mysql_close(c4);
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

	// Release the two BEGIN-locked conns (close implies ROLLBACK). We do
	// NOT SAVE TO DISK any of the runtime state we touched: proxysql-tester.py
	// runs LOAD MYSQL {SERVERS,USERS,VARIABLES,QUERY RULES} FROM DISK +
	// LOAD ... TO RUNTIME before the next test, which restores everything.
	if (c1) mysql_close(c1);
	if (c2) mysql_close(c2);
	mysql_close(admin);
	return exit_status();
}
