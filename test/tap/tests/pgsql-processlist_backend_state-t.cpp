/**
 * @file pgsql-processlist_backend_state-t.cpp
 * @brief backend_state in the PgSQL processlist must reflect the backend, on the
 *        native backend protocol as well as on libpq (#6434).
 *
 * PgSQL_Connection::get_pg_backend_state() used to ask libpq only. On a native
 * backend connection pgsql_conn is always NULL, so every native backend showed
 * up as 'disconnected' in stats_pgsql_processlist.backend_state,
 * stats_pgsql_stat_activity.state and SHOW PGSQL PROCESSLIST/ACTIVITY, right
 * next to a real backend_pid.
 *
 * Each phase empties the pool first, because a backend connection is built as
 * libpq or native once and never converts. libpq runs first as the oracle, then
 * native must report the same values:
 *   - client A: BEGIN                -> 'idle in transaction'
 *   - client A: SELECT 1/0 inside it -> 'idle in transaction (aborted)'
 *   - client B: SELECT pg_sleep(..) in flight -> 'active'
 * Every value is read from all four places the column is exposed and they must
 * agree. Finally, A's connection is looked up in stats_pgsql_free_connections
 * after ROLLBACK: its native_mode must match the phase, otherwise the phase did
 * not test what it claims (after the fix both modes report the same states).
 *
 * Connections are matched by backend pid. A bare "SELECT pg_backend_pid()" is
 * answered by ProxySQL itself, so the pid is read through pg_stat_activity.
 *
 * Pool flush: the hostgroup's servers are deleted, loaded, and put back unchanged
 * (OFFLINE_HARD keeps the pool). Runtime state is restored at the end, never
 * saved to disk.
 */
#include <chrono>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

#include "libpq-fe.h"
#include "json.hpp"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using nlohmann::json;
CommandLine cl;

static const char* ACTIVE_MARKER = "bstate_6434_active";

static PGConnPtr openConn(const char* host, int port, const char* user,
                          const char* pass, const char* db) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable connect_timeout=10";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr createAdminConn() {
	return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port,
	                cl.admin_username, cl.admin_password, nullptr);
}

static PGConnPtr createClientConn() {
	return openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username,
	                cl.pgsql_password, cl.pgsql_username);
}

static bool execAdmin(PGconn* admin, const std::string& q) {
	PGresult* r = PQexec(admin, q.c_str());
	const ExecStatusType st = PQresultStatus(r);
	const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(admin));
	PQclear(r);
	return good;
}

static std::string scalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string v;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		v = PQgetvalue(r, 0, 0);
	PQclear(r);
	return v;
}

static ExecStatusType execClient(PGconn* c, const char* q) {
	PGresult* r = PQexec(c, q);
	const ExecStatusType st = PQresultStatus(r);
	PQclear(r);
	return st;
}

template <typename Predicate>
static bool waitUntil(Predicate predicate, int timeout_ms) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	do {
		if (predicate()) return true;
		usleep(50 * 1000);
	} while (std::chrono::steady_clock::now() < deadline);
	return false;
}

static bool setNativeMode(PGconn* admin, bool enabled) {
	return execAdmin(admin, std::string("SET pgsql-use_native_backend_protocol='") +
	                        (enabled ? "true" : "false") + "'") &&
	       execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

static const char* SERVER_COLS =
	"hostgroup_id,hostname,port,status,weight,compression,max_connections,"
	"max_replication_lag,use_ssl,max_latency_ms,comment";

static std::string sqlQuote(const std::string& v) {
	std::string out = "'";
	for (char c : v) { if (c == '\'') out += "''"; else out += c; }
	return out + "'";
}

// The hostgroup's servers as the INSERTs that recreate them, every column included.
static std::vector<std::string> snapshotServers(PGconn* admin, int hg) {
	std::vector<std::string> inserts;
	std::stringstream sel;
	sel << "SELECT " << SERVER_COLS << " FROM pgsql_servers WHERE hostgroup_id=" << hg;
	PGresult* res = PQexec(admin, sel.str().c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		const int rows = PQntuples(res), cols = PQnfields(res);
		for (int r = 0; r < rows; r++) {
			std::stringstream ins;
			ins << "INSERT INTO pgsql_servers (" << SERVER_COLS << ") VALUES (";
			for (int c = 0; c < cols; c++) {
				if (c) ins << ",";
				if (PQgetisnull(res, r, c)) ins << "NULL";
				else ins << sqlQuote(PQgetvalue(res, r, c));
			}
			ins << ")";
			inserts.push_back(ins.str());
		}
	} else {
		diag("snapshotServers: %s", PQerrorMessage(admin));
	}
	PQclear(res);
	return inserts;
}

static bool restoreServers(PGconn* admin, int hg, const std::vector<std::string>& inserts) {
	if (!execAdmin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
	for (const auto& q : inserts) {
		if (!execAdmin(admin, q)) return false;
	}
	return execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

static int poolCount(PGconn* admin, int hg, const char* col) {
	const std::string v = scalar(admin, std::string("SELECT COALESCE(SUM(") + col +
		"),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(hg));
	return v.empty() ? -1 : atoi(v.c_str());
}

// Removing the servers closes their free connections; OFFLINE_HARD does not.
// Connections still in use survive the removal: the server object is revived
// when it is put back, and they return to the pool afterwards -- still built in
// whatever mode a previous test left behind. So wait for the hostgroup to have
// none in use first, and check the pool really is empty afterwards.
static bool flushBackendPool(PGconn* admin, int hg, const std::vector<std::string>& inserts) {
	if (inserts.empty()) return false;
	diag("flushBackendPool: hostgroup %d before flush ConnUsed=%d ConnFree=%d", hg,
	     poolCount(admin, hg, "ConnUsed"), poolCount(admin, hg, "ConnFree"));
	for (int attempt = 0; attempt < 3; attempt++) {
		if (!waitUntil([&]() { return poolCount(admin, hg, "ConnUsed") == 0; }, 10000))
			diag("flushBackendPool: hostgroup %d still has connections in use", hg);
		if (!execAdmin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
		if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
		if (!restoreServers(admin, hg, inserts)) return false;
		usleep(200000);
		const int used = poolCount(admin, hg, "ConnUsed"), free_ = poolCount(admin, hg, "ConnFree");
		if (used == 0 && free_ == 0) return true;
		diag("flushBackendPool: attempt %d left ConnUsed=%d ConnFree=%d", attempt, used, free_);
	}
	return false;
}

// The real backend pid: a bare SELECT pg_backend_pid() is answered by ProxySQL.
static std::string backendPid(PGconn* c) {
	return scalar(c, "SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()");
}

// backend_state of one backend pid, as seen through the four places it is exposed.
struct States {
	std::string processlist, stat_activity, show_processlist, show_activity;
	bool all(const std::string& v) const {
		return processlist == v && stat_activity == v && show_processlist == v && show_activity == v;
	}
	std::string str() const {
		return "processlist='" + processlist + "' stat_activity='" + stat_activity +
		       "' SHOW PROCESSLIST='" + show_processlist + "' SHOW ACTIVITY='" + show_activity + "'";
	}
};

// SHOW PGSQL PROCESSLIST / ACTIVITY both put backend_pid in column 4 and the state in column 5.
static std::string showLookup(PGconn* admin, const char* show, const std::string& pid) {
	std::string v;
	PGresult* r = PQexec(admin, show);
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQnfields(r) > 5) {
		for (int i = 0; i < PQntuples(r); i++) {
			if (!PQgetisnull(r, i, 4) && pid == PQgetvalue(r, i, 4)) {
				v = PQgetisnull(r, i, 5) ? "" : PQgetvalue(r, i, 5);
				break;
			}
		}
	} else {
		diag("%s failed: %s", show, PQerrorMessage(admin));
	}
	PQclear(r);
	return v;
}

static States readStates(PGconn* admin, const std::string& pid) {
	States s;
	s.processlist = scalar(admin, "SELECT backend_state FROM stats_pgsql_processlist WHERE backend_pid=" + pid);
	s.stat_activity = scalar(admin, "SELECT state FROM stats_pgsql_stat_activity WHERE backend_pid=" + pid);
	s.show_processlist = showLookup(admin, "SHOW PGSQL PROCESSLIST", pid);
	s.show_activity = showLookup(admin, "SHOW PGSQL ACTIVITY", pid);
	return s;
}

static void checkStates(PGconn* admin, const char* phase, const char* who,
                        const std::string& pid, const std::string& expected) {
	States s;
	// The state is settled by the time the client has its reply; the wait only
	// absorbs scheduling noise.
	waitUntil([&]() { s = readStates(admin, pid); return s.all(expected); }, 3000);
	ok(s.processlist == expected, "%s: %s pid %s stats_pgsql_processlist.backend_state='%s' (expected '%s')",
	   phase, who, pid.c_str(), s.processlist.c_str(), expected.c_str());
	ok(s.stat_activity == expected, "%s: %s pid %s stats_pgsql_stat_activity.state='%s' (expected '%s')",
	   phase, who, pid.c_str(), s.stat_activity.c_str(), expected.c_str());
	ok(s.show_processlist == expected, "%s: %s pid %s SHOW PGSQL PROCESSLIST backend_state='%s' (expected '%s')",
	   phase, who, pid.c_str(), s.show_processlist.c_str(), expected.c_str());
	ok(s.show_activity == expected, "%s: %s pid %s SHOW PGSQL ACTIVITY state='%s' (expected '%s')",
	   phase, who, pid.c_str(), s.show_activity.c_str(), expected.c_str());
	if (!s.all(expected)) diag("%s: %s", phase, s.str().c_str());
}

// pgsql_info of the pooled connection with this backend pid, or null when not pooled.
static json pooledInfo(PGconn* admin, const std::string& pid) {
	PGresult* r = PQexec(admin, "SELECT pgsql_info FROM stats_pgsql_free_connections");
	json found;
	if (PQresultStatus(r) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(r) && found.is_null(); i++) {
			if (PQgetisnull(r, i, 0)) continue;
			const json j = json::parse(PQgetvalue(r, i, 0), nullptr, false);
			if (j.is_object() && j.contains("backend_pid") && j["backend_pid"].is_number() &&
			    std::to_string(j["backend_pid"].get<long long>()) == pid) {
				found = j;
			}
		}
	}
	PQclear(r);
	return found;
}

static const int TESTS_PER_PHASE = 16;

static void runPhase(PGconn* admin, int hg, const std::vector<std::string>& servers, bool native) {
	const char* phase = native ? "native" : "libpq";
	const bool ready = setNativeMode(admin, native) && flushBackendPool(admin, hg, servers);
	ok(ready, "%s: backend mode selected and pool of hostgroup %d emptied", phase, hg);
	if (!ready) { skip(TESTS_PER_PHASE - 1, "%s: could not prepare the phase", phase); return; }

	// Client A: an open transaction pins the backend to the session.
	auto A = createClientConn();
	std::string a_pid;
	if (PQstatus(A.get()) == CONNECTION_OK && execClient(A.get(), "BEGIN") == PGRES_COMMAND_OK) {
		a_pid = backendPid(A.get());
	}
	ok(!a_pid.empty() && atoi(a_pid.c_str()) > 0, "%s: client A in a transaction on backend pid '%s'",
	   phase, a_pid.c_str());
	if (a_pid.empty()) {
		diag("%s: client A: %s", phase, PQerrorMessage(A.get()));
		skip(TESTS_PER_PHASE - 2, "%s: client A has no backend", phase);
		return;
	}
	checkStates(admin, phase, "A", a_pid, "idle in transaction");

	// A failed statement leaves the transaction aborted on the same backend.
	if (execClient(A.get(), "SELECT 1/0") != PGRES_FATAL_ERROR)
		diag("%s: SELECT 1/0 did not fail as expected", phase);
	checkStates(admin, phase, "A", a_pid, "idle in transaction (aborted)");

	// Client B: a query in flight on the backend.
	auto B = createClientConn();
	const std::string sleep_q = std::string("SELECT pg_sleep(5), '") + ACTIVE_MARKER + "'";
	const bool sent = PQstatus(B.get()) == CONNECTION_OK && PQsendQuery(B.get(), sleep_q.c_str());
	std::string b_pid;
	if (sent) {
		const std::string q = std::string("SELECT backend_pid FROM stats_pgsql_processlist WHERE backend_pid > 0 "
		                                  "AND info LIKE '%") + ACTIVE_MARKER + "%'";
		waitUntil([&]() { b_pid = scalar(admin, q); return !b_pid.empty(); }, 3000);
	}
	if (b_pid.empty()) {
		diag("%s: client B's in-flight query not found in the processlist (sent=%d)", phase, sent);
		b_pid = "-1";
	}
	checkStates(admin, phase, "B", b_pid, "active");
	bool b_done = false;
	if (sent) {
		PGresult* r;
		b_done = true;
		while ((r = PQgetResult(B.get())) != nullptr) {
			if (PQresultStatus(r) != PGRES_TUPLES_OK) b_done = false;
			PQclear(r);
		}
	}
	ok(b_done, "%s: client B's pg_sleep completed", phase);

	// A's connection back in the pool: it must be the mode under test.
	execClient(A.get(), "ROLLBACK");
	json info;
	waitUntil([&]() { info = pooledInfo(admin, a_pid); return !info.is_null(); }, 3000);
	const bool is_native = info.is_object() && info.contains("native_mode") && info["native_mode"] == true;
	ok(!info.is_null() && is_native == native, "%s: pooled connection pid %s reports native_mode=%s",
	   phase, a_pid.c_str(), info.is_null() ? "(not pooled)" : (is_native ? "true" : "false"));
}

int main(int argc, char** argv) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(2 * TESTS_PER_PHASE);

	auto admin = createAdminConn();
	if (PQstatus(admin.get()) != CONNECTION_OK) {
		BAIL_OUT("admin connection failed: %s", PQerrorMessage(admin.get()));
		return exit_status();
	}

	const std::string hg_s = scalar(admin.get(),
		std::string("SELECT default_hostgroup FROM runtime_pgsql_users WHERE username=") +
		sqlQuote(cl.pgsql_username) + " LIMIT 1");
	const std::string orig_native = scalar(admin.get(),
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	if (hg_s.empty() || orig_native.empty()) {
		BAIL_OUT("cannot read default hostgroup ('%s') or pgsql-use_native_backend_protocol ('%s')",
		         hg_s.c_str(), orig_native.c_str());
		return exit_status();
	}
	const int hg = atoi(hg_s.c_str());
	const std::vector<std::string> servers = snapshotServers(admin.get(), hg);
	diag("hostgroup %d, %zu server(s), pgsql-use_native_backend_protocol originally '%s'",
	     hg, servers.size(), orig_native.c_str());

	runPhase(admin.get(), hg, servers, false);
	runPhase(admin.get(), hg, servers, true);

	// Restore the original mode with a pool built under it.
	execAdmin(admin.get(), "SET pgsql-use_native_backend_protocol='" + orig_native + "'");
	execAdmin(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	if (!servers.empty() && !flushBackendPool(admin.get(), hg, servers))
		restoreServers(admin.get(), hg, servers);

	return exit_status();
}
