/**
 * @file pgsql-native_portal_close_after_cache_hit-t.cpp
 * @brief Reproducer: Close('P', <registered named portal>) as the first routed
 *        message after a simple-query QUERY CACHE HIT inside an explicit
 *        transaction must not abort ProxySQL.
 *
 * BUG UNDER TEST
 * --------------
 * Native backend-protocol mode (PROXYSQL31+ default) supports protocol-level
 * named portals. The named-portal Close branch in
 * PgSQL_Session::handle_post_sync_close_message() routes to the portal's
 * connection via `previous_hostgroup` and guards it with
 *     assert(previous_hostgroup != -1); // a registered portal implies a prior Bind set this
 * That premise is false: `previous_hostgroup` is "hostgroup of the LAST request"
 * (RequestEnd()), and a simple-query cache hit with
 * `transaction_persistent_hostgroup == -1` sets `current_hostgroup = -1` and then
 * calls RequestEnd(), so `previous_hostgroup` becomes -1 while the named portal
 * is still registered (its txn is still open: ReadyForQuery 'T', the portal
 * registry is only cleared at an 'I' boundary). include/proxysql.h #undef's
 * NDEBUG, so the assert is live in every build: the whole process aborts.
 *
 * FIX UNDER TEST (#6412, temporary): when previous_hostgroup is -1, or the
 * backend attached there is not the connection that bound the portal, the Close
 * evicts the registry entry and synthesizes CloseComplete locally (same path as
 * a Close of an unregistered portal) instead of aborting. The backend portal
 * itself is not closed by the round-trip; protocol portals are never holdable,
 * so it is released when the transaction ends. Routing the Close to the
 * portal's own hostgroup is follow-up work; once it lands, case C should also
 * prove that the backend (not the registry) answers the later Execute.
 *
 * Preconditions for the crash (all non-default except native mode):
 *   - pgsql-use_native_backend_protocol=true (default in PROXYSQL31/40),
 *   - pgsql_users.transaction_persistent=0 for the client user,
 *   - a pgsql_query_rules row with cache_ttl>0 matching a simple 'Q' statement
 *     that the client sends inside the transaction,
 *   - Close('P', name) is the FIRST routed message of the cycle after the hit.
 *
 * CASES (the crash cases run LAST because they kill ProxySQL when the bug is
 * present):
 *   A  control, transaction_persistent=1 — the txn pins the hostgroup, the
 *      cache hit leaves current/previous_hostgroup alone. Must pass.
 *   B  transaction_persistent=0, resume Execute(C_1) after the cache hit. Goes
 *      through the query processor (exec_qp), so it does not hit the assert.
 *   C  CRASH REPRO: transaction_persistent=0, standalone Close('P','C_1')+Sync
 *      after the cache hit. Expect a local CloseComplete + Z{T}, the proxy
 *      alive, the registry entry gone (Execute(C_1) -> 34000) and ROLLBACK ->
 *      Z{I}.
 *   D  pgJDBC frame shape: Close('P','C_1') + Parse/Bind/Execute(unnamed) + Sync
 *      in one frame after the cache hit (same root cause). If case C already
 *      killed the proxy, D's checks are reported as failed "not run: cannot
 *      connect to proxy" (swap the caseC/caseD calls in main() to exercise D
 *      alone against a buggy build).
 *
 * Every case asserts that the cache hit ACTUALLY happened
 * (stats_pgsql_global.Query_Cache_count_GET_OK delta >= 1) so the test cannot
 * pass vacuously, and every crash case checks liveness afterwards (fresh admin
 * SELECT 1, ProxySQL_Uptime monotonic, no assertion line in the proxysql log).
 *
 * INFRA: legacy-g1 (docker-pgsql16-single). Raw wire via pg_lite_client:
 * libpq cannot emit named portals.
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <csignal>
#include "libpq-fe.h"
#include "pg_lite_client.h"  // MUST precede utils.h: mysql.h defines a PROTOCOL_VERSION macro
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
static const int BACKEND_HG = 0;
static const int RULE_ID = 60001;
static const char* MARKER_QUERY = "SELECT 'proxysql_qc_named_portal_marker' AS v";
static const char* PORTAL_QUERY = "SELECT g FROM generate_series(1,5) g";
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// ---------------------------------------------------------------------------
// Admin helpers (copied from pgsql-native_portals-t).
// ---------------------------------------------------------------------------
static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " connect_timeout=5";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execAdmin(PGconn* admin, const std::string& q) {
	PGresult* res = PQexec(admin, q.c_str());
	ExecStatusType st = PQresultStatus(res);
	bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(admin));
	PQclear(res);
	return good;
}

static std::string adminScalar(PGconn* admin, const std::string& q) {
	PGresult* res = PQexec(admin, q.c_str());
	std::string v;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
		v = PQgetvalue(res, 0, 0);
	PQclear(res);
	return v;
}

static long long statVal(PGconn* admin, const char* name) {
	std::string v = adminScalar(admin,
		std::string("SELECT Variable_Value FROM stats_pgsql_global WHERE Variable_Name='") + name + "'");
	return v.empty() ? -1 : atoll(v.c_str());
}

static long long cacheHits(PGconn* admin) { return statVal(admin, "Query_Cache_count_GET_OK"); }
static long long uptime(PGconn* admin) { return statVal(admin, "ProxySQL_Uptime"); }

// The hostgroup's servers, as INSERT statements recreating every column of each row,
// so a restore cannot bring an OFFLINE server back or reset weight, use_ssl, etc.
static std::vector<std::string> readServers(PGconn* admin, int hg) {
	std::vector<std::string> rows;
	PGresult* res = PQexec(admin,
	    ("SELECT * FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg)).c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		std::string cols;
		for (int c = 0; c < PQnfields(res); c++) cols += std::string(c ? "," : "") + PQfname(res, c);
		for (int i = 0; i < PQntuples(res); i++) {
			std::string ins = "INSERT INTO pgsql_servers (" + cols + ") VALUES (";
			for (int c = 0; c < PQnfields(res); c++) {
				if (c) ins += ",";
				if (PQgetisnull(res, i, c)) { ins += "NULL"; continue; }
				ins += "'";
				for (const char* v = PQgetvalue(res, i, c); *v; v++) ins += (*v == '\'') ? "''" : std::string(1, *v);
				ins += "'";
			}
			rows.push_back(ins + ")");
		}
	}
	PQclear(res);
	return rows;
}

// Drop + re-add the backend servers so the pool is recreated in the CURRENT
// (native) mode. Same trick as pgsql-native_portals-t::flushBackendPool.
static bool flushBackendPool(PGconn* admin, int hg, const std::vector<std::string>& saved) {
	if (saved.empty()) return false;
	if (!execAdmin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	for (const auto& ins : saved) {
		if (!execAdmin(admin, ins)) return false;
	}
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(200000);
	return true;
}

static bool setTxnPersistent(PGconn* admin, int v) {
	return execAdmin(admin, "UPDATE pgsql_users SET transaction_persistent=" + std::to_string(v) +
		" WHERE username='" + std::string(cl.pgsql_root_username) + "'") &&
		execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME");
}

// ---------------------------------------------------------------------------
// Global admin state + single restore path (BAIL_OUT is exit(255) and skips
// destructors, so every exit path calls restoreAll() explicitly).
// ---------------------------------------------------------------------------
struct SavedState {
	std::string auth_method;      // pgsql-authentication_method
	std::string native_mode;      // pgsql-use_native_backend_protocol
	std::string txn_persistent;   // pgsql_users.transaction_persistent (root user)
	std::vector<std::string> servers; // INSERTs recreating the full rows
	bool changed_auth = false, changed_native = false, changed_users = false, added_rule = false;
	bool restored = false;
};
static SavedState g_saved;

static void restoreAll() {
	if (g_saved.restored) return;
	g_saved.restored = true;
	PGConnPtr admin = open_admin_conn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
		diag("restoreAll: admin unreachable (proxysql down?) -- cannot restore settings");
		return;
	}
	PGconn* a = admin.get();
	if (g_saved.added_rule) {
		execAdmin(a, "DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(RULE_ID));
		execAdmin(a, "LOAD PGSQL QUERY RULES TO RUNTIME");
		execAdmin(a, "PROXYSQL FLUSH PGSQL QUERY CACHE");
	}
	if (g_saved.changed_users && !g_saved.txn_persistent.empty()) {
		setTxnPersistent(a, atoi(g_saved.txn_persistent.c_str()));
	}
	if (g_saved.changed_auth && !g_saved.auth_method.empty()) {
		execAdmin(a, "SET pgsql-authentication_method=" + g_saved.auth_method);
	}
	if (g_saved.changed_native && !g_saved.native_mode.empty()) {
		execAdmin(a, "SET pgsql-use_native_backend_protocol='" + g_saved.native_mode + "'");
	}
	execAdmin(a, "LOAD PGSQL VARIABLES TO RUNTIME");
	if (g_saved.changed_native) flushBackendPool(a, BACKEND_HG, g_saved.servers);
}

// ---------------------------------------------------------------------------
// Raw-wire helpers.
// ---------------------------------------------------------------------------
static const int PG_TIMEOUT_MS = 8000;

static std::unique_ptr<PgConnection> connectProxy() {
	auto c = std::make_unique<PgConnection>(PG_TIMEOUT_MS);
	c->connect(cl.pgsql_host, cl.pgsql_port, "postgres",
	           cl.pgsql_root_username, cl.pgsql_root_password);
	return c;
}

static std::string errSqlstate(const std::vector<uint8_t>& body) {
	size_t i = 0;
	while (i < body.size() && body[i] != 0) {
		char field = (char)body[i++];
		std::string val;
		while (i < body.size() && body[i] != 0) val += (char)body[i++];
		if (i < body.size()) i++;
		if (field == 'C') return val;
	}
	return "";
}

// Compact message-type trace until (and including) ReadyForQuery:
//   ParameterStatus dropped, ErrorResponse -> "E{C=<sqlstate>}",
//   ReadyForQuery -> "Z{<txn status>}", everything else -> its type byte.
static std::string collectTypes(PgConnection& c) {
	std::string out;
	char type;
	std::vector<uint8_t> buf;
	while (true) {
		c.readMessage(type, buf);
		switch (type) {
		case 'S': break;
		case 'N': break;
		case 'E': out += "E{C=" + errSqlstate(buf) + "}"; break;
		case 'Z': out += std::string("Z{") + (buf.empty() ? '?' : (char)buf[0]) + "}"; break;
		default: out += type; break;
		}
		if (type == 'Z') break;
	}
	return out;
}

// Run one frame; on exception (EOF/reset/timeout -> proxy died) return
// "EXC: <what>" so the caller records it as a mismatch.
template <typename F>
static std::string frame(PgConnection& c, F send) {
	try {
		send();
		return collectTypes(c);
	} catch (const PgException& e) {
		return std::string("EXC: ") + e.what();
	}
}

static std::fstream f_proxysql_log{};
static void drainLogToNow() { get_matching_lines(f_proxysql_log, "__no_such_marker_line__"); }

// Liveness after a (potential) crash: fresh admin SELECT 1, uptime monotonic,
// no assertion line in the proxysql log. 3 ok() calls.
static void livenessChecks(const char* tag, long long uptime_before) {
	PGConnPtr a = open_admin_conn();
	bool admin_ok = a && PQstatus(a.get()) == CONNECTION_OK && adminScalar(a.get(), "SELECT 1") == "1";
	ok(admin_ok, "[%s] liveness: fresh admin connection runs SELECT 1%s%s", tag,
	   admin_ok ? "" : " -- ", admin_ok ? "" : (a ? PQerrorMessage(a.get()) : "null conn"));
	long long up_after = admin_ok ? uptime(a.get()) : -1;
	ok(admin_ok && uptime_before > 0 && up_after >= uptime_before,
	   "[%s] liveness: ProxySQL_Uptime monotonic (no crash/restart): %lld -> %lld",
	   tag, uptime_before, up_after);
	const std::string re = ".*Assertion.*previous_hostgroup != -1.*";
	std::vector<line_match_t> m = get_matching_lines(f_proxysql_log, re).second;
	if (m.empty()) {
		// give the abort message a moment to be flushed to the log
		usleep(500000);
		m = get_matching_lines(f_proxysql_log, re).second;
	}
	for (const auto& lm : m) diag("[%s] proxysql log: %s", tag, std::get<LINE_MATCH_T::LINE>(lm).c_str());
	ok(m.empty(), "[%s] proxysql log has no 'Assertion ... previous_hostgroup != -1' line (found %zu)",
	   tag, m.size());
}

// F0 (populate cache), F1 BEGIN, F2 Parse s1 / Bind C_1 / Execute(C_1,2) / Sync,
// F3 marker query (cache hit). Emits ONE ok(): the cache-hit precondition +
// the setup frames' shape. Returns true when the precondition holds.
static bool setupPortalAndCacheHit(PGconn* admin, PgConnection& c, const char* tag) {
	std::string f0 = frame(c, [&] { c.execute(MARKER_QUERY); });
	std::string f1 = frame(c, [&] { c.execute("BEGIN"); });
	std::string f2 = frame(c, [&] {
		c.prepareStatement("s1", PORTAL_QUERY, false);
		c.bindStatement("s1", "C_1", {}, {}, false);
		c.executePortal("C_1", 2, false);
		c.sendSync();
	});
	long long hits_before = cacheHits(admin);
	std::string f3 = frame(c, [&] { c.execute(MARKER_QUERY); });
	long long hits_after = cacheHits(admin);
	bool shape = (f0 == "TDCZ{I}" && f1 == "CZ{T}" && f2 == "12DDsZ{T}" && f3 == "TDCZ{T}");
	bool hit = (hits_before >= 0 && hits_after >= hits_before + 1);
	ok(shape && hit,
	   "[%s] precondition: named portal C_1 open in txn, then marker query served from cache "
	   "(GET_OK %lld -> %lld) -- F0='%s' F1='%s' F2='%s' F3='%s'",
	   tag, hits_before, hits_after, f0.c_str(), f1.c_str(), f2.c_str(), f3.c_str());
	return shape && hit;
}

// ---------------------------------------------------------------------------
// Cases.
// ---------------------------------------------------------------------------
static const int CASE_A_TESTS = 4;
static const int CASE_B_TESTS = 3;
static const int CASE_C_TESTS = 7;
static const int CASE_D_TESTS = 6;

// Connect for a case; on failure record `n` failing checks so the plan holds.
static std::unique_ptr<PgConnection> connectForCase(const char* tag, int n) {
	try { return connectProxy(); }
	catch (const PgException& e) {
		for (int i = 0; i < n; i++)
			ok(0, "[%s] not run: cannot connect to proxy (%s)", tag, e.what());
	}
	return nullptr;
}

// Case A: control, transaction_persistent=1.
static void caseA(PGconn* admin) {
	const char* tag = "A persistent=1 Close after cache hit";
	auto c = connectForCase(tag, CASE_A_TESTS);
	if (!c) return;
	{
		long long up0 = uptime(admin);
		setupPortalAndCacheHit(admin, *c, tag);
		std::string f4 = frame(*c, [&] { c->closePortal("C_1", false); c->sendSync(); });
		ok(f4 == "3Z{T}", "[%s] Close('P','C_1')+Sync -> CloseComplete, Z{T}: got '%s'", tag, f4.c_str());
		std::string f5 = frame(*c, [&] { c->executePortal("C_1", 0, false); c->sendSync(); });
		std::string f6 = frame(*c, [&] { c->execute("ROLLBACK"); });
		// SQLSTATE only: the ReadyForQuery status after this locally synthesized
		// registry-miss 34000 is a separate issue, #6424 (PostgreSQL reports 'E' inside a
		// txn; ProxySQL's generate_error_packet() always writes 'I'), not this bug.
		if (f5 != "E{C=34000}Z{E}")
			diag("[%s] NOTE: Execute(closed portal) in txn -> '%s' (PostgreSQL would send 'E{C=34000}Z{E}')",
			     tag, f5.c_str());
		ok(f5.rfind("E{C=34000}Z{", 0) == 0 && f6 == "CZ{I}",
		   "[%s] portal really closed (Execute -> 34000) and ROLLBACK -> Z{I}: got '%s' / '%s'",
		   tag, f5.c_str(), f6.c_str());
		long long up1 = uptime(admin);
		ok(up0 > 0 && up1 >= up0, "[%s] ProxySQL_Uptime monotonic: %lld -> %lld", tag, up0, up1);
		try { c->disconnect(); } catch (...) {}
	}
}

// Case B: transaction_persistent=0, resume Execute(C_1) after the cache hit.
static void caseB(PGconn* admin) {
	const char* tag = "B persistent=0 resume Execute after cache hit";
	auto c = connectForCase(tag, CASE_B_TESTS);
	if (!c) return;
	{
		drainLogToNow();
		long long up0 = uptime(admin);
		setupPortalAndCacheHit(admin, *c, tag);
		std::string f4 = frame(*c, [&] { c->executePortal("C_1", 2, false); c->sendSync(); });
		std::string f5 = frame(*c, [&] { c->execute("ROLLBACK"); });
		ok(f4 == "DDsZ{T}" && f5 == "CZ{I}",
		   "[%s] Execute(C_1,2) resumes rows 3,4 -> 'DDsZ{T}', ROLLBACK -> 'CZ{I}': got '%s' / '%s'",
		   tag, f4.c_str(), f5.c_str());
		long long up1 = uptime(admin);
		ok(up0 > 0 && up1 >= up0, "[%s] ProxySQL_Uptime monotonic: %lld -> %lld", tag, up0, up1);
		try { c->disconnect(); } catch (...) {}
	}
}

// Case C: CRASH REPRO. transaction_persistent=0, standalone Close('P','C_1').
static void caseC(PGconn* admin) {
	const char* tag = "C persistent=0 standalone Close after cache hit";
	auto c = connectForCase(tag, CASE_C_TESTS);
	if (!c) return;
	drainLogToNow();
	long long up0 = uptime(admin);
	setupPortalAndCacheHit(admin, *c, tag);
	diag("[%s] sending Close('P','C_1') + Sync (asserts previous_hostgroup != -1 when buggy)", tag);
	std::string f4 = frame(*c, [&] { c->closePortal("C_1", false); c->sendSync(); });
	ok(f4 == "3Z{T}", "[%s] Close('P','C_1')+Sync -> CloseComplete, Z{T}: got '%s'", tag, f4.c_str());
	livenessChecks(tag, up0);
	std::string f5 = frame(*c, [&] { c->executePortal("C_1", 0, false); c->sendSync(); });
	// The temporary fix completes this Close locally, so the 34000 comes from the
	// registry miss, not from the backend. SQLSTATE only, see caseA.
	ok(f5.rfind("E{C=34000}Z{", 0) == 0, "[%s] portal evicted: Execute(C_1) -> 34000: got '%s'",
	   tag, f5.c_str());
	std::string f6 = frame(*c, [&] { c->execute("ROLLBACK"); });
	ok(f6 == "CZ{I}", "[%s] ROLLBACK -> 'CZ{I}': got '%s'", tag, f6.c_str());
	try { c->disconnect(); } catch (...) {}
}

// Case D: pgJDBC frame shape. Close('P','C_1') + unnamed Parse/Bind/Execute + Sync.
static void caseD(PGconn* admin) {
	const char* tag = "D persistent=0 pgJDBC Close+Parse/Bind/Execute frame after cache hit";
	auto c = connectForCase(tag, CASE_D_TESTS);
	if (!c) return;
	drainLogToNow();
	long long up0 = uptime(admin);
	setupPortalAndCacheHit(admin, *c, tag);
	diag("[%s] sending Close('P','C_1') + Parse/Bind/Execute(unnamed) + Sync", tag);
	std::string f4 = frame(*c, [&] {
		c->closePortal("C_1", false);
		c->prepareStatement("", "SELECT 1", false);
		c->bindStatement("", "", {}, {}, false);
		c->executePortal("", 0, false);
		c->sendSync();
	});
	ok(f4 == "312DCZ{T}", "[%s] frame -> '312DCZ{T}': got '%s'", tag, f4.c_str());
	livenessChecks(tag, up0);
	std::string f6 = frame(*c, [&] { c->execute("ROLLBACK"); });
	ok(f6 == "CZ{I}", "[%s] ROLLBACK -> 'CZ{I}': got '%s'", tag, f6.c_str());
	try { c->disconnect(); } catch (...) {}
}

int main(int /*argc*/, char** /*argv*/) {
	if (cl.getEnv()) return exit_status();
	// A crash closes the proxy socket under us; writing to it must surface as a
	// PgException (recorded as a failed check), not kill the test with SIGPIPE.
	signal(SIGPIPE, SIG_IGN);

	PGConnPtr admin_p = open_admin_conn();
	if (!admin_p || PQstatus(admin_p.get()) != CONNECTION_OK) {
		plan(1);
		BAIL_OUT("admin connect failed");
		return exit_status();
	}
	PGconn* admin = admin_p.get();

	// Stable tier (< 3.1) has no named-portal support: native mode is forced off
	// and Close('P', named) is rejected with 0A000 before the assert. The group
	// entry carries @proxysql_min_version:3.1.0, so this is a defensive path only.
	{
		std::string ver = adminScalar(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='admin-version'");
		int major = 0, minor = 0;
		sscanf(ver.c_str(), "%d.%d", &major, &minor);
		if (major < 3 || (major == 3 && minor < 1)) {
			plan(1);
			skip(1, "ProxySQL %s: named portals not supported below 3.1 (native mode forced off)", ver.c_str());
			return exit_status();
		}
	}

	plan(CASE_A_TESTS + CASE_B_TESTS + CASE_C_TESTS + CASE_D_TESTS);

	g_saved.servers = readServers(admin, BACKEND_HG);
	if (g_saved.servers.empty()) {
		BAIL_OUT("No pgsql_servers in hostgroup %d", BACKEND_HG);
		return exit_status();
	}
	std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS) {
		BAIL_OUT("Cannot open ProxySQL log at %s", log_path.c_str());
		return exit_status();
	}

	g_saved.auth_method = adminScalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-authentication_method'");
	g_saved.native_mode = adminScalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	g_saved.txn_persistent = adminScalar(admin,
		"SELECT transaction_persistent FROM pgsql_users WHERE username='" +
		std::string(cl.pgsql_root_username) + "' LIMIT 1");
	diag("saved: authentication_method=%s use_native_backend_protocol=%s transaction_persistent=%s",
	     g_saved.auth_method.c_str(), g_saved.native_mode.c_str(), g_saved.txn_persistent.c_str());
	if (g_saved.auth_method.empty() || g_saved.native_mode.empty() || g_saved.txn_persistent.empty()) {
		BAIL_OUT("cannot read current settings to restore later");
		return exit_status();
	}

	// Setup: cleartext frontend auth (pg_lite_client -> proxy), native mode +
	// fresh native pool, caching rule on the marker literal only (match_pattern,
	// NOT '^SELECT', so the portal's Parse is not matched).
	g_saved.changed_auth = true;
	g_saved.changed_native = true;
	bool setup_ok =
		execAdmin(admin, "SET pgsql-authentication_method=1") &&
		execAdmin(admin, "SET pgsql-use_native_backend_protocol='true'") &&
		execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME") &&
		flushBackendPool(admin, BACKEND_HG, g_saved.servers);
	if (setup_ok && adminScalar(admin, "SELECT COUNT(*) FROM pgsql_query_rules WHERE rule_id=" +
		std::to_string(RULE_ID)) != "0") {
		// The rule id is dedicated to this test; do not delete someone else's rule.
		restoreAll();
		BAIL_OUT("pgsql_query_rules already has rule_id=%d; refusing to overwrite it", RULE_ID);
		return exit_status();
	}
	if (setup_ok) {
		g_saved.added_rule = true;
		setup_ok =
			execAdmin(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(RULE_ID)) &&
			execAdmin(admin, "INSERT INTO pgsql_query_rules (rule_id,active,match_pattern,cache_ttl,apply) VALUES (" +
				std::to_string(RULE_ID) + ",1,'proxysql_qc_named_portal_marker',60000,1)") &&
			execAdmin(admin, "LOAD PGSQL QUERY RULES TO RUNTIME") &&
			execAdmin(admin, "PROXYSQL FLUSH PGSQL QUERY CACHE");
	}
	if (!setup_ok) {
		restoreAll();
		BAIL_OUT("admin setup failed");
		return exit_status();
	}

	// ---- Case A: control, transaction_persistent=1 ----
	g_saved.changed_users = true;
	if (!setTxnPersistent(admin, 1)) { restoreAll(); BAIL_OUT("set transaction_persistent=1 failed"); return exit_status(); }
	caseA(admin);

	// ---- transaction_persistent=0 for the remaining cases ----
	if (!setTxnPersistent(admin, 0)) { restoreAll(); BAIL_OUT("set transaction_persistent=0 failed"); return exit_status(); }
	caseB(admin);

	// ---- Crash cases LAST (they abort ProxySQL while the bug is present) ----
	caseC(admin);
	admin_p = open_admin_conn();  // re-open: case C may have killed the old one
	caseD(admin_p.get());

	restoreAll();
	return exit_status();
}
