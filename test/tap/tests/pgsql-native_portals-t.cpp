/**
 * @file pgsql-native_portals-t.cpp
 * @brief Raw-wire NAMED-PORTAL differential test: ProxySQL (native backend
 *        protocol) vs a direct PostgreSQL backend used as the oracle.
 *
 * PURPOSE
 * -------
 * Tasks P1/P2 taught the native backend-protocol path to drive NAMED portals
 * end-to-end (immediate Bind dispatch + registry, Execute(named) with max_rows
 * and PortalSuspended resume, Describe('P') name-compared fold, Close('P') real
 * backend round-trip with eviction, txn-'I' portal-lifetime clearing, sticky
 * pinning). No test in the tree drives a named Execute/Describe/Close over the
 * wire — libpq collapses everything onto the unnamed portal. This test closes
 * that gap with a hand-rolled protocol client (pg_lite_client) that emits the
 * exact Parse/Bind/Describe/Execute/Close/Sync byte stream we want.
 *
 * METHOD (per corpus case)
 * ------------------------
 * Run an identical raw-wire script twice and compare the CLIENT-VISIBLE backend
 * message sequence (type + payload), normalized only as documented below:
 *   Leg A (ORACLE): straight to the backend (cl.pgsql_server_host:port),
 *                   authenticating with SCRAM-SHA-256 (pg_hba scram-sha-256).
 *   Leg B (CANDIDATE): through ProxySQL (cl.pgsql_host:port) with
 *                   `pgsql-use_native_backend_protocol=true`, frontend cleartext
 *                   (`pgsql-authentication_method=1`).
 * Both legs run as the same backend role (postgres) against the same physical
 * backend and database, so table OIDs / type OIDs / command tags are identical;
 * the only legitimate differences are handled by normalizeSeq().
 *
 * NORMALIZATION (exhaustive — every item justified)
 * -------------------------------------------------
 *  1. ParameterStatus ('S') messages are DROPPED. The backend and the proxy
 *     advertise different startup GUC sets, and any mid-cycle ParameterStatus is
 *     proxy-vs-backend plumbing noise unrelated to portal semantics. (Startup
 *     ParameterStatus/BackendKeyData are consumed inside connect() and never
 *     reach the compared cycle anyway.)
 *  2. ErrorResponse ('E') / NoticeResponse ('N') are reduced to their SQLSTATE
 *     ('C') field ONLY in the frames where ProxySQL SYNTHESIZES the error
 *     locally (the post-invalidation Execute of PORTAL_TXN / PORTAL_SYNC_DESTROY
 *     — a registry miss builds a local undefined-cursor ErrorResponse whose
 *     field set legitimately differs from a backend-generated one; the SQLSTATE
 *     is the semantic contract there). Frames whose errors are BACKEND-generated
 *     on both legs (e.g. PORTAL_ERR_BIND_DUP's 42P03) are compared with the FULL
 *     error payload — severity/message/detail/position included — proving the
 *     native drive forwards backend errors unchanged.
 * Everything else — DataRow 'D', CommandComplete 'C', RowDescription 'T',
 * ParseComplete '1', BindComplete '2', CloseComplete '3', NoData 'n',
 * PortalSuspended 's', EmptyQueryResponse 'I', ParameterDescription 't', and the
 * ReadyForQuery 'Z' transaction-status byte — is compared in FULL.
 *
 * INFRA: legacy-g1 (docker-pgsql16-single, scram-sha-256, no TLS).
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include "libpq-fe.h"
#include "pg_lite_client.h"  // MUST precede utils.h: mysql.h defines a PROTOCOL_VERSION macro
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql-native_tracking.h"

CommandLine cl;
static const int BACKEND_HG = 0;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// ---------------------------------------------------------------------------
// Admin helpers (mode + pool control), mirrored from pgsql-native_prepared-t.
// ---------------------------------------------------------------------------
static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password;
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

static bool setNativeMode(PGconn* admin, bool on) {
	std::string v = on ? "true" : "false";
	return execAdmin(admin, "SET pgsql-use_native_backend_protocol='" + v + "'") &&
	       execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

struct ServerRow { std::string hostname, port, max_connections, comment; };

static std::vector<ServerRow> readServers(PGconn* admin, int hg) {
	std::vector<ServerRow> rows;
	PGresult* res = PQexec(admin,
	    ("SELECT hostname, port, max_connections, comment FROM pgsql_servers "
	     "WHERE hostgroup_id=" + std::to_string(hg)).c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(res); i++) {
			ServerRow r;
			r.hostname = PQgetvalue(res, i, 0);
			r.port = PQgetvalue(res, i, 1);
			r.max_connections = PQgetvalue(res, i, 2);
			r.comment = PQgetisnull(res, i, 3) ? "" : PQgetvalue(res, i, 3);
			rows.push_back(std::move(r));
		}
	}
	PQclear(res);
	return rows;
}

// Drop + re-add the backend servers so every pooled connection is torn down and
// recreated in the CURRENT mode (a warm libpq pool would otherwise make named
// Bind hit the libpq-guard reject and mask the native path). Same trick as
// pgsql-native_prepared-t::flushBackendPool.
static bool flushBackendPool(PGconn* admin, int hg, const std::vector<ServerRow>& saved) {
	if (saved.empty()) return false;
	if (!execAdmin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	for (const auto& r : saved) {
		std::string ins = "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) VALUES ("
			+ std::to_string(hg) + ",'" + r.hostname + "'," + r.port + ","
			+ (r.max_connections.empty() ? std::string("1000") : r.max_connections)
			+ ",'" + r.comment + "')";
		if (!execAdmin(admin, ins)) return false;
	}
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(200000);
	return true;
}

// RAII: force frontend cleartext auth (so pg_lite_client can talk to the proxy
// without SCRAM) for the whole test, restoring the prior value on exit.
// IMPORTANT: BAIL_OUT() is exit(255) and skips destructors — every exit path
// taken AFTER construction must call restore() explicitly first, or the global
// pgsql-authentication_method=1 would leak into later tests on infra failure.
// restore() is idempotent, so the destructor calling it again is harmless.
struct AuthMethodScope {
	PGconn* admin;
	std::string saved;
	bool ok = false;
	bool restored = false;
	explicit AuthMethodScope(PGconn* a) : admin(a) {
		saved = adminScalar(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-authentication_method'");
		if (saved.empty()) {
			// Cannot read the current value -> do NOT change it (we could never
			// restore); the caller bails out with restore() a no-op.
			diag("AuthMethodScope: cannot read pgsql-authentication_method");
			return;
		}
		ok = execAdmin(admin, "SET pgsql-authentication_method=1") &&
		     execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	void restore() {
		if (restored) return;
		restored = true;
		if (saved.empty()) return;  // never changed
		execAdmin(admin, "SET pgsql-authentication_method=" + saved);
		execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	~AuthMethodScope() { restore(); }
	AuthMethodScope(const AuthMethodScope&) = delete;
	AuthMethodScope& operator=(const AuthMethodScope&) = delete;
};

// ---------------------------------------------------------------------------
// Raw-wire connection factories.
// ---------------------------------------------------------------------------
static const int PG_TIMEOUT_MS = 8000;

// Leg A: straight to the backend, SCRAM-SHA-256 (pg_hba scram-sha-256).
static std::unique_ptr<PgConnection> connectBackend() {
	auto c = std::make_unique<PgConnection>(PG_TIMEOUT_MS);
	c->connect(cl.pgsql_server_host, cl.pgsql_server_port, "postgres",
	           cl.pgsql_root_username, cl.pgsql_root_password);
	return c;
}

// Leg B: through ProxySQL, frontend cleartext (AuthMethodScope active).
static std::unique_ptr<PgConnection> connectProxy() {
	auto c = std::make_unique<PgConnection>(PG_TIMEOUT_MS);
	c->connect(cl.pgsql_host, cl.pgsql_port, "postgres",
	           cl.pgsql_root_username, cl.pgsql_root_password);
	return c;
}

// ---------------------------------------------------------------------------
// Message-sequence capture + normalization.
// ---------------------------------------------------------------------------
static std::string errSqlstate(const std::vector<uint8_t>& body) {
	// ErrorResponse/NoticeResponse body: repeated (fieldType byte, C-string),
	// terminated by a 0 field type. 'C' carries the SQLSTATE code.
	size_t i = 0;
	while (i < body.size() && body[i] != 0) {
		char field = (char)body[i++];
		std::string val;
		while (i < body.size() && body[i] != 0) val += (char)body[i++];
		if (i < body.size()) i++;  // skip the string NUL
		if (field == 'C') return val;
	}
	return "";
}

// One normalized token per message. Returns "" for messages that are dropped.
// `reduce_errors` applies normalization #2 (E/N -> SQLSTATE) and must be set
// ONLY for frames whose errors ProxySQL synthesizes locally; frames with
// backend-generated errors compare the full E/N payload.
static std::string normToken(char type, const std::vector<uint8_t>& payload, bool reduce_errors) {
	switch (type) {
	case 'S':  // ParameterStatus — dropped (normalization #1)
		return "";
	case 'E':  // ErrorResponse
	case 'N':  // NoticeResponse
		if (reduce_errors)  // normalization #2, synthesized-error frames only
			return std::string(1, type) + "{C=" + errSqlstate(payload) + "}";
		break;  // backend-generated on both legs -> full-payload path below
	case 'Z': {  // ReadyForQuery — keep transaction-status byte
		char s = payload.empty() ? '?' : (char)payload[0];
		return std::string("Z{") + s + "}";
	}
	default:
		break;
	}
	// Everything else compared in full: type + raw payload bytes.
	std::stringstream ss;
	ss << type << "[";
	for (uint8_t b : payload) {
		// printable payload bytes verbatim, others as \xNN, so text tags
		// ("SELECT 1") stay readable in mismatch diagnostics.
		if (b >= 0x20 && b < 0x7f && b != '\\') ss << (char)b;
		else { char h[6]; snprintf(h, sizeof(h), "\\x%02x", b); ss << h; }
	}
	ss << "]";
	return ss.str();
}

// Read backend messages until (and including) the first ReadyForQuery 'Z',
// returning the concatenation of their normalized tokens.
static std::string collectUntilReady(PgConnection& c, bool reduce_errors = false) {
	std::string out;
	char type;
	std::vector<uint8_t> buf;
	while (true) {
		c.readMessage(type, buf);
		out += normToken(type, buf, reduce_errors);
		if (type == 'Z') break;
	}
	return out;
}

// ---------------------------------------------------------------------------
// Native-path verification via the proxysql log (coverage truthfulness): a
// case only counts as "native" if no libpq-fallback warning appeared during
// its proxy leg. Same drain/scan pattern as pgsql-native_prepared-t.
// ---------------------------------------------------------------------------
static std::fstream f_proxysql_log{};

static void drainLogToNow() {
	get_matching_lines(f_proxysql_log, "__no_such_marker_line__");
}

static bool nativeFallbackObserved() {
	// Matches the connection-level auth-capability-gap fallback and any future
	// extended-query "falling back to libpq" warning.
	const std::string re = ".*falling back to libpq.*";
	return wait_for_log_match(f_proxysql_log, re, 500, 100);
}

// Read messages until 'Z' but return the raw (type,payload) list — used by the
// libpq-mode reject case which asserts on the full error text, not just SQLSTATE.
static std::vector<std::pair<char, std::vector<uint8_t>>> collectRaw(PgConnection& c) {
	std::vector<std::pair<char, std::vector<uint8_t>>> msgs;
	char type;
	std::vector<uint8_t> buf;
	while (true) {
		c.readMessage(type, buf);
		msgs.emplace_back(type, buf);
		if (type == 'Z') break;
	}
	return msgs;
}

// ---------------------------------------------------------------------------
// Corpus scripts. Each takes a live PgConnection and returns the normalized,
// client-visible backend message sequence for the whole case (concatenated
// across every Sync / simple-query boundary the script drives).
// pg_lite_client's *(..., send_sync=false)* overloads emit ONLY the frontend
// message with no implicit Sync/drain, so we control framing exactly.
// ---------------------------------------------------------------------------
using ScriptFn = std::string(*)(PgConnection&);

// Case 1: Parse s1 -> Bind p1 -> Describe('P',p1) -> Execute(p1,0) -> Close('P',p1) -> Sync
static std::string script_basic(PgConnection& c) {
	c.prepareStatement("s1", "SELECT $1::int", false);
	c.bindStatement("s1", "p1", {{std::string("7"), 0}}, {}, false);
	c.describePortal("p1", false);
	c.executePortal("p1", 0, false);
	c.closePortal("p1", false);
	c.sendSync();
	return collectUntilReady(c);
}

// Case 2: two portals over one statement, executed interleaved (p2 then p1),
// all inside one implicit transaction (single frame) so both portals live.
static std::string script_multi(PgConnection& c) {
	c.prepareStatement("s1", "SELECT $1::int", false);
	c.bindStatement("s1", "p1", {{std::string("10"), 0}}, {}, false);
	c.bindStatement("s1", "p2", {{std::string("20"), 0}}, {}, false);
	c.executePortal("p2", 0, false);
	c.executePortal("p1", 0, false);
	c.sendSync();
	return collectUntilReady(c);
}

// Case 3: max_rows suspend/resume over a 5-row portal.
//   Execute(p1,2) -> D,D,s ; Execute(p1,2) -> D,D,s ; Execute(p1,0) -> D,C
static std::string script_suspend(PgConnection& c) {
	c.prepareStatement("s1", "SELECT g FROM generate_series(1,5) g", false);
	c.bindStatement("s1", "p1", {}, {}, false);
	c.executePortal("p1", 2, false);
	c.executePortal("p1", 2, false);
	c.executePortal("p1", 0, false);
	c.sendSync();
	return collectUntilReady(c);
}

// Case 4: portal survives Sync inside an explicit txn; dies at COMMIT.
static std::string script_txn(PgConnection& c) {
	std::string out;
	c.execute("BEGIN");                 // Frame 1
	out += collectUntilReady(c);
	c.prepareStatement("s1", "SELECT $1::int", false);   // Frame 2: Parse+Bind+Sync
	c.bindStatement("s1", "p1", {{std::string("5"), 0}}, {}, false);
	c.sendSync();
	out += collectUntilReady(c);
	c.executePortal("p1", 0, false);    // Frame 3: portal survived the Sync
	c.sendSync();
	out += collectUntilReady(c);
	c.execute("COMMIT");                // Frame 4: portals destroyed at txn end
	out += collectUntilReady(c);
	c.executePortal("p1", 0, false);    // Frame 5: undefined cursor
	c.sendSync();
	// reduce_errors: the proxy SYNTHESIZES this undefined-cursor ErrorResponse
	// (registry miss) — compare at SQLSTATE level (normalization #2).
	out += collectUntilReady(c, /*reduce_errors=*/true);
	return out;
}

// Case 5: bind outside a txn, Sync ends the implicit txn and destroys the
// portal; the next-frame Execute must fail with undefined-cursor.
static std::string script_sync_destroy(PgConnection& c) {
	std::string out;
	c.prepareStatement("s1", "SELECT $1::int", false);   // Frame 1: Parse+Bind+Sync
	c.bindStatement("s1", "p1", {{std::string("5"), 0}}, {}, false);
	c.sendSync();
	out += collectUntilReady(c);
	c.executePortal("p1", 0, false);    // Frame 2: portal gone
	c.sendSync();
	// reduce_errors: synthesized undefined-cursor (registry miss), see script_txn.
	out += collectUntilReady(c, /*reduce_errors=*/true);
	return out;
}

// Case 6: Close of a non-existent portal is idempotent (bare CloseComplete).
static std::string script_close_idempotent(PgConnection& c) {
	c.closePortal("does_not_exist", false);
	c.sendSync();
	return collectUntilReady(c);
}

// Case 7: bind the same portal name twice without closing (one implicit txn).
static std::string script_bind_dup(PgConnection& c) {
	c.prepareStatement("s1", "SELECT $1::int", false);
	c.bindStatement("s1", "p1", {{std::string("1"), 0}}, {}, false);
	c.bindStatement("s1", "p1", {{std::string("2"), 0}}, {}, false);
	c.sendSync();
	return collectUntilReady(c);
}

// Case 10 (PORTAL_STMT_LAST_OWNER): the client closes the STATEMENT while its
// portal still lives, then executes the portal. PostgreSQL keeps a portal valid
// after its source statement is closed, so Execute must still return the row on
// both legs. On the proxy side this makes the portal's registry entry the LAST
// shared_ptr owner of the statement info; the Sync's implicit-txn end then
// destroys the portal and drops that final reference in the rc0 teardown — the
// exact ordering d561b767c fixed (clear_named_portals() deferred until AFTER
// RequestEnd()/LogQuery() has read digest/query text/stmt_client_name for the
// eventslog). NOTE: the UAF this guards against historically fired only under
// ASAN (on a lucky heap a plain build reads freed-but-intact bytes and the
// differential still passes), so this case's primary value is making the path
// EXIST — statement-closed + last-owner portal teardown + eventslog active —
// for future ASAN runs; the runner block adds an uptime/no-restart assertion
// for the plain-build crash-grade failure mode.
static std::string script_stmt_last_owner(PgConnection& c) {
	c.prepareStatement("s1", "SELECT $1::int", false);
	c.bindStatement("s1", "p1", {{std::string("9"), 0}}, {}, false);
	c.closeStatement("s1", false);      // statement closed, portal p1 survives
	c.executePortal("p1", 0, false);    // must still return the row
	c.sendSync();                       // implicit-txn end: portal + last stmt ref dropped
	return collectUntilReady(c);
}

// Unnamed extended-query cycle (case 9 payload).
static std::string script_unnamed(PgConnection& c) {
	c.prepareStatement("", "SELECT $1::int", false);
	c.bindStatement("", "", {{std::string("5"), 0}}, {}, false);
	c.describePortal("", false);
	c.executePortal("", 0, false);
	c.sendSync();
	return collectUntilReady(c);
}

// ---------------------------------------------------------------------------
// Differential driver: run `fn` on the backend (oracle) and through the proxy
// (native), compare normalized sequences.
// ---------------------------------------------------------------------------
static OpRecord runDifferential(const std::string& label, const std::string& kind, ScriptFn fn) {
	std::string a, b;
	bool ran = false;
	try {
		auto ca = connectBackend();
		a = fn(*ca);
		ca->disconnect();
		drainLogToNow();  // scope the fallback scan to THIS case's proxy leg
		auto cb = connectProxy();
		b = fn(*cb);
		cb->disconnect();
		ran = true;
	} catch (const PgException& e) {
		return {label, kind, false, false, std::string("exception: ") + e.what()};
	}
	// Coverage truthfulness: "native" is VERIFIED from the proxysql log (no
	// libpq-fallback warning during the proxy leg), not assumed.
	bool fell_back = nativeFallbackObserved();
	bool match = ran && (a == b);
	std::string detail = "backend='" + a + "'";
	if (!match) detail += " proxy='" + b + "'";
	return {label, kind, match, !fell_back, detail};
}

int main(int /*argc*/, char** /*argv*/) {
	plan(1 /*smoke*/ + 10 /*corpus records*/ + 1 /*coverage summary*/ + 1 /*multiplexing*/);
	if (cl.getEnv()) return exit_status();

	PGConnPtr admin = open_admin_conn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
		BAIL_OUT("admin connect failed");
		return exit_status();
	}
	std::vector<ServerRow> saved = readServers(admin.get(), BACKEND_HG);
	if (saved.empty()) {
		BAIL_OUT("No pgsql_servers in hostgroup %d", BACKEND_HG);
		return exit_status();
	}
	diag("Backend (leg A, SCRAM): %s:%d  |  Proxy (leg B, cleartext): %s:%d",
	     cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_host, cl.pgsql_port);

	// Open the proxysql log for the native-fallback tripwire (FIX 4) BEFORE the
	// auth scope: BAIL_OUT skips destructors, so nothing that must be undone may
	// precede a bail-able step without an explicit restore.
	std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS) {
		BAIL_OUT("Cannot open ProxySQL log at %s", log_path.c_str());
		return exit_status();
	}

	AuthMethodScope auth_scope(admin.get());
	if (!auth_scope.ok) {
		auth_scope.restore();  // BAIL_OUT is exit(255): destructor never runs
		BAIL_OUT("failed to force frontend cleartext (pgsql-authentication_method=1)");
		return exit_status();
	}

	// ---- P3.1 smoke: raw client SCRAM-connects DIRECTLY to the backend ----
	{
		bool smoke_ok = false;
		std::string detail;
		try {
			auto c = connectBackend();
			c->execute("SELECT 1");
			auto res = c->readResult();
			smoke_ok = (res->rowCount() == 1 && res->columnCount() == 1 &&
			            std::get<std::string>(res->getValue(0, 0)) == "1");
			c->disconnect();
		} catch (const PgException& e) { detail = e.what(); }
		ok(smoke_ok, "P3.1 SCRAM smoke: direct-backend SELECT 1 round-trips%s%s",
		   detail.empty() ? "" : " -- ", detail.c_str());
	}

	// ---- Native mode + fresh native-only pool for the differential corpus ----
	if (!setNativeMode(admin.get(), true) || !flushBackendPool(admin.get(), BACKEND_HG, saved)) {
		auth_scope.restore();  // BAIL_OUT is exit(255): destructor never runs
		BAIL_OUT("failed to enable native mode / flush pool");
		return exit_status();
	}

	CoverageRecorder cov;

	// Cases 1-7: direct-vs-proxy differentials.
	cov.record(runDifferential("PORTAL_BASIC: Parse+Bind+Describe(P)+Execute+Close+Sync",
		"PORTAL_BASIC", script_basic));
	cov.record(runDifferential("PORTAL_MULTI: p1,p2 over one stmt, Execute p2 then p1",
		"PORTAL_MULTI", script_multi));
	cov.record(runDifferential("PORTAL_SUSPEND: Execute(max_rows=2) x2 + Execute(0) over 5 rows",
		"PORTAL_SUSPEND", script_suspend));
	cov.record(runDifferential("PORTAL_TXN: portal survives Sync in txn, dies at COMMIT",
		"PORTAL_TXN", script_txn));
	cov.record(runDifferential("PORTAL_SYNC_DESTROY: implicit-txn Sync destroys portal",
		"PORTAL_SYNC_DESTROY", script_sync_destroy));
	cov.record(runDifferential("PORTAL_CLOSE_IDEMPOTENT: Close(P,nonexistent)->CloseComplete",
		"PORTAL_CLOSE_IDEMPOTENT", script_close_idempotent));
	cov.record(runDifferential("PORTAL_ERR_BIND_DUP: Bind same portal twice, no close",
		"PORTAL_ERR_BIND_DUP", script_bind_dup));

	// ---- Case 10: statement closed while its portal lives (last-owner teardown
	// path through the d561b767c-fixed rc0 ordering), with the EVENTSLOG ACTIVE
	// so LogQuery's format=2 JSON writer actually reads stmt_client_name/digest
	// before the deferred clear frees the registry entry. The infra defaults
	// eventslog_default_log=1/format=2 (docker-pgsql16-single config.sql); we
	// verify and force+restore if a prior run left them off. Also asserts
	// proxysql did NOT crash/restart across the case (ProxySQL_Uptime monotonic)
	// — see the script's comment on why the differential alone is not enough. ----
	{
		const std::string q_ev_log =
			"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-eventslog_default_log'";
		const std::string q_ev_fmt =
			"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-eventslog_format'";
		const std::string q_uptime =
			"SELECT Variable_Value FROM stats_pgsql_global WHERE Variable_Name='ProxySQL_Uptime'";
		std::string ev_log = adminScalar(admin.get(), q_ev_log);
		std::string ev_fmt = adminScalar(admin.get(), q_ev_fmt);
		bool ev_forced = false;
		if (ev_log != "1" || ev_fmt != "2") {
			ev_forced = execAdmin(admin.get(), "SET pgsql-eventslog_default_log=1") &&
			            execAdmin(admin.get(), "SET pgsql-eventslog_format=2") &&
			            execAdmin(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
		}
		diag("PORTAL_STMT_LAST_OWNER: eventslog default_log=%s format=%s%s",
		     ev_log.c_str(), ev_fmt.c_str(), ev_forced ? " (forced on for this case)" : "");
		long uptime_before = atol(adminScalar(admin.get(), q_uptime).c_str());
		OpRecord rec = runDifferential(
			"PORTAL_STMT_LAST_OWNER: Close('S') with portal open, Execute, Sync teardown (eventslog on)",
			"PORTAL_STMT_LAST_OWNER", script_stmt_last_owner);
		long uptime_after = atol(adminScalar(admin.get(), q_uptime).c_str());
		// A crash would restart proxysql (angel) and reset the uptime counter.
		bool no_restart = (uptime_before > 0 && uptime_after >= uptime_before);
		if (!no_restart) {
			rec.result_match = false;
			rec.detail += " (proxysql RESTARTED during case: uptime " +
				std::to_string(uptime_before) + " -> " + std::to_string(uptime_after) + ")";
		} else {
			rec.detail += " uptime_monotonic=" + std::to_string(uptime_before) + "->" +
				std::to_string(uptime_after);
		}
		if (ev_forced) {  // restore only what we changed
			execAdmin(admin.get(), "SET pgsql-eventslog_default_log=" + (ev_log.empty() ? "0" : ev_log));
			execAdmin(admin.get(), "SET pgsql-eventslog_format=" + (ev_fmt.empty() ? "1" : ev_fmt));
			execAdmin(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
		}
		cov.record(rec);
	}

	// ---- Case 4 addendum: multiplexing pin release, asserted NON-vacuously.
	// The raw client STAYS CONNECTED AND IDLE while we watch the admin stats:
	//   * during the explicit txn (portal p1 bound, Sync'd) the backend conn is
	//     attached to the session -> SUM(ConnUsed)=1 for the hostgroup;
	//   * after COMMIT completes, the txn ended AND the txn-'I' clear destroyed
	//     the named portal, so the sticky portal pin must release and the conn
	//     return to the pool -> SUM(ConnUsed) drops to 0 WHILE the client is
	//     still connected.
	// If the pin release were broken (e.g. named_portals surviving the txn-'I'
	// clear kept sticky_backend_connection true), ConnUsed would stay 1 for the
	// whole 5s window and this fails. The client disconnects only AFTER the
	// poll, so session teardown cannot fake the release (the previous version
	// polled after disconnect, which passes regardless — vacuous).
	{
		int used_in_txn = -1, used_after = -1;
		bool released = false;
		std::string err;
		auto pollConnUsed = [&](void) -> int {
			std::string v = adminScalar(admin.get(),
				"SELECT SUM(ConnUsed) FROM stats_pgsql_connection_pool WHERE hostgroup="
				+ std::to_string(BACKEND_HG));
			return v.empty() ? -1 : atoi(v.c_str());
		};
		try {
			auto c = connectProxy();
			c->execute("BEGIN");
			c->consumeInputUntilReady();
			c->prepareStatement("s1", "SELECT $1::int", false);
			c->bindStatement("s1", "p1", {{std::string("5"), 0}}, {}, false);
			c->sendSync();
			c->consumeInputUntilReady();
			used_in_txn = pollConnUsed();          // expect 1: pinned by open txn+portal
			c->execute("COMMIT");
			c->consumeInputUntilReady();
			for (int i = 0; i < 50; i++) {         // bounded window: <= 5s
				used_after = pollConnUsed();
				if (used_after == 0) { released = true; break; }
				usleep(100000);
			}
			c->disconnect();                       // AFTER the poll — see above
		} catch (const PgException& e) { err = e.what(); }
		ok(released && used_in_txn == 1,
		   "Multiplexing pin release: ConnUsed %d (in txn, portal bound) -> %d within 5s of "
		   "COMMIT+portal-invalidation, client still connected%s%s",
		   used_in_txn, used_after, err.empty() ? "" : " -- ", err.c_str());
	}

	// ---- Case 8: libpq-mode named-Bind reject (leg B only, regression guard
	// for invariant 1). Named Bind -> FEATURE_NOT_SUPPORTED (0A000) with the
	// byte-exact "only unnamed portals are supported" message. ----
	{
		bool reject_ok = false;
		std::string detail;
		if (setNativeMode(admin.get(), false) && flushBackendPool(admin.get(), BACKEND_HG, saved)) {
			try {
				auto c = connectProxy();
				c->prepareStatement("s1", "SELECT $1::int", false);
				c->bindStatement("s1", "p1", {{std::string("1"), 0}}, {}, false);
				c->sendSync();
				auto msgs = collectRaw(*c);
				c->disconnect();
				std::string sqlstate, msg;
				for (auto& m : msgs) {
					if (m.first == 'E') {
						sqlstate = errSqlstate(m.second);
						// extract 'M' (message) field
						size_t i = 0;
						while (i < m.second.size() && m.second[i] != 0) {
							char field = (char)m.second[i++];
							std::string val;
							while (i < m.second.size() && m.second[i] != 0) val += (char)m.second[i++];
							if (i < m.second.size()) i++;
							if (field == 'M') msg = val;
						}
					}
				}
				reject_ok = (sqlstate == "0A000" && msg == "only unnamed portals are supported");
				detail = "sqlstate='" + sqlstate + "' msg='" + msg + "'";
			} catch (const PgException& e) { detail = std::string("exception: ") + e.what(); }
		} else {
			detail = "admin: set libpq mode failed";
		}
		cov.record({"PORTAL_LIBPQ_MODE_REJECTS: named Bind -> FEATURE_NOT_SUPPORTED (libpq mode)",
			"PORTAL_LIBPQ_MODE_REJECTS", reject_ok, false, detail});
	}

	// ---- Case 9: unnamed flow client-visible sequence is byte-identical
	// between native and libpq ProxySQL (the P1/P2 changes must not perturb the
	// unnamed single-slot flow — invariant 2, seen from the client). ----
	{
		std::string native_seq, libpq_seq, detail;
		bool eq = false;
		bool fell_back = true;  // pessimistic until the native phase is log-verified
		try {
			if (setNativeMode(admin.get(), true) && flushBackendPool(admin.get(), BACKEND_HG, saved)) {
				drainLogToNow();  // scope the fallback scan to the native phase
				auto c = connectProxy();
				native_seq = script_unnamed(*c);
				c->disconnect();
				fell_back = nativeFallbackObserved();
			}
			if (setNativeMode(admin.get(), false) && flushBackendPool(admin.get(), BACKEND_HG, saved)) {
				auto c = connectProxy();
				libpq_seq = script_unnamed(*c);
				c->disconnect();
			}
			eq = !native_seq.empty() && (native_seq == libpq_seq);
			detail = "native='" + native_seq + "'";
			if (!eq) detail += " libpq='" + libpq_seq + "'";
		} catch (const PgException& e) { detail = std::string("exception: ") + e.what(); }
		cov.record({"PORTAL_UNNAMED_UNCHANGED: native==libpq client-visible unnamed cycle",
			"PORTAL_UNNAMED_UNCHANGED", eq, !fell_back, detail});
	}

	// Restore defaults.
	setNativeMode(admin.get(), false);
	flushBackendPool(admin.get(), BACKEND_HG, saved);

	cov.emit_tap();
	return exit_status();
}
