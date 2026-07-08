/**
 * @file pgsql-native_cancel-t.cpp
 * @brief Differential test for PostgreSQL query cancellation: libpq oracle vs native backend.
 *
 * The design spec (docs/superpowers/specs/2026-06-11-pgsql-native-protocol-design.md
 * §4) requires that in native backend mode ProxySQL cancels an in-flight
 * backend query by opening a fresh connection and sending a raw CancelRequest
 * with the stored (pid, secret) from BackendKeyData — matching what libpq's
 * PQcancel does in libpq mode.
 *
 * This test drives an identical client-visible cancellation flow in BOTH modes
 * and asserts the outcomes are the same:
 *   - a long `SELECT pg_sleep(30)` is started through ProxySQL,
 *   - a frontend CancelRequest is fired via PQcancel() on the client conn,
 *   - the query must abort with SQLSTATE 57014 ("canceling statement due to
 *     user request") within a tight time bound (nowhere near 30s),
 *   - the client session must remain usable afterwards (SELECT 1 succeeds),
 *   - the backend query must actually be gone (checked on a DIRECT connection
 *     to the backend via pg_stat_activity).
 *
 * The libpq phase runs first and establishes the bar. The native phase must
 * match it AND must not have silently fallen back to libpq (log tripwire).
 *
 * Empirical bar (recorded at authoring time, INFRA_ID=dev-rene-natproto):
 *   libpq mode  -> 57014, cancelled in ~2s, connection reusable.
 *   native mode (pre-fix) -> "Failed to cancel query ... backend PID 0",
 *                            query ran the full 30s (the gap this closes).
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <fstream>
#include <regex>
#include <atomic>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
static const int BACKEND_HG = 0;
static std::fstream f_proxysql_log{};
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// A distinctive marker embedded in the long query so the DIRECT backend check
// can find (and exclude its own detection query from) pg_stat_activity.
static const char* SLEEP_MARK = "natcancel_sleep";

static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host
	   << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username
	   << " password=" << cl.admin_password;
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr open_client_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host
	   << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username
	   << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username
	   << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

// Direct (bypass-ProxySQL) connection to a backend host:port, used to observe
// pg_stat_activity and confirm the cancelled query really left the backend.
static PGConnPtr open_direct_backend_conn(const std::string& host, const std::string& port) {
	std::stringstream ss;
	ss << "host=" << host
	   << " port=" << port
	   << " user=" << cl.pgsql_username
	   << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username
	   << " sslmode=disable";
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

// Drop all pooled backend connections for the hostgroup so the NEXT client
// query is served by a FRESH backend connection created in the current mode
// (native vs libpq). Without this a stale pooled libpq connection could serve
// the native phase and mask the native cancel path entirely.
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
	usleep(300000);
	return true;
}

// Single-pass scan of the proxysql log for BOTH the libpq-fallback tripwire
// (any match in the native phase is a regression) AND the positive evidence
// that the native cancel branch actually ran: the
// "Canceled query (native) on ... successfully" warning that
// PgSQL_backend_kill_thread emits only from the raw-CancelRequest path.
// A single combined scan is required because wait_for_log_match /
// get_matching_lines consume the stream forward — two sequential scans for two
// different regexes would each miss lines the other already read past (same
// reasoning as scanNativePhaseLog in pgsql-native_prepared-t). Polls until the
// native-cancel line is seen or wait_ms elapses; the fallback flag reflects
// everything read either way.
static void scanNativePhaseLog(bool& fell_back, bool& native_cancel_logged, uint32_t wait_ms) {
	const std::regex re_fallback(".*falling back to libpq.*");
	const std::regex re_native_cancel(".*Canceled query \\(native\\) on .* successfully.*");
	fell_back = false;
	native_cancel_logged = false;
	uint32_t elapsed = 0;
	while (true) {
		// Clear eof/fail so getline() can read bytes appended since the last scan.
		f_proxysql_log.clear(f_proxysql_log.rdstate() &
		                     ~std::ios_base::eofbit & ~std::ios_base::failbit);
		std::string line;
		while (std::getline(f_proxysql_log, line)) {
			if (!fell_back && std::regex_match(line, re_fallback)) fell_back = true;
			if (!native_cancel_logged && std::regex_match(line, re_native_cancel)) native_cancel_logged = true;
		}
		if (native_cancel_logged || elapsed >= wait_ms) return;
		usleep(100000);
		elapsed += 100;
	}
}

static void drainLogToNow() {
	get_matching_lines(f_proxysql_log, "__no_such_marker_line__");
}

// Count active backend sessions still running our marked pg_sleep, observed
// directly on the backend (bypassing ProxySQL). Excludes this detection query.
static int countActiveSleep(PGconn* direct) {
	if (!direct || PQstatus(direct) != CONNECTION_OK) return -1;
	std::string q =
		"SELECT count(*) FROM pg_stat_activity WHERE state='active' "
		"AND query LIKE '%" + std::string(SLEEP_MARK) + "%' "
		"AND query NOT LIKE '%pg_stat_activity%'";
	PGresult* res = PQexec(direct, q.c_str());
	int n = -1;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1)
		n = atoi(PQgetvalue(res, 0, 0));
	PQclear(res);
	return n;
}

struct PhaseResult {
	bool started_ok = false;
	bool canceled_57014 = false;   // query aborted with SQLSTATE 57014
	std::string sqlstate;          // observed sqlstate (empty if none)
	double elapsed_s = 0.0;        // wall time from cancel-fire to query return
	bool conn_usable_after = false;// SELECT 1 works on the same conn afterwards
	int backend_active_after = -1; // active marked sleeps on the direct backend
	bool fell_back = false;        // native phase only: libpq fallback observed
	bool native_cancel_logged = false; // native phase only: positive "Canceled query (native)" log evidence
};

// Threaded long-query state.
struct QState {
	std::mutex m;
	std::condition_variable cv;
	bool started = false;
	bool done = false;
	ExecStatusType status = PGRES_EMPTY_QUERY;
	std::string sqlstate;
};

static void run_long_query(PGconn* conn, QState* qs) {
	{
		std::lock_guard<std::mutex> lk(qs->m);
		qs->started = true;
	}
	qs->cv.notify_all();
	std::string q = std::string("SELECT pg_sleep(30) /* ") + SLEEP_MARK + " */";
	PGresult* res = PQexec(conn, q.c_str());
	{
		std::lock_guard<std::mutex> lk(qs->m);
		qs->status = res ? PQresultStatus(res) : PGRES_FATAL_ERROR;
		const char* ss = res ? PQresultErrorField(res, PG_DIAG_SQLSTATE) : nullptr;
		qs->sqlstate = ss ? ss : "";
		qs->done = true;
	}
	if (res) PQclear(res);
	qs->cv.notify_all();
}

// Run one full cancellation cycle in the currently-configured mode.
static PhaseResult runPhase(PGconn* admin, bool native,
                            const std::vector<ServerRow>& saved) {
	PhaseResult pr;

	setNativeMode(admin, native);
	flushBackendPool(admin, BACKEND_HG, saved);
	drainLogToNow(); // so scanNativePhaseLog() only sees this phase

	PGConnPtr conn = open_client_conn();
	if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
		diag("client connect failed (%s phase): %s", native ? "native" : "libpq",
		     conn ? PQerrorMessage(conn.get()) : "null");
		return pr;
	}

	QState qs;
	std::thread th(run_long_query, conn.get(), &qs);

	// Wait for the query to have started on the wire.
	{
		std::unique_lock<std::mutex> lk(qs.m);
		qs.cv.wait_for(lk, std::chrono::seconds(5), [&]{ return qs.started; });
	}
	pr.started_ok = qs.started;
	// Give the backend a moment to actually be executing pg_sleep before cancel.
	usleep(1500000);

	// Fire the frontend CancelRequest (this is exactly PQcancel-over-ProxySQL,
	// the same client-visible path in both modes).
	auto t0 = std::chrono::steady_clock::now();
	PGcancel* cancel = PQgetCancel(conn.get());
	char errbuf[256] = {0};
	int crc = cancel ? PQcancel(cancel, errbuf, sizeof(errbuf)) : 0;
	if (cancel) PQfreeCancel(cancel);
	if (crc != 1) diag("PQcancel returned %d (%s phase): %s", crc, native ? "native" : "libpq", errbuf);

	// Wait for the query to return (bounded well under the 30s sleep).
	{
		std::unique_lock<std::mutex> lk(qs.m);
		qs.cv.wait_for(lk, std::chrono::seconds(15), [&]{ return qs.done; });
	}
	auto t1 = std::chrono::steady_clock::now();
	th.join();

	pr.elapsed_s = std::chrono::duration<double>(t1 - t0).count();
	pr.sqlstate = qs.sqlstate;
	pr.canceled_57014 = (qs.status == PGRES_FATAL_ERROR && qs.sqlstate == "57014");

	// Session must still be usable after a cancel.
	PGresult* r2 = PQexec(conn.get(), "SELECT 1");
	pr.conn_usable_after = (PQresultStatus(r2) == PGRES_TUPLES_OK &&
	                        PQntuples(r2) == 1 && std::string(PQgetvalue(r2, 0, 0)) == "1");
	PQclear(r2);

	// Backend must have released the query. Poll the DIRECT backend briefly.
	// NOTE: this infra (docker-pgsql16-single) has a single backend server —
	// hostgroup 0 and 1 both point at the same host:port — so checking
	// saved[0] covers the only backend the query could have landed on. If the
	// infra ever grows additional distinct backends, loop over `saved` here.
	PGConnPtr direct = open_direct_backend_conn(saved[0].hostname, saved[0].port);
	int active = -1;
	for (int i = 0; i < 20; i++) { // up to ~2s
		active = countActiveSleep(direct.get());
		if (active == 0) break;
		usleep(100000);
	}
	pr.backend_active_after = active;

	if (native) scanNativePhaseLog(pr.fell_back, pr.native_cancel_logged, 2000);

	return pr;
}

int main(int, char**) {
	// libpq: 4 asserts; native: 5 asserts; differential: 1 assert.
	plan(4 + 5 + 1);
	if (cl.getEnv()) return exit_status();

	std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS) {
		BAIL_OUT("Cannot open ProxySQL log at %s", log_path.c_str());
		return exit_status();
	}

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
	diag("Backend under test (hg %d): %s:%s", BACKEND_HG,
	     saved[0].hostname.c_str(), saved[0].port.c_str());

	// ---- Phase 1: libpq mode (the differential BAR) ----
	diag("=== Phase 1: libpq mode (oracle / bar) ===");
	PhaseResult lib = runPhase(admin.get(), /*native=*/false, saved);
	diag("libpq: started=%d sqlstate=%s elapsed=%.2fs usable=%d backend_active=%d",
	     lib.started_ok, lib.sqlstate.c_str(), lib.elapsed_s,
	     lib.conn_usable_after, lib.backend_active_after);

	ok(lib.canceled_57014,
	   "[libpq] query canceled with SQLSTATE 57014 (bar) — got '%s'", lib.sqlstate.c_str());
	ok(lib.started_ok && lib.elapsed_s < 10.0,
	   "[libpq] cancel took effect promptly (%.2fs, well under 30s sleep)", lib.elapsed_s);
	ok(lib.conn_usable_after,
	   "[libpq] client session usable after cancel (SELECT 1)");
	ok(lib.backend_active_after == 0,
	   "[libpq] backend query gone from pg_stat_activity (active=%d)", lib.backend_active_after);

	// ---- Phase 2: native mode (must MATCH the bar) ----
	diag("=== Phase 2: native backend mode ===");
	PhaseResult nat = runPhase(admin.get(), /*native=*/true, saved);
	diag("native: started=%d sqlstate=%s elapsed=%.2fs usable=%d backend_active=%d fell_back=%d native_cancel_logged=%d",
	     nat.started_ok, nat.sqlstate.c_str(), nat.elapsed_s,
	     nat.conn_usable_after, nat.backend_active_after, nat.fell_back,
	     nat.native_cancel_logged);

	ok(nat.canceled_57014,
	   "[native] query canceled with SQLSTATE 57014 — got '%s'", nat.sqlstate.c_str());
	ok(nat.started_ok && nat.elapsed_s < 10.0,
	   "[native] cancel took effect promptly (%.2fs, well under 30s sleep)", nat.elapsed_s);
	ok(nat.conn_usable_after,
	   "[native] client session usable after cancel (SELECT 1)");
	ok(nat.backend_active_after == 0,
	   "[native] backend query gone from pg_stat_activity (active=%d)", nat.backend_active_after);
	// Folded case result: absence of the libpq-fallback tripwire AND positive
	// evidence that the raw-CancelRequest branch ran ("Canceled query (native)"
	// is logged only from that branch in PgSQL_backend_kill_thread).
	ok(!nat.fell_back && nat.native_cancel_logged,
	   "[native] cancel exercised the NATIVE path (no libpq fallback%s; 'Canceled query (native)' logged=%s)",
	   nat.fell_back ? " VIOLATED" : "", nat.native_cancel_logged ? "yes" : "no");

	// ---- Differential: native must produce the identical client-visible outcome ----
	ok(lib.canceled_57014 && nat.canceled_57014 && lib.sqlstate == nat.sqlstate,
	   "[differential] libpq vs native identical cancel outcome (both %s)",
	   nat.sqlstate.c_str());

	// Restore native mode off for a clean shared runtime.
	setNativeMode(admin.get(), false);

	return exit_status();
}
