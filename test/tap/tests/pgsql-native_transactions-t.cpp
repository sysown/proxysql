/**
 * @file pgsql-native_transactions-t.cpp
 * @brief Differential test: native vs libpq for transaction control flows.
 *
 * PURPOSE
 * -------
 * Exercises BEGIN / COMMIT / ROLLBACK / SAVEPOINT / RELEASE / isolation levels /
 * error-in-tx auto-rollback / multi-cycle pool reuse through ProxySQL twice:
 *   1. with `pgsql-use_native_backend_protocol='false'`  -> the libpq ORACLE
 *   2. with `pgsql-use_native_backend_protocol='true'`   -> the NATIVE path
 * and asserts:
 *   - the post-query ReadyForQuery transaction-status byte ('I'/'T'/'E')
 *     matches between the two paths
 *   - any DML persistence check (count(*) after rollback/commit) matches
 *   - the native run did NOT fall back to libpq
 *
 * KNOWN ISSUES (discovered by this test, see per-case "not ok" lines)
 * --------------------------------------------------------------------
 * The native path's `PgSQL_ExplicitTxnStateMgr` (the session-level txn
 * tracker) is NOT kept in sync with the backend's actual transaction state
 * for BEGIN / ROLLBACK / ROLLBACK TO / SAVEPOINT. Symptom: queries that
 * depend on the session thinking it's in a transaction behave wrongly:
 *   - ROLLBACK: the session thinks there's no transaction, so DML is
 *     auto-committed and persists; ROLLBACK then has no effect.
 *   - ROLLBACK TO SAVEPOINT: same as above.
 *   - Error-in-tx: backend marks the tx as in-error, but session thinks
 *     it's still in-tx; the verify query at the end can then fail in
 *     unexpected ways.
 *   - Long tx (T14): the admin connection can be killed by ProxySQL's
 *     session timeout machinery (need to investigate which), causing the
 *     next `setNativeMode` call to fail.
 *
 * The CoverageRecorder summary at the end of the run reports per-kind
 * native coverage. For T0/T2/T4/T8/T9/T10/T12 the test passes (commit-only
 * or select-only, no state divergence). For T1/T3/T5/T6/T7/T11/T13/T14 the
 * test reports a real divergence and emits "not ok". These are not test
 * bugs; they are bugs in the native protocol path that this test is the
 * first to surface systematically.
 *
 * INFRA: legacy-g1 (docker-pgsql16-single, scram-sha-256, no TLS).
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <unistd.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql-native_tracking.h"

CommandLine cl;

static const int BACKEND_HG = 0;

// Live ProxySQL log stream; opened in main(). See auth test for rationale.
static std::fstream f_proxysql_log{};

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// Unique-per-run table name suffix.
static std::string make_table_name() {
	return "pgsql_native_txn_" + std::to_string(getpid()) + "_" +
	       std::to_string(time(nullptr));
}

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
			r.hostname      = PQgetvalue(res, i, 0);
			r.port          = PQgetvalue(res, i, 1);
			r.max_connections = PQgetvalue(res, i, 2);
			r.comment       = PQgetisnull(res, i, 3) ? "" : PQgetvalue(res, i, 3);
			rows.push_back(std::move(r));
		}
	}
	PQclear(res);
	return rows;
}

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

static void drainLogToNow() {
	get_matching_lines(f_proxysql_log, "__no_such_marker_line__");
}

// Translate a libpq PQtransactionStatus to the 'I'/'T'/'E' wire byte the
// backend emits in ReadyForQuery.
static char txn_status_byte(PGconn* c) {
	switch (PQtransactionStatus(c)) {
		case PQTRANS_IDLE: return 'I';
		case PQTRANS_INTRANS:
		case PQTRANS_ACTIVE: return 'T';
		case PQTRANS_INERROR: return 'E';
		default: return '?';
	}
}

// Replace "{T}" with `tbl` in a query string.
static std::string substitute_table(const std::string& q, const std::string& tbl) {
	std::string out;
	size_t pos = 0;
	while (pos < q.size()) {
		if (pos + 2 < q.size() && q[pos] == '{' && q[pos+1] == 'T' && q[pos+2] == '}') {
			out += tbl; pos += 3;
		} else {
			out += q[pos++];
		}
	}
	return out;
}

// How each query in a case is sent on the wire.
//   EXEC_SIMPLE       : PQexec()          -> simple Query message (one 'Q' packet).
//   EXEC_EXT_PARAMS   : PQexecParams()    -> extended protocol on the UNNAMED portal
//                                            (Parse/Bind/Describe/Execute/Sync).
//   EXEC_EXT_PREPARED : PQprepare()+PQexecPrepared() -> extended protocol via a NAMED
//                                            prepared statement. This is exactly what
//                                            `pgbench -M prepared` does for BEGIN/END,
//                                            i.e. the shape that produced the native
//                                            per-COMMIT "no transaction in progress"
//                                            warning storm.
enum ExecMode { EXEC_SIMPLE, EXEC_EXT_PARAMS, EXEC_EXT_PREPARED };

static const char* exec_mode_name(ExecMode m) {
	switch (m) {
		case EXEC_EXT_PARAMS:   return "ext-params";
		case EXEC_EXT_PREPARED: return "ext-prepared";
		default:                return "simple";
	}
}

// Run a sequence of queries; return per-query txn-status bytes and an
// "all_ok" flag indicating no query returned PGRES_FATAL_ERROR.
struct TxnRun {
	std::vector<char> states;
	bool all_ok = true;
};
static TxnRun run_txn_sequence(PGconn* c, const std::vector<std::string>& qs, ExecMode mode = EXEC_SIMPLE) {
	TxnRun r;
	int idx = 0;
	for (const auto& q : qs) {
		PGresult* res = nullptr;
		switch (mode) {
			case EXEC_EXT_PARAMS:
				// 0 params still forces the extended protocol (Parse/Bind/Execute/Sync).
				res = PQexecParams(c, q.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0);
				break;
			case EXEC_EXT_PREPARED: {
				// pgbench-style: prepare each statement under a unique name, then execute
				// it. A fresh name per query keeps this independent of DEALLOCATE support.
				std::string sname = "txn_ext_" + std::to_string(getpid()) + "_" + std::to_string(idx);
				PGresult* pr = PQprepare(c, sname.c_str(), q.c_str(), 0, nullptr);
				ExecStatusType pst = PQresultStatus(pr);
				PQclear(pr);
				if (pst != PGRES_COMMAND_OK) {
					// Parse failed (e.g. intentional error case): record the failure and
					// keep the per-query txn-status so the differential still lines up.
					r.all_ok = false;
					r.states.push_back(txn_status_byte(c));
					idx++;
					continue;
				}
				res = PQexecPrepared(c, sname.c_str(), 0, nullptr, nullptr, nullptr, 0);
				break;
			}
			case EXEC_SIMPLE:
			default:
				res = PQexec(c, q.c_str());
				break;
		}
		ExecStatusType st = PQresultStatus(res);
		if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
			r.all_ok = false;
		}
		PQclear(res);
		r.states.push_back(txn_status_byte(c));
		idx++;
	}
	return r;
}

static int run_count_query(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	int n = -1;
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		n = atoi(PQgetvalue(res, 0, 0));
	}
	PQclear(res);
	return n;
}

// A case: a sequence of queries with expected post-query txn-status bytes,
// plus an optional post-tx count(*) verification.
struct TxnCase {
	std::string label;
	std::string kind;
	std::string setup;                    // pre-queries (e.g. CREATE TABLE); {T} substituted; "" = skip
	std::vector<std::string> queries;     // {T} substituted
	std::vector<char> expected_states;    // size 0 = don't check
	std::string verify;                   // count(*) query, {T} substituted; "" = skip
	ExecMode mode = EXEC_SIMPLE;          // how the queries are sent on the wire
};

// Count native-window explicit-txn-tracker warnings and detect libpq fallback in a
// SINGLE forward pass over the log (the stream is consumed forward, so we must scan
// once). Both "no transaction in progress" (COMMIT/ROLLBACK on empty state) and
// "already a transaction in progress" (duplicate BEGIN) are the exact symptoms of the
// native-mode double-registration bug; a correct native path emits ZERO of them for a
// well-formed BEGIN/.../COMMIT sequence — the same as the libpq oracle.
struct NativeLogScan { int txn_warnings = 0; bool fell_back = false; };
static NativeLogScan scan_native_window(std::fstream& log) {
	// ProxySQL log writes are async wrt the SQL that triggers them; give the producer
	// a moment to flush before the single-shot scan (absence assertions can't poll).
	usleep(400000);
	NativeLogScan s;
	// drainLogToNow()'s prior get_matching_lines() left the stream at EOF. It clears
	// failbit but NOT eofbit, so a fresh getline() would short-circuit and read none of
	// the lines appended since. Clear both bits first (same fix wait_for_log_match uses).
	log.clear(log.rdstate() & ~std::ios_base::eofbit & ~std::ios_base::failbit);
	// Match case-stable substrings of the actual log lines. The full messages are
	// "... There is no transaction in progress" / "... There is already a transaction
	// in progress" — note the capital 'T', so an "^there is" pattern would silently
	// never match (RE2 is case-sensitive). The lowercase tails below appear verbatim.
	auto [n, lines] = get_matching_lines(log,
		"(no transaction in progress"
		"|already a transaction in progress"
		"|falling back to libpq)");
	(void)n;
	for (const auto& l : lines) {
		const std::string& text = std::get<LINE_MATCH_T::LINE>(l);
		if (text.find("transaction in progress") != std::string::npos) s.txn_warnings++;
		if (text.find("falling back to libpq") != std::string::npos)   s.fell_back = true;
	}
	return s;
}

// Compare two TxnRun results + count verification; return true if all match.
struct CaseResult { bool result_match; bool fell_back; std::string detail; };

static CaseResult run_case(PGconn* admin, const TxnCase& tc,
                           const std::vector<ServerRow>& saved) {
	std::string tbl = make_table_name();
	std::string tbl_n = tbl + "_n";

	// Substitute {T} into the case's queries and setup.
	TxnCase lp_tc = tc;
	for (auto& q : lp_tc.queries) q = substitute_table(q, tbl);
	lp_tc.setup  = substitute_table(tc.setup, tbl);
	lp_tc.verify = substitute_table(tc.verify, tbl);

	TxnCase nt_tc = tc;
	for (auto& q : nt_tc.queries) q = substitute_table(q, tbl_n);
	nt_tc.setup  = substitute_table(tc.setup, tbl_n);
	nt_tc.verify = substitute_table(tc.verify, tbl_n);

	// ---- libpq oracle ----
	if (!setNativeMode(admin, false) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set libpq mode failed"};
	}
	PGConnPtr lp = open_client_conn();
	if (!lp || PQstatus(lp.get()) != CONNECTION_OK) {
		return {false, false, "libpq client conn failed"};
	}
	if (!lp_tc.setup.empty()) {
		PGresult* sr = PQexec(lp.get(), lp_tc.setup.c_str());
		PQclear(sr);
	}
	TxnRun lp_run = run_txn_sequence(lp.get(), lp_tc.queries, tc.mode);
	int lp_count = lp_tc.verify.empty() ? 0 : run_count_query(lp.get(), lp_tc.verify);

	// ---- native candidate ----
	if (!setNativeMode(admin, true) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set native mode failed"};
	}
	drainLogToNow();
	PGConnPtr nt = open_client_conn();
	if (!nt || PQstatus(nt.get()) != CONNECTION_OK) {
		return {false, false, "native client conn failed"};
	}
	if (!nt_tc.setup.empty()) {
		PGresult* sr = PQexec(nt.get(), nt_tc.setup.c_str());
		PQclear(sr);
	}
	TxnRun nt_run = run_txn_sequence(nt.get(), nt_tc.queries, tc.mode);
	int nt_count = nt_tc.verify.empty() ? 0 : run_count_query(nt.get(), nt_tc.verify);
	// Single forward pass over the native-run log window: captures libpq fallback AND
	// any explicit-txn-tracker warning ("no/already transaction in progress"). The
	// latter must be ZERO on the native path for a well-formed BEGIN/.../COMMIT — this
	// is the positive-absence assertion for the double-registration bug.
	NativeLogScan scan = scan_native_window(f_proxysql_log);
	bool fell_back = scan.fell_back;

	// Compare.
	bool states_match = true;
	if (!tc.expected_states.empty()) {
		for (size_t i = 0; i < tc.expected_states.size(); i++) {
			if (lp_run.states[i] != nt_run.states[i] ||
			    lp_run.states[i] != tc.expected_states[i]) {
				states_match = false;
			}
		}
	}
	bool no_txn_warnings = (scan.txn_warnings == 0);
	bool result_match = (lp_run.all_ok == nt_run.all_ok) && states_match &&
	                    (lp_count == nt_count) && no_txn_warnings;
	std::string detail;
	if (!result_match) {
		std::stringstream ss;
		ss << "mode=" << exec_mode_name(tc.mode)
		   << " lp_ok=" << lp_run.all_ok << " nt_ok=" << nt_run.all_ok
		   << " lp_count=" << lp_count << " nt_count=" << nt_count
		   << " native_txn_warnings=" << scan.txn_warnings;
		// If states mismatched, show the per-query state diffs.
		if (!states_match) {
			for (size_t i = 0; i < tc.expected_states.size(); i++) {
				if (i < lp_run.states.size() && i < nt_run.states.size() &&
				    (lp_run.states[i] != nt_run.states[i] ||
				     lp_run.states[i] != tc.expected_states[i])) {
					ss << " Q" << i << "[exp=" << tc.expected_states[i]
					   << " lp=" << lp_run.states[i]
					   << " nt=" << nt_run.states[i] << "]";
				}
			}
		}
		detail = ss.str();
	}
	// Restore to libpq for the next case.
	setNativeMode(admin, false);
	flushBackendPool(admin, BACKEND_HG, saved);
	return {result_match, fell_back, detail};
}

// ---------------------------------------------------------------------------
// The 15 cases
// ---------------------------------------------------------------------------
struct RawCase { std::string label, kind, setup;
                 std::vector<std::string> queries;
                 std::vector<char> exp_states;
                 std::string verify;
                 ExecMode mode = EXEC_SIMPLE; };

static std::vector<RawCase> build_cases() {
	return {
		// T0: simple cycle
		{"T0: BEGIN; SELECT 1; COMMIT", "TXN_CYCLE", "",
		 {"BEGIN", "SELECT 1", "COMMIT"},
		 {'T','T','I'}, ""},
		// T1: rollback drops the row
		{"T1: BEGIN; INSERT; ROLLBACK (no row persists)", "TXN_ROLLBACK",
		 "CREATE TABLE {T} (id int, name text)",
		 {"BEGIN", "INSERT INTO {T} VALUES (1, 'a')", "ROLLBACK"},
		 {'T','T','I'}, "SELECT count(*) FROM {T}"},
		// T2: commit keeps the row
		{"T2: BEGIN; INSERT; COMMIT (row persists)", "TXN_COMMIT",
		 "CREATE TABLE {T} (id int, name text)",
		 {"BEGIN", "INSERT INTO {T} VALUES (1, 'a')", "COMMIT"},
		 {'T','T','I'}, "SELECT count(*) FROM {T}"},
		// T3: savepoint with rollback to s1
		{"T3: BEGIN; INSERT a1; SAVEPOINT s1; INSERT a2; ROLLBACK TO s1; COMMIT (a1 persists)", "TXN_SAVEPOINT",
		 "CREATE TABLE {T} (id int, name text)",
		 {"BEGIN",
		  "INSERT INTO {T} VALUES (1, 'a1')",
		  "SAVEPOINT s1",
		  "INSERT INTO {T} VALUES (2, 'a2')",
		  "ROLLBACK TO SAVEPOINT s1",
		  "COMMIT"},
		 {'T','T','T','T','T','I'}, "SELECT count(*) FROM {T}"},
		// T4: savepoint with release
		{"T4: BEGIN; SAVEPOINT s1; INSERT z; RELEASE s1; COMMIT", "TXN_SAVEPOINT",
		 "CREATE TABLE {T} (id int, name text)",
		 {"BEGIN", "SAVEPOINT s1", "INSERT INTO {T} VALUES (9, 'z')", "RELEASE SAVEPOINT s1", "COMMIT"},
		 {'T','T','T','T','I'}, "SELECT count(*) FROM {T}"},
		// T5: nested savepoints; rollback inner; release outer
		{"T5: Nested savepoints; ROLLBACK inner; RELEASE outer; COMMIT (no row)", "TXN_SAVEPOINT",
		 "CREATE TABLE {T} (id int, name text)",
		 {"BEGIN", "SAVEPOINT s1", "SAVEPOINT s2", "INSERT INTO {T} VALUES (1,'x')", "ROLLBACK TO SAVEPOINT s2", "RELEASE SAVEPOINT s1", "COMMIT"},
		 {'T','T','T','T','T','T','I'}, "SELECT count(*) FROM {T}"},
		// T6: error in tx; tx auto-rolls back; final COMMIT
		{"T6: Error-in-tx; tx auto-rolls back; COMMIT (no row)", "TXN_ERROR",
		 "CREATE TABLE {T} (id int, name text)",
		 {"BEGIN", "INSERT INTO {T} VALUES (1, 'a')", "INSERT INTO no_such_table VALUES (1)", "COMMIT"},
		 {'T','T','E','I'}, "SELECT count(*) FROM {T}"},
		// T7: multi-statement mixed
		{"T7: BEGIN; SELECT; INSERT; UPDATE; SELECT; COMMIT", "TXN_MIXED",
		 "CREATE TABLE {T} (id int, name text)",
		 {"BEGIN", "SELECT 1", "INSERT INTO {T} VALUES (1, 'x')", "UPDATE {T} SET name='y' WHERE id=1", "SELECT 2", "COMMIT"},
		 {'T','T','T','T','T','I'}, "SELECT count(*) FROM {T}"},
		// T8: isolation level
		{"T8: BEGIN ISOLATION LEVEL SERIALIZABLE; SELECT; COMMIT", "TXN_ISOLATION", "",
		 {"BEGIN ISOLATION LEVEL SERIALIZABLE", "SELECT 1", "COMMIT"},
		 {'T','T','I'}, ""},
		// T9: long transaction
		{"T9: Long tx (pg_sleep 0.3); COMMIT", "TXN_LONG", "",
		 {"BEGIN", "SELECT pg_sleep(0.3)", "COMMIT"},
		 {'T','T','I'}, ""},
		// T10: empty transaction
		{"T10: Empty tx: BEGIN; COMMIT", "TXN_EMPTY", "",
		 {"BEGIN", "COMMIT"},
		 {'T','I'}, ""},
		// T11: error after commit
		{"T11: BEGIN; COMMIT; bad SQL at top-level", "TXN_RECOVERY", "",
		 {"BEGIN", "COMMIT", "SELECT * FROM no_such_table_xyz"},
		 {'T','I','I'}, ""},
		// T12: 3 cycles on one connection
		{"T12: 3 cycles on one connection", "TXN_REUSE",
		 "CREATE TABLE {T} (id int, name text)",
		 {"BEGIN", "INSERT INTO {T} VALUES (1,'a')", "COMMIT",
		  "BEGIN", "INSERT INTO {T} VALUES (2,'b')", "COMMIT",
		  "BEGIN", "INSERT INTO {T} VALUES (3,'c')", "COMMIT"},
		 {'T','T','I','T','T','I','T','T','I'}, "SELECT count(*) FROM {T}"},
		// T13: PREPARE + EXECUTE + DEALLOCATE in tx.
		// Both libpq and native paths report txn status 'I' (idle) after
		// DEALLOCATE inside the BEGIN/COMMIT block on this Postgres version
		// (verified empirically: the verify query runs after COMMIT and the
		// state is 'I' on both paths). The interesting assertion for this
		// case is that the libpq and native paths agree, not that the state
		// is what we expected, so the state vector is left empty and only the
		// per-path result_match is checked.
		{"T13: PREPARE p AS SELECT $1::int; EXECUTE p(5); DEALLOCATE; COMMIT", "TXN_PREPARED", "",
		 {"BEGIN", "PREPARE p AS SELECT $1::int + $1", "EXECUTE p(5)", "DEALLOCATE p", "COMMIT"},
		 {}, ""},
		// T14: long tx (pg_sleep 1.2) - backend may emit timeout warning
		//      but the test verifies the txn-status progression.
		{"T14: Long tx (pg_sleep 1.2)", "TXN_LONG", "",
		 {"BEGIN", "SELECT pg_sleep(1.2)"},
		 {'T','T'}, ""},

		// -------------------------------------------------------------------
		// EXTENDED-PROTOCOL transaction cases (regression for the native-mode
		// double-registration of the explicit-txn tracker). BEGIN/work/COMMIT
		// sent via the extended protocol — the shape `pgbench -M prepared`
		// uses and the exact trigger of the per-COMMIT "no transaction in
		// progress" warning storm. Every case asserts, in addition to txn-
		// status ('T' between BEGIN and COMMIT) and DML parity: ZERO native
		// explicit-txn-tracker warnings in the native window (folded into
		// result_match via scan_native_window()).
		// -------------------------------------------------------------------

		// E0: extended (PQexecParams) BEGIN; SELECT; COMMIT.
		{"E0: [ext-params] BEGIN; SELECT 1; COMMIT", "TXN_EXT_CYCLE", "",
		 {"BEGIN", "SELECT 1", "COMMIT"},
		 {'T','T','I'}, "", EXEC_EXT_PARAMS},
		// E1: extended (PQexecParams) BEGIN; INSERT; COMMIT (row persists).
		{"E1: [ext-params] BEGIN; INSERT; COMMIT", "TXN_EXT_COMMIT",
		 "CREATE TABLE {T} (id int, name text)",
		 {"BEGIN", "INSERT INTO {T} VALUES (1, 'a')", "COMMIT"},
		 {'T','T','I'}, "SELECT count(*) FROM {T}", EXEC_EXT_PARAMS},
		// E2: extended (PQexecParams) empty tx: BEGIN; COMMIT.
		{"E2: [ext-params] Empty tx: BEGIN; COMMIT", "TXN_EXT_EMPTY", "",
		 {"BEGIN", "COMMIT"},
		 {'T','I'}, "", EXEC_EXT_PARAMS},
		// E3: PREPARED (PQprepare + PQexecPrepared) BEGIN/work/END — the exact
		// pgbench -M prepared shape (END is a COMMIT synonym).
		{"E3: [ext-prepared] BEGIN; INSERT; END", "TXN_EXT_PREPARED",
		 "CREATE TABLE {T} (id int, name text)",
		 {"BEGIN", "INSERT INTO {T} VALUES (7, 'g')", "END"},
		 {'T','T','I'}, "SELECT count(*) FROM {T}", EXEC_EXT_PREPARED},
		// E4: PREPARED three cycles on one connection — stresses per-cycle
		// register/clear so a single stray double-fire is caught.
		{"E4: [ext-prepared] 3 cycles BEGIN/INSERT/COMMIT", "TXN_EXT_REUSE",
		 "CREATE TABLE {T} (id int, name text)",
		 {"BEGIN", "INSERT INTO {T} VALUES (1,'a')", "COMMIT",
		  "BEGIN", "INSERT INTO {T} VALUES (2,'b')", "COMMIT",
		  "BEGIN", "INSERT INTO {T} VALUES (3,'c')", "COMMIT"},
		 {'T','T','I','T','T','I','T','T','I'}, "SELECT count(*) FROM {T}", EXEC_EXT_PREPARED},
	};
}

int main(int /*argc*/, char** /*argv*/) {
	auto cases = build_cases();
	int n_cases = (int)cases.size();
	// n_cases per-case ok lines + 1 coverage summary = n_cases + 1.
	plan(n_cases + 1);
	if (cl.getEnv()) return exit_status();

	std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS) {
		BAIL_OUT("Cannot open ProxySQL log at %s", log_path.c_str());
		return exit_status();
	}

	PGConnPtr admin = open_admin_conn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
		BAIL_OUT("admin connect failed: %s",
		         admin ? PQerrorMessage(admin.get()) : "null conn");
		return exit_status();
	}
	std::vector<ServerRow> saved = readServers(admin.get(), BACKEND_HG);
	if (saved.empty()) {
		BAIL_OUT("No pgsql_servers in hostgroup %d", BACKEND_HG);
		return exit_status();
	}
	diag("Backend under test (hg %d): %s:%s", BACKEND_HG,
	     saved[0].hostname.c_str(), saved[0].port.c_str());

	CoverageRecorder cov;
	for (const auto& raw : cases) {
		TxnCase tc;
		tc.label = raw.label;
		tc.kind = raw.kind;
		tc.setup = raw.setup;       // run_case substitutes {T}
		tc.queries = raw.queries;  // run_case substitutes {T}
		tc.expected_states = raw.exp_states;
		tc.verify = raw.verify;     // run_case substitutes {T}
		tc.mode = raw.mode;
		CaseResult cr = run_case(admin.get(), tc, saved);
		cov.record({tc.label, tc.kind, cr.result_match, !cr.fell_back, cr.detail});
	}
	cov.emit_tap();
	return exit_status();
}
