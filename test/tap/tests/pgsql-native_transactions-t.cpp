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

static bool nativeFallbackObserved() {
	const std::string re =
		".*(native_mode requested but unimplemented at this stage; falling back to libpq"
		"|native backend auth capability gap .* falling back to libpq).*";
	return wait_for_log_match(f_proxysql_log, re, 1000, 100);
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

// Run a sequence of queries; return per-query txn-status bytes and an
// "all_ok" flag indicating no query returned PGRES_FATAL_ERROR.
struct TxnRun {
	std::vector<char> states;
	bool all_ok = true;
};
static TxnRun run_txn_sequence(PGconn* c, const std::vector<std::string>& qs) {
	TxnRun r;
	for (const auto& q : qs) {
		PGresult* res = PQexec(c, q.c_str());
		ExecStatusType st = PQresultStatus(res);
		if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
			r.all_ok = false;
		}
		PQclear(res);
		r.states.push_back(txn_status_byte(c));
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
};

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
	TxnRun lp_run = run_txn_sequence(lp.get(), lp_tc.queries);
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
	TxnRun nt_run = run_txn_sequence(nt.get(), nt_tc.queries);
	int nt_count = nt_tc.verify.empty() ? 0 : run_count_query(nt.get(), nt_tc.verify);
	bool fell_back = nativeFallbackObserved();

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
	bool result_match = (lp_run.all_ok == nt_run.all_ok) && states_match &&
	                    (lp_count == nt_count);
	std::string detail;
	if (!result_match) {
		std::stringstream ss;
		ss << "lp_ok=" << lp_run.all_ok << " nt_ok=" << nt_run.all_ok
		   << " lp_count=" << lp_count << " nt_count=" << nt_count;
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
                 std::string verify; };

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
		// T13: PREPARE + EXECUTE + DEALLOCATE in tx
		{"T13: PREPARE p AS SELECT $1::int; EXECUTE p(5); DEALLOCATE; COMMIT", "TXN_PREPARED", "",
		 {"BEGIN", "PREPARE p AS SELECT $1::int + $1", "EXECUTE p(5)", "DEALLOCATE p", "COMMIT"},
		 {'T','T','T','T','I'}, ""},
		// T14: long tx (pg_sleep 1.2) - backend may emit timeout warning
		//      but the test verifies the txn-status progression.
		{"T14: Long tx (pg_sleep 1.2)", "TXN_LONG", "",
		 {"BEGIN", "SELECT pg_sleep(1.2)"},
		 {'T','T'}, ""},
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
		CaseResult cr = run_case(admin.get(), tc, saved);
		cov.record({tc.label, tc.kind, cr.result_match, !cr.fell_back, cr.detail});
	}
	cov.emit_tap();
	return exit_status();
}
