/**
 * @file pgsql-native_prepared-t.cpp
 * @brief Differential test: native vs libpq for prepared statements.
 *
 * PURPOSE
 * -------
 * Exercises prepared statements through ProxySQL twice:
 *   1. with `pgsql-use_native_backend_protocol='false'`  -> the libpq ORACLE
 *   2. with `pgsql-use_native_backend_protocol='true'`   -> the NATIVE path
 *
 * Byte-equality between the two runs is required for EVERY case in both
 * sub-suites below — there is no "expected gap" escape hatch left. The
 * libpq run is the oracle; any divergence is a hard failure.
 *
 * Two sub-suites:
 *
 * SQL-SIDE (cases P0-P9): `PREPARE` / `EXECUTE` / `DEALLOCATE` issued as
 * simple Query messages. These are simple queries on the wire, so the native
 * path handles them. We expect 100% native coverage here.
 *
 * EXTENDED-QUERY (cases P10 onward): client-driven Parse / Bind / Describe /
 * Execute / Close / Sync cycle using libpq's `PQsendPrepare`,
 * `PQsendQueryPrepared`, and `PQsendQueryParams`. As of the native-drive
 * stmt-pipeline work (see
 * docs/superpowers/specs/2026-07-07-pgsql-native-extq-stmt-pipeline-design.md
 * and lib/PgSQL_Connection.cpp:3032-3043), the native path drives the full
 * extended-query cycle itself — ProxySQL's prepared-statement bookkeeping
 * (GloPgStmt global cache, per-connection local_stmts, backend-id reuse, ack
 * synthesis) is shared between the native and libpq wire layers, so both
 * paths are expected to be byte-identical AND fully native (no libpq
 * fallback) for every case here. The coverage summary reports the per-kind
 * native rate as a regression signal.
 *
 * Beyond the single Parse+Bind+Execute cycle, this file also covers:
 *   - EXT_MULTI_CYCLE: two independent extended-query cycles on one session.
 *   - EXT_REUSE: the same client-visible statement name re-prepared (with a
 *     different query) after an explicit DEALLOCATE, exercising the
 *     backend-stmt-id reuse decision (lib/PgSQL_Session.cpp:~3444-3477).
 *   - EXT_GLOBAL_DEDUP: two distinct sessions preparing byte-identical query
 *     text under different local names, exercising the global prepared-
 *     statement cache dedup path (lib/PgSQL_PreparedStatement.cpp
 *     `add_prepared_statement`).
 *   - EXT_PARSE_ERR_MIDFRAME: `PQsendQueryParams` sends Parse/Bind/Describe/
 *     Execute/Sync as ONE client frame (unlike `PQsendPrepare` +
 *     `PQsendQueryPrepared`, which are each their own Sync-terminated
 *     frame). With invalid SQL, the backend's Parse fails while
 *     Bind/Describe/Execute are already queued behind it in the same
 *     received frame, so ProxySQL dispatches the Parse as Flush- (not
 *     Sync-) terminated and must inject its own Sync to resynchronize the
 *     backend (lib/PgSQL_Connection.cpp:~2803-2825). This is the only
 *     flagship native-drive recovery mechanism not otherwise exercised by
 *     this file.
 *
 * KNOWN ISSUES (discovered by this test)
 * --------------------------------------
 * 1. P8 (PREPARE/EXECUTE inside a transaction): the session-state divergence
 *    identified by `pgsql-native_transactions-t` also affects SQL-side
 *    prepared statements that run inside a BEGIN/COMMIT block. The same
 *    fix will repair both.
 *
 * INFRA: legacy-g1 (docker-pgsql16-single, scram-sha-256, no TLS).
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <regex>
#include <unistd.h>
#include <cstring>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql-native_tracking.h"

CommandLine cl;
static const int BACKEND_HG = 0;
static std::fstream f_proxysql_log{};
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static std::string make_table_name() {
	return "pgsql_native_prep_" + std::to_string(getpid()) + "_" +
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
	// Deliberately broad: matches the connection-level auth-capability-gap
	// fallback (lib/PgSQL_Connection.cpp:1475) AND any future
	// extended-query-specific "falling back to libpq" warning, without
	// hardcoding today's exact wording. Now that the native path drives the
	// full extended-query cycle itself (stmt-pipeline work), any case in
	// this file matching this regex is a regression tripwire — every
	// EXT_*/PREPARE_SQL case here is expected to be fully native.
	const std::string re = ".*falling back to libpq.*";
	return wait_for_log_match(f_proxysql_log, re, 1000, 100);
}

static void drainLogToNow() {
	get_matching_lines(f_proxysql_log, "__no_such_marker_line__");
}

// Single-pass scan of the proxysql log for BOTH the libpq-fallback tripwire
// and the injected-Sync recovery warning. Needed because wait_for_log_match /
// get_matching_lines consume the stream forward: two sequential scans for two
// different regexes would each miss lines the other already read past. Polls
// until the injected-Sync line is seen or `wait_ms` elapses; the fallback
// flag reflects everything read either way.
static void scanNativePhaseLog(bool& fell_back, bool& resync_logged, uint32_t wait_ms) {
	const std::regex re_fallback(".*falling back to libpq.*");
	const std::regex re_resync(".*native extq: mid-frame stmt-step error.*");
	fell_back = false;
	resync_logged = false;
	uint32_t elapsed = 0;
	while (true) {
		// Clear eof/fail so getline() can read bytes appended since the last scan
		// (same trick as wait_for_log_match).
		f_proxysql_log.clear(f_proxysql_log.rdstate() &
		                     ~std::ios_base::eofbit & ~std::ios_base::failbit);
		std::string line;
		while (std::getline(f_proxysql_log, line)) {
			if (!fell_back && std::regex_match(line, re_fallback)) fell_back = true;
			if (!resync_logged && std::regex_match(line, re_resync)) resync_logged = true;
		}
		if (resync_logged || elapsed >= wait_ms) return;
		usleep(100000);
		elapsed += 100;
	}
}

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

// Capture a deterministic snapshot of a PGresult. NULL values become "\\N".
static std::string serialize_result(PGresult* res) {
	if (!res) return "<null>";
	std::stringstream ss;
	ExecStatusType st = PQresultStatus(res);
	ss << "st=" << (int)st << " ";
	if (st == PGRES_TUPLES_OK) {
		int nf = PQnfields(res);
		int nr = PQntuples(res);
		ss << "nf=" << nf << " nr=" << nr << " ";
		for (int c = 0; c < nf; c++) {
			ss << "c" << c << "=" << (PQfname(res, c) ? PQfname(res, c) : "") << ":" << PQftype(res, c) << ";";
		}
		for (int r = 0; r < nr; r++) {
			ss << "R" << r << ":";
			for (int c = 0; c < nf; c++) {
				if (PQgetisnull(res, r, c)) ss << "\\N|";
				else ss << PQgetvalue(res, r, c) << "|";
			}
			ss << ";";
		}
	} else if (st == PGRES_COMMAND_OK) {
		const char* ct = PQcmdStatus(res);
		ss << "tag=" << (ct ? ct : "") << " ";
	} else if (st == PGRES_FATAL_ERROR) {
		const char* sqlstate = PQresultErrorField(res, PG_DIAG_SQLSTATE);
		ss << "sqlstate=" << (sqlstate ? sqlstate : "") << " ";
		const char* msg = PQresultErrorMessage(res);
		ss << "msg=" << (msg ? msg : "") << " ";
	}
	return ss.str();
}

// ===========================================================================
// SQL-side prepared statements (cases P0-P9). Each is a list of simple
// queries. We capture the result of each and compare across libpq/native.
// ===========================================================================
struct SqlCase {
	std::string label, kind;
	std::string setup;       // {T} substituted
	std::vector<std::string> queries;  // {T} substituted
};

// Each result entry is the serialized form of the corresponding PGresult.
struct SqlCaseResult {
	std::vector<std::string> serials;  // per-query serials
	bool all_ok = true;
	std::string err_sqlstate;
};
static SqlCaseResult run_sql_case(PGconn* c, const std::vector<std::string>& qs) {
	SqlCaseResult r;
	for (const auto& q : qs) {
		PGresult* res = PQexec(c, q.c_str());
		r.serials.push_back(serialize_result(res));
		ExecStatusType st = PQresultStatus(res);
		if (st == PGRES_FATAL_ERROR) {
			r.all_ok = false;
			const char* ss = PQresultErrorField(res, PG_DIAG_SQLSTATE);
			if (ss) r.err_sqlstate = ss;
		}
		PQclear(res);
	}
	return r;
}

static std::vector<SqlCase> build_sql_cases() {
	std::vector<SqlCase> v;
	// P0: simple prepare+execute+deallocate
	v.push_back({"P0: PREPARE p AS SELECT 42; EXECUTE p; DEALLOCATE p", "PREPARE_SQL", "",
		{"PREPARE p AS SELECT 42", "EXECUTE p", "DEALLOCATE p"}});
	// P1: prepare with $1, execute with various params
	v.push_back({"P1: PREPARE p AS SELECT $1::int + $1; EXECUTE p(5); EXECUTE p(7); DEALLOCATE", "PREPARE_SQL", "",
		{"PREPARE p AS SELECT $1::int + $1", "EXECUTE p(5)", "EXECUTE p(7)", "DEALLOCATE p"}});
	// P2: prepare with no params
	v.push_back({"P2: PREPARE p AS SELECT 1+1; EXECUTE p; DEALLOCATE", "PREPARE_SQL", "",
		{"PREPARE p AS SELECT 1+1", "EXECUTE p", "DEALLOCATE p"}});
	// P3: prepare, execute with NULL
	v.push_back({"P3: PREPARE p AS SELECT $1::int IS NULL; EXECUTE p(NULL); DEALLOCATE", "PREPARE_SQL", "",
		{"PREPARE p AS SELECT $1::int IS NULL", "EXECUTE p(NULL)", "DEALLOCATE p"}});
	// P4: text result type
	v.push_back({"P4: PREPARE p AS SELECT $1::text; EXECUTE p('hello'); DEALLOCATE", "PREPARE_SQL", "",
		{"PREPARE p AS SELECT $1::text", "EXECUTE p('hello')", "DEALLOCATE p"}});
	// P5: re-prepare same name (overwrite)
	v.push_back({"P5: PREPARE p AS SELECT 1; PREPARE p AS SELECT 2; EXECUTE p; DEALLOCATE", "PREPARE_SQL", "",
		{"PREPARE p AS SELECT 1", "PREPARE p AS SELECT 2", "EXECUTE p", "DEALLOCATE p"}});
	// P6: execute of unknown name -> error
	v.push_back({"P6: EXECUTE no_such_prepared (error path)", "PREPARE_SQL", "",
		{"EXECUTE no_such_prepared"}});
	// P7: deallocate of unknown name -> error
	v.push_back({"P7: DEALLOCATE no_such_prepared (error path)", "PREPARE_SQL", "",
		{"DEALLOCATE no_such_prepared"}});
	// P8: prepare in a transaction
	v.push_back({"P8: BEGIN; PREPARE; EXECUTE; COMMIT", "PREPARE_SQL", "",
		{"BEGIN", "PREPARE p AS SELECT $1::int + $1", "EXECUTE p(5)", "DEALLOCATE p", "COMMIT"}});
	// P9: prepare + DML with RETURNING
	v.push_back({"P9: PREPARE ins AS INSERT INTO {T} VALUES ($1, $2) RETURNING *; EXECUTE ins(99, 'z'); DEALLOCATE",
	             "PREPARE_SQL",
	             "CREATE TABLE {T} (id int, name text)",
	             // {T} substitution happens in run_case; we keep the raw form.
	             {"PREPARE ins AS INSERT INTO {T} VALUES ($1, $2) RETURNING *",
	              "EXECUTE ins(99, 'z')", "DEALLOCATE ins"}});
	return v;
}

struct SqlCaseRunResult { bool result_match; bool fell_back; std::string detail; };

static SqlCaseRunResult run_sql(PGconn* admin, const SqlCase& tc,
                                const std::vector<ServerRow>& saved) {
	std::string tbl = make_table_name();
	std::string tbl_n = tbl + "_n";
	// Substitute {T} in the queries.
	std::vector<std::string> qs_lp, qs_nt;
	for (const auto& q : tc.queries) qs_lp.push_back(substitute_table(q, tbl));
	for (const auto& q : tc.queries) qs_nt.push_back(substitute_table(q, tbl_n));
	std::string setup_lp = substitute_table(tc.setup, tbl);
	std::string setup_nt = substitute_table(tc.setup, tbl_n);

	// ---- libpq control ----
	if (!setNativeMode(admin, false) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set libpq mode failed"};
	}
	PGConnPtr lp = open_client_conn();
	if (!lp || PQstatus(lp.get()) != CONNECTION_OK) return {false, false, "libpq conn failed"};
	if (!setup_lp.empty()) { PGresult* sr = PQexec(lp.get(), setup_lp.c_str()); PQclear(sr); }
	SqlCaseResult lp_r = run_sql_case(lp.get(), qs_lp);

	// ---- native candidate ----
	if (!setNativeMode(admin, true) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set native mode failed"};
	}
	drainLogToNow();
	PGConnPtr nt = open_client_conn();
	if (!nt || PQstatus(nt.get()) != CONNECTION_OK) return {false, false, "native conn failed"};
	if (!setup_nt.empty()) { PGresult* sr = PQexec(nt.get(), setup_nt.c_str()); PQclear(sr); }
	SqlCaseResult nt_r = run_sql_case(nt.get(), qs_nt);
	bool fell_back = nativeFallbackObserved();

	bool result_match = (lp_r.serials == nt_r.serials) && (lp_r.all_ok == nt_r.all_ok);
	std::stringstream det;
	det << "n_queries=" << tc.queries.size();
	if (!result_match) {
		det << " (mismatch; sqlstate lp='" << lp_r.err_sqlstate << "' nt='" << nt_r.err_sqlstate << "')";
	}
	setNativeMode(admin, false);
	flushBackendPool(admin, BACKEND_HG, saved);
	return {result_match, fell_back, det.str()};
}

// ===========================================================================
// Extended-query (cases P10 onward). We use libpq's PQsendPrepare +
// PQsendQueryPrepared + PQdescribePrepared + PQclosePrepared to drive the
// extended-query cycle. Both the libpq path and the native path drive this
// cycle to completion themselves now (native-drive stmt-pipeline work); the
// result is required to be byte-equal.
// ===========================================================================
struct ExtQCase {
	std::string label, kind;
	std::string stmt_name;       // "" => unnamed
	std::string query;           // SQL with $1, $2, ...
	std::vector<std::string> param_types;  // OID names like "23", "25" — empty for inference
	struct BindStep {
		std::string portal;     // "" => unnamed
		std::vector<std::string> param_values;
		std::vector<int> param_lengths;  // -1 => text, else binary length
		std::vector<int> param_formats;  // 0=text, 1=binary
		int result_format;      // 0=text, 1=binary
	};
	std::vector<BindStep> bind_steps;
	bool describe_after_bind;    // true => Describe portal after each Bind
	bool describe_stmt;          // true => Describe statement ('S') before Bind
	bool close_stmt;             // true => send Close('S', stmt_name) at end
	bool close_portal;           // true => send Close('P', portal) at end
	bool expect_error;           // true => we expect an ErrorResponse in the cycle
	std::string expect_sqlstate; // if !empty => assert exact SQLSTATE on error
};

// Run an extended-query cycle. Returns a single string that's the
// concatenation of every PGresult returned by PQgetResult, serialized.
static std::string run_extq_cycle(PGconn* c, const ExtQCase& tc) {
	std::string out;
	// PQsendPrepare takes `const Oid *paramTypes`. Convert our string-form
	// OID list ("23"=int4, "25"=text) to actual Oid values.
	Oid paramOids[16] = {0};
	for (size_t i = 0; i < tc.param_types.size() && i < 16; i++) {
		paramOids[i] = (Oid)atoi(tc.param_types[i].c_str());
	}
	// Parse phase: PQsendPrepare.
	const char* stmt_name = tc.stmt_name.empty() ? NULL : tc.stmt_name.c_str();
	if (PQsendPrepare(c, stmt_name, tc.query.c_str(), (int)tc.param_types.size(), paramOids) == 0) {
		out += "PQsendPrepare:fail:" + std::string(PQerrorMessage(c)) + ";";
		return out;
	}
	// Drain ParseComplete.
	PGresult* res;
	while ((res = PQgetResult(c)) != NULL) {
		out += "Parse:" + serialize_result(res) + ";";
		PQclear(res);
	}
	// Optional Describe statement.
	if (tc.describe_stmt && stmt_name) {
		PGresult* dr = PQdescribePrepared(c, stmt_name);
		out += "DescribeStmt:" + serialize_result(dr) + ";";
		PQclear(dr);
	}
	// Bind+Execute steps.
	for (const auto& bs : tc.bind_steps) {
		// Build param arrays.
		const char* paramValues[16] = {0};
		int paramLengths[16] = {0};
		int paramFormats[16] = {0};
		int n_params = (int)bs.param_values.size();
		for (int i = 0; i < n_params && i < 16; i++) {
			paramValues[i] = bs.param_values[i].data();
			paramLengths[i] = bs.param_lengths.empty() ? (int)bs.param_values[i].size() : bs.param_lengths[i];
			paramFormats[i] = bs.param_formats.empty() ? 0 : bs.param_formats[i];
		}
		if (PQsendQueryPrepared(c, stmt_name, n_params, paramValues, paramLengths, paramFormats, bs.result_format) == 0) {
			out += "PQsendQueryPrepared:fail:" + std::string(PQerrorMessage(c)) + ";";
			return out;
		}
		// Drain.
		while ((res = PQgetResult(c)) != NULL) {
			out += "Execute:" + serialize_result(res) + ";";
			PQclear(res);
		}
	}
	// Optional Close statement: PQclosePrepared is not in this libpq version;
	// use the SQL DEALLOCATE path (which is itself a simple query — not
	// strictly extended-query, but tests the same prepared-statement removal
	// observable).
	if (tc.close_stmt && stmt_name) {
		std::string dealloc = "DEALLOCATE \"" + std::string(stmt_name) + "\"";
		PGresult* dr = PQexec(c, dealloc.c_str());
		out += "Deallocate:" + serialize_result(dr) + ";";
		PQclear(dr);
	}
	return out;
}

static std::vector<ExtQCase> build_extq_cases() {
	std::vector<ExtQCase> v;
	// P10: Parse unnamed + Bind + Execute + Sync, simple
	v.push_back({"P10: unnamed Parse+Bind+Execute (text)", "EXT_EXECUTE",
		"", "SELECT $1::int",
		{}, {{"", {"42"}, {}, {}, 0}}, false, false, false, false, false, ""});
	// P11: named statement
	v.push_back({"P11: named Parse+Bind+Execute 's1'", "EXT_PARSE",
		"s1", "SELECT $1::int",
		{}, {{"", {"42"}, {}, {}, 0}}, false, false, true, false, false, ""});
	// P12: multiple params, mixed types
	v.push_back({"P12: 3-param text Parse+Bind+Execute", "EXT_EXECUTE",
		"", "SELECT $1::int, $2::text, $3::bool",
		{}, {{"", {"1", "a", "t"}, {}, {}, 0}}, false, false, false, false, false, ""});
	// P13: binary result format
	v.push_back({"P13: binary result format (int4)", "EXT_EXECUTE",
		"", "SELECT $1::int",
		{}, {{"", {"1"}, {}, {}, 1}}, false, false, false, false, false, ""});
	// P14: re-execute same named statement 3x
	v.push_back({"P14: re-execute same statement 3 times", "EXT_EXECUTE",
		"s2", "SELECT $1::int + 1",
		{},
		{{"", {"1"}, {}, {}, 0}, {"", {"2"}, {}, {}, 0}, {"", {"3"}, {}, {}, 0}},
		false, false, true, false, false, ""});
	// P15: close statement
	v.push_back({"P15: Parse 's3' + Close 's3'", "EXT_PARSE",
		"s3", "SELECT 1", {}, {}, false, false, true, false, false, ""});
	// P16: bad SQL in Parse -> error
	v.push_back({"P16: Parse with bad SQL (error path)", "EXT_PARSE",
		"", "NOT VALID SQL", {}, {{"", {}, {}, {}, 0}}, false, false, false, false, true, "42601"});
	// P17: divide by zero
	v.push_back({"P17: Execute with divide-by-zero (error path)", "EXT_EXECUTE",
		"", "SELECT 1/0", {}, {{"", {}, {}, {}, 0}}, false, false, false, false, true, "22012"});
	// P18: EmptyStatement (empty query string)
	v.push_back({"P18: Parse with empty query (EmptyQueryResponse)", "EXT_PARSE",
		"", "", {}, {}, false, false, false, false, false, ""});
	// (P19 used to be a dead "multiple Parse+Execute" placeholder — real
	// coverage for that now lives in the EXT_MULTI_CYCLE case run separately
	// in main(), since it needs two independent cycles on one connection,
	// which doesn't fit the single-cycle-per-case shape of run_extq().)
	// P20: Parse with type OIDs
	v.push_back({"P20: Parse with explicit type OIDs {23, 25}", "EXT_PARSE",
		"", "SELECT $1::int, $2::text",
		{"23", "25"},
		{{"", {"5", "hello"}, {}, {}, 0}}, false, false, false, false, false, ""});
	return v;
}

struct ExtQCaseRunResult { bool result_match; bool fell_back; std::string detail; };

static ExtQCaseRunResult run_extq(PGconn* admin, const ExtQCase& tc,
                                  const std::vector<ServerRow>& saved) {
	// ---- libpq control ----
	if (!setNativeMode(admin, false) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set libpq mode failed"};
	}
	PGConnPtr lp = open_client_conn();
	if (!lp || PQstatus(lp.get()) != CONNECTION_OK) return {false, false, "libpq conn failed"};
	std::string lp_out = run_extq_cycle(lp.get(), tc);

	// ---- native candidate ----
	if (!setNativeMode(admin, true) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set native mode failed"};
	}
	drainLogToNow();
	PGConnPtr nt = open_client_conn();
	if (!nt || PQstatus(nt.get()) != CONNECTION_OK) return {false, false, "native conn failed"};
	std::string nt_out = run_extq_cycle(nt.get(), tc);
	bool fell_back = nativeFallbackObserved();

	// Byte-equality is required for every case — no escape hatch. The native
	// path drives the full extended-query cycle itself now, so a mismatch is
	// a real regression, not an expected/documented gap.
	bool result_match = (lp_out == nt_out);
	std::stringstream det;
	det << "n_steps=" << tc.bind_steps.size();
	if (!result_match) {
		// Truncate the diff for readability.
		det << " (mismatch; lp_out_size=" << lp_out.size() << " nt_out_size=" << nt_out.size() << ")";
	}
	setNativeMode(admin, false);
	flushBackendPool(admin, BACKEND_HG, saved);
	return {result_match, fell_back, det.str()};
}

// ===========================================================================
// EXT_MULTI_CYCLE / EXT_REUSE / EXT_GLOBAL_DEDUP: cases that need more than
// the single-cycle-per-connection shape of run_extq() above. `seq` is a list
// of independent extended-query cycles, run either all on ONE connection
// (same_connection=true — multi-cycle / re-prepare-after-DEALLOCATE) or each
// on its OWN connection (same_connection=false — global-cache dedup across
// distinct sessions). Outputs from every cycle are concatenated in order and
// compared byte-for-byte between libpq and native, exactly like run_extq().
// ===========================================================================
static ExtQCaseRunResult run_extq_sequence(PGconn* admin, const std::vector<ExtQCase>& seq,
                                           bool same_connection,
                                           const std::vector<ServerRow>& saved) {
	// ---- libpq control ----
	if (!setNativeMode(admin, false) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set libpq mode failed"};
	}
	std::string lp_out;
	if (same_connection) {
		PGConnPtr c = open_client_conn();
		if (!c || PQstatus(c.get()) != CONNECTION_OK) return {false, false, "libpq conn failed"};
		for (const auto& tc : seq) lp_out += run_extq_cycle(c.get(), tc);
	} else {
		for (const auto& tc : seq) {
			PGConnPtr c = open_client_conn();
			if (!c || PQstatus(c.get()) != CONNECTION_OK) return {false, false, "libpq conn failed"};
			lp_out += run_extq_cycle(c.get(), tc);
		}
	}

	// ---- native candidate ----
	if (!setNativeMode(admin, true) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set native mode failed"};
	}
	drainLogToNow();
	std::string nt_out;
	if (same_connection) {
		PGConnPtr c = open_client_conn();
		if (!c || PQstatus(c.get()) != CONNECTION_OK) return {false, false, "native conn failed"};
		for (const auto& tc : seq) nt_out += run_extq_cycle(c.get(), tc);
	} else {
		for (const auto& tc : seq) {
			PGConnPtr c = open_client_conn();
			if (!c || PQstatus(c.get()) != CONNECTION_OK) return {false, false, "native conn failed"};
			nt_out += run_extq_cycle(c.get(), tc);
		}
	}
	bool fell_back = nativeFallbackObserved();

	bool result_match = (lp_out == nt_out);
	std::stringstream det;
	det << "n_cycles=" << seq.size() << (same_connection ? " (same conn)" : " (per-conn)");
	if (!result_match) {
		det << " (mismatch; lp_out_size=" << lp_out.size() << " nt_out_size=" << nt_out.size() << ")";
	}
	setNativeMode(admin, false);
	flushBackendPool(admin, BACKEND_HG, saved);
	return {result_match, fell_back, det.str()};
}

// ===========================================================================
// ADDITION 1 (Task C review): the injected-Sync error-recovery path.
// `PQsendQueryParams` sends Parse/Bind/Describe/Execute/Sync as ONE client
// frame/flush (unlike `PQsendPrepare` + `PQsendQueryPrepared`, which are two
// independently Sync-terminated frames — each drains to 'Z' before the next
// is sent). With syntactically invalid SQL, the backend's Parse fails while
// Bind/Describe/Execute are already queued behind it in the SAME received
// frame; ProxySQL's native drive therefore dispatches the Parse as
// Flush-terminated (more stmt-step messages are already pending in the
// frame), and the backend sends no 'Z' after the 'E' until it receives a
// Sync. The native path must inject that Sync itself to resynchronize
// (lib/PgSQL_Connection.cpp:~2803-2825, `native_stmt_error_resync`). This is
// the only flagship native-drive recovery mechanism not otherwise exercised
// by this file. The case POSITIVELY asserts the branch ran by scraping the
// proxysql log for its once-per-connection proxy_warning (the native phase
// always runs on a fresh backend connection — see the comment in
// run_midframe_err — so the once-per-connection dedup cannot hide the line).
// ===========================================================================
static std::string run_midframe_err_case(PGconn* c, const std::string& bad_sql) {
	std::string out;
	if (PQsendQueryParams(c, bad_sql.c_str(), 0, NULL, NULL, NULL, NULL, 0) == 0) {
		out += "PQsendQueryParams:fail:" + std::string(PQerrorMessage(c)) + ";";
		return out;
	}
	PGresult* res;
	while ((res = PQgetResult(c)) != NULL) {
		out += "Ext:" + serialize_result(res) + ";";
		PQclear(res);
	}
	// The connection must be usable afterwards: run a follow-up query in the
	// same phase and fold its result into the comparable output.
	PGresult* fr = PQexec(c, "SELECT 1");
	out += "Follow:" + serialize_result(fr) + ";";
	PQclear(fr);
	return out;
}

static ExtQCaseRunResult run_midframe_err(PGconn* admin, const std::string& bad_sql,
                                          const std::vector<ServerRow>& saved) {
	// ---- libpq control ----
	if (!setNativeMode(admin, false) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set libpq mode failed"};
	}
	PGConnPtr lp = open_client_conn();
	if (!lp || PQstatus(lp.get()) != CONNECTION_OK) return {false, false, "libpq conn failed"};
	std::string lp_out = run_midframe_err_case(lp.get(), bad_sql);

	// ---- native candidate ----
	// flushBackendPool() drops every pooled backend connection (servers are
	// removed with OFFLINE_HARD, then re-added), so this phase runs on a FRESH
	// backend connection: the once-per-connection guard on the injected-Sync
	// warning (PgSQL_Connection::native_stmt_resync_logged) cannot have been
	// consumed by an earlier case, and the positive log assertion below is
	// guaranteed to see the line if (and only if) the branch runs.
	if (!setNativeMode(admin, true) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set native mode failed"};
	}
	drainLogToNow();
	PGConnPtr nt = open_client_conn();
	if (!nt || PQstatus(nt.get()) != CONNECTION_OK) return {false, false, "native conn failed"};
	std::string nt_out = run_midframe_err_case(nt.get(), bad_sql);
	// Single combined scan: the fallback tripwire AND a POSITIVE assertion that
	// the injected-Sync error-recovery branch actually ran in the native phase
	// (lib/PgSQL_Connection.cpp native_fetch_result_cont, native_stmt_error_resync).
	bool fell_back = false;
	bool resync_logged = false;
	scanNativePhaseLog(fell_back, resync_logged, 2000);

	// Explicit SQLSTATE assertion (42601 = syntax_error), in addition to the
	// full byte-equality check below — guards against both sides agreeing on
	// the WRONG code.
	bool sqlstate_ok = (nt_out.find("sqlstate=42601") != std::string::npos);

	bool result_match = (lp_out == nt_out) && sqlstate_ok && resync_logged;
	std::stringstream det;
	det << "midframe error-recovery; sqlstate_ok=" << (sqlstate_ok ? "yes" : "no")
	    << "; injected_sync_observed=" << (resync_logged ? "yes" : "no");
	if (!resync_logged) {
		det << " (injected-Sync branch not observed in proxysql.log)";
	}
	if (lp_out != nt_out) {
		det << " (mismatch; lp_out='" << lp_out << "' nt_out='" << nt_out << "')";
	}
	setNativeMode(admin, false);
	flushBackendPool(admin, BACKEND_HG, saved);
	return {result_match, fell_back, det.str()};
}

// ===========================================================================
// EXT_DESCRIBE_CACHED (Task E): statement-level Describe metadata cache.
//
// A statement-level Describe ('S') of an already-described global statement is
// served from the set-once cache on PgSQL_STMT_Global_info — no backend round
// trip — in BOTH backend modes. What the cache serves MUST be byte-identical to
// a round-trip (the differential is the cross-oracle). Evidence that the second
// Describe actually hit the cache: the proxy_debug(PROXY_DEBUG_MYSQL_COM, 5)
// marker line emitted by handle_post_sync_describe_message on a hit — debug
// level because the hit is the COMMON path by design (an always-on line would
// be per-query log flood). The cases below raise the debug routing through the
// admin connection for the duration of the phase (see enableDescribeDebugLog)
// so the line lands in the proxysql.log this test scrapes, then restore it —
// same durable-in-test-evidence idea as P24's injected-Sync log assertion.
//
// serialize_describe() captures the FULL Describe metadata (param OIDs + every
// RowDescription column field), unlike serialize_result()'s COMMAND_OK branch —
// so any byte difference in the 't'/'T' payload surfaces as a serial mismatch.
// ===========================================================================
static std::string serialize_describe(PGresult* r) {
	if (!r) return "<null>";
	std::stringstream ss;
	ss << "st=" << (int)PQresultStatus(r) << " ";
	int np = PQnparams(r);
	ss << "np=" << np << " ";
	for (int i = 0; i < np; i++) ss << "p" << i << "=" << PQparamtype(r, i) << ";";
	int nf = PQnfields(r);
	ss << "nf=" << nf << " ";
	for (int c = 0; c < nf; c++) {
		ss << "f" << c << "=" << (PQfname(r, c) ? PQfname(r, c) : "")
		   << ":tbl=" << PQftable(r, c) << ":col=" << PQftablecol(r, c)
		   << ":oid=" << PQftype(r, c) << ":sz=" << PQfsize(r, c)
		   << ":mod=" << PQfmod(r, c) << ":fmt=" << PQfformat(r, c) << ";";
	}
	return ss.str();
}

// Prepare `stmt` then Describe it TWICE (first = miss→populate, second = hit),
// returning "D1:<serial>;D2:<serial>;" for byte-comparison across modes/orders.
static std::string run_describe_twice(PGconn* c, const std::string& stmt_name,
                                      const std::string& query) {
	std::string out;
	if (PQsendPrepare(c, stmt_name.c_str(), query.c_str(), 0, NULL) == 0) {
		out += "PQsendPrepare:fail:" + std::string(PQerrorMessage(c)) + ";";
		return out;
	}
	PGresult* res;
	while ((res = PQgetResult(c)) != NULL) PQclear(res);
	PGresult* d1 = PQdescribePrepared(c, stmt_name.c_str()); // miss → populate
	out += "D1:" + serialize_describe(d1) + ";";
	PQclear(d1);
	PGresult* d2 = PQdescribePrepared(c, stmt_name.c_str()); // hit → served from cache
	out += "D2:" + serialize_describe(d2) + ";";
	PQclear(d2);
	return out;
}

// --- Debug-log routing for the cache-hit evidence line -----------------------
// The cache-hit marker is emitted via proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, ...).
// For it to land in the proxysql.log this test scrapes (the infra runs proxysql
// in the foreground with stderr teed into that file), two admin knobs must hold
// during the phase:
//   - admin-debug_output must include stderr → 3 (stderr + debug DB). The infra
//     default is 2 (debug DB only), which never reaches the log file;
//   - debug_levels verbosity for module 'debug_mysql_com' must be >= 5 (infra
//     default is 7; set explicitly anyway for robustness).
// DebugLogScope captures both, applies them, and restores on destruction (so
// early returns in the case runner cannot leak the raised debug routing).
static std::string adminScalar(PGconn* admin, const std::string& q) {
	PGresult* res = PQexec(admin, q.c_str());
	std::string v;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0)) {
		v = PQgetvalue(res, 0, 0);
	}
	PQclear(res);
	return v;
}

struct DebugLogScope {
	PGconn* admin;
	std::string saved_output, saved_verbosity;
	bool enabled = false;

	explicit DebugLogScope(PGconn* a) : admin(a) {
		saved_output = adminScalar(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='admin-debug_output'");
		saved_verbosity = adminScalar(admin,
			"SELECT verbosity FROM debug_levels WHERE module='debug_mysql_com'");
		if (saved_output.empty() || saved_verbosity.empty()) {
			diag("DebugLogScope: cannot read current debug conf (debug build required)");
			return;
		}
		enabled = execAdmin(admin, "SET admin-debug_output='3'") &&
		          execAdmin(admin, "LOAD ADMIN VARIABLES TO RUNTIME") &&
		          execAdmin(admin, "UPDATE debug_levels SET verbosity=7 WHERE module='debug_mysql_com'") &&
		          execAdmin(admin, "LOAD DEBUG TO RUNTIME");
	}
	~DebugLogScope() {
		if (saved_output.empty() || saved_verbosity.empty()) return;
		execAdmin(admin, "SET admin-debug_output='" + saved_output + "'");
		execAdmin(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
		execAdmin(admin, "UPDATE debug_levels SET verbosity=" + saved_verbosity +
		                 " WHERE module='debug_mysql_com'");
		execAdmin(admin, "LOAD DEBUG TO RUNTIME");
	}
	DebugLogScope(const DebugLogScope&) = delete;
	DebugLogScope& operator=(const DebugLogScope&) = delete;
};

// Single-pass scan for BOTH the libpq-fallback tripwire and the (debug-level)
// "Describe served from metadata cache" marker, counting the latter. One
// combined scan is mandatory — wait_for_log_match / get_matching_lines consume
// the stream forward, so two sequential scans for two regexes would each miss
// lines the other already read past (same reasoning as scanNativePhaseLog).
// Polls until `want_hits` markers are seen or `wait_ms` elapses.
static void scanDescribeCachePhaseLog(bool& fell_back, int& cache_hits,
                                      int want_hits, uint32_t wait_ms) {
	const std::regex re_fallback(".*falling back to libpq.*");
	const std::regex re_hit(".*Describe served from metadata cache.*");
	fell_back = false;
	cache_hits = 0;
	uint32_t elapsed = 0;
	while (true) {
		f_proxysql_log.clear(f_proxysql_log.rdstate() &
		                     ~std::ios_base::eofbit & ~std::ios_base::failbit);
		std::string line;
		while (std::getline(f_proxysql_log, line)) {
			if (!fell_back && std::regex_match(line, re_fallback)) fell_back = true;
			if (std::regex_match(line, re_hit)) cache_hits++;
		}
		if (cache_hits >= want_hits || elapsed >= wait_ms) return;
		usleep(100000);
		elapsed += 100;
	}
}

// Run Describe-x2 in `first_native` mode first (fresh, unique query → that mode
// takes the miss and POPULATES the cache: exercises that mode's CAPTURE path),
// then in the other mode (both Describes are cache HITS served from the
// first-mode-captured bytes: exercises the other mode's SERVE path). Asserts:
//   - byte-equality across the two modes (cross-oracle: served bytes == round-trip);
//   - within each mode D1 == D2 (miss and hit are byte-identical);
//   - the second (cache-serving) mode logged >= 2 Describe cache hits.
static ExtQCaseRunResult run_describe_cached(PGconn* admin, bool first_native,
                                             const std::string& stmt_name,
                                             const std::string& query,
                                             const std::vector<ServerRow>& saved) {
	// Route the debug-level cache-hit marker into proxysql.log for the whole
	// case; restored automatically on every exit path (RAII).
	DebugLogScope debug_scope(admin);
	if (!debug_scope.enabled) {
		return {false, false, "admin: enabling debug-log routing failed"};
	}

	// ---- first mode (takes the miss; populates via its capture path) ----
	if (!setNativeMode(admin, first_native) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set first mode failed"};
	}
	PGConnPtr c1 = open_client_conn();
	if (!c1 || PQstatus(c1.get()) != CONNECTION_OK) return {false, false, "first conn failed"};
	std::string out1 = run_describe_twice(c1.get(), stmt_name, query);

	// ---- second mode (both Describes are cache hits, served from mode-1 bytes) ----
	if (!setNativeMode(admin, !first_native) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set second mode failed"};
	}
	drainLogToNow();
	PGConnPtr c2 = open_client_conn();
	if (!c2 || PQstatus(c2.get()) != CONNECTION_OK) return {false, false, "second conn failed"};
	std::string out2 = run_describe_twice(c2.get(), stmt_name, query);
	bool fell_back = false;
	int cache_hits = 0;
	scanDescribeCachePhaseLog(fell_back, cache_hits, /*want_hits=*/2, 3000);

	// Within-mode miss==hit byte-parity (first mode): D1 and D2 serials must match.
	auto d1 = out1.find("D1:"), d2 = out1.find(";D2:");
	bool within_mode_equal = (d1 != std::string::npos && d2 != std::string::npos &&
		out1.substr(d1 + 3, d2 - (d1 + 3)) == out1.substr(d2 + 4, out1.size() - (d2 + 4) - 1));

	bool result_match = (out1 == out2) && within_mode_equal && (cache_hits >= 2);
	std::stringstream det;
	det << (first_native ? "native-first (native capture, libpq serve)"
	                     : "libpq-first (libpq capture, native serve)")
	    << "; within_mode_miss_eq_hit=" << (within_mode_equal ? "yes" : "no")
	    << "; cache_hits_2nd_mode=" << cache_hits;
	if (out1 != out2) det << " (cross-mode mismatch; m1='" << out1 << "' m2='" << out2 << "')";
	setNativeMode(admin, false);
	flushBackendPool(admin, BACKEND_HG, saved);
	return {result_match, fell_back, det.str()};
}

// ===========================================================================
// DEALLOCATE-forwarding regression (ABSOLUTE, not differential).
//
// ProxySQL used to intercept every single-statement DEALLOCATE and resolve the
// name only against local_stmts -- which tracks extended-query (binary)
// prepares. A name from a SQL-level PREPARE is never in that map, so ProxySQL
// answered with a fabricated "prepared statement does not exist" and never
// forwarded the command, even though the statement was alive on the backend.
//
// The differential P0/P7 cases above cannot catch this: the interception lives
// in the protocol-independent client handler, so libpq-through-ProxySQL and
// native-through-ProxySQL are affected identically and still match each other.
// These checks assert the real-PostgreSQL outcome directly. Driven on the
// native path here; the libpq-path equivalent lives in
// pgsql-extended_query_protocol_test-t (test_deallocate_sql_prepared_via_simple_query).
// ===========================================================================
static const int N_DEALLOC_REG_PER_MODE = 10;

static void run_dealloc_regression(PGconn* admin, bool native,
                                   const std::vector<ServerRow>& saved) {
	const char* m = native ? "native" : "libpq";
	if (!setNativeMode(admin, native) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		for (int i = 0; i < N_DEALLOC_REG_PER_MODE; i++)
			ok(false, "[%s] dealloc-regression: admin setup failed", m);
		return;
	}
	PGConnPtr c = open_client_conn();
	if (!c || PQstatus(c.get()) != CONNECTION_OK) {
		for (int i = 0; i < N_DEALLOC_REG_PER_MODE; i++)
			ok(false, "[%s] dealloc-regression: client connect failed", m);
		return;
	}
	PGconn* cc = c.get();

	// 0. On a fresh, unpinned connection, a DEALLOCATE of an unknown name is
	//    answered locally (no SQL PREPARE happened, so it cannot exist) rather
	//    than acquiring a backend connection just to fail.
	{ PGresult* r = PQexec(cc, "DEALLOCATE dealloc_reg_unpinned");
	  ok(PQresultStatus(r) == PGRES_FATAL_ERROR,
	     "[%s] DEALLOCATE of an unknown name on a fresh connection errors -> %s",
	     m, PQresStatus(PQresultStatus(r)));
	  PQclear(r); }

	// 1. A SQL-level PREPARE succeeds (forwarded to the backend as usual).
	{ PGresult* r = PQexec(cc, "PREPARE dealloc_reg AS SELECT 42");
	  ok(PQresultStatus(r) == PGRES_COMMAND_OK,
	     "[%s] SQL PREPARE dealloc_reg -> %s", m, PQresStatus(PQresultStatus(r)));
	  PQclear(r); }

	// 2. EXECUTE returns the row: the statement is genuinely live on the backend.
	{ PGresult* r = PQexec(cc, "EXECUTE dealloc_reg");
	  bool good = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1
	              && std::string(PQgetvalue(r, 0, 0)) == "42";
	  ok(good, "[%s] EXECUTE dealloc_reg returns 42", m);
	  PQclear(r); }

	// 3. THE FIX: DEALLOCATE of a SQL-prepared statement is forwarded and
	//    succeeds, instead of a fabricated "does not exist" error.
	{ PGresult* r = PQexec(cc, "DEALLOCATE dealloc_reg");
	  ok(PQresultStatus(r) == PGRES_COMMAND_OK,
	     "[%s] DEALLOCATE dealloc_reg succeeds (forwarded, not fabricated) -> %s",
	     m, PQresStatus(PQresultStatus(r)));
	  PQclear(r); }

	// 4. It really was deallocated on the backend: a second EXECUTE now fails.
	{ PGresult* r = PQexec(cc, "EXECUTE dealloc_reg");
	  ok(PQresultStatus(r) == PGRES_FATAL_ERROR,
	     "[%s] EXECUTE after DEALLOCATE fails, statement is gone -> %s",
	     m, PQresStatus(PQresultStatus(r)));
	  PQclear(r); }

	// 5. A mistyped/unknown name returns the backend's real error (not silent OK).
	{ PGresult* r = PQexec(cc, "DEALLOCATE dealloc_reg_never_prepared");
	  ok(PQresultStatus(r) == PGRES_FATAL_ERROR,
	     "[%s] DEALLOCATE of an unknown name errors -> %s",
	     m, PQresStatus(PQresultStatus(r)));
	  PQclear(r); }

	// 6. ...and the session is still usable afterwards: a typo must not wedge it
	//    or lock the connection onto a hostgroup.
	{ PGresult* r = PQexec(cc, "SELECT 1");
	  bool good = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1
	              && std::string(PQgetvalue(r, 0, 0)) == "1";
	  ok(good, "[%s] session still usable after a bogus DEALLOCATE", m);
	  PQclear(r); }

	// 7-9. ALL-prefix guard: a statement whose name starts with "all" must be
	//      treated as a normal DEALLOCATE (forwarded), not mistaken for
	//      DEALLOCATE ALL. Without the exact-match fix, DEALLOCATE all_users
	//      returns the tag "DEALLOCATE ALL" and never frees the statement.
	{ PGresult* r = PQexec(cc, "PREPARE all_users AS SELECT 7");
	  ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] PREPARE all_users", m);
	  PQclear(r); }
	{ PGresult* r = PQexec(cc, "DEALLOCATE all_users");
	  const char* tag = PQcmdStatus(r);
	  ok(PQresultStatus(r) == PGRES_COMMAND_OK && tag && strcmp(tag, "DEALLOCATE") == 0,
	     "[%s] DEALLOCATE all_users -> tag '%s' (a normal DEALLOCATE, not DEALLOCATE ALL)",
	     m, tag ? tag : "");
	  PQclear(r); }
	{ PGresult* r = PQexec(cc, "EXECUTE all_users");
	  ok(PQresultStatus(r) == PGRES_FATAL_ERROR,
	     "[%s] EXECUTE all_users after DEALLOCATE errors, so it was really deallocated -> %s",
	     m, PQresStatus(PQresultStatus(r)));
	  PQclear(r); }
}

// ===========================================================================
// Cross-protocol DEALLOCATE (the tracked side of the same fix).
//
// A statement prepared via the EXTENDED (binary) protocol -- PQprepare -- is
// tracked by ProxySQL in local_stmts and RENAMED on the backend
// (proxysql_ps_<id>). A SQL-text DEALLOCATE of its client name must therefore
// stay handled LOCALLY (client_close finds it) and must NOT be forwarded:
// forwarding the client name would fail on the backend, which knows it only by
// the renamed name. This guards that the DEALLOCATE-forwarding fix draws the
// line at the tracked/untracked boundary, not at "any DEALLOCATE".
// ===========================================================================
static const int N_DEALLOC_XPROTO_PER_MODE = 5;

static void run_dealloc_xproto_regression(PGconn* admin, bool native,
                                          const std::vector<ServerRow>& saved) {
	const char* m = native ? "native" : "libpq";
	if (!setNativeMode(admin, native) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		for (int i = 0; i < N_DEALLOC_XPROTO_PER_MODE; i++)
			ok(false, "[%s] xproto-dealloc: admin setup failed", m);
		return;
	}
	PGConnPtr c = open_client_conn();
	if (!c || PQstatus(c.get()) != CONNECTION_OK) {
		for (int i = 0; i < N_DEALLOC_XPROTO_PER_MODE; i++)
			ok(false, "[%s] xproto-dealloc: client connect failed", m);
		return;
	}
	PGconn* cc = c.get();

	// 1. Named binary prepare (extended protocol): ProxySQL tracks it and renames
	//    it on the backend.
	{ PGresult* r = PQprepare(cc, "xp_bp", "SELECT 77", 0, nullptr);
	  ok(PQresultStatus(r) == PGRES_COMMAND_OK,
	     "[%s] binary PQprepare xp_bp -> %s", m, PQresStatus(PQresultStatus(r)));
	  PQclear(r); }

	// 2. Binary execute returns the row.
	{ PGresult* r = PQexecPrepared(cc, "xp_bp", 0, nullptr, nullptr, nullptr, 0);
	  bool good = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1
	              && std::string(PQgetvalue(r, 0, 0)) == "77";
	  ok(good, "[%s] binary EXECUTE xp_bp returns 77", m);
	  PQclear(r); }

	// 3. SQL-text DEALLOCATE of the binary name is handled locally and succeeds
	//    -- it must NOT be forwarded (the backend name differs).
	{ PGresult* r = PQexec(cc, "DEALLOCATE xp_bp");
	  ok(PQresultStatus(r) == PGRES_COMMAND_OK,
	     "[%s] SQL DEALLOCATE of a binary-prepared name succeeds (handled locally) -> %s",
	     m, PQresStatus(PQresultStatus(r)));
	  PQclear(r); }

	// 4. It is really gone: re-executing the binary statement now fails.
	{ PGresult* r = PQexecPrepared(cc, "xp_bp", 0, nullptr, nullptr, nullptr, 0);
	  ok(PQresultStatus(r) == PGRES_FATAL_ERROR,
	     "[%s] binary EXECUTE after DEALLOCATE fails, statement is gone -> %s",
	     m, PQresStatus(PQresultStatus(r)));
	  PQclear(r); }

	// 5. Session still usable.
	{ PGresult* r = PQexec(cc, "SELECT 1");
	  bool good = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1
	              && std::string(PQgetvalue(r, 0, 0)) == "1";
	  ok(good, "[%s] session still usable after cross-protocol DEALLOCATE", m);
	  PQclear(r); }
}

// ===========================================================================
// DEALLOCATE ALL matrix.
//
// DEALLOCATE ALL now forwards to the pinned backend and releases ProxySQL's
// backend-side statement bookkeeping (backend_close_all), so SQL-level PREPARE
// statements are actually freed while binary statements and the shared global
// statement cache stay consistent. Scenarios:
//   S1 SQL-only            S2 binary-only         S3 mixed (SQL + binary)
//   S4 nothing prepared    S5 cross-connection isolation   S6 repeated cycles
//   S7 aborted-txn (DEALLOCATE ALL rejected -> statements survive, guard keeps tracking)
// ===========================================================================
static const int N_DALLALL_MATRIX = 36;

static bool exec_ok(PGconn* c, const char* q) {
	PGresult* r = PQexec(c, q);
	bool good = PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK;
	PQclear(r);
	return good;
}
static bool val_is(PGresult* r, const char* v) {
	return PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1
	       && std::string(PQgetvalue(r, 0, 0)) == v;
}

static void run_dealloc_all_matrix(PGconn* admin, bool native,
                                   const std::vector<ServerRow>& saved) {
	const char* m = native ? "native" : "libpq";
	auto fail = [&](int n, const char* why) {
		for (int i = 0; i < n; i++) ok(false, "[%s] dealloc-all matrix: %s", m, why);
	};
	if (!setNativeMode(admin, native) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		fail(N_DALLALL_MATRIX, "admin setup failed");
		return;
	}

	// ---- S1: SQL-only. Pinned by SQL PREPARE -> DEALLOCATE ALL forwards; the
	//          statements are actually freed on the backend. ----
	{
		PGConnPtr c = open_client_conn(); PGconn* cc = c.get();
		if (!c || PQstatus(cc) != CONNECTION_OK) { fail(5, "S1 conn failed"); }
		else {
			PGresult* r;
			r = PQexec(cc, "PREPARE s1 AS SELECT 1"); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S1 PREPARE s1", m); PQclear(r);
			r = PQexec(cc, "PREPARE s2 AS SELECT 2"); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S1 PREPARE s2", m); PQclear(r);
			(void)exec_ok(cc, "DEALLOCATE ALL");
			r = PQexec(cc, "EXECUTE s1"); ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "[%s] S1 EXECUTE s1 freed -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
			r = PQexec(cc, "EXECUTE s2"); ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "[%s] S1 EXECUTE s2 freed -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
			r = PQexec(cc, "PREPARE s1 AS SELECT 1"); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S1 re-PREPARE s1 (backend cleared) -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
		}
	}

	// ---- S2: binary-only. Not pinned -> DEALLOCATE ALL stays local; the client
	//          name is dropped, but the cached statement is reusable (no desync). ----
	{
		PGConnPtr c = open_client_conn(); PGconn* cc = c.get();
		if (!c || PQstatus(cc) != CONNECTION_OK) { fail(5, "S2 conn failed"); }
		else {
			PGresult* r;
			r = PQprepare(cc, "b1", "SELECT 88", 0, nullptr); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S2 binary prepare b1", m); PQclear(r);
			r = PQexecPrepared(cc, "b1", 0, nullptr, nullptr, nullptr, 0); ok(val_is(r, "88"), "[%s] S2 EXECUTE b1 = 88", m); PQclear(r);
			(void)exec_ok(cc, "DEALLOCATE ALL");
			r = PQexecPrepared(cc, "b1", 0, nullptr, nullptr, nullptr, 0); ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "[%s] S2 EXECUTE b1 after DEALLOCATE ALL fails -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
			r = PQprepare(cc, "b2", "SELECT 88", 0, nullptr); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S2 re-prepare same-hash b2 (no desync)", m); PQclear(r);
			r = PQexecPrepared(cc, "b2", 0, nullptr, nullptr, nullptr, 0); ok(val_is(r, "88"), "[%s] S2 EXECUTE b2 = 88", m); PQclear(r);
		}
	}

	// ---- S3: mixed. SQL PREPARE pins the connection; a binary prepare then lands
	//          on it. DEALLOCATE ALL forwards + backend_close_all: the SQL stmt is
	//          freed and the binary bookkeeping stays consistent (same-hash reuse
	//          still works). ----
	{
		PGConnPtr c = open_client_conn(); PGconn* cc = c.get();
		if (!c || PQstatus(cc) != CONNECTION_OK) { fail(7, "S3 conn failed"); }
		else {
			PGresult* r;
			r = PQexec(cc, "PREPARE sp AS SELECT 5"); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S3 SQL PREPARE sp", m); PQclear(r);
			r = PQprepare(cc, "bp", "SELECT 88", 0, nullptr); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S3 binary prepare bp", m); PQclear(r);
			r = PQexecPrepared(cc, "bp", 0, nullptr, nullptr, nullptr, 0); ok(val_is(r, "88"), "[%s] S3 EXECUTE bp = 88", m); PQclear(r);
			(void)exec_ok(cc, "DEALLOCATE ALL");
			r = PQexec(cc, "EXECUTE sp"); ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "[%s] S3 EXECUTE sp freed -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
			r = PQexec(cc, "PREPARE sp AS SELECT 5"); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S3 re-PREPARE sp (backend cleared) -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
			r = PQprepare(cc, "bp2", "SELECT 88", 0, nullptr); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S3 re-prepare same-hash bp2 (no desync after backend_close_all)", m); PQclear(r);
			r = PQexecPrepared(cc, "bp2", 0, nullptr, nullptr, nullptr, 0); ok(val_is(r, "88"), "[%s] S3 EXECUTE bp2 = 88", m); PQclear(r);
		}
	}

	// ---- S4: nothing prepared. DEALLOCATE ALL on a fresh connection is harmless
	//          and the session stays usable. ----
	{
		PGConnPtr c = open_client_conn(); PGconn* cc = c.get();
		if (!c || PQstatus(cc) != CONNECTION_OK) { fail(2, "S4 conn failed"); }
		else {
			ok(exec_ok(cc, "DEALLOCATE ALL"), "[%s] S4 DEALLOCATE ALL on fresh connection ok", m);
			PGresult* r = PQexec(cc, "SELECT 1"); ok(val_is(r, "1"), "[%s] S4 session usable after DEALLOCATE ALL", m); PQclear(r);
		}
	}

	// ---- S5: cross-connection isolation. connA holds a binary statement X; connB
	//          (mixed) does DEALLOCATE ALL, which forwards and releases connB's copy
	//          of X. connA's X must be untouched -- proof the shared cache/refcounts
	//          are not corrupted. ----
	{
		PGConnPtr ca = open_client_conn(); PGconn* a = ca.get();
		PGConnPtr cb = open_client_conn(); PGconn* b = cb.get();
		if (!ca || PQstatus(a) != CONNECTION_OK || !cb || PQstatus(b) != CONNECTION_OK) { fail(5, "S5 conn failed"); }
		else {
			PGresult* r;
			r = PQprepare(a, "X", "SELECT 42", 0, nullptr); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S5 connA prepare X", m); PQclear(r);
			r = PQexecPrepared(a, "X", 0, nullptr, nullptr, nullptr, 0); ok(val_is(r, "42"), "[%s] S5 connA EXECUTE X = 42", m); PQclear(r);
			r = PQexec(b, "PREPARE spB AS SELECT 1"); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S5 connB SQL PREPARE spB (pins)", m); PQclear(r);
			r = PQprepare(b, "X", "SELECT 42", 0, nullptr); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S5 connB prepare X (same hash)", m); PQclear(r);
			(void)exec_ok(b, "DEALLOCATE ALL"); // connB forwards + backend_close_all
			r = PQexecPrepared(a, "X", 0, nullptr, nullptr, nullptr, 0); ok(val_is(r, "42"), "[%s] S5 connA EXECUTE X still = 42 (no corruption) -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
		}
	}

	// ---- S6: repeated PREPARE + DEALLOCATE ALL cycles. Each cycle must re-prepare
	//          cleanly (no lingering 42P05), and the refcounts must stay balanced. ----
	{
		PGConnPtr c = open_client_conn(); PGconn* cc = c.get();
		if (!c || PQstatus(cc) != CONNECTION_OK) { fail(4, "S6 conn failed"); }
		else {
			for (int i = 1; i <= 3; i++) {
				PGresult* r = PQexec(cc, "PREPARE cyc AS SELECT 1");
				ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S6 cycle %d PREPARE cyc -> %s", m, i, PQresStatus(PQresultStatus(r)));
				PQclear(r);
				(void)exec_ok(cc, "DEALLOCATE ALL");
			}
			PGresult* r = PQexec(cc, "EXECUTE cyc"); ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "[%s] S6 EXECUTE cyc after last DEALLOCATE ALL fails -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
		}
	}

	// ---- S7: aborted transaction. DEALLOCATE ALL inside an aborted txn is rejected
	//          by the backend, so every statement survives. The aborted-txn guard
	//          must keep our tracking intact (no optimistic client/backend clear) so
	//          both the SQL PREPARE and the binary prepare are still usable after
	//          ROLLBACK -- byte-for-byte what real PostgreSQL does. ----
	{
		PGConnPtr c = open_client_conn(); PGconn* cc = c.get();
		if (!c || PQstatus(cc) != CONNECTION_OK) { fail(8, "S7 conn failed"); }
		else {
			PGresult* r;
			r = PQexec(cc, "PREPARE sp AS SELECT 5"); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S7 SQL PREPARE sp (pins)", m); PQclear(r);
			r = PQprepare(cc, "bp", "SELECT 88", 0, nullptr); ok(PQresultStatus(r) == PGRES_COMMAND_OK, "[%s] S7 binary prepare bp", m); PQclear(r);
			r = PQexecPrepared(cc, "bp", 0, nullptr, nullptr, nullptr, 0); ok(val_is(r, "88"), "[%s] S7 EXECUTE bp = 88", m); PQclear(r);
			(void)exec_ok(cc, "BEGIN");
			r = PQexec(cc, "SELECT 1/0"); ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "[%s] S7 SELECT 1/0 aborts txn -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
			r = PQexec(cc, "DEALLOCATE ALL"); ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "[%s] S7 DEALLOCATE ALL rejected in aborted txn -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
			(void)exec_ok(cc, "ROLLBACK");
			r = PQexec(cc, "EXECUTE sp"); ok(val_is(r, "5"), "[%s] S7 SQL sp survives (guard kept tracking) -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
			r = PQexecPrepared(cc, "bp", 0, nullptr, nullptr, nullptr, 0); ok(val_is(r, "88"), "[%s] S7 binary bp survives (guard kept tracking) -> %s", m, PQresStatus(PQresultStatus(r))); PQclear(r);
			r = PQexec(cc, "SELECT 99"); ok(val_is(r, "99"), "[%s] S7 session usable after aborted-txn DEALLOCATE ALL", m); PQclear(r);
		}
	}

}

int main(int /*argc*/, char** /*argv*/) {
	auto sql_cases = build_sql_cases();
	auto extq_cases = build_extq_cases();
	const int n_extra_cases = 6; // EXT_MULTI_CYCLE, EXT_REUSE, EXT_GLOBAL_DEDUP, EXT_PARSE_ERR_MIDFRAME, 2x EXT_DESCRIBE_CACHED
	int n_cases = (int)(sql_cases.size() + extq_cases.size()) + n_extra_cases;
	const int n_dealloc_reg = N_DEALLOC_REG_PER_MODE;      // SQL DEALLOCATE forwarding, native path
	const int n_dealloc_xproto = N_DEALLOC_XPROTO_PER_MODE; // binary-prepare + SQL DEALLOCATE, native path
	const int n_dealloc_all = N_DALLALL_MATRIX;           // DEALLOCATE ALL matrix, native path
	plan(n_cases + 1 + n_dealloc_reg + n_dealloc_xproto + n_dealloc_all);
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

	CoverageRecorder cov;
	diag("=== SQL-side prepared statements (cases P0-P9) ===");
	for (const auto& tc : sql_cases) {
		SqlCaseRunResult cr = run_sql(admin.get(), tc, saved);
		cov.record({tc.label, tc.kind, cr.result_match, !cr.fell_back, cr.detail});
	}
	diag("=== Extended-query prepared statements (cases P10-P29) ===");
	for (const auto& tc : extq_cases) {
		ExtQCaseRunResult cr = run_extq(admin.get(), tc, saved);
		cov.record({tc.label, tc.kind, cr.result_match, !cr.fell_back, cr.detail});
	}

	diag("=== EXT_MULTI_CYCLE: two independent extended-query cycles, one session ===");
	{
		std::vector<ExtQCase> seq;
		seq.push_back({"mc1", "EXT_MULTI_CYCLE",
			"mc1", "SELECT $1::int + 1",
			{}, {{"", {"10"}, {}, {}, 0}}, false, false, true, false, false, ""});
		seq.push_back({"mc2", "EXT_MULTI_CYCLE",
			"mc2", "SELECT $1::text || '!'",
			{}, {{"", {"hi"}, {}, {}, 0}}, false, false, true, false, false, ""});
		ExtQCaseRunResult cr = run_extq_sequence(admin.get(), seq, /*same_connection=*/true, saved);
		cov.record({"P21: EXT_MULTI_CYCLE (mc1, mc2 in one session)", "EXT_MULTI_CYCLE",
			cr.result_match, !cr.fell_back, cr.detail});
	}

	diag("=== EXT_REUSE: same statement name re-prepared after DEALLOCATE ===");
	{
		std::vector<ExtQCase> seq;
		seq.push_back({"ru1-first", "EXT_REUSE",
			"ru1", "SELECT $1::int + 1",
			{}, {{"", {"1"}, {}, {}, 0}}, false, false, true, false, false, ""});
		seq.push_back({"ru1-reprepared", "EXT_REUSE",
			"ru1", "SELECT $1::int + 100", // different query text, same client name
			{}, {{"", {"2"}, {}, {}, 0}}, false, false, true, false, false, ""});
		ExtQCaseRunResult cr = run_extq_sequence(admin.get(), seq, /*same_connection=*/true, saved);
		cov.record({"P22: EXT_REUSE ('ru1' re-prepared after DEALLOCATE)", "EXT_REUSE",
			cr.result_match, !cr.fell_back, cr.detail});
	}

	diag("=== EXT_GLOBAL_DEDUP: two sessions, identical query text ===");
	{
		std::vector<ExtQCase> seq;
		seq.push_back({"gd1", "EXT_GLOBAL_DEDUP",
			"gd1", "SELECT $1::int * 2",
			{}, {{"", {"21"}, {}, {}, 0}}, false, false, true, false, false, ""});
		seq.push_back({"gd2", "EXT_GLOBAL_DEDUP",
			"gd2", "SELECT $1::int * 2", // identical text, different session+name
			{}, {{"", {"5"}, {}, {}, 0}}, false, false, true, false, false, ""});
		ExtQCaseRunResult cr = run_extq_sequence(admin.get(), seq, /*same_connection=*/false, saved);
		cov.record({"P23: EXT_GLOBAL_DEDUP (gd1, gd2 identical query, distinct sessions)", "EXT_GLOBAL_DEDUP",
			cr.result_match, !cr.fell_back, cr.detail});
	}

	diag("=== EXT_PARSE_ERR_MIDFRAME: injected-Sync error-recovery (PQsendQueryParams) ===");
	{
		ExtQCaseRunResult cr = run_midframe_err(admin.get(), "NOT VALID SQL AT ALL", saved);
		cov.record({"P24: EXT_PARSE_ERR_MIDFRAME (mid-frame Parse error, connection reused after)",
			"EXT_PARSE_ERR_MIDFRAME", cr.result_match, !cr.fell_back, cr.detail});
	}

	// Unique query text per sub-case keeps each global statement fresh: the FIRST
	// Describe in the first-run mode is a genuine cache MISS (round-trip → populate),
	// so that mode's capture path runs; the second run mode then serves both
	// Describes from the freshly-populated cache.
	const std::string uniq = std::to_string(getpid()) + "_" + std::to_string(time(nullptr));

	diag("=== EXT_DESCRIBE_CACHED (libpq capture → native serve): Describe x2, byte-equal, 2nd from cache ===");
	{
		std::string q = "SELECT " + uniq + "025::bigint AS u, $1::int AS a, $2::text AS b";
		ExtQCaseRunResult cr = run_describe_cached(admin.get(), /*first_native=*/false, "dc25", q, saved);
		cov.record({"P25: EXT_DESCRIBE_CACHED (libpq-capture, native-serve; Describe x2 byte-equal, 2nd=cache hit)",
			"EXT_DESCRIBE_CACHED", cr.result_match, !cr.fell_back, cr.detail});
	}

	diag("=== EXT_DESCRIBE_CACHED (native capture → libpq serve): Describe x2, byte-equal, 2nd from cache ===");
	{
		std::string q = "SELECT " + uniq + "026::bigint AS u, $1::int AS a, $2::text AS b";
		ExtQCaseRunResult cr = run_describe_cached(admin.get(), /*first_native=*/true, "dc26", q, saved);
		cov.record({"P26: EXT_DESCRIBE_CACHED (native-capture, libpq-serve; Describe x2 byte-equal, 2nd=cache hit)",
			"EXT_DESCRIBE_CACHED", cr.result_match, !cr.fell_back, cr.detail});
	}

	cov.emit_tap();

	diag("=== DEALLOCATE-forwarding regression (native path; absolute checks) ===");
	run_dealloc_regression(admin.get(), /*native=*/true, saved);

	diag("=== Cross-protocol DEALLOCATE: binary prepare + SQL DEALLOCATE (native path) ===");
	run_dealloc_xproto_regression(admin.get(), /*native=*/true, saved);

	diag("=== DEALLOCATE ALL matrix (native path) ===");
	run_dealloc_all_matrix(admin.get(), /*native=*/true, saved);
	setNativeMode(admin.get(), false); // leave the proxy in the default mode

	return exit_status();
}
