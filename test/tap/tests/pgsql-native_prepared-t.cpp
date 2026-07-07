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
// by this file (see taskD-report.md for the log evidence that this case
// actually reaches that branch).
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
	if (!setNativeMode(admin, true) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set native mode failed"};
	}
	drainLogToNow();
	PGConnPtr nt = open_client_conn();
	if (!nt || PQstatus(nt.get()) != CONNECTION_OK) return {false, false, "native conn failed"};
	std::string nt_out = run_midframe_err_case(nt.get(), bad_sql);
	bool fell_back = nativeFallbackObserved();

	// Explicit SQLSTATE assertion (42601 = syntax_error), in addition to the
	// full byte-equality check below — guards against both sides agreeing on
	// the WRONG code.
	bool sqlstate_ok = (nt_out.find("sqlstate=42601") != std::string::npos);

	bool result_match = (lp_out == nt_out) && sqlstate_ok;
	std::stringstream det;
	det << "midframe error-recovery; sqlstate_ok=" << (sqlstate_ok ? "yes" : "no");
	if (!result_match) {
		det << " (mismatch; lp_out='" << lp_out << "' nt_out='" << nt_out << "')";
	}
	setNativeMode(admin, false);
	flushBackendPool(admin, BACKEND_HG, saved);
	return {result_match, fell_back, det.str()};
}

int main(int /*argc*/, char** /*argv*/) {
	auto sql_cases = build_sql_cases();
	auto extq_cases = build_extq_cases();
	const int n_extra_cases = 4; // EXT_MULTI_CYCLE, EXT_REUSE, EXT_GLOBAL_DEDUP, EXT_PARSE_ERR_MIDFRAME
	int n_cases = (int)(sql_cases.size() + extq_cases.size()) + n_extra_cases;
	plan(n_cases + 1);
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

	cov.emit_tap();
	return exit_status();
}
