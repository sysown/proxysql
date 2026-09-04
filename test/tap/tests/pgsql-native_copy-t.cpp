/**
 * @file pgsql-native_copy-t.cpp
 * @brief Differential test: native vs libpq for COPY IN / COPY OUT.
 *
 * PURPOSE
 * -------
 * Exercises COPY IN (write to backend) and COPY OUT (read from backend)
 * through ProxySQL twice:
 *   1. with `pgsql-use_native_backend_protocol='false'`  -> the libpq ORACLE
 *   2. with `pgsql-use_native_backend_protocol='true'`   -> the NATIVE path
 * (which currently routes COPY through fast_forward, see lib/PgSQL_Session.cpp)
 *
 * For COPY OUT we compare the concatenated CopyData bytes received by the
 * client. For COPY IN we compare the row count after the operation (and the
 * CommandComplete tag). For error cases we compare the SQLSTATE.
 *
 * The client is always libpq; the toggle determines which path the proxy
 * uses internally. The result MUST be byte-equal between the two phases.
 *
 * ROUTING (as of the 2026-07 COPY-hardening decision):
 *  - COPY t TO STDOUT (no FROM token)      -> native stream-through (native drive)
 *  - COPY ... FROM STDIN                   -> session fast_forward (raw byte forwarding, by design)
 *  - COPY (SELECT ... FROM ...) TO STDOUT  -> session fast_forward (regex over-match; still byte-equal)
 * Both routes must produce byte-equal results vs the libpq oracle. The
 * coverage summary reports which route each case took; fast_forward cases
 * are native_path_used=false with an explanatory detail. A CopyInResponse
 * reaching the native drive is answered with CopyFail (clean error, no hang).
 *
 * INFRA: legacy-g1 (docker-pgsql16-single, scram-sha-256, no TLS).
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <chrono>
#include <regex>
#include <unistd.h>
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
	return "pgsql_native_copy_" + std::to_string(getpid()) + "_" +
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
	const std::string re =
		".*(native_mode requested but unimplemented at this stage; falling back to libpq"
		"|native backend auth capability gap .* falling back to libpq).*";
	return wait_for_log_match(f_proxysql_log, re, 1000, 100);
}

// Mirrors CopyCmdMatcher (include/PgSQL_Thread.h:142): queries matching this
// are intercepted by the session and routed through fast_forward BEFORE the
// native connection drive ever sees them. That is the intended design after
// the 2026-07-07 decision (harden + keep fast_forward): fast_forward is raw
// byte forwarding, already zero-copy and byte-equal. We record such cases as
// native_path_used=false so the coverage summary is truthful.
static bool routed_via_fast_forward(const std::string& sql) {
	static const std::regex re(
		R"(\bCOPY\b[^;]*?\bFROM\b[^;]*?\b(?:STDIN|STDOUT)\b)",
		std::regex::icase);
	return std::regex_search(sql, re);
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

// Run a COPY TO STDOUT, return the concatenated CopyData bytes received
// (each PQgetCopyData() call yields one chunk; the protocol does not
// guarantee row-aligned chunks, so we concatenate for comparison).
struct CopyOutResult {
	std::string cmd_tag;        // CommandComplete (e.g. "COPY 1000")
	std::string concatenated;   // all CopyData chunks joined
	int nrows = 0;              // number of newlines in the concatenated bytes
	bool ok = true;             // false if any step errored
	std::string err_sqlstate;
};

static CopyOutResult run_copy_out(PGconn* c, const std::string& sql) {
	CopyOutResult r;
	PGresult* res = PQexec(c, sql.c_str());
	ExecStatusType st = PQresultStatus(res);
	if (st != PGRES_COPY_OUT) {
		const char* ss = PQresultErrorField(res, PG_DIAG_SQLSTATE);
		r.err_sqlstate = ss ? ss : "";
		r.ok = false;
		PQclear(res);
		return r;
	}
	PQclear(res);
	char* buf = NULL;
	int len = 0;
	while ((len = PQgetCopyData(c, &buf, 0)) > 0) {
		r.concatenated.append(buf, len);
		r.nrows += /* count newlines: */ [&](){
			int n = 0;
			for (int i = 0; i < len; i++) if (buf[i] == '\n') n++;
			return n;
		}();
		PQfreemem(buf);
		buf = NULL;
	}
	// Drain final results (CommandComplete + ReadyForQuery).
	res = PQgetResult(c);
	while (res != NULL) {
		ExecStatusType s = PQresultStatus(res);
		if (s == PGRES_COMMAND_OK) {
			const char* ct = PQcmdStatus(res);
			r.cmd_tag = ct ? std::string(ct) : std::string();
		} else if (s == PGRES_FATAL_ERROR) {
			const char* ss = PQresultErrorField(res, PG_DIAG_SQLSTATE);
			r.err_sqlstate = ss ? ss : "";
			r.ok = false;
		}
		PQclear(res);
		res = PQgetResult(c);
	}
	return r;
}

struct CopyInResult {
	int count = -1;          // SELECT count(*) after the COPY
	std::string cmd_tag;
	bool ok = true;
	std::string err_sqlstate;
};

static CopyInResult run_copy_in(PGconn* c, const std::string& sql,
                                const std::vector<std::string>& rows,
                                const std::string& end_err_msg = "") {
	CopyInResult r;
	PGresult* res = PQexec(c, sql.c_str());
	ExecStatusType st = PQresultStatus(res);
	if (st != PGRES_COPY_IN) {
		const char* ss = PQresultErrorField(res, PG_DIAG_SQLSTATE);
		r.err_sqlstate = ss ? ss : "";
		r.ok = false;
		PQclear(res);
		return r;
	}
	PQclear(res);
	for (const auto& row : rows) {
		std::string line = row + "\n";
		if (PQputCopyData(c, line.data(), (int)line.size()) != 1) {
			r.ok = false;
			return r;
		}
	}
	if (end_err_msg.empty()) {
		if (PQputCopyEnd(c, NULL) != 1) {
			r.ok = false;
			return r;
		}
	} else {
		// Send CopyFail: PQputCopyEnd with non-NULL errormsg.
		if (PQputCopyEnd(c, end_err_msg.c_str()) != 1) {
			r.ok = false;
			return r;
		}
	}
	// Drain.
	res = PQgetResult(c);
	while (res != NULL) {
		ExecStatusType s = PQresultStatus(res);
		if (s == PGRES_COMMAND_OK) {
			const char* ct = PQcmdStatus(res);
			r.cmd_tag = ct ? std::string(ct) : std::string();
		} else if (s == PGRES_FATAL_ERROR) {
			const char* ss = PQresultErrorField(res, PG_DIAG_SQLSTATE);
			r.err_sqlstate = ss ? ss : "";
			r.ok = false;
		}
		PQclear(res);
		res = PQgetResult(c);
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

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

struct CopyOutCase {
	std::string label, kind;
	std::string setup;     // {T} substituted
	std::string cmd;       // {T} substituted
};

struct CopyInCase {
	std::string label, kind;
	std::string setup;     // {T} substituted
	std::string cmd;       // {T} substituted
	std::vector<std::string> rows;
	int expected_count;    // -1 = don't verify
	std::string fail_msg;  // non-empty => use PQputCopyEnd(fail_msg) instead of success
};

static std::string rows_text(int n) {
	std::string s;
	for (int i = 1; i <= n; i++) {
		s += std::to_string(i) + "\trow_" + std::to_string(i) + "\n";
	}
	return s;
}

static std::vector<std::string> split_lines(const std::string& s) {
	std::vector<std::string> out;
	std::string line;
	for (char c : s) {
		if (c == '\n') { out.push_back(line); line.clear(); }
		else if (c != '\r') { line += c; }
	}
	if (!line.empty()) out.push_back(line);
	return out;
}

static std::vector<CopyOutCase> copy_out_cases() {
	return {
		{"C0: COPY TO STDOUT (text, 100 rows)", "COPY_OUT",
		 "DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int, name text); "
		 "INSERT INTO {T} SELECT g, 'n' || g FROM generate_series(1, 100) g;",
		 "COPY {T} TO STDOUT"},
		{"C1: COPY TO STDOUT (CSV with HEADER, 50 rows)", "COPY_OUT",
		 "DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int, name text); "
		 "INSERT INTO {T} SELECT g, 'v' || g FROM generate_series(1, 50) g;",
		 "COPY {T} TO STDOUT WITH (FORMAT csv, HEADER true)"},
		{"C2: COPY (id, val) partial columns, 25 rows", "COPY_OUT",
		 "DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int, val text, other text); "
		 "INSERT INTO {T} SELECT g, 'v' || g, 'o' || g FROM generate_series(1, 25) g;",
		 "COPY {T}(id, val) TO STDOUT"},
		{"C3: COPY (SELECT ... WHERE id < 100) TO STDOUT, 99 rows", "COPY_OUT",
		 "DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int, name text); "
		 "INSERT INTO {T} SELECT g, 'n' || g FROM generate_series(1, 200) g;",
		 "COPY (SELECT id, name FROM {T} WHERE id < 100) TO STDOUT"},
		{"C9: COPY TO STDOUT (10MB payload, 1000 rows of 1KB)", "COPY_OUT_LARGE",
		 "DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int, payload text); "
		 "INSERT INTO {T} SELECT g, repeat('x', 1024) FROM generate_series(1, 1000) g;",
		 "COPY {T} TO STDOUT"},
		{"C10: COPY (SELECT ... LIMIT 50) TO STDOUT", "COPY_OUT",
		 "DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int); "
		 "INSERT INTO {T} SELECT g FROM generate_series(1, 1000) g;",
		 "COPY (SELECT * FROM {T} LIMIT 50) TO STDOUT"},
		{"C11: COPY (SELECT ... WHERE false) TO STDOUT, 0 rows", "COPY_OUT",
		 "DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int);",
		 "COPY (SELECT * FROM {T} WHERE false) TO STDOUT"},
	};
}

static std::vector<CopyInCase> copy_in_cases() {
	std::vector<CopyInCase> v;

	// C4: COPY FROM STDIN (text, 100 rows)
	{
		std::vector<std::string> rows;
		for (int i = 0; i < 100; i++) rows.push_back(std::to_string(i) + "\trow_" + std::to_string(i));
		v.push_back({"C4: COPY FROM STDIN (text, 100 rows)", "COPY_IN",
			"DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int, name text);",
			"COPY {T} FROM STDIN", rows, 100, ""});
	}

	// C5: COPY FROM STDIN (CSV with HEADER)
	{
		std::vector<std::string> rows;
		rows.push_back("id,name");
		for (int i = 0; i < 50; i++) rows.push_back(std::to_string(i) + ",v" + std::to_string(i));
		v.push_back({"C5: COPY FROM STDIN (CSV with HEADER, 50 rows)", "COPY_IN",
			"DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int, name text);",
			"COPY {T} FROM STDIN WITH (FORMAT csv, HEADER true)", rows, 50, ""});
	}

	// C6: COPY FROM STDIN with quoted/escaped values
	{
		std::vector<std::string> rows = {
			"1\thello\tworld",
			"2\thas\ttab\\there",
			"3\thas\nnewline",
			"4\thas\"quote",
			"5\tcomma,inside",
		};
		v.push_back({"C6: COPY FROM STDIN (quoted/escaped values)", "COPY_IN",
			"DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int, name text, note text);",
			"COPY {T} FROM STDIN", rows, 5, ""});
	}

	// C7: COPY FROM STDIN with non-default NULL marker '?'
	{
		std::vector<std::string> rows = {
			"1\\N\\N",
			"2\\N?",
		};
		v.push_back({"C7: COPY FROM STDIN (NULL marker '?')", "COPY_IN",
			"DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int, a text, b text);",
			"COPY {T} FROM STDIN WITH (NULL '?')", rows, 2, ""});
	}

	// C8: COPY FROM STDIN (2-col out of 4, rest DEFAULT)
	{
		std::vector<std::string> rows;
		for (int i = 0; i < 50; i++) rows.push_back(std::to_string(i) + "\tval_" + std::to_string(i));
		v.push_back({"C8: COPY FROM STDIN (2 cols, 2 DEFAULT-filled)", "COPY_IN",
			"DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int, val text, "
			"created_at timestamp DEFAULT now(), updated_at timestamp DEFAULT now());",
			"COPY {T}(id, val) FROM STDIN", rows, 50, ""});
	}

	// C12: COPY FROM STDIN with mid-stream type error
	{
		std::vector<std::string> rows;
		for (int i = 0; i < 50; i++) rows.push_back(std::to_string(i));
		rows.push_back("not_an_int");
		v.push_back({"C12: COPY FROM STDIN (mid-stream type error)", "COPY_IN",
			"DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int);",
			"COPY {T} FROM STDIN", rows, -1, ""});
	}

	// C13: COPY FROM STDIN with CopyFail mid-stream
	{
		std::vector<std::string> rows;
		for (int i = 0; i < 10; i++) rows.push_back(std::to_string(i));
		v.push_back({"C13: COPY FROM STDIN (CopyFail mid-stream)", "COPY_IN",
			"DROP TABLE IF EXISTS {T}; CREATE TABLE {T} (id int);",
			"COPY {T} FROM STDIN", rows, -1, "client_cancel: giving up"});
	}

	return v;
}

struct CaseRunResult { bool result_match; bool fell_back; std::string detail; };

static CaseRunResult run_out_case(PGconn* admin, const CopyOutCase& tc,
                                  const std::vector<ServerRow>& saved) {
	std::string tbl = make_table_name();
	std::string tbl_n = tbl + "_n";
	std::string setup  = substitute_table(tc.setup, tbl);
	std::string setup_n = substitute_table(tc.setup, tbl_n);
	std::string cmd    = substitute_table(tc.cmd, tbl);
	std::string cmd_n  = substitute_table(tc.cmd, tbl_n);

	// ---- libpq control ----
	if (!setNativeMode(admin, false) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set libpq mode failed"};
	}
	PGConnPtr lp = open_client_conn();
	if (!lp || PQstatus(lp.get()) != CONNECTION_OK) return {false, false, "libpq conn failed"};
	PGresult* sr = PQexec(lp.get(), setup.c_str());
	if (PQresultStatus(sr) != PGRES_COMMAND_OK) {
		diag("libpq setup failed: %s -- %s", setup.c_str(), PQresultErrorMessage(sr));
		PQclear(sr);
		return {false, false, "libpq setup failed"};
	}
	PQclear(sr);
	auto t0 = std::chrono::steady_clock::now();
	CopyOutResult lp_r = run_copy_out(lp.get(), cmd);
	auto t1 = std::chrono::steady_clock::now();

	// ---- native candidate ----
	if (!setNativeMode(admin, true) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set native mode failed"};
	}
	drainLogToNow();
	PGConnPtr nt = open_client_conn();
	if (!nt || PQstatus(nt.get()) != CONNECTION_OK) return {false, false, "native conn failed"};
	sr = PQexec(nt.get(), setup_n.c_str());
	if (PQresultStatus(sr) != PGRES_COMMAND_OK) {
		diag("native setup failed: %s -- %s", setup_n.c_str(), PQresultErrorMessage(sr));
		PQclear(sr);
		return {false, false, "native setup failed"};
	}
	PQclear(sr);
	auto t2 = std::chrono::steady_clock::now();
	CopyOutResult nt_r = run_copy_out(nt.get(), cmd_n);
	auto t3 = std::chrono::steady_clock::now();
	bool fell_back = nativeFallbackObserved();

	bool result_match = (lp_r.cmd_tag == nt_r.cmd_tag) &&
	                    (lp_r.concatenated == nt_r.concatenated) &&
	                    (lp_r.err_sqlstate == nt_r.err_sqlstate);
	std::stringstream det;
	auto ms = [](std::chrono::steady_clock::time_point a, std::chrono::steady_clock::time_point b){
		return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
	};
	det << "lp_bytes=" << lp_r.concatenated.size() << " nt_bytes=" << nt_r.concatenated.size()
	    << " lp_rows=" << lp_r.nrows << " nt_rows=" << nt_r.nrows
	    << " lp_tag='" << lp_r.cmd_tag << "' nt_tag='" << nt_r.cmd_tag << "'"
	    << " lp=" << ms(t0, t1) << "ms nt=" << ms(t2, t3) << "ms";
	if (!result_match) {
		det << " (mismatch; sqlstate lp='" << lp_r.err_sqlstate << "' nt='" << nt_r.err_sqlstate << "')";
	}
	setNativeMode(admin, false);
	flushBackendPool(admin, BACKEND_HG, saved);
	return {result_match, fell_back, det.str()};
}

static CaseRunResult run_in_case(PGconn* admin, const CopyInCase& tc,
                                 const std::vector<ServerRow>& saved) {
	std::string tbl = make_table_name();
	std::string tbl_n = tbl + "_n";
	std::string setup  = substitute_table(tc.setup, tbl);
	std::string setup_n = substitute_table(tc.setup, tbl_n);
	std::string cmd    = substitute_table(tc.cmd, tbl);
	std::string cmd_n  = substitute_table(tc.cmd, tbl_n);
	std::string count_q = "SELECT count(*) FROM " + tbl;
	std::string count_q_n = "SELECT count(*) FROM " + tbl_n;

	// ---- libpq control ----
	if (!setNativeMode(admin, false) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set libpq mode failed"};
	}
	PGConnPtr lp = open_client_conn();
	if (!lp || PQstatus(lp.get()) != CONNECTION_OK) return {false, false, "libpq conn failed"};
	PGresult* sr = PQexec(lp.get(), setup.c_str());
	PQclear(sr);
	CopyInResult lp_r = run_copy_in(lp.get(), cmd, tc.rows, tc.fail_msg);
	int lp_count = (tc.expected_count >= 0) ? run_count_query(lp.get(), count_q) : 0;

	// ---- native candidate ----
	if (!setNativeMode(admin, true) || !flushBackendPool(admin, BACKEND_HG, saved)) {
		return {false, false, "admin: set native mode failed"};
	}
	drainLogToNow();
	PGConnPtr nt = open_client_conn();
	if (!nt || PQstatus(nt.get()) != CONNECTION_OK) return {false, false, "native conn failed"};
	sr = PQexec(nt.get(), setup_n.c_str());
	PQclear(sr);
	CopyInResult nt_r = run_copy_in(nt.get(), cmd_n, tc.rows, tc.fail_msg);
	int nt_count = (tc.expected_count >= 0) ? run_count_query(nt.get(), count_q_n) : 0;
	bool fell_back = nativeFallbackObserved();

	bool result_match;
	if (tc.expected_count >= 0) {
		result_match = (lp_r.cmd_tag == nt_r.cmd_tag) && (lp_count == nt_count) &&
		                (lp_r.err_sqlstate == nt_r.err_sqlstate);
	} else {
		// For error cases, just compare SQLSTATE.
		result_match = (lp_r.err_sqlstate == nt_r.err_sqlstate);
	}
	std::stringstream det;
	det << "lp_count=" << lp_count << " nt_count=" << nt_count
	    << " lp_tag='" << lp_r.cmd_tag << "' nt_tag='" << nt_r.cmd_tag << "'"
	    << " sqlstate lp='" << lp_r.err_sqlstate << "' nt='" << nt_r.err_sqlstate << "'";
	if (!result_match) det << " (mismatch)";
	setNativeMode(admin, false);
	flushBackendPool(admin, BACKEND_HG, saved);
	return {result_match, fell_back, det.str()};
}

int main(int /*argc*/, char** /*argv*/) {
	auto outs = copy_out_cases();
	auto ins  = copy_in_cases();
	int n_cases = (int)(outs.size() + ins.size());
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
	for (const auto& tc : outs) {
		CaseRunResult cr = run_out_case(admin.get(), tc, saved);
		bool ff = routed_via_fast_forward(tc.cmd);
		std::string detail = cr.detail;
		if (ff) detail += " [routed via session fast_forward (by design)]";
		cov.record({tc.label, tc.kind, cr.result_match, ff ? false : !cr.fell_back, detail});
	}
	for (const auto& tc : ins) {
		CaseRunResult cr = run_in_case(admin.get(), tc, saved);
		bool ff = routed_via_fast_forward(tc.cmd);
		std::string detail = cr.detail;
		if (ff) detail += " [routed via session fast_forward (by design)]";
		cov.record({tc.label, tc.kind, cr.result_match, ff ? false : !cr.fell_back, detail});
	}
	cov.emit_tap();
	return exit_status();
}
