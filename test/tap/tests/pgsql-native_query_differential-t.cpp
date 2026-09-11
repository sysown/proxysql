/**
 * @file pgsql-native_query_differential-t.cpp
 * @brief Differential test: native path vs libpq path on a broad query corpus.
 *
 * PURPOSE
 * -------
 * `pgsql-native_auth_differential-t` covers the auth path and a handful of
 * simple SELECTs. This test goes broader: DML, DDL, multi-statement, empty
 * result, NULL-heavy, large result, transactions. For each query it runs the
 * same query through ProxySQL twice:
 *   1. with `pgsql-use_native_backend_protocol='false'`  -> the libpq ORACLE
 *   2. with `pgsql-use_native_backend_protocol='true'`   -> the NATIVE path
 * and asserts the client-visible results are byte-for-byte identical (same
 * column count, same column names, same column type OIDs, same row count,
 * same row values, same SQLSTATE for errors).
 *
 * Like the auth test, it ALSO asserts the native run actually used the native
 * path (no fallback warning in the proxy log).
 *
 * PROXYSQL INTERNAL SESSION (the last 12 assertions)
 * -------------------------------------------------
 * The corpus above compares RESULTS. The tail of main() applies the same
 * two-phase method to `PROXYSQL INTERNAL SESSION`, which the corpus cannot
 * carry: both paths answer it, but with legitimately DIFFERENT documents (they
 * describe different backend connections), so the assertions are on whether the
 * command is answered at all and on the SHAPE of the native document -- not on
 * equality. It is a regression guard for a crash, not a fidelity check: four
 * get_pg_*() accessors used to call libpq on the NULL PGconn of a native
 * connection and the resulting NULL, assigned into a nlohmann::json, aborted the
 * whole proxy process. See the comment block at that section for detail.
 *
 * INFRA / SCENARIO COVERAGE
 * -------------------------
 * Same legacy-g1 infra as the auth test (docker-pgsql16-single, scram-sha-256
 * over non-TLS). All queries are LIVE; no SKIP scenarios. The infra backend
 * has the testuser with CREATE permission on its own database, so DDL is
 * available.
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <sys/select.h>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "json.hpp"

using nlohmann::json;

CommandLine cl;

static const int BACKEND_HG = 0;

// Unique-per-run table name to avoid collisions if a prior run left state.
static std::string make_table_name() {
    return "pgsql_native_qdiff_" + std::to_string(getpid()) + "_" +
        std::to_string(time(nullptr));
}

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

struct QueryResult {
    bool ok = false;
    int nfields = 0;
    int nrows = 0;
    std::vector<std::string> colnames;
    std::vector<Oid> coltypes;
    std::vector<std::vector<std::string>> rows;  // "\\N" sentinel for NULL
    std::string err_sqlstate;
    std::string cmd_tag;  // CommandComplete (e.g. "INSERT 0 3", "SELECT 5") for empty results

    bool operator==(const QueryResult& o) const {
        return ok == o.ok && nfields == o.nfields && nrows == o.nrows &&
               colnames == o.colnames && coltypes == o.coltypes &&
               rows == o.rows && err_sqlstate == o.err_sqlstate &&
               cmd_tag == o.cmd_tag;
    }
    std::string describe() const {
        std::stringstream ss;
        ss << "ok=" << ok << " nfields=" << nfields << " nrows=" << nrows
           << " sqlstate='" << err_sqlstate << "'"
           << " tag='" << cmd_tag << "'";
        return ss.str();
    }
};

static QueryResult run_one_query(PGconn* conn, const std::string& q) {
    QueryResult r;
    PGresult* res = PQexec(conn, q.c_str());
    ExecStatusType st = PQresultStatus(res);
    if (st == PGRES_TUPLES_OK || st == PGRES_COMMAND_OK) {
        r.ok = true;
        r.nfields = PQnfields(res);
        r.nrows = PQntuples(res);
        // CommandComplete cmdtag (only for COMMAND_OK, e.g. "INSERT 0 3")
        const char* ct = PQcmdStatus(res);
        r.cmd_tag = (ct != nullptr) ? std::string(ct) : std::string();
        for (int c = 0; c < r.nfields; c++) {
            r.colnames.emplace_back(PQfname(res, c) ? PQfname(res, c) : "");
            r.coltypes.push_back(PQftype(res, c));
        }
        for (int row = 0; row < r.nrows; row++) {
            std::vector<std::string> vals;
            for (int c = 0; c < r.nfields; c++) {
                if (PQgetisnull(res, row, c)) {
                    vals.emplace_back("\\N");
                } else {
                    vals.emplace_back(PQgetvalue(res, row, c));
                }
            }
            r.rows.push_back(std::move(vals));
        }
    } else {
        r.ok = false;
        const char* ss = PQresultErrorField(res, PG_DIAG_SQLSTATE);
        r.err_sqlstate = ss ? ss : "";
    }
    PQclear(res);
    return r;
}

// Admin helpers (same pattern as the auth test, copied to keep this file
// self-contained — the alternative of factoring a shared header would force
// every legacy-g* test to depend on it, which is a heavier change than this
// test warrants).
static PGConnPtr createAdminConn() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_admin_host
       << " port=" << cl.pgsql_admin_port
       << " user=" << cl.admin_username
       << " password=" << cl.admin_password;
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execAdmin(PGconn* admin, const std::string& query) {
    PGresult* res = PQexec(admin, query.c_str());
    ExecStatusType st = PQresultStatus(res);
    bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    if (!good) {
        diag("Admin query failed: %s -- %s", query.c_str(), PQerrorMessage(admin));
    }
    PQclear(res);
    return good;
}

static bool setNativeMode(PGconn* admin, bool enabled) {
    std::string v = enabled ? "true" : "false";
    bool a = execAdmin(admin, "SET pgsql-use_native_backend_protocol='" + v + "'");
    bool b = execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
    return a && b;
}

struct ServerRow {
    std::string hostname;
    std::string port;
    std::string max_connections;
    std::string comment;
};

static std::vector<ServerRow> readServers(PGconn* admin, int hg) {
    std::vector<ServerRow> rows;
    std::stringstream q;
    q << "SELECT hostname, port, max_connections, comment FROM pgsql_servers "
      << "WHERE hostgroup_id=" << hg;
    PGresult* res = PQexec(admin, q.str().c_str());
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        for (int i = 0; i < PQntuples(res); i++) {
            ServerRow r;
            r.hostname = PQgetvalue(res, i, 0);
            r.port = PQgetvalue(res, i, 1);
            r.max_connections = PQgetvalue(res, i, 2);
            r.comment = PQgetisnull(res, i, 3) ? "" : PQgetvalue(res, i, 3);
            rows.push_back(std::move(r));
        }
    } else {
        diag("readServers failed: %s", PQerrorMessage(admin));
    }
    PQclear(res);
    return rows;
}

static bool flushBackendPool(PGconn* admin, int hg, const std::vector<ServerRow>& saved) {
    if (saved.empty()) {
        diag("flushBackendPool: no saved server rows for hg %d; cannot flush safely", hg);
        return false;
    }
    std::stringstream del;
    del << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << hg;
    if (!execAdmin(admin, del.str())) return false;
    if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    for (const auto& r : saved) {
        std::stringstream ins;
        ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) "
            << "VALUES (" << hg << ",'" << r.hostname << "'," << r.port << ","
            << (r.max_connections.empty() ? std::string("1000") : r.max_connections)
            << ",'" << r.comment << "')";
        if (!execAdmin(admin, ins.str())) return false;
    }
    if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    usleep(200000);
    return true;
}

// Open a client conn, run every query in `queries` on it, return results.
static std::vector<QueryResult> run_query_set(PGconn* conn,
                                              const std::vector<std::string>& queries,
                                              bool& conn_ok) {
    std::vector<QueryResult> out;
    if (!conn || PQstatus(conn) != CONNECTION_OK) {
        conn_ok = false;
        return out;
    }
    conn_ok = true;
    for (const auto& q : queries) {
        out.push_back(run_one_query(conn, q));
    }
    return out;
}

static PGConnPtr createClientConn() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
       << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
       << " dbname=" << cl.pgsql_username << " sslmode=disable";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

// Same as createClientConn(), plus the client-supplied `options` a real client passes
// as PGOPTIONS / options= in its conninfo.
static PGConnPtr createClientConnWithOptions(const std::string& options) {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
       << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
       << " dbname=" << cl.pgsql_username << " sslmode=disable";
    if (!options.empty()) ss << " options='" << options << "'";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

// Connects with `options` and reports what the BACKEND session ended up with, as one
// comparable string. A connection failure is folded into the same string rather than
// bailing, because failing to connect on one path and not the other is exactly the
// divergence this phase is here to catch.
static std::string options_outcome(const std::string& options, const std::string& probe) {
    PGConnPtr c = createClientConnWithOptions(options);
    if (!c || PQstatus(c.get()) != CONNECTION_OK) {
        std::string e = c ? PQerrorMessage(c.get()) : "PQconnectdb returned null";
        for (char& ch : e) if (ch == '\n') ch = ' ';
        return "CONNECT-FAILED: " + e;
    }
    QueryResult r = run_one_query(c.get(), probe);
    if (!r.ok) return "QUERY-FAILED: sqlstate=" + r.err_sqlstate;
    if (r.rows.empty() || r.rows[0].empty()) return "NO-ROWS";
    return r.rows[0][0];
}

// Runs `sql` under a hard wall-clock deadline using libpq's async API.
// Returns 1 = completed (result in *out, caller PQclears), 0 = deadline expired,
// -1 = transport error. Copied from pgsql-native_prepared-t.cpp, in line with this
// file's self-contained-helpers convention above.
//
// Needed because the failure this guards against is an unbounded hang: a plain
// PQexec would wedge the whole TAP suite instead of reporting `not ok`.
static int exec_with_deadline(PGconn* c, const char* sql, int timeout_ms, PGresult** out) {
    *out = nullptr;
    if (PQsendQuery(c, sql) == 0) return -1;
    const int sock = PQsocket(c);
    if (sock < 0) return -1;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (PQisBusy(c)) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return 0;
        const long long left_us =
            std::chrono::duration_cast<std::chrono::microseconds>(deadline - now).count();
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        struct timeval tv;
        tv.tv_sec = (time_t)(left_us / 1000000);
        tv.tv_usec = (suseconds_t)(left_us % 1000000);
        const int rc = select(sock + 1, &rfds, nullptr, nullptr, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (rc == 0) return 0;
        if (PQconsumeInput(c) == 0) return -1;
    }
    *out = PQgetResult(c);
    while (!PQisBusy(c)) {
        PGresult* extra = PQgetResult(c);
        if (extra == nullptr) break;
        PQclear(extra);
    }
    return 1;
}

// One step of the within-session variable-sync sequence, folded into a comparable
// string. Any hang shows up as "TIMEOUT(<step>)" rather than wedging the run.
static std::string deadline_step(PGconn* c, const char* step, const char* sql, bool want_rows) {
    PGresult* r = nullptr;
    const int rc = exec_with_deadline(c, sql, 10000, &r);
    if (rc == 0) return std::string("TIMEOUT(") + step + ")";
    if (rc < 0) { if (r) PQclear(r); return std::string("SENDFAIL(") + step + ")"; }
    const ExecStatusType st = PQresultStatus(r);
    std::string outcome;
    if (st == PGRES_TUPLES_OK && want_rows) {
        outcome = (PQntuples(r) == 1 && PQnfields(r) == 1 && !PQgetisnull(r, 0, 0))
                      ? std::string(PQgetvalue(r, 0, 0))
                      : std::string("BAD-SHAPE");
    } else if (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK) {
        outcome = "OK";
    } else {
        const char* ss = PQresultErrorField(r, PG_DIAG_SQLSTATE);
        outcome = std::string("ERR(") + step + "," + (ss ? ss : "?") + ")";
    }
    PQclear(r);
    return outcome;
}

static std::fstream f_proxysql_log{};

static bool nativeFallbackObserved() {
    const std::string regex =
        ".*(native_mode requested but unimplemented at this stage; falling back to libpq"
        "|native backend auth capability gap .* falling back to libpq).*";
    return wait_for_log_match(f_proxysql_log, regex, /*timeout_ms*/ 1000, /*poll*/ 100);
}

static void drainLogToNow() {
    get_matching_lines(f_proxysql_log, "__no_such_marker_line__");
}

// ------------------------------------------------- internal-session probe
//
// `PROXYSQL INTERNAL SESSION` is a ProxySQL command, so it has no direct-
// PostgreSQL oracle. Its oracle here is the OTHER ProxySQL path: the same
// command, on the same proxy, with pgsql-use_native_backend_protocol flipped.

struct InternalSession {
    bool answered = false;
    json doc;
};

// Pin a freshly-built backend connection to a client session, then read the
// session-introspection document back out of it.
//
// BEGIN keeps the backend attached for the lifetime of the transaction, and the
// create_new_connection hint guarantees the attached connection was built under
// the CURRENT value of pgsql-use_native_backend_protocol rather than reused from
// the pool. Both matter: with no backend attached, "backends" is empty and not a
// single get_pg_*() accessor is called, so the probe would pass while testing
// nothing.
static InternalSession probe_internal_session() {
    InternalSession out;
    auto c = createClientConn();
    if (!c || PQstatus(c.get()) != CONNECTION_OK) {
        diag("internal-session probe: client connection failed: %s",
             c ? PQerrorMessage(c.get()) : "null conn");
        return out;
    }
    PQclear(PQexec(c.get(), "BEGIN"));
    PQclear(PQexec(c.get(), "/* create_new_connection=1 */ SELECT 42"));

    PGresult* r = PQexec(c.get(), "PROXYSQL INTERNAL SESSION");
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0)) {
        try {
            out.doc = json::parse(PQgetvalue(r, 0, 0));
            out.answered = true;
        } catch (const std::exception& e) {
            diag("internal-session probe: unparseable JSON: %s", e.what());
        }
    } else {
        diag("internal-session probe: PROXYSQL INTERNAL SESSION failed: %s",
             PQerrorMessage(c.get()));
    }
    PQclear(r);
    PQclear(PQexec(c.get(), "COMMIT"));
    return out;
}

// backends[0].conn.pgsql, or a null json when no backend is attached.
static json backend_pgsql(const json& j) {
    try {
        if (j.contains("backends") && j["backends"].is_array() && !j["backends"].empty()) {
            const json& b = j["backends"][0];
            if (b.contains("conn") && b["conn"].contains("pgsql")) return b["conn"]["pgsql"];
        }
    } catch (const std::exception&) {}
    return json();
}

// One assertion that a reported field survived as a JSON string. A NULL returned
// by a libpq accessor cannot reach this point: assigning it into a nlohmann::json
// constructs a std::string from a null pointer and throws, taking the process
// with it. So this passes only once the accessor has a native branch returning a
// real C string.
static void ok_pgsql_string_field(const json& pg, const char* key) {
    const bool present = pg.is_object() && pg.contains(key);
    const std::string got = present ? pg[key].dump() : std::string("<absent>");
    ok(present && pg[key].is_string(),
       "native: backends[0].conn.pgsql.%s is a string (got %s)", key, got.c_str());
}

// backends[0].conn.pgsql.address is PgSQL_Connection::get_pg_connection(), the libpq
// PGconn. A libpq connection always has one; a native connection never does. That is
// what tells the two legs apart, and each leg asserts its own so neither can be served
// by the wrong kind of pooled connection without the run saying so.
static std::string pgconn_address(const json& pg) {
    if (pg.is_object() && pg.contains("address") && pg["address"].is_string())
        return pg[std::string("address")].get<std::string>();
    return "<absent>";
}
static bool is_null_pgconn(const std::string& addr) {
    return addr == "(nil)" || addr == "0x0" || addr == "0";
}

// One assertion that a reported field is IDENTICAL on both paths. Used for values
// that describe the SERVER rather than the connection, so unlike host_addr / port /
// options they must not differ between libpq and native. Compared against the oracle
// rather than a literal, so the assertion does not pin the infra's PostgreSQL version.
static void ok_pgsql_field_matches(const json& opg, const json& npg, const char* key) {
    const bool have = opg.is_object() && npg.is_object() &&
                      opg.contains(key) && npg.contains(key);
    const std::string o = have ? opg[key].dump() : std::string("<absent>");
    const std::string n = have ? npg[key].dump() : std::string("<absent>");
    ok(have && opg[key] == npg[key],
       "native: backends[0].conn.pgsql.%s matches libpq (libpq=%s native=%s)",
       key, o.c_str(), n.c_str());
}

// One query: 2 assertions (result match, native path used).
// On mismatch, log the diff to help diagnose.
static void assert_query(const char* label, const std::vector<QueryResult>& libpq_res,
                         size_t i, const std::vector<QueryResult>& native_res) {
    if (i >= libpq_res.size() || i >= native_res.size()) {
        ok(false, "query %s: index out of range (libpq=%zu native=%zu)",
           label, libpq_res.size(), native_res.size());
        return;
    }
    if (libpq_res[i] == native_res[i]) {
        ok(true, "query %s: native result matches libpq", label);
    } else {
        diag("query %s: result mismatch", label);
        diag("  libpq : %s", libpq_res[i].describe().c_str());
        diag("  native: %s", native_res[i].describe().c_str());
        ok(false, "query %s: native result matches libpq", label);
    }
}

int main(int /*argc*/, char** /*argv*/) {
    // 15 query-result assertions + 1 native-path assertion
    // + 12 PROXYSQL INTERNAL SESSION assertions + 3 client-options assertions
    // + 2 within-session varsync assertions.
    plan(33);

    if (cl.getEnv())
        return exit_status();

    std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
    if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS) {
        BAIL_OUT("Could not open ProxySQL log at '%s'", log_path.c_str());
        return exit_status();
    }

    auto admin = createAdminConn();
    if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
        BAIL_OUT("Cannot proceed without admin connection: %s",
                 admin ? PQerrorMessage(admin.get()) : "null conn");
        return exit_status();
    }

    std::vector<ServerRow> saved = readServers(admin.get(), BACKEND_HG);
    if (saved.empty()) {
        BAIL_OUT("No pgsql_servers row in hostgroup %d", BACKEND_HG);
        return exit_status();
    }
    diag("Backend under test (hg %d): %s:%s",
         BACKEND_HG, saved[0].hostname.c_str(), saved[0].port.c_str());

    // Build the query corpus. All queries are deterministic; no use of
    // current_user, current_timestamp, random(), etc.
    const std::string tbl = make_table_name();
    const std::string q_drop   = "DROP TABLE IF EXISTS " + tbl;
    const std::string q_create = "CREATE TABLE " + tbl +
        " (id int PRIMARY KEY, name text NOT NULL, val int NOT NULL)";
    const std::string q_insert = "INSERT INTO " + tbl +
        " VALUES (1, 'a', 10), (2, 'b', 20), (3, 'c', 30)";
    const std::string q_select_all = "SELECT id, name, val FROM " + tbl + " ORDER BY id";
    const std::string q_update   = "UPDATE " + tbl + " SET val = val + 1 WHERE id > 1";
    const std::string q_delete   = "DELETE FROM " + tbl + " WHERE id = 1";
    const std::string q_drop_end = "DROP TABLE " + tbl;

    const std::vector<std::string> QUERIES = {
        // DDL + DML cycle (idempotent)
        q_drop,                                             // 0
        q_create,                                           // 1
        q_insert,                                           // 2  INSERT 0 3
        q_select_all,                                       // 3
        q_update,                                           // 4  UPDATE 2
        "SELECT id, val FROM " + tbl + " ORDER BY id",      // 5
        q_delete,                                           // 6  DELETE 1
        "SELECT count(*) FROM " + tbl,                      // 7
        q_drop_end,                                         // 8

        // Multi-statement
        "SELECT 1 AS a; SELECT 2 AS b, 3 AS c",             // 9  (libpq returns 2 results, native too)
        "SELECT 1; SELECT 2; SELECT 3",                     // 10

        // Empty
        "SELECT 1 WHERE false",                             // 11
        "SELECT * FROM (VALUES (1, 'x'), (2, 'y')) AS t(id, n) WHERE id > 100", // 12

        // NULL-heavy
        "SELECT NULL::int, NULL::text, NULL::bool, NULL::numeric, NULL::timestamp", // 13
        "SELECT 1, NULL, 'x', NULL, 5",                     // 14
    };

    // Phase 1: libpq oracle.
    if (!setNativeMode(admin.get(), false)) {
        BAIL_OUT("Failed to set libpq mode");
        return exit_status();
    }
    if (!flushBackendPool(admin.get(), BACKEND_HG, saved)) {
        BAIL_OUT("Failed to flush backend pool for libpq phase");
        return exit_status();
    }
    auto libpq_client = createClientConn();
    bool libpq_conn_ok = false;
    std::vector<QueryResult> libpq_res =
        run_query_set(libpq_client.get(), QUERIES, libpq_conn_ok);
    if (!libpq_conn_ok) {
        BAIL_OUT("libpq client conn failed: %s",
                 libpq_client ? PQerrorMessage(libpq_client.get()) : "null");
        return exit_status();
    }

    // Phase 2: native path.
    if (!setNativeMode(admin.get(), true)) {
        BAIL_OUT("Failed to set native mode");
        return exit_status();
    }
    if (!flushBackendPool(admin.get(), BACKEND_HG, saved)) {
        BAIL_OUT("Failed to flush backend pool for native phase");
        return exit_status();
    }
    drainLogToNow();
    auto native_client = createClientConn();
    bool native_conn_ok = false;
    std::vector<QueryResult> native_res =
        run_query_set(native_client.get(), QUERIES, native_conn_ok);
    if (!native_conn_ok) {
        BAIL_OUT("native client conn failed: %s",
                 native_client ? PQerrorMessage(native_client.get()) : "null");
        return exit_status();
    }

    // Verify both phases produced the same number of results.
    if (libpq_res.size() != native_res.size()) {
        BAIL_OUT("Result count mismatch: libpq=%zu native=%zu",
                 libpq_res.size(), native_res.size());
        return exit_status();
    }

    // One assertion per query (result match).
    for (size_t i = 0; i < QUERIES.size(); i++) {
        std::string label = "Q" + std::to_string(i) + ":" + QUERIES[i].substr(0, 40);
        assert_query(label.c_str(), libpq_res, i, native_res);
    }

    // Native-path assertion (counted as 1 line for the whole phase).
    bool fell_back = nativeFallbackObserved();
    ok(!fell_back, "native phase used native path (no libpq fallback in log)");

    // ---- PROXYSQL INTERNAL SESSION, libpq oracle vs native ------------------
    //
    // Same two-phase method as the corpus above, on a query the corpus cannot
    // carry: the two paths return legitimately DIFFERENT documents (they
    // describe different backend connections), so what is compared is whether
    // the command is answered at all, plus the shape of the native document.
    //
    // REGRESSION GUARD. generate_proxysql_internal_session_json() describes the
    // attached backend through the get_pg_*() accessors. Four of them USED TO have
    // no native branch and called libpq on the PGconn, which is NULL for a native
    // connection: get_pg_hostaddr(), get_pg_port(), get_pg_password() and
    // get_pg_options(). PQhostaddr(NULL) & co. return NULL, that NULL was assigned
    // straight into a nlohmann::json, which constructs a std::string from a null
    // pointer and throws std::logic_error, and nothing on the path catches it --
    // so three ordinary statements from any authenticated client took down the
    // whole proxy process. An exception, not an assertion, so release builds died
    // identically. Those four accessors now have native branches returning a real
    // C string (include/PgSQL_Connection.h). The libpq branches are untouched: on a
    // live PGconn none of the PQ*() calls can return NULL -- PQhost/PQhostaddr/
    // PQport/PQpass fall back to "" themselves, PQdb/PQuser are filled by
    // connectOptions2() or the connect fails, and `options` has the compiled-in
    // default DefaultOption "". Only a NULL PGconn produces NULL, which is exactly
    // what a native connection has and a libpq one never does here.
    //
    // The oracle leg runs FIRST on purpose. Taken the other way round, a native
    // leg that kills the proxy also takes the oracle leg down with it, and the
    // run then reads as "libpq is broken too" -- the wrong diagnosis.
    {
        InternalSession oracle;
        if (setNativeMode(admin.get(), false) &&
            flushBackendPool(admin.get(), BACKEND_HG, saved)) {
            oracle = probe_internal_session();
        } else {
            diag("internal session: could not return the proxy to libpq mode for the oracle leg");
        }

        InternalSession candidate;
        if (setNativeMode(admin.get(), true) &&
            flushBackendPool(admin.get(), BACKEND_HG, saved)) {
            candidate = probe_internal_session();
        } else {
            diag("internal session: could not put the proxy into native mode for the candidate leg");
        }

        const json opg = backend_pgsql(oracle.doc);
        const json npg = backend_pgsql(candidate.doc);

        ok(oracle.answered, "libpq: PROXYSQL INTERNAL SESSION answers");
        // Guards the probe recipe itself: if BEGIN + create_new_connection stops
        // attaching a backend, every native assertion below would pass vacuously.
        ok(opg.is_object(), "libpq: INTERNAL SESSION reports an attached backend (probe recipe works)");
        {
            const std::string addr = pgconn_address(opg);
            ok(opg.is_object() && addr != "<absent>" && !is_null_pgconn(addr),
               "libpq: the oracle leg really is libpq, it has a PGconn (address=%s)", addr.c_str());
        }

        ok(candidate.answered, "native: PROXYSQL INTERNAL SESSION answers");

        // Confirms the attached connection really is native: the reported address
        // is PgSQL_Connection::get_pg_connection(), the libpq PGconn, which a
        // native connection does not have. A real pointer here would mean the
        // session fell back to libpq and the field assertions prove nothing.
        {
            const std::string addr = pgconn_address(npg);
            ok(npg.is_object() && is_null_pgconn(addr),
               "native: the attached backend has no libpq PGconn, i.e. it is native (address=%s)",
               addr.c_str());
        }

        ok_pgsql_string_field(npg, "host_addr");   // was PQhostaddr(NULL) -> NULL
        ok_pgsql_string_field(npg, "port");        // was PQport(NULL)     -> NULL
        ok_pgsql_string_field(npg, "options");     // was PQoptions(NULL)  -> NULL

        // password is reported only by DEBUG builds (#ifdef DEBUG in
        // generate_proxysql_internal_session_json), so its absence is not a
        // failure -- but a missing document is, or this reads as "release build,
        // nothing to check" when the truth is that the proxy died.
        {
            const bool have_doc = npg.is_object();
            const bool present = have_doc && npg.contains("password");
            ok(have_doc && (!present || npg["password"].is_string()),
               "native: backends[0].conn.pgsql.password is a string when reported%s",
               have_doc ? (present ? "" : " [absent: release build]") : " [no document]");
        }

        // Both of these describe the SERVER, so they must agree across paths.
        // client_encoding came back -1 on native -- PQclientEncoding()'s error
        // sentinel, returned because a native connection has no PGconn -- and
        // server_version used the pre-PostgreSQL-10 numeric encoding, so a 16.14
        // backend reported "16.14.0" where libpq reports "16.0.14" from 160014.
        ok_pgsql_field_matches(opg, npg, "client_encoding");
        ok_pgsql_field_matches(opg, npg, "server_version");

        {
            auto a2 = createAdminConn();
            bool alive = false;
            if (a2 && PQstatus(a2.get()) == CONNECTION_OK) {
                PGresult* r = PQexec(a2.get(), "SELECT 1");
                alive = (PQresultStatus(r) == PGRES_TUPLES_OK);
                PQclear(r);
            }
            ok(alive, "ProxySQL still alive after the internal-session probes");
        }
    }

    // ---- Client connection options, libpq oracle vs native -----------------
    //
    // A client's `options` reach the backend inside the StartupMessage `options`
    // parameter, which the backend splits on unescaped whitespace (pg_split_opts,
    // postinit.c). A value that itself contains a space therefore has to arrive
    // escaped, and at the right level: a conninfo value passes through libpq, which
    // strips one level of backslashes before it reaches the wire, while the native
    // path writes to the wire directly and must not carry that extra level.
    //
    // REGRESSION GUARD. Untracked options used to be stored already escaped for a
    // conninfo and then handed to the native path verbatim, so the backend saw the
    // over-escaped form: an option whose value held a space FAILED THE CONNECTION on
    // native while libpq was fine, e.g.
    //     ERROR:  invalid value for parameter "work_mem": "4\"
    // The tracked variables carry the same hazard through DateStyle, whose default
    // value "ISO, MDY" contains a space.
    {
        // The options string below is a CONNINFO value, and libpq strips one level of
        // backslashes while parsing it. So a value that must reach the wire as `4\ MB`
        // is written here as `4\\ MB`. Getting this level wrong makes both paths fail to
        // connect, which would still compare equal and quietly assert nothing -- hence
        // the explicit `expected` below rather than a bare libpq-vs-native comparison.
        struct OptCase {
            const char* label;
            const char* options;    // as a client passes it in its conninfo
            const char* probe;      // what to read back from the backend session
            const char* expected;   // what BOTH paths must report
        };
        // work_mem, geqo and join_collapse_limit must stay OUT of pgsql_variable_name for
        // these to exercise the untracked path -- note maintenance_work_mem IS tracked
        // while work_mem is not. If one of them is ever added to that enum, the case
        // silently starts testing the tracked path instead and still passes; pick a
        // different GUC then rather than leaving it.
        // Every expected value below MUST differ from the backend's own default, or the
        // case cannot tell "the option arrived" from "the option was silently dropped" --
        // it would only ever catch a failure to connect. Defaults on PostgreSQL 16 are
        // work_mem=4MB, DateStyle='ISO, MDY', geqo=on, join_collapse_limit=8.
        const OptCase cases[] = {
            {"untracked value containing a space",
             "-c work_mem=8\\\\ MB",
             "SELECT current_setting('work_mem')",
             "8MB"},
            {"untracked values needing no escaping",
             "-c geqo=off -c join_collapse_limit=3",
             "SELECT current_setting('geqo')||' '||current_setting('join_collapse_limit')",
             "off 3"},
            {"tracked value containing a space (DateStyle)",
             "-c DateStyle=ISO,\\\\ DMY",
             "SELECT current_setting('DateStyle')",
             "ISO, DMY"},
        };
        for (const auto& oc : cases) {
            setNativeMode(admin.get(), false);
            flushBackendPool(admin.get(), BACKEND_HG, saved);
            const std::string lp = options_outcome(oc.options, oc.probe);

            setNativeMode(admin.get(), true);
            flushBackendPool(admin.get(), BACKEND_HG, saved);
            const std::string nt = options_outcome(oc.options, oc.probe);

            ok(lp == oc.expected && nt == oc.expected,
               "client options -- %s -- reach the backend on both paths "
               "(expected='%s' libpq='%s' native='%s')",
               oc.label, oc.expected, lp.c_str(), nt.c_str());
        }
    }

    // ---- Within-session variable sync after an extended-query step ---------
    //
    // This guards the same hang as run_varsync_reuse_regression() in
    // pgsql-native_prepared-t, but reaches it a different way. The fix is the end-state
    // pin in ASYNC_QUERY_START in lib/PgSQL_Connection.cpp, and the full write-up is in
    // docs/superpowers/specs/2026-09-01-pgsql-native-varsync-reuse-hang.md.
    //
    // That other test covers the pool boundary. A client dirties a backend connection by
    // running a prepared statement, the connection goes back to the pool, and a second
    // client picks it up and hangs. This test never lets the connection reach the pool
    // at all. Everything happens on one session, holding the same backend connection
    // throughout, first because a prepared statement keeps it attached and then, in the
    // second sub-case, because an explicit transaction does. It is the same stale mark
    // left by the prepared statement, but no pooling is involved in getting to it.
    //
    // The sequence is: prepare and execute a statement, send a SET client_encoding, then
    // read the setting back. The deadline has to cover that last read, not just the SET.
    // ProxySQL answers the SET to the client on its own and only passes it to the
    // backend when the next query comes along, so that read is where the hang actually
    // appears. A test that stopped after the SET would pass even with the bug present.
    //
    // Like everything else in this file the check is differential, with the libpq path
    // as the oracle. libpq cannot hit this bug, because its flush never reports that it
    // sent everything in one go, so a native-only regression shows up as the two paths
    // disagreeing, and a break affecting both shows up as both disagreeing with the
    // expected value.
    {
        struct VarSyncCase {
            const char* label;
            bool use_txn;   // pin the backend connection with an explicit txn too
        };
        const VarSyncCase cases[] = {
            {"prepared-statement-pinned session", false},
            {"explicit transaction", true},
        };
        // The SET must change client_encoding to something the session does not
        // already have, or ProxySQL issues no sync at all and the case asserts nothing.
        const char* expected = "LATIN1";

        for (const auto& vc : cases) {
            std::string outcome[2];
            for (int native = 0; native <= 1; native++) {
                setNativeMode(admin.get(), native != 0);
                flushBackendPool(admin.get(), BACKEND_HG, saved);

                PGConnPtr c = createClientConn();
                if (!c || PQstatus(c.get()) != CONNECTION_OK) {
                    outcome[native] = "CONNECT-FAILED";
                    continue;
                }
                PGconn* cc = c.get();

                if (vc.use_txn) {
                    const std::string b = deadline_step(cc, "BEGIN", "BEGIN", false);
                    if (b != "OK") { outcome[native] = b; continue; }
                }

                // Extended-query step: this is what pins ASYNC_STMT_EXECUTE_END.
                PGresult* pr = PQprepare(cc, "vsd", "SELECT 88", 0, nullptr);
                const bool prepared = PQresultStatus(pr) == PGRES_COMMAND_OK;
                PQclear(pr);
                if (!prepared) { outcome[native] = "PREPARE-FAILED"; continue; }
                pr = PQexecPrepared(cc, "vsd", 0, nullptr, nullptr, nullptr, 0);
                const bool executed = PQresultStatus(pr) == PGRES_TUPLES_OK;
                PQclear(pr);
                if (!executed) { outcome[native] = "EXECUTE-FAILED"; continue; }

                // The variable sync. This is the step that used to hang forever.
                const std::string s1 =
                    deadline_step(cc, "SET", "SET client_encoding TO 'LATIN1'", false);
                if (s1 != "OK") { outcome[native] = s1; continue; }

                outcome[native] = deadline_step(
                    cc, "probe", "SELECT current_setting('client_encoding')", true);

                if (vc.use_txn) {
                    const std::string cm = deadline_step(cc, "COMMIT", "COMMIT", false);
                    if (cm != "OK" && outcome[native] == expected) outcome[native] = cm;
                }
            }
            ok(outcome[0] == expected && outcome[1] == expected,
               "within-session varsync after extended query -- %s -- no hang, both paths agree "
               "(expected='%s' libpq='%s' native='%s')",
               vc.label, expected, outcome[0].c_str(), outcome[1].c_str());
        }
    }

    // Restore native mode to default (off) and flush the pool.
    setNativeMode(admin.get(), false);
    flushBackendPool(admin.get(), BACKEND_HG, saved);

    return exit_status();
}
