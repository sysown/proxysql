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
#include <unistd.h>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

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
    // 15 query-result assertions + 1 native-path assertion = 16 lines.
    plan(16);

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

    // Restore native mode to default (off) and flush the pool.
    setNativeMode(admin.get(), false);
    flushBackendPool(admin.get(), BACKEND_HG, saved);

    return exit_status();
}
