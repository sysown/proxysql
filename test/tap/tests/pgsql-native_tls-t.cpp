/**
 * @file pgsql-native_tls-t.cpp
 * @brief Differential test: native backend protocol over a TLS backend connection.
 *
 * PURPOSE
 * -------
 * `use_ssl` appears in NO existing native-path test, so two substantial pieces
 * of the implementation have never executed end to end:
 *
 *   1. The TLS branch of native_recv_into_framer() (lib/PgSQL_Connection.cpp:2129):
 *      recv ciphertext -> BIO_write into rbio -> SSL_read plaintext -> feed the
 *      framer. TLS record boundaries have no relationship to protocol message
 *      boundaries, so this is precisely where partial-message framing bugs live.
 *      Plaintext testing cannot reach it.
 *
 *   2. SCRAM-SHA-256-PLUS channel binding. PostgreSQL 16 advertises both
 *      SCRAM-SHA-256 and SCRAM-SHA-256-PLUS; over TLS the mechanism selection at
 *      lib/PgSQL_Connection.cpp:2345 takes -PLUS and derives the binding from
 *      pg_tls_server_end_point(). Those helpers have unit tests at the crypto
 *      level and no integration coverage at all.
 *
 * WHY A SUCCESSFUL CONNECT PROVES CHANNEL BINDING
 * -----------------------------------------------
 * There is no log line naming the chosen SASL mechanism, so -PLUS selection
 * cannot be asserted directly. It does not need to be: the channel-binding data
 * is mixed into the SCRAM client proof. If pg_tls_server_end_point() computed
 * the wrong certificate digest, or
 * pg_scram_build_cbind_input_tls_server_end_point() laid out the cbind input
 * wrongly, the proof would not verify and PostgreSQL would REJECT the login.
 * A successful native TLS connection is therefore an end-to-end proof that both
 * are correct.
 *
 * To stop a silent plaintext connection from masquerading as a passing TLS test,
 * the test independently confirms via pg_stat_ssl — joined on the backend PID
 * observed through the proxy, from a DIRECT connection to PostgreSQL — that the
 * backend connection really is encrypted.
 *
 * METHOD
 * ------
 * Sets use_ssl=1 on the backend row, then runs the standard two-phase
 * differential: the same corpus with pgsql-use_native_backend_protocol false
 * (libpq oracle) and true (native candidate), requiring identical results.
 *
 * The corpus is deliberately weighted toward SIZE. A 10,000-row result is what
 * forces many TLS records per result set and makes records straddle message
 * boundaries; small queries would exercise almost none of the interesting path.
 *
 * INFRA
 * -----
 * legacy-g1 (docker-pgsql16-single). No new fixtures are needed:
 * postgresql.conf:15 already sets `ssl = 'on'`, and pg_hba.conf:35
 * (`host all all all scram-sha-256`) matches before the `hostssl ... cert` rule
 * at line 46, so TLS connections authenticate with SCRAM and no client
 * certificate is required.
 *
 * EXPECTATION
 * -----------
 * This test is expected to PASS. Unlike the framer and pool-reset tests it does
 * not document a known defect — it covers surface that has simply never run.
 * A failure here is a NEW finding in the TLS or channel-binding path.
 *
 * Runtime state is restored in memory at the end — never SAVE ... TO DISK.
 */
#include <fstream>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int BACKEND_HG = 0;

static PGConnPtr openConn(const char* host, int port, const char* user,
                          const char* pass, const char* db, const char* sslmode) {
    std::stringstream ss;
    ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
    if (db && *db) ss << " dbname=" << db;
    ss << " sslmode=" << sslmode << " connect_timeout=10";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr createAdminConn() {
    return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port,
                    cl.admin_username, cl.admin_password, nullptr, "disable");
}
// The CLIENT leg stays plaintext throughout: only the BACKEND leg is under test.
static PGConnPtr createClientConn() {
    return openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username,
                    cl.pgsql_password, cl.pgsql_username, "disable");
}
static PGConnPtr createDirectBackendConn() {
    return openConn(cl.pgsql_server_host, cl.pgsql_server_port,
                    cl.pgsql_server_username, cl.pgsql_server_password, "postgres", "disable");
}

static bool execAdmin(PGconn* admin, const std::string& q) {
    PGresult* r = PQexec(admin, q.c_str());
    ExecStatusType st = PQresultStatus(r);
    bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(admin));
    PQclear(r);
    return good;
}

static std::string scalar(PGconn* c, const std::string& q) {
    PGresult* r = PQexec(c, q.c_str());
    std::string v;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
        v = PQgetvalue(r, 0, 0);
    PQclear(r);
    return v;
}

// The backend pid as PostgreSQL sees it. pg_backend_pid() asked through ProxySQL never
// reaches a backend -- the proxy answers it with a number of its own -- so the connection
// is named by a marker left in the query text and read from a direct connection.
// pg_stat_activity keeps an idle backend's last query, so the marker outlives the client.
static std::string backendPidForMarker(PGconn* direct, const std::string& marker) {
    return scalar(direct,
        "SELECT pid::text FROM pg_stat_activity WHERE query LIKE '%" + marker +
        "%' AND pid <> pg_backend_pid() ORDER BY state_change DESC LIMIT 1");
}

static std::string sslInUseForPid(PGconn* direct, const std::string& pid) {
    if (pid.empty()) return "";
    return scalar(direct, "SELECT ssl::text FROM pg_stat_ssl WHERE pid=" + pid);
}

static bool setNativeMode(PGconn* admin, bool enabled) {
    return execAdmin(admin, std::string("SET pgsql-use_native_backend_protocol='") +
                            (enabled ? "true" : "false") + "'") &&
           execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

// A structural fingerprint of a result: enough to catch truncated rows, byte
// corruption, dropped/duplicated rows and wrong type OIDs, without holding a
// 10k-row result in memory twice.
struct Fingerprint {
    bool ok = false;
    std::string sqlstate;
    int nrows = 0, ncols = 0;
    std::string coltypes;      // "oid,oid,..."
    unsigned long long checksum = 0;   // order-sensitive over every field
};

static Fingerprint fingerprint(PGconn* c, const std::string& query) {
    Fingerprint fp;
    PGresult* r = PQexec(c, query.c_str());
    const ExecStatusType st = PQresultStatus(r);
    if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
        const char* ss = PQresultErrorField(r, PG_DIAG_SQLSTATE);
        fp.sqlstate = ss ? ss : "unknown";
        PQclear(r);
        return fp;
    }
    fp.ok = true;
    fp.nrows = PQntuples(r);
    fp.ncols = PQnfields(r);
    std::stringstream ts;
    for (int c2 = 0; c2 < fp.ncols; c2++) {
        if (c2) ts << ",";
        ts << (unsigned)PQftype(r, c2);
    }
    fp.coltypes = ts.str();

    // FNV-1a over (row, col, isnull, value) for every field, in order.
    unsigned long long h = 1469598103934665603ULL;
    auto mix = [&h](const char* p, size_t n) {
        for (size_t i = 0; i < n; i++) { h ^= (unsigned char)p[i]; h *= 1099511628211ULL; }
    };
    for (int row = 0; row < fp.nrows; row++) {
        for (int col = 0; col < fp.ncols; col++) {
            if (PQgetisnull(r, row, col)) { mix("\x01NULL", 5); continue; }
            const char* v = PQgetvalue(r, row, col);
            const int len = PQgetlength(r, row, col);
            mix("\x02", 1);
            mix(v, (size_t)len);
        }
    }
    fp.checksum = h;
    PQclear(r);
    return fp;
}

static bool sameFingerprint(const Fingerprint& a, const Fingerprint& b) {
    return a.ok == b.ok && a.sqlstate == b.sqlstate && a.nrows == b.nrows &&
           a.ncols == b.ncols && a.coltypes == b.coltypes && a.checksum == b.checksum;
}

// Corpus: breadth plus one deliberately large result.
static std::vector<std::pair<std::string, std::string>> corpus() {
    return {
        { "scalar",        "SELECT 1" },
        { "text+null",     "SELECT 'abc'::text, NULL::text, 42::int" },
        { "empty",         "SELECT 1 WHERE false" },
        { "types",         "SELECT 1::int2, 2::int4, 3::int8, 4.5::numeric, "
                           "'t'::bool, '2024-01-01'::date, 'x'::bytea" },
        { "multirow-100",  "SELECT g, md5(g::text), g::numeric/7 FROM generate_series(1,100) g" },
        { "wide-text",     "SELECT repeat('z', 100000)" },
        { "error",         "SELECT * FROM no_such_table_for_tls_test" },
        // The point of this file: many TLS records per result set.
        { "large-10k",     "SELECT g, md5(g::text) AS h, g::numeric/3 AS n, "
                           "CASE WHEN g%7=0 THEN NULL ELSE repeat('q', (g%50)+1) END AS t "
                           "FROM generate_series(1,10000) g" },
    };
}

static std::fstream f_proxysql_log{};
static bool nativeFallbackObserved() {
    const std::string regex =
        ".*(native_mode requested but unimplemented at this stage; falling back to libpq"
        "|native backend auth capability gap .* falling back to libpq).*";
    return wait_for_log_match(f_proxysql_log, regex, 1000, 100);
}
static void drainLogToNow() {
    get_matching_lines(f_proxysql_log, "__no_such_marker_line__");
}

// Unique enough to find in pg_stat_activity, stable enough to write into a LIKE.
static const char* MARKER_CORPUS = "native_tls_marker_corpus";
static const char* MARKER_POOL_1 = "native_tls_marker_pool_first";
static const char* MARKER_POOL_2 = "native_tls_marker_pool_second";

int main(int, char**) {
    // one per corpus entry + backend-is-really-encrypted + pooled-reuse +
    // no-fallback + fast_forward capability gap.
    const auto C = corpus();
    plan((int)C.size() + 4);

    if (cl.getEnv()) return exit_status();

    const std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
    if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS)
        BAIL_OUT("could not open the ProxySQL log at '%s'", log_path.c_str());

    auto adminOwner = createAdminConn();
    if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
        BAIL_OUT("cannot proceed without an admin connection");
    PGconn* admin = adminOwner.get();

    // ---- save runtime state ------------------------------------------------
    std::string saved_native = scalar(admin,
        "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
    std::string saved_use_ssl;
    {
        std::stringstream q;
        q << "SELECT use_ssl FROM pgsql_servers WHERE hostgroup_id=" << BACKEND_HG << " LIMIT 1";
        saved_use_ssl = scalar(admin, q.str());
    }

    // Drop every pooled backend connection for the hostgroup.
    //
    // Necessary because flipping use_ssl does not by itself evict connections
    // that were established while it was off. A surviving PLAINTEXT connection
    // would serve the native phase perfectly well, the corpus would match, and
    // the pg_stat_ssl check below would then report ssl=false — blaming the
    // native TLS path for a stale-pool artefact. OFFLINE_HARD forces the drop.
    auto flushPool = [&]() {
        std::stringstream off, on;
        off << "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" << BACKEND_HG;
        on  << "UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=" << BACKEND_HG;
        bool good = execAdmin(admin, off.str()) && execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
        usleep(300000);
        good = good && execAdmin(admin, on.str()) && execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
        usleep(300000);
        return good;
    };

    auto setUseSsl = [&](int v) {
        std::stringstream u;
        u << "UPDATE pgsql_servers SET use_ssl=" << v << " WHERE hostgroup_id=" << BACKEND_HG;
        if (!execAdmin(admin, u.str()) || !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
            return false;
        return flushPool();
    };
    auto restore = [&]() {
        if (!saved_use_ssl.empty()) setUseSsl(atoi(saved_use_ssl.c_str()));
        if (!saved_native.empty())
            setNativeMode(admin, saved_native == "true" || saved_native == "1");
    };

    // ---- turn on backend TLS ----------------------------------------------
    if (!setUseSsl(1)) { restore(); BAIL_OUT("could not enable use_ssl on the backend"); }
    usleep(500000);   // let existing plaintext pooled connections be replaced

    // ================= phase 1: libpq oracle, over TLS =======================
    if (!setNativeMode(admin, false)) { restore(); BAIL_OUT("cannot select libpq mode"); }
    usleep(300000);

    std::vector<Fingerprint> oracle;
    {
        auto c = createClientConn();
        if (!c || PQstatus(c.get()) != CONNECTION_OK) {
            restore();
            BAIL_OUT("libpq phase: client connection failed: %s",
                     c ? PQerrorMessage(c.get()) : "null");
        }
        for (const auto& q : C) oracle.push_back(fingerprint(c.get(), q.second));
    }

    // ================= phase 2: native candidate, over TLS ===================
    if (!setNativeMode(admin, true)) { restore(); BAIL_OUT("cannot select native mode"); }
    // Evict the libpq-phase connections so the native phase must establish its
    // own TLS connection rather than inheriting one built by libpq.
    flushPool();
    drainLogToNow();

    std::vector<Fingerprint> candidate;
    std::string native_backend_pid;
    {
        auto c = createClientConn();
        if (!c || PQstatus(c.get()) != CONNECTION_OK) {
            restore();
            BAIL_OUT("native phase: client connection failed (native TLS connect broken?): %s",
                     c ? PQerrorMessage(c.get()) : "null");
        }
        for (const auto& q : C) candidate.push_back(fingerprint(c.get(), q.second));
        // Last, on the same connection: pg_stat_activity keeps only the most recent
        // query, so a marker sent first would be overwritten by the corpus.
        scalar(c.get(), "SELECT '" + std::string(MARKER_CORPUS) + "' AS marker");
    }

    // ---- per-query differential -------------------------------------------
    for (size_t i = 0; i < C.size(); i++) {
        const Fingerprint& o = oracle[i];
        const Fingerprint& n = candidate[i];
        ok(sameFingerprint(o, n),
           "%s: libpq(ok=%d rows=%d cols=%d types=[%s] sqlstate=%s sum=%llu) == "
           "native(ok=%d rows=%d cols=%d types=[%s] sqlstate=%s sum=%llu)",
           C[i].first.c_str(),
           (int)o.ok, o.nrows, o.ncols, o.coltypes.c_str(),
           o.sqlstate.empty() ? "-" : o.sqlstate.c_str(), o.checksum,
           (int)n.ok, n.nrows, n.ncols, n.coltypes.c_str(),
           n.sqlstate.empty() ? "-" : n.sqlstate.c_str(), n.checksum);
    }

    // ---- the backend leg really was encrypted ------------------------------
    // Without this, a native path that silently fell back to plaintext would
    // produce identical results and the whole file would pass while testing
    // nothing.
    {
        bool encrypted = false;
        std::string detail;
        auto direct = createDirectBackendConn();
        if (direct && PQstatus(direct.get()) == CONNECTION_OK) {
            native_backend_pid = backendPidForMarker(direct.get(), MARKER_CORPUS);
            if (native_backend_pid.empty()) {
                detail = "no backend found carrying the marker query";
            } else {
                const std::string ssl_used = sslInUseForPid(direct.get(), native_backend_pid);
                if (ssl_used.empty()) {
                    detail = "backend pid " + native_backend_pid + " not present in pg_stat_ssl";
                } else {
                    encrypted = (ssl_used == "t" || ssl_used == "true");
                    detail = "pg_stat_ssl.ssl=" + ssl_used + " for pid " + native_backend_pid;
                }
            }
        } else {
            detail = "no direct backend connection to consult pg_stat_ssl";
        }
        ok(encrypted,
           "native backend connection is genuinely TLS-encrypted (%s) -- "
           "also proves SCRAM-SHA-256-PLUS channel binding, since a wrong "
           "tls-server-end-point digest would have failed the login",
           detail.c_str());
    }

    // ---- a pooled TLS connection survives being handed to the next client ---
    // Everything above uses a freshly opened connection. The second use is a different
    // path: the connection returns to the pool with its TLS session attached and the
    // next client inherits it instead of handshaking. A7 was this going wrong the other
    // way -- the session destroyed while the socket stayed pooled.
    {
        std::string pid_first, pid_second, ssl_second;
        auto direct = createDirectBackendConn();

        {   // first client: leave a marker, then let go so it returns to the pool
            auto c = createClientConn();
            if (c && PQstatus(c.get()) == CONNECTION_OK)
                scalar(c.get(), "SELECT '" + std::string(MARKER_POOL_1) + "' AS marker");
        }
        // Resolved before the second client runs: if the same backend is handed over,
        // its last-query text is about to be overwritten.
        if (direct && PQstatus(direct.get()) == CONNECTION_OK)
            pid_first = backendPidForMarker(direct.get(), MARKER_POOL_1);

        bool second_served = false;
        {   // the SET makes ProxySQL talk on the pooled connection before the query,
            // which is where a dead TLS transport would surface
            auto c = createClientConn();
            if (c && PQstatus(c.get()) == CONNECTION_OK) {
                execAdmin(c.get(), "SET application_name='pooled_tls_reuse'");
                second_served =
                    (scalar(c.get(), "SELECT '" + std::string(MARKER_POOL_2) + "' AS marker")
                        == std::string(MARKER_POOL_2));
            }
        }

        if (direct && PQstatus(direct.get()) == CONNECTION_OK) {
            pid_second = backendPidForMarker(direct.get(), MARKER_POOL_2);
            ssl_second = sslInUseForPid(direct.get(), pid_second);
        }

        const bool reused = (!pid_first.empty() && pid_first == pid_second);
        const bool still_encrypted = (ssl_second == "t" || ssl_second == "true");
        ok(second_served && reused && still_encrypted,
           "a pooled TLS backend connection serves the next client, still encrypted "
           "(first pid=%s second pid=%s served=%d pg_stat_ssl.ssl=%s)%s",
           pid_first.empty() ? "-" : pid_first.c_str(),
           pid_second.empty() ? "-" : pid_second.c_str(),
           (int)second_served, ssl_second.empty() ? "-" : ssl_second.c_str(),
           reused ? "" : "  <-- not the same backend connection, so reuse was never tested");
    }

    // ---- no silent fallback to libpq ---------------------------------------
    {
        const bool fell_back = nativeFallbackObserved();
        ok(!fell_back, "native TLS path used throughout (no libpq fallback warning in the proxy log)");
    }

    // ---- fast_forward + native TLS takes the documented way out -------------
    // A fast_forward session wants the backend's TLS on the data stream, which the
    // native path cannot lend: handing over its two memory buffers means installing new
    // ones, freeing the pair still in use. ProxySQL routes the session to libpq instead.
    // The combination works on neither path, so what is asserted is the safe exit, not a
    // served query. Runs last: it puts a fallback line in the log the check above
    // requires to be absent.
    {
        execAdmin(admin, "UPDATE pgsql_users SET fast_forward=1");
        execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME");
        // The guard sits on the connect path, so a NEW connection is needed to meet it.
        // From the pool the session takes attach_connection()'s borrow instead: also
        // safe, but a different route, and no log line.
        flushPool();
        drainLogToNow();

        {
            auto c = createClientConn();
            if (c && PQstatus(c.get()) == CONNECTION_OK) scalar(c.get(), "SELECT 1");
        }
        const bool fell_back = nativeFallbackObserved();

        execAdmin(admin, "UPDATE pgsql_users SET fast_forward=0");
        execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME");

        const bool alive = (scalar(admin, "SELECT 1") == "1");
        bool still_serving = false;
        {   // a half-handed-over transport shows up here as a backend that can no
            // longer be talked to
            auto c = createClientConn();
            if (c && PQstatus(c.get()) == CONNECTION_OK)
                still_serving = (scalar(c.get(), "SELECT 7") == "7");
        }
        // The capability-gap line is diagnostic, never the verdict: its warning fires
        // once per worker thread for the life of the process, so a proxy that already
        // logged one stays silent here however it handles this session.
        ok(alive && still_serving,
           "a fast_forward session over a TLS backend leaves the proxy working "
           "(alive=%d, next session served=%d, capability-gap line seen=%d)",
           (int)alive, (int)still_serving, (int)fell_back);
    }

    restore();
    return exit_status();
}
