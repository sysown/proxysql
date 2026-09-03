/**
 * @file pgsql-native_auth_matrix-t.cpp
 * @brief The native PostgreSQL backend protocol's authentication matrix, against a REAL backend.
 *
 * PURPOSE
 * -------
 * `native_drive_auth()` (lib/PgSQL_Connection.cpp:2238) implements four ways of
 * authenticating to a PostgreSQL backend without libpq:
 *
 *     case 0        AuthenticationOk                 (pg_hba `trust`)
 *     case 3        AuthenticationCleartextPassword  (pg_hba `password`, also ldap/pam/radius)
 *     case 5        AuthenticationMD5Password        (pg_hba `md5`)
 *     case 10/11/12 SASL / SCRAM-SHA-256(-PLUS)      (pg_hba `scram-sha-256`)
 *
 * Before this file, the shared pgsql16 infra could only ever produce ONE of them.
 * Its pg_hba.conf offered `scram-sha-256` to every role except `md5user`, and the
 * one md5 test (pgsql-md5_passthrough-t) runs the LIBPQ path. So cases 0, 3 and 5
 * had never executed against a real PostgreSQL, and neither had the backend's
 * ErrorResponse-during-auth path.
 *
 * The infra now provisions a role per method -- `authtrust`, `authpw`,
 * `authreject`, `authscram` (test/infra/docker-pgsql16-single/bin/docker-pgsql-post.bash)
 * with username-scoped pg_hba rules above the scram-sha-256 catch-alls
 * (conf/pgsql/pgsql1/pg_hba.conf) -- plus the pre-existing `md5user`. This test
 * drives each of them through ProxySQL on the native path.
 *
 * THE AXIS THAT ACTUALLY MATTERS: HOW THE SECRET IS STORED
 * --------------------------------------------------------
 * ProxySQL can hold a user's credential in `pgsql_users.password` three ways: the
 * plaintext, a SCRAM verifier ("SCRAM-SHA-256$<iters>:<salt>$<stored>:<server>"),
 * or an md5 hash ("md5"+32hex). The LIBPQ path handles all three -- it passes the
 * harvested keys down as the patched conninfo params `scram_client_key` /
 * `scram_server_key` / `md5_secret` (lib/PgSQL_Connection.cpp:1101-1123, gated on
 * `userinfo->has_scram_keys`).
 *
 * The NATIVE path has no equivalent. It reads `userinfo->password` and treats it
 * as a plaintext password, unconditionally, at all three call sites
 * (lib/PgSQL_Connection.cpp:2293 cleartext, :2314 md5, :2427 SCRAM). Nothing in
 * the native connect path so much as consults `has_scram_keys`. So for a
 * verifier-stored user the literal verifier STRING is fed through PBKDF2 as if it
 * were the password, and for an md5-stored user pg_build_md5() hashes the stored
 * hash a second time. Both produce a wrong credential and the backend rejects the
 * login.
 *
 * That is the point of this file. Cells `scram-verifier` and `md5-hash` are
 * declared expect_ok=false and the suite is GREEN while the gap exists -- but the
 * libpq leg is run alongside every cell and reported, so the divergence is
 * visible in the output rather than merely asserted. The failure mode is worth
 * spelling out: because native never calls native_capability_gap() for this case,
 * there is no graceful fallback to libpq the way there is for GSSAPI/SSPI
 * (:1544). The user gets an opaque authentication failure instead.
 *
 * If either cell starts PASSING, the pass-through has been implemented and the
 * expectation must be flipped. If either starts failing DIFFERENTLY -- e.g. the
 * connection begins succeeding via a silent libpq fallback -- the native_mode
 * assertion below catches it.
 *
 * PROVING THE NATIVE PATH WAS ACTUALLY USED
 * ------------------------------------------
 * A test like this passes trivially if ProxySQL quietly served the request over
 * libpq. Existing native tests detect that by grepping the proxy log for the
 * capability-gap warning. That signal is NOT reliable: native_capability_gap()
 * guards its warning with `static thread_local bool warned`
 * (lib/PgSQL_Connection.cpp:1545), so only the FIRST gap per worker thread is
 * ever logged, despite the comment above it claiming "once per backend". A suite
 * of 21 cells would see at most one warning no matter how many times it fell back.
 *
 * So we assert positively instead: `stats_pgsql_free_connections.pgsql_info`
 * carries a per-connection `"native_mode":true|false`
 * (lib/PgSQL_HostGroups_Manager.cpp:3077, surfaced via
 * lib/ProxySQL_Admin_Stats.cpp:1332). After each successful cell we read it back
 * for that hostgroup and user and require true.
 *
 * Backend TLS is confirmed the same way pgsql-native_tls-t does it: capture
 * pg_backend_pid() through the proxy, then read pg_stat_ssl for that pid from a
 * DIRECT superuser connection. A native path that silently downgraded to
 * plaintext would otherwise look identical.
 *
 * THE MATRIX
 * ----------
 * 7 base cells (backend method x stored-secret type) x backend use_ssl {0,1},
 * plus a 7-cell overlay at use_ssl=1 with the CLIENT leg on TLS too. Frontend TLS
 * is orthogonal to backend authentication -- it changes nothing about which
 * Authentication message the backend sends -- so it gets an overlay rather than a
 * full cross product; the overlay's job is to prove both legs can be encrypted at
 * once. 21 cells total.
 *
 * `pgsql-authentication_method` (the frontend floor) is NOT a free axis: it is
 * fixed per cell by the stored secret type, because pgsql_reconcile_auth_method()
 * (lib/PgSQL_Protocol.cpp:386) makes a verifier satisfy any floor, an md5 hash
 * REJECT at floor 3, and plaintext take the floor's own method. Setting it
 * correctly per cell is therefore mandatory, and it means the frontend leg gets
 * covered across cleartext/md5/scram challenges as a side effect.
 *
 * ISOLATION
 * ---------
 * Everything runs on a dedicated hostgroup so the default hostgroup's pool is
 * never disturbed. `authscram` exists as its own role rather than reusing
 * `testuser` precisely because this test rewrites each role's pgsql_users row and
 * `testuser` is seeded for the whole suite by conf/proxysql/config.sql.
 *
 * The monitor is disabled and shun_on_failures raised for the duration: three of
 * the seven base cells fail their backend connect BY DESIGN, and without this the
 * hostgroup would be shunned part-way through and later cells would fail for the
 * wrong reason.
 *
 * Per project rule: only LOAD ... TO RUNTIME, never SAVE ... TO DISK. All runtime
 * state touched here is restored in memory at the end.
 */
#include <cstdlib>
#include <cstring>
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

// A hostgroup of our own, so flushing the pool between cells cannot disturb the
// default hostgroup that the rest of the group's tests are using.
static const int AUTH_HG = 91;

// ---------------------------------------------------------------- connections

static PGConnPtr openConn(const char* host, int port, const char* user,
                          const char* pass, const char* db, const char* sslmode) {
    std::stringstream ss;
    ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
    if (db && *db) ss << " dbname=" << db;
    ss << " sslmode=" << sslmode << " connect_timeout=10";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr adminConn() {
    return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port,
                    cl.admin_username, cl.admin_password, nullptr, "disable");
}

static PGConnPtr directBackendConn() {
    return openConn(cl.pgsql_server_host, cl.pgsql_server_port,
                    cl.pgsql_server_username, cl.pgsql_server_password, "postgres", "disable");
}

static bool execAdmin(PGconn* a, const std::string& q) {
    PGresult* r = PQexec(a, q.c_str());
    const ExecStatusType st = PQresultStatus(r);
    const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(a));
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

// Collapse a libpq error blob to a single line so TAP output stays readable.
static std::string oneLine(std::string s) {
    for (char& ch : s) if (ch == '\n' || ch == '\r' || ch == '\t') ch = ' ';
    while (!s.empty() && s.back() == ' ') s.pop_back();
    if (s.size() > 160) s = s.substr(0, 157) + "...";
    return s;
}

// ---------------------------------------------------------------- the matrix

enum class Secret { PLAINTEXT, VERIFIER, MD5HASH };

struct Cell {
    const char* id;
    const char* role;       // PG role == ProxySQL username == that role's database
    const char* password;   // the plaintext the client presents
    Secret      secret;     // how pgsql_users stores it
    const char* floor;      // pgsql-authentication_method for this cell
    bool        expect_ok;  // is the NATIVE path expected to serve a query?
    const char* rationale;
};

static const Cell BASE[] = {
    { "trust", "authtrust", "deliberately-wrong-password", Secret::PLAINTEXT, "3", true,
      "pg_hba trust: the backend sends AuthenticationOk with no challenge, so even a "
      "wrong password connects -- which is exactly what proves no credential was exchanged (native case 0)" },

    { "cleartext", "authpw", "authpw", Secret::PLAINTEXT, "1", true,
      "pg_hba password: AuthenticationCleartextPassword, answered from the stored plaintext (native case 3)" },

    { "md5", "md5user", "md5user", Secret::PLAINTEXT, "2", true,
      "pg_hba md5: AuthenticationMD5Password, answered by pg_build_md5() over the stored plaintext (native case 5)" },

    { "scram", "authscram", "authscram", Secret::PLAINTEXT, "3", true,
      "pg_hba scram-sha-256: full SASL exchange derived from the stored plaintext (native cases 10/11/12)" },

    { "reject", "authreject", "authreject", Secret::PLAINTEXT, "3", false,
      "pg_hba reject: the backend sends ErrorResponse where an Authentication message belongs; "
      "native must surface it as a clean client error and not crash or hang" },

    { "scram-verifier", "authscram", "authscram", Secret::VERIFIER, "3", false,
      "KNOWN GAP: native has no scram_client_key/scram_server_key pass-through, so the verifier "
      "STRING is run through PBKDF2 as if it were the password. libpq serves this cell" },

    { "md5-hash", "md5user", "md5user", Secret::MD5HASH, "2", false,
      "KNOWN GAP: native has no md5_secret pass-through, so pg_build_md5() hashes the stored "
      "hash a second time. libpq serves this cell" },
};
static const size_t NBASE = sizeof(BASE) / sizeof(BASE[0]);

struct Run {
    const Cell* cell;
    int  use_ssl;       // backend leg
    bool frontend_tls;  // client leg
};

// ---------------------------------------------------------------- probing

struct Probe {
    bool conn_ok = false;
    bool query_ok = false;
    std::string err;
    std::string backend_pid;   // from the FIRST query
    std::string backend_pid2;  // from the SECOND query (must match the first)
};

// DO NOT use `SELECT pg_backend_pid()` anywhere in this file.
//
// ProxySQL INTERCEPTS it (lib/PgSQL_Session.cpp:5247) on a prefix match against
// the query digest and answers it locally with `this->thread_session_id` -- its
// own session counter, not a backend pid. The query never reaches a backend and
// never causes one to be opened.
//
// An earlier revision of this test used it as the probe, and every one of the 21
// cells reported SERVED -- including the pg_hba `reject` cell, which PostgreSQL
// demonstrably refuses. It also made the pool lookup find nothing (no backend
// connection had been opened at all) and the pg_stat_ssl lookup miss (the pid was
// fabricated). One wrong query invalidated all three assertion families at once.
//
// The two queries below are the safe forms:
//   PROBE_QUERY  round-trips to the backend and matches no interception prefix.
//   PID_QUERY    evaluates pg_backend_pid() SERVER-side inside a catalog scan, so
//                the digest does not begin with "SELECT pg_backend_pid()" and the
//                value returned is the real backend pid.
static const char* PROBE_QUERY = "SELECT 42";
static const char* PID_QUERY   = "SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()";

// "Served" means the whole path worked: the client authenticated to ProxySQL AND
// a query round-tripped to the backend. The distinction matters because ProxySQL
// authenticates the client first and only opens the backend connection lazily on
// the first query -- so every backend-auth failure in this file surfaces at query
// time, with PQconnectdb having already returned CONNECTION_OK.
static Probe probeThroughProxy(const Cell& c, bool frontend_tls) {
    Probe p;
    PGConnPtr conn = openConn(cl.pgsql_host, cl.pgsql_port, c.role, c.password,
                              c.role, frontend_tls ? "require" : "disable");
    if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
        p.err = oneLine(conn ? PQerrorMessage(conn.get()) : "null connection");
        return p;
    }
    p.conn_ok = true;

    // Run PID_QUERY TWICE on the same client session. Both round-trip to the
    // backend, so the first proves the path works and the second is exactly the
    // query that the pooled-TLS bug used to break -- the one served after the connection
    // has been detached and re-attached. Comparing the two backend PIDs proves
    // the second query really was served by the SAME pooled backend connection
    // rather than a freshly opened one, which is what makes this a regression
    // test by construction instead of by luck.
    for (int i = 0; i < 2; i++) {
        PGresult* r = PQexec(conn.get(), PID_QUERY);
        const bool good = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1);
        if (good) {
            if (i == 0) p.backend_pid = PQgetvalue(r, 0, 0);
            else        p.backend_pid2 = PQgetvalue(r, 0, 0);
        } else if (p.err.empty()) {
            p.err = oneLine(PQerrorMessage(conn.get()));
        }
        PQclear(r);
        if (!good) return p;
    }
    p.query_ok = true;
    return p;
}

// Positive proof that the pooled backend connection for this cell ran native.
// Returns "" when no free connection is recorded (which is itself diagnostic).
// Count pooled connections for this role. Used after a cell whose backend auth
// FAILED: a connection that never authenticated must not be left in the pool.
// That was reported against the mock backend (via its leftover counter);
// this checks it against a REAL PostgreSQL, using the per-method roles
// the infra provisions, which is the more trustworthy signal.
static int poolCount(PGconn* admin, const char* role) {
    std::stringstream q;
    q << "SELECT count(*) FROM stats_pgsql_free_connections WHERE hostgroup=" << AUTH_HG
      << " AND user='" << role << "'";
    usleep(500000);   // allow any return-to-pool to land before we look
    const std::string v = scalar(admin, q.str());
    return v.empty() ? -1 : atoi(v.c_str());
}

// Hardened for CI, where the pool is NOT guaranteed to be in any particular
// state and machines are slow and loaded:
//   - POLLS for the connection to appear rather than sleeping a fixed 300ms; a
//     loaded runner can easily exceed any constant we pick, and an empty result
//     would otherwise be misread as "fell back to libpq".
//   - Aggregates over EVERY row for this hostgroup+user instead of LIMIT 1. With
//     more than one pooled connection, LIMIT 1 could return a native row while a
//     libpq row sat behind it, hiding a real fallback.
// Returns "true" only if at least one row was found and EVERY row is native.
static std::string poolNativeMode(PGconn* admin, const char* role) {
    std::stringstream q;
    q << "SELECT pgsql_info FROM stats_pgsql_free_connections WHERE hostgroup=" << AUTH_HG
      << " AND user='" << role << "'";
    for (int waited = 0; waited <= 5000; waited += 100) {
        PGresult* r = PQexec(admin, q.str().c_str());
        const bool okres = (PQresultStatus(r) == PGRES_TUPLES_OK);
        const int n = okres ? PQntuples(r) : 0;
        if (n > 0) {
            int native = 0, libpq = 0, unparsed = 0;
            for (int i = 0; i < n; i++) {
                const std::string info = PQgetvalue(r, i, 0);
                if (info.find("\"native_mode\":true") != std::string::npos) native++;
                else if (info.find("\"native_mode\":false") != std::string::npos) libpq++;
                else unparsed++;
            }
            PQclear(r);
            if (unparsed) { std::stringstream m; m << "unparsed rows=" << unparsed; return m.str(); }
            if (libpq)    { std::stringstream m; m << "false (native=" << native << " libpq=" << libpq << ")"; return m.str(); }
            return "true";
        }
        PQclear(r);
        usleep(100000);
    }
    return "";   // nothing ever appeared
}

// Wait for the hostgroup's free-connection list to drain. Called after the server
// row is re-created so a cell never inspects a connection left behind by the
// previous cell -- or, in CI, by whatever ran before this test.
static bool waitPoolDrained(PGconn* admin) {
    std::stringstream q;
    q << "SELECT count(*) FROM stats_pgsql_free_connections WHERE hostgroup=" << AUTH_HG;
    for (int waited = 0; waited <= 5000; waited += 100) {
        if (scalar(admin, q.str()) == "0") return true;
        usleep(100000);
    }
    return false;
}

int main(int, char**) {
    // Build the run list first so the plan is derived, never hand-counted.
    //
    // Cells run in natural matrix order, expect-ok and expect-fail INTERLEAVED.
    //
    // This previously had to be ordered expect-ok-first: a backend auth failure
    // poisoned the connection it left behind and the next connect aborted the
    // whole process, so the suite lost every assertion after the
    // first failing cell. That is fixed -- is_connection_in_reusable_state() now
    // refuses to call a torn-down native connection reusable, so it is destroyed
    // instead of re-pooled. Interleaving is the regression check: if that ever
    // returns, cell 5 (reject) poisons cell 6 and the run dies here rather than
    // at the very end.
    std::vector<Run> runs;
    for (int ssl = 0; ssl <= 1; ssl++)
        for (size_t i = 0; i < NBASE; i++) runs.push_back({ &BASE[i], ssl, false });
    for (size_t i = 0; i < NBASE; i++) runs.push_back({ &BASE[i], 1, true });

    int planned = 1;                       // the final proxy-still-alive assertion
    for (const Run& r : runs) {
        planned += 1;                                       // outcome vs expectation
        if (r.cell->expect_ok) planned += 2;                // native_mode + same-connection reuse
        else                   planned += 1;                // no connection stranded in the pool
        if (r.cell->expect_ok && r.use_ssl) planned += 1;   // backend really encrypted
    }
    plan(planned);

    if (cl.getEnv()) return exit_status();

    PGConnPtr adminOwner = adminConn();
    if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
        BAIL_OUT("cannot proceed without an admin connection");
    PGconn* admin = adminOwner.get();

    // ---- save every piece of runtime state we are about to change ----------
    auto getVar = [&](const char* n) {
        return scalar(admin, std::string("SELECT variable_value FROM global_variables "
                                         "WHERE variable_name='") + n + "'");
    };
    const std::string saved_native  = getVar("pgsql-use_native_backend_protocol");
    const std::string saved_floor   = getVar("pgsql-authentication_method");
    const std::string saved_monitor = getVar("pgsql-monitor_enabled");
    const std::string saved_shun    = getVar("pgsql-shun_on_failures");
    const std::string saved_conn_to = getVar("pgsql-connect_timeout_server_max");

    // Snapshot any pgsql_users rows for the roles we are about to overwrite, so a
    // pre-existing row (md5user is injected by other tests) is put back verbatim.
    //
    // frontend/backend MUST be part of both the snapshot and the restore. The admin
    // table keeps a SEPARATE row per role for each flag -- one (frontend=1,backend=0)
    // and one (frontend=0,backend=1) -- under PRIMARY KEY (username, backend) and
    // UNIQUE (username, frontend). Selecting without them yields two indistinguishable
    // rows per role and re-inserting without them collapses both onto the column
    // defaults, so the second INSERT per role hits the primary key and the restore
    // silently loses the frontend/backend split.
    struct SavedUser { std::string username, password, active, hg, frontend, backend; };
    std::vector<SavedUser> saved_users;
    {
        std::stringstream q;
        q << "SELECT username,password,active,default_hostgroup,frontend,backend"
             " FROM pgsql_users WHERE username IN (";
        for (size_t i = 0; i < NBASE; i++) q << (i ? "," : "") << "'" << BASE[i].role << "'";
        q << ")";
        PGresult* r = PQexec(admin, q.str().c_str());
        if (PQresultStatus(r) == PGRES_TUPLES_OK)
            for (int i = 0; i < PQntuples(r); i++)
                saved_users.push_back({ PQgetvalue(r,i,0), PQgetvalue(r,i,1),
                                        PQgetvalue(r,i,2), PQgetvalue(r,i,3),
                                        PQgetvalue(r,i,4), PQgetvalue(r,i,5) });
        PQclear(r);
    }

    auto setVar = [&](const char* n, const std::string& v) {
        return execAdmin(admin, std::string("SET ") + n + "='" + v + "'") &&
               execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
    };

    auto restore = [&]() {
        execAdmin(admin, "DELETE FROM pgsql_users WHERE username IN "
                         "('authtrust','authpw','authreject','authscram','md5user')");
        for (const SavedUser& u : saved_users) {
            std::stringstream q;
            q << "INSERT INTO pgsql_users"
                 " (username,password,active,default_hostgroup,frontend,backend) VALUES ('"
              << u.username << "','" << u.password << "'," << u.active << "," << u.hg
              << "," << u.frontend << "," << u.backend << ")";
            execAdmin(admin, q.str());
        }
        execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME");

        std::stringstream d;
        d << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << AUTH_HG;
        execAdmin(admin, d.str());
        execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");

        if (!saved_native.empty())  setVar("pgsql-use_native_backend_protocol", saved_native);
        if (!saved_floor.empty())   setVar("pgsql-authentication_method", saved_floor);
        if (!saved_monitor.empty()) setVar("pgsql-monitor_enabled", saved_monitor);
        if (!saved_shun.empty())    setVar("pgsql-shun_on_failures", saved_shun);
        if (!saved_conn_to.empty()) setVar("pgsql-connect_timeout_server_max", saved_conn_to);
    };

    // ---- preconditions -----------------------------------------------------
    // Three of the seven base cells fail their backend connect by design. Without
    // these two settings the hostgroup gets shunned part-way through the matrix
    // and every later cell fails for the wrong reason.
    if (!setVar("pgsql-monitor_enabled", "false"))   BAIL_OUT("cannot disable the monitor");
    if (!setVar("pgsql-shun_on_failures", "10000"))  BAIL_OUT("cannot raise shun_on_failures");
    setVar("pgsql-connect_timeout_server_max", "5000");   // a hang becomes a failed cell, not a hung run

    // ---- the dedicated hostgroup, pointed at the real pgsql16 backend ------
    {
        std::stringstream d, i;
        d << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << AUTH_HG;
        i << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,use_ssl) VALUES ("
          << AUTH_HG << ",'" << cl.pgsql_server_host << "'," << cl.pgsql_server_port << ",0)";
        if (!execAdmin(admin, d.str()) || !execAdmin(admin, i.str()) ||
            !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) {
            restore();
            BAIL_OUT("could not create the dedicated auth hostgroup %d", AUTH_HG);
        }
    }

    // Re-create the hostgroup's server row from scratch, with the use_ssl this
    // cell wants. This is BOTH the use_ssl switch and the pool flush, on purpose.
    //
    // Mandatory between cells: a connection picks native-vs-libpq AND its TLS mode
    // at creation and never switches (lib/PgSQL_Connection.cpp:350, :1642), so a
    // survivor from the previous cell silently serves the next one in the wrong
    // mode.
    //
    // DELETE + re-INSERT, not UPDATE status OFFLINE_HARD -> ONLINE. The latter was
    // tried first and does NOT reliably evict at this cadence: cells asserted
    // pg_stat_ssl.ssl=false while a direct check on a freshly created pool showed
    // native use_ssl=1 negotiating TLSv1.3 correctly. The whole "native ignores
    // use_ssl" reading was an artefact of plaintext connections surviving from the
    // preceding use_ssl=0 cell. Removing a server drops its free connections
    // immediately (PgSQL_HostGroups_Manager purge -> drop_all_connections).
    auto applyServer = [&](int use_ssl) {
        std::stringstream d, i;
        d << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << AUTH_HG;
        i << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,use_ssl) VALUES ("
          << AUTH_HG << ",'" << cl.pgsql_server_host << "'," << cl.pgsql_server_port
          << "," << use_ssl << ")";
        execAdmin(admin, d.str());
        execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
        usleep(200000);
        execAdmin(admin, i.str());
        execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
        // Confirm the hostgroup's free list is actually empty before the cell
        // probes it. A fixed sleep is not safe on a loaded CI runner, and a
        // leftover connection would be read as this cell's result.
        if (!waitPoolDrained(admin))
            diag("pool for hg %d did not drain; this cell's native_mode reading may be unreliable", AUTH_HG);
    };

    auto setNative = [&](bool on) {
        return setVar("pgsql-use_native_backend_protocol", on ? "true" : "false");
    };

    // Write this cell's user row: the same plaintext password, stored in whichever
    // form the cell is exercising. Verifier and md5 hash are generated at runtime
    // by libpq (never hardcoded), exactly as pgsql-verifier_auth-t does.
    auto writeUser = [&](const Cell& c) -> bool {
        std::string secret = c.password;
        if (c.secret != Secret::PLAINTEXT) {
            const char* algo = (c.secret == Secret::VERIFIER) ? "scram-sha-256" : "md5";
            char* enc = PQencryptPasswordConn(admin, c.password, c.role, algo);
            if (enc == nullptr) {
                diag("PQencryptPasswordConn(%s,%s) failed: %s", c.role, algo, PQerrorMessage(admin));
                return false;
            }
            secret = enc;
            PQfreemem(enc);
        }
        std::stringstream d, i;
        d << "DELETE FROM pgsql_users WHERE username='" << c.role << "'";
        i << "INSERT INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('"
          << c.role << "','" << secret << "',1," << AUTH_HG << ")";
        return execAdmin(admin, d.str()) && execAdmin(admin, i.str()) &&
               execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME");
    };

    // ---- run the matrix ----------------------------------------------------
    for (const Run& run : runs) {
        const Cell& c = *run.cell;
        std::stringstream lbl;
        lbl << c.id << " [backend_ssl=" << run.use_ssl
            << " frontend_tls=" << (run.frontend_tls ? 1 : 0) << "]";
        const std::string label = lbl.str();

        if (!setVar("pgsql-authentication_method", c.floor) || !writeUser(c)) {
            diag("%s: setup failed, skipping to keep the plan aligned", label.c_str());
        }
        // -------- native leg --------
        // setNative BEFORE applyServer: the flush is what makes the new mode take
        // effect, so the variable must already be set when the pool is emptied.
        setNative(true);
        applyServer(run.use_ssl);
        const Probe nat = probeThroughProxy(c, run.frontend_tls);
        const bool nat_served = nat.conn_ok && nat.query_ok;
        const std::string native_mode = nat_served ? poolNativeMode(admin, c.role) : std::string();

        // Confirm the backend leg was genuinely encrypted, from OUTSIDE ProxySQL.
        std::string ssl_detail = "not checked";
        bool ssl_confirmed = false;
        if (nat_served && run.use_ssl) {
            if (nat.backend_pid.empty()) {
                ssl_detail = "backend pid not captured";
            } else {
                PGConnPtr direct = directBackendConn();
                if (direct && PQstatus(direct.get()) == CONNECTION_OK) {
                    const std::string v = scalar(direct.get(),
                        "SELECT ssl::text FROM pg_stat_ssl WHERE pid=" + nat.backend_pid);
                    if (v.empty()) ssl_detail = "pid " + nat.backend_pid + " absent from pg_stat_ssl";
                    else { ssl_confirmed = (v == "t" || v == "true");
                           ssl_detail = "pg_stat_ssl.ssl=" + v + " for pid " + nat.backend_pid; }
                } else {
                    ssl_detail = "no direct backend connection available";
                }
            }
        }

        // Sample the pool NOW, while only the native leg has run. Sampling after
        // the libpq leg would count the connection libpq legitimately pools when
        // it serves a cell native cannot (md5-hash and scram-verifier), and report
        // it as a stranded native connection.
        const int stranded_after_native = c.expect_ok ? 0 : poolCount(admin, c.role);

        // -------- libpq leg, for the differential diagnostic --------
        setNative(false);
        applyServer(run.use_ssl);
        const Probe lpq = probeThroughProxy(c, run.frontend_tls);
        const bool lpq_served = lpq.conn_ok && lpq.query_ok;

        // -------- assertions --------
        ok(nat_served == c.expect_ok,
           "%s: native %s, expected %s | libpq %s | %s",
           label.c_str(),
           nat_served ? "SERVED" : "FAILED",
           c.expect_ok ? "SERVED" : "FAILED",
           lpq_served ? "SERVED" : "FAILED",
           nat_served ? "-" : nat.err.c_str());

        if (nat_served != lpq_served) {
            diag("  DIVERGENCE %s: native=%s libpq=%s -- %s",
                 label.c_str(), nat_served ? "served" : "failed",
                 lpq_served ? "served" : "failed", c.rationale);
            if (!nat.err.empty()) diag("  native error: %s", nat.err.c_str());
            if (!lpq.err.empty()) diag("  libpq  error: %s", lpq.err.c_str());
        }

        if (c.expect_ok) {
            ok(native_mode == "true",
               "%s: the pooled backend connection reports native_mode=true (got '%s')",
               label.c_str(), native_mode.empty() ? "no free connection recorded" : native_mode.c_str());

            // Pooled-TLS regression guard. Both queries ran on one client session; if the
            // second was served by the same backend PID then the connection really
            // was detached and re-attached between them -- the path on which a
            // native TLS connection used to lose myds->encrypted and be read as
            // plaintext. Different PIDs would mean a fresh connect served query 2
            // and the regression would go undetected.
            ok(!nat.backend_pid.empty() && nat.backend_pid == nat.backend_pid2,
               "%s: both queries served by the same pooled backend connection (pid '%s' then '%s')",
               label.c_str(),
               nat.backend_pid.empty()  ? "-" : nat.backend_pid.c_str(),
               nat.backend_pid2.empty() ? "-" : nat.backend_pid2.c_str());

            if (run.use_ssl) {
                ok(ssl_confirmed,
                   "%s: backend leg genuinely TLS-encrypted (%s)%s",
                   label.c_str(), ssl_detail.c_str(),
                   (c.secret == Secret::PLAINTEXT && strcmp(c.id, "scram") == 0)
                       ? " -- also proves SCRAM-SHA-256-PLUS channel binding, since a wrong "
                         "tls-server-end-point digest would have failed the login"
                       : "");
            }
        }

        if (!c.expect_ok) {
            // The backend auth failed by design. A connection that never
            // authenticated must be destroyed, not returned to the pool -- a
            // stranded one is both a leak and, before that fix, the object that
            // aborted the process on the next connect.
            ok(stranded_after_native == 0,
               "%s: failed auth left NO connection in the pool (found %d)",
               label.c_str(), stranded_after_native);
        }

        // Stop the moment the proxy dies. Without this the remaining cells emit a
        // cascade of "no connection to the server" noise that buries the one fact
        // that matters: WHICH cell killed it.
        if (scalar(admin, "SELECT 1") != "1") {
            BAIL_OUT("ProxySQL died during cell '%s' -- expect the assert at "
                     "lib/PgSQL_Connection.cpp:1075 (async_state_machine==ASYNC_IDLE) "
                     "in proxysql.log. That signature means a connection left behind "
                     "by a failed backend authentication was reused instead of "
                     "destroyed.", label.c_str());
        }
    }

    // ---- the proxy survived the whole matrix -------------------------------
    // Three cells drive deliberate backend auth failures; one of them is a backend
    // that answers an Authentication request with ErrorResponse. A crash there
    // would take the process down mid-run, so prove it is still answering.
    {
        PGConnPtr a2 = adminConn();
        const bool alive = a2 && PQstatus(a2.get()) == CONNECTION_OK &&
                           scalar(a2.get(), "SELECT 1") == "1";
        ok(alive, "ProxySQL still alive and answering admin queries after the full auth matrix");
    }

    restore();
    return exit_status();
}
