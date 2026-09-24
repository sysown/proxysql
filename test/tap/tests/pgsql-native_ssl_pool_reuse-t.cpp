/**
 * @file pgsql-native_ssl_pool_reuse-t.cpp
 * @brief Regression test: a pooled native TLS backend connection must keep its
 *        encryption when a DIFFERENT client session picks it up.
 *
 * THE BUG THIS GUARDS
 * -------------------
 * The native path used to store its SSL and BIOs on PgSQL_Data_Stream. That
 * object belongs to the SESSION and is destroyed when the session finishes with
 * the backend (PgSQL_Session.cpp:1119/:1142/:1175); its destructor SSL_free()s
 * the SSL (PgSQL_Data_Stream.cpp:376). But a PgSQL_Connection is POOLED -- it
 * outlives any one session -- so pooling a TLS connection destroyed its TLS
 * context while the socket stayed open and encrypted. The next session attached
 * it to a fresh data stream with no SSL, read TLS records as plaintext, and
 * reported "backend closed during result fetch". The fix moved the TLS state
 * onto PgSQL_Connection, giving it the socket's lifetime.
 *
 * WHAT THE SCENARIOS COVER
 * ------------------------
 * A (7 assertions x 4 combinations = 28) -- the pool-reuse guard, run under EVERY
 *    combination of backend use_ssl x client sslmode. Per combination: three
 *    separate client sessions, asserting all are served, that the backend PIDs
 *    MATCH, that the reused connection's real encryption state matches use_ssl,
 *    that the native path served it, and finally that EVERY connection left in
 *    the pool -- not merely the one a probe happened to land on -- is encrypted
 *    as use_ssl asked, cross-checked against ProxySQL's own using_ssl claim.
 *
 *    The PID match is what makes this a regression test: if session 2 opened a
 *    fresh connection instead of reusing the pooled one, every other assertion
 *    would still pass while the bug went unexercised.
 *
 *    The pool-wide check exists because every OTHER encryption assertion in this
 *    file is keyed on a pid the test learned from its own query, so it can only
 *    ever speak for connections the test personally used. It enumerates the pool
 *    from stats_pgsql_free_connections and verifies each entry against
 *    pg_stat_ssl. The trust boundary is preserved: ProxySQL supplies only the
 *    backend_pid -- an identifier -- while the encryption verdict still comes
 *    from PostgreSQL. ProxySQL's using_ssl is then compared against that verdict
 *    rather than trusted, so a proxy that MISREPORTS its own transport fails
 *    here. Both fields are reported for native connections as of
 *    lib/PgSQL_HostGroups_Manager.cpp:3082; against a binary predating that, the
 *    pid comes back absent and the assertion fails saying so rather than
 *    silently checking nothing.
 *
 *    Running it per combination crosses the two axes that matter. The frontend
 *    leg (client <-> ProxySQL) and the backend leg (ProxySQL <-> PostgreSQL) are
 *    separate data streams with separate TLS state, so a fix that confused them,
 *    or that keyed the backend's transport off the client's, fails here. It also
 *    covers the case a real deployment actually runs -- BOTH legs encrypted
 *    across a pooled handoff -- which a single-combination test does not reach.
 *
 * B (3) -- configuration disagreeing with the connection. use_ssl is flipped to 0
 *    while an encrypted connection is still warm in the pool. It must keep
 *    working: `encrypted` follows the connection's own SSL object, NOT config. A
 *    fix that re-derived it from use_ssl would fail here.
 *
 * (There is no Scenario C. It was removed, as was a Scenario E covering a
 * multi-server hostgroup; the surviving labels were left alone rather than
 * renumbered so that assertion numbers in older run logs still line up.)
 *
 * WHICH ASSERTIONS GUARD THE BUG ABOVE: A's first three, and B's second query.
 * They fail because session 2 cannot READ the connection. The pool-wide checks
 * (A's last two) deliberately do NOT catch that bug and must not be mistaken for
 * it: when the SSL is freed on pool return the socket stays encrypted as far as
 * PostgreSQL is concerned, so pg_stat_ssl still reports 't' and they pass. They
 * cover a different property -- that no connection ANYWHERE in the pool has the
 * wrong transport, and that ProxySQL's own account of it is truthful.
 *
 * D (4) -- churn. Several client sessions are held open at once and queried
 *    round-robin, so pooled TLS connections are detached and re-attached many
 *    times instead of once. A lifetime bug that only trips on the fifth or
 *    twelfth handoff is invisible to a scenario that hands off once; this is also
 *    the shape most likely to expose a use-after-free when run under ASAN.
 *
 * THE SINGLE-SERVER PRECONDITION IS VERIFIED, NOT ASSUMED: freshServer() bails
 * out if the hostgroup does not hold exactly one server, because with several,
 * two sessions legitimately land on different backends -- a pid mismatch would be
 * correct behaviour reported as a bug, and a pid match would prove nothing.
 * Every query about a server names the (hostname, port) it means, since
 * "SELECT use_ssl ... WHERE hostgroup_id=N" returns an arbitrary row as soon as
 * the hostgroup holds more than one.
 *
 * VALIDATED IN BOTH DIRECTIONS: with the bug deliberately reintroduced, Scenario
 * A's reuse and encryption assertions fail and Scenario B's second query fails;
 * with the fix in place the file passes in full. (That check was performed on the
 * equivalent single-combination form of Scenario A -- parameterising it only
 * widens the same assertions, so the specific assertion NUMBERS from that run no
 * longer apply.)
 *
 * Backend encryption is read from pg_stat_ssl over a DIRECT connection to
 * PostgreSQL, never from ProxySQL, which is the component under test.
 *
 * SCENARIO INDEPENDENCE: every scenario (and every Scenario A combination) begins
 * with freshServer(), which rebuilds the server row and waits for the pool to
 * drain. So none of them inherits the previous one's use_ssl or its pooled
 * connections, and they may be reordered or run individually. Scenario B
 * deliberately ends with use_ssl=0 -- without that rule the next scenario would
 * silently start on a plaintext backend.
 *
 * Native path only (pgsql-use_native_backend_protocol=true). This test does NOT
 * restore runtime state; it only ever uses LOAD ... TO RUNTIME and never writes
 * to disk.
 */
#include <cstdlib>
#include <memory>
#include <functional>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int HG = 92;                 // dedicated: never disturb other tests' pools

// pg_backend_pid() alone is INTERCEPTED by ProxySQL (lib/PgSQL_Session.cpp:5247)
// and answered locally, never reaching a backend. Wrapping it in a catalog scan
// changes the digest so it executes server-side and returns the real pid.
// Scenario A runs once per row: backend use_ssl x client sslmode. At file scope
// so plan() is DERIVED from it -- adding a row must not silently desync the
// assertion count.
struct Combo { int backend_ssl; const char* client_sslmode; const char* want_backend; };
static const Combo COMBOS[] = {
    { 1, "require", "t" },   // both legs encrypted -- the production-like case
    { 1, "disable", "t" },   // client plaintext, backend encrypted
    { 0, "require", "f" },   // client encrypted, backend plaintext
    { 0, "disable", "f" },   // neither encrypted
};
static const size_t NCOMBOS = sizeof(COMBOS) / sizeof(COMBOS[0]);

// Scenario D. Sessions are held open SIMULTANEOUSLY and queried round-robin:
// that is what forces repeated detach/re-attach against more than one pooled
// connection. Sequential sessions would hand the same single connection back and
// forth and never exercise a pool of them.
static const int CHURN_CLIENTS = 4;
static const int CHURN_ROUNDS  = 8;

// Assertions: A = 7 per combination, B = 3, D = 4, plus a final liveness check.
static const int PLAN_A_PER = 7, PLAN_B = 3, PLAN_D = 4, PLAN_FINAL = 1;

// One pooled connection as ProxySQL describes it. Only the pid is taken on
// trust (it is an identifier, not a verdict); `claim` is ProxySQL's assertion
// about its own transport, which the test CHECKS rather than believes.
// One pooled connection as ProxySQL describes it. host/port are carried because
// a backend pid is only meaningful ON THE SERVER THAT ISSUED IT: pids are
// per-machine, so looking one up on the wrong PostgreSQL does not merely miss --
// it can find an UNRELATED backend that happens to have the same pid number and
// report its encryption instead. Scenarios here pin the hostgroup to a single
// server, but the pool query is hostgroup-wide, so the lookup is aimed at the
// server the connection actually belongs to rather than at a global default.
struct PooledConn { std::string pid; std::string claim; std::string host; int port; };

// Minimal field reader for the pgsql_info JSON. This file links libpq and tap
// only -- there is no JSON parser available -- and poolNativeMode() already
// reads the same blob by substring search, so this stays consistent with it.
// nlohmann's dump() emits no spaces, hence the exact "key": prefix match.
static std::string jsonField(const std::string& blob, const std::string& key) {
    const std::string k = "\"" + key + "\":";
    size_t p = blob.find(k);
    if (p == std::string::npos) return "";
    p += k.size();
    if (p < blob.size() && blob[p] == '"') {          // string value
        const size_t e = blob.find('"', ++p);
        return e == std::string::npos ? "" : blob.substr(p, e - p);
    }
    const size_t e = blob.find_first_of(",}", p);     // numeric / bare value
    return e == std::string::npos ? "" : blob.substr(p, e - p);
}

static const char* PID_QUERY =
    "SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()";

static PGConnPtr openConn(const char* h, int p, const char* u, const char* pw,
                          const char* db, const char* sslmode) {
    std::stringstream ss;
    ss << "host=" << h << " port=" << p << " user=" << u << " password=" << pw;
    if (db && *db) ss << " dbname=" << db;
    ss << " sslmode=" << sslmode << " connect_timeout=10";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}
// libpq errors arrive multi-line; TAP assertion text is one line per assertion.
static std::string oneline(std::string e) {
    for (char& ch : e) if (ch == '\n' || ch == '\r') ch = ' ';
    while (!e.empty() && e.back() == ' ') e.pop_back();
    return e;
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

int main(int, char**) {
    plan((int)(NCOMBOS * PLAN_A_PER) + PLAN_B + PLAN_D + PLAN_FINAL);
    if (cl.getEnv()) return exit_status();

    PGConnPtr adminOwner = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port,
                                    cl.admin_username, cl.admin_password, nullptr, "disable");
    if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
        BAIL_OUT("cannot proceed without an admin connection");
    PGconn* admin = adminOwner.get();


    // NOTHING BELOW IS RESTORED, AND THAT IS CORRECT. The harness reconfigures
    // ProxySQL before EVERY test: proxysql-tester.py:811 calls
    // reconfigure_proxysql() (:370) inside the per-test loop, which issues
    // LOAD PGSQL VARIABLES / USERS / SERVERS FROM DISK followed by TO RUNTIME.
    // So the native flag, this user's default_hostgroup and the hostgroup rows
    // are all reset before the next test sees them.
    //
    // That restore only works because this file uses LOAD ... TO RUNTIME and
    // NEVER SAVE ... TO DISK: the on-disk config stays pristine, so reloading
    // from disk genuinely undoes everything done here. Writing any of it to disk
    // would defeat the harness for every test that follows.

    auto setVar = [&](const char* n, const std::string& v) {
        return execAdmin(admin, std::string("SET ") + n + "='" + v + "'") &&
               execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
    };
    // Poll a condition instead of sleeping. Returns false if it never became true
    // within the budget, so the caller can report it rather than silently continue.
    auto waitUntil = [&](const std::function<bool()>& cond) {
        for (int waited = 0; waited <= 5000; waited += 50) {
            if (cond()) return true;
            usleep(50000);
        }
        return false;
    };
    // A HOSTGROUP CAN HOLD MANY SERVERS. pgsql_servers is keyed on
    // (hostgroup_id, hostname, port), so "the server in hostgroup N" is not a
    // thing that exists: a hostgroup-wide "SELECT use_ssl FROM
    // runtime_pgsql_servers WHERE hostgroup_id=N" returns an ARBITRARY row once
    // there is more than one, and a hostgroup-wide pool count silently mixes
    // servers together. Everything below that asks about a server therefore
    // names the (hostname, port) it means. Only the drain check is deliberately
    // hostgroup-wide, because "no connections left anywhere in this hostgroup"
    // is genuinely the question it asks.
    auto poolCountHG = [&]() {
        std::stringstream q;
        q << "SELECT count(*) FROM stats_pgsql_free_connections WHERE hostgroup=" << HG;
        const std::string v = scalar(admin, q.str());
        return v.empty() ? -1 : atoi(v.c_str());
    };
    auto hgServerCount = [&]() {
        std::stringstream q;
        q << "SELECT count(*) FROM runtime_pgsql_servers WHERE hostgroup_id=" << HG;
        const std::string v = scalar(admin, q.str());
        return v.empty() ? -1 : atoi(v.c_str());
    };
    auto srvPresent = [&](const std::string& host, int port) {
        std::stringstream q;
        q << "SELECT count(*) FROM runtime_pgsql_servers WHERE hostgroup_id=" << HG
          << " AND hostname='" << host << "' AND port=" << port;
        const std::string v = scalar(admin, q.str());
        return v.empty() ? -1 : atoi(v.c_str());
    };
    auto runtimeUseSslFor = [&](const std::string& host, int port) {
        std::stringstream q;
        q << "SELECT use_ssl FROM runtime_pgsql_servers WHERE hostgroup_id=" << HG
          << " AND hostname='" << host << "' AND port=" << port;
        const std::string v = scalar(admin, q.str());
        return v.empty() ? -1 : atoi(v.c_str());
    };
    // EVERY pooled connection in the hostgroup, as (backend_pid, using_ssl).
    // This is what lets an assertion speak for the whole pool instead of only
    // the connection a probe happened to land on: without a pid there is no way
    // to correlate a pooled connection with pg_stat_ssl, and pg_stat_ssl is the
    // only trustworthy source for what the transport really is.
    auto poolConns = [&]() {
        std::stringstream q;
        q << "SELECT srv_host, srv_port, pgsql_info FROM stats_pgsql_free_connections "
          << "WHERE hostgroup=" << HG;
        std::vector<PooledConn> out;
        PGresult* r = PQexec(admin, q.str().c_str());
        if (PQresultStatus(r) == PGRES_TUPLES_OK) {
            for (int i = 0; i < PQntuples(r); i++) {
                const std::string host = PQgetvalue(r, i, 0);
                const int         port = atoi(PQgetvalue(r, i, 1));
                const std::string blob = PQgetvalue(r, i, 2);
                out.push_back({ jsonField(blob, "backend_pid"), jsonField(blob, "using_ssl"),
                                host, port });
            }
        }
        PQclear(r);
        return out;
    };

    auto freshServer = [&](int use_ssl) {
        std::stringstream d, i;
        d << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << HG;
        i << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,use_ssl) VALUES ("
          << HG << ",'" << cl.pgsql_server_host << "'," << cl.pgsql_server_port << "," << use_ssl << ")";
        // TWO loads, deliberately. The first is what EVICTS the pool: connections
        // are dropped only when the server actually disappears from the runtime
        // table. Collapsing this into DELETE + INSERT + one LOAD evicts nothing --
        // measured: the pooled connection count stays at 1, because ProxySQL sees
        // the same hostgroup/host/port still present and treats it as unchanged.
        // That matters here because a connection fixes its TLS mode at creation,
        // so a surviving use_ssl=0 connection would serve a use_ssl=1 cell and the
        // test would blame the native path for a stale-pool artefact.
        //
        // Both waits POLL for the condition rather than sleeping a fixed span: a
        // constant that is comfortable here is not necessarily comfortable on a
        // loaded CI runner, and guessing high just makes every cell slower.
        execAdmin(admin, d.str()); execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
        int seen = -1;
        if (!waitUntil([&]{ seen = poolCountHG(); return seen == 0; })) {
            // -1 means the admin query itself failed -- a different problem from
            // "the pool still has connections", and worth saying so.
            if (seen < 0) diag("could not read the pool for hostgroup %d (admin query failed)", HG);
            else diag("hostgroup %d did not drain (%d connection(s) left); this cell "
                      "may be served by a stale connection", HG, seen);
        }

        execAdmin(admin, i.str()); execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
        seen = -1;
        if (!waitUntil([&]{ seen = srvPresent(cl.pgsql_server_host, cl.pgsql_server_port); return seen == 1; })) {
            if (seen < 0) diag("could not read runtime_pgsql_servers (admin query failed)");
            else diag("server %s:%d did not come back online in hostgroup %d (found %d)",
                      cl.pgsql_server_host, cl.pgsql_server_port, HG, seen);
        }

        // VERIFY the single-server precondition instead of assuming it. Scenarios
        // A, B and D assert that two sessions land on the SAME backend pid; that
        // only means anything when the hostgroup holds exactly one server. With
        // several, ProxySQL load-balances and two sessions legitimately land on
        // different backends, so a pid mismatch would be a correct result being
        // reported as a bug -- and, worse, a pid MATCH would prove nothing.
        const int nsrv = hgServerCount();
        if (nsrv != 1) {
            BAIL_OUT("hostgroup %d holds %d servers, expected exactly 1 -- the reuse "
                     "assertions require a single-server hostgroup to be meaningful",
                     HG, nsrv);
        }
    };

    if (!setVar("pgsql-use_native_backend_protocol", "true")) BAIL_OUT("cannot enable native mode");
    {
        std::stringstream u;
        u << "UPDATE pgsql_users SET default_hostgroup=" << HG << " WHERE username='" << cl.pgsql_username << "'";
        if (!execAdmin(admin, u.str()) || !execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME")) {
            BAIL_OUT("cannot point %s at hostgroup %d", cl.pgsql_username, HG);
        }
    }

    auto probeSsl = [&](std::string& pid, const char* client_sslmode) {
        PGConnPtr c = openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, cl.pgsql_username, client_sslmode);
        if (!c || PQstatus(c.get()) != CONNECTION_OK) {
            // Report the actual reason. Collapsing every connect failure to a
            // fixed string hides exactly what a failing run needs: auth rejected,
            // backend down, TLS refused and "remaining connection slots are
            // reserved..." are very different problems.
            const std::string e = oneline(c ? PQerrorMessage(c.get()) : "null connection");
            return e.empty() ? std::string("connect failed") : e;
        }
        PGresult* r = PQexec(c.get(), PID_QUERY);
        std::string err;
        if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) pid = PQgetvalue(r, 0, 0);
        else err = oneline(PQerrorMessage(c.get()));
        PQclear(r);
        return err;
    };
    auto probe = [&](std::string& pid) { return probeSsl(pid, "disable"); };
    // Positive proof that the NATIVE path served these queries. Without it the
    // whole file passes just as happily if ProxySQL silently fell back to libpq,
    // because every other check here (query served, pg_stat_ssl, matching pids)
    // is satisfied by the libpq path too. Reads the per-connection
    // "native_mode":true|false that stats_pgsql_free_connections exposes
    // (lib/PgSQL_HostGroups_Manager.cpp:3077). Polls, because the return to the
    // FREE list is not instantaneous on a loaded runner.
    auto poolNativeMode = [&]() {
        std::stringstream q;
        q << "SELECT pgsql_info FROM stats_pgsql_free_connections WHERE hostgroup=" << HG;
        std::string verdict;
        // Reuses waitUntil so there is exactly ONE polling implementation here.
        waitUntil([&]() {
            PGresult* r = PQexec(admin, q.str().c_str());
            const int n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
            if (n > 0) {
                int native = 0, libpq = 0;
                for (int i = 0; i < n; i++) {
                    const std::string info = PQgetvalue(r, i, 0);
                    if (info.find("\"native_mode\":true") != std::string::npos) native++;
                    else if (info.find("\"native_mode\":false") != std::string::npos) libpq++;
                }
                // Judge EVERY row: one libpq connection hiding behind a native one
                // would otherwise pass.
                if (libpq) { std::stringstream m; m << "false (native=" << native << " libpq=" << libpq << ")"; verdict = m.str(); }
                else if (native) verdict = "true";
                else verdict = "unparsed";
            }
            PQclear(r);
            return !verdict.empty();
        });
        return verdict;   // "" if no free connection ever appeared
    };

    // Ask a SPECIFIC PostgreSQL whether the backend with this pid is encrypted.
    // The server must be named rather than assumed: pids are per-machine, so
    // querying the wrong node can return an unrelated backend that happens to
    // share the number, which is a wrong ANSWER rather than a missing one.
    auto backendSslOn = [&](const std::string& host, int port, const std::string& pid) {
        if (pid.empty() || host.empty()) return std::string("");
        // `pid` is BACKEND-CONTROLLED data -- it arrives as a text field through
        // ProxySQL from the server -- and it is about to be concatenated into a
        // query run as a SUPERUSER on the real PostgreSQL. This suite ships a
        // scriptable mock server (pgsql_mock_backend.h) and a hostile-backend
        // test, so a value like "1;DROP TABLE ..." is a reachable input, not a
        // hypothetical. Refuse anything that is not a plain integer.
        if (pid.find_first_not_of("0123456789") != std::string::npos) {
            diag("refusing to query pg_stat_ssl with a non-numeric backend pid '%s'", pid.c_str());
            return std::string("");
        }
        PGConnPtr d = openConn(host.c_str(), port,
                               cl.pgsql_server_username, cl.pgsql_server_password, "postgres", "disable");
        if (!d || PQstatus(d.get()) != CONNECTION_OK) {
            // SAY SO when the ORACLE is what failed. This returns "" for the same
            // reason "pid absent from pg_stat_ssl" does, and the callers turn both
            // into "not found" -- which reads as the pooled-TLS path being broken
            // when in fact the measuring instrument never connected. That is the
            // exact misdiagnosis the rest of this file works to avoid, so the two
            // causes must at least be distinguishable in the log.
            diag("direct connection to %s:%d FAILED, so pg_stat_ssl could not be read for "
                 "pid %s -- the assertion below reports 'not found' for that reason, NOT "
                 "because the pooled connection is wrong: %s",
                 host.c_str(), port, pid.c_str(),
                 d ? oneline(PQerrorMessage(d.get())).c_str() : "null connection");
            return std::string("");
        }
        return scalar(d.get(), "SELECT ssl::text FROM pg_stat_ssl WHERE pid=" + pid);
    };
    // Scenarios A, B and D read a pid returned by a query they just ran through a
    // hostgroup freshServer() has verified holds exactly ONE server, and that
    // server is cl.pgsql_server_host by construction -- so naming it here is
    // correct, not an assumption.
    auto backendSsl = [&](const std::string& pid) {
        return backendSslOn(cl.pgsql_server_host, cl.pgsql_server_port, pid);
    };

    // ======================================================================
    // SCENARIO A -- the pool-reuse regression guard, run under EVERY combination
    // of backend use_ssl x client sslmode. Session 1 establishes a backend
    // connection and pools it; session 2 must pick that same connection up and
    // use it, and its real transport must still match what use_ssl asked for.
    //
    // This is the case that was broken: the TLS session used to live on the
    // SESSION's backend data stream, which is destroyed when session 1 finishes
    // (PgSQL_Session.cpp:1119/:1142/:1175) and whose destructor SSL_free()s the
    // SSL (PgSQL_Data_Stream.cpp:376). The pooled connection was left with a live
    // encrypted socket and no TLS context, so session 2 read ciphertext as
    // plaintext and reported "backend closed during result fetch". The TLS state
    // now lives on PgSQL_Connection, giving it the socket's lifetime.
    //
    // The use_ssl=0 rows are not filler: they are the control. They prove the
    // encryption assertion is reading a real per-connection property rather than
    // a constant that happens to say "encrypted" for every connection.
    // ======================================================================
    for (const Combo& c : COMBOS) {
        freshServer(c.backend_ssl);
        const bool want_enc = (std::string(c.want_backend) == "t");
        std::stringstream tagss;
        tagss << "use_ssl=" << c.backend_ssl << "/sslmode=" << c.client_sslmode;
        const std::string tag = tagss.str();

        std::string a1, a2;
        const std::string ea1 = probeSsl(a1, c.client_sslmode);
        // Session 1's backend must be back on the FREE list before session 2
        // asks for one. poolNativeMode() below already documents that this
        // return is not instantaneous on a loaded runner; the pid match is this
        // file's core assertion, so it waits for the same condition instead of
        // relying on session 2's connect+SCRAM handshake taking long enough.
        // Otherwise session 2 opens a FRESH connection and the reuse assertion
        // fails for a reason that has nothing to do with TLS lifetime.
        if (!waitUntil([&]{ return poolCountHG() >= 1; })) {
            diag("A[%s]: nothing returned to the pool after session 1; session 2 may open "
                 "a fresh connection and the reuse assertion below would then fail for a "
                 "scheduling reason rather than a TLS one", tag.c_str());
        }
        const std::string ea2 = probeSsl(a2, c.client_sslmode);
        ok(ea1.empty() && ea2.empty() && !a1.empty() && !a2.empty(),
           "A[%s]: two separate sessions were both served (pids '%s','%s')%s%s",
           tag.c_str(), a1.empty() ? "-" : a1.c_str(), a2.empty() ? "-" : a2.c_str(),
           (ea1.empty() && ea2.empty()) ? "" : " -- ",
           ea1.empty() ? ea2.c_str() : ea1.c_str());

        ok(!a1.empty() && a1 == a2,
           "A[%s]: session 2 reused the SAME pooled connection (pid '%s' then '%s') "
           "-- differing pids would mean the pooled-reuse path was never exercised",
           tag.c_str(), a1.empty() ? "-" : a1.c_str(), a2.empty() ? "-" : a2.c_str());

        // The BACKEND leg's real state, read from PostgreSQL itself. client
        // sslmode=require is separately its own proof that the FRONTEND leg is
        // encrypted -- libpq aborts the connection if TLS is not negotiated -- so
        // a row where the two legs disagree is what proves they are independent.
        const std::string assl = backendSsl(a2);
        const bool enc = (assl == "t" || assl == "true");
        ok(!assl.empty() && enc == want_enc,
           "A[%s]: the reused connection's backend encryption follows use_ssl and NOT "
           "the client leg (pg_stat_ssl.ssl='%s', want '%s')",
           tag.c_str(), assl.empty() ? "not found" : assl.c_str(), c.want_backend);

        std::string a3;
        const std::string ea3 = probeSsl(a3, c.client_sslmode);
        ok(ea3.empty() && !a3.empty(),
           "A[%s]: a third session is served too (pid '%s')%s%s", tag.c_str(),
           a3.empty() ? "-" : a3.c_str(), ea3.empty() ? "" : " -- ", ea3.c_str());

        const std::string nm = poolNativeMode();
        ok(nm == "true",
           "A[%s]: the pooled connection really used the NATIVE path, not a silent "
           "libpq fallback (native_mode='%s')",
           tag.c_str(), nm.empty() ? "no free connection recorded" : nm.c_str());

        // ---- pool-wide: EVERY pooled connection, not just the probed one -----
        // Assertions above are keyed on pids this test learned from its own
        // queries, so they can only speak for connections it personally used.
        // Here the pool itself is enumerated and each entry checked against
        // pg_stat_ssl, so a stray connection with the wrong transport -- one the
        // probes never landed on -- is caught rather than ignored.
        std::vector<PooledConn> pooled;
        waitUntil([&]{ pooled = poolConns(); return !pooled.empty(); });

        // CROSS-CHECK ProxySQL's claim against the BACKEND's own report. Every
        // assertion below is keyed on a pid ProxySQL ASSERTS, whereas a1/a2 came
        // from the backend itself answering pg_stat_activity. Nothing otherwise
        // ties the two together, so a wrong backend_pid would silently send the
        // encryption checks to some OTHER connection's pg_stat_ssl row -- and on
        // the use_ssl=0 rows, where 'f' is what is wanted, any plaintext
        // connection on the server satisfies them. That is a real false pass,
        // and it matters most precisely here: backend_pid is newly reported for
        // native connections (lib/PgSQL_HostGroups_Manager.cpp), so this file is
        // the first thing that exercises it.
        bool pool_has_a2 = false;
        for (const PooledConn& pc : pooled) {
            if (!a2.empty() && pc.pid == a2) { pool_has_a2 = true; break; }
        }

        int checked = 0, correct = 0, agree = 0, nopid = 0, noclaim = 0;
        for (const PooledConn& pc : pooled) {
            // No pid means the pool cannot be correlated with pg_stat_ssl at
            // all. That is a real gap, not something to skip past, so it is
            // counted and failed on below.
            if (pc.pid.empty() || pc.pid == "0") { nopid++; continue; }
            // Ask THIS connection's own server, not a global default. The pool
            // query is hostgroup-wide and a hostgroup may hold many servers, so
            // a fixed target would silently read the wrong machine -- where the
            // same pid number can belong to an entirely different backend.
            const std::string truth = backendSslOn(pc.host, pc.port, pc.pid);
            if (truth.empty()) continue;   // deliberately NOT counted in `checked`
            checked++;
            const bool e = (truth == "t" || truth == "true");
            if (e == want_enc) correct++;
            // An ABSENT claim must not read as agreement. jsonField() returns ""
            // for a missing field, and ("" == "YES") is false -- which happens to
            // equal `e` for every use_ssl=0 row, so a proxy that stopped
            // reporting using_ssl entirely would silently "agree" in exactly the
            // combinations meant to be the control. Judge the claim only when
            // there IS one, and count the rest as a missing measurement, the same
            // way nopid does above. Testing against both literals rather than for
            // emptiness also catches a re-encoding of the field (say to a JSON
            // bool) instead of reading it as a plaintext claim.
            if (pc.claim != "YES" && pc.claim != "NO") noclaim++;
            else if ((pc.claim == "YES") == e)         agree++;
        }

        // `checked` must equal the pool size, not merely be non-zero: a
        // connection that vanished from pg_stat_ssl between enumerating the pool
        // and checking it must shrink the pass, never the denominator.
        ok(!pooled.empty() && nopid == 0 && pool_has_a2 &&
               checked == (int)pooled.size() && correct == checked,
           "A[%s]: EVERY connection in the pool is encrypted as use_ssl asked, not just "
           "the probed one, and the pool really holds the connection session 2 used "
           "(pid '%s' %s; %d pooled, %d verified against pg_stat_ssl, %d correct, "
           "%d with no usable backend_pid)",
           tag.c_str(), a2.empty() ? "-" : a2.c_str(), pool_has_a2 ? "present" : "MISSING",
           (int)pooled.size(), checked, correct, nopid);

        // ProxySQL's own account of its transport, CHECKED against PostgreSQL's
        // rather than trusted. A proxy that pooled a plaintext connection while
        // reporting using_ssl=YES would satisfy every other assertion here.
        ok(checked > 0 && noclaim == 0 && agree == checked,
           "A[%s]: ProxySQL's using_ssl agrees with pg_stat_ssl for all %d verified "
           "pooled connection(s) (%d agree, %d with no usable using_ssl claim)",
           tag.c_str(), checked, agree, noclaim);
    }

    // ======================================================================
    // SCENARIO B -- configuration disagreeing with the connection: turn use_ssl
    // OFF while an encrypted connection is still warm in the pool.
    // ======================================================================
    freshServer(1);
    std::string pid1;
    std::string err1 = probe(pid1);
    ok(err1.empty() && !pid1.empty(),
       "B: query 1 served over a use_ssl=1 backend (pid '%s')%s%s",
       pid1.empty() ? "-" : pid1.c_str(), err1.empty() ? "" : " -- ", err1.c_str());

    const std::string ssl1 = backendSsl(pid1);
    ok(ssl1 == "t" || ssl1 == "true",
       "B: that backend connection is genuinely TLS-encrypted (pg_stat_ssl.ssl='%s')",
       ssl1.empty() ? "not found" : ssl1.c_str());

    // ---- step 2: turn use_ssl OFF, WITHOUT draining the pool ---------------
    {
        std::stringstream u;
        u << "UPDATE pgsql_servers SET use_ssl=0 WHERE hostgroup_id=" << HG
          << " AND hostname='" << cl.pgsql_server_host << "' AND port=" << cl.pgsql_server_port;
        execAdmin(admin, u.str());
        execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");

        // Wait for the new setting to actually be visible in the runtime table,
        // rather than sleeping a fixed span and hoping. Note this deliberately
        // does NOT drain the pool -- the whole point of the scenario is that the
        // already-established TLS connection stays warm across the change.
        int seen = -1;
        if (!waitUntil([&]{ seen = runtimeUseSslFor(cl.pgsql_server_host, cl.pgsql_server_port);
                            return seen == 0; })) {
            if (seen < 0) diag("could not read runtime_pgsql_servers.use_ssl for %s:%d "
                               "(admin query failed)", cl.pgsql_server_host, cl.pgsql_server_port);
            else diag("server %s:%d still advertises use_ssl=%d after LOAD; query 2 may not be "
                      "exercising the config-disagrees-with-connection case",
                      cl.pgsql_server_host, cl.pgsql_server_port, seen);
        }
        // Whether the warm connection survived is what makes the next probe
        // meaningful, so report it instead of assuming it.
        diag("after use_ssl=0 landed, hostgroup %d holds %d pooled connection(s)", HG, poolCountHG());
    }

    // ---- step 3: the warm TLS connection must still serve -------------------
    std::string pid2;
    std::string err2 = probe(pid2);
    ok(err2.empty() && !pid2.empty(),
       "B: query 2 served after use_ssl was turned off with a warm TLS connection (pid '%s')%s%s",
       pid2.empty() ? "-" : pid2.c_str(), err2.empty() ? "" : " -- ", err2.c_str());

    // Diagnostic, not an assertion: whether the warm TLS connection was actually
    // reused is ProxySQL's pooling decision, not this test's contract. What the
    // test requires is that the query is SERVED either way. Reporting it keeps a
    // "passed because a fresh plaintext connection was opened" result visible
    // rather than silently counted as coverage.
    if (!pid2.empty()) {
        const std::string ssl2 = backendSsl(pid2);
        diag("query 2: pid '%s' (%s), pg_stat_ssl.ssl='%s'", pid2.c_str(),
             (pid1 == pid2) ? "SAME connection reused" : "new connection",
             ssl2.empty() ? "not found" : ssl2.c_str());
    }

    // ======================================================================
    // SCENARIO D -- churn. Scenarios A and B each hand a connection over once.
    // A lifetime bug that survives the first handoff and trips on a later one --
    // or that corrupts one connection out of several in the pool -- passes both.
    //
    // Here CHURN_CLIENTS sessions are held open at once and queried round-robin
    // for CHURN_ROUNDS rounds, so every pooled TLS connection is detached and
    // re-attached repeatedly and the pool holds several of them at a time. Under
    // ASAN this is the shape that turns a stale SSL pointer into a reported
    // use-after-free rather than a silent success.
    // ======================================================================
    freshServer(1);
    {
        std::vector<PGConnPtr> clients;
        int connected = 0;
        std::string connect_err;
        for (int i = 0; i < CHURN_CLIENTS; i++) {
            PGConnPtr c = openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username,
                                   cl.pgsql_password, cl.pgsql_username, "require");
            if (c && PQstatus(c.get()) == CONNECTION_OK) connected++;
            else if (connect_err.empty())
                connect_err = oneline(c ? PQerrorMessage(c.get()) : "null connection");
            clients.push_back(std::move(c));
        }

        int served = 0, failed = 0;
        std::set<std::string> pids;
        std::string first_err;
        for (int r = 0; r < CHURN_ROUNDS; r++) {
            // Fire every query BEFORE collecting any of them, so they are in
            // flight simultaneously. Issuing them synchronously would put only
            // one query in flight at a time, and ProxySQL would multiplex all of
            // them onto a SINGLE pooled connection -- measured: 32 queries, one
            // backend pid. That still exercises repeated handoff, but never
            // builds a pool holding several TLS connections at once, which is
            // the state this scenario exists to cover.
            std::vector<bool> sent(clients.size(), false);
            for (size_t i = 0; i < clients.size(); i++) {
                PGConnPtr& c = clients[i];
                if (!c || PQstatus(c.get()) != CONNECTION_OK) continue;
                sent[i] = (PQsendQuery(c.get(), PID_QUERY) == 1);
            }
            for (size_t i = 0; i < clients.size(); i++) {
                PGConnPtr& c = clients[i];
                if (!c || PQstatus(c.get()) != CONNECTION_OK || !sent[i]) {
                    failed++;
                    if (first_err.empty() && c) first_err = oneline(PQerrorMessage(c.get()));
                    continue;
                }
                // PQgetResult must be drained to NULL before the connection can
                // be used again.
                bool got = false;
                while (PGresult* res = PQgetResult(c.get())) {
                    if (!got && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
                        pids.insert(PQgetvalue(res, 0, 0));
                        got = true;
                    }
                    PQclear(res);
                }
                if (got) served++;
                else {
                    failed++;
                    if (first_err.empty()) first_err = oneline(PQerrorMessage(c.get()));
                }
            }
        }
        const int total = CHURN_CLIENTS * CHURN_ROUNDS;

        ok(connected == CHURN_CLIENTS,
           "D: all %d concurrent client sessions connected over TLS (%d ok)%s%s",
           CHURN_CLIENTS, connected, connect_err.empty() ? "" : " -- ", connect_err.c_str());

        ok(served == total,
           "D: all %d queries across %d interleaved sessions were served (%d ok, %d failed)%s%s",
           total, CHURN_CLIENTS, served, failed, first_err.empty() ? "" : " -- ",
           first_err.c_str());

        // Reuse actually happened. If every query got its own backend connection
        // there was no handoff to break, and the scenario would pass while
        // testing nothing. At most CHURN_CLIENTS sessions are ever in flight, so
        // more distinct pids than that means connections were destroyed and
        // recreated rather than pooled.
        std::string pidlist;
        for (const std::string& p : pids) { if (!pidlist.empty()) pidlist += ","; pidlist += p; }
        ok(!pids.empty() && (int)pids.size() <= CHURN_CLIENTS,
           "D: %d queries were served by only %d distinct backend connection(s) [%s] "
           "-- pooled reuse, not one connection per query",
           total, (int)pids.size(), pidlist.empty() ? "-" : pidlist.c_str());

        // Every connection that carried this traffic must STILL be encrypted --
        // not merely the last one sampled, which is all a single-handoff scenario
        // can show.
        int found = 0, encrypted = 0;
        for (const std::string& p : pids) {
            const std::string s = backendSsl(p);
            if (s.empty()) continue;
            found++;
            if (s == "t" || s == "true") encrypted++;
        }
        // BOTH guards are required, and each closes a hole the other leaves.
        // `found == pids.size()` stops a pid missing from pg_stat_ssl from
        // shrinking the DENOMINATOR: judging "encrypted == found" alone lets
        // three of four connections disappear and still reports success as
        // "1 of 1 encrypted". `!pids.empty()` stops the whole thing passing
        // VACUOUSLY at 0 == 0 when no connection was ever established -- measured:
        // with the backend user misconfigured, every query failed and this
        // assertion still reported "0 of 0 connections found, 0 encrypted" as a
        // pass, which is the one outcome a TLS check must never call success.
        ok(!pids.empty() && found == (int)pids.size() && encrypted == found,
           "D: every backend connection used during churn is still TLS-encrypted "
           "(%d of %d connections found in pg_stat_ssl, %d encrypted)",
           found, (int)pids.size(), encrypted);
    }

    {
        PGConnPtr a2 = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port,
                                cl.admin_username, cl.admin_password, nullptr, "disable");
        ok(a2 && PQstatus(a2.get()) == CONNECTION_OK && scalar(a2.get(), "SELECT 1") == "1",
           "ProxySQL still alive afterwards");
    }

    return exit_status();
}
