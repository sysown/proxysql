/**
 * @file pgsql-native_concurrency-t.cpp
 * @brief Concurrent sessions competing for a small pool, plus abrupt client and
 *        backend disappearance.
 *
 * WHY THIS EXISTS
 * ---------------
 * Everything else written for the native backend protocol drives ONE session at
 * a time. That leaves the pool itself untested: connections being handed between
 * sessions, reset between users, returned mid-transaction, and reclaimed while
 * another session is waiting for one.
 *
 * That gap matters because of finding F2
 * (docs/superpowers/specs/2026-08-03-pgsql-native-protocol-findings.md): ProxySQL
 * aborted at PgSQL_Connection.cpp:1075 — the "not implemented yet" default arm of
 * the connection state machine — reached through
 * CONNECTING_SERVER -> get_connection(), i.e. while picking a POOLED connection
 * for a new query. It was seen twice and could not be reproduced from any single
 * sequential case, which points at concurrent sessions sharing the pool. This
 * test is the deliberate attempt to reproduce it.
 *
 * It also covers the mirror image of finding F1. F1 is the BACKEND vanishing
 * mid-result, which crashes the proxy. Nothing has ever tested the CLIENT
 * vanishing while the backend is still streaming.
 *
 * WHAT IS ASSERTED
 * ----------------
 * Robustness is necessary but not sufficient here, so correctness is checked
 * too. Every worker thread stamps a value unique to itself, reads it back on the
 * same connection, and fails if it sees anyone else's. A pool that hands a
 * connection to the wrong session, or replays state across sessions, shows up as
 * a token mismatch rather than as a vague "something broke".
 *
 *   1. no crash, and the admin interface still answers at the end
 *   2. every worker sees its OWN data, never another worker's
 *   3. queries either succeed or fail cleanly (no truncated/garbled results)
 *   4. the pool returns to a sane size afterwards (no stranded connections)
 *   5. the proxy still serves normal traffic when it is all over
 *
 * PHASES
 * ------
 *   P1 concurrent simple queries with per-thread token verification
 *   P2 concurrent transactions (BEGIN/INSERT/COMMIT and BEGIN/INSERT/ROLLBACK)
 *   P3 sessions abandoned mid-transaction (disconnect without COMMIT/ROLLBACK)
 *   P4 concurrent session-variable churn, which forces RESETTING_CONNECTION and
 *      is the path finding F6 concerns
 *   P5 clients that disappear mid-result (the F1 mirror)
 *   P6 the backend taken OFFLINE_HARD while queries are in flight
 *
 * The pool is deliberately smaller than the worker count so that sessions must
 * queue for and reuse each other's connections; with a pool large enough for
 * everyone, none of the interesting paths are taken.
 *
 * EXPECTATION
 * -----------
 * Exploratory. If F2 reproduces here it will show as the proxy dying partway
 * through, and the phase that was running localises it.
 *
 * INFRA: legacy-g1. Runtime state restored in memory only — never SAVE ... TO DISK.
 */
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int BACKEND_HG   = 0;
static const int POOL_SIZE    = 4;     // deliberately smaller than WORKERS
static const int WORKERS      = 16;
static const int ITERATIONS   = 25;
static const char* CTAB       = "native_concurrency_tab";

// ------------------------------------------------------------------ helpers

static PGConnPtr openConn(const char* host, int port, const char* user,
                          const char* pass, const char* db) {
    std::stringstream ss;
    ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
    if (db && *db) ss << " dbname=" << db;
    ss << " sslmode=disable connect_timeout=10";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}
static PGConnPtr createAdminConn() {
    return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port,
                    cl.admin_username, cl.admin_password, nullptr);
}
static PGConnPtr createClientConn() {
    return openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username,
                    cl.pgsql_password, cl.pgsql_username);
}
static PGConnPtr createBackendConn() {
    // Must be the SAME database the workers reach through ProxySQL
    // (createClientConn uses dbname=cl.pgsql_username): the fixture table is
    // created on this connection, and a table in `postgres` is invisible to them.
    return openConn(cl.pgsql_server_host, cl.pgsql_server_port,
                    cl.pgsql_root_username, cl.pgsql_root_password, cl.pgsql_username);
}
static bool execAdmin(PGconn* a, const std::string& q) {
    PGresult* r = PQexec(a, q.c_str());
    ExecStatusType st = PQresultStatus(r);
    bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(a));
    PQclear(r);
    return good;
}
static std::string adminScalar(PGconn* a, const std::string& q) {
    PGresult* r = PQexec(a, q.c_str());
    std::string v;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
        v = PQgetvalue(r, 0, 0);
    PQclear(r);
    return v;
}
static std::string scalar(PGconn* c, const std::string& q) {
    PGresult* r = PQexec(c, q.c_str());
    std::string v;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
        v = PQgetvalue(r, 0, 0);
    PQclear(r);
    return v;
}
static bool setNativeMode(PGconn* a, bool on) {
    return execAdmin(a, std::string("SET pgsql-use_native_backend_protocol='") +
                        (on ? "true" : "false") + "'") &&
           execAdmin(a, "LOAD PGSQL VARIABLES TO RUNTIME");
}
static int poolConns(PGconn* a) {
    std::stringstream q;
    q << "SELECT IFNULL(SUM(ConnUsed + ConnFree),0) FROM stats_pgsql_connection_pool "
      << "WHERE hostgroup=" << BACKEND_HG;
    const std::string v = adminScalar(a, q.str());
    return v.empty() ? 0 : atoi(v.c_str());
}
static bool proxyAlive() {
    auto a = createAdminConn();
    return a && PQstatus(a.get()) == CONNECTION_OK && adminScalar(a.get(), "SELECT 1") == "1";
}

// Shared failure accounting across worker threads.
struct Tally {
    std::atomic<int> ok{0};
    std::atomic<int> conn_fail{0};
    std::atomic<int> query_fail{0};
    std::atomic<int> wrong_data{0};   // the serious one: someone else's value
    std::mutex mtx;
    std::string first_wrong;
    void wrong(const std::string& what) {
        wrong_data.fetch_add(1);
        std::lock_guard<std::mutex> g(mtx);
        if (first_wrong.empty()) first_wrong = what;
    }
};

// ------------------------------------------------------------------ phases

// P1: each worker writes a token only it uses, then reads it back.
static void worker_tokens(int id, Tally& t) {
    for (int i = 0; i < ITERATIONS; i++) {
        auto c = createClientConn();
        if (!c || PQstatus(c.get()) != CONNECTION_OK) { t.conn_fail.fetch_add(1); continue; }
        std::stringstream tok;
        tok << "w" << id << "_i" << i;
        const std::string q = "SELECT '" + tok.str() + "'::text";
        const std::string got = scalar(c.get(), q);
        if (got.empty()) { t.query_fail.fetch_add(1); continue; }
        if (got != tok.str()) { t.wrong("expected " + tok.str() + " got " + got); continue; }
        t.ok.fetch_add(1);
    }
}

// P2: transactions that commit or roll back, each row tagged by worker.
static void worker_txn(int id, Tally& t) {
    for (int i = 0; i < ITERATIONS; i++) {
        auto c = createClientConn();
        if (!c || PQstatus(c.get()) != CONNECTION_OK) { t.conn_fail.fetch_add(1); continue; }
        const bool commit = (i % 2) == 0;
        const int key = id * 100000 + i;
        std::stringstream ins;
        ins << "INSERT INTO " << CTAB << " (id, owner) VALUES (" << key << ", " << id << ")";
        PGresult* r = PQexec(c.get(), "BEGIN");
        bool good = (PQresultStatus(r) == PGRES_COMMAND_OK);
        PQclear(r);
        if (!good) { t.query_fail.fetch_add(1); continue; }
        r = PQexec(c.get(), ins.str().c_str());
        good = (PQresultStatus(r) == PGRES_COMMAND_OK);
        PQclear(r);
        if (!good) { t.query_fail.fetch_add(1); PQclear(PQexec(c.get(), "ROLLBACK")); continue; }
        // Inside the transaction the row must be visible to US and tagged with
        // OUR id; anything else means the session landed on foreign state.
        std::stringstream sel;
        sel << "SELECT owner FROM " << CTAB << " WHERE id=" << key;
        const std::string owner = scalar(c.get(), sel.str());
        if (owner != std::to_string(id)) {
            t.wrong("txn row owner expected " + std::to_string(id) + " got '" + owner + "'");
        }
        PQclear(PQexec(c.get(), commit ? "COMMIT" : "ROLLBACK"));
        t.ok.fetch_add(1);
    }
}

// P3: disconnect while a transaction is still open, without COMMIT or ROLLBACK.
static void worker_abandon_txn(int id, Tally& t) {
    for (int i = 0; i < ITERATIONS; i++) {
        auto c = createClientConn();
        if (!c || PQstatus(c.get()) != CONNECTION_OK) { t.conn_fail.fetch_add(1); continue; }
        PQclear(PQexec(c.get(), "BEGIN"));
        std::stringstream ins;
        ins << "INSERT INTO " << CTAB << " (id, owner) VALUES ("
            << (500000 + id * 1000 + i) << ", " << id << ")";
        {
            // F2 needs a LIVE transaction abandoned, not an already-aborted one.
            // Without this check a failing INSERT still counted as ok and the
            // phase silently tested nothing.
            PGresult* r = PQexec(c.get(), ins.str().c_str());
            const bool inserted = (PQresultStatus(r) == PGRES_COMMAND_OK);
            PQclear(r);
            if (!inserted) { t.query_fail.fetch_add(1); continue; }
        }
        t.ok.fetch_add(1);
        // fall out of scope -> PQfinish mid-transaction
    }
}

// P4: session-variable churn. Different clients ask for different values, which
// is what drives requires_RESETTING_CONNECTION() and the reset path of F6.
static void worker_vars(int id, Tally& t) {
    static const char* vals[] = { "hex", "escape" };
    for (int i = 0; i < ITERATIONS; i++) {
        auto c = createClientConn();
        if (!c || PQstatus(c.get()) != CONNECTION_OK) { t.conn_fail.fetch_add(1); continue; }
        const char* want = vals[(id + i) % 2];
        std::stringstream st;
        st << "SET bytea_output = '" << want << "'";
        PGresult* r = PQexec(c.get(), st.str().c_str());
        const bool good = (PQresultStatus(r) == PGRES_COMMAND_OK);
        PQclear(r);
        if (!good) { t.query_fail.fetch_add(1); continue; }
        const std::string got = scalar(c.get(), "SELECT current_setting('bytea_output')");
        if (got != want) {
            t.wrong(std::string("bytea_output expected ") + want + " got '" + got + "'");
            continue;
        }
        t.ok.fetch_add(1);
    }
}

// P5: start a large result, then vanish without reading it (the F1 mirror).
static void worker_abort_midresult(int id, Tally& t) {
    for (int i = 0; i < ITERATIONS; i++) {
        auto c = createClientConn();
        if (!c || PQstatus(c.get()) != CONNECTION_OK) { t.conn_fail.fetch_add(1); continue; }
        // Ask for a big result and deliberately do NOT drain it.
        if (PQsendQuery(c.get(),
                "SELECT g, repeat('x', 500) FROM generate_series(1,20000) g") == 0) {
            t.query_fail.fetch_add(1);
            continue;
        }
        PQconsumeInput(c.get());       // pull a little, then abandon
        usleep(1000 * ((id % 5) + 1)); // stagger the abort point across workers
        t.ok.fetch_add(1);
        // PQfinish() mid-stream via scope exit
    }
}

static void runPhase(const char* label, void (*fn)(int, Tally&), Tally& t) {
    std::vector<std::thread> th;
    th.reserve(WORKERS);
    for (int i = 0; i < WORKERS; i++) th.emplace_back(fn, i, std::ref(t));
    for (auto& x : th) x.join();
    diag("%s: ok=%d conn_fail=%d query_fail=%d wrong_data=%d",
         label, t.ok.load(), t.conn_fail.load(), t.query_fail.load(), t.wrong_data.load());
}

int main(int, char**) {
    // 5 phases x 2 assertions (no wrong data / proxy alive) + backend-removal
    // phase + final pool + final traffic = 13
    plan(13);

    if (cl.getEnv()) return exit_status();

    auto adminOwner = createAdminConn();
    if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
        BAIL_OUT("cannot proceed without an admin connection");
    PGconn* admin = adminOwner.get();

    const std::string saved_native = adminScalar(admin,
        "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
    std::string saved_maxconn;
    {
        std::stringstream q;
        q << "SELECT max_connections FROM pgsql_servers WHERE hostgroup_id=" << BACKEND_HG << " LIMIT 1";
        saved_maxconn = adminScalar(admin, q.str());
    }

    auto restore = [&]() {
        if (!saved_maxconn.empty()) {
            std::stringstream u;
            u << "UPDATE pgsql_servers SET max_connections=" << saved_maxconn
              << ", status='ONLINE' WHERE hostgroup_id=" << BACKEND_HG;
            execAdmin(admin, u.str());
            execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
        }
        if (!saved_native.empty())
            setNativeMode(admin, saved_native == "true" || saved_native == "1");
    };

    // fixture
    {
        auto be = createBackendConn();
        if (!be || PQstatus(be.get()) != CONNECTION_OK) { restore(); BAIL_OUT("no direct backend connection"); }
        PQclear(PQexec(be.get(), (std::string("DROP TABLE IF EXISTS ") + CTAB).c_str()));
        PQclear(PQexec(be.get(), (std::string("CREATE TABLE ") + CTAB +
                                  " (id bigint primary key, owner int)").c_str()));
        PQclear(PQexec(be.get(), (std::string("GRANT ALL ON ") + CTAB + " TO PUBLIC").c_str()));
    }

    if (!setNativeMode(admin, true)) { restore(); BAIL_OUT("cannot enable the native backend protocol"); }

    // Squeeze the pool so sessions must share and reuse connections.
    {
        std::stringstream u;
        u << "UPDATE pgsql_servers SET max_connections=" << POOL_SIZE
          << " WHERE hostgroup_id=" << BACKEND_HG;
        if (!execAdmin(admin, u.str()) || !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) {
            restore(); BAIL_OUT("could not shrink the pool");
        }
    }
    usleep(300000);
    diag("pool pinned to %d connections, %d workers, %d iterations each",
         POOL_SIZE, WORKERS, ITERATIONS);

    struct { const char* label; void (*fn)(int, Tally&); } phases[] = {
        { "P1 concurrent simple queries",      worker_tokens },
        { "P2 concurrent transactions",        worker_txn },
        { "P3 abandoned transactions",         worker_abandon_txn },
        { "P4 session-variable churn",         worker_vars },
        { "P5 clients aborting mid-result",    worker_abort_midresult },
    };

    for (const auto& ph : phases) {
        Tally t;
        runPhase(ph.label, ph.fn, t);
        ok(t.wrong_data.load() == 0,
           "%s: no session saw another session's data (%d violations%s%s)",
           ph.label, t.wrong_data.load(),
           t.first_wrong.empty() ? "" : "; first: ",
           t.first_wrong.c_str());
        ok(proxyAlive(), "%s: ProxySQL still alive afterwards", ph.label);
        if (!proxyAlive()) {
            diag("ProxySQL died during %s -- this is where to look for F2", ph.label);
            break;
        }
    }

    // P6: take the backend away while queries are in flight.
    {
        std::atomic<bool> stop{false};
        std::atomic<int> completed{0}, failed{0};
        std::vector<std::thread> th;
        for (int i = 0; i < 4; i++) {
            th.emplace_back([&]() {
                while (!stop.load()) {
                    auto c = createClientConn();
                    if (!c || PQstatus(c.get()) != CONNECTION_OK) { failed.fetch_add(1); continue; }
                    PGresult* r = PQexec(c.get(),
                        "SELECT count(*) FROM generate_series(1,50000)");
                    if (PQresultStatus(r) == PGRES_TUPLES_OK) completed.fetch_add(1);
                    else failed.fetch_add(1);
                    PQclear(r);
                }
            });
        }
        usleep(400000);
        std::stringstream off;
        off << "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" << BACKEND_HG;
        execAdmin(admin, off.str());
        execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
        usleep(600000);
        std::stringstream on;
        on << "UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=" << BACKEND_HG;
        execAdmin(admin, on.str());
        execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
        usleep(400000);
        stop.store(true);
        for (auto& x : th) x.join();
        diag("P6 backend removal: completed=%d failed=%d", completed.load(), failed.load());
        ok(proxyAlive(), "P6: ProxySQL survived the backend being taken OFFLINE_HARD mid-query");
    }

    // Settle, then check the pool is not left holding connections it cannot use.
    usleep(2000000);
    {
        auto a2 = createAdminConn();
        const bool alive = a2 && PQstatus(a2.get()) == CONNECTION_OK;
        const int left = alive ? poolConns(a2.get()) : -1;
        ok(alive && left <= POOL_SIZE,
           "pool holds no more than its %d-connection limit afterwards (found %d)",
           POOL_SIZE, left);
    }

    // And normal traffic still works.
    {
        auto c = createClientConn();
        const bool served = c && PQstatus(c.get()) == CONNECTION_OK &&
                            scalar(c.get(), "SELECT 1") == "1";
        ok(served, "normal traffic still served after all concurrency phases");
    }

    // teardown
    {
        auto be = createBackendConn();
        if (be && PQstatus(be.get()) == CONNECTION_OK)
            PQclear(PQexec(be.get(), (std::string("DROP TABLE IF EXISTS ") + CTAB).c_str()));
    }
    restore();
    return exit_status();
}
