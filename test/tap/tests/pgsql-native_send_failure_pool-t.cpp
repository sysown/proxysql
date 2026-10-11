/**
 * @file pgsql-native_send_failure_pool-t.cpp
 * @brief A pooled native backend connection whose send() fails must be destroyed
 *        and the query retried, not handed back to the pool (issue #6409).
 *
 * A connection sitting in the free pool is polled by nobody, so when its peer goes
 * away ProxySQL only finds out when the next client's query is written to it. With
 * the native backend protocol that write failed with ECONNRESET / EPIPE, the error
 * was recorded, and nothing else happened: the connection still looked live and
 * reusable, so the client got 08006 "send(Query) failed" with no retry and the dead
 * connection went straight back to the pool for the next client to fail on.
 *
 *   Phase 1 -- RST while pooled. A scriptable mock backend serves one query, waits
 *   for the connection to be parked in the free pool, and aborts it (SO_LINGER
 *   {1,0}). The next query is written to a socket that already received the RST,
 *   so the very first send() fails. The hostgroup allows one connection, so every
 *   later query depends on the dead one having been destroyed rather than pooled.
 *
 *   Phase 2 -- FIN while pooled, then a large simple Query. A real PostgreSQL
 *   backend is killed with pg_terminate_backend() while pooled. An 8 MiB Query is
 *   larger than the socket send buffer: the first send() is partial, the backend
 *   answers the data with an RST, and a later send() fails. (A small query would
 *   go out whole and the death would be found on the read side, which already
 *   worked.)
 *
 *   Phase 3 -- the same on the extended-query path: a prepared statement executed
 *   with an 8 MiB parameter. The statement is already prepared on the pooled backend
 *   connection, so the Bind carrying the parameter is the first thing written.
 *
 * Phases 2 and 3 raise pgsql-threshold_query_length so a large query does not get
 * its connection destroyed on the way back to the pool for an unrelated reason.
 *
 * NOTE: phase 1 disables pgsql-monitor_enabled, because monitor probes would
 * connect to the mock and consume script steps, and puts the saved value back when
 * it is done: the monitor scheduler thread stays alive while disabled and resumes
 * its checks once the variable is loaded as true again. Phase 1 also raises pgsql-free_connections_pct to 100: with
 * max_connections=1 the default 10% allows no free connection at all, and the pool
 * maintenance would drop the parked connection before the query could draw it.
 */
#include <chrono>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_native_tier.h"
#include "pgsql_mock_backend.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int   MOCK_HG   = 49;
static const char* MOCK_USER = "sendfailpool";
static const char* MOCK_PASS = "sendfailpool";
static const size_t BIG_LEN  = 8 * 1024 * 1024;

static void silenceNotices(void*, const char*) {}

static PGConnPtr openConn(const char* h, int p, const char* u, const char* pw, const char* db) {
    std::stringstream ss;
    ss << "host=" << h << " port=" << p << " user=" << u << " password=" << pw;
    if (db && *db) ss << " dbname=" << db;
    ss << " sslmode=disable connect_timeout=10";
    PGConnPtr c(PQconnectdb(ss.str().c_str()), &PQfinish);
    if (c) PQsetNoticeProcessor(c.get(), &silenceNotices, nullptr);
    return c;
}

static PGConnPtr openClient()     { return openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, cl.pgsql_username); }
static PGConnPtr openMockClient() { return openConn(cl.pgsql_host, cl.pgsql_port, MOCK_USER, MOCK_PASS, MOCK_USER); }
static PGConnPtr openAdmin()      { return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, ""); }
static PGConnPtr openBackend()    { return openConn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username, cl.pgsql_server_password, cl.pgsql_username); }

static bool connected(const PGConnPtr& c) { return c && PQstatus(c.get()) == CONNECTION_OK; }

static std::string sqlQuote(const char* s) {
    std::string out = "'";
    for (const char* p = s; p && *p; p++) { if (*p == '\'') out += '\''; out += *p; }
    return out + "'";
}

static bool execOk(PGconn* c, const std::string& q) {
    PGresult* r = PQexec(c, q.c_str());
    const ExecStatusType st = PQresultStatus(r);
    PQclear(r);
    return st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK;
}

static std::string trimmed(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

// First column of the first row, or "" on failure; the error, if any, goes to `err`.
static std::string takeScalar(PGresult* r, std::string* err) {
    std::string out;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
        out = PQgetvalue(r, 0, 0);
    else if (err)
        *err = trimmed(PQresultErrorMessage(r));
    PQclear(r);
    return out;
}

static std::string scalar(PGconn* c, const std::string& q, std::string* err = nullptr) {
    return takeScalar(PQexec(c, q.c_str()), err);
}

static bool setVar(PGconn* admin, const char* name, const char* value) {
    return execOk(admin, std::string("SET ") + name + "='" + value + "'")
        && execOk(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

static int poolStat(PGconn* admin, int hg, const char* expr) {
    const std::string n = scalar(admin, std::string("SELECT COALESCE(SUM(") + expr +
        "),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(hg));
    return n.empty() ? -1 : atoi(n.c_str());
}

static int poolFreeWithin(PGconn* admin, int hg, int want, int seconds) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    int last = -1;
    while (true) {
        last = poolStat(admin, hg, "ConnFree");
        if (last == want || std::chrono::steady_clock::now() >= deadline) return last;
        usleep(100000);
    }
}

// Empty a hostgroup's pool: OFFLINE_HARD and back. Deleting and re-inserting the
// same rows leaves pooled connections in place.
static bool flushPool(PGconn* admin, int hg) {
    const std::string h = std::to_string(hg);
    std::string prev = scalar(admin, "SELECT status FROM pgsql_servers WHERE hostgroup_id=" + h + " LIMIT 1");
    if (prev.empty()) prev = "ONLINE";
    if (!execOk(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + h)
        || !execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (poolStat(admin, hg, "ConnUsed+ConnFree") != 0 && std::chrono::steady_clock::now() < deadline)
        usleep(100000);
    const bool emptied = poolStat(admin, hg, "ConnUsed+ConnFree") == 0;
    if (!execOk(admin, "UPDATE pgsql_servers SET status='" + prev + "' WHERE hostgroup_id=" + h)
        || !execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    usleep(200000);
    return emptied;
}

// Kill every backend session of the proxied role, over a direct connection as a
// different role, and wait for them to be gone. Returns how many were killed.
static int killProxiedBackends(PGconn* backend, int* left) {
    const std::string n = scalar(backend,
        "SELECT count(*) FROM (SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
        " WHERE usename = " + sqlQuote(cl.pgsql_username) + ") x");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    int alive = -1;
    while (true) {
        const std::string a = scalar(backend,
            "SELECT count(*) FROM pg_stat_activity WHERE usename = " + sqlQuote(cl.pgsql_username));
        alive = a.empty() ? -1 : atoi(a.c_str());
        if (alive == 0 || std::chrono::steady_clock::now() >= deadline) break;
        usleep(100000);
    }
    if (left) *left = alive;
    return n.empty() ? -1 : atoi(n.c_str());
}

// ------------------------------------------------------------------ phase 1

static void phase1_rst_while_pooled(PGconn* admin) {
    std::string monitor_enabled = scalar(admin,
        "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-monitor_enabled'");
    if (monitor_enabled.empty()) monitor_enabled = "true";
    if (!setVar(admin, "pgsql-monitor_enabled", "false"))
        BAIL_OUT("cannot disable the monitor for the mock phase");
    std::string free_pct = scalar(admin,
        "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-free_connections_pct'");
    if (free_pct.empty()) free_pct = "10";
    if (!setVar(admin, "pgsql-free_connections_pct", "100"))
        BAIL_OUT("cannot raise pgsql-free_connections_pct for the mock phase");

    PgSQL_Mock_Backend mock;
    if (!mock.start()) BAIL_OUT("mock backend failed to listen");
    const std::string myip = pgmb_local_ip_towards(cl.pgsql_host, cl.pgsql_port);
    if (myip.empty()) BAIL_OUT("could not discover this container's IP toward ProxySQL");
    diag("mock backend listening on %s:%u (hostgroup %d)", myip.c_str(), mock.port(), MOCK_HG);

    const std::string hg = std::to_string(MOCK_HG);
    // max_connections=1: once the dead connection is in the pool, every later query
    // either gets it or waits for it. Nothing else can hide a dead pooled connection.
    const bool registered =
        execOk(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + hg)
        && execOk(admin,
            "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) VALUES ("
            + hg + ",'" + myip + "'," + std::to_string(mock.port()) + ",1,0,'send failure mock')")
        && execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")
        && execOk(admin,
            "INSERT OR REPLACE INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('"
            + std::string(MOCK_USER) + "','" + MOCK_PASS + "',1," + hg + ")")
        && execOk(admin, "LOAD PGSQL USERS TO RUNTIME");
    if (!registered) BAIL_OUT("could not register the mock backend and its user");
    flushPool(admin, MOCK_HG);

    // First connection: serve one query, give ProxySQL time to park the connection in
    // the free pool, then abort it.
    const int park_ms = 1500;
    std::vector<Step> first = pgmb_script_accept_trust();
    first.push_back(step_expect_query());
    first.push_back(step_send(pgmb_simple_result("c", "1", 1)));
    first.push_back(step_sleep(park_ms));
    first.push_back(step_reset());
    mock.set_script(first);
    mock.reset_stats();

    std::string err;
    std::string got;
    {
        auto c = openMockClient();
        if (connected(c)) got = scalar(c.get(), "SELECT 1", &err);
        else if (c) err = trimmed(PQerrorMessage(c.get()));
    }
    // Every later connection serves queries for as long as the test needs.
    std::vector<Step> rest = pgmb_script_accept_trust();
    for (int i = 0; i < 16; i++) {
        rest.push_back(step_expect_query());
        rest.push_back(step_send(pgmb_simple_result("c", "1", 1)));
    }
    mock.set_script(rest);

    const int parked = poolFreeWithin(admin, MOCK_HG, 1, 1);
    ok(got == "1" && parked == 1,
       "phase 1: the first query was served and its connection parked in the free pool (got '%s', ConnFree=%d)%s%s",
       got.c_str(), parked, err.empty() ? "" : ", error: ", err.c_str());

    // Let the RST land, well after the park window. Nothing polls the free pool, so the
    // dead connection is still there: the next query is written to it, which is the
    // send failure under test, rather than to a connection opened after a cleanup.
    usleep((park_ms + 1000) * 1000);
    const int still_parked = poolStat(admin, MOCK_HG, "ConnFree");
    ok(still_parked == 1 && mock.connections_accepted() == 1,
       "phase 1: after the RST the dead connection is still the only one, waiting in the free pool (ConnFree=%d, connections=%d)",
       still_parked, mock.connections_accepted());

    // The next client draws the dead connection; its first send() fails.
    int succeeded = 0;
    std::string first_err;
    {
        auto c = openMockClient();
        if (!connected(c)) BAIL_OUT("mock client connection failed: %s", c ? PQerrorMessage(c.get()) : "null");
        err.clear();
        got = scalar(c.get(), "SELECT 1", &err);
        first_err = err;
        ok(got == "1",
           "phase 1: the query that drew the reset connection was retried and succeeded (got '%s')%s%s",
           got.c_str(), first_err.empty() ? "" : ", error: ", first_err.c_str());
        for (int i = 0; i < 5; i++) {
            err.clear();
            if (scalar(c.get(), "SELECT 1", &err) == "1") succeeded++;
            else diag("phase 1: follow-up query %d failed: %s", i + 1, err.c_str());
        }
    }
    {
        // A fresh session too: the dead connection must not be waiting for it either.
        auto c = openMockClient();
        err.clear();
        if (connected(c) && scalar(c.get(), "SELECT 1", &err) == "1") succeeded++;
        else diag("phase 1: query from a new session failed: %s", err.c_str());
    }
    ok(succeeded == 6, "phase 1: every later query succeeds, from the same session and from a new one (%d/6)", succeeded);
    const int conns = mock.connections_accepted();
    ok(conns == 2,
       "phase 1: exactly one replacement connection was opened -- the reset one was destroyed, not pooled (connections=%d, expected 2)",
       conns);

    execOk(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + hg);
    execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME");
    execOk(admin, std::string("DELETE FROM pgsql_users WHERE username='") + MOCK_USER + "'");
    execOk(admin, "LOAD PGSQL USERS TO RUNTIME");
    setVar(admin, "pgsql-free_connections_pct", free_pct.c_str());
    // Later tests sharing this ProxySQL rely on PgSQL monitoring.
    if (!setVar(admin, "pgsql-monitor_enabled", monitor_enabled.c_str()))
        diag("phase 1: could not restore pgsql-monitor_enabled='%s'", monitor_enabled.c_str());
    mock.stop();
}

// ------------------------------------------------------------- phases 2 and 3

// Leave exactly one native connection in hostgroup 0's free pool, run `warmup` on it
// first, then kill its backend. Returns whether all of that happened.
static bool poolOneThenKill(PGconn* admin, PGconn* backend, const char* label,
                            bool (*warmup)(PGconn*)) {
    int left = -1;
    killProxiedBackends(backend, &left);
    if (!flushPool(admin, 0)) { diag("%s: could not empty hostgroup 0", label); return false; }
    bool warmed = false;
    {
        auto c = openClient();
        if (connected(c)) warmed = warmup(c.get());
    }
    const int parked = poolFreeWithin(admin, 0, 1, 10);
    const int killed = killProxiedBackends(backend, &left);
    diag("%s: warmed=%s, pooled=%d, killed=%d, left alive=%d", label, warmed ? "yes" : "no", parked, killed, left);
    return warmed && parked == 1 && killed == 1 && left == 0;
}

static bool warmSimple(PGconn* c) { return scalar(c, "SELECT 'send_failure_victim'") == "send_failure_victim"; }

static const char* STMT_NAME = "send_failure_len";
static const char* STMT_SQL  = "SELECT length($1::text)";

static bool prepareStmt(PGconn* c) {
    PGresult* r = PQprepare(c, STMT_NAME, STMT_SQL, 1, nullptr);
    const bool ok_ = PQresultStatus(r) == PGRES_COMMAND_OK;
    PQclear(r);
    return ok_;
}

static std::string execStmt(PGconn* c, const std::string& param, std::string* err) {
    const char* values[1] = { param.c_str() };
    return takeScalar(PQexecPrepared(c, STMT_NAME, 1, values, nullptr, nullptr, 0), err);
}

// Prepares and executes the statement, so the pooled backend connection holds it and
// the next execution starts with the Bind.
static bool warmPrepared(PGconn* c) {
    std::string err;
    return prepareStmt(c) && execStmt(c, "abc", &err) == "3";
}

int main(int, char**) {
    plan(13);
    if (cl.getEnv()) return exit_status();

    auto admin = openAdmin();
    ok(connected(admin), "ADMIN connection created");
    if (!connected(admin)) return exit_status();
    if (!pgsql_native_supported(admin.get())) {
        skip(12, "native backend protocol is unavailable in this tier");
        return exit_status();
    }
    if (!setVar(admin.get(), "pgsql-use_native_backend_protocol", "true"))
        BAIL_OUT("cannot enable the native backend protocol");

    phase1_rst_while_pooled(admin.get());   // 5

    auto backend = openBackend();
    ok(connected(backend), "direct backend connection created (kills sessions without going through the proxy)");
    if (!connected(backend)) return exit_status();
    if (!setVar(admin.get(), "pgsql-threshold_query_length", std::to_string(64 * 1024 * 1024).c_str()))
        BAIL_OUT("cannot raise pgsql-threshold_query_length");

    const std::string big(BIG_LEN, 'x');
    const std::string want = std::to_string(BIG_LEN);

    // ---- phase 2: FIN while pooled, then an 8 MiB simple Query ----
    const bool p2_ready = poolOneThenKill(admin.get(), backend.get(), "phase 2", warmSimple);
    ok(p2_ready, "phase 2: one native connection pooled and its backend terminated");
    {
        auto c = openClient();
        std::string err, got, after;
        if (connected(c)) {
            got = scalar(c.get(), "SELECT length('" + big + "')", &err);
            std::string err2;
            after = scalar(c.get(), "SELECT 42", &err2);
            if (err.empty()) err = err2;
        }
        ok(got == want, "phase 2: the 8 MiB query that drew the dead connection was retried (got '%s', want %s)%s%s",
           got.c_str(), want.c_str(), err.empty() ? "" : ", error: ", err.c_str());
        ok(after == "42", "phase 2: the next query succeeds too (got '%s')", after.c_str());
    }

    // ---- phase 3: same, extended query with an 8 MiB parameter ----
    const bool p3_ready = poolOneThenKill(admin.get(), backend.get(), "phase 3", warmPrepared);
    ok(p3_ready, "phase 3: one native connection holding the prepared statement pooled and its backend terminated");
    {
        auto c = openClient();
        std::string err, got, after;
        if (connected(c) && prepareStmt(c.get())) {
            got = execStmt(c.get(), big, &err);
            std::string err2;
            after = scalar(c.get(), "SELECT 42", &err2);
            if (err.empty()) err = err2;
        } else if (c) {
            err = trimmed(PQerrorMessage(c.get()));
        }
        ok(got == want, "phase 3: the 8 MiB extended-query execution that drew the dead connection was retried (got '%s', want %s)%s%s",
           got.c_str(), want.c_str(), err.empty() ? "" : ", error: ", err.c_str());
        ok(after == "42", "phase 3: the next query succeeds too (got '%s')", after.c_str());
    }

    int left = -1;
    killProxiedBackends(backend.get(), &left);
    flushPool(admin.get(), 0);
    return exit_status();
}
