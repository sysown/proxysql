/**
 * @file pgsql-backend_death_query_retry-t.cpp
 * @brief A backend connection that dies while ProxySQL holds it must cost the
 *        next client a retry, not its connection -- unless a transaction was open.
 *
 * A backend session can go away while it is sitting in ProxySQL's pool: a DBA runs
 * pg_terminate_backend(), the server restarts, a firewall drops an idle socket. The
 * next client to be handed that connection has done nothing wrong and must not pay
 * for it. ProxySQL is configured for exactly this, pgsql-query_retries_on_failure
 * defaults to 1, so the statement belongs on a fresh connection.
 *
 * The one case where it must NOT be replayed is an open transaction. Re-running a
 * statement from a lost transaction on a new connection runs it as autocommit, and
 * the client's next COMMIT then lands on a connection with nothing open. Both halves
 * are asserted here: the retry happens, and it stops at the transaction boundary.
 *
 * Determinism: the backend sessions are killed over a DIRECT connection to
 * PostgreSQL, never through the proxy, so the kill cannot leave a healthy pooled
 * connection behind that the probe might be served from instead. The pool is
 * flushed first for the same reason. The killer authenticates as a different role
 * than the proxied sessions, so it cannot match itself.
 *
 * ProxySQL reaches the same retry decision from two different branches, so the
 * file has two phases:
 *
 *   Phase 1 -- the socket dies. A real PostgreSQL backend is terminated while
 *   ProxySQL holds the connection, which takes handler_minus1_ClientLibraryError.
 *
 *   Phase 2 -- the backend announces it is going away (57P01) while the connection
 *   is still usable, which takes handler_minus1_HandleErrorCodes instead. A real
 *   PostgreSQL will not produce that on demand, so phase 2 drives the scriptable
 *   mock backend and measures from the backend side: a replay is a SECOND
 *   connection carrying the same statement.
 *
 *   Phase 3 -- phase 1 again on the native backend protocol, which answers the
 *   transaction question from its own ReadyForQuery status byte rather than from
 *   libpq. Native never had the defect; this phase is here because the change made
 *   it stricter, and because nothing else asserts the path at all.
 *
 * Not covered, deliberately: with pgsql-query_digests off ProxySQL's own
 * BEGIN/COMMIT tracking records nothing, so a dead libpq connection has no source
 * able to say a transaction was open. That gap is documented rather than fixed --
 * fixing it meant changing shared code outside this defect's scope.
 *
 * NOTE: phase 2 disables pgsql-monitor_enabled, because monitor probes would
 * connect to the mock and consume script steps meant for the client's query. The
 * harness reloads variables from disk before every test, so the setting does not
 * leak -- but the monitor THREAD does not come back until ProxySQL restarts, so a
 * monitor test running later against the same container needs a fresh proxy.
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
#include "pgsql_mock_backend.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const char* VICTIM_MARKER = "backend_death_victim";
static const char* TBL = "backend_death_retry_t";

// Phase 2 gets a hostgroup and a user of its own, so the mock cannot disturb the
// servers the rest of the group depends on.
static const int   MOCK_HG   = 48;
static const char* MOCK_USER = "retryboundary";
static const char* MOCK_PASS = "retryboundary";

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

static PGConnPtr openClient()  { return openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, cl.pgsql_username); }
static PGConnPtr openAdmin()   { return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, ""); }
static PGConnPtr openBackend() { return openConn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username, cl.pgsql_server_password, cl.pgsql_username); }

// Single-quote a literal for SQL. The role name comes from the harness, so this is
// about a clear failure rather than an attack: an unescaped apostrophe would fail as
// a syntax error two helpers away from the cause.
static std::string sqlQuote(const char* s) {
    std::string out = "'";
    for (const char* p = s; p && *p; p++) { if (*p == '\'') out += '\''; out += *p; }
    return out + "'";
}

// Run a statement and report only whether it succeeded.
static bool execOk(PGconn* c, const std::string& q) {
    PGresult* r = PQexec(c, q.c_str());
    const ExecStatusType st = PQresultStatus(r);
    const bool ok = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    PQclear(r);
    return ok;
}

// First column of the first row, or "" on any failure.
static std::string scalar(PGconn* c, const std::string& q) {
    PGresult* r = PQexec(c, q.c_str());
    std::string out;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
        out = PQgetvalue(r, 0, 0);
    PQclear(r);
    return out;
}

// A query with a deadline. The failure this test guards is a client left waiting on
// a connection that will never answer, and a plain blocking query would sit there
// until the harness killed the test rather than reporting it.
static std::string scalarWithin(PGconn* c, const std::string& q, int seconds, bool* timed_out, std::string* err) {
    *timed_out = false;
    err->clear();
    if (PQsendQuery(c, q.c_str()) == 0) { *err = PQerrorMessage(c); return ""; }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    std::string out;
    while (true) {
        if (PQconsumeInput(c) == 0) { *err = PQerrorMessage(c); break; }   // connection died
        if (PQisBusy(c) == 0) {
            PGresult* r = PQgetResult(c);
            if (r == nullptr) break;
            if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
                out = PQgetvalue(r, 0, 0);
            else if (PQresultStatus(r) != PGRES_TUPLES_OK)
                *err = PQresultErrorMessage(r);
            PQclear(r);
            continue;
        }
        if (std::chrono::steady_clock::now() >= deadline) { *timed_out = true; return ""; }
        usleep(20000);
    }
    return out;
}

// ProxySQL reports its own view of the session as one JSON column. The field we
// need says whether the session is pinned to a hostgroup, which is what stops its
// transaction from being tracked -- and therefore what the retry guard relies on.
static int lockedOnHostgroup(PGconn* c) {
    const std::string j = scalar(c, "PROXYSQL INTERNAL SESSION");
    const std::string key = "\"locked_on_hostgroup\":";
    const size_t at = j.find(key);
    if (at == std::string::npos) return -99;
    return atoi(j.c_str() + at + key.size());
}

// Kill every backend session belonging to the proxied role. Runs on a direct
// connection as a different role, so it can never match itself.
static int killProxiedBackends(PGconn* backend) {
    const std::string q = "SELECT count(*) FROM (SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
                          " WHERE usename = " + sqlQuote(cl.pgsql_username) + ") x";
    const std::string n = scalar(backend, q);
    return n.empty() ? -1 : atoi(n.c_str());
}

// The pool drains asynchronously: a LOAD that drops connections, and a killed
// backend, both land some milliseconds after the statement returns. Sampling once
// reads whatever the worker threads happen not to have finished yet.
static int poolFreeWithin(PGconn* admin, int hg, int want, int seconds);

// Kill ONLY the backend serving the session that just ran `marker`. Killing every
// session of the role leaves other dead connections pooled, and the retry then lands
// on one of those and fails -- which looks exactly like the retry being refused, so
// an assertion about refusing would pass either way.
static int killBackendRunningMarker(PGconn* backend, const std::string& marker) {
    const std::string q =
        "SELECT count(*) FROM (SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
        " WHERE usename = " + sqlQuote(cl.pgsql_username) +
        " AND query LIKE '%" + marker + "%' AND query NOT LIKE '%pg_stat_activity%') x";
    const std::string n = scalar(backend, q);
    return n.empty() ? -1 : atoi(n.c_str());
}

// pg_terminate_backend() returns as soon as the signal is sent; the session leaves
// pg_stat_activity a moment later. Wait for it rather than reading once.
static int proxiedSessionsWithin(PGconn* backend, int want, int seconds) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    int last = -1;
    while (true) {
        const std::string n = scalar(backend,
            "SELECT count(*) FROM pg_stat_activity WHERE usename = " + sqlQuote(cl.pgsql_username));
        last = n.empty() ? -1 : atoi(n.c_str());
        if (last == want || std::chrono::steady_clock::now() >= deadline) return last;
        usleep(100000);
    }
}

static int poolFree(PGconn* admin, int hg) {
    const std::string n = scalar(admin, "SELECT ConnFree FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(hg));
    return n.empty() ? -1 : atoi(n.c_str());
}

static int poolFreeWithin(PGconn* admin, int hg, int want, int seconds) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    int last = -1;
    while (true) {
        last = poolFree(admin, hg);
        if (last == want || std::chrono::steady_clock::now() >= deadline) return last;
        usleep(100000);
    }
}

// Emptying the pool needs the server taken OFFLINE_HARD and put back: deleting and
// re-inserting identical rows leaves every pooled connection in place (measured), so
// a test that relied on that would run against whatever the previous test left behind.
static bool flushPool(PGconn* admin) {
    // Put back the status the row actually had. Assuming ONLINE would quietly promote
    // a server the harness left in another state, and the next test would inherit it.
    std::string prev = scalar(admin, "SELECT status FROM pgsql_servers WHERE hostgroup_id=0 LIMIT 1");
    if (prev.empty()) prev = "ONLINE";
    if (!execOk(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=0")) return false;
    if (!execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    const int emptied = poolFreeWithin(admin, 0, 0, 10);
    if (!execOk(admin, "UPDATE pgsql_servers SET status='" + prev + "' WHERE hostgroup_id=0")) return false;
    if (!execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    return emptied == 0;
}

// ------------------------------------------------------------------ phase 2

static PGConnPtr openMockClient() {
    return openConn(cl.pgsql_host, cl.pgsql_port, MOCK_USER, MOCK_PASS, MOCK_USER);
}

static bool setVar(PGconn* admin, const char* name, const char* value) {
    return execOk(admin, std::string("SET ") + name + "='" + value + "'")
        && execOk(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

static int mockPoolConns(PGconn* admin) {
    const std::string n = scalar(admin,
        "SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup="
        + std::to_string(MOCK_HG));
    return n.empty() ? -1 : atoi(n.c_str());
}

// Each case must start from a fresh backend connection. A connection left over
// from the previous case fails first and spends the single retry budget, and the
// case under test then reports "no retry" for a reason that has nothing to do with
// the code -- so wait for the drain rather than sleeping a guess.
static bool resetMockPool(PGconn* admin) {
    const std::string hg = std::to_string(MOCK_HG);
    if (!execOk(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg)
        || !execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (mockPoolConns(admin) != 0 && std::chrono::steady_clock::now() < deadline) usleep(100000);
    if (!execOk(admin, "UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=" + hg)
        || !execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    usleep(200000);
    return true;
}

// Run statements through ProxySQL as the mock's user. Reports whether every one
// succeeded; the client error, if any, comes back in `err`.
static bool runThroughProxy(const std::vector<std::string>& stmts, std::string& err) {
    err.clear();
    auto c = openMockClient();
    if (!c || PQstatus(c.get()) != CONNECTION_OK) {
        err = c ? PQerrorMessage(c.get()) : "null connection";
        return false;
    }
    bool all_ok = true;
    for (const auto& s : stmts) {
        PGresult* r = PQexec(c.get(), s.c_str());
        const ExecStatusType st = PQresultStatus(r);
        if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
            all_ok = false;
            if (err.empty()) err = PQresultErrorMessage(r);
        }
        PQclear(r);
    }
    while (!err.empty() && (err.back() == '\n' || err.back() == '\r')) err.pop_back();
    return all_ok;
}

// The shutdown announcement: an ErrorResponse from the 57P0x family followed by
// ReadyForQuery, so the connection is still usable when ProxySQL decides what to
// do. That is what steers the error into handler_minus1_HandleErrorCodes rather
// than the dead-socket branch phase 1 exercises.
static std::string goingAway(char txn_state) {
    return pgmb_error_response("57P01", "mock: terminating connection due to administrator command")
         + pgmb_ready_for_query(txn_state);
}

int main(int, char**) {
    plan(21);
    if (cl.getEnv()) return exit_status();

    auto admin = openAdmin();
    ok(admin && PQstatus(admin.get()) == CONNECTION_OK, "ADMIN connection created%s",
       admin ? "" : " (null)");
    if (!admin || PQstatus(admin.get()) != CONNECTION_OK) return exit_status();

    auto backend = openBackend();
    ok(backend && PQstatus(backend.get()) == CONNECTION_OK,
       "direct backend connection created (needed to kill sessions without going through the proxy)");
    if (!backend || PQstatus(backend.get()) != CONNECTION_OK) return exit_status();

    // Whatever ran before may have left connections pooled, including dead ones that
    // only a client picking them up would notice. Start from an empty pool so the
    // probe below can only be served by the connection this test kills.
    killProxiedBackends(backend.get());
    const bool flushed = flushPool(admin.get());
    ok(flushed, "hostgroup 0 starts with no pooled connection (ConnFree=%d)", poolFree(admin.get(), 0));

    // ---- the connection that will be killed while ProxySQL holds it ----
    {
        auto victim = openClient();
        if (!victim || PQstatus(victim.get()) != CONNECTION_OK) BAIL_OUT("client connection failed");
        const std::string got = scalar(victim.get(), "SELECT '" + std::string(VICTIM_MARKER) + "'");
        ok(got == VICTIM_MARKER, "a first session ran a query over a backend connection (got '%s')", got.c_str());
    }
    const int free_after_victim = poolFreeWithin(admin.get(), 0, 1, 10);
    ok(free_after_victim == 1, "the first session left exactly one connection in the pool (ConnFree=%d)", free_after_victim);

    const int killed = killProxiedBackends(backend.get());
    const int still_live = proxiedSessionsWithin(backend.get(), 0, 10);
    ok(killed == 1 && still_live == 0,
       "the pooled backend session was terminated server-side (terminated %d, %d left alive)",
       killed, still_live);

    // ---- the guard ----
    // A brand new session, its very first statement, on a connection that was already
    // dead when ProxySQL handed it over. Nothing of the client's is at stake, so the
    // statement belongs on a fresh connection rather than in an error.
    {
        auto probe = openClient();
        bool timed_out = false;
        std::string got, err;
        if (probe && PQstatus(probe.get()) == CONNECTION_OK)
            got = scalarWithin(probe.get(), "SELECT 42", 20, &timed_out, &err);
        else if (probe)
            err = PQerrorMessage(probe.get());
        while (!err.empty() && (err.back() == '\n' || err.back() == '\r')) err.pop_back();
        ok(got == "42",
           "a new session's first query survives the connection a killed backend left pooled (got '%s'%s%s%s)",
           got.c_str(), timed_out ? ", timed out" : "",
           err.empty() ? "" : ", error: ", err.c_str());
    }

    // ---- the boundary the retry must not cross ----
    // Same death, but inside an explicit transaction. Replaying here would run the
    // statement on its own outside the transaction the client believes it is in.
    {
        auto setup = openClient();
        if (!setup || PQstatus(setup.get()) != CONNECTION_OK) BAIL_OUT("client connection failed");
        execOk(setup.get(), "DROP TABLE IF EXISTS " + std::string(TBL));
        if (!execOk(setup.get(), "CREATE TABLE " + std::string(TBL) + " (id int)"))
            BAIL_OUT("could not create the test table");
    }

    bool replayed = false;
    {
        auto tx = openClient();
        if (!tx || PQstatus(tx.get()) != CONNECTION_OK) BAIL_OUT("client connection failed");
        execOk(tx.get(), "BEGIN");
        execOk(tx.get(), "INSERT INTO " + std::string(TBL) + " VALUES (1)");
        scalar(tx.get(), "SELECT 'txn_victim_marker'");
        killBackendRunningMarker(backend.get(), "txn_victim_marker");
        // Whatever this returns, it must not have run: a success here is the replay.
        // The kill above left a healthy backend to retry onto, so if the decision
        // allowed a retry this statement would succeed.
        PGresult* r = PQexec(tx.get(), ("INSERT INTO " + std::string(TBL) + " VALUES (2)").c_str());
        replayed = (PQresultStatus(r) == PGRES_COMMAND_OK);
        PQclear(r);
    }
    ok(replayed == false, "a statement is not replayed after the backend died inside an explicit transaction");

    const std::string rows = scalar(backend.get(), "SELECT count(*) FROM " + std::string(TBL));
    ok(rows == "0", "nothing from the lost transaction reached the table (count=%s)", rows.c_str());

    // ---- the same boundary, for a session ProxySQL cannot track ------------
    // A SET it cannot replay pins the session to one hostgroup, and while pinned
    // its BEGIN/COMMIT tracking is not updated at all. The transaction is then
    // invisible to the retry decision, so being pinned has to count as "may be in
    // one" -- otherwise this is exactly the case that gets replayed into.
    int locked = -99;
    bool locked_replayed = false;
    {
        auto tx = openClient();
        if (!tx || PQstatus(tx.get()) != CONNECTION_OK) BAIL_OUT("client connection failed");
        execOk(tx.get(), "SET work_mem='4MB'");
        locked = lockedOnHostgroup(tx.get());
        execOk(tx.get(), "BEGIN");
        execOk(tx.get(), "INSERT INTO " + std::string(TBL) + " VALUES (10)");
        scalar(tx.get(), "SELECT 'locked_victim_marker'");
        killBackendRunningMarker(backend.get(), "locked_victim_marker");
        PGresult* r = PQexec(tx.get(), ("INSERT INTO " + std::string(TBL) + " VALUES (11)").c_str());
        locked_replayed = (PQresultStatus(r) == PGRES_COMMAND_OK);
        PQclear(r);
    }
    ok(locked >= 0,
       "the SET really pinned the session to a hostgroup, so the guard is under test (locked_on_hostgroup=%d)",
       locked);
    ok(locked_replayed == false,
       "a statement from a hostgroup-pinned session is not replayed after the backend died");
    const std::string locked_rows = scalar(backend.get(), "SELECT count(*) FROM " + std::string(TBL));
    ok(locked_rows == "0",
       "nothing from the pinned session's transaction reached the table (count=%s)", locked_rows.c_str());

    // ---- phase 1 cleanup ----
    {
        auto cleanup = openClient();
        if (cleanup && PQstatus(cleanup.get()) == CONNECTION_OK)
            execOk(cleanup.get(), "DROP TABLE IF EXISTS " + std::string(TBL));
    }

    // ======================================================================
    //  Phase 2 -- the backend announces a shutdown while still usable
    // ======================================================================
    // Same retry decision, reached through handler_minus1_HandleErrorCodes rather
    // than the dead-socket branch above. Measured from the backend side: a replay
    // is a SECOND connection carrying the same statement.
    if (!setVar(admin.get(), "pgsql-monitor_enabled", "false"))
        BAIL_OUT("cannot disable the monitor for the mock phase");
    // This defect is the libpq path; native keeps its own transaction byte and
    // never lost the retry. Pin the mode so the test says what it measured.
    if (!setVar(admin.get(), "pgsql-use_native_backend_protocol", "false"))
        BAIL_OUT("cannot select the libpq backend path");

    PgSQL_Mock_Backend mock;
    mock.set_scram_password(MOCK_PASS);
    if (!mock.start()) BAIL_OUT("mock backend failed to listen");

    const std::string myip = pgmb_local_ip_towards(cl.pgsql_host, cl.pgsql_port);
    if (myip.empty()) BAIL_OUT("could not discover this container's IP toward ProxySQL");
    diag("mock backend listening on %s:%u (hostgroup %d)", myip.c_str(), mock.port(), MOCK_HG);

    {
        const std::string hg = std::to_string(MOCK_HG);
        const bool registered =
            execOk(admin.get(), "DELETE FROM pgsql_servers WHERE hostgroup_id=" + hg)
            && execOk(admin.get(),
                "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) VALUES ("
                + hg + ",'" + myip + "'," + std::to_string(mock.port()) + ",4,0,'retry boundary mock')")
            && execOk(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME")
            && execOk(admin.get(),
                "INSERT OR REPLACE INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('"
                + std::string(MOCK_USER) + "','" + MOCK_PASS + "',1," + hg + ")")
            && execOk(admin.get(), "LOAD PGSQL USERS TO RUNTIME");
        if (!registered) BAIL_OUT("could not register the mock backend and its user");
    }
    usleep(300000);

    // Control: without it, the counters below could equally be explained by a
    // client that never reached the mock at all.
    {
        std::vector<Step> script = pgmb_script_accept_trust();
        script.push_back(step_expect_query());
        script.push_back(step_send(pgmb_simple_result("c", "served", 1)));
        mock.set_script(script);
        resetMockPool(admin.get());
        mock.reset_stats();

        std::string err;
        const bool served = runThroughProxy({"SELECT 1"}, err);
        ok(served && mock.queries_observed() == 1,
           "control: a query reaches the mock and its answer reaches the client (served=%s, queries=%d)%s%s",
           served ? "yes" : "no", mock.queries_observed(),
           err.empty() ? "" : ", error: ", err.c_str());
    }

    // No transaction open: nothing of the client's is at stake, so the statement
    // belongs on a fresh connection and the mock is asked the same question twice.
    int c1_conns = -1, c1_queries = -1;
    {
        std::vector<Step> script = pgmb_script_accept_trust();
        script.push_back(step_expect_query());
        script.push_back(step_send(goingAway('I')));
        mock.set_script(script);
        resetMockPool(admin.get());
        mock.reset_stats();

        std::string err;
        runThroughProxy({"SELECT 1"}, err);  // errors either way: the retry meets the same script
        usleep(300000);
        c1_conns = mock.connections_accepted();
        c1_queries = mock.queries_observed();
    }
    ok(c1_conns == 2, "shutdown announced, no transaction: the statement was re-sent on a second backend connection (connections=%d, expected 2)", c1_conns);
    ok(c1_queries == 2, "shutdown announced, no transaction: the backend was asked the same question twice (queries=%d, expected 2)", c1_queries);

    // Same announcement inside an explicit transaction. Replaying would run the
    // statement outside the transaction the client believes it is in.
    int c2_conns = -1;
    bool c2_client_saw_error = false;
    {
        std::vector<Step> script = pgmb_script_accept_trust();
        // BEGIN is transaction control, which EXPECT_QUERY treats as housekeeping and
        // acks generically with ReadyForQuery('I') -- telling ProxySQL no transaction
        // is open and quietly destroying the case. Stop on it and answer with 'T'.
        script.push_back(step_expect_query(/* stop_at_housekeeping */ true));
        script.push_back(step_send(pgmb_command_complete("BEGIN") + pgmb_ready_for_query('T')));
        script.push_back(step_expect_query());
        script.push_back(step_send(goingAway('E')));
        mock.set_script(script);
        resetMockPool(admin.get());
        mock.reset_stats();

        std::string err;
        c2_client_saw_error = (runThroughProxy({"BEGIN", "SELECT 1"}, err) == false);
        usleep(300000);
        c2_conns = mock.connections_accepted();
        diag("in-transaction case: client error was '%s'", err.empty() ? "-" : err.c_str());
    }
    ok(c2_conns == 1, "shutdown announced in a transaction: the statement was NOT replayed on another connection (connections=%d, expected 1)", c2_conns);
    ok(c2_client_saw_error, "shutdown announced in a transaction: the error reached the client instead of being replayed away");

    // Take the mock's rows back out so anything sharing this container is not left
    // pointing at a listener that is about to stop.
    execOk(admin.get(), "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(MOCK_HG));
    execOk(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME");
    execOk(admin.get(), std::string("DELETE FROM pgsql_users WHERE username='") + MOCK_USER + "'");
    execOk(admin.get(), "LOAD PGSQL USERS TO RUNTIME");
    mock.stop();

    // ======================================================================
    //  Phase 3 -- the same two cases on the native backend protocol
    // ======================================================================
    // Native never had this defect: it keeps the ReadyForQuery status byte, which
    // survives the connection dying, so it could always answer "was a transaction
    // open?" on a dead connection. This phase pins that, because the change made
    // native marginally STRICTER (it now also consults the session's own tracking
    // and refuses while pinned to a hostgroup), and nothing else asserts it.
    //
    // There is no per-connection "this is native" marker exposed anywhere, so the
    // phase establishes it by construction instead: the flag is read back from
    // runtime, and the pool and the backend are both verified empty first, so every
    // connection used below had to be created after the flip. Flipping without that
    // check is the classic way this test would pass while testing libpq twice --
    // pooled connections do not convert.
    if (!setVar(admin.get(), "pgsql-use_native_backend_protocol", "true"))
        BAIL_OUT("cannot enable the native backend protocol");
    killProxiedBackends(backend.get());
    flushPool(admin.get());
    const std::string native_flag = scalar(admin.get(),
        "SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
    const int native_pool = poolFreeWithin(admin.get(), 0, 0, 10);
    const int native_sessions = proxiedSessionsWithin(backend.get(), 0, 10);
    ok(native_flag == "true" && native_pool == 0 && native_sessions == 0,
       "native mode is on and nothing is left to reuse, so every connection below is native "
       "(flag=%s, pooled=%d, backend sessions=%d)",
       native_flag.c_str(), native_pool, native_sessions);

    {
        auto setup = openClient();
        if (!setup || PQstatus(setup.get()) != CONNECTION_OK) BAIL_OUT("client connection failed");
        execOk(setup.get(), "DROP TABLE IF EXISTS " + std::string(TBL));
        if (!execOk(setup.get(), "CREATE TABLE " + std::string(TBL) + " (id int)"))
            BAIL_OUT("could not create the test table for the native phase");
    }

    // Leave a connection in the pool, kill it server-side, then have a new session
    // pick it up -- the same shape as phase 1, on the other protocol.
    {
        auto victim = openClient();
        if (victim && PQstatus(victim.get()) == CONNECTION_OK)
            scalar(victim.get(), "SELECT '" + std::string(VICTIM_MARKER) + "'");
    }
    poolFreeWithin(admin.get(), 0, 1, 10);
    killProxiedBackends(backend.get());
    proxiedSessionsWithin(backend.get(), 0, 10);
    {
        auto probe = openClient();
        bool timed_out = false;
        std::string got, err;
        if (probe && PQstatus(probe.get()) == CONNECTION_OK)
            got = scalarWithin(probe.get(), "SELECT 42", 20, &timed_out, &err);
        else if (probe)
            err = PQerrorMessage(probe.get());
        while (!err.empty() && (err.back() == '\n' || err.back() == '\r')) err.pop_back();
        ok(got == "42",
           "native: a new session's first query survives the connection a killed backend left pooled (got '%s'%s%s%s)",
           got.c_str(), timed_out ? ", timed out" : "",
           err.empty() ? "" : ", error: ", err.c_str());
    }

    // The boundary, on native: the status byte says 'T'/'E' after the death, so the
    // statement must not be replayed.
    bool native_replayed = false;
    {
        auto tx = openClient();
        if (!tx || PQstatus(tx.get()) != CONNECTION_OK) BAIL_OUT("client connection failed");
        execOk(tx.get(), "BEGIN");
        execOk(tx.get(), "INSERT INTO " + std::string(TBL) + " VALUES (1)");
        scalar(tx.get(), "SELECT 'native_victim_marker'");
        killBackendRunningMarker(backend.get(), "native_victim_marker");
        PGresult* r = PQexec(tx.get(), ("INSERT INTO " + std::string(TBL) + " VALUES (2)").c_str());
        native_replayed = (PQresultStatus(r) == PGRES_COMMAND_OK);
        PQclear(r);
    }
    ok(native_replayed == false,
       "native: a statement is not replayed after the backend died inside an explicit transaction");
    const std::string native_rows = scalar(backend.get(), "SELECT count(*) FROM " + std::string(TBL));
    ok(native_rows == "0",
       "native: nothing from the lost transaction reached the table (count=%s)", native_rows.c_str());

    {
        auto cleanup = openClient();
        if (cleanup && PQstatus(cleanup.get()) == CONNECTION_OK)
            execOk(cleanup.get(), "DROP TABLE IF EXISTS " + std::string(TBL));
    }
    return exit_status();
}
