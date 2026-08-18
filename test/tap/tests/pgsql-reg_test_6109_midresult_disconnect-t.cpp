/**
 * @file pgsql-reg_test_6109_midresult_disconnect-t.cpp
 * @brief Regression test: a PostgreSQL backend that disconnects mid-result must
 *        not take the whole ProxySQL process down.
 *
 * Regression test for issue #6109. The related #6110 (a backend replying with no
 * command outcome) has its own test - it was only reachable once #6109 was fixed,
 * because before that the process was already gone.
 *
 * THE DEFECT
 * ----------
 * When a backend starts sending a result and the connection dies before the
 * result is complete, ProxySQL aborts. Not the one connection — the entire
 * process, killing every other client's session at the same time. One ordinary
 * client query is enough, and the triggers are everyday events: a database
 * restart, a failover, pg_terminate_backend(), an OOM kill, or a network blip in
 * the middle of a large result.
 *
 * ROOT CAUSE — one omission, three abort sites
 * --------------------------------------------
 * fetch_result_cont() detects a TERMINAL condition and reports it as an
 * INDETERMINATE one.
 *
 * On backend EOF, PQconsumeInput() returns 0. lib/PgSQL_Connection.cpp:1238 logs
 * "Failed to consume input", sets error_info, and returns early WITHOUT
 * assigning either `result_type` or `async_exit_status`. Meanwhile libpq has
 * already run pqDropConnection() and set conn->status = CONNECTION_BAD, closing
 * the socket out from under ProxySQL.
 *
 * Back in handler()/ASYNC_USE_RESULT_CONT, async_exit_status is PG_EVENT_NONE, so
 * control falls into the `result_type` dispatch (lib/PgSQL_Connection.cpp:447 and
 * :626) carrying STALE per-fetch state: `result_type` is assigned only in the
 * constructor at :149 and is never reset per fetch. What happens next depends on
 * how far the result had progressed when the backend died:
 *
 *   result_type == 0   (no row handled yet — the truncated-frame shape)
 *       matches neither arm -> lib/PgSQL_Connection.cpp:652 assert(0). Immediate.
 *
 *   result_type == 2   (rows already streamed — the production shape)
 *       takes the row arm with a stale ps_result, re-appends the same row, and
 *       does NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT). The cycle never terminates,
 *       so the session never reaches its rc == -1 handling and the dead fd is
 *       never unplugged from mypolls. The worker thread stalls (watchdog:
 *       "1 PostgreSQL threads missed a heartbeat"), then the poll loop observes
 *       the descriptor libpq closed -> lib/Base_Thread.cpp:247
 *       assert(thr->mypolls.fds[n].revents!=POLLNVAL).
 *
 * A fourth abort sits on the same trigger but needs a COPY OUT to reach:
 * `is_copy_out` is cleared only at :2233/:2239, so a backend dying mid-COPY would
 * reach ASYNC_QUERY_END and trip assert(!is_copy_out) at :820.
 *
 * Note on the stale row: pqDropConnection(conn, false) deliberately PRESERVES
 * libpq's input buffer ("Do *not* drop any already-read data"), so ps_result.data
 * still addresses valid memory. This is duplicated/incorrect data, NOT a
 * use-after-free — do not go looking for a memory-safety bug here.
 *
 * NOT DEBUG-ONLY
 * --------------
 * All of these are assert(), and -DNDEBUG appears nowhere in Makefile,
 * lib/Makefile or src/Makefile. Release builds abort at these points too, so this
 * test asserts real shipped behaviour, not a debug-only guard.
 *
 * WHAT IS ASSERTED
 * ----------------
 * Per scenario:
 *   1. ProxySQL is still alive and still serving the REAL backend.
 *   2. The client receives an ERROR — not a hang, and not a silent success that
 *      would mean a truncated resultset was forwarded as if complete.
 *   3. No backend connection is stranded in the mock's hostgroup. A connection
 *      whose peer vanished mid-result must be destroyed, not returned to the pool
 *      for the next session to pick up.
 * Plus the query-cache corollary: a truncated result must never be stored. That
 * is the silent-corruption form of the same bug, and it is what a release build
 * would do if the asserts were simply deleted rather than handled.
 *
 * TWO SHAPES, AND WHY BOTH
 * ------------------------
 * "complete rows then FIN" runs FIRST and is the production shape: every byte is
 * well-formed and every DataRow complete; the server just dies before
 * CommandComplete, exactly as a restart or failover does. Nothing is malformed,
 * so a fix that only hardens framing still fails it.
 *
 * "truncated DataRow then FIN" runs last. It leaves the parser holding an
 * incomplete message at EOF where the first shape leaves it message-aligned —
 * a different state, and the one that produces result_type == 0.
 *
 * BEHAVIOUR ON CRASH — deliberate
 * -------------------------------
 * When the proxy dies, every remaining scenario is reported as a FAILURE naming
 * the earlier crash, and no further traffic is driven. The TAP plan is still
 * satisfied, so the run reads as "N failures, all caused by the crash in scenario
 * X" instead of a truncated plan plus a harness traceback.
 *
 * NO HANGS
 * --------
 * Every client query runs through driveQuery(), which drives libpq asynchronously
 * against a wall-clock deadline. A proxy that neither answers nor errors is a
 * distinct, reportable outcome (TIMED_OUT) rather than a test that blocks until
 * the harness timeout. That matters here: the observed failure includes a worker
 * thread stalling for ~11 seconds before it aborts, and a partial fix that stops
 * the abort without emitting an ErrorResponse leaves the CLIENT wedged instead.
 *
 * INFRA
 * -----
 * legacy-g1 (docker-pgsql16-single). The mock listens inside the test-runner
 * container, which shares the Docker network with ProxySQL, and is registered in
 * pgsql_servers by its runtime-discovered IP.
 *
 * PRECONDITIONS
 * -------------
 * A backend that dies on purpose trips two mechanisms that would otherwise pull
 * it out of rotation part-way through: the Monitor shuns non-responsive servers
 * (and probes with libpq, which every truncated result defeats), and
 * pgsql-shun_on_failures defaults to 5 while this file contains more than five
 * deliberate failures. Both are adjusted for the duration and restored at the
 * end, IN MEMORY ONLY — never SAVE ... TO DISK, per project rule.
 */
#include <chrono>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <sys/select.h>
#include <unistd.h>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

#include "pgsql_mock_backend.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

// Hostgroup and user dedicated to the mock, kept away from the real backend's
// hostgroup 0 so a dying mock cannot affect normal traffic.
static const int MOCK_HG = 48;
static const char* MOCK_USER = "midresult_mock_user";
static const char* MOCK_PASS = "midresult_mock_pw";

// Query-cache probe. The mock ignores SQL and returns canned bytes, so the text
// only has to be distinctive enough to match exactly one query rule.
static const char* CACHE_PROBE_SQL = "SELECT 'midresultcacheprobe'";
static const char* CACHE_COMPLETE_VALUE = "midresult-complete";
static const int CACHE_RULE_ID = 90480;

// Bounded wait for any single client query. Generous enough that a slow but
// working proxy is never mislabelled, short enough that a spin or a deadlock is
// reported as a failure rather than hanging the run.
static const int QUERY_DEADLINE_MS = 15000;

// Set once the proxy is observed to be down; every later scenario short-circuits
// so one crash produces one diagnosis instead of a cascade.
static bool g_proxy_down = false;
static std::string g_proxy_down_where;

static std::string g_mock_ip;
static uint16_t g_mock_port = 0;

// ------------------------------------------------------------------ helpers

enum ConnType { ADMIN, BACKEND };

PGConnPtr createNewConnection(ConnType conn_type) {
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

    std::stringstream ss;
    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << " sslmode=disable";

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

// The mock-backend user is a third identity that ConnType has no slot for: it
// authenticates against ProxySQL like any client, but its default_hostgroup routes
// it to the mock rather than to the real PostgreSQL backend.
static PGConnPtr createMockUserConnection() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
       << " user=" << MOCK_USER << " password=" << MOCK_PASS
       << " dbname=postgres sslmode=disable connect_timeout=10";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execAdmin(PGconn* admin, const std::string& q) {
    PGresult* r = PQexec(admin, q.c_str());
    const ExecStatusType st = PQresultStatus(r);
    const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(admin));
    PQclear(r);
    return good;
}

static std::string adminScalar(PGconn* admin, const std::string& q) {
    PGresult* r = PQexec(admin, q.c_str());
    std::string v;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
        v = PQgetvalue(r, 0, 0);
    PQclear(r);
    return v;
}

static bool setVar(PGconn* admin, const std::string& name, const std::string& val) {
    return execAdmin(admin, "SET " + name + "='" + val + "'") &&
           execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

static std::string savedVar(PGconn* admin, const char* name) {
    return adminScalar(admin,
        std::string("SELECT variable_value FROM global_variables WHERE variable_name='") + name + "'");
}

// Backend connections currently held for the mock's hostgroup.
static int mockPoolConnsNow(PGconn* admin) {
    std::stringstream q;
    q << "SELECT IFNULL(SUM(ConnUsed + ConnFree),0) FROM stats_pgsql_connection_pool "
      << "WHERE hostgroup=" << MOCK_HG;
    const std::string v = adminScalar(admin, q.str());
    return v.empty() ? 0 : atoi(v.c_str());
}

// Settle before judging. ProxySQL retries a failing backend several times, and
// teardown of the last attempt can still be in flight when the client's error
// surfaces; sampling immediately reports connections on their way out as leaks.
// Poll toward zero for a bounded window and report the last value seen.
static int mockPoolConns(PGconn* admin) {
    int last = mockPoolConnsNow(admin);
    for (int i = 0; i < 20 && last != 0; i++) {   // up to ~2s
        usleep(100000);
        last = mockPoolConnsNow(admin);
    }
    return last;
}

// Drop every pooled backend connection for the mock hostgroup by removing and
// re-adding the server row. Without this, scenarios are not independent: one that
// leaves a live connection means the next is served from the pool and its script
// never runs, so its verdict describes the previous scenario.
static bool resetMockPool(PGconn* admin) {
    std::stringstream del;
    del << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << MOCK_HG;
    if (!execAdmin(admin, del.str()) || !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
        return false;
    std::stringstream ins;
    ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) "
        << "VALUES (" << MOCK_HG << ",'" << g_mock_ip << "'," << g_mock_port
        << ",4,0,'mid-result disconnect mock')";
    if (!execAdmin(admin, ins.str()) || !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
        return false;
    usleep(150000);
    return true;
}

// ------------------------------------------------------- client-side driving

enum class Outcome {
    SERVED,          // the proxy answered with a resultset / command completion
    ERRORED,         // the proxy answered with an error -- the DESIRED outcome here
    TIMED_OUT,       // neither, within the deadline: a spin or a deadlock
    CONNECT_FAILED   // could not even connect: the proxy is gone
};

static const char* outcomeName(Outcome o) {
    switch (o) {
        case Outcome::SERVED:         return "served";
        case Outcome::ERRORED:        return "errored";
        case Outcome::TIMED_OUT:      return "TIMED OUT";
        case Outcome::CONNECT_FAILED: return "CONNECT FAILED";
    }
    return "?";
}

static bool waitReadable(int fd, int timeout_ms) {
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(fd, &rf);
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select(fd + 1, &rf, nullptr, nullptr, &tv) > 0;
}

// Run one query through ProxySQL against a hard wall-clock deadline.
//
// Deliberately asynchronous: PQexec would block indefinitely against a proxy that
// is spinning rather than answering, turning a reportable defect into a hung test
// run. `values` collects row 0 column 0 of EACH tuple result, so a multi-statement
// query yields one entry per statement - which is how the multi-statement
// scenarios below verify that all statements came back, in order.
static Outcome driveQuery(std::string& err, std::vector<std::string>* values,
                          const char* query, int timeout_ms) {
    err.clear();
    if (values) values->clear();

    auto c = createMockUserConnection();
    if (!c || PQstatus(c.get()) != CONNECTION_OK) {
        err = c ? PQerrorMessage(c.get()) : "null conn";
        return Outcome::CONNECT_FAILED;
    }
    if (PQsendQuery(c.get(), query) == 0) {
        err = PQerrorMessage(c.get());
        return Outcome::ERRORED;
    }

    const int fd = PQsocket(c.get());
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);

    Outcome out = Outcome::SERVED;
    for (;;) {
        while (PQisBusy(c.get())) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                err = "no response from the proxy within the deadline";
                return Outcome::TIMED_OUT;
            }
            int remain = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - now).count();
            if (remain > 250) remain = 250;          // re-check the deadline regularly
            if (!waitReadable(fd, remain)) continue;
            if (PQconsumeInput(c.get()) == 0) {
                err = PQerrorMessage(c.get());
                return Outcome::ERRORED;             // peer gone: a clean client error
            }
        }
        PGresult* r = PQgetResult(c.get());
        if (r == nullptr) break;
        const ExecStatusType st = PQresultStatus(r);
        if (st == PGRES_TUPLES_OK) {
            if (values && PQntuples(r) > 0 && PQnfields(r) > 0 && !PQgetisnull(r, 0, 0)) {
                values->push_back(PQgetvalue(r, 0, 0));
            }
        } else if (st != PGRES_COMMAND_OK) {
            if (err.empty()) err = PQresultErrorMessage(r);
            if (err.empty()) err = PQerrorMessage(c.get());
            out = Outcome::ERRORED;
        }
        PQclear(r);
    }
    return out;
}

// One line of client error, for readable TAP output.
static std::string oneLine(const std::string& s) {
    std::string t = s.substr(0, s.find('\n'));
    while (!t.empty() && (t.back() == ' ' || t.back() == '\r')) t.pop_back();
    return t.empty() ? "-" : t;
}

// ProxySQL alive, and the real backend still reachable through it. Returns ""
// when healthy, else what broke. Reconnects once: a crashed proxy fails the
// reconnect too, so this cannot mask a crash.
static std::string checkInvariants(PGconn*& adminRef, PGConnPtr& adminOwner) {
    if (adminScalar(adminRef, "SELECT 1") != "1") {
        adminOwner = createNewConnection(ConnType::ADMIN);
        if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
            return "ProxySQL admin unreachable (proxy down?)";
        adminRef = adminOwner.get();
        if (adminScalar(adminRef, "SELECT 1") != "1")
            return "ProxySQL admin not answering";
    }
    auto c = createNewConnection(ConnType::BACKEND);
    if (!c || PQstatus(c.get()) != CONNECTION_OK)
        return "real-backend traffic broken after the mid-result disconnect";
    PGresult* r = PQexec(c.get(), "SELECT 1");
    const bool good = (PQresultStatus(r) == PGRES_TUPLES_OK);
    PQclear(r);
    if (!good) return "real-backend query failed after the mid-result disconnect";
    return "";
}

// ------------------------------------------------------------ mock fixtures

// Handshake prefix that gets the mock to a ready-for-query state.
static std::string acceptedHandshake() {
    return pgmb_auth_ok() +
           pgmb_parameter_status("server_version", "16.2") +
           pgmb_parameter_status("client_encoding", "UTF8") +
           pgmb_backend_key_data(4242, 987654321) +
           pgmb_ready_for_query('I');
}

// Shape 1 -- the production shape. Every byte sent is well-formed and every
// DataRow is complete; the server simply dies before CommandComplete and
// ReadyForQuery, exactly as a restart, failover, pg_terminate_backend(), OOM kill
// or network blip does mid-stream. Because rows WERE handled, result_type is 2 at
// the EOF, which is the stale-row / POLLNVAL route.
static std::vector<Step> scriptCompleteRowsThenFin(int rows) {
    std::string body = pgmb_row_description_1col("c", 25);
    for (int i = 0; i < rows; i++) body += pgmb_data_row_1col("row-payload-value");
    return { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
             step_send(body), step_close() };
}

// Shape 2 -- a DataRow whose length field promises far more than the server ever
// sends, then FIN. No row is ever completed, so result_type is still 0 at the EOF,
// which is the assert(0) route.
static std::vector<Step> scriptTruncatedRowThenFin() {
    return { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
             step_send(pgmb_row_description_1col("c", 25) +
                       std::string("D") + pgmb_be32(1000) + "only-a-few-bytes"),
             step_close() };
}

// A well-formed, complete result -- used to prove the cache is not serving the
// truncated bytes from the preceding attempt.
static std::vector<Step> scriptCompleteResult() {
    return { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
             step_send(pgmb_simple_result("c", CACHE_COMPLETE_VALUE, 1)),
             step_close() };
}

// Two complete statements in one response: RowDescription/rows/CommandComplete
// twice, with ReadyForQuery only at the very end. This is what a backend sends for
// "SELECT ...; SELECT ...", and it is the ONLY path that re-enters
// fetch_result_cont() with a PGresult already pending -- next_multi_statement_result()
// stashes it and jumps back to ASYNC_USE_RESULT_START. That is precisely the case
// the per-fetch result_type reset has to account for.
static std::string multiStatementBody(const std::string& v1, const std::string& v2,
                                      int rows_each, bool complete) {
    std::string out = pgmb_row_description_1col("c", 25);
    for (int i = 0; i < rows_each; i++) out += pgmb_data_row_1col(v1);
    out += pgmb_command_complete("SELECT " + std::to_string(rows_each));
    if (!complete) return out;               // caller FINs here, mid-chain
    out += pgmb_row_description_1col("c", 25);
    for (int i = 0; i < rows_each; i++) out += pgmb_data_row_1col(v2);
    out += pgmb_command_complete("SELECT " + std::to_string(rows_each));
    out += pgmb_ready_for_query('I');
    return out;
}

// Handshake, wait for the query, send `body`, then FIN.
static std::vector<Step> scriptServe(const std::string& body) {
    return { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
             step_send(body), step_close() };
}

// A message that declares nearly a gigabyte, sends 100 bytes, then goes quiet
// before closing. ProxySQL must not buffer toward the declared size, must give up
// rather than wait forever, and must not abort on the eventual FIN. Byte-identical
// to pgsql-native_hostile_backend-t case R4, which was proven to abort an unfixed
// build at the result_type dispatch.
static std::vector<Step> scriptHugeDeclaredLenThenSilence() {
    return { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
             step_send(std::string("D") + pgmb_be32(900u * 1024 * 1024) + std::string(100, 'x')),
             step_sleep(6000), step_close() };
}

// COPY ... TO STDOUT that dies after some CopyData. PGRES_COPY_OUT makes
// handle_copy_out() set is_copy_out; if the result cycle then ends without
// clearing it, ASYNC_QUERY_END trips assert(!is_copy_out). This is the only
// scenario that reaches that line. COPY ... TO STDOUT is deliberately used rather
// than FROM STDIN: the session's copy_cmd_matcher intercepts COPY...FROM...STDIN
// into fast-forward mode, which never enters this code path at all.
static std::vector<Step> scriptCopyOutThenFin(int chunks) {
    std::string body = pgmb_copy_out_response(1);
    for (int i = 0; i < chunks; i++) body += pgmb_copy_data("copy-payload-line\n");
    return scriptServe(body);        // no CopyDone, no CommandComplete, no ReadyForQuery
}

// ------------------------------------------------------------- the scenarios

// Emit the three standard assertions for one mid-result-disconnect scenario.
static void runDisconnectScenario(PGconn*& admin, PGConnPtr& adminOwner,
                                  PgSQL_Mock_Backend& mock,
                                  const char* label,
                                  const std::vector<Step>& script,
                                  const char* query = "SELECT 1") {
    if (g_proxy_down) {
        for (int i = 0; i < 3; i++)
            ok(false, "%s: not run -- ProxySQL was already down from '%s'",
               label, g_proxy_down_where.c_str());
        return;
    }

    resetMockPool(admin);
    mock.set_script(script);
    mock.reset_stats();

    std::string err;
    const Outcome out = driveQuery(err, nullptr, query, QUERY_DEADLINE_MS);

    const std::string broke = checkInvariants(admin, adminOwner);
    if (!broke.empty()) {
        g_proxy_down = true;
        g_proxy_down_where = label;
    }

    ok(broke.empty(),
       "%s: ProxySQL survived the mid-result disconnect%s%s",
       label, broke.empty() ? "" : " -- ", broke.c_str());

    ok(out == Outcome::ERRORED,
       "%s: client got a clean error, not a hang and not a silent truncation "
       "(outcome=%s, client=%s)",
       label, outcomeName(out), oneLine(err).c_str());

    // Only meaningful while the proxy is up; a dead proxy reports 0 connections
    // for every hostgroup, which would read as a pass.
    if (broke.empty()) {
        const int stranded = mockPoolConns(admin);
        ok(stranded == 0,
           "%s: no backend connection stranded in the pool after the peer vanished "
           "(found %d)",
           label, stranded);
    } else {
        ok(false,
           "%s: pool cleanliness not assertable -- ProxySQL is down, so the "
           "connection-pool stats are meaningless",
           label);
    }
}

// Assert a query is served CORRECTLY and completely. These cover the paths the fix
// touches on the success side: multi-statement chaining depends on the pending
// PGresult still being dispatched as result_type 1 after fetch_result_start() has
// zeroed it, and threshold pauses widen the window between that reset and the point
// a value is re-derived. A regression here shows up as a wrong/missing result or an
// abort, not as a mid-result disconnect.
static void runServedScenario(PGconn*& admin, PGConnPtr& adminOwner,
                              PgSQL_Mock_Backend& mock, const char* label,
                              const std::vector<Step>& script, const char* query,
                              const std::vector<std::string>& expected) {
    if (g_proxy_down) {
        for (int i = 0; i < 2; i++)
            ok(false, "%s: not run -- ProxySQL was already down from '%s'",
               label, g_proxy_down_where.c_str());
        return;
    }

    resetMockPool(admin);
    mock.set_script(script);
    mock.reset_stats();

    std::string err;
    std::vector<std::string> got;
    const Outcome out = driveQuery(err, &got, query, QUERY_DEADLINE_MS);

    const std::string broke = checkInvariants(admin, adminOwner);
    if (!broke.empty()) {
        g_proxy_down = true;
        g_proxy_down_where = label;
    }
    ok(broke.empty(), "%s: ProxySQL survived%s%s",
       label, broke.empty() ? "" : " -- ", broke.c_str());

    std::string joined;
    for (const auto& v : got) { if (!joined.empty()) joined += ","; joined += v; }
    ok(out == Outcome::SERVED && got == expected,
       "%s: served %zu result(s), correct and in order (outcome=%s, got=[%s], client=%s)",
       label, expected.size(), outcomeName(out), joined.c_str(), oneLine(err).c_str());
}

// The silent-corruption corollary: a truncated result must never be stored in the
// query cache.
//
// With the aborts in place this scenario is unreachable -- the proxy has already
// died. It is the guard for the FIXED code: once the result cycle terminates
// cleanly, execution reaches the cache-store block, and without resultset
// completeness as a precondition a partial resultset is cached and then served to
// every later client as if it were whole. That is the failure a release build
// produces if the asserts are merely deleted.
static void runCacheScenario(PGconn*& admin, PGConnPtr& adminOwner,
                             PgSQL_Mock_Backend& mock) {
    const char* label = "truncated result is not stored in the query cache";

    if (g_proxy_down) {
        for (int i = 0; i < 2; i++)
            ok(false, "%s: not run -- ProxySQL was already down from '%s'",
               label, g_proxy_down_where.c_str());
        return;
    }

    // Attempt 1: the cacheable query dies mid-result.
    resetMockPool(admin);
    mock.set_script(scriptCompleteRowsThenFin(20));
    std::string err;
    driveQuery(err, nullptr, CACHE_PROBE_SQL, QUERY_DEADLINE_MS);

    const std::string broke = checkInvariants(admin, adminOwner);
    if (!broke.empty()) {
        g_proxy_down = true;
        g_proxy_down_where = label;
    }
    ok(broke.empty(),
       "%s: ProxySQL survived the cacheable query dying mid-result%s%s",
       label, broke.empty() ? "" : " -- ", broke.c_str());

    if (!broke.empty()) {
        ok(false, "%s: cache content not assertable -- ProxySQL is down", label);
        return;
    }

    // Attempt 2: the same query against a healthy backend. If the truncated bytes
    // were cached, this is answered from the cache and never reaches the mock, so
    // the complete value cannot come back.
    resetMockPool(admin);
    mock.set_script(scriptCompleteResult());
    std::vector<std::string> got;
    const Outcome out = driveQuery(err, &got, CACHE_PROBE_SQL, QUERY_DEADLINE_MS);

    ok(out == Outcome::SERVED && got.size() == 1 && got[0] == CACHE_COMPLETE_VALUE,
       "%s: the repeat query returned the COMPLETE result '%s' "
       "(outcome=%s, got='%s', client=%s)",
       label, CACHE_COMPLETE_VALUE, outcomeName(out),
       got.empty() ? "" : got[0].c_str(), oneLine(err).c_str());
}

// ---------------------------------------------------------------------- main

int main(int, char**) {
    // Healthy paths the fix must not have broken:   2 + 2 + 2
    // Mid-result disconnects, five shapes:            3 + 3 + 3 + 3 + 3
    // Query-cache corollary:                          2
    // Truncated frame:                                3
    // Final pool cleanliness:                         1
    plan(27);

    if (cl.getEnv()) return exit_status();

    PGConnPtr adminOwner = createNewConnection(ConnType::ADMIN);
    if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
        BAIL_OUT("cannot proceed without an admin connection");
    PGconn* admin = adminOwner.get();

    // ---- save the runtime state we are about to change ---------------------
    const std::string saved_monitor = savedVar(admin, "pgsql-monitor_enabled");
    const std::string saved_shun    = savedVar(admin, "pgsql-shun_on_failures");
    const std::string saved_conn_to = savedVar(admin, "pgsql-connect_timeout_server_max");
    const std::string saved_thresh  = savedVar(admin, "pgsql-threshold_resultset_size");

    auto restore = [&]() {
        // The proxy may have died; one reconnect so cleanup still runs when it was
        // merely restarted underneath us. If it is really gone, say so once instead
        // of emitting a failed-admin line per statement -- every change this test
        // makes is in-memory only, so a restart clears all of it.
        if (adminScalar(admin, "SELECT 1") != "1") {
            adminOwner = createNewConnection(ConnType::ADMIN);
            if (adminOwner && PQstatus(adminOwner.get()) == CONNECTION_OK) {
                admin = adminOwner.get();
            } else {
                diag("restore: ProxySQL admin unreachable -- runtime state not restored. "
                     "All of it is in-memory only (never SAVE ... TO DISK), so restarting "
                     "the proxy clears it.");
                return;
            }
        }
        if (!saved_monitor.empty()) setVar(admin, "pgsql-monitor_enabled", saved_monitor);
        if (!saved_shun.empty())    setVar(admin, "pgsql-shun_on_failures", saved_shun);
        if (!saved_conn_to.empty()) setVar(admin, "pgsql-connect_timeout_server_max", saved_conn_to);
        if (!saved_thresh.empty())  setVar(admin, "pgsql-threshold_resultset_size", saved_thresh);

        std::stringstream dr;
        dr << "DELETE FROM pgsql_query_rules WHERE rule_id=" << CACHE_RULE_ID;
        execAdmin(admin, dr.str());
        execAdmin(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");

        execAdmin(admin, std::string("DELETE FROM pgsql_users WHERE username='") + MOCK_USER + "'");
        execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME");
        std::stringstream ds;
        ds << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << MOCK_HG;
        execAdmin(admin, ds.str());
        execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
    };

    // ---- preconditions -----------------------------------------------------
    if (!setVar(admin, "pgsql-monitor_enabled", "false"))
        BAIL_OUT("cannot disable the monitor");
    if (!setVar(admin, "pgsql-shun_on_failures", "10000"))
        BAIL_OUT("cannot raise shun_on_failures");
    setVar(admin, "pgsql-connect_timeout_server_max", "5000");

    // ---- start the mock and point ProxySQL at it ---------------------------
    // No set_scram_password(): the harness answers the startup packet with a
    // trust-style AuthenticationOk, so no backend credential is negotiated.
    // MOCK_PASS is still the FRONTEND credential ProxySQL authenticates the test
    // client with, registered in pgsql_users below.
    PgSQL_Mock_Backend mock;
    if (!mock.start()) { restore(); BAIL_OUT("mock backend failed to listen"); }

    g_mock_ip = pgmb_local_ip_towards(cl.pgsql_host, cl.pgsql_port);
    if (g_mock_ip.empty()) {
        mock.stop(); restore();
        BAIL_OUT("could not discover this container's IP toward ProxySQL");
    }
    g_mock_port = mock.port();
    diag("mock backend listening on %s:%u (hostgroup %d)", g_mock_ip.c_str(), g_mock_port, MOCK_HG);

    {
        std::stringstream d;
        d << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << MOCK_HG;
        execAdmin(admin, d.str());
        std::stringstream ins;
        ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) "
            << "VALUES (" << MOCK_HG << ",'" << g_mock_ip << "'," << g_mock_port
            << ",4,0,'mid-result disconnect mock')";
        if (!execAdmin(admin, ins.str()) || !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) {
            mock.stop(); restore(); BAIL_OUT("could not register the mock backend");
        }
        std::stringstream u;
        u << "INSERT OR REPLACE INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('"
          << MOCK_USER << "','" << MOCK_PASS << "',1," << MOCK_HG << ")";
        if (!execAdmin(admin, u.str()) || !execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME")) {
            mock.stop(); restore(); BAIL_OUT("could not register the mock user");
        }
        // Cache rule for the probe query only, scoped to this test's user so no
        // other traffic is affected.
        std::stringstream qr;
        qr << "INSERT OR REPLACE INTO pgsql_query_rules "
           << "(rule_id,active,username,match_pattern,cache_ttl,apply) VALUES ("
           << CACHE_RULE_ID << ",1,'" << MOCK_USER << "','midresultcacheprobe',10000,1)";
        if (!execAdmin(admin, qr.str()) || !execAdmin(admin, "LOAD PGSQL QUERY RULES TO RUNTIME")) {
            mock.stop(); restore(); BAIL_OUT("could not register the cache rule");
        }
    }
    usleep(300000);

    // ---- the scenarios -----------------------------------------------------
    //
    // Healthy paths FIRST. They are the ones the fix could have broken rather than
    // fixed, they cannot themselves crash the proxy, and running them before the
    // destructive scenarios means a later abort cannot mask their verdicts.

    runServedScenario(admin, adminOwner, mock,
                      "multi-statement chaining still works",
                      scriptServe(multiStatementBody("ms-one", "ms-two", 1, true)),
                      "SELECT 'ms-one'; SELECT 'ms-two'",
                      { "ms-one", "ms-two" });

    // A low threshold makes ProxySQL pause and return to the event loop mid-result.
    // Combined with multi-statement that puts a pause between fetch_result_start()
    // zeroing result_type and the point it is re-derived, with a PGresult pending
    // across it -- the sharpest case the reset had to survive.
    setVar(admin, "pgsql-threshold_resultset_size", "512");

    runServedScenario(admin, adminOwner, mock,
                      "multi-statement across resultset-threshold pauses",
                      scriptServe(multiStatementBody("mt-one", "mt-two", 200, true)),
                      "SELECT 'mt-one'; SELECT 'mt-two'",
                      { "mt-one", "mt-two" });

    runServedScenario(admin, adminOwner, mock,
                      "large result streamed across threshold pauses",
                      scriptServe(pgmb_simple_result("c", "big-row", 400)),
                      "SELECT 'bigresult'",
                      { "big-row" });

    // ---- mid-result disconnects --------------------------------------------
    // Production shape first: the one a real PostgreSQL produces.
    runDisconnectScenario(admin, adminOwner, mock,
                          "complete rows then FIN before CommandComplete",
                          scriptCompleteRowsThenFin(50));

    runDisconnectScenario(admin, adminOwner, mock,
                          "large result dies mid-stream under a low threshold",
                          scriptCompleteRowsThenFin(400));

    setVar(admin, "pgsql-threshold_resultset_size",
           saved_thresh.empty() ? "8192" : saved_thresh);

    // Dies after statement 1's CommandComplete: the disconnect lands while a
    // multi-statement chain is in flight, which is the case part A's
    // pgsql_result == NULL guard exists for.
    runDisconnectScenario(admin, adminOwner, mock,
                          "multi-statement dies between statements",
                          scriptServe(multiStatementBody("md-one", "md-two", 5, false)),
                          "SELECT 'md-one'; SELECT 'md-two'");

    // The only scenario that reaches assert(!is_copy_out).
    runDisconnectScenario(admin, adminOwner, mock,
                          "COPY TO STDOUT dies mid-copy",
                          scriptCopyOutThenFin(20),
                          "COPY (SELECT 1) TO STDOUT");

    runDisconnectScenario(admin, adminOwner, mock,
                          "huge declared length, 100 bytes, then silence",
                          scriptHugeDeclaredLenThenSilence());

    runCacheScenario(admin, adminOwner, mock);

    runDisconnectScenario(admin, adminOwner, mock,
                          "truncated DataRow then FIN",
                          scriptTruncatedRowThenFin());

    // ---- final pool cleanliness --------------------------------------------
    if (g_proxy_down) {
        ok(false,
           "no backend connections stranded after all scenarios: not assertable -- "
           "ProxySQL went down at '%s'", g_proxy_down_where.c_str());
    } else {
        usleep(1000000);
        const int leftover = mockPoolConns(admin);
        ok(leftover == 0,
           "no backend connections stranded in the mock hostgroup after all scenarios "
           "(found %d)", leftover);
    }

    mock.stop();
    restore();
    return exit_status();
}
