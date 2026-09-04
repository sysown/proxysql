/**
 * @file pgsql-native_hostile_backend-t.cpp
 * @brief Drives ProxySQL's native backend protocol against a deliberately
 *        hostile PostgreSQL server.
 *
 * PURPOSE
 * -------
 * Every other native-path test uses a healthy PostgreSQL as its oracle. That
 * leaves the entire error surface untested, because a real PostgreSQL never
 * sends a malformed frame, never forges an authentication signature, and never
 * disappears mid-result. This test supplies a backend that does all of those
 * things (see pgsql_mock_backend.h) and asserts ProxySQL survives them.
 *
 * The bar for every case is the same three invariants, checked after each:
 *   1. ProxySQL is still alive and its admin interface answers.
 *   2. The proxy still serves the REAL backend — a hostile connection must not
 *      poison unrelated traffic.
 *   3. No backend connections are left stranded in the mock's hostgroup pool.
 *
 * A case that produces a clean client error passes. A case that crashes, hangs,
 * or leaks fails. What the SQLSTATE happens to be is mostly not asserted — the
 * point is robustness, not a specific error string.
 *
 * ============================================================================
 *  EXPECTATIONS AND HONESTY
 * ============================================================================
 *  Most cases here are EXPLORATORY. Predictions exist for the framing and
 *  bounds cases; the response to a forged SCRAM signature, a stray second
 *  ReadyForQuery, or an idle-pool NotificationResponse is not known in advance.
 *  Any failure is a NEW FINDING, to be investigated and reported — never
 *  normalised away or relabelled flaky.
 *
 *  ONE CASE IS A PROBER, NOT A PROOF. Case R1 targets defect D4
 *  (lib/PgSQL_Connection.cpp:2201 returns -1 on EOF while ignoring `got`,
 *  discarding an already-framed complete result; the TLS branch at :2181
 *  correctly returns `got ? 1 : -1`). Triggering it requires the FINAL recv()
 *  to return exactly 16384 bytes, which a black-box test cannot arrange over
 *  TCP: ProxySQL wakes on the first readable segment (~1448 bytes over a Docker
 *  bridge), and any short read mid-stream destroys the alignment. R1 therefore
 *  retries a bounded number of times and reports
 *      "D4 not observed in N iterations"
 *  when it does not fire. That is NOT evidence the defect is absent — the same
 *  run against known-defective code can legitimately miss it. R1 must never be
 *  treated as a regression guard.
 *
 * INFRA
 * -----
 * legacy-g1 (docker-pgsql16-single). The mock listens inside the test-runner
 * container, which shares the Docker network with ProxySQL, and is registered
 * in pgsql_servers by its runtime-discovered IP.
 *
 * PRECONDITIONS (without these, cases fail for unrelated reasons)
 * ---------------------------------------------------------------
 * A backend that breaks handshakes on purpose trips two mechanisms that would
 * remove it from rotation before most cases run:
 *   - the Monitor shuns non-responsive servers (PgSQL_Monitor.cpp:1729), and it
 *     probes with libpq, which every hostile handshake defeats;
 *   - pgsql-shun_on_failures defaults to 5 (PgSQL_Thread.cpp:1042) and this
 *     file contains well over five deliberate failures.
 * Both are adjusted in memory for the duration. They are deliberately NOT
 * restored: proxysql-tester.py reloads every config table FROM DISK before each
 * test, so the isolation lives in the harness. Never SAVE ... TO DISK, which is
 * what would actually defeat it.
 */
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

#include "pgsql_mock_backend.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

// Hostgroup and user dedicated to the mock; kept away from the real backend's
// hostgroup 0 so a shunned/broken mock cannot affect normal traffic.
static const int MOCK_HG = 47;
static const char* MOCK_USER = "hostile_mock_user";
static const char* MOCK_PASS = "hostile_mock_pw";

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

static bool execAdmin(PGconn* admin, const std::string& q) {
    PGresult* r = PQexec(admin, q.c_str());
    ExecStatusType st = PQresultStatus(r);
    bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
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

// Backend connections currently held for the mock's hostgroup. Used as the
// leak invariant: a hostile case must not strand connections in the pool.
static int mockPoolConnsNow(PGconn* admin) {
    std::stringstream q;
    q << "SELECT IFNULL(SUM(ConnUsed + ConnFree),0) FROM stats_pgsql_connection_pool "
      << "WHERE hostgroup=" << MOCK_HG;
    const std::string v = adminScalar(admin, q.str());
    return v.empty() ? 0 : atoi(v.c_str());
}

// Settle before judging. ProxySQL retries a failing backend many times (10-20
// connects per hostile case were observed), and teardown of the last attempt
// can still be in flight when the client's error surfaces. Sampling the pool
// immediately reports connections that are on their way out as leaks. Poll to
// zero for a bounded window and report the last value seen.
// The pool drains ASYNCHRONOUSLY, and measurement showed the drain landing at
// ~2.0s -- which is exactly where the old 20*100ms budget expired. A case that
// drained on iteration 19 passed and one that needed iteration 21 failed, so the
// verdict flipped between runs of an identical binary (observed: R8/R14/R20).
// The budget must sit COMFORTABLY ABOVE the natural drain time, not on top of
// it. This does not weaken the assertion: a connection that is genuinely stranded
// still fails, it just takes longer to say so. `drain_ms` reports how long the
// drain actually took, so a future shift shows up as a number instead of a
// coin flip.
static int mockPoolConns(PGconn* admin, int* drain_ms = nullptr) {
    int last = mockPoolConnsNow(admin);
    int i = 0;
    for (; i < 100 && last != 0; i++) {   // up to ~10s
        usleep(100000);
        last = mockPoolConnsNow(admin);
    }
    if (drain_ms) *drain_ms = i * 100;
    return last;
}

// Drive one attempt through ProxySQL at the mock hostgroup. Returns true if the
// client got a usable answer; on failure `err` carries the client-visible error.
// Either outcome is acceptable for most cases — what matters is that this
// RETURNS AT ALL (no hang) and leaves the proxy healthy.
static bool queryThroughProxy(std::string& err, const char* query = "SELECT 1") {
    auto c = openConn(cl.pgsql_host, cl.pgsql_port, MOCK_USER, MOCK_PASS, "postgres");
    if (!c || PQstatus(c.get()) != CONNECTION_OK) {
        err = c ? PQerrorMessage(c.get()) : "null conn";
        return false;
    }
    PGresult* r = PQexec(c.get(), query);
    const ExecStatusType st = PQresultStatus(r);
    const bool good = (st == PGRES_TUPLES_OK || st == PGRES_COMMAND_OK);
    if (!good) err = PQerrorMessage(c.get());
    PQclear(r);
    return good;
}

// The three post-case invariants. Returns "" when healthy, else what broke.
static std::string checkInvariants(PGconn*& adminRef, PGConnPtr& adminOwner) {
    // 1. ProxySQL alive / admin answering. Reconnect once: a crashed proxy
    //    fails the reconnect too, so this does not mask a crash.
    if (adminScalar(adminRef, "SELECT 1") != "1") {
        adminOwner = createAdminConn();
        if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
            return "ProxySQL admin unreachable (proxy down?)";
        adminRef = adminOwner.get();
        if (adminScalar(adminRef, "SELECT 1") != "1")
            return "ProxySQL admin not answering";
    }
    // 2. The real backend still serves traffic through the proxy.
    {
        auto c = openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username,
                          cl.pgsql_password, cl.pgsql_username);
        if (!c || PQstatus(c.get()) != CONNECTION_OK)
            return "real-backend traffic broken after hostile case";
        PGresult* r = PQexec(c.get(), "SELECT 1");
        const bool good = (PQresultStatus(r) == PGRES_TUPLES_OK);
        PQclear(r);
        if (!good) return "real-backend query failed after hostile case";
    }
    return "";
}

// Drop every pooled backend connection for the mock hostgroup by removing and
// re-adding the server row.
//
// Without this, cases are not independent: a case whose handshake SUCCEEDS
// leaves a connection in the pool, and the next case may be served from it
// instead of opening a new one — so the next case's script never runs and its
// result describes the previous case's connection. Relying on the mock closing
// each connection would leave that to timing.
static bool resetMockPool(PGconn* admin, const std::string& ip, uint16_t port) {
    std::stringstream del;
    del << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << MOCK_HG;
    if (!execAdmin(admin, del.str()) || !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
        return false;
    std::stringstream ins;
    ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) "
        << "VALUES (" << MOCK_HG << ",'" << ip << "'," << port << ",4,0,'hostile mock backend')";
    if (!execAdmin(admin, ins.str()) || !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
        return false;
    usleep(150000);
    return true;
}

// Set by main() once the mock is listening, so runCase can flush the pool.
static std::string g_mock_ip;
static uint16_t g_mock_port = 0;

// Run one hostile case end to end and emit exactly one TAP assertion.
static void runCase(PGconn*& admin, PGConnPtr& adminOwner, PgSQL_Mock_Backend& mock,
                    const char* label, const std::vector<Step>& script,
                    const char* query = "SELECT 1") {
    resetMockPool(admin, g_mock_ip, g_mock_port);
    mock.set_script(script);
    mock.reset_stats();

    std::string clierr;
    const bool served = queryThroughProxy(clierr, query);   // must simply RETURN

    const std::string broke = checkInvariants(admin, adminOwner);
    int drain_ms = 0;
    const int stranded = mockPoolConns(admin, &drain_ms);

    // Trim the client error to one line for readable TAP output.
    std::string first_line = clierr.substr(0, clierr.find('\n'));

    ok(broke.empty() && stranded == 0,
       "%s: proxy survived (client %s: %s; mock conns=%d; pool leftover=%d; drain=%dms)%s%s",
       label,
       served ? "served" : "errored",
       first_line.empty() ? "-" : first_line.c_str(),
       mock.connections_accepted(), stranded, drain_ms,
       broke.empty() ? "" : " -- BROKE: ", broke.c_str());
}

// ------------------------------------------------------------- script pieces

// Handshake prefix that gets the mock to a ready-for-query state.
static std::string acceptedHandshake() {
    return pgmb_auth_ok() +
           pgmb_parameter_status("server_version", "16.2") +
           pgmb_parameter_status("client_encoding", "UTF8") +
           pgmb_backend_key_data(4242, 987654321) +
           pgmb_ready_for_query('I');
}

// ---------------------------------------------------------------- harness
// Six checks on the MOCK itself, using libpq as an independent oracle, before
// a single verdict is passed on ProxySQL.
//
// This has to come first. The cases below judge ProxySQL against fixtures this
// harness produces; if a fixture were wrong the verdict would be confident
// nonsense. A9 is the sharp example: it asserts ProxySQL REJECTS a forged SCRAM
// server signature, so if the mock's "forged" signature were accidentally
// VALID, A9 would pass no matter what ProxySQL did. libpq is the natural
// oracle -- an independent, widely deployed SCRAM client that verifies server
// signatures. Pointing it at the mock tests the mock, not the proxy.
//
// Folded in from the former pgsql-native_mock_selftest-t: a broken harness must
// surface before the results that depend on it, not in a separate test that may
// run later or not at all.
static PGconn* selftestConnect(uint16_t port, const char* pw) {
    std::stringstream ss;
    ss << "host=127.0.0.1 port=" << port << " user=mockuser password=" << pw
       << " dbname=postgres sslmode=disable connect_timeout=5";
    return PQconnectdb(ss.str().c_str());
}

static void harness_selftest() {
    PgSQL_Mock_Backend mock;
    mock.set_scram_password("mockpw");
    if (!mock.start()) BAIL_OUT("harness self-test: mock backend failed to listen on loopback");
    diag("harness self-test: mock listening on 127.0.0.1:%u", mock.port());

    // 1/2. Trust handshake plus a canned result: the framing, the startup
    // exchange and the result builders are all wire-legal to a real client.
    mock.set_script({ step_expect_startup(), step_send(acceptedHandshake()),
                      step_expect_message(), step_send(pgmb_simple_result("c", "1", 1)),
                      step_sleep(200) });
    {
        PGconn* c = selftestConnect(mock.port(), "mockpw");
        const bool connected = (PQstatus(c) == CONNECTION_OK);
        ok(connected, "harness: libpq completes the mock's trust handshake%s%s",
           connected ? "" : ": ", connected ? "" : PQerrorMessage(c));
        if (connected) {
            PGresult* r = PQexec(c, "SELECT 1");
            ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 && PQnfields(r) == 1,
               "harness: libpq parses the mock's canned RowDescription/DataRow/CommandComplete/ReadyForQuery");
            PQclear(r);
        } else {
            ok(false, "harness: skipped result parse -- handshake did not complete");
        }
        PQfinish(c);
    }

    // 3. Honest SCRAM-SHA-256: proves the mock's server-side key derivation.
    mock.set_script({ step_expect_startup(),
                      step_send(pgmb_auth_sasl({ "SCRAM-SHA-256" })),
                      step_scram_server_first(false),
                      step_scram_server_final(false),
                      step_send(acceptedHandshake()),
                      step_sleep(200) });
    {
        PGconn* c = selftestConnect(mock.port(), "mockpw");
        const bool connected = (PQstatus(c) == CONNECTION_OK);
        ok(connected, "harness: libpq authenticates against the mock's honest SCRAM-SHA-256 exchange%s%s",
           connected ? "" : ": ", connected ? "" : PQerrorMessage(c));
        PQfinish(c);
    }

    // 4. Forged server signature. libpq MUST reject it -- this is what makes
    // A9 below a real assertion rather than a formality.
    mock.set_script({ step_expect_startup(),
                      step_send(pgmb_auth_sasl({ "SCRAM-SHA-256" })),
                      step_scram_server_first(false),
                      step_scram_server_final(true),          // forged
                      step_send(acceptedHandshake()),         // then pretend all is well
                      step_sleep(200) });
    {
        PGconn* c = selftestConnect(mock.port(), "mockpw");
        const bool rejected = (PQstatus(c) != CONNECTION_OK);
        const std::string why = rejected ? PQerrorMessage(c) : "";
        ok(rejected,
           "harness: libpq REJECTS the mock's forged SCRAM server signature (makes A9 meaningful): %s",
           rejected ? why.substr(0, why.find('\n')).c_str()
                    : "ACCEPTED -- forgery is not detectable, A9 is void");
        PQfinish(c);
    }

    // 5. Server nonce that does not extend the client nonce (reference for A10).
    mock.set_script({ step_expect_startup(),
                      step_send(pgmb_auth_sasl({ "SCRAM-SHA-256" })),
                      step_scram_server_first(true),          // bad nonce
                      step_sleep(200) });
    {
        PGconn* c = selftestConnect(mock.port(), "mockpw");
        const bool rejected = (PQstatus(c) != CONNECTION_OK);
        ok(rejected, "harness: libpq REJECTS a server nonce that does not extend the client nonce (makes A10 meaningful)");
        PQfinish(c);
    }

    // 6. The exact-size builder the R1 D4 prober depends on. Off by one byte
    // and the prober can never hit its trigger condition.
    {
        std::string body;
        const size_t target = 16384 * 4;
        const bool built = pgmb_result_of_exact_size(body, target);
        ok(built && body.size() == target,
           "harness: exact-size result builder produces precisely %zu bytes (got %zu)",
           target, body.size());
    }

    mock.stop();
}

int main(int, char**) {
    // 6 harness self-test cases (the mock, judged by libpq)
    // + 18 auth cases (A1-A18; A8 and A17 are positive controls)
    // + 21 result cases (R1-R22, minus R17) + 1 final pool-cleanliness assertion.
    plan(46);

    if (cl.getEnv()) return exit_status();

    // Validate the harness before judging ProxySQL with it. A broken fixture
    // would make every verdict below meaningless -- see harness_selftest().
    harness_selftest();

    PGConnPtr adminOwner = createAdminConn();
    if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
        BAIL_OUT("cannot proceed without an admin connection");
    PGconn* admin = adminOwner.get();

    // ---- preconditions -----------------------------------------------------
    // See the file header: without these the mock is shunned part-way through
    // and the remaining cases never reach it.
    if (!setVar(admin, "pgsql-monitor_enabled", "false")) BAIL_OUT("cannot disable the monitor");
    if (!setVar(admin, "pgsql-shun_on_failures", "10000")) BAIL_OUT("cannot raise shun_on_failures");
    // Bound the wait on cases where the mock deliberately stops responding, so
    // a hang shows up as a failed case rather than a hung test run.
    setVar(admin, "pgsql-connect_timeout_server_max", "5000");
    // The native path is what this suite exists to exercise.
    //
    // When investigating a failure it is worth running the SAME corpus against the
    // libpq path -- flip pgsql-use_native_backend_protocol to 'false' below and diff
    // the two runs. That answers "is this native-specific, or does the shipped libpq
    // path do the same?", which is how #6109 and #6110 were established as
    // pre-existing v3.0 defects rather than native regressions. It is a debugging
    // technique, not something CI needs to toggle, so it is a one-line edit here
    // rather than a knob.
    if (!setVar(admin, "pgsql-use_native_backend_protocol", "true"))
        BAIL_OUT("cannot enable the native backend protocol");

    // ---- start the mock and point ProxySQL at it ---------------------------
    PgSQL_Mock_Backend mock;
    mock.set_scram_password(MOCK_PASS);
    if (!mock.start()) BAIL_OUT("mock backend failed to listen");

    const std::string myip = pgmb_local_ip_towards(cl.pgsql_host, cl.pgsql_port);
    if (myip.empty()) { BAIL_OUT("could not discover this container's IP toward ProxySQL"); }
    diag("mock backend listening on %s:%u (hostgroup %d)", myip.c_str(), mock.port(), MOCK_HG);
    g_mock_ip = myip;
    g_mock_port = mock.port();

    {
        std::stringstream q;
        q << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << MOCK_HG << ";";
        execAdmin(admin, q.str());
        std::stringstream ins;
        ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) "
            << "VALUES (" << MOCK_HG << ",'" << myip << "'," << mock.port() << ",4,0,'hostile mock backend')";
        if (!execAdmin(admin, ins.str()) || !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) {
            BAIL_OUT("could not register the mock backend");
        }
        std::stringstream u;
        u << "INSERT OR REPLACE INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('"
          << MOCK_USER << "','" << MOCK_PASS << "',1," << MOCK_HG << ")";
        if (!execAdmin(admin, u.str()) || !execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME")) {
            BAIL_OUT("could not register the mock user");
        }
    }
    usleep(300000);

    // ======================================================================
    //  AUTH-PHASE CASES
    // ======================================================================

    // A1: ErrorResponse where an Authentication message belongs. The backend's
    // error fields should reach the client rather than a generic failure.
    runCase(admin, adminOwner, mock, "A1 ErrorResponse instead of Authentication",
        { step_expect_startup(),
          step_send(pgmb_error_response("28000", "mock: no such role")),
          step_close() });

    // A2: a message type that has no meaning during authentication.
    runCase(admin, adminOwner, mock, "A2 unexpected message type during auth",
        { step_expect_startup(),
          step_send(pgmb_command_complete("SELECT 1")),   // 'C' out of nowhere
          step_close() });

    // A3: Authentication message too short to hold its own subtype code.
    runCase(admin, adminOwner, mock, "A3 Authentication payload shorter than 4 bytes",
        { step_expect_startup(),
          step_send(std::string("R") + pgmb_be32(6) + "xx"),   // len 6 => 2-byte payload
          step_close() });

    // A4: AuthenticationMD5Password promising a salt it does not supply.
    runCase(admin, adminOwner, mock, "A4 md5 challenge with a truncated salt",
        { step_expect_startup(),
          step_send(pgmb_auth_raw(5, "ab")),               // 2 salt bytes, needs 4
          step_close() });

    // A5/A6: mechanisms the native path cannot do. Per design section 4 these
    // are capability gaps: tear down, fall back to libpq, log once. libpq will
    // also fail against the mock, so what is asserted is that ProxySQL handles
    // it without crashing or hanging.
    runCase(admin, adminOwner, mock, "A5 GSSAPI challenge (capability gap)",
        { step_expect_startup(), step_send(pgmb_auth_raw(7, "")), step_close() });
    runCase(admin, adminOwner, mock, "A6 undefined authentication subtype",
        { step_expect_startup(), step_send(pgmb_auth_raw(99, "")), step_close() });

    // A7: SASL offered with an empty mechanism list.
    runCase(admin, adminOwner, mock, "A7 SASL with an empty mechanism list",
        { step_expect_startup(), step_send(pgmb_auth_sasl({})), step_close() });

    // A8 (positive control): a full, HONEST SCRAM-SHA-256 exchange. This must
    // succeed. Without it, A9's rejection could be caused by anything at all —
    // this is what makes A9 a statement about signature verification.
    {
        std::vector<Step> s = {
            step_expect_startup(),
            step_send(pgmb_auth_sasl({ "SCRAM-SHA-256" })),
            step_scram_server_first(false),
            step_scram_server_final(false),
            step_send(acceptedHandshake()),
            step_expect_query(),                            // the Query
            step_send(pgmb_simple_result("c", "1", 1)),
            step_sleep(300)
        };
        mock.set_script(s);
        mock.reset_stats();
        std::string err;
        const bool served = queryThroughProxy(err);
        ok(served, "A8 control: honest SCRAM-SHA-256 exchange authenticates and serves a result%s%s",
           served ? "" : " -- ", served ? "" : err.substr(0, err.find('\n')).c_str());
    }

    // A9 (SECURITY): the server returns a SCRAM final message whose signature it
    // could not have computed without the shared secret. ProxySQL verifies it
    // via pg_scram_verify_server_final() — the sole defence against a spoofed or
    // MITM'd backend. Accepting this would mean authenticating to any server
    // that merely claims to be the right one.
    {
        std::vector<Step> s = {
            step_expect_startup(),
            step_send(pgmb_auth_sasl({ "SCRAM-SHA-256" })),
            step_scram_server_first(false),
            step_scram_server_final(true),                  // forged signature
            step_send(acceptedHandshake()),                 // pretend all is well
            step_expect_query(),
            step_send(pgmb_simple_result("c", "1", 1)),
            step_sleep(300)
        };
        mock.set_script(s);
        mock.reset_stats();
        std::string err;
        const bool served = queryThroughProxy(err);
        ok(!served,
           "A9 SECURITY: forged SCRAM server signature must be REJECTED "
           "(served=%s) -- a served result means server impersonation succeeds",
           served ? "YES (BAD)" : "no");
    }

    // A10: server nonce that does not extend the client nonce (RFC 5802 breach).
    {
        std::vector<Step> s = {
            step_expect_startup(),
            step_send(pgmb_auth_sasl({ "SCRAM-SHA-256" })),
            step_scram_server_first(true),                  // bad nonce
            step_sleep(300),
            step_close()
        };
        mock.set_script(s);
        mock.reset_stats();
        std::string err;
        const bool served = queryThroughProxy(err);
        ok(!served, "A10 SECURITY: server nonce not extending the client nonce must be rejected (served=%s)",
           served ? "YES (BAD)" : "no");
    }

    // A11/A12: disappearing mid-handshake.
    runCase(admin, adminOwner, mock, "A11 FIN immediately after the startup packet",
        { step_expect_startup(), step_close() });
    runCase(admin, adminOwner, mock, "A12 FIN after AuthenticationOk, before ReadyForQuery",
        { step_expect_startup(), step_send(pgmb_auth_ok()), step_close() });

    // A13: the whole handshake delivered one byte per write, so every length
    // field is split across reads.
    runCase(admin, adminOwner, mock, "A13 handshake delivered one byte at a time",
        { step_expect_startup(),
          step_send(acceptedHandshake(), /*chunk*/1, /*delay_us*/200),
          step_expect_query(),
          step_send(pgmb_simple_result("c", "1", 1), 1, 200),
          step_sleep(300) });

    // ---- A14-A18: branches of native_drive_auth() that a real PostgreSQL
    // cannot produce, so only the mock can reach them. ----------------------

    // A14: SCRAM-SHA-256-PLUS advertised as the ONLY mechanism, over a PLAINTEXT
    // connection. Channel binding has no meaning without TLS, so mechanism
    // selection (lib/PgSQL_Connection.cpp:2345) must take the capability-gap exit
    // rather than try to derive a tls-server-end-point digest from a NULL SSL*.
    // The libpq fallback that follows then fails against the mock, which is fine —
    // what is under test is that the proxy chooses the gap and survives.
    runCase(admin, adminOwner, mock, "A14 SCRAM-SHA-256-PLUS offered alone over plaintext",
        { step_expect_startup(),
          step_send(pgmb_auth_sasl({ "SCRAM-SHA-256-PLUS" })),
          step_sleep(300),
          step_close() });

    // A15/A16: SASL continuation messages with no SASL exchange ever started, so
    // native_scram is NULL. Both guards (:2410 and :2440) must reject cleanly
    // rather than dereference it.
    runCase(admin, adminOwner, mock, "A15 AuthenticationSASLContinue with no SASL exchange started",
        { step_expect_startup(),
          step_send(pgmb_auth_sasl_continue("r=nonce,s=c2FsdA==,i=4096")),
          step_close() });
    runCase(admin, adminOwner, mock, "A16 AuthenticationSASLFinal with no SASL exchange started",
        { step_expect_startup(),
          step_send(pgmb_auth_sasl_final("v=bm90YXNpZ25hdHVyZQ==")),
          step_close() });

    // A17 (positive control): a NoticeResponse arriving mid-authentication must be
    // IGNORED and the handshake must still complete (lib/PgSQL_Connection.cpp:2270).
    // Asserting survival alone would pass even if the notice aborted the login, so
    // this one asserts the query is actually SERVED.
    {
        // NoticeResponse payload: (field-type byte + NUL-terminated value)*, then a
        // single 0 byte. Built here rather than with ProxySQL's own encoder, per
        // the harness's independence rule.
        std::string notice;
        {
            std::string payload;
            payload += 'S'; payload += "NOTICE"; payload += '\0';
            payload += 'C'; payload += "00000";  payload += '\0';
            payload += 'M'; payload += "mid-auth notice"; payload += '\0';
            payload += '\0';
            pgmb_append_msg(notice, 'N', payload);
        }
        std::vector<Step> s = {
            step_expect_startup(),
            step_send(notice + acceptedHandshake()),
            step_expect_query(),
            step_send(pgmb_simple_result("c", "1", 1)),
            step_sleep(300)
        };
        resetMockPool(admin, g_mock_ip, g_mock_port);
        mock.set_script(s);
        mock.reset_stats();
        std::string err;
        const bool served = queryThroughProxy(err);
        ok(served, "A17 control: NoticeResponse during auth is ignored and the handshake completes%s%s",
           served ? "" : " -- ", served ? "" : err.substr(0, err.find('\n')).c_str());
    }

    // A18: a mechanism list whose final name is NOT NUL-terminated — the payload
    // simply ends mid-name. The scan at :2331 bounds each name with
    // strnlen(mech, rest_len - i), so the walk must stop at the payload end
    // instead of reading past it. Under ASAN a regression here is a heap
    // buffer-overflow read, not merely a wrong answer.
    runCase(admin, adminOwner, mock, "A18 SASL mechanism name not NUL-terminated",
        { step_expect_startup(),
          step_send(pgmb_auth_raw(10, "SCRAM-SHA-256")),   // no trailing NUL, no list terminator
          step_close() });

    // ======================================================================
    //  RESULT-PHASE CASES  (handshake accepted, then hostile result bytes)
    // ======================================================================

    // R1: defect D4 prober. See the header — bounded retries, cannot prove
    // absence. A large exact-multiple-of-16384 response followed by FIN.
    {
        // Every runCase() starts by flushing and re-registering the mock server;
        // R1/R2 are hand-rolled and skipped it, so they inherited whatever state the
        // ~18 hostile AUTH cases left -- including a SHUNNED server. The auth cases
        // trip the shun threshold (which is min(shun_on_failures,
        // connect_retries_on_failure + 1) = 11, so raising shun_on_failures alone
        // cannot prevent it) and the shun lasts shun_recovery_time_sec = 10s. R1/R2
        // run inside that window and fail with "Hostgroup has no servers available",
        // which reads exactly like a mid-result regression but is not one.
        resetMockPool(admin, g_mock_ip, g_mock_port);
        const size_t CHUNKSZ = 16384;
        const size_t TARGET = CHUNKSZ * 64;                 // 1 MiB, exact multiple
        std::string body;
        bool built = pgmb_result_of_exact_size(body, TARGET);
        int hits = 0, iterations = 0;
        const int MAX_ITER = 50;
        if (built) {
            for (; iterations < MAX_ITER; iterations++) {
                mock.set_script({ step_expect_startup(),
                                  step_send(acceptedHandshake()),
                                  step_expect_query(),
                                  step_send(body),
                                  step_close() });
                std::string err;
                if (!queryThroughProxy(err)) {
                    if (err.find("backend closed during result fetch") != std::string::npos ||
                        err.find("closed during result fetch") != std::string::npos) {
                        hits++;
                        diag("D4 HIT on iteration %d: %s", iterations,
                             err.substr(0, err.find('\n')).c_str());
                        break;
                    }
                }
            }
        }
        if (!built) {
            ok(false, "R1 D4 prober: could not build an exact-size response of %zu bytes", TARGET);
        } else if (hits > 0) {
            ok(false,
               "R1 D4 CONFIRMED after %d iterations: a fully-delivered %zu-byte result was "
               "reported as 'backend closed during result fetch' "
               "[PgSQL_Connection.cpp:2201 returns -1 ignoring `got`; TLS branch at :2181 does not]",
               iterations + 1, TARGET);
        } else {
            // Not a pass claim about the code — a statement about this run.
            ok(true, "R1 D4 not observed in %d iterations (NOT evidence of absence; "
                     "the trigger needs the final recv() to return exactly %zu bytes, "
                     "which is not controllable over TCP)", MAX_ITER, CHUNKSZ);
        }
    }

    // R2 (control for R1): one byte over the multiple. Must be served cleanly.
    {
        // Same reason as R1 above: clear any shun left by the preceding cases.
        resetMockPool(admin, g_mock_ip, g_mock_port);
        std::string body;
        if (pgmb_result_of_exact_size(body, 16384 * 64 + 1)) {
            mock.set_script({ step_expect_startup(), step_send(acceptedHandshake()),
                              step_expect_query(), step_send(body), step_close() });
            std::string err;
            const bool served = queryThroughProxy(err);
            ok(served, "R2 control: non-multiple-sized result delivered before FIN%s%s",
               served ? "" : " -- ", served ? "" : err.substr(0, err.find('\n')).c_str());
        } else {
            ok(false, "R2 control: could not build the control response");
        }
    }

    // R3: a DataRow that promises more bytes than the server ever sends.
    runCase(admin, adminOwner, mock, "R3 truncated DataRow then FIN",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_row_description_1col("c", 25) +
                    std::string("D") + pgmb_be32(1000) + "only-a-few-bytes"),
          step_close() });

    // R4: a message declaring nearly a gigabyte, then silence. Must not buffer
    // toward the declared size, and must give up rather than wait forever.
    runCase(admin, adminOwner, mock, "R4 900MB declared length, 100 bytes sent, then silence",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(std::string("D") + pgmb_be32(900u * 1024 * 1024) + std::string(100, 'x')),
          step_sleep(6000), step_close() });

    // R5: declared length below the 4-byte minimum, mid-result.
    runCase(admin, adminOwner, mock, "R5 malformed frame (declared length 2) mid-result",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_row_description_1col("c", 25) +
                    std::string("D") + pgmb_be32(2)),
          step_sleep(300), step_close() });

    // R6: a message type with no backend-direction meaning, mid-result.
    runCase(admin, adminOwner, mock, "R6 unrecognised message type mid-result",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_row_description_1col("c", 25) +
                    pgmb_data_row_1col("1")),
          step_send(std::string("\x7f") + pgmb_be32(8) + "abcd"),   // bogus type
          step_send(pgmb_command_complete("SELECT 1") + pgmb_ready_for_query('I')),
          step_sleep(300) });

    // R7: a second ReadyForQuery after the result is complete. The drain stops
    // at the first 'Z', so the stray bytes stay buffered on a connection that
    // returns to the pool — the NEXT query on it is the real test.
    runCase(admin, adminOwner, mock, "R7 stray extra ReadyForQuery poisoning the next query",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_simple_result("c", "1", 1) + pgmb_ready_for_query('I')),
          step_expect_query(),
          step_send(pgmb_simple_result("c", "2", 1)),
          step_sleep(300) },
        "SELECT 1");

    // R8: ErrorResponse whose final field value has no NUL and no terminator.
    runCase(admin, adminOwner, mock, "R8 ErrorResponse with an unterminated field value",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_error_response_unterminated("42P01") + pgmb_ready_for_query('I')),
          step_sleep(300) });

    // R9: ParameterStatus with no NUL terminators — the mid-session tracking
    // path parses these into native_params (PgSQL_Protocol.cpp:2939).
    runCase(admin, adminOwner, mock, "R9 ParameterStatus with unterminated strings",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(std::string("S") + pgmb_be32(4 + 11) + "no_nul_here"),
          step_send(pgmb_simple_result("c", "1", 1)),
          step_sleep(300) });

    // R10: an entire result delivered one byte per write.
    runCase(admin, adminOwner, mock, "R10 result delivered one byte at a time",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_simple_result("c", "hello", 3), 1, 100),
          step_sleep(500) });

    // R11: an asynchronous NotificationResponse arriving while the connection
    // sits idle in the pool, followed by a query from a DIFFERENT client. The
    // stray 'A' is buffered on the pooled connection; whether it reaches a
    // client that never issued LISTEN is the question.
    runCase(admin, adminOwner, mock, "R11 NotificationResponse while idle in the pool",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_simple_result("c", "1", 1)),
          step_send(pgmb_notification_response(4242, "unlistened_channel", "surprise")),
          step_expect_query(),
          step_send(pgmb_simple_result("c", "2", 1)),
          step_sleep(300) });

    // R12: the length field claims the message is longer than the framer's
    // 1 GiB ceiling (PGSQL_MAX_BACKEND_MSG_LEN). Must be rejected as malformed
    // rather than trusted into an enormous allocation.
    runCase(admin, adminOwner, mock, "R12 declared length above the 1 GiB framer cap",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(std::string("D") + pgmb_be32(0x40000001u) + std::string(64, 'x')),
          step_sleep(300), step_close() });

    // R13: a DataRow claiming more columns than it supplies. The framing is
    // valid; only the payload is internally inconsistent, so this reaches any
    // code that parses row structure rather than just forwarding bytes.
    runCase(admin, adminOwner, mock, "R13 DataRow claiming more columns than it carries",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_row_description_1col("c", 25) +
                    std::string("D") + pgmb_be32(4 + 2 + 4) + pgmb_be16(99) + pgmb_be32(0xffffffffu) +
                    pgmb_command_complete("SELECT 1") + pgmb_ready_for_query('I')),
          step_sleep(300) });

    // R14: a field length that overruns its own message. A parser that trusts
    // the field length without bounding it against payload_len over-reads here.
    runCase(admin, adminOwner, mock, "R14 DataRow field length overruns the message",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_row_description_1col("c", 25) +
                    std::string("D") + pgmb_be32(4 + 2 + 4 + 2) + pgmb_be16(1) + pgmb_be32(9999) + "ab" +
                    pgmb_command_complete("SELECT 1") + pgmb_ready_for_query('I')),
          step_sleep(300) });

    // R15: RowDescription announcing far more columns than it describes.
    runCase(admin, adminOwner, mock, "R15 RowDescription with a lying column count",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(std::string("T") + pgmb_be32(4 + 2) + pgmb_be16(500) +
                    pgmb_command_complete("SELECT 0") + pgmb_ready_for_query('I')),
          step_sleep(300) });

    // R16: ReadyForQuery carrying an undefined transaction-status byte. Valid
    // values are 'I', 'T', 'E'; the byte is cached as the connection's txn state
    // and drives pooling decisions.
    runCase(admin, adminOwner, mock, "R16 ReadyForQuery with an invalid status byte",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_row_description_1col("c", 25) + pgmb_data_row_1col("1") +
                    pgmb_command_complete("SELECT 1")),
          step_send(std::string("Z") + pgmb_be32(5) + "X"),
          step_sleep(300) });

    // R18: CommandComplete whose tag has no NUL terminator. The tag is parsed
    // for the affected-rows count (PgSQL_Protocol.cpp ~2893).
    runCase(admin, adminOwner, mock, "R18 CommandComplete tag without a NUL terminator",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(std::string("C") + pgmb_be32(4 + 8) + "INSERT 9" +
                    pgmb_ready_for_query('I')),
          step_sleep(300) });

    // R19: a CommandComplete tag whose trailing number is far wider than 64
    // bits, exercising the strtoull path that produces affected_rows.
    runCase(admin, adminOwner, mock, "R19 CommandComplete with an absurd row count",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_command_complete("INSERT 0 999999999999999999999999999999") +
                    pgmb_ready_for_query('I')),
          step_sleep(300) });

    // R20: CopyInResponse arriving where the native drive cannot supply
    // CopyData. There is an explicit CopyFail safety net for this
    // (PgSQL_Connection.cpp ~2830) that no test reaches with a real backend.
    runCase(admin, adminOwner, mock, "R20 unexpected CopyInResponse (CopyFail safety net)",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(std::string("G") + pgmb_be32(4 + 1 + 2) + std::string(1, '\0') + pgmb_be16(0)),
          step_expect_message(),                    // the CopyFail ProxySQL should send
          step_send(pgmb_error_response("57014", "COPY aborted by client") +
                    pgmb_ready_for_query('I')),
          step_sleep(300) });

    // R21: an unsolicited NoticeResponse burst before the result. Notices are
    // legal at any time and must not be mistaken for the result stream.
    runCase(admin, adminOwner, mock, "R21 notice burst before the result",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_error_response("00000", "notice one").replace(0, 1, "N") +
                    pgmb_error_response("00000", "notice two").replace(0, 1, "N") +
                    pgmb_simple_result("c", "1", 1)),
          step_sleep(300) });

    // R22: the backend answers a query with nothing but ReadyForQuery — no
    // RowDescription, no CommandComplete. The result is "complete" by the
    // drain's rule ('Z' seen) yet carries no command outcome.
    runCase(admin, adminOwner, mock, "R22 bare ReadyForQuery as the whole result",
        { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
          step_send(pgmb_ready_for_query('I')),
          step_sleep(300) });

    // ---- final pool cleanliness -------------------------------------------
    // Every hostile connection above should have been torn down. Anything still
    // held in the mock's hostgroup after all of it is a connection leak.
    usleep(1000000);
    {
        const int leftover = mockPoolConns(admin);
        ok(leftover == 0,
           "no backend connections stranded in the mock hostgroup after all hostile cases (found %d)",
           leftover);
    }

    mock.stop();
    return exit_status();
}
