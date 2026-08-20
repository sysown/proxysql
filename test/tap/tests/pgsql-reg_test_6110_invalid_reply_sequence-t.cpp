/**
 * @file pgsql-reg_test_6110_invalid_reply_sequence-t.cpp
 * @brief Regression test for issue #6110 - a backend reply sequence with no command
 *        outcome must not abort ProxySQL.
 *
 * A backend can answer a query with only ReadyForQuery: no CommandComplete, no
 * EmptyQueryResponse, no ErrorResponse. Nothing about that message is malformed -
 * the 'Z' is correctly framed with a valid transaction-status byte, and no bounds
 * or length check would reject it. What is invalid is the SEQUENCE: the protocol
 * requires a command outcome before ReadyForQuery, and even an empty query string
 * produces EmptyQueryResponse. It is a protocol state-machine violation, not a
 * framing one.
 *
 * ProxySQL used to abort on it. The code assumed that reaching the end of the
 * result cycle with no command outcome implied an error had been recorded on an
 * earlier call, and asserted otherwise - which holds when ProxySQL itself failed,
 * but not when the backend simply replies in an invalid sequence. An assert()
 * cannot validate a fact this process does not control.
 *
 * A healthy PostgreSQL never sends this, so the reply has to come from a
 * scriptable fake backend (pgsql_mock_backend.h).
 *
 * ASSERTED -- PART 1, the violation
 * ---------------------------------
 *   1. ProxySQL is still alive and still serving the REAL backend.
 *   2. The client receives an ERROR - not a hang, and not a silent success.
 *   3. The scenario actually ran: the mock took delivery of the query and sent the
 *      invalid reply. Without this, a fixture that never routed anything to the mock
 *      produces the same error and the same empty pool as a correct outcome.
 *   4. The BACKEND CONNECTION is destroyed - not pooled, and not reset back into
 *      service. Asserted while the mock still holds that socket OPEN, so ordinary
 *      EOF cleanup cannot account for the connection being gone. Checked BEFORE 5,
 *      because that one can wait seconds and a mock that closed in the meantime
 *      would make this pass for the wrong reason.
 *   5. The SESSION is closed. A reply we cannot interpret leaves ProxySQL unable to
 *      vouch for the session's protocol state.
 *
 * ASSERTED -- PART 2, regressions
 * -------------------------------
 * The 'healthy' checks added for this fix sit on the ordinary teardown path of
 * EVERY connection, so the far bigger risk is over-reach. None of these involve
 * the mock:
 *   6. An ordinary SQL error does NOT close the session or condemn its connection -
 *      a failing query followed by a working one on the SAME connection.
 *   7. Healthy connections are still returned to the pool (the guard added to
 *      PgSQL_Data_Stream::reset_connection).
 *   8. Connections that need a reset are still reset rather than destroyed (the
 *      guard added to destroy_MySQL_Connection_From_Pool's reset branch), driven by
 *      disconnecting with a transaction still open.
 *   9. ProxySQL and the real backend are still healthy after all of it.
 *
 * NO HANGS
 * --------
 * driveQuery() drives libpq asynchronously against a wall-clock deadline, so a
 * proxy that neither answers nor errors is a reportable outcome (TIMED_OUT) rather
 * than a test that blocks until the harness timeout.
 *
 * INFRA
 * -----
 * legacy-g1 (docker-pgsql16-single). The mock listens inside the test-runner
 * container, which shares the Docker network with ProxySQL, and is registered in
 * pgsql_servers by its runtime-discovered IP.
 *
 * PRECONDITIONS
 * -------------
 * The Monitor shuns non-responsive servers and probes with libpq, so it is
 * disabled for the duration, along with a raised pgsql-shun_on_failures. Both are
 * restored at the end, IN MEMORY ONLY - never SAVE ... TO DISK, per project rule.
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
// hostgroup 0 so a misbehaving mock cannot affect normal traffic.
static const int MOCK_HG = 49;
static const char* MOCK_USER = "replyseq_mock_user";
static const char* MOCK_PASS = "replyseq_mock_pw";

// Bounded wait for the client query, so a proxy that spins rather than answering is
// reported instead of hanging the run.
static const int QUERY_DEADLINE_MS = 15000;

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

// A counter from stats_pgsql_global. Returns -1 when absent so a renamed metric
// shows up as a failed assertion rather than a silently-zero comparison.
static long long globalStat(PGconn* admin, const char* name) {
    const std::string v = adminScalar(admin,
        std::string("SELECT Variable_Value FROM stats_pgsql_global WHERE Variable_Name='") + name + "'");
    return v.empty() ? -1 : atoll(v.c_str());
}

// Backend connections held for every hostgroup EXCEPT the mock's, i.e. the real
// PostgreSQL. Used to show that ordinary traffic still pools normally.
static int realPoolConns(PGconn* admin) {
    std::stringstream q;
    q << "SELECT IFNULL(SUM(ConnUsed + ConnFree),0) FROM stats_pgsql_connection_pool "
      << "WHERE hostgroup<>" << MOCK_HG;
    const std::string v = adminScalar(admin, q.str());
    return v.empty() ? 0 : atoi(v.c_str());
}

// Poll a stats_pgsql_global counter until it exceeds `floor`, or the deadline
// expires. Connection teardown is asynchronous, so a fixed sleep is a guess about
// how fast the machine is; this waits for the event instead and returns the last
// value seen either way.
static long long waitStatAbove(PGconn* admin, const char* name, long long floor, int timeout_ms) {
    long long v = globalStat(admin, name);
    for (int waited = 0; waited < timeout_ms && v >= 0 && v <= floor; waited += 200) {
        usleep(200000);
        v = globalStat(admin, name);
    }
    return v;
}

// Wait for ProxySQL to close this client connection. PQconsumeInput() returns 0 on
// EOF, which is how a closed session is observed from the client side. Returns
// false if the connection was still alive when the deadline expired.
static bool waitPeerClosed(PGconn* c, int timeout_ms) {
    for (int waited = 0; waited < timeout_ms; waited += 100) {
        if (PQstatus(c) != CONNECTION_OK) return true;
        if (PQconsumeInput(c) == 0) return true;
        usleep(100000);
    }
    return false;
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
// run. `values` collects row 0 column 0 of each tuple result, which is how the
// regression checks below confirm a query came back with the value expected.
static Outcome runQueryOn(PGconn* c, std::string& err, std::vector<std::string>* values,
                          const char* query, int timeout_ms) {
    err.clear();
    if (values) values->clear();

    if (c == nullptr || PQstatus(c) != CONNECTION_OK) {
        err = c ? PQerrorMessage(c) : "null conn";
        return Outcome::CONNECT_FAILED;
    }
    if (PQsendQuery(c, query) == 0) {
        err = PQerrorMessage(c);
        return Outcome::ERRORED;
    }

    const int fd = PQsocket(c);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);

    Outcome out = Outcome::SERVED;
    for (;;) {
        while (PQisBusy(c)) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                err = "no response from the proxy within the deadline";
                return Outcome::TIMED_OUT;
            }
            int remain = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - now).count();
            if (remain > 250) remain = 250;          // re-check the deadline regularly
            if (!waitReadable(fd, remain)) continue;
            if (PQconsumeInput(c) == 0) {
                err = PQerrorMessage(c);
                return Outcome::ERRORED;             // peer gone: a clean client error
            }
        }
        PGresult* r = PQgetResult(c);
        if (r == nullptr) break;
        const ExecStatusType st = PQresultStatus(r);
        if (st == PGRES_TUPLES_OK) {
            if (values && PQntuples(r) > 0 && PQnfields(r) > 0 && !PQgetisnull(r, 0, 0)) {
                values->push_back(PQgetvalue(r, 0, 0));
            }
        } else if (st != PGRES_COMMAND_OK) {
            if (err.empty()) err = PQresultErrorMessage(r);
            if (err.empty()) err = PQerrorMessage(c);
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


// ------------------------------------------------------------ mock fixture

static std::string acceptedHandshake() {
    return pgmb_auth_ok() +
           pgmb_parameter_status("server_version", "16.2") +
           pgmb_parameter_status("client_encoding", "UTF8") +
           pgmb_backend_key_data(4242, 987654321) +
           pgmb_ready_for_query('I');
}

// How long the mock holds the connection open after the invalid reply. It must
// outlast every Part 1 observation, including the session-close wait, or a closing
// mock would explain the backend connection's disappearance by itself.
static const int HOLD_OPEN_MS = 25000;

// The reply under test: a bare ReadyForQuery as the entire answer to a query.
//
// The socket is deliberately KEPT OPEN afterwards. Closing it would give ProxySQL a
// second, independently sufficient reason to drop the connection -- libpq sees EOF,
// the transport goes CONNECTION_BAD, and it is discarded regardless of what the code
// under test decided. The pool assertion would then pass against an implementation
// that ignored the protocol violation entirely.
static std::vector<Step> scriptBareReadyForQuery() {
    return { step_expect_startup(), step_send(acceptedHandshake()), step_expect_query(),
             step_send(pgmb_ready_for_query('I')),
             step_sleep(HOLD_OPEN_MS) };
}

// ---------------------------------------------------------------------- main

int main(int, char**) {
    plan(9);

    if (cl.getEnv()) return exit_status();

    PGConnPtr adminOwner = createNewConnection(ConnType::ADMIN);
    if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
        BAIL_OUT("cannot proceed without an admin connection");
    PGconn* admin = adminOwner.get();

    const std::string saved_monitor = savedVar(admin, "pgsql-monitor_enabled");
    const std::string saved_shun    = savedVar(admin, "pgsql-shun_on_failures");
    const std::string saved_conn_to = savedVar(admin, "pgsql-connect_timeout_server_max");

    auto restore = [&]() {
        if (adminScalar(admin, "SELECT 1") != "1") {
            adminOwner = createNewConnection(ConnType::ADMIN);
            if (adminOwner && PQstatus(adminOwner.get()) == CONNECTION_OK) {
                admin = adminOwner.get();
            } else {
                diag("restore: ProxySQL admin unreachable -- runtime state not restored. "
                     "All of it is in-memory only, so restarting the proxy clears it.");
                return;
            }
        }
        if (!saved_monitor.empty()) setVar(admin, "pgsql-monitor_enabled", saved_monitor);
        if (!saved_shun.empty())    setVar(admin, "pgsql-shun_on_failures", saved_shun);
        if (!saved_conn_to.empty()) setVar(admin, "pgsql-connect_timeout_server_max", saved_conn_to);
        execAdmin(admin, std::string("DELETE FROM pgsql_users WHERE username='") + MOCK_USER + "'");
        execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME");
        std::stringstream ds;
        ds << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << MOCK_HG;
        execAdmin(admin, ds.str());
        execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
    };

    if (!setVar(admin, "pgsql-monitor_enabled", "false"))
        BAIL_OUT("cannot disable the monitor");
    if (!setVar(admin, "pgsql-shun_on_failures", "10000"))
        BAIL_OUT("cannot raise shun_on_failures");
    setVar(admin, "pgsql-connect_timeout_server_max", "5000");

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
            << ",4,0,'invalid reply sequence mock')";
        if (!execAdmin(admin, ins.str()) || !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) {
            mock.stop(); restore(); BAIL_OUT("could not register the mock backend");
        }
        std::stringstream u;
        u << "INSERT OR REPLACE INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('"
          << MOCK_USER << "','" << MOCK_PASS << "',1," << MOCK_HG << ")";
        if (!execAdmin(admin, u.str()) || !execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME")) {
            mock.stop(); restore(); BAIL_OUT("could not register the mock user");
        }
    }
    usleep(300000);

    // Fixture failure is fatal, not silent: if the pool reset does not take, the query
    // below never reaches the mock, yet the client still sees an error and the mock
    // hostgroup still holds no connections -- every Part 1 assertion would pass
    // without the scripted reply ever being sent.
    if (!resetMockPool(admin)) {
        mock.stop(); restore();
        BAIL_OUT("could not reset the mock hostgroup's pool");
    }
    mock.set_script(scriptBareReadyForQuery());
    mock.reset_stats();

    // ================================================================ PART 1
    // The protocol violation: both consequences must happen.

    auto client = createMockUserConnection();
    if (!client || PQstatus(client.get()) != CONNECTION_OK) {
        mock.stop(); restore();
        BAIL_OUT("could not connect the mock-hostgroup client to ProxySQL");
    }

    std::string err;
    const Outcome out = runQueryOn(client.get(), err, nullptr, "SELECT 1", QUERY_DEADLINE_MS);

    const std::string broke = checkInvariants(admin, adminOwner);

    ok(broke.empty(),
       "[1] ProxySQL survived the invalid reply and still serves the real backend%s%s",
       broke.empty() ? "" : " -- ", broke.c_str());

    ok(out == Outcome::ERRORED,
       "[2] client got a clean error, not a hang and not a silent success "
       "(outcome=%s, client=%s)",
       outcomeName(out), oneLine(err).c_str());

    // Anti-vacuous: proves the scenario actually ran.
    const int observed = mock.queries_observed();
    ok(observed > 0,
       "[3] the mock backend received the query and sent the invalid reply "
       "(queries observed=%d, connections accepted=%d, mock=%s)",
       observed, mock.connections_accepted(),
       mock.last_error().empty() ? "no errors" : mock.last_error().c_str());

    // Consequence one: the BACKEND CONNECTION is destroyed -- not pooled, and not
    // reset back into service. The mock is still holding that socket OPEN
    // (HOLD_OPEN_MS), so ordinary EOF cleanup cannot account for it being gone.
    //
    // Sampled FIRST, and deliberately so: the session-close check below can burn
    // seconds waiting, and if the mock's hold-open window expired in the meantime the
    // backend connection would die of plain EOF and this assertion would pass for
    // that reason instead. Order is load-bearing, not cosmetic.
    if (broke.empty()) {
        const int stranded = mockPoolConns(admin);
        ok(stranded == 0,
           "[4] the backend connection was destroyed, not pooled or reset, while its "
           "socket was still open (found %d)",
           stranded);
    } else {
        ok(false, "[4] pool state not assertable -- ProxySQL is down");
    }

    // Consequence two: the SESSION is closed. Detected as EOF on the client socket.
    const bool session_closed = waitPeerClosed(client.get(), 10000);
    ok(session_closed,
       "[5] ProxySQL closed the client session after the protocol violation (%s)",
       session_closed ? "peer closed" : "STILL OPEN after 10s");
    client.reset();

    // ================================================================ PART 2
    // Regression: the two gates that gained a 'healthy' check are on the ordinary
    // teardown path of EVERY connection. Nothing below involves the mock.

    // An ordinary backend error must NOT condemn anything. This is the case the
    // new behaviour could most easily over-reach into: a plain failing query.
    {
        auto rc = createNewConnection(ConnType::BACKEND);
        if (!rc || PQstatus(rc.get()) != CONNECTION_OK) {
            ok(false, "[6] could not open a real-backend connection");
        } else {
            std::string e1, e2;
            std::vector<std::string> vals;
            const Outcome bad = runQueryOn(rc.get(), e1, nullptr,
                "SELECT * FROM __no_such_table_reg6110__", QUERY_DEADLINE_MS);
            const Outcome good = runQueryOn(rc.get(), e2, &vals, "SELECT 42", QUERY_DEADLINE_MS);
            const bool survived = (bad == Outcome::ERRORED) && (good == Outcome::SERVED) &&
                                  vals.size() == 1 && vals[0] == "42";
            ok(survived,
               "[6] an ordinary SQL error leaves the session and its connection usable "
               "(bad=%s, next=%s, value=%s)",
               outcomeName(bad), outcomeName(good), vals.empty() ? "-" : vals[0].c_str());
        }
    }

    // Normal pooling still works: the pool-return arm of reset_connection() now also
    // requires healthy==true, so a healthy connection must still reach the pool.
    {
        const long long push_before = globalStat(admin, "PgHGM_pgconnpoll_push");
        {
            auto rc = createNewConnection(ConnType::BACKEND);
            std::string e; std::vector<std::string> v;
            if (rc && PQstatus(rc.get()) == CONNECTION_OK)
                runQueryOn(rc.get(), e, &v, "SELECT 1", QUERY_DEADLINE_MS);
        }                                   // closed here -> connection returns to pool
        const long long push_after = waitStatAbove(admin, "PgHGM_pgconnpoll_push", push_before, 15000);
        const int pooled = realPoolConns(admin);
        ok(push_before >= 0 && push_after > push_before && pooled > 0,
           "[7] healthy connections are still returned to the pool "
           "(pgconnpoll_push %lld -> %lld, real-backend pool=%d)",
           push_before, push_after, pooled);
    }

    // The reset path still works: leaving a transaction open makes reset_connection()
    // skip its fast arm, so teardown goes through destroy_MySQL_Connection_From_Pool's
    // reset branch -- the other gate that gained the healthy check. It must still
    // reset the connection rather than destroy it.
    {
        const long long reset_before = globalStat(admin, "PgHGM_pgconnpoll_reset");
        {
            auto rc = createNewConnection(ConnType::BACKEND);
            std::string e; std::vector<std::string> v;
            if (rc && PQstatus(rc.get()) == CONNECTION_OK) {
                runQueryOn(rc.get(), e, nullptr, "BEGIN", QUERY_DEADLINE_MS);
                runQueryOn(rc.get(), e, &v, "SELECT 7", QUERY_DEADLINE_MS);
            }
        }                                   // closed mid-transaction -> needs a reset
        const long long reset_after = waitStatAbove(admin, "PgHGM_pgconnpoll_reset", reset_before, 15000);
        ok(reset_before >= 0 && reset_after > reset_before,
           "[8] connections needing a reset are still reset, not destroyed "
           "(pgconnpoll_reset %lld -> %lld)",
           reset_before, reset_after);
    }

    // Everything still healthy after all of the above.
    {
        const std::string broke2 = checkInvariants(admin, adminOwner);
        ok(broke2.empty(),
           "[9] ProxySQL and the real backend are still healthy at the end%s%s",
           broke2.empty() ? "" : " -- ", broke2.c_str());
    }

    mock.stop();
    restore();
    return exit_status();
}
