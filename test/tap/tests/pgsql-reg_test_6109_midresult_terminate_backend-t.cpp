/**
 * @file pgsql-reg_test_6109_midresult_terminate_backend-t.cpp
 * @brief Regression test for issue #6109 - backend connection lost mid-result,
 *        exercised against a REAL PostgreSQL rather than a scripted backend.
 *
 * A raw transport death mid-result is known to abort the process. This asks the
 * narrower question: does the ORDINARY, supported way of killing a backend session
 * -- pg_terminate_backend() against a real PostgreSQL -- do the same?
 *
 * The expectation is NO: PostgreSQL sends a FATAL ErrorResponse (57P01) before it
 * closes, so ProxySQL receives a well-formed error and takes its normal error path,
 * never reaching the state where the transport simply vanished.
 */
#include <chrono>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;
static const char* MARKER = "midresult_kill_marker";

static PGConnPtr openConn(const char* h, int p, const char* u, const char* pw, const char* db) {
    std::stringstream ss;
    ss << "host=" << h << " port=" << p << " user=" << u << " password=" << pw;
    if (db && *db) ss << " dbname=" << db;
    ss << " sslmode=disable connect_timeout=10";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

int main(int, char**) {
    plan(4);
    if (cl.getEnv()) return exit_status();

    auto victim = openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, cl.pgsql_username);
    if (!victim || PQstatus(victim.get()) != CONNECTION_OK) BAIL_OUT("cannot open victim connection");

    // Large result so it is still streaming when we kill it.
    std::string q = "SELECT repeat('x',200) /* " + std::string(MARKER) + " */ FROM generate_series(1,20000000)";
    if (PQsendQuery(victim.get(), q.c_str()) == 0) BAIL_OUT("could not send the long query");
    PQsetSingleRowMode(victim.get());

    // Pull a few rows so the result is genuinely in flight.
    int rows = 0;
    for (int i = 0; i < 50; i++) {
        PGresult* r = PQgetResult(victim.get());
        if (!r) break;
        if (PQresultStatus(r) == PGRES_SINGLE_TUPLE) rows++;
        PQclear(r);
        if (rows >= 5) break;
    }
    diag("pulled %d row(s) before killing the backend", rows);
    ok(rows > 0, "the result was in flight before the kill (%d rows pulled)", rows);

    // Kill it the supported way, from a second session.
    //
    // The result of the kill is ASSERTED, not just logged. If the lookup matches no
    // session -- the marker never reached pg_stat_activity, the victim already
    // finished -- then nothing was terminated and the survival check below would
    // pass without having tested anything at all.
    int killed = -1;
    {
        auto killer = openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, cl.pgsql_username);
        if (!killer || PQstatus(killer.get()) != CONNECTION_OK) BAIL_OUT("cannot open killer connection");
        std::string k = "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE '%" +
                        std::string(MARKER) + "%' AND query NOT LIKE '%pg_stat_activity%'";
        PGresult* r = PQexec(killer.get(), k.c_str());
        killed = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : -1;
        PQclear(r);
    }
    ok(killed == 1, "the streaming backend session was found and terminated "
       "(pg_terminate_backend matched %d session(s), expected 1)", killed);

    // Drain the victim: it should end in an error, not a hang.
    //
    // BOUNDED BY TIME, deliberately, and NOT by a row count. ProxySQL buffers the
    // resultset, so after the backend dies the client still legitimately drains
    // thousands of already-buffered rows - a row cap fires on that and reports a
    // working proxy as broken (observed). What actually distinguishes a landed kill
    // from a missed one is elapsed time: draining the buffer takes milliseconds,
    // while reading all 20M rows one PGresult at a time does not. Unbounded, a missed
    // kill would look like a hung test rather than a failed one.
    const auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    std::string err;
    int rows_after_kill = 0;
    bool drain_bounded_out = false;
    for (;;) {
        PGresult* r = PQgetResult(victim.get());
        if (!r) break;
        const ExecStatusType st = PQresultStatus(r);
        if (st == PGRES_SINGLE_TUPLE) rows_after_kill++;
        else if (st != PGRES_TUPLES_OK) err = PQresultErrorMessage(r);
        PQclear(r);
        if (std::chrono::steady_clock::now() > drain_deadline) {
            drain_bounded_out = true;
            break;
        }
    }
    if (drain_bounded_out)
        diag("drain gave up after 30s and %d rows -- the result was still streaming",
             rows_after_kill);
    if (err.empty()) err = PQerrorMessage(victim.get());
    diag("victim client saw: %s", err.substr(0, err.find('\n')).c_str());

    // THE question: is ProxySQL still alive?
    auto probe = openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, cl.pgsql_username);
    bool alive = probe && PQstatus(probe.get()) == CONNECTION_OK;
    if (alive) {
        PGresult* r = PQexec(probe.get(), "SELECT 1");
        alive = (PQresultStatus(r) == PGRES_TUPLES_OK);
        PQclear(r);
    }
    ok(alive && !drain_bounded_out,
       "ProxySQL survived pg_terminate_backend() during a large result%s",
       drain_bounded_out ? " -- INCONCLUSIVE: still streaming after 30s" : "");
    ok(!err.empty(), "the client was told something (%s)", err.empty() ? "nothing" : err.substr(0, 60).c_str());

    return exit_status();
}
