/**
 * @file pgsql-native_framer_retention-t.cpp
 * @brief Drives the native backend path hard enough to trip the framer's
 *        consumed-byte assertion in PgSQL_Backend_Msg_Framer::feed().
 *
 * The defect: feed() must slide the unread tail down and drop the consumed
 * prefix. Without that the prefix accumulates for the whole result set.
 *
 * Detection lives in the framer itself, as an invariant that holds immediately
 * after the compaction block:
 *
 *     assert(pos == 0 || pos < len - pos);
 *
 * It is the exact negation of the compaction condition, so it cannot false-fire,
 * and it trips on the first feed after a substantial drain. This test's only job
 * is to make sure that code path actually RUNS: enable the native protocol,
 * stream a result big enough to need many reads with drains in between, and
 * confirm the proxy is still alive and serving afterwards.
 *
 * So a regression shows up as ProxySQL aborting mid-test, not as a numeric
 * comparison here. Assertion 1 is the liveness check that catches it; the other
 * two then fail as a consequence and say so. The assert message in the proxy log
 * names the file, line and expression.
 *
 * REQUIRES a DEBUG build -- assert() is compiled out of the framer under
 * #ifdef DEBUG, so on a release build this degrades to a plain smoke test.
 *
 * INFRA: legacy-g1. Runtime state restored in memory only -- never SAVE ... TO DISK.
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

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int BACKEND_HG = 0;

// A DataRow carrying one text column of N chars is 11 + N bytes on the wire.
// The width is not load-bearing here (see the header) -- it only needs to be
// wide enough that ~58 MiB streams in a reasonable number of rows.
static const int PAYLOAD = 2038;

// Deliberately fixed, not env-tunable. The stream must be large enough to need
// many reads with drains between them, which is what exercises the compaction
// path the assert guards. Change by reviewed edit, not env var.
static const int ROWS = 30000;       // ~58.3 MiB streamed

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
// ConnOK counts backend connections successfully created. Used to prove the
// stream really got a FRESH connection -- which, with native mode on at the
// time, is a connection that latched the native path.
static long long connOK(PGconn* a, int hg) {
    std::stringstream q;
    q << "SELECT IFNULL(SUM(ConnOK),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" << hg;
    const std::string v = adminScalar(a, q.str());
    return v.empty() ? -1 : atoll(v.c_str());
}

// Sets a runtime variable. Deliberately does NOT remember the old value:
// proxysql-tester.py reloads every config table FROM DISK before each test, so
// putting variables back is the harness's job, not the test's.
// Caller issues a single LOAD PGSQL VARIABLES TO RUNTIME afterwards.
static bool forceVar(PGconn* a, const std::string& name, const std::string& value) {
    return execAdmin(a, "SET " + name + "='" + value + "'");
}

// native_mode is latched per backend connection on its first handler() call
// (lib/PgSQL_Connection.cpp), so connections pooled before the toggle keep the
// old path. Recycling pgsql_servers drops them and forces fresh ones.
struct ServerRow { std::string hostname, port, max_connections, comment; };
static std::vector<ServerRow> readServers(PGconn* a, int hg) {
    std::vector<ServerRow> rows;
    std::stringstream q;
    q << "SELECT hostname, port, max_connections, comment FROM pgsql_servers "
      << "WHERE hostgroup_id=" << hg;
    PGresult* r = PQexec(a, q.str().c_str());
    if (PQresultStatus(r) == PGRES_TUPLES_OK) {
        for (int i = 0; i < PQntuples(r); i++) {
            ServerRow s;
            s.hostname = PQgetvalue(r, i, 0);
            s.port     = PQgetvalue(r, i, 1);
            s.max_connections = PQgetvalue(r, i, 2);
            s.comment  = PQgetisnull(r, i, 3) ? "" : PQgetvalue(r, i, 3);
            rows.push_back(std::move(s));
        }
    }
    PQclear(r);
    return rows;
}
static bool flushBackendPool(PGconn* a, int hg, const std::vector<ServerRow>& saved) {
    if (saved.empty()) return false;
    std::stringstream del;
    del << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << hg;
    if (!execAdmin(a, del.str())) return false;
    if (!execAdmin(a, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    for (const auto& s : saved) {
        std::stringstream ins;
        ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) "
            << "VALUES (" << hg << ",'" << s.hostname << "'," << s.port << ","
            << (s.max_connections.empty() ? std::string("1000") : s.max_connections)
            << ",'" << s.comment << "')";
        if (!execAdmin(a, ins.str())) return false;
    }
    if (!execAdmin(a, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    usleep(300000);
    return true;
}

// Stream one wide result in single-row mode. Single-row mode keeps THIS process
// small; it does not change what ProxySQL does with the backend stream.
static bool streamWideResult(PGconn* c, long long* out_rows, long long* out_bytes) {
    std::stringstream q;
    // create_new_connection=1 forces a fresh backend connection. A connection
    // latches native-vs-libpq when it is created, so one pooled before the
    // toggle would serve this query on the old path. Needs query_digests on --
    // see main(). If it ever stops working the query runs on a pooled libpq
    // connection, the framer is never fed, and the assert has nothing to guard.
    q << "/* create_new_connection=1 */ "
      << "SELECT repeat('x', " << PAYLOAD << ") FROM generate_series(1," << ROWS << ")";
    if (!PQsendQuery(c, q.str().c_str())) return false;
    PQsetSingleRowMode(c);
    long long rows = 0, bytes = 0;
    bool ok = true;
    PGresult* r;
    while ((r = PQgetResult(c)) != nullptr) {
        const ExecStatusType st = PQresultStatus(r);
        if (st == PGRES_SINGLE_TUPLE) { rows++; bytes += PQgetlength(r, 0, 0); }
        else if (st != PGRES_TUPLES_OK) ok = false;
        PQclear(r);
    }
    *out_rows = rows;
    *out_bytes = bytes;
    return ok;
}

int main(int, char**) {
    // native path reachable + volume sanity + proxy survived
    plan(3);

    if (cl.getEnv()) return exit_status();

    auto adminOwner = createAdminConn();
    if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
        BAIL_OUT("cannot proceed without an admin connection");
    PGconn* admin = adminOwner.get();

    const std::vector<ServerRow> saved_servers = readServers(admin, BACKEND_HG);
    if (saved_servers.empty()) BAIL_OUT("no pgsql_servers in hostgroup %d", BACKEND_HG);

    // NOT a variable restore (the harness handles those). This recycles the
    // backend POOL, which the harness does not touch.
    auto recyclePool = [&]() {
        // Not redundant with create_new_connection=1: that hint gets us a native
        // connection, it does not take it away. The connection returns to the
        // pool still latched native, where a later test expecting libpq could be
        // handed it.
        flushBackendPool(admin, BACKEND_HG, saved_servers);
    };

    // Force the whole precondition set, not just the native switch. The
    // create_new_connection hint is parsed from the query's first comment, and
    // first_comment is only extracted inside `if (query_digests)`
    // (Query_Processor.cpp, query_parser_init); first_comment_parsing=0 disables
    // annotation parsing outright. With either off the hint silently does
    // nothing. Set here because the harness reloads variables from disk before
    // every test, so a group config could otherwise disarm it.
    const bool prereq =
        forceVar(admin, "pgsql-use_native_backend_protocol", "true") &&
        forceVar(admin, "pgsql-query_digests", "true") &&
        forceVar(admin, "pgsql-query_processor_first_comment_parsing", "3") &&
        execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
    if (!prereq) { recyclePool(); BAIL_OUT("cannot set the native-path preconditions"); }

    // No pool recycle here on purpose: create_new_connection=1 on the streaming
    // query already gets a fresh connection, and recycling would add a window
    // where pgsql_servers is empty for this hostgroup -- a crash inside it
    // strands every later test with no backend. recyclePool() still recycles.

    auto c = createClientConn();
    if (!c || PQstatus(c.get()) != CONNECTION_OK) {
        recyclePool();
        BAIL_OUT("client connection failed: %s", c ? PQerrorMessage(c.get()) : "null");
    }

    const long long conn_ok_before = connOK(admin, BACKEND_HG);

    long long rows = 0, bytes = 0;
    const bool streamed = streamWideResult(c.get(), &rows, &bytes);

    // Liveness FIRST, and it is the headline. If the framer retained consumed
    // bytes, the assert in feed() has already aborted ProxySQL, so a dead proxy
    // here IS the signal -- not an infrastructure problem. Reporting it
    // first matters: the crash also makes the two checks below fail, and without
    // this line those read like a broken query rather than a memory defect.
    auto probe = createClientConn();
    const bool alive = probe && PQstatus(probe.get()) == CONNECTION_OK &&
                       adminScalar(probe.get(), "SELECT 1") == "1";
    probe.reset();

    const long long want_bytes = (long long)ROWS * PAYLOAD;

    if (!alive) {
        diag("ProxySQL is GONE after streaming. The framer invariant "
             "assert(pos == 0 || pos < len - pos) in PgSQL_Backend_Msg_Framer::feed() "
             "aborted the process: consumed bytes were not reclaimed.");
        diag("Confirm with: docker logs <proxysql container> | grep Assertion");
        diag("The two checks below could not be evaluated and fail as a consequence, "
             "not as separate defects.");
    }

    ok(alive,
       "ProxySQL survived streaming %.1f MiB on the native path "
       "[feed() must compact the consumed prefix; a crash here means it did not]",
       (double)want_bytes / (1024.0 * 1024.0));

    // Volume: a query that silently failed streams nothing, leaves the framer
    // untouched, and would make the check above pass for the wrong reason.
    ok(streamed && rows == (long long)ROWS && bytes == want_bytes,
       "streamed the expected volume: %lld/%d rows, %lld/%lld payload bytes%s",
       rows, ROWS, bytes, want_bytes,
       alive ? "" : "  <-- truncated because ProxySQL aborted mid-stream");

    // The stream must have gone through the NATIVE path, or the framer was never
    // fed and the assert had nothing to guard. create_new_connection=1 forces a
    // fresh backend connection, so ConnOK must rise, and native mode was on when
    // it was created, so that connection latched native.
    const long long conn_ok_after = alive ? connOK(admin, BACKEND_HG) : -1;
    ok(alive && conn_ok_before >= 0 && conn_ok_after > conn_ok_before,
       "stream ran on a NEW backend connection created under native mode%s",
       alive ? (std::string(" (ConnOK ") + std::to_string(conn_ok_before) + " -> " +
                std::to_string(conn_ok_after) + "), so the framer was exercised").c_str()
             : "  <-- unreadable because ProxySQL aborted; admin is gone");

    c.reset();     // close the client before touching runtime config
    recyclePool();
    return exit_status();
}
