/**
 * @file pgsql-native_pool_reset-t.cpp
 * @brief Does a pooled backend connection really get reset before the next
 *        client reuses it, on the native backend protocol as well as libpq?
 *
 * ProxySQL resets a pooled connection that carries session state the incoming
 * client never asked for. The reset is two commands: ROLLBACK when the
 * connection is inside a transaction, DISCARD ALL otherwise -- DISCARD ALL is
 * rejected by the backend inside a transaction block, so the order matters.
 *
 * Each scenario runs twice, once with the libpq backend and once with the native
 * one, and the two runs must agree; libpq is the oracle.
 *   S1 (DISCARD ALL): client A sets bytea_output, disappears, client B must
 *      read back the default.
 *   S2 (ROLLBACK): client A opens a transaction, disappears, client B must not
 *      find itself inside one.
 *   S3 (ROLLBACK, failed transaction): A's statement errors first, so the connection
 *      goes back marked 'E' rather than 'T' -- a separate route, since a failed
 *      transaction still counts as reusable. B must be outside the transaction AND
 *      able to run a statement at all.
 *
 * A last check counts instead of comparing: a reset that does nothing still leaves
 * each connection looking clean, because the broken one is thrown away. Only the
 * number of connections opened per client gives that away.
 *
 * Both assertions are worthless unless B actually inherited A's connection, so
 * every case proves it by backend pid and retries when it does not. The pid
 * comes from a pg_stat_activity lookup, not from a bare SELECT pg_backend_pid()
 * -- ProxySQL answers that one itself with its own session counter, which would
 * make every case appear to reuse a connection that was never touched.
 *
 * bytea_output is the variable under test because ProxySQL tracks it as a
 * dynamic variable, and that is what makes it hand the connection to the reset
 * path in the first place.
 *
 * Two things have to be forced or the test silently measures nothing.
 *
 * A connection is built as either libpq or native once, at creation, and never
 * converts. Flipping the variable therefore does nothing to a connection that
 * is already pooled, and the "native" run happily reuses a libpq one. So the
 * pool is emptied after every switch, and each run additionally asserts that
 * its backend pid differs from the previous run's -- equal pids mean the flush
 * did not take and the result proves nothing.
 *
 * The pool also prefers handing out a connection that needs no reset over one
 * that does, so as long as a clean connection is available client B will get
 * that one and the reset path is never entered. Emptying the pool first leaves
 * client A's dirty connection as the only candidate.
 *
 * The pool is emptied by removing the hostgroup's servers and putting them back
 * unchanged; ProxySQL closes a removed server's free connections.
 *
 * This assumes the hostgroup has ONE backend, which is what every group it is
 * registered in provides. With several, ProxySQL picks a server before it picks a
 * connection, so client B often opens a new connection to a different server
 * instead of inheriting A's; the retries would run out and the run would report no
 * verdict rather than a wrong one.
 *
 * INFRA: legacy-g1 (docker-pgsql16-single, scram-sha-256, no TLS).
 * Runtime state is restored in memory at the end -- never SAVE ... TO DISK.
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

// The value client A leaves behind. The PostgreSQL default is 'hex', so seeing
// 'escape' from client B means A's state survived into B's session.
static const char* LEAKED_VALUE = "escape";
static const char* DEFAULT_VALUE = "hex";

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

static bool execAdmin(PGconn* admin, const std::string& q) {
    PGresult* r = PQexec(admin, q.c_str());
    ExecStatusType st = PQresultStatus(r);
    bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(admin));
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

// The real backend pid. A bare "SELECT pg_backend_pid()" never leaves ProxySQL
// -- it matches an intercepted digest prefix and is answered with the ProxySQL
// session id -- so it cannot tell us which backend connection served a client.
// Selecting through pg_stat_activity moves the digest past that prefix, so the
// query runs on the backend and the answer identifies the connection.
static std::string backendPid(PGconn* c) {
    return scalar(c, "SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()");
}

static bool setNativeMode(PGconn* admin, bool enabled) {
    return execAdmin(admin, std::string("SET pgsql-use_native_backend_protocol='") +
                            (enabled ? "true" : "false") + "'") &&
           execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

// Drop every pooled connection for the hostgroup. Only removing the server does
// that -- ProxySQL closes a removed server's free connections when the change is
// loaded. Setting status to OFFLINE_HARD is not enough: the server object and its
// pool survive it. So the rows are read, deleted, and put back exactly as they
// were, every column included, because anything left out of the re-insert would
// come back as a table default and stay that way at runtime.
static const char* SERVER_COLS =
    "hostgroup_id,hostname,port,status,weight,compression,max_connections,"
    "max_replication_lag,use_ssl,max_latency_ms,comment";

static std::string sqlQuote(const std::string& v) {
    std::string out = "'";
    for (char c : v) { if (c == '\'') out += "''"; else out += c; }
    out += "'";
    return out;
}

// Read the hostgroup's servers back as the INSERT statements that would recreate
// them. Kept as a snapshot at startup so the rows can be put back if a flush dies
// half way through -- between the DELETE and the re-INSERT the hostgroup has no
// servers at all, and leaving it that way would fail every later test in the group.
static std::vector<std::string> snapshotServers(PGconn* admin, int hg) {
    std::vector<std::string> inserts;
    std::stringstream sel;
    sel << "SELECT " << SERVER_COLS << " FROM pgsql_servers WHERE hostgroup_id=" << hg;
    PGresult* res = PQexec(admin, sel.str().c_str());
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        diag("snapshotServers: cannot read pgsql_servers for hg %d: %s", hg, PQerrorMessage(admin));
        PQclear(res);
        return inserts;
    }
    const int rows = PQntuples(res), cols = PQnfields(res);
    for (int r = 0; r < rows; r++) {
        std::stringstream ins;
        ins << "INSERT INTO pgsql_servers (" << SERVER_COLS << ") VALUES (";
        for (int c = 0; c < cols; c++) {
            if (c) ins << ",";
            if (PQgetisnull(res, r, c)) ins << "NULL";
            else ins << sqlQuote(PQgetvalue(res, r, c));
        }
        ins << ")";
        inserts.push_back(ins.str());
    }
    PQclear(res);
    return inserts;
}

static bool applyServers(PGconn* admin, const std::vector<std::string>& inserts) {
    for (const auto& q : inserts) {
        if (!execAdmin(admin, q)) return false;
    }
    return execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

static bool flushBackendPool(PGconn* admin, int hg) {
    const std::vector<std::string> inserts = snapshotServers(admin, hg);
    if (inserts.empty()) {
        diag("flushBackendPool: no servers in hg %d; refusing to flush", hg);
        return false;
    }
    std::stringstream del;
    del << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << hg;
    if (!execAdmin(admin, del.str())) return false;
    if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false; // closes the free connections
    if (!applyServers(admin, inserts)) return false;
    usleep(200000); // let the servers come back online before anyone connects
    return true;
}

// Select a backend mode and guarantee the next connection is built under it.
static bool selectMode(PGconn* admin, bool native) {
    return setNativeMode(admin, native) && flushBackendPool(admin, BACKEND_HG);
}

// Result of one scenario run.
struct Outcome {
    bool ran = false;           // did B actually inherit A's backend connection?
    bool usable = false;        // did B's first statement on it succeed?
    std::string observed;       // what B read back
    std::string a_pid, b_pid;
};

/**
 * Scenario 1 — a plain session variable left behind.
 *
 * Retries until client B lands on the same backend connection client A used.
 * The pool was emptied just before, so A's is the only one there to hand out.
 */
static Outcome runVariableLeakScenario(int max_attempts) {
    Outcome out;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        std::string a_pid;
        {
            auto A = createClientConn();
            if (!A || PQstatus(A.get()) != CONNECTION_OK) {
                diag("attempt %d: client A could not connect: %s", attempt,
                     A ? PQerrorMessage(A.get()) : "(null)");
                usleep(200000); continue;
            }
            a_pid = backendPid(A.get());
            if (a_pid.empty())
                diag("attempt %d: client A got no backend pid: %s", attempt, PQerrorMessage(A.get()));
            PGresult* r = PQexec(A.get(), (std::string("SET bytea_output = '") + LEAKED_VALUE + "'").c_str());
            const bool set_ok = (PQresultStatus(r) == PGRES_COMMAND_OK);
            PQclear(r);
            if (!set_ok || a_pid.empty()) { usleep(200000); continue; }
            // Confirm the backend really took it while A is still connected.
            if (scalar(A.get(), "SELECT current_setting('bytea_output')") != LEAKED_VALUE) {
                usleep(200000); continue;
            }
        }   // A disconnects here; its backend connection returns to the pool

        usleep(300000);   // let the connection settle back into the pool

        {
            auto B = createClientConn();
            if (!B || PQstatus(B.get()) != CONNECTION_OK) { usleep(200000); continue; }
            // Both values in one round trip. Read as two queries, multiplexing can
            // answer them from different backend connections, and the pid check would
            // then vouch for a connection that did not produce the value.
            std::string b_pid, observed;
            {
                PGresult* r = PQexec(B.get(),
                    "SELECT (SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()), "
                    "current_setting('bytea_output')");
                if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
                    if (!PQgetisnull(r, 0, 0)) b_pid = PQgetvalue(r, 0, 0);
                    if (!PQgetisnull(r, 0, 1)) observed = PQgetvalue(r, 0, 1);
                }
                PQclear(r);
            }
            if (b_pid.empty() || b_pid != a_pid) {
                diag("attempt %d: client B landed on backend pid %s, not A's %s; retrying",
                     attempt, b_pid.c_str(), a_pid.c_str());
                usleep(300000);
                continue;
            }
            out.ran = true;
            out.observed = observed;
            out.a_pid = a_pid;
            out.b_pid = b_pid;
            return out;
        }
    }
    return out;
}

/**
 * Scenario 2 — a connection returned while a transaction is still open.
 * Scenario 3 — the same, but the transaction has already failed.
 *
 * A connection handed back with a transaction still open is rolled back before
 * anyone else gets it, so client B must never find itself inside one. Read as B's
 * transaction status: 'I' (idle) is clean, 'T' (in a transaction block) means A's
 * transaction survived into B's session, 'E' means it survived and is broken.
 *
 * abort_txn picks which of the two. It matters because a failed transaction takes
 * a different route: ProxySQL still counts the connection reusable, so it goes to
 * the reset path rather than being destroyed. A reset that reports success without
 * sending anything then pools a connection PostgreSQL will refuse every statement
 * on, and the next client gets it.
 */
static Outcome runOpenTransactionScenario(int max_attempts, bool abort_txn) {
    Outcome out;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        std::string a_pid;
        {
            auto A = createClientConn();
            if (!A || PQstatus(A.get()) != CONNECTION_OK) {
                diag("attempt %d: client A could not connect: %s", attempt,
                     A ? PQerrorMessage(A.get()) : "(null)");
                usleep(200000); continue;
            }
            a_pid = backendPid(A.get());
            if (a_pid.empty())
                diag("attempt %d: client A got no backend pid: %s", attempt, PQerrorMessage(A.get()));
            if (a_pid.empty()) { usleep(200000); continue; }
            PGresult* r = PQexec(A.get(), "BEGIN");
            const bool began = (PQresultStatus(r) == PGRES_COMMAND_OK);
            PQclear(r);
            if (!began) { usleep(200000); continue; }
            if (abort_txn) {
                // Fail on purpose: the backend moves to 'E' and refuses everything
                // until the transaction ends. Division by zero needs no fixture.
                PGresult* bad = PQexec(A.get(), "SELECT 1/0");
                const bool did_fail = (PQresultStatus(bad) == PGRES_FATAL_ERROR);
                PQclear(bad);
                if (!did_fail) { usleep(200000); continue; }
                if (PQtransactionStatus(A.get()) != PQTRANS_INERROR) { usleep(200000); continue; }
            } else {
                // Do real work inside the transaction so it is genuinely open.
                PQclear(PQexec(A.get(), "CREATE TEMP TABLE IF NOT EXISTS pool_reset_probe(x int)"));
                PQclear(PQexec(A.get(), "INSERT INTO pool_reset_probe VALUES (1)"));
            }
        }   // A vanishes mid-transaction

        usleep(400000);

        {
            auto B = createClientConn();
            if (!B || PQstatus(B.get()) != CONNECTION_OK) { usleep(200000); continue; }
            const std::string b_pid = backendPid(B.get());
            if (b_pid.empty() || b_pid != a_pid) { usleep(300000); continue; }
            // PQtransactionStatus reflects the last ReadyForQuery the client saw.
            PGresult* first = PQexec(B.get(), "SELECT 1");
            const bool first_ok = (PQresultStatus(first) == PGRES_TUPLES_OK);
            PQclear(first);
            const PGTransactionStatusType ts = PQtransactionStatus(B.get());
            out.ran = true;
            out.usable = first_ok;
            out.observed = (ts == PQTRANS_IDLE) ? "I"
                         : (ts == PQTRANS_INTRANS) ? "T"
                         : (ts == PQTRANS_INERROR) ? "E" : "?";
            out.a_pid = a_pid;
            out.b_pid = b_pid;
            return out;
        }
    }
    return out;
}

// ConnOK for the hostgroup: backend connections ProxySQL has opened since it
// started. It only ever goes up, so the interesting number is the difference
// across a workload, not the value.
static int connOK(PGconn* admin, int hg) {
    std::stringstream q;
    q << "SELECT ConnOK FROM stats_pgsql_connection_pool WHERE hostgroup=" << hg;
    const std::string v = scalar(admin, q.str());
    return v.empty() ? -1 : atoi(v.c_str());
}

// A reset that only claims to have run hands every client a connection stuck in
// the aborted transaction; its first statement is refused and the connection is
// thrown away, so the cost tracks the client count instead of staying flat.
// Measured here: 1-2 connections with the reset working, 16 without.
static int abandonBudget(PGconn* admin, int sessions) {
    const int before = connOK(admin, BACKEND_HG);
    if (before < 0) return -1;
    for (int i = 0; i < sessions; i++) {
        auto A = createClientConn();
        if (!A || PQstatus(A.get()) != CONNECTION_OK) continue;
        PQclear(PQexec(A.get(), "BEGIN"));
        PQclear(PQexec(A.get(), "SELECT 1/0"));
        // A disconnects here, still inside the failed transaction.
    }
    usleep(500000);   // let the last connection finish going back to the pool
    const int after = connOK(admin, BACKEND_HG);
    return (after < 0) ? -1 : (after - before);
}

int main(int, char**) {
    // Per scenario: libpq oracle ran, native ran, native used a fresh backend
    // connection, native matches oracle. x3 scenarios = 12, plus one summary
    // assertion naming the leak explicitly, plus S3's usability and connection
    // budget checks.
    plan(15);

    if (cl.getEnv()) return exit_status();

    auto adminOwner = createAdminConn();
    if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
        BAIL_OUT("cannot proceed without an admin connection");
    PGconn* admin = adminOwner.get();

    // ---- save runtime state ------------------------------------------------
    PGresult* sv = PQexec(admin,
        "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
    std::string saved_native;
    if (PQresultStatus(sv) == PGRES_TUPLES_OK && PQntuples(sv) > 0)
        saved_native = PQgetvalue(sv, 0, 0);
    PQclear(sv);

    const std::vector<std::string> saved_servers = snapshotServers(admin, BACKEND_HG);
    if (saved_servers.empty())
        BAIL_OUT("no pgsql_servers rows for the backend hostgroup; nothing to test against");

    auto restore = [&]() {
        // If a flush died between its DELETE and its re-INSERT the hostgroup is
        // empty; put the startup snapshot back before anything else runs.
        std::stringstream cnt;
        cnt << "SELECT count(*) FROM pgsql_servers WHERE hostgroup_id=" << BACKEND_HG;
        if (scalar(admin, cnt.str()) == "0")
            applyServers(admin, saved_servers);
        // Put the setting back, then empty the pool again. Without the second flush
        // the pool keeps the connections built during the last phase, and the next
        // test would run over native connections while the setting reads false --
        // a connection never changes mode after it is created.
        if (!saved_native.empty()) {
            setNativeMode(admin, saved_native == "true" || saved_native == "1");
            flushBackendPool(admin, BACKEND_HG);
        }
    };

    usleep(500000);

    // Generous: each attempt is cheap, and a scenario that never establishes its
    // precondition produces NO verdict at all — which is worse than a slow test.
    const int ATTEMPTS = 15;

    // ================= Scenario 1: session variable ==========================
    if (!selectMode(admin, false)) { restore(); BAIL_OUT("cannot select libpq mode"); }
    const Outcome libpq_var = runVariableLeakScenario(ATTEMPTS);
    ok(libpq_var.ran,
       "S1 oracle: libpq run reused backend pid %s for both clients",
       libpq_var.a_pid.c_str());

    if (!selectMode(admin, true)) { restore(); BAIL_OUT("cannot select native mode"); }
    const Outcome native_var = runVariableLeakScenario(ATTEMPTS);
    ok(native_var.ran,
       "S1 native: run reused backend pid %s for both clients",
       native_var.a_pid.c_str());

    ok(native_var.ran && libpq_var.ran && native_var.a_pid != libpq_var.a_pid,
       "S1 native run is on a different backend connection than the libpq run "
       "(libpq pid %s, native pid %s); equal pids mean the pool was not flushed "
       "and the native run measured a libpq connection",
       libpq_var.a_pid.c_str(), native_var.a_pid.c_str());

    ok(libpq_var.ran && native_var.ran && libpq_var.observed == native_var.observed,
       "S1 bytea_output after connection reuse: libpq='%s' native='%s' "
       "(a mismatch means DISCARD ALL never reached the backend)",
       libpq_var.observed.c_str(), native_var.observed.c_str());

    // ================= Scenario 2: open transaction ==========================
    if (!selectMode(admin, false)) { restore(); BAIL_OUT("cannot select libpq mode"); }
    const Outcome libpq_txn = runOpenTransactionScenario(ATTEMPTS, false);
    ok(libpq_txn.ran, "S2 oracle: libpq run reused backend pid %s for both clients",
       libpq_txn.a_pid.c_str());

    if (!selectMode(admin, true)) { restore(); BAIL_OUT("cannot select native mode"); }
    const Outcome native_txn = runOpenTransactionScenario(ATTEMPTS, false);
    ok(native_txn.ran, "S2 native: run reused backend pid %s for both clients",
       native_txn.a_pid.c_str());

    ok(native_txn.ran && libpq_txn.ran && native_txn.a_pid != libpq_txn.a_pid,
       "S2 native run is on a different backend connection than the libpq run "
       "(libpq pid %s, native pid %s); equal pids mean the pool was not flushed "
       "and the native run measured a libpq connection",
       libpq_txn.a_pid.c_str(), native_txn.a_pid.c_str());

    ok(libpq_txn.ran && native_txn.ran && libpq_txn.observed == native_txn.observed,
       "S2 transaction status inherited by the next client: libpq='%s' native='%s' "
       "(a mismatch means ROLLBACK never reached the backend)",
       libpq_txn.observed.c_str(), native_txn.observed.c_str());

    // ================= Scenario 3: aborted transaction =======================
    if (!selectMode(admin, false)) { restore(); BAIL_OUT("cannot select libpq mode"); }
    const Outcome libpq_abort = runOpenTransactionScenario(ATTEMPTS, true);
    ok(libpq_abort.ran, "S3 oracle: libpq run reused backend pid %s for both clients",
       libpq_abort.a_pid.c_str());

    if (!selectMode(admin, true)) { restore(); BAIL_OUT("cannot select native mode"); }
    const Outcome native_abort = runOpenTransactionScenario(ATTEMPTS, true);
    ok(native_abort.ran, "S3 native: run reused backend pid %s for both clients",
       native_abort.a_pid.c_str());

    ok(native_abort.ran && libpq_abort.ran && native_abort.a_pid != libpq_abort.a_pid,
       "S3 native run is on a different backend connection than the libpq run "
       "(libpq pid %s, native pid %s); equal pids mean the pool was not flushed "
       "and the native run measured a libpq connection",
       libpq_abort.a_pid.c_str(), native_abort.a_pid.c_str());

    ok(libpq_abort.ran && native_abort.ran && libpq_abort.observed == native_abort.observed,
       "S3 transaction status inherited after an ABORTED transaction: libpq='%s' "
       "native='%s' (a mismatch means the failed transaction was never rolled back)",
       libpq_abort.observed.c_str(), native_abort.observed.c_str());

    ok(native_abort.ran && native_abort.usable,
       "S3 native: the next client can actually use the connection it was given%s",
       (native_abort.ran && !native_abort.usable)
           ? " -- ITS FIRST STATEMENT WAS REFUSED, the aborted transaction came with it" : "");

    // ---- explicit statement of the leak ------------------------------------
    // Separate from the differential so a reader sees the concrete claim, not
    // just "two strings differ". The oracle establishes what clean looks like.
    {
        const bool leaked = native_var.ran && native_var.observed == LEAKED_VALUE;
        ok(!leaked,
           "client B must not observe client A's session state: expected '%s', native gave '%s'%s",
           DEFAULT_VALUE, native_var.observed.c_str(),
           leaked ? " -- SESSION STATE CROSSED BETWEEN CLIENTS" : "");
    }


    // ---- what the reset costs when it does not happen -----------------------
    // The differential above proves one connection is clean. This proves the pool
    // as a whole is: a reset that silently does nothing still leaves each single
    // connection looking fine after ProxySQL throws it away, and only the count of
    // connections opened gives that away.
    {
        if (!selectMode(admin, true)) { restore(); BAIL_OUT("cannot select native mode"); }
        const int SESSIONS = 30;
        const int BUDGET = 10;   // clean runs cost 1-2; a dead reset costs one per session
        const int used = abandonBudget(admin, SESSIONS);
        ok(used >= 0 && used <= BUDGET,
           "%d clients abandoning a failed transaction opened %d backend connections "
           "(budget %d); one per client means every reuse handed over a broken "
           "connection and it was thrown away",
           SESSIONS, used, BUDGET);
    }

    restore();
    return exit_status();
}
