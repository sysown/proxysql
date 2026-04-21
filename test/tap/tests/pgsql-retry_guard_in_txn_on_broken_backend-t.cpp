/**
 * @file pgsql-retry_guard_in_txn_on_broken_backend-t.cpp
 * @brief Regression test for the "silent in-transaction retry" bug fixed in
 *        commit 68c76eb42 ("fix(pgsql): mark transaction state unknown when
 *        backend connection is broken").
 *
 * Before the fix, when a backend connection broke mid-transaction (e.g. the
 * backend process was SIGTERM'd or the postmaster died), libpq's
 * PQtransactionStatus() returned PQTRANS_UNKNOWN rather than PQTRANS_INTRANS.
 * ProxySQL's IsActiveTransaction() then reported false, so the retry path in
 * PgSQL_Session::handler_minus1_ClientLibraryError() replayed the failed
 * statement on a fresh backend connection as autocommit. The client's next
 * COMMIT landed on a connection with no open transaction and PostgreSQL
 * emitted "WARNING: there is no transaction in progress" — a silent data-
 * consistency hazard that the application never saw.
 *
 * The fix forces unknown_transaction_status=true whenever
 * is_connected() == false, so the retry guard refuses to replay inside-tx
 * statements on a fresh connection.
 *
 * This test reproduces the scenario and asserts the post-fix behavior: a
 * mid-transaction backend termination surfaces as a fatal error to the client
 * instead of being silently replayed as autocommit.
 *
 * Method:
 *   1. Open a client connection to ProxySQL and start an explicit transaction.
 *   2. Learn the backend-side PID currently serving this session via
 *      pg_backend_pid().
 *   3. Issue a long-running query (SELECT pg_sleep(N)) and, from a separate
 *      thread, use a DIRECT (non-ProxySQL) superuser connection to the primary
 *      to call pg_terminate_backend() on the PID from step 2.
 *   4. Assert that the long-running query returns PGRES_FATAL_ERROR (fix
 *      present). Without the fix, ProxySQL would silently retry the statement
 *      on a fresh backend and we'd see PGRES_TUPLES_OK instead.
 *
 * Pre-fix failure mode of this test: the pg_sleep returns TUPLES_OK after ~3s
 * and the FATAL_ERROR assertion fails — exactly the signal you want a
 * regression guard to raise.
 */

#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sstream>
#include <thread>
#include <chrono>
#include <atomic>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

static PGconn* openConnection(const char* host, int port,
                              const char* user, const char* password,
                              const char* label) {
    std::stringstream ss;
    ss << "host=" << host << " port=" << port;
    ss << " user=" << user << " password=" << password;
    ss << " sslmode=disable";
    PGconn* c = PQconnectdb(ss.str().c_str());
    if (PQstatus(c) != CONNECTION_OK) {
        diag("Connection to %s (%s:%d user=%s) failed: %s",
             label, host, port, user, PQerrorMessage(c));
        PQfinish(c);
        return nullptr;
    }
    return c;
}

int main(int /*argc*/, char** /*argv*/) {
    plan(6);

    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }

    // Client <-> ProxySQL.
    PGconn* cli = openConnection(cl.pgsql_host, cl.pgsql_port,
                                 cl.pgsql_username, cl.pgsql_password,
                                 "ProxySQL");
    if (!cli) return exit_status();

    // Start an explicit transaction. After BEGIN the backend state is
    // PQTRANS_INTRANS; the bug manifests when that state is lost (backend
    // dies) and PQtransactionStatus() flips to PQTRANS_UNKNOWN.
    PGresult* r = PQexec(cli, "BEGIN");
    ok(PQresultStatus(r) == PGRES_COMMAND_OK,
       "BEGIN succeeded (%s)", PQresStatus(PQresultStatus(r)));
    PQclear(r);

    // Learn the backend-side PID for this session. pg_backend_pid() returns
    // the real Postgres backend PID behind the ProxySQL session, which is
    // what pg_terminate_backend() takes as its argument.
    int backend_pid = -1;
    r = PQexec(cli, "SELECT pg_backend_pid()");
    bool pid_ok = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1);
    if (pid_ok) backend_pid = atoi(PQgetvalue(r, 0, 0));
    PQclear(r);
    ok(pid_ok && backend_pid > 0,
       "SELECT pg_backend_pid() returned a pid (%d)", backend_pid);
    if (!pid_ok) {
        PQfinish(cli);
        return exit_status();
    }

    // Fire the kill from a separate thread so it lands while the main thread
    // is blocked inside PQexec(SELECT pg_sleep). We use a DIRECT superuser
    // connection to the primary (not ProxySQL) so the kill path is unrelated
    // to the code path under test.
    std::atomic<bool> kill_delivered(false);
    std::thread killer([&]() {
        // Let the main thread enter pg_sleep before we fire.
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        PGconn* direct = openConnection(cl.pgsql_server_host, cl.pgsql_server_port,
                                        cl.pgsql_server_username, cl.pgsql_server_password,
                                        "PG-direct (superuser)");
        if (!direct) return;

        char q[96];
        snprintf(q, sizeof(q), "SELECT pg_terminate_backend(%d)", backend_pid);
        PGresult* kr = PQexec(direct, q);
        if (PQresultStatus(kr) == PGRES_TUPLES_OK && PQntuples(kr) == 1) {
            // pg_terminate_backend returns boolean: 't' iff signal delivered.
            kill_delivered.store(PQgetvalue(kr, 0, 0)[0] == 't');
        }
        PQclear(kr);
        PQfinish(direct);
    });

    // This query will be in-flight when the terminate_backend signal arrives.
    // With the fix, ProxySQL refuses to retry it (because the session is in
    // an explicit transaction) and the error propagates to the client. Without
    // the fix, ProxySQL retries on a fresh backend as autocommit and we'd see
    // the sleep complete successfully — the silent-corruption path.
    r = PQexec(cli, "SELECT pg_sleep(3)");
    killer.join();

    ok(kill_delivered.load(),
       "pg_terminate_backend(%d) signalled successfully", backend_pid);

    // THE KEY ASSERTION. Pre-fix: PGRES_TUPLES_OK (silent replay). Post-fix:
    // PGRES_FATAL_ERROR (correct error propagation).
    ExecStatusType st = PQresultStatus(r);
    ok(st == PGRES_FATAL_ERROR,
       "SELECT pg_sleep inside tx returned FATAL_ERROR after backend kill "
       "(got %s) — regression guard for 68c76eb42",
       PQresStatus(st));
    if (st != PGRES_FATAL_ERROR) {
        diag("*** Bug reproduced: ProxySQL silently retried an in-transaction "
             "statement on a fresh backend. This build is missing the "
             "68c76eb42 fix.");
    }
    PQclear(r);

    // ProxySQL must not drop the *client* connection just because a backend
    // went away. The client socket should still be usable.
    ok(PQstatus(cli) == CONNECTION_OK,
       "Client connection to ProxySQL is still open after backend kill");

    // Recover: ROLLBACK clears the failed transaction on a pool-reusable
    // connection. A follow-up SELECT 1 should succeed.
    r = PQexec(cli, "ROLLBACK");
    diag("post-kill ROLLBACK status: %s", PQresStatus(PQresultStatus(r)));
    PQclear(r);

    r = PQexec(cli, "SELECT 1");
    ok(PQresultStatus(r) == PGRES_TUPLES_OK,
       "SELECT 1 on the same client connection succeeds post-recovery");
    PQclear(r);

    PQfinish(cli);
    return exit_status();
}
