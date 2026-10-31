/**
 * @file test_ffto_pgsql_concurrent-t.cpp
 * @brief FFTO E2E TAP test — concurrent PostgreSQL sessions.
 *
 * Validates that FFTO works correctly under concurrent load with
 * multiple threads, each running its own PgSQL fast-forward session.
 * Each thread opens its own PGconn (mapped to a separate PgSQL_Session
 * with its own PgSQLFFTO instance). GloPgQPro->update_query_digest()
 * uses internal locking for thread-safe stats updates.
 *
 * @par Test scenarios
 *  1. 10 concurrent threads, each executing 50 SELECTs + 50 INSERTs
 *  2. Aggregate stats: SUM(count_star) >= 1000, SUM(rows_affected) >= 500
 *
 * @pre  ProxySQL running with a PostgreSQL backend.
 */

#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <cstdint>
#include <mutex>
#include <pthread.h>
#include "libpq-fe.h"
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

static constexpr int NUM_THREADS = 10;
static constexpr int QUERIES_PER_THREAD = 50;

/**
 * @brief Total TAP assertions: 1 (setup) + NUM_THREADS + 2 (aggregates) = 13
 */
static constexpr int kPlannedTests = 1 + NUM_THREADS + 2;

/** @brief Mutex for serializing TAP ok() calls from worker threads. */
static std::mutex tap_mutex;

/** @brief Arguments passed to each worker thread. */
struct thread_args {
    int thread_id;
    const CommandLine* cl;
    int success;
};

/**
 * @brief Worker thread: opens PGconn, runs SELECTs + INSERTs.
 *
 * @param arg  Pointer to thread_args struct.
 * @return NULL always.
 */
static void* worker_thread(void* arg) {
    thread_args* ta = static_cast<thread_args*>(arg);
    const CommandLine* cl = ta->cl;
    ta->success = 0;

    char ci[1024];
    snprintf(ci, sizeof(ci),
        "host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
        cl->pgsql_host, cl->pgsql_port,
        cl->pgsql_root_username, cl->pgsql_root_password);

    PGconn* conn = NULL;
    for (int retry = 0; retry < 3; retry++) {
        conn = PQconnectdb(ci);
        if (PQstatus(conn) == CONNECTION_OK) break;
        PQfinish(conn); conn = NULL;
        usleep(100000 * (retry + 1));
    }

    if (!conn || PQstatus(conn) != CONNECTION_OK) {
        std::lock_guard<std::mutex> lock(tap_mutex);
        diag("Thread %d: connection failed", ta->thread_id);
        if (conn) PQfinish(conn);
        return NULL;
    }

    int total_ok = 0;

    /* SELECTs */
    for (int i = 0; i < QUERIES_PER_THREAD; i++) {
        char q[256];
        snprintf(q, sizeof(q), "SELECT val FROM ffto_pg_conc WHERE id = %d",
                 (ta->thread_id * QUERIES_PER_THREAD + i) % 100 + 1);
        PGresult* rs = PQexec(conn, q);
        if (rs && PQresultStatus(rs) == PGRES_TUPLES_OK) total_ok++;
        if (rs) PQclear(rs);
    }

    /* INSERTs with per-thread ID ranges */
    int base_id = 1000 + ta->thread_id * QUERIES_PER_THREAD;
    for (int i = 0; i < QUERIES_PER_THREAD; i++) {
        char q[256];
        snprintf(q, sizeof(q),
            "INSERT INTO ffto_pg_conc (id, val) VALUES (%d, 'thr%d_%d')",
            base_id + i, ta->thread_id, i);
        PGresult* rs = PQexec(conn, q);
        if (rs && PQresultStatus(rs) == PGRES_COMMAND_OK) total_ok++;
        if (rs) PQclear(rs);
    }

    PQfinish(conn);
    ta->success = (total_ok == QUERIES_PER_THREAD * 2) ? 1 : 0;

    {
        std::lock_guard<std::mutex> lock(tap_mutex);
        ok(ta->success, "Thread %d completed %d/%d queries",
           ta->thread_id, total_ok, QUERIES_PER_THREAD * 2);
    }
    return NULL;
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) { diag("Failed to get env vars."); return -1; }

    diag("=== FFTO PostgreSQL Concurrent Sessions Test ===");
    diag("10 threads x %d SELECTs + %d INSERTs each.",
         QUERIES_PER_THREAD, QUERIES_PER_THREAD);
    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    PGconn* setup_conn = NULL;

    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
                           NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed"); return -1;
    }

    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='true' "
                       "WHERE variable_name='pgsql-ffto_enabled'");
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='1048576' "
                       "WHERE variable_name='pgsql-ffto_max_buffer_size'");
    MYSQL_QUERY(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

    /* Enable fast_forward on ALL pgsql_users rows (frontend + backend).
     * Partial INSERT OR REPLACE only touches PK (username, backend) and leaves
     * the frontend credential row at fast_forward=0. */
    MYSQL_QUERY(admin, "UPDATE pgsql_users SET fast_forward=1");
    MYSQL_QUERY(admin, "LOAD PGSQL USERS TO RUNTIME");

    {
        char sq[1024];
        snprintf(sq, sizeof(sq),
            "INSERT OR REPLACE INTO pgsql_servers (hostgroup_id, hostname, port) "
            "VALUES (0, '%s', %d)", cl.pgsql_server_host, cl.pgsql_server_port);
        MYSQL_QUERY(admin, sq);
        MYSQL_QUERY(admin, "LOAD PGSQL SERVERS TO RUNTIME");
    }

    /* ── Populate test table ────────────────────────────────────────── */
    {
        char ci[1024];
        snprintf(ci, sizeof(ci),
            "host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
            cl.pgsql_host, cl.pgsql_port,
            cl.pgsql_root_username, cl.pgsql_root_password);
        setup_conn = PQconnectdb(ci);
    }
    if (!setup_conn || PQstatus(setup_conn) != CONNECTION_OK) {
        diag("Setup connection failed"); return -1;
    }

    {
        PGresult* r;
        r = PQexec(setup_conn, "DROP TABLE IF EXISTS ffto_pg_conc");
        if (r) PQclear(r);
        r = PQexec(setup_conn, "CREATE TABLE ffto_pg_conc ("
                               "id INT PRIMARY KEY, val VARCHAR(255))");
        if (r) PQclear(r);
        r = PQexec(setup_conn,
            "INSERT INTO ffto_pg_conc (id, val) "
            "SELECT g, 'seed_' || g FROM generate_series(1, 100) AS g");
        if (r) PQclear(r);
    }
    PQfinish(setup_conn);

    ok(1, "Test table ffto_pg_conc created with 100 seed rows");

    /* ── Clear stats and launch threads ─────────────────────────────── */
    {
        mysql_query(admin, "SELECT * FROM stats_pgsql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    thread_args args[NUM_THREADS];
    pthread_t threads[NUM_THREADS];
    bool thread_created[NUM_THREADS] = {};

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].cl = &cl;
        args[i].success = 0;
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, worker_thread, &args[i]) != 0) {
            std::lock_guard<std::mutex> lock(tap_mutex);
            ok(0, "Thread %d creation failed", i);
        } else {
            thread_created[i] = true;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        if (thread_created[i]) pthread_join(threads[i], NULL);
    }

    /* ── Aggregate stats verification ───────────────────────────────── */
    diag("--- Verifying aggregate stats ---");

    {
        int total_count = 0;
        for (int attempt = 0; attempt < 50; attempt++) {
            run_q(admin,
                "SELECT SUM(count_star) FROM stats_pgsql_query_digest "
                "WHERE digest_text LIKE '%ffto_pg_conc%'");
            MYSQL_RES* res = mysql_store_result(admin);
            MYSQL_ROW row = mysql_fetch_row(res);
            total_count = row && row[0] ? atoi(row[0]) : 0;
            if (res) mysql_free_result(res);
            if (total_count >= NUM_THREADS * QUERIES_PER_THREAD * 2) break;
            usleep(100000);
        }
        ok(total_count >= NUM_THREADS * QUERIES_PER_THREAD * 2,
           "Aggregate count_star: %d (expected >= %d)",
           total_count, NUM_THREADS * QUERIES_PER_THREAD * 2);
    }

    {
        run_q(admin,
            "SELECT SUM(sum_rows_affected) FROM stats_pgsql_query_digest "
            "WHERE digest_text LIKE '%INSERT INTO ffto_pg_conc%'");
        MYSQL_RES* res = mysql_store_result(admin);
        MYSQL_ROW row = mysql_fetch_row(res);
        int total_affected = row && row[0] ? atoi(row[0]) : 0;
        if (res) mysql_free_result(res);

        ok(total_affected >= NUM_THREADS * QUERIES_PER_THREAD,
           "Aggregate sum_rows_affected: %d (expected >= %d)",
           total_affected, NUM_THREADS * QUERIES_PER_THREAD);
    }

    mysql_close(admin);
    return exit_status();
}
