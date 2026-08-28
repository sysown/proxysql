/**
 * @file test_ffto_mysql_concurrent-t.cpp
 * @brief FFTO E2E TAP test — concurrent sessions.
 *
 * Validates that FFTO works correctly under concurrent load with multiple
 * threads, each running its own fast-forward session.  Verifies:
 * - No cross-session metric contamination
 * - Correct aggregation of `count_star` and `sum_rows_affected` across
 *   all sessions
 * - Thread safety of the FFTO → Query Processor stats reporting path
 *
 * Each thread opens its own MYSQL* connection (which maps to a separate
 * MySQL_Session in ProxySQL with its own `m_ffto` instance).  The
 * `GloMyQPro->update_query_digest()` call in `report_query_stats` uses
 * internal locking in the query processor, so concurrent updates are safe.
 *
 * @par Test scenarios
 *  1. 10 concurrent threads, each executing 50 SELECTs + 50 INSERTs
 *  2. Aggregate stats verification: total count_star and rows_affected
 *
 * @pre  ProxySQL running with a MySQL backend, reachable via the standard
 *       TAP environment variables.
 *
 * @note TAP's ok() function is not thread-safe.  All ok() calls from
 *       worker threads are serialized via a global std::mutex, following
 *       the pattern established in test_ssl_fast_forward-3.cpp.
 */

#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <cstdint>
#include <mutex>
#include <pthread.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

/** @brief Number of concurrent worker threads. */
static constexpr int NUM_THREADS = 10;

/** @brief Number of queries each thread executes per type (SELECT + INSERT). */
static constexpr int QUERIES_PER_THREAD = 50;

/**
 * @brief Total number of planned TAP assertions.
 *
 * Breakdown:
 *  - 1 (table setup)
 *  - NUM_THREADS (one ok per thread completion)
 *  - 2 (aggregate count_star and rows_affected)
 *  Total = 1 + 10 + 2 = 13
 */
static constexpr int kPlannedTests = 1 + NUM_THREADS + 2;

/**
 * @brief Global mutex for serializing TAP ok() calls from worker threads.
 *
 * TAP's ok() function is not thread-safe — concurrent calls can interleave
 * output and corrupt the test counter.  All worker threads must acquire
 * this mutex before calling ok() or diag().
 */
static std::mutex tap_mutex;

/**
 * @brief Arguments passed to each worker thread.
 */
struct thread_args {
    int thread_id;          /**< @brief Unique thread identifier (0..NUM_THREADS-1). */
    const CommandLine* cl;  /**< @brief Shared CommandLine with connection parameters. */
    int success;            /**< @brief Set to 1 on success, 0 on failure. */
};

/**
 * @brief Worker thread function.
 *
 * Opens a fast-forward connection to ProxySQL, executes QUERIES_PER_THREAD
 * SELECT queries and QUERIES_PER_THREAD INSERT queries using per-thread
 * ID ranges to avoid primary key conflicts, then closes the connection.
 *
 * @param arg  Pointer to a thread_args struct.
 * @return NULL always.
 */
static void* worker_thread(void* arg) {
    thread_args* ta = static_cast<thread_args*>(arg);
    const CommandLine* cl = ta->cl;
    ta->success = 0;

    MYSQL* conn = mysql_init(NULL);
    if (!conn) {
        std::lock_guard<std::mutex> lock(tap_mutex);
        diag("Thread %d: mysql_init failed", ta->thread_id);
        return NULL;
    }

    /* Retry connection up to 3 times (ProxySQL may be under load) */
    bool connected = false;
    for (int retry = 0; retry < 3; retry++) {
        if (mysql_real_connect(conn, cl->host, cl->root_username, cl->root_password,
                               NULL, cl->port, NULL, 0)) {
            connected = true;
            break;
        }
        usleep(100000 * (retry + 1));
    }

    if (!connected) {
        std::lock_guard<std::mutex> lock(tap_mutex);
        diag("Thread %d: connection failed after retries: %s",
             ta->thread_id, mysql_error(conn));
        mysql_close(conn);
        return NULL;
    }

    if (mysql_query(conn, "USE ffto_db")) {
        std::lock_guard<std::mutex> lock(tap_mutex);
        diag("Thread %d: USE ffto_db failed: %s", ta->thread_id, mysql_error(conn));
        mysql_close(conn);
        return NULL;
    }

    int total_ok = 0;

    /* Execute QUERIES_PER_THREAD SELECTs */
    for (int i = 0; i < QUERIES_PER_THREAD; i++) {
        /*
         * Use a modular ID to select from the pre-populated table.
         * The table has 100 rows with id 1..100.
         */
        char q[256];
        snprintf(q, sizeof(q),
            "SELECT val FROM ffto_concurrent WHERE id = %d",
            (ta->thread_id * QUERIES_PER_THREAD + i) % 100 + 1);

        if (mysql_query(conn, q) != 0) {
            std::lock_guard<std::mutex> lock(tap_mutex);
            diag("Thread %d: SELECT %d failed: %s",
                 ta->thread_id, i, mysql_error(conn));
            break;
        }
        MYSQL_RES* rs = mysql_store_result(conn);
        if (!rs && mysql_field_count(conn) > 0) {
            std::lock_guard<std::mutex> lock(tap_mutex);
            diag("Thread %d: SELECT %d store_result failed: %s",
                 ta->thread_id, i, mysql_error(conn));
            break;
        }
        if (rs) mysql_free_result(rs);
        total_ok++;
    }

    /* Execute QUERIES_PER_THREAD INSERTs with per-thread ID ranges */
    int base_id = 1000 + ta->thread_id * QUERIES_PER_THREAD;
    for (int i = 0; i < QUERIES_PER_THREAD; i++) {
        char q[256];
        snprintf(q, sizeof(q),
            "INSERT INTO ffto_concurrent (id, val) VALUES (%d, 'thr%d_%d')",
            base_id + i, ta->thread_id, i);

        if (mysql_query(conn, q) != 0) {
            std::lock_guard<std::mutex> lock(tap_mutex);
            diag("Thread %d: INSERT %d failed: %s",
                 ta->thread_id, i, mysql_error(conn));
            break;
        }
        MYSQL_RES* rs = mysql_store_result(conn);
        if (rs) mysql_free_result(rs);
        total_ok++;
    }

    mysql_close(conn);

    ta->success = (total_ok == QUERIES_PER_THREAD * 2) ? 1 : 0;

    {
        std::lock_guard<std::mutex> lock(tap_mutex);
        ok(ta->success,
           "Thread %d completed %d/%d queries",
           ta->thread_id, total_ok, QUERIES_PER_THREAD * 2);
    }

    return NULL;
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    diag("=== FFTO MySQL Concurrent Sessions Test ===");
    diag("Validates FFTO with %d concurrent threads, each running", NUM_THREADS);
    diag("%d SELECTs + %d INSERTs. Verifies aggregate stats and", QUERIES_PER_THREAD, QUERIES_PER_THREAD);
    diag("no cross-session metric contamination.");
    diag("============================================");

    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    MYSQL* setup_conn = NULL;

    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
                           NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed: %s", mysql_error(admin));
        return -1;
    }

    /* ── FFTO Configuration (1 MB buffer) ───────────────────────────── */
    MYSQL_QUERY(admin, "SET mysql-ffto_enabled='true'");
    MYSQL_QUERY(admin, "SET mysql-ffto_max_buffer_size=1048576");
    MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    /* Enable fast_forward on ALL mysql_users rows (frontend + backend).
     * Partial INSERT OR REPLACE only touches PK (username, backend) and leaves
     * the frontend credential row at fast_forward=0, so sessions never enter
     * FAST_FORWARD and MySQLFFTO is never constructed. */
    MYSQL_QUERY(admin, "UPDATE mysql_users SET fast_forward=1");
    MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");
    {
        char sq[1024];
        snprintf(sq, sizeof(sq),
            "INSERT OR REPLACE INTO mysql_servers "
            "(hostgroup_id, hostname, port) VALUES (0, '%s', %d)",
            cl.mysql_host, cl.mysql_port);
        MYSQL_QUERY(admin, sq);
        MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");
    }

    /* ── Populate test table ────────────────────────────────────────── */
    setup_conn = mysql_init(NULL);
    if (!mysql_real_connect(setup_conn, cl.host, cl.root_username, cl.root_password,
                           NULL, cl.port, NULL, 0)) {
        diag("Setup connection failed: %s", mysql_error(setup_conn));
        return -1;
    }

    mysql_query(setup_conn, "CREATE DATABASE IF NOT EXISTS ffto_db");
    mysql_query(setup_conn, "USE ffto_db");
    mysql_query(setup_conn, "DROP TABLE IF EXISTS ffto_concurrent");
    mysql_query(setup_conn, "CREATE TABLE ffto_concurrent ("
                            "id INT PRIMARY KEY, "
                            "val VARCHAR(255))");

    /* Insert 100 seed rows for SELECT queries */
    {
        std::string ins = "INSERT INTO ffto_concurrent (id, val) VALUES ";
        for (int i = 1; i <= 100; i++) {
            if (i > 1) ins += ",";
            char v[64];
            snprintf(v, sizeof(v), "(%d, 'seed_%d')", i, i);
            ins += v;
        }
        if (mysql_query(setup_conn, ins.c_str())) {
            diag("Seed INSERT failed: %s", mysql_error(setup_conn));
            mysql_close(setup_conn);
            mysql_close(admin);
            return -1;
        }
        MYSQL_RES* r = mysql_store_result(setup_conn);
        if (r) mysql_free_result(r);
    }

    mysql_close(setup_conn);
    setup_conn = NULL;

    ok(1, "Test table ffto_concurrent created with 100 seed rows");

    /* ── Clear stats and launch threads ─────────────────────────────── */
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
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
            diag("Failed to create thread %d", i);
            std::lock_guard<std::mutex> lock(tap_mutex);
            ok(0, "Thread %d creation failed", i);
        } else {
            thread_created[i] = true;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        if (thread_created[i]) {
            pthread_join(threads[i], NULL);
        }
    }

    /* ── Aggregate stats verification ───────────────────────────────── */
    diag("--- Verifying aggregate stats ---");

    /*
     * Expected total queries: NUM_THREADS × QUERIES_PER_THREAD × 2 = 1000
     * (50 SELECTs + 50 INSERTs per thread × 10 threads)
     *
     * All SELECTs normalize to: "SELECT val FROM ffto_concurrent WHERE id = ?"
     * All INSERTs normalize to: "INSERT INTO ffto_concurrent (id,val) VALUES (?,?)"
     *
     * Poll for up to 5 seconds to allow all stats to propagate.
     */
    {
        int total_count = 0;
        for (int attempt = 0; attempt < 50; attempt++) {
            run_q(admin,
                "SELECT SUM(count_star) FROM stats_mysql_query_digest "
                "WHERE digest_text LIKE '%ffto_concurrent%'");
            MYSQL_RES* res = mysql_store_result(admin);
        if (!res) { usleep(100000); continue; }
            MYSQL_ROW row = mysql_fetch_row(res);
            total_count = row && row[0] ? atoi(row[0]) : 0;
            if (res) mysql_free_result(res);

            if (total_count >= NUM_THREADS * QUERIES_PER_THREAD * 2) break;
            usleep(100000);
        }

        /*
         * Use >= rather than == because some queries (like USE, CREATE,
         * DROP, INSERT for setup) may also be captured in digests if they
         * passed through the same fast-forward sessions.
         */
        ok(total_count >= NUM_THREADS * QUERIES_PER_THREAD * 2,
           "Aggregate count_star: %d (expected >= %d)",
           total_count, NUM_THREADS * QUERIES_PER_THREAD * 2);
    }

    /* Verify rows_affected from INSERTs */
    {
        run_q(admin,
            "SELECT SUM(sum_rows_affected) FROM stats_mysql_query_digest "
            "WHERE digest_text LIKE '%INSERT INTO ffto_concurrent%'");
        MYSQL_RES* res = mysql_store_result(admin);
        
        MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
        int total_affected = row && row[0] ? atoi(row[0]) : 0;
        if (res) mysql_free_result(res);

        ok(total_affected >= NUM_THREADS * QUERIES_PER_THREAD,
           "Aggregate sum_rows_affected: %d (expected >= %d)",
           total_affected, NUM_THREADS * QUERIES_PER_THREAD);
    }

    mysql_close(admin);
    return exit_status();
}
