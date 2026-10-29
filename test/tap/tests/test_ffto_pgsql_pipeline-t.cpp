/**
 * @file test_ffto_pgsql_pipeline-t.cpp
 * @brief FFTO E2E TAP test — PostgreSQL extended query pipelining.
 *
 * Validates that PgSQLFFTO correctly tracks queries sent in a pipelined
 * fashion via the PostgreSQL extended query protocol. Pipelining means
 * multiple Parse+Bind+Execute sequences are sent before a single Sync,
 * and the server responds with multiple CommandComplete messages followed
 * by a single ReadyForQuery.
 *
 * Uses pg_lite_client for raw protocol access — libpq doesn't expose
 * true pipelining (it sends Sync after each PQexecPrepared).
 *
 * @par Test scenarios
 *  1. 3 different queries pipelined before Sync → 3 separate digests
 *  2. Same prepared statement executed 10 times in pipeline → count_star=10
 *  3. Extended Execute + Sync + simple Query pipelined together → each digest
 *     keeps its own row counts across the exchange boundary
 *
 * @pre  ProxySQL running with a PostgreSQL backend.
 *
 * @see  PgSQLFFTO.cpp — m_pending_queries deque handles pipelined queries
 * @see  pg_lite_client.h — PgConnection for raw protocol access
 */

#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <cstdint>
/* pg_lite_client.h must come before mysql.h to avoid PROTOCOL_VERSION macro conflict */
#include "pg_lite_client.h"
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

/**
 * @brief Total number of planned TAP assertions.
 *
 * Breakdown:
 *  - Setup:                  1 (connect)
 *  - Scenario 1 (3 queries): 3 x 3 = 9 (3 verify_pg_digest calls)
 *  - Scenario 2 (10x exec):  1 x 3 = 3 (1 verify_pg_digest call)
 *  - Scenario 3 (boundary):  2 x 3 = 6 (2 verify_pg_digest calls)
 *  Total = 19
 */
static constexpr int kPlannedTests = 19;

#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
    do { \
        diag(fmt, ##__VA_ARGS__); \
        int remaining = kPlannedTests - tests_last(); \
        if (remaining > 0) { \
            skip(remaining, "Skipping remaining assertions after setup failure"); \
        } \
        goto cleanup_label; \
    } while (0)

void verify_pg_digest(MYSQL* admin, const char* template_text, int expected_count,
                      uint64_t expected_rows_affected = 0, uint64_t expected_rows_sent = 0) {
    char query[1024];
    snprintf(query, sizeof(query),
        "SELECT count_star, sum_rows_affected, sum_rows_sent, digest_text "
        "FROM stats_pgsql_query_digest WHERE digest_text LIKE '%%%s%%'",
        template_text);
    MYSQL_RES* res = NULL;
    MYSQL_ROW row = NULL;
    for (int attempt = 0; attempt < 20; attempt++) {
        int rc = run_q(admin, query);
        if (rc != 0) { usleep(100000); continue; }
        res = mysql_store_result(admin);
        if (!res) { usleep(100000); continue; }
        row = mysql_fetch_row(res);
        if (row) break;
        mysql_free_result(res); res = NULL;
        usleep(100000);
    }
    if (row) {
        int count = atoi(row[0]);
        uint64_t ra = strtoull(row[1], NULL, 10);
        uint64_t rs_val = strtoull(row[2], NULL, 10);
        ok(count >= expected_count, "PG digest '%s': count=%d (>= %d)", row[3], count, expected_count);
        ok(ra == expected_rows_affected, "PG rows_affected '%s': %llu (== %llu)",
           row[3], (unsigned long long)ra, (unsigned long long)expected_rows_affected);
        ok(rs_val == expected_rows_sent, "PG rows_sent '%s': %llu (== %llu)",
           row[3], (unsigned long long)rs_val, (unsigned long long)expected_rows_sent);
    } else {
        ok(0, "PG digest NOT found: %s", template_text);
        ok(0, "Skipping rows_affected"); ok(0, "Skipping rows_sent");
        diag("Dumping stats_pgsql_query_digest:");
        run_q(admin, "SELECT digest_text, count_star FROM stats_pgsql_query_digest");
        MYSQL_RES* dr = mysql_store_result(admin);
        MYSQL_ROW drw;
        while (dr && (drw = mysql_fetch_row(dr))) diag("  %s  count:%s", drw[0], drw[1]);
        if (dr) mysql_free_result(dr);
    }
    if (res) mysql_free_result(res);
}

static void clear_pg_stats(MYSQL* admin) {
    mysql_query(admin, "SELECT * FROM stats_pgsql_query_digest_reset");
    MYSQL_RES* r = mysql_store_result(admin);
    if (r) mysql_free_result(r);
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) { diag("Failed to get env vars."); return -1; }

    diag("=== FFTO PostgreSQL Pipeline Test ===");
    diag("Validates FFTO with pipelined extended query protocol.");
    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    PgConnection* pgc = NULL;

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

    /* ── PgConnection (raw protocol) ────────────────────────────────── */
    try {
        pgc = new PgConnection(5000);
        pgc->connect(cl.pgsql_host, cl.pgsql_port, "postgres",
                     cl.pgsql_root_username, cl.pgsql_root_password);
    } catch (const PgException& e) {
        diag("PgConnection failed: %s", e.what());
        FAIL_AND_SKIP_REMAINING(cleanup, "PgConnection failed");
    }
    ok(pgc != NULL && pgc->isConnected(), "Connected via pg_lite_client");

    /* Create test table via simple query.
     *
     * Each response MUST be consumed. execute() only writes the Query message;
     * it does not read the reply, so firing three of them back-to-back leaves
     * three unread ReadyForQuery messages in the socket. The next
     * consumeInputUntilReady() -- the one after the Parse batch below -- stops
     * at the FIRST ReadyForQuery it sees, which would be DROP TABLE's, not the
     * one it is waiting for. From that point the client is a full exchange
     * behind the server and keeps pipelining anyway, so an old ReadyForQuery is
     * still in flight when the Bind/Execute batch starts. Whether that stray
     * message reaches the proxy before or after the batch's first Execute is
     * pure timing, which is exactly how this test failed intermittently in CI
     * (SELECT/INSERT/UPDATE stats each shifted by one position) while passing
     * locally. */
    pgc->execute("DROP TABLE IF EXISTS ffto_pg_pipe");
    pgc->consumeInputUntilReady();
    pgc->execute("CREATE TABLE ffto_pg_pipe (id INT PRIMARY KEY, val TEXT)");
    pgc->consumeInputUntilReady();
    pgc->execute("INSERT INTO ffto_pg_pipe VALUES (1,'a'), (2,'b'), (3,'c')");
    pgc->consumeInputUntilReady();

    /* ================================================================
     * Scenario 1:  3 different queries pipelined before Sync
     *
     * Send Parse+Bind+Execute for 3 different queries, then Sync.
     * PgSQLFFTO queues them in m_pending_queries and finalizes each
     * on its respective CommandComplete, then ReadyForQuery.
     * ================================================================ */
    diag("--- Scenario 1: 3 pipelined queries ---");
    clear_pg_stats(admin);

    try {
        /* Parse 3 different statements without sending Sync */
        pgc->prepareStatement("pipe_sel", "SELECT val FROM ffto_pg_pipe WHERE id = $1", false);
        pgc->prepareStatement("pipe_ins", "INSERT INTO ffto_pg_pipe VALUES ($1, $2)", false);
        pgc->prepareStatement("pipe_upd", "UPDATE ffto_pg_pipe SET val = $2 WHERE id = $1", false);

        /* Send Sync to get ParseComplete responses */
        pgc->sendSync();
        pgc->consumeInputUntilReady();

        /* Bind+Execute all 3 without Sync between them */
        pgc->bindStatement("pipe_sel", "",
            {{std::string("1"), 0}}, {}, false);
        pgc->executePortal("", 0, false);

        pgc->bindStatement("pipe_ins", "",
            {{std::string("10"), 0}, {std::string("pipelined"), 0}}, {}, false);
        pgc->executePortal("", 0, false);

        pgc->bindStatement("pipe_upd", "",
            {{std::string("1"), 0}, {std::string("pipe_updated"), 0}}, {}, false);
        pgc->executePortal("", 0, false);

        /* Single Sync for all 3 */
        pgc->sendSync();
        pgc->consumeInputUntilReady();
    } catch (const PgException& e) {
        diag("Pipeline scenario 1 failed: %s", e.what());
        FAIL_AND_SKIP_REMAINING(cleanup, "Pipeline failed");
    }

    verify_pg_digest(admin, "SELECT val FROM ffto_pg_pipe WHERE id = $1", 1, 0, 1);
    verify_pg_digest(admin, "INSERT INTO ffto_pg_pipe VALUES ($1,$2)", 1, 1, 0);
    verify_pg_digest(admin, "UPDATE ffto_pg_pipe SET val = $2 WHERE id = $1", 1, 1, 0);

    /* ================================================================
     * Scenario 2:  Same statement executed 10 times in pipeline
     *
     * Bind+Execute the same prepared statement 10 times, then Sync.
     * All 10 should aggregate into one digest with count_star=10.
     * ================================================================ */
    diag("--- Scenario 2: 10x pipelined execution ---");
    clear_pg_stats(admin);

    try {
        for (int i = 0; i < 10; i++) {
            char id_str[8];
            snprintf(id_str, sizeof(id_str), "%d", (i % 3) + 1);
            pgc->bindStatement("pipe_sel", "",
                {{std::string(id_str), 0}}, {}, false);
            pgc->executePortal("", 0, false);
        }
        pgc->sendSync();
        pgc->consumeInputUntilReady();
    } catch (const PgException& e) {
        diag("Pipeline scenario 2 failed: %s", e.what());
        FAIL_AND_SKIP_REMAINING(cleanup, "Pipeline 10x failed");
    }

    verify_pg_digest(admin, "SELECT val FROM ffto_pg_pipe WHERE id = $1", 10, 0, 10);

    /* ================================================================
     * Scenario 3:  extended Execute + Sync + SIMPLE query, pipelined
     *
     * Regression guard for stats attribution across an exchange boundary.
     * The client sends Bind/Execute, Sync, and then a simple Query without
     * reading anything in between, so two exchanges are in flight at once
     * and the server answers:
     *
     *   CommandComplete(Execute), ReadyForQuery(Sync),
     *   CommandComplete(Query),   ReadyForQuery(Query)
     *
     * The Execute's CommandComplete finalizes the Execute and activates the
     * simple query, which is queued behind it. The ReadyForQuery that then
     * arrives belongs to the *Sync*, i.e. to the exchange that just ended --
     * not to the simple query now sitting in front of it. Finalizing on it
     * reports the simple query with zero rows and pops the queue, so the
     * CommandComplete that really is its own is discarded and its digest
     * silently records rows_sent=0.
     *
     * Unlike scenarios 1 and 2 this ordering is deterministic, not a race:
     * the response sequence above follows purely from what the client sends.
     * ================================================================ */
    diag("--- Scenario 3: extended Execute + Sync + simple query ---");
    clear_pg_stats(admin);

    try {
        /* Exchange 1: extended Bind/Execute terminated by Sync. */
        pgc->bindStatement("pipe_sel", "",
            {{std::string("2"), 0}}, {}, false);
        pgc->executePortal("", 0, false);
        pgc->sendSync();

        /* Exchange 2: a simple query, sent WITHOUT reading exchange 1's
         * replies -- that overlap is the whole point of the scenario. */
        pgc->execute("SELECT count(*) FROM ffto_pg_pipe");

        /* Now drain both exchanges: one ReadyForQuery each. */
        pgc->consumeInputUntilReady();
        pgc->consumeInputUntilReady();
    } catch (const PgException& e) {
        diag("Pipeline scenario 3 failed: %s", e.what());
        FAIL_AND_SKIP_REMAINING(cleanup, "Pipelined exchange-boundary test failed");
    }

    /* The extended Execute is unaffected -- it is finalized by its own
     * CommandComplete before the boundary is crossed. */
    verify_pg_digest(admin, "SELECT val FROM ffto_pg_pipe WHERE id = $1", 1, 0, 1);
    /* The simple query is the one that gets zeroed when ReadyForQuery is
     * allowed to finalize a query that has not yet seen its own response. */
    verify_pg_digest(admin, "SELECT count(*) FROM ffto_pg_pipe", 1, 0, 1);

cleanup:
    if (pgc) { delete pgc; }
    if (admin) mysql_close(admin);
    return exit_status();
}
