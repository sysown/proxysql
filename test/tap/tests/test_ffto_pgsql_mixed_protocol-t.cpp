/**
 * @file test_ffto_pgsql_mixed_protocol-t.cpp
 * @brief FFTO E2E TAP test — PostgreSQL mixed simple + extended query.
 *
 * Validates that PgSQLFFTO correctly handles alternating between
 * simple query protocol (PQexec / 'Q' message) and extended query
 * protocol (PQprepare+PQexecPrepared / Parse+Bind+Execute) within
 * the same fast-forward session.
 *
 * @par Test scenarios
 *  1. Simple SELECT then extended SELECT — separate tracking
 *  2. Extended INSERT then simple UPDATE — clean state transition
 *  3. Repeated extended execution (20x) — count_star accuracy
 *
 * @pre  ProxySQL running with a PostgreSQL backend.
 *
 * @see  PgSQLFFTO.cpp — process_client_message() handles 'Q', 'P', 'B', 'E'
 */

#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <cstdint>
#include "libpq-fe.h"
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

/**
 * @brief Total number of planned TAP assertions.
 *
 * Breakdown:
 *  - Setup:               1 (connect)
 *  - Scenario 1 (simple+ext): 2 x 3 = 6
 *  - Scenario 2 (ext+simple): 2 x 3 = 6
 *  - Scenario 3 (20x exec):   1 x 3 = 3
 *  Total = 16
 */
static constexpr int kPlannedTests = 16;

#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
    do { \
        diag(fmt, ##__VA_ARGS__); \
        int remaining = kPlannedTests - tests_last(); \
        if (remaining > 0) { \
            skip(remaining, "Skipping remaining assertions after setup failure"); \
        } \
        goto cleanup_label; \
    } while (0)

#define EXEC_PG_QUERY(conn, q) \
    { \
        PGresult* res_exec = PQexec(conn, q); \
        if (!res_exec) { \
            ok(0, "PG Query failed: %s", q); \
            FAIL_AND_SKIP_REMAINING(cleanup, "No result: %s", PQerrorMessage(conn)); \
        } \
        if (PQresultStatus(res_exec) != PGRES_COMMAND_OK && \
            PQresultStatus(res_exec) != PGRES_TUPLES_OK) { \
            ok(0, "PG Query failed: %s", q); \
            PQclear(res_exec); \
            FAIL_AND_SKIP_REMAINING(cleanup, "Failed: %s", PQerrorMessage(conn)); \
        } \
        PQclear(res_exec); \
    }

/** @brief Verify PgSQL digest with polling. Emits 3 assertions. */
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

    diag("=== FFTO PostgreSQL Mixed Protocol Test ===");
    diag("Validates FFTO state transitions between simple and extended query.");
    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    PGconn* conn = NULL;

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

    {
        char ci[1024];
        snprintf(ci, sizeof(ci), "host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
                 cl.pgsql_host, cl.pgsql_port, cl.pgsql_root_username, cl.pgsql_root_password);
        conn = PQconnectdb(ci);
    }
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("PG connection failed: %s", PQerrorMessage(conn));
        FAIL_AND_SKIP_REMAINING(cleanup, "PG connection failed");
    }
    ok(conn != NULL, "Connected to PostgreSQL via ProxySQL");

    EXEC_PG_QUERY(conn, "DROP TABLE IF EXISTS ffto_pg_mixed");
    EXEC_PG_QUERY(conn, "CREATE TABLE ffto_pg_mixed (id INT PRIMARY KEY, val TEXT)");
    EXEC_PG_QUERY(conn, "INSERT INTO ffto_pg_mixed VALUES (1,'a'), (2,'b'), (3,'c')");

    /* ================================================================
     * Scenario 1:  Simple SELECT then extended SELECT
     *
     * Simple query uses 'Q' message, normalized with ? placeholders.
     * Extended query uses Parse+Bind+Execute with $1 parameters.
     * Both should produce separate digest entries.
     * ================================================================ */
    diag("--- Scenario 1: simple SELECT then extended SELECT ---");
    clear_pg_stats(admin);

    /* Simple protocol SELECT */
    {
        PGresult* rs = PQexec(conn, "SELECT val FROM ffto_pg_mixed WHERE id = 1");
        if (rs) PQclear(rs);
    }

    /* Extended protocol SELECT */
    {
        PGresult* prep = PQprepare(conn, "sel_mixed",
            "SELECT val FROM ffto_pg_mixed WHERE id = $1", 1, NULL);
        if (!prep || PQresultStatus(prep) != PGRES_COMMAND_OK) {
            diag("PQprepare failed: %s", PQerrorMessage(conn));
            if (prep) PQclear(prep);
            FAIL_AND_SKIP_REMAINING(cleanup, "PQprepare failed");
        }
        PQclear(prep);

        const char* pv[1] = {"2"};
        PGresult* rs = PQexecPrepared(conn, "sel_mixed", 1, pv, NULL, NULL, 0);
        if (rs) PQclear(rs);
    }

    /* Simple query normalizes with ? placeholder */
    verify_pg_digest(admin, "SELECT val FROM ffto_pg_mixed WHERE id = ?", 1, 0, 1);
    /* Extended query uses $1 parameter marker */
    verify_pg_digest(admin, "SELECT val FROM ffto_pg_mixed WHERE id = $1", 1, 0, 1);

    /* ================================================================
     * Scenario 2:  Extended INSERT then simple UPDATE
     *
     * Tests transition from extended protocol back to simple protocol.
     * FFTO state machine should cleanly reset between protocol modes.
     * ================================================================ */
    diag("--- Scenario 2: extended INSERT then simple UPDATE ---");
    clear_pg_stats(admin);

    /* Extended protocol INSERT */
    {
        PGresult* prep = PQprepare(conn, "ins_mixed",
            "INSERT INTO ffto_pg_mixed VALUES ($1, $2)", 2, NULL);
        if (!prep || PQresultStatus(prep) != PGRES_COMMAND_OK) {
            diag("PQprepare INSERT failed: %s", PQerrorMessage(conn));
            if (prep) PQclear(prep);
            FAIL_AND_SKIP_REMAINING(cleanup, "PQprepare INSERT failed");
        }
        PQclear(prep);

        const char* pv[2] = {"10", "extended_val"};
        PGresult* rs = PQexecPrepared(conn, "ins_mixed", 2, pv, NULL, NULL, 0);
        if (rs) PQclear(rs);
    }

    /* Simple protocol UPDATE */
    EXEC_PG_QUERY(conn, "UPDATE ffto_pg_mixed SET val = 'updated' WHERE id = 10");

    verify_pg_digest(admin, "INSERT INTO ffto_pg_mixed VALUES ($1,$2)", 1, 1, 0);
    verify_pg_digest(admin, "UPDATE ffto_pg_mixed SET val", 1, 1, 0);

    /* ================================================================
     * Scenario 3:  Extended statement executed 20 times
     *
     * All executions share the same prepared statement and digest.
     * count_star should be >= 20, sum_rows_sent should be 20.
     * ================================================================ */
    diag("--- Scenario 3: extended SELECT x20 ---");
    clear_pg_stats(admin);

    {
        PGresult* prep = PQprepare(conn, "sel_repeat",
            "SELECT val FROM ffto_pg_mixed WHERE id = $1", 1, NULL);
        if (!prep || PQresultStatus(prep) != PGRES_COMMAND_OK) {
            diag("PQprepare repeat failed: %s", PQerrorMessage(conn));
            if (prep) PQclear(prep);
            FAIL_AND_SKIP_REMAINING(cleanup, "PQprepare repeat failed");
        }
        PQclear(prep);

        for (int i = 0; i < 20; i++) {
            char id_str[8];
            snprintf(id_str, sizeof(id_str), "%d", (i % 3) + 1);
            const char* pv[1] = {id_str};
            PGresult* rs = PQexecPrepared(conn, "sel_repeat", 1, pv, NULL, NULL, 0);
            if (rs) PQclear(rs);
        }
    }

    verify_pg_digest(admin, "SELECT val FROM ffto_pg_mixed WHERE id = $1", 20, 0, 20);

cleanup:
    if (conn) PQfinish(conn);
    if (admin) mysql_close(admin);
    return exit_status();
}
