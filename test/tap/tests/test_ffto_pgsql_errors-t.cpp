/**
 * @file test_ffto_pgsql_errors-t.cpp
 * @brief FFTO E2E TAP test — PostgreSQL error handling.
 *
 * Validates that PgSQLFFTO gracefully handles ErrorResponse ('E')
 * messages from the PostgreSQL backend. When an error occurs, FFTO
 * should report partial stats for the failed query and cleanly
 * transition back to IDLE state for subsequent queries.
 *
 * @par Test scenarios
 *  1. Syntax error followed by successful query — recovery
 *  2. Constraint violation (duplicate key) — recovery
 *  3. Error within transaction — ROLLBACK tracked
 *
 * @pre  ProxySQL running with a PostgreSQL backend.
 *
 * @see  PgSQLFFTO.cpp — process_server_message() handles 'E' (ErrorResponse)
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
 *  - Setup:                   1 (connect)
 *  - Scenario 1 (syntax):    3 (recovery query digest)
 *  - Scenario 2 (constraint): 3 (successful INSERT after failure)
 *  - Scenario 3 (txn error): 3 (ROLLBACK digest)
 *  Total = 10
 */
static constexpr int kPlannedTests = 10;

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
        uint64_t rs = strtoull(row[2], NULL, 10);
        ok(count >= expected_count, "PG digest '%s': count=%d (>= %d)", row[3], count, expected_count);
        ok(ra == expected_rows_affected, "PG rows_affected '%s': %llu (== %llu)",
           row[3], (unsigned long long)ra, (unsigned long long)expected_rows_affected);
        ok(rs == expected_rows_sent, "PG rows_sent '%s': %llu (== %llu)",
           row[3], (unsigned long long)rs, (unsigned long long)expected_rows_sent);
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

    diag("=== FFTO PostgreSQL Error Handling Test ===");
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

    EXEC_PG_QUERY(conn, "DROP TABLE IF EXISTS ffto_pg_err");
    EXEC_PG_QUERY(conn, "CREATE TABLE ffto_pg_err (id INT PRIMARY KEY, val TEXT)");
    EXEC_PG_QUERY(conn, "INSERT INTO ffto_pg_err VALUES (1, 'existing')");

    /* ================================================================
     * Scenario 1:  Syntax error followed by successful query
     * ================================================================ */
    diag("--- Scenario 1: syntax error recovery ---");
    clear_pg_stats(admin);

    {
        PGresult* rs = PQexec(conn, "SELEC BAD SYNTAX HERE");
        if (rs) { diag("Error status: %s", PQresStatus(PQresultStatus(rs))); PQclear(rs); }
    }

    { PGresult* rs = PQexec(conn, "SELECT val FROM ffto_pg_err WHERE id = 1"); if (rs) PQclear(rs); }

    verify_pg_digest(admin, "SELECT val FROM ffto_pg_err WHERE id", 1, 0, 1);

    /* ================================================================
     * Scenario 2:  Constraint violation — duplicate key
     * ================================================================ */
    diag("--- Scenario 2: constraint violation recovery ---");
    clear_pg_stats(admin);

    { PGresult* rs = PQexec(conn, "INSERT INTO ffto_pg_err VALUES (1, 'duplicate')");
      if (rs) { diag("Dup key: %s", PQresStatus(PQresultStatus(rs))); PQclear(rs); } }

    EXEC_PG_QUERY(conn, "INSERT INTO ffto_pg_err VALUES (2, 'new_row')");

    verify_pg_digest(admin, "INSERT INTO ffto_pg_err VALUES", 1, 1, 0);

    /* ================================================================
     * Scenario 3:  Error within transaction — ROLLBACK tracked
     * ================================================================ */
    diag("--- Scenario 3: error in transaction ---");
    clear_pg_stats(admin);

    EXEC_PG_QUERY(conn, "BEGIN");
    { PGresult* rs = PQexec(conn, "INSERT INTO ffto_pg_err VALUES (1, 'dup_txn')");
      if (rs) PQclear(rs); }
    EXEC_PG_QUERY(conn, "ROLLBACK");

    verify_pg_digest(admin, "ROLLBACK", 1, 0, 0);

cleanup:
    if (conn) PQfinish(conn);
    if (admin) mysql_close(admin);
    return exit_status();
}
