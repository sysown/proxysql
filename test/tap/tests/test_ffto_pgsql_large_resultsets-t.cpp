/**
 * @file test_ffto_pgsql_large_resultsets-t.cpp
 * @brief FFTO E2E TAP test — PostgreSQL large result sets.
 *
 * Validates that the Fast Forward Traffic Observer (FFTO) correctly tracks
 * query digest statistics when PostgreSQL queries produce large result sets.
 * Exercises the FFTO row-counting logic under sustained load via the
 * CommandComplete tag parsing in PgSQLFFTO::process_server_message().
 *
 * @par Test scenarios
 *  1. SELECT returning 10,000 rows — verify sum_rows_sent accuracy
 *  2. SELECT returning rows with ~1 KB TEXT payload (50 rows)
 *  3. Result set under ffto_max_buffer_size threshold — FFTO stays active
 *  4. Bulk INSERT of 500 rows — verify sum_rows_affected accuracy
 *
 * @pre  ProxySQL running with a PostgreSQL backend, reachable via the
 *       standard TAP environment variables (TAP_PGSQL_HOST, etc.).
 *
 * @see  test_ffto_pgsql-t.cpp for the foundational PgSQL FFTO test pattern
 * @see  PgSQLFFTO.cpp — extract_pg_rows_affected() parses CommandComplete tags
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
 *  - Scenario 1 (10K rows):    1 (connect) + 3 (verify) = 4
 *  - Scenario 2 (TEXT data):   3 (verify)               = 3
 *  - Scenario 3 (under threshold): 3 (verify)           = 3
 *  - Scenario 4 (bulk INSERT): 3 (verify)               = 3
 *  Total = 13
 */
static constexpr int kPlannedTests = 13;

/** @brief Skip remaining TAP assertions and jump to cleanup. */
#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
    do { \
        diag(fmt, ##__VA_ARGS__); \
        int remaining = kPlannedTests - tests_last(); \
        if (remaining > 0) { \
            skip(remaining, "Skipping remaining assertions after setup failure"); \
        } \
        goto cleanup_label; \
    } while (0)

/** @brief Execute a PgSQL query via simple protocol, bail on failure. */
#define EXEC_PG_QUERY(conn, q) \
    { \
        PGresult* res_exec = PQexec(conn, q); \
        if (!res_exec) { \
            ok(0, "PG Query failed: %s", q); \
            FAIL_AND_SKIP_REMAINING(cleanup, "PG Query returned no result: %s", PQerrorMessage(conn)); \
        } \
        if (PQresultStatus(res_exec) != PGRES_COMMAND_OK && PQresultStatus(res_exec) != PGRES_TUPLES_OK) { \
            ok(0, "PG Query failed: %s — %s", q, PQerrorMessage(conn)); \
            PQclear(res_exec); \
            FAIL_AND_SKIP_REMAINING(cleanup, "PG Query failed: %s", PQerrorMessage(conn)); \
        } \
        PQclear(res_exec); \
    }

/**
 * @brief Verify a PgSQL query digest exists with expected counters.
 *
 * Polls stats_pgsql_query_digest (via MySQL admin) for up to 2 seconds.
 * Emits 3 TAP assertions: count_star, sum_rows_affected, sum_rows_sent.
 *
 * @param admin               MySQL admin connection to ProxySQL.
 * @param template_text       Substring to match against digest_text.
 * @param expected_count      Minimum expected count_star.
 * @param expected_rows_affected  Expected sum_rows_affected.
 * @param expected_rows_sent      Expected sum_rows_sent.
 */
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
        mysql_free_result(res);
        res = NULL;
        usleep(100000);
    }

    if (row) {
        int count = atoi(row[0]);
        uint64_t rows_affected = strtoull(row[1], NULL, 10);
        uint64_t rows_sent = strtoull(row[2], NULL, 10);

        ok(count >= expected_count,
           "PG digest count for '%s': %d (expected >= %d)", row[3], count, expected_count);
        ok(rows_affected == expected_rows_affected,
           "PG rows_affected for '%s': %llu (expected %llu)",
           row[3], (unsigned long long)rows_affected, (unsigned long long)expected_rows_affected);
        ok(rows_sent == expected_rows_sent,
           "PG rows_sent for '%s': %llu (expected %llu)",
           row[3], (unsigned long long)rows_sent, (unsigned long long)expected_rows_sent);
    } else {
        ok(0, "PG digest NOT found for pattern: %s", template_text);
        ok(0, "Skipping PG rows_affected check (digest not found)");
        ok(0, "Skipping PG rows_sent check (digest not found)");
        diag("Dumping stats_pgsql_query_digest for debugging:");
        run_q(admin, "SELECT digest_text, count_star FROM stats_pgsql_query_digest");
        MYSQL_RES* dump_res = mysql_store_result(admin);
        MYSQL_ROW dump_row;
        while (dump_res && (dump_row = mysql_fetch_row(dump_res))) {
            diag("  digest: %s  count: %s", dump_row[0], dump_row[1]);
        }
        if (dump_res) mysql_free_result(dump_res);
    }
    if (res) mysql_free_result(res);
}

/** @brief Atomically clear stats_pgsql_query_digest via the _reset table. */
static void clear_pg_stats(MYSQL* admin) {
    mysql_query(admin, "SELECT * FROM stats_pgsql_query_digest_reset");
    MYSQL_RES* r = mysql_store_result(admin);
    if (r) mysql_free_result(r);
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    diag("=== FFTO PostgreSQL Large Result Sets Test ===");
    diag("Validates FFTO row counting with large PgSQL result sets");
    diag("(10K+ rows, TEXT columns, bulk INSERT).");
    diag("===============================================");

    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    PGconn* conn = NULL;

    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
                           NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed: %s", mysql_error(admin));
        return -1;
    }

    /* ── FFTO Configuration ─────────────────────────────────────────── */
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


    /* Ensure backend server is registered */
    {
        char sq[1024];
        snprintf(sq, sizeof(sq),
            "INSERT OR REPLACE INTO pgsql_servers (hostgroup_id, hostname, port) "
            "VALUES (0, '%s', %d)", cl.pgsql_server_host, cl.pgsql_server_port);
        MYSQL_QUERY(admin, sq);
        MYSQL_QUERY(admin, "LOAD PGSQL SERVERS TO RUNTIME");
    }

    clear_pg_stats(admin);

    /* ── PgSQL Client Connection ────────────────────────────────────── */
    {
        char conninfo[1024];
        snprintf(conninfo, sizeof(conninfo),
            "host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
            cl.pgsql_host, cl.pgsql_port,
            cl.pgsql_root_username, cl.pgsql_root_password);
        conn = PQconnectdb(conninfo);
    }
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("PG connection failed: %s", PQerrorMessage(conn));
        FAIL_AND_SKIP_REMAINING(cleanup, "PG connection failed");
    }
    ok(conn != NULL, "Connected to PostgreSQL via ProxySQL");

    /* ================================================================
     * Scenario 1:  SELECT returning 10,000 rows
     * ================================================================ */
    diag("--- Scenario 1: 10K-row SELECT ---");
    EXEC_PG_QUERY(conn, "DROP TABLE IF EXISTS ffto_pg_large");
    EXEC_PG_QUERY(conn, "CREATE TABLE ffto_pg_large ("
                        "id SERIAL PRIMARY KEY, val VARCHAR(64))");

    /* Use generate_series for efficient bulk insert */
    EXEC_PG_QUERY(conn,
        "INSERT INTO ffto_pg_large (val) "
        "SELECT 'row_' || g FROM generate_series(1, 10000) AS g");

    clear_pg_stats(admin);

    {
        PGresult* rs = PQexec(conn, "SELECT id,val FROM ffto_pg_large");
        if (!rs || PQresultStatus(rs) != PGRES_TUPLES_OK) {
            diag("Large SELECT failed: %s", PQerrorMessage(conn));
            if (rs) PQclear(rs);
            FAIL_AND_SKIP_REMAINING(cleanup, "Large SELECT failed");
        }
        diag("Fetched %d rows from large SELECT", PQntuples(rs));
        PQclear(rs);
    }

    verify_pg_digest(admin, "SELECT id,val FROM ffto_pg_large", 1, 0, 10000);

    /* ================================================================
     * Scenario 2:  SELECT with ~1 KB TEXT columns (50 rows)
     * ================================================================ */
    diag("--- Scenario 2: TEXT-column result set ---");
    EXEC_PG_QUERY(conn, "DROP TABLE IF EXISTS ffto_pg_text");
    EXEC_PG_QUERY(conn, "CREATE TABLE ffto_pg_text ("
                        "id SERIAL PRIMARY KEY, data TEXT)");

    EXEC_PG_QUERY(conn,
        "INSERT INTO ffto_pg_text (data) "
        "SELECT repeat('A', 1000) FROM generate_series(1, 50)");

    clear_pg_stats(admin);

    {
        PGresult* rs = PQexec(conn, "SELECT id,data FROM ffto_pg_text");
        if (!rs || PQresultStatus(rs) != PGRES_TUPLES_OK) {
            diag("TEXT SELECT failed: %s", PQerrorMessage(conn));
            if (rs) PQclear(rs);
            FAIL_AND_SKIP_REMAINING(cleanup, "TEXT SELECT failed");
        }
        PQclear(rs);
    }

    verify_pg_digest(admin, "SELECT id,data FROM ffto_pg_text", 1, 0, 50);

    /* ================================================================
     * Scenario 3:  Result set under threshold — FFTO stays active
     * ================================================================ */
    diag("--- Scenario 3: result set under 64 KB threshold ---");

    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='65536' "
                       "WHERE variable_name='pgsql-ffto_max_buffer_size'");
    MYSQL_QUERY(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

    /* Need fresh connection for new buffer size */
    PQfinish(conn);
    {
        char conninfo[1024];
        snprintf(conninfo, sizeof(conninfo),
            "host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
            cl.pgsql_host, cl.pgsql_port,
            cl.pgsql_root_username, cl.pgsql_root_password);
        conn = PQconnectdb(conninfo);
    }
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("PG reconnect failed: %s", PQerrorMessage(conn));
        FAIL_AND_SKIP_REMAINING(cleanup, "PG reconnect failed");
    }

    EXEC_PG_QUERY(conn, "DROP TABLE IF EXISTS ffto_pg_threshold");
    EXEC_PG_QUERY(conn, "CREATE TABLE ffto_pg_threshold ("
                        "id SERIAL PRIMARY KEY, data VARCHAR(255))");
    /* 20 rows x ~200 bytes = ~4 KB, well under 64 KB */
    EXEC_PG_QUERY(conn,
        "INSERT INTO ffto_pg_threshold (data) "
        "SELECT repeat('B', 200) FROM generate_series(1, 20)");

    clear_pg_stats(admin);

    {
        PGresult* rs = PQexec(conn, "SELECT id,data FROM ffto_pg_threshold");
        if (!rs || PQresultStatus(rs) != PGRES_TUPLES_OK) {
            diag("Threshold SELECT failed: %s", PQerrorMessage(conn));
            if (rs) PQclear(rs);
            FAIL_AND_SKIP_REMAINING(cleanup, "Threshold SELECT failed");
        }
        PQclear(rs);
    }

    verify_pg_digest(admin, "SELECT id,data FROM ffto_pg_threshold", 1, 0, 20);

    /* ================================================================
     * Scenario 4:  Bulk INSERT — verify sum_rows_affected
     * ================================================================ */
    diag("--- Scenario 4: bulk INSERT rows_affected ---");

    /* Restore large buffer */
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='1048576' "
                       "WHERE variable_name='pgsql-ffto_max_buffer_size'");
    MYSQL_QUERY(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

    PQfinish(conn);
    {
        char conninfo[1024];
        snprintf(conninfo, sizeof(conninfo),
            "host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
            cl.pgsql_host, cl.pgsql_port,
            cl.pgsql_root_username, cl.pgsql_root_password);
        conn = PQconnectdb(conninfo);
    }
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("PG reconnect failed: %s", PQerrorMessage(conn));
        FAIL_AND_SKIP_REMAINING(cleanup, "PG reconnect failed");
    }

    EXEC_PG_QUERY(conn, "DROP TABLE IF EXISTS ffto_pg_bulk");
    EXEC_PG_QUERY(conn, "CREATE TABLE ffto_pg_bulk ("
                        "id SERIAL PRIMARY KEY, val VARCHAR(64))");

    clear_pg_stats(admin);

    EXEC_PG_QUERY(conn,
        "INSERT INTO ffto_pg_bulk (val) "
        "SELECT 'bulk_' || g FROM generate_series(1, 500) AS g");

    verify_pg_digest(admin, "INSERT INTO ffto_pg_bulk", 1, 500, 0);

cleanup:
    if (conn) PQfinish(conn);
    if (admin) mysql_close(admin);

    return exit_status();
}
