/**
 * @file test_ffto_pgsql_command_types-t.cpp
 * @brief FFTO E2E TAP test — PostgreSQL CommandComplete tag varieties.
 *
 * Validates that PgSQLFFTO correctly parses all standard PostgreSQL
 * CommandComplete tag formats and records the appropriate row counts.
 * The CommandComplete message ('C') contains a tag string like
 * "INSERT 0 5", "SELECT 10", "UPDATE 3", "DELETE 1", "CREATE TABLE", etc.
 * PgSQLFFTO::extract_pg_rows_affected() must handle all these formats.
 *
 * @par Test scenarios
 *  1. Standard DML: INSERT, UPDATE, DELETE, SELECT — each with row counts
 *  2. DDL commands: CREATE TABLE, DROP TABLE, ALTER TABLE — no row count
 *  3. 100 rapid-fire SELECTs — verify count_star accuracy
 *
 * @pre  ProxySQL running with a PostgreSQL backend.
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
 *  - Setup:              1 (connect)
 *  - Scenario 1 (DML):  4 x 3 = 12 (INSERT, SELECT, UPDATE, DELETE)
 *  - Scenario 2 (DDL):  1 (CREATE TABLE digest exists)
 *  - Scenario 3 (rapid): 3 (verify count_star >= 100)
 *  Total = 1 + 12 + 1 + 3 = 17
 */
static constexpr int kPlannedTests = 17;

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
            FAIL_AND_SKIP_REMAINING(cleanup, "PG Query returned no result: %s", PQerrorMessage(conn)); \
        } \
        if (PQresultStatus(res_exec) != PGRES_COMMAND_OK && PQresultStatus(res_exec) != PGRES_TUPLES_OK) { \
            ok(0, "PG Query failed: %s", q); \
            PQclear(res_exec); \
            FAIL_AND_SKIP_REMAINING(cleanup, "PG Query failed: %s", PQerrorMessage(conn)); \
        } \
        PQclear(res_exec); \
    }

/**
 * @brief Verify a PgSQL query digest exists with expected counters.
 *
 * Polls stats_pgsql_query_digest for up to 2 seconds. Emits 3 assertions.
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
        ok(count >= expected_count, "PG digest count for '%s': %d (expected >= %d)",
           row[3], count, expected_count);
        ok(rows_affected == expected_rows_affected, "PG rows_affected for '%s': %llu (expected %llu)",
           row[3], (unsigned long long)rows_affected, (unsigned long long)expected_rows_affected);
        ok(rows_sent == expected_rows_sent, "PG rows_sent for '%s': %llu (expected %llu)",
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

static void clear_pg_stats(MYSQL* admin) {
    mysql_query(admin, "SELECT * FROM stats_pgsql_query_digest_reset");
    MYSQL_RES* r = mysql_store_result(admin);
    if (r) mysql_free_result(r);
}

/**
 * @brief Poll stats for a digest and return count_star, or 0 if not found.
 */
static int poll_pg_digest_count(MYSQL* admin, const char* template_text) {
    char query[1024];
    snprintf(query, sizeof(query),
        "SELECT count_star FROM stats_pgsql_query_digest "
        "WHERE digest_text LIKE '%%%s%%'", template_text);
    int count = 0;
    for (int attempt = 0; attempt < 20; attempt++) {
        run_q(admin, query);
        MYSQL_RES* res = mysql_store_result(admin);
        if (!res) { usleep(100000); continue; }
        MYSQL_ROW row = mysql_fetch_row(res);
        count = row ? atoi(row[0]) : 0;
        if (res) mysql_free_result(res);
        if (count > 0) return count;
        usleep(100000);
    }
    return count;
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    diag("=== FFTO PostgreSQL Command Types Test ===");
    diag("Validates FFTO CommandComplete tag parsing for all DML/DDL types.");
    diag("============================================");

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

    {
        char sq[1024];
        snprintf(sq, sizeof(sq),
            "INSERT OR REPLACE INTO pgsql_servers (hostgroup_id, hostname, port) "
            "VALUES (0, '%s', %d)", cl.pgsql_server_host, cl.pgsql_server_port);
        MYSQL_QUERY(admin, sq);
        MYSQL_QUERY(admin, "LOAD PGSQL SERVERS TO RUNTIME");
    }

    /* ── PgSQL Connection ───────────────────────────────────────────── */
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
     * Scenario 1:  Standard DML types — INSERT, SELECT, UPDATE, DELETE
     *
     * Each produces a CommandComplete tag with a row count:
     *  - "INSERT 0 3" -> rows_affected=3
     *  - "SELECT 2"   -> rows_sent=2
     *  - "UPDATE 1"   -> rows_affected=1
     *  - "DELETE 1"   -> rows_affected=1
     * ================================================================ */
    diag("--- Scenario 1: DML command types ---");

    EXEC_PG_QUERY(conn, "DROP TABLE IF EXISTS ffto_pg_cmd");
    EXEC_PG_QUERY(conn, "CREATE TABLE ffto_pg_cmd ("
                        "id INT PRIMARY KEY, val TEXT)");

    clear_pg_stats(admin);

    EXEC_PG_QUERY(conn,
        "INSERT INTO ffto_pg_cmd VALUES (1,'a'), (2,'b'), (3,'c')");

    {
        PGresult* rs = PQexec(conn, "SELECT val FROM ffto_pg_cmd WHERE id <= 2");
        if (rs) PQclear(rs);
    }

    EXEC_PG_QUERY(conn, "UPDATE ffto_pg_cmd SET val = 'updated' WHERE id = 1");
    EXEC_PG_QUERY(conn, "DELETE FROM ffto_pg_cmd WHERE id = 3");

    verify_pg_digest(admin, "INSERT INTO ffto_pg_cmd VALUES", 1, 3, 0);
    verify_pg_digest(admin, "SELECT val FROM ffto_pg_cmd WHERE id", 1, 0, 2);
    verify_pg_digest(admin, "UPDATE ffto_pg_cmd SET val", 1, 1, 0);
    verify_pg_digest(admin, "DELETE FROM ffto_pg_cmd WHERE id", 1, 1, 0);

    /* ================================================================
     * Scenario 2:  DDL commands — no row count in CommandComplete tag
     *
     * DDL commands produce tags like "CREATE TABLE", "DROP TABLE".
     * FFTO should still record the digest with rows_affected=0.
     * ================================================================ */
    diag("--- Scenario 2: DDL command types ---");
    clear_pg_stats(admin);

    EXEC_PG_QUERY(conn, "DROP TABLE IF EXISTS ffto_pg_ddl_test");
    EXEC_PG_QUERY(conn, "CREATE TABLE ffto_pg_ddl_test (id INT)");
    EXEC_PG_QUERY(conn, "ALTER TABLE ffto_pg_ddl_test ADD COLUMN val TEXT");
    EXEC_PG_QUERY(conn, "DROP TABLE ffto_pg_ddl_test");

    {
        int count = poll_pg_digest_count(admin, "CREATE TABLE ffto_pg_ddl_test");
        ok(count >= 1, "DDL CREATE TABLE recorded (count: %d)", count);
    }

    /* ================================================================
     * Scenario 3:  100 rapid-fire SELECTs — verify count_star accuracy
     * ================================================================ */
    diag("--- Scenario 3: rapid-fire 100 SELECTs ---");
    clear_pg_stats(admin);

    for (int i = 0; i < 100; i++) {
        PGresult* rs = PQexec(conn, "SELECT 1 AS rapid_fire");
        if (rs) PQclear(rs);
    }

    verify_pg_digest(admin, "SELECT ? AS rapid_fire", 100, 0, 100);

cleanup:
    if (conn) PQfinish(conn);
    if (admin) mysql_close(admin);

    return exit_status();
}
