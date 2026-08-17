/**
 * @file test_ffto_mysql_transactions-t.cpp
 * @brief FFTO E2E TAP test — transaction patterns and repeated prepared
 *        statement execution.
 *
 * Validates that the Fast Forward Traffic Observer (FFTO) correctly tracks
 * individual query digests within explicit transactions (BEGIN/COMMIT/ROLLBACK)
 * and accurately counts repeated prepared statement executions.
 *
 * In fast-forward mode, ProxySQL forwards packets directly to the backend.
 * FFTO observes each COM_QUERY and COM_STMT_EXECUTE independently, so every
 * statement within a transaction should produce its own digest entry.
 *
 * @par Test scenarios
 *  1. BEGIN → 2× INSERT → COMMIT — each statement gets its own digest
 *  2. BEGIN → INSERT → SELECT → ROLLBACK — all 4 statements tracked
 *  3. Prepared statement executed 20 times — count_star and rows_affected
 *  4. SAVEPOINT → DML → RELEASE SAVEPOINT — intermediate statements tracked
 *
 * @pre  ProxySQL running with a MySQL backend, reachable via the standard
 *       TAP environment variables.
 */

#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <cstdint>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

/**
 * @brief Total number of planned TAP assertions.
 *
 * Breakdown (stats cleared between scenarios):
 *  - Setup:      1 (connect ok)
 *  - Scenario 1: 3 verify_digest calls (BEGIN, INSERT, COMMIT)         = 9
 *  - Scenario 2: 4 verify_digest calls (BEGIN, INSERT, SELECT, ROLLBACK) = 12
 *  - Scenario 3: 1 verify_digest call  (prepared INSERT ×20)           = 3
 *  - Scenario 4: 3 verify_digest calls (SAVEPOINT, INSERT, RELEASE)    = 9
 *  Total = 1 + 9 + 12 + 3 + 9 = 34
 */
static constexpr int kPlannedTests = 34;

/** @copydoc FAIL_AND_SKIP_REMAINING */
#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
    do { \
        diag(fmt, ##__VA_ARGS__); \
        int remaining = kPlannedTests - tests_last(); \
        if (remaining > 0) { \
            skip(remaining, "Skipping remaining assertions after setup failure"); \
        } \
        goto cleanup_label; \
    } while (0)

/** @copydoc EXEC_QUERY */
#define EXEC_QUERY(conn, q) \
    do { \
        if (mysql_query(conn, q)) { \
            ok(0, "Query failed: %s", q); \
            FAIL_AND_SKIP_REMAINING(cleanup, "Query failed: %s", mysql_error(conn)); \
        } \
        MYSQL_RES* dummy_res = mysql_store_result(conn); \
        if (dummy_res) { \
            mysql_free_result(dummy_res); \
        } else if (mysql_field_count(conn) > 0) { \
            ok(0, "Failed to store result for query: %s", q); \
            FAIL_AND_SKIP_REMAINING(cleanup, "Error storing result: %s", mysql_error(conn)); \
        } \
    } while (0)

/**
 * @brief Verify that a query digest exists with expected counters.
 *
 * Polls stats_mysql_query_digest for up to 2 seconds.  Emits 3 TAP
 * assertions: count_star, sum_rows_affected, sum_rows_sent.
 *
 * @param admin               Admin MYSQL* connection.
 * @param template_text       Substring to match against digest_text.
 * @param expected_count      Minimum expected count_star.
 * @param expected_rows_affected  Expected sum_rows_affected.
 * @param expected_rows_sent      Expected sum_rows_sent.
 */
void verify_digest(MYSQL* admin, const char* template_text, int expected_count,
                   uint64_t expected_rows_affected = 0, uint64_t expected_rows_sent = 0) {
    char query[1024];
    snprintf(query, sizeof(query),
        "SELECT count_star, sum_rows_affected, sum_rows_sent, digest_text "
        "FROM stats_mysql_query_digest WHERE digest_text LIKE '%%%s%%'",
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
           "Digest count for '%s': %d (expected >= %d)", row[3], count, expected_count);
        ok(rows_affected == expected_rows_affected,
           "rows_affected for '%s': %llu (expected %llu)",
           row[3], (unsigned long long)rows_affected, (unsigned long long)expected_rows_affected);
        ok(rows_sent == expected_rows_sent,
           "rows_sent for '%s': %llu (expected %llu)",
           row[3], (unsigned long long)rows_sent, (unsigned long long)expected_rows_sent);
    } else {
        ok(0, "Digest NOT found for pattern: %s", template_text);
        ok(0, "Skipping rows_affected check (digest not found)");
        ok(0, "Skipping rows_sent check (digest not found)");
        diag("Dumping stats_mysql_query_digest for debugging:");
        run_q(admin, "SELECT digest_text, count_star FROM stats_mysql_query_digest");
        MYSQL_RES* dump_res = mysql_store_result(admin);
        MYSQL_ROW dump_row;
        while (dump_res && (dump_row = mysql_fetch_row(dump_res))) {
            diag("  digest: %s  count: %s", dump_row[0], dump_row[1]);
        }
        if (dump_res) mysql_free_result(dump_res);
    }
    if (res) mysql_free_result(res);
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    diag("=== FFTO MySQL Transactions Test ===");
    diag("Validates per-statement digest tracking within explicit");
    diag("transactions and repeated prepared statement execution.");
    diag("====================================");

    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    MYSQL* conn = NULL;
    MYSQL_STMT* stmt = NULL;

    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
                           NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed: %s", mysql_error(admin));
        return -1;
    }

    /* ── FFTO Configuration ─────────────────────────────────────────── */
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

    /* ── Client Connection ──────────────────────────────────────────── */
    conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, cl.host, cl.root_username, cl.root_password,
                           NULL, cl.port, NULL, 0)) {
        diag("Client connection failed: %s", mysql_error(conn));
        return -1;
    }
    ok(conn != NULL, "Connected to ProxySQL in fast-forward mode");

    EXEC_QUERY(conn, "CREATE DATABASE IF NOT EXISTS ffto_db");
    EXEC_QUERY(conn, "USE ffto_db");
    EXEC_QUERY(conn, "DROP TABLE IF EXISTS ffto_txn");
    EXEC_QUERY(conn, "CREATE TABLE ffto_txn ("
                     "id INT PRIMARY KEY, "
                     "val VARCHAR(255))");

    /* ================================================================
     * Scenario 1:  BEGIN → 2× INSERT → COMMIT
     *
     * Each statement is a separate COM_QUERY.  FFTO should record:
     *  - BEGIN:  count_star=1, rows_affected=0, rows_sent=0
     *  - INSERT: count_star=2, rows_affected=2 (1 per exec), rows_sent=0
     *  - COMMIT: count_star=1, rows_affected=0, rows_sent=0
     * ================================================================ */
    diag("--- Scenario 1: BEGIN / INSERT / INSERT / COMMIT ---");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    EXEC_QUERY(conn, "BEGIN");
    EXEC_QUERY(conn, "INSERT INTO ffto_txn (id, val) VALUES (1, 'txn_a')");
    EXEC_QUERY(conn, "INSERT INTO ffto_txn (id, val) VALUES (2, 'txn_b')");
    EXEC_QUERY(conn, "COMMIT");

    verify_digest(admin, "BEGIN", 1, 0, 0);
    verify_digest(admin, "INSERT INTO ffto_txn", 2, 2, 0);
    verify_digest(admin, "COMMIT", 1, 0, 0);

    /* ================================================================
     * Scenario 2:  BEGIN → INSERT → SELECT → ROLLBACK
     *
     * FFTO should track all 4 statement types independently.
     * The SELECT within the transaction should see the uncommitted row.
     * ================================================================ */
    diag("--- Scenario 2: BEGIN / INSERT / SELECT / ROLLBACK ---");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    EXEC_QUERY(conn, "BEGIN");
    EXEC_QUERY(conn, "INSERT INTO ffto_txn (id, val) VALUES (100, 'rollback_me')");

    /* SELECT within transaction — should see the uncommitted row */
    if (mysql_query(conn, "SELECT val FROM ffto_txn WHERE id = 100")) {
        diag("SELECT in txn failed: %s", mysql_error(conn));
        FAIL_AND_SKIP_REMAINING(cleanup, "SELECT in txn failed");
    }
    {
        MYSQL_RES* rs = mysql_store_result(conn);
        if (rs) {
            diag("SELECT in txn returned %llu rows",
                 (unsigned long long)mysql_num_rows(rs));
            mysql_free_result(rs);
        }
    }

    EXEC_QUERY(conn, "ROLLBACK");

    verify_digest(admin, "BEGIN", 1, 0, 0);
    verify_digest(admin, "INSERT INTO ffto_txn", 1, 1, 0);
    verify_digest(admin, "SELECT val FROM ffto_txn WHERE id", 1, 0, 1);
    verify_digest(admin, "ROLLBACK", 1, 0, 0);

    /* ================================================================
     * Scenario 3:  Prepared statement executed 20 times
     *
     * Uses COM_STMT_PREPARE + COM_STMT_EXECUTE (binary protocol).
     * All 20 executions share the same digest because the SQL template
     * is identical; only parameter values differ.  FFTO tracks this via
     * the m_statements map (stmt_id → SQL text).
     * ================================================================ */
    diag("--- Scenario 3: prepared INSERT × 20 ---");

    /* Clean table state */
    EXEC_QUERY(conn, "DELETE FROM ffto_txn");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    {
        const char* ps_query = "INSERT INTO ffto_txn (id, val) VALUES (?, ?)";
        stmt = mysql_stmt_init(conn);
        if (mysql_stmt_prepare(stmt, ps_query, strlen(ps_query))) {
            diag("mysql_stmt_prepare failed: %s", mysql_stmt_error(stmt));
            FAIL_AND_SKIP_REMAINING(cleanup, "mysql_stmt_prepare failed");
        }

        MYSQL_BIND bind[2];
        int id_val = 0;
        char str_val[64] = "";
        unsigned long str_len = 0;

        memset(bind, 0, sizeof(bind));
        bind[0].buffer_type = MYSQL_TYPE_LONG;
        bind[0].buffer = (char*)&id_val;
        bind[1].buffer_type = MYSQL_TYPE_STRING;
        bind[1].buffer = (char*)str_val;
        bind[1].buffer_length = sizeof(str_val);
        bind[1].length = &str_len;

        if (mysql_stmt_bind_param(stmt, bind)) {
            diag("mysql_stmt_bind_param failed: %s", mysql_stmt_error(stmt));
            FAIL_AND_SKIP_REMAINING(cleanup, "bind_param failed");
        }

        for (int i = 0; i < 20; i++) {
            id_val = 200 + i;
            snprintf(str_val, sizeof(str_val), "ps_val_%d", i);
            str_len = strlen(str_val);

            if (mysql_stmt_execute(stmt)) {
                diag("mysql_stmt_execute %d failed: %s", i, mysql_stmt_error(stmt));
                FAIL_AND_SKIP_REMAINING(cleanup, "stmt_execute failed");
            }
        }

        mysql_stmt_close(stmt);
        stmt = NULL;
    }

    verify_digest(admin, "INSERT INTO ffto_txn (id,val) VALUES (?,?)", 20, 20, 0);

    /* ================================================================
     * Scenario 4:  SAVEPOINT → DML → RELEASE SAVEPOINT
     *
     * Tests that FFTO tracks SAVEPOINT and RELEASE SAVEPOINT as
     * distinct digest entries alongside the intermediate DML.
     * ================================================================ */
    diag("--- Scenario 4: SAVEPOINT / INSERT / RELEASE ---");
    EXEC_QUERY(conn, "DELETE FROM ffto_txn");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    EXEC_QUERY(conn, "BEGIN");
    EXEC_QUERY(conn, "SAVEPOINT sp1");
    EXEC_QUERY(conn, "INSERT INTO ffto_txn (id, val) VALUES (300, 'savepoint_val')");
    EXEC_QUERY(conn, "RELEASE SAVEPOINT sp1");
    EXEC_QUERY(conn, "COMMIT");

    /* Use exact digest_text match to disambiguate SAVEPOINT from RELEASE SAVEPOINT */
    verify_digest(admin, "RELEASE SAVEPOINT sp1", 1, 0, 0);
    verify_digest(admin, "INSERT INTO ffto_txn", 1, 1, 0);
    /* For plain SAVEPOINT, query with NOT LIKE to exclude RELEASE variant */
    {
        char q[512];
        snprintf(q, sizeof(q),
            "SELECT count_star, sum_rows_affected, sum_rows_sent, digest_text "
            "FROM stats_mysql_query_digest WHERE digest_text LIKE '%%SAVEPOINT sp1%%' "
            "AND digest_text NOT LIKE '%%RELEASE%%'");
        MYSQL_RES* res = NULL;
        MYSQL_ROW row = NULL;
        for (int attempt = 0; attempt < 20; attempt++) {
            int rc = run_q(admin, q);
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
            ok(count >= 1, "Digest count for '%s': %d (>= 1)", row[3], count);
            ok(ra == 0, "rows_affected for '%s': %llu (== 0)", row[3], (unsigned long long)ra);
            ok(rs == 0, "rows_sent for '%s': %llu (== 0)", row[3], (unsigned long long)rs);
        } else {
            ok(0, "SAVEPOINT sp1 digest not found (excluding RELEASE)");
            ok(0, "Skipping rows_affected"); ok(0, "Skipping rows_sent");
        }
        if (res) mysql_free_result(res);
    }

cleanup:
    if (stmt) mysql_stmt_close(stmt);
    if (conn) mysql_close(conn);
    if (admin) mysql_close(admin);

    return exit_status();
}
