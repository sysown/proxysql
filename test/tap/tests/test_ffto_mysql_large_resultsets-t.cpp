/**
 * @file test_ffto_mysql_large_resultsets-t.cpp
 * @brief FFTO E2E TAP test — large result sets.
 *
 * Validates that the Fast Forward Traffic Observer (FFTO) correctly tracks
 * query digest statistics when queries produce large result sets. Exercises
 * the FFTO row-counting state machine (`READING_ROWS`) under sustained load
 * and verifies row counting under sustained load.
 *
 * @par Test scenarios
 *  1. SELECT returning 10,000 rows — verify `sum_rows_sent` accuracy
 *  2. SELECT returning rows with large TEXT payload (~1 KB each)
 *  3. Result set under reconfigured threshold — FFTO stays active
 *  4. Bulk INSERT of 500 rows — verify `sum_rows_affected` accuracy
 *
 * @pre  ProxySQL running with a MySQL backend, reachable via the standard
 *       TAP environment variables (TAP_HOST, TAP_PORT, etc.).
 *
 * @see  test_ffto_mysql-t.cpp  for the foundational FFTO test pattern
 * @see  test_ffto_bypass-t.cpp for bypass-specific test patterns
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
 * Breakdown:
 *  - Scenario 1 (10K rows):  1 (connect) + 3 (verify_digest)    = 4
 *  - Scenario 2 (TEXT data): 3 (verify_digest)                  = 3
 *  - Scenario 3 (under threshold): 3 (verify_digest)            = 3
 *  - Scenario 4 (bulk INSERT): 3 (verify_digest)                = 3
 *  Total = 13
 */
static constexpr int kPlannedTests = 13;

/**
 * @brief Skip all remaining TAP assertions and jump to the cleanup label.
 *
 * Used when a setup or intermediate step fails fatally — ensures that the
 * TAP plan is honoured even on early exit.
 *
 * @param cleanup_label  The goto label for resource cleanup.
 * @param fmt            printf-style format string for the diagnostic message.
 */
#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
    do { \
        diag(fmt, ##__VA_ARGS__); \
        int remaining = kPlannedTests - tests_last(); \
        if (remaining > 0) { \
            skip(remaining, "Skipping remaining assertions after setup failure"); \
        } \
        goto cleanup_label; \
    } while (0)

/**
 * @brief Execute a SQL query and consume its result set.
 *
 * On failure, emits a TAP failure and skips the remaining tests via
 * FAIL_AND_SKIP_REMAINING.
 *
 * @param conn  MYSQL* connection handle.
 * @param q     SQL query string.
 */
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
 * @brief Verify that a query digest exists in stats_mysql_query_digest with
 *        the expected counters.
 *
 * Uses a LIKE pattern to match digest_text, accommodating normalization
 * differences.  Emits exactly 3 TAP assertions (count_star, rows_affected,
 * rows_sent).  On lookup failure, dumps the entire digest table for
 * diagnostics.
 *
 * @param admin               Admin MYSQL* connection.
 * @param template_text       Substring to match against digest_text.
 * @param expected_count      Minimum expected count_star value.
 * @param expected_rows_affected  Expected sum_rows_affected value.
 * @param expected_rows_sent      Expected sum_rows_sent value.
 */
void verify_digest(MYSQL* admin, const char* template_text, int expected_count,
                   uint64_t expected_rows_affected = 0, uint64_t expected_rows_sent = 0) {
    char query[1024];
    snprintf(query, sizeof(query),
        "SELECT count_star, sum_rows_affected, sum_rows_sent, digest_text "
        "FROM stats_mysql_query_digest WHERE digest_text LIKE '%%%s%%'",
        template_text);

    /* Poll for up to 2 seconds — stats may appear asynchronously. */
    MYSQL_RES* res = NULL;
    MYSQL_ROW row = NULL;
    for (int attempt = 0; attempt < 20; attempt++) {
        int rc = run_q(admin, query);
        if (rc != 0) {
            usleep(100000);
            continue;
        }
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

/**
 * @brief Verify that NO digest matching the given pattern exists.
 *
 * Waits briefly (500 ms) to allow any asynchronous stats recording,
 * then asserts that the digest count is zero.
 *
 * @param admin          Admin MYSQL* connection.
 * @param template_text  Substring to match against digest_text.
 */
void verify_no_digest(MYSQL* admin, const char* template_text) {
    usleep(500000);
    char query[1024];
    snprintf(query, sizeof(query),
        "SELECT count(*) FROM stats_mysql_query_digest "
        "WHERE digest_text LIKE '%%%s%%'",
        template_text);
    run_q(admin, query);
    MYSQL_RES* res = mysql_store_result(admin);
    MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
    int count = row ? atoi(row[0]) : -1;
    ok(count == 0, "No digest recorded for '%s' (count: %d)", template_text, count);
    if (res) mysql_free_result(res);
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    diag("=== FFTO MySQL Large Result Sets Test ===");
    diag("Validates FFTO row counting and buffer threshold behavior");
    diag("with large result sets (10K+ rows, TEXT columns, boundary cases).");
    diag("==========================================");

    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    MYSQL* conn = NULL;

    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
                           NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed: %s", mysql_error(admin));
        return -1;
    }

    /* ── FFTO Configuration ─────────────────────────────────────────── */
    MYSQL_QUERY(admin, "SET mysql-ffto_enabled='true'");
    MYSQL_QUERY(admin, "SET mysql-ffto_max_buffer_size=1048576");
    MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    /* Configure user with fast_forward=1 */
    /* Enable fast_forward on ALL mysql_users rows (frontend + backend).
     * Partial INSERT OR REPLACE only touches PK (username, backend) and leaves
     * the frontend credential row at fast_forward=0, so sessions never enter
     * FAST_FORWARD and MySQLFFTO is never constructed. */
    MYSQL_QUERY(admin, "UPDATE mysql_users SET fast_forward=1");
    MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");

    /* Ensure backend server is registered */
    {
        char sq[1024];
        snprintf(sq, sizeof(sq),
            "INSERT OR REPLACE INTO mysql_servers "
            "(hostgroup_id, hostname, port) VALUES (0, '%s', %d)",
            cl.mysql_host, cl.mysql_port);
        MYSQL_QUERY(admin, sq);
        MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");
    }

    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
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

    /* ================================================================
     * Scenario 1:  SELECT returning 10,000 rows
     *              Verify sum_rows_sent = 10000
     * ================================================================ */
    diag("--- Scenario 1: 10K-row SELECT ---");
    EXEC_QUERY(conn, "DROP TABLE IF EXISTS ffto_large_rs");
    EXEC_QUERY(conn, "CREATE TABLE ffto_large_rs ("
                     "id INT PRIMARY KEY AUTO_INCREMENT, "
                     "val VARCHAR(64))");

    /* Batch-insert 10,000 rows in groups of 100 */
    for (int batch = 0; batch < 100; batch++) {
        std::string ins = "INSERT INTO ffto_large_rs (val) VALUES ";
        for (int i = 0; i < 100; i++) {
            if (i > 0) ins += ",";
            char v[64];
            snprintf(v, sizeof(v), "('row_%d')", batch * 100 + i);
            ins += v;
        }
        if (mysql_query(conn, ins.c_str())) {
            diag("Batch insert %d failed: %s", batch, mysql_error(conn));
            FAIL_AND_SKIP_REMAINING(cleanup, "Batch insert failed");
        }
        MYSQL_RES* r = mysql_store_result(conn);
        if (r) mysql_free_result(r);
    }

    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    /* Execute the large SELECT */
    if (mysql_query(conn, "SELECT id,val FROM ffto_large_rs")) {
        diag("Large SELECT failed: %s", mysql_error(conn));
        FAIL_AND_SKIP_REMAINING(cleanup, "Large SELECT failed");
    }
    {
        MYSQL_RES* rs = mysql_store_result(conn);
        if (rs) {
            diag("Fetched %llu rows from large SELECT",
                 (unsigned long long)mysql_num_rows(rs));
            mysql_free_result(rs);
        }
    }

    verify_digest(admin, "SELECT id,val FROM ffto_large_rs", 1, 0, 10000);

    /* ================================================================
     * Scenario 2:  SELECT rows with ~1 KB TEXT data
     *              Verify sum_rows_sent for TEXT-heavy rows
     * ================================================================ */
    diag("--- Scenario 2: TEXT-column result set ---");
    EXEC_QUERY(conn, "DROP TABLE IF EXISTS ffto_text_rs");
    EXEC_QUERY(conn, "CREATE TABLE ffto_text_rs ("
                     "id INT PRIMARY KEY AUTO_INCREMENT, "
                     "data TEXT)");

    /* Insert 50 rows with ~1 KB TEXT each */
    {
        std::string pad(1000, 'A');
        for (int i = 0; i < 50; i++) {
            char ins[2048];
            snprintf(ins, sizeof(ins),
                "INSERT INTO ffto_text_rs (data) VALUES ('%s')", pad.c_str());
            if (mysql_query(conn, ins)) {
                diag("TEXT insert %d failed: %s", i, mysql_error(conn));
                FAIL_AND_SKIP_REMAINING(cleanup, "TEXT insert failed");
            }
            MYSQL_RES* r = mysql_store_result(conn);
            if (r) mysql_free_result(r);
        }
    }

    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    if (mysql_query(conn, "SELECT id,data FROM ffto_text_rs")) {
        diag("TEXT SELECT failed: %s", mysql_error(conn));
        FAIL_AND_SKIP_REMAINING(cleanup, "TEXT SELECT failed");
    }
    {
        MYSQL_RES* rs = mysql_store_result(conn);
        if (rs) mysql_free_result(rs);
    }

    verify_digest(admin, "SELECT id,data FROM ffto_text_rs", 1, 0, 50);

    /* ================================================================
     * Scenario 3:  Result set just under the buffer threshold (64 KB)
     *              FFTO should stay active and record the digest
     * ================================================================ */
    diag("--- Scenario 3: result set under 64 KB threshold ---");

    /*
     * Reconfigure buffer to 65536 (64 KB).  This takes effect for new
     * sessions only — existing connections keep the old value, which is
     * desirable for test isolation.
     */
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='65536' "
                       "WHERE variable_name='mysql-ffto_max_buffer_size'");
    MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    /* Close the old connection and open a new one to pick up the 64 KB limit */
    mysql_close(conn);
    conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, cl.host, cl.root_username, cl.root_password,
                           NULL, cl.port, NULL, 0)) {
        diag("Reconnect failed: %s", mysql_error(conn));
        FAIL_AND_SKIP_REMAINING(cleanup, "Reconnect failed");
    }
    EXEC_QUERY(conn, "USE ffto_db");

    EXEC_QUERY(conn, "DROP TABLE IF EXISTS ffto_threshold_rs");
    EXEC_QUERY(conn, "CREATE TABLE ffto_threshold_rs ("
                     "id INT PRIMARY KEY AUTO_INCREMENT, "
                     "data VARCHAR(255))");

    /* Insert 20 rows × ~200 bytes ≈ 4 KB — well under 64 KB threshold */
    {
        std::string pad(200, 'B');
        for (int i = 0; i < 20; i++) {
            char ins[512];
            snprintf(ins, sizeof(ins),
                "INSERT INTO ffto_threshold_rs (data) VALUES ('%s')", pad.c_str());
            if (mysql_query(conn, ins)) {
                diag("Threshold insert %d failed: %s", i, mysql_error(conn));
                FAIL_AND_SKIP_REMAINING(cleanup, "Threshold insert failed");
            }
            MYSQL_RES* r = mysql_store_result(conn);
            if (r) mysql_free_result(r);
        }
    }

    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    if (mysql_query(conn, "SELECT id,data FROM ffto_threshold_rs")) {
        diag("Threshold SELECT failed: %s", mysql_error(conn));
        FAIL_AND_SKIP_REMAINING(cleanup, "Threshold SELECT failed");
    }
    {
        MYSQL_RES* rs = mysql_store_result(conn);
        if (rs) mysql_free_result(rs);
    }

    verify_digest(admin, "SELECT id,data FROM ffto_threshold_rs", 1, 0, 20);

    /* ================================================================
     * Scenario 4:  Bulk INSERT of 500 rows — verify sum_rows_affected
     * ================================================================ */
    diag("--- Scenario 4: bulk INSERT rows_affected ---");

    /* Restore large buffer for this scenario */
    MYSQL_QUERY(admin, "SET mysql-ffto_max_buffer_size=1048576");
    MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    /* Open a fresh connection to pick up the restored 1 MB buffer */
    mysql_close(conn);
    conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, cl.host, cl.root_username, cl.root_password,
                           NULL, cl.port, NULL, 0)) {
        diag("Reconnect for scenario 5 failed: %s", mysql_error(conn));
        FAIL_AND_SKIP_REMAINING(cleanup, "Reconnect failed");
    }
    EXEC_QUERY(conn, "USE ffto_db");

    EXEC_QUERY(conn, "DROP TABLE IF EXISTS ffto_bulk_ins");
    EXEC_QUERY(conn, "CREATE TABLE ffto_bulk_ins ("
                     "id INT PRIMARY KEY AUTO_INCREMENT, "
                     "val VARCHAR(64))");

    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    /* Single INSERT with 500 value tuples */
    {
        std::string ins = "INSERT INTO ffto_bulk_ins (val) VALUES ";
        for (int i = 0; i < 500; i++) {
            if (i > 0) ins += ",";
            char v[32];
            snprintf(v, sizeof(v), "('bulk_%d')", i);
            ins += v;
        }
        if (mysql_query(conn, ins.c_str())) {
            diag("Bulk INSERT failed: %s", mysql_error(conn));
            FAIL_AND_SKIP_REMAINING(cleanup, "Bulk INSERT failed");
        }
        MYSQL_RES* r = mysql_store_result(conn);
        if (r) mysql_free_result(r);
    }

    verify_digest(admin, "INSERT INTO ffto_bulk_ins", 1, 500, 0);

cleanup:
    if (conn) mysql_close(conn);
    if (admin) mysql_close(admin);

    return exit_status();
}
