/**
 * @file test_ffto_mysql_large_queries-t.cpp
 * @brief FFTO E2E TAP test — large queries and rapid-fire execution.
 *
 * Validates that the Fast Forward Traffic Observer (FFTO) correctly handles
 * queries with large SQL text, both within and exceeding the configured
 * buffer threshold.  Also exercises counter accuracy under rapid-fire
 * query execution.
 *
 * @par Test scenarios
 *  1. Long INSERT (~10 KB VALUES clause) within 1 MB buffer — recorded
 *  2. Long WHERE clause (IN list with 2000 elements) — recorded
 *  3. Query exceeding 1 KB buffer on fresh connection — client-side bypass
 *  4. 100 identical SELECTs in tight loop — verify count_star accuracy
 *  5. 10 distinct queries in rapid succession — verify separate digests
 *
 * @pre  ProxySQL running with a MySQL backend, reachable via the standard
 *       TAP environment variables.
 *
 * @see  MySQLFFTO.cpp line 73: client-side bypass check (`pkt_len > ffto_max_buffer_size`)
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
 *  - Scenario 1 (long INSERT):     1 (connect) + 3 (verify_digest) = 4
 *  - Scenario 2 (long WHERE):      3 (verify_digest)               = 3
 *  - Scenario 3 (client bypass):   1 (connect) + 1 (no digest)     = 2
 *  - Scenario 4 (100× same):       3 (verify_digest)               = 3
 *  - Scenario 5 (10 distinct):     1 (verify count)                = 1
 *  Total = 13
 */
static constexpr int kPlannedTests = 13;

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
 * Polls stats_mysql_query_digest for up to 2 seconds, then emits
 * 3 TAP assertions (count_star, sum_rows_affected, sum_rows_sent).
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

/**
 * @brief Verify that NO digest matching the given pattern exists.
 *
 * Waits 500 ms for any async recording, then asserts count is zero.
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

    diag("=== FFTO MySQL Large Queries Test ===");
    diag("Validates FFTO with large SQL text, client-side bypass,");
    diag("and counter accuracy under rapid-fire execution.");
    diag("=====================================");

    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    MYSQL* conn = NULL;
    MYSQL* conn_bypass = NULL;

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
    EXEC_QUERY(conn, "DROP TABLE IF EXISTS ffto_lq");
    EXEC_QUERY(conn, "CREATE TABLE ffto_lq ("
                     "id INT PRIMARY KEY AUTO_INCREMENT, "
                     "val VARCHAR(64))");

    /* Seed some rows for WHERE-clause testing */
    for (int batch = 0; batch < 20; batch++) {
        std::string ins = "INSERT INTO ffto_lq (val) VALUES ";
        for (int i = 0; i < 100; i++) {
            if (i > 0) ins += ",";
            char v[32];
            snprintf(v, sizeof(v), "('v_%d')", batch * 100 + i);
            ins += v;
        }
        if (mysql_query(conn, ins.c_str())) {
            diag("Seed insert %d failed: %s", batch, mysql_error(conn));
            FAIL_AND_SKIP_REMAINING(cleanup, "Seed insert failed");
        }
        MYSQL_RES* r = mysql_store_result(conn);
        if (r) mysql_free_result(r);
    }

    /* ================================================================
     * Scenario 1:  Long INSERT (~10 KB VALUES clause) within 1 MB buffer
     * ================================================================ */
    diag("--- Scenario 1: long INSERT within buffer ---");

    EXEC_QUERY(conn, "DROP TABLE IF EXISTS ffto_long_ins");
    EXEC_QUERY(conn, "CREATE TABLE ffto_long_ins ("
                     "id INT PRIMARY KEY AUTO_INCREMENT, "
                     "val VARCHAR(255))");

    /* Build a single INSERT with ~10 KB of VALUES (~400 tuples × ~25 bytes) */
    {
        std::string ins = "INSERT INTO ffto_long_ins (val) VALUES ";
        for (int i = 0; i < 400; i++) {
            if (i > 0) ins += ",";
            char v[64];
            snprintf(v, sizeof(v), "('long_value_%05d')", i);
            ins += v;
        }
        diag("Long INSERT query length: %zu bytes", ins.size());

        /* Clear stats right before the query we want to measure */
        {
            MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
            MYSQL_RES* r = mysql_store_result(admin);
            if (r) mysql_free_result(r);
        }

        if (mysql_query(conn, ins.c_str())) {
            diag("Long INSERT failed: %s", mysql_error(conn));
            FAIL_AND_SKIP_REMAINING(cleanup, "Long INSERT failed");
        }
        MYSQL_RES* r = mysql_store_result(conn);
        if (r) mysql_free_result(r);
    }

    verify_digest(admin, "INSERT INTO ffto_long_ins", 1, 400, 0);

    /* ================================================================
     * Scenario 2:  Long WHERE clause with IN list (2000 elements)
     * ================================================================ */
    diag("--- Scenario 2: long WHERE IN clause ---");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    {
        std::string sel = "SELECT id, val FROM ffto_lq WHERE id IN (";
        for (int i = 1; i <= 2000; i++) {
            if (i > 1) sel += ",";
            sel += std::to_string(i);
        }
        sel += ")";
        diag("Long WHERE query length: %zu bytes", sel.size());

        if (mysql_query(conn, sel.c_str())) {
            diag("Long WHERE SELECT failed: %s", mysql_error(conn));
            FAIL_AND_SKIP_REMAINING(cleanup, "Long WHERE SELECT failed");
        }
        MYSQL_RES* rs = mysql_store_result(conn);
        uint64_t num_rows = 0;
        if (rs) {
            num_rows = mysql_num_rows(rs);
            mysql_free_result(rs);
        }
        diag("Long WHERE SELECT returned %llu rows", (unsigned long long)num_rows);
    }

    verify_digest(admin, "SELECT id,val FROM ffto_lq WHERE id IN", 1, 0, 2000);

    /* ================================================================
     * Scenario 3:  Query exceeding 1 KB buffer — client-side bypass
     * ================================================================ */
    diag("--- Scenario 3: client-side bypass with 1 KB buffer ---");

    /* Lower buffer to 1 KB */
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='1024' "
                       "WHERE variable_name='mysql-ffto_max_buffer_size'");
    MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    /* Fresh connection to pick up the 1 KB buffer limit */
    conn_bypass = mysql_init(NULL);
    if (!mysql_real_connect(conn_bypass, cl.host, cl.root_username, cl.root_password,
                           NULL, cl.port, NULL, 0)) {
        diag("Bypass connection failed: %s", mysql_error(conn_bypass));
        FAIL_AND_SKIP_REMAINING(cleanup, "Bypass connection failed");
    }
    ok(conn_bypass != NULL, "Fresh connection for client-side bypass test");
    EXEC_QUERY(conn_bypass, "USE ffto_db");

    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    /* Build a query > 1024 bytes (MySQL packet payload = 1 byte cmd + SQL text) */
    {
        std::string big_sel = "SELECT '";
        big_sel.append(1100, 'X');
        big_sel += "' AS bypass_marker";
        diag("Bypass query length: %zu bytes", big_sel.size());

        if (mysql_query(conn_bypass, big_sel.c_str())) {
            diag("Bypass SELECT failed: %s", mysql_error(conn_bypass));
            FAIL_AND_SKIP_REMAINING(cleanup, "Bypass SELECT failed");
        }
        MYSQL_RES* rs = mysql_store_result(conn_bypass);
        if (rs) mysql_free_result(rs);
    }

    verify_no_digest(admin, "bypass_marker");

    /* ================================================================
     * Scenario 4:  100 identical SELECTs in a tight loop
     * ================================================================ */
    diag("--- Scenario 4: rapid-fire 100 identical SELECTs ---");

    /* Restore large buffer */
    MYSQL_QUERY(admin, "SET mysql-ffto_max_buffer_size=1048576");
    MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    /* Reuse conn (still has the original 1 MB buffer from its session creation) */
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    for (int i = 0; i < 100; i++) {
        if (mysql_query(conn, "SELECT 1 AS rapid_fire")) {
            diag("Rapid-fire SELECT %d failed: %s", i, mysql_error(conn));
            FAIL_AND_SKIP_REMAINING(cleanup, "Rapid-fire SELECT failed");
        }
        MYSQL_RES* rs = mysql_store_result(conn);
        if (rs) mysql_free_result(rs);
    }

    verify_digest(admin, "SELECT ? AS rapid_fire", 100, 0, 100);

    /* ================================================================
     * Scenario 5:  10 queries with different literals — normalization
     * ================================================================ */
    diag("--- Scenario 5: 10 distinct queries ---");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    for (int i = 0; i < 10; i++) {
        char q[256];
        snprintf(q, sizeof(q), "SELECT val FROM ffto_lq WHERE id = %d", i + 1);
        if (mysql_query(conn, q)) {
            diag("Distinct query %d failed: %s", i, mysql_error(conn));
            FAIL_AND_SKIP_REMAINING(cleanup, "Distinct query failed");
        }
        MYSQL_RES* rs = mysql_store_result(conn);
        if (rs) mysql_free_result(rs);
    }

    /*
     * All 10 queries normalize to the same digest: "SELECT val FROM ffto_lq WHERE id = ?"
     * Verify that count_star >= 10.
     */
    {
        char check[256];
        snprintf(check, sizeof(check),
            "SELECT count_star FROM stats_mysql_query_digest "
            "WHERE digest_text LIKE '%%SELECT val FROM ffto_lq WHERE id%%'");
        int count = 0;
        for (int attempt = 0; attempt < 20; attempt++) {
            run_q(admin, check);
            MYSQL_RES* res = mysql_store_result(admin);
        if (!res) { usleep(100000); continue; }
            MYSQL_ROW row = mysql_fetch_row(res);
            count = row ? atoi(row[0]) : 0;
            mysql_free_result(res);
            if (count >= 10) break;
            usleep(100000);
        }
        ok(count >= 10,
           "10 distinct queries produced count_star=%d (expected >= 10)", count);
    }

cleanup:
    if (conn_bypass) mysql_close(conn_bypass);
    if (conn) mysql_close(conn);
    if (admin) mysql_close(admin);

    return exit_status();
}
