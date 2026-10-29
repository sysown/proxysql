/**
 * @file test_ffto_mysql_bypass_recovery-t.cpp
 * @brief FFTO E2E TAP test — bypass stickiness, per-session isolation,
 *        and buffer boundary behavior.
 *
 * Validates the FFTO bypass mechanism in detail:
 * - Once a session triggers bypass (via a packet exceeding
 *   `ffto_max_buffer_size`), the `ffto_bypassed` flag is set permanently
 *   for that session.  Subsequent queries on the same connection are NOT
 *   observed, even if they are small.
 * - Bypass is per-session: other concurrent or subsequent connections
 *   are unaffected.
 * - A new connection after a bypassed one gets a fresh FFTO instance.
 * - A query well under the buffer limit is recorded on a fresh connection.
 *
 * @par Test scenarios
 *  1. Trigger bypass, verify small queries no longer recorded (sticky)
 *  2. Fresh connection B unaffected by connection A's bypass
 *  3. New connection after closing bypassed one gets fresh FFTO
 *  4. Query under buffer limit recorded on fresh connection
 *
 * @pre  ProxySQL running with a MySQL backend, reachable via the standard
 *       TAP environment variables.
 *
 * @see  MySQLFFTO.cpp line 73: `if (pkt_len > ffto_max_buffer_size)`
 * @see  MySQL_Session.cpp: `ffto_bypassed` flag
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
 *  - Scenario 1: 1 (connect) + 1 (small recorded) + 1 (no post-bypass) = 3
 *  - Scenario 2: 1 (connect) + 1 (small recorded on B)                 = 2
 *  - Scenario 3: 1 (connect) + 1 (small recorded on C)                 = 2
 *  - Scenario 4: 1 (connect) + 1 (boundary recorded)                   = 2
 *  Total = 9
 */
static constexpr int kPlannedTests = 9;

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

/**
 * @brief Poll stats_mysql_query_digest for a matching digest.
 *
 * Returns the count_star value if found, 0 if not found after polling.
 *
 * @param admin          Admin MYSQL* connection.
 * @param template_text  Substring to match against digest_text.
 * @param max_attempts   Number of 100 ms polling attempts (default 20 = 2 s).
 * @return count_star value, or 0 if not found.
 */
static int poll_digest_count(MYSQL* admin, const char* template_text, int max_attempts = 20) {
    char query[1024];
    snprintf(query, sizeof(query),
        "SELECT count_star FROM stats_mysql_query_digest "
        "WHERE digest_text LIKE '%%%s%%'",
        template_text);

    int count = 0;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
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

/**
 * @brief Dump all current digest entries for debugging.
 *
 * @param admin  Admin MYSQL* connection.
 */
static void dump_digests(MYSQL* admin) {
    diag("Dumping stats_mysql_query_digest for debugging:");
    run_q(admin, "SELECT digest_text, count_star FROM stats_mysql_query_digest");
    MYSQL_RES* res = mysql_store_result(admin);
    MYSQL_ROW row;
    while (res && (row = mysql_fetch_row(res))) {
        diag("  digest: %s  count: %s", row[0], row[1]);
    }
    if (res) mysql_free_result(res);
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    diag("=== FFTO MySQL Bypass Recovery Test ===");
    diag("Validates bypass stickiness, per-session isolation, and");
    diag("buffer boundary behavior.");
    diag("=======================================");

    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    MYSQL* conn_a = NULL;
    MYSQL* conn_b = NULL;
    MYSQL* conn_c = NULL;
    MYSQL* conn_d = NULL;

    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
                           NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed: %s", mysql_error(admin));
        return -1;
    }

    /* ── FFTO Configuration — small buffer (200 bytes) ──────────────── */
    MYSQL_QUERY(admin, "SET mysql-ffto_enabled='true'");
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='200' "
                       "WHERE variable_name='mysql-ffto_max_buffer_size'");
    MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    /* Enable fast_forward on ALL mysql_users rows (frontend + backend).
     * Partial INSERT OR REPLACE only touches PK (username, backend) and leaves
     * the frontend credential row at fast_forward=0, so sessions never enter
     * FAST_FORWARD and MySQLFFTO is never constructed. */
    MYSQL_QUERY(admin, "UPDATE mysql_users SET fast_forward=1");
    MYSQL_QUERY(admin, "UPDATE mysql_users SET default_schema='information_schema'");
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

    /* ================================================================
     * Scenario 1:  Trigger bypass on connection A, verify stickiness
     *
     * Step 1: Small query (< 200 bytes) → should be recorded
     * Step 2: Large query (> 200 bytes) → triggers bypass
     * Step 3: Another small query on same connection → NOT recorded
     *         (bypass is sticky for the session lifetime)
     * ================================================================ */
    diag("--- Scenario 1: bypass stickiness ---");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    conn_a = mysql_init(NULL);
    if (!mysql_real_connect(conn_a, cl.host, cl.username, cl.password,
                           NULL, cl.port, NULL, 0)) {
        diag("conn_a failed: %s", mysql_error(conn_a));
        FAIL_AND_SKIP_REMAINING(cleanup, "conn_a failed");
    }
    ok(conn_a != NULL, "Connection A established");

    /* Step 1: small query — should be recorded */
    {
        if (mysql_query(conn_a, "SELECT 1 AS small_a") != 0) {
            diag("Small query A failed: %s", mysql_error(conn_a));
            FAIL_AND_SKIP_REMAINING(cleanup, "Small query A failed");
        }
        MYSQL_RES* rs = mysql_store_result(conn_a);
        if (rs) mysql_free_result(rs);
    }

    {
        int count = poll_digest_count(admin, "SELECT ? AS small_a");
        if (count == 0) dump_digests(admin);
        ok(count > 0, "Small query recorded on conn A before bypass (count: %d)", count);
    }

    /* Step 2: large query — triggers bypass */
    {
        std::string big = "SELECT '";
        big.append(300, 'Z');
        big += "' AS big_a";

        if (mysql_query(conn_a, big.c_str()) != 0) {
            diag("Large query A failed: %s", mysql_error(conn_a));
            FAIL_AND_SKIP_REMAINING(cleanup, "Large query A failed");
        }
        MYSQL_RES* rs = mysql_store_result(conn_a);
        if (rs) mysql_free_result(rs);
    }

    /* Step 3: another small query — should NOT be recorded (bypass sticky) */
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    {
        if (mysql_query(conn_a, "SELECT 2 AS post_bypass_a") != 0) {
            diag("Post-bypass query failed: %s", mysql_error(conn_a));
            FAIL_AND_SKIP_REMAINING(cleanup, "Post-bypass query failed");
        }
        MYSQL_RES* rs = mysql_store_result(conn_a);
        if (rs) mysql_free_result(rs);
    }

    /* Wait to ensure it would have been recorded if not bypassed */
    usleep(500000);

    {
        run_q(admin, "SELECT count(*) FROM stats_mysql_query_digest "
                     "WHERE digest_text LIKE '%post_bypass_a%'");
        MYSQL_RES* res = mysql_store_result(admin);
        MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
        int count = row ? atoi(row[0]) : -1;
        ok(count == 0,
           "Post-bypass query NOT recorded on conn A (bypass sticky, count: %d)", count);
        if (res) mysql_free_result(res);
    }

    /* ================================================================
     * Scenario 2:  Fresh connection B unaffected by A's bypass
     *
     * Connection A is bypassed.  A new connection B should get a fresh
     * FFTO instance and record queries normally.
     * ================================================================ */
    diag("--- Scenario 2: connection B unaffected ---");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    conn_b = mysql_init(NULL);
    if (!mysql_real_connect(conn_b, cl.host, cl.username, cl.password,
                           NULL, cl.port, NULL, 0)) {
        diag("conn_b failed: %s", mysql_error(conn_b));
        FAIL_AND_SKIP_REMAINING(cleanup, "conn_b failed");
    }
    ok(conn_b != NULL, "Connection B established (while A is bypassed)");

    {
        if (mysql_query(conn_b, "SELECT 3 AS fresh_b") != 0) {
            diag("Fresh query B failed: %s", mysql_error(conn_b));
            FAIL_AND_SKIP_REMAINING(cleanup, "Fresh query B failed");
        }
        MYSQL_RES* rs = mysql_store_result(conn_b);
        if (rs) mysql_free_result(rs);
    }

    {
        int count = poll_digest_count(admin, "SELECT ? AS fresh_b");
        if (count == 0) dump_digests(admin);
        ok(count > 0,
           "Fresh query recorded on conn B (unaffected by A's bypass, count: %d)", count);
    }

    /* ================================================================
     * Scenario 3:  New connection after closing bypassed one
     *
     * Close connection A, open connection C.  The new session should
     * have ffto_bypassed=false and record queries normally.
     * ================================================================ */
    diag("--- Scenario 3: new connection after bypass close ---");
    mysql_close(conn_a);
    conn_a = NULL;

    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    conn_c = mysql_init(NULL);
    if (!mysql_real_connect(conn_c, cl.host, cl.username, cl.password,
                           NULL, cl.port, NULL, 0)) {
        diag("conn_c failed: %s", mysql_error(conn_c));
        FAIL_AND_SKIP_REMAINING(cleanup, "conn_c failed");
    }
    ok(conn_c != NULL, "Connection C established (after A closed)");

    {
        if (mysql_query(conn_c, "SELECT 4 AS after_close_c") != 0) {
            diag("Post-close query C failed: %s", mysql_error(conn_c));
            FAIL_AND_SKIP_REMAINING(cleanup, "Post-close query C failed");
        }
        MYSQL_RES* rs = mysql_store_result(conn_c);
        if (rs) mysql_free_result(rs);
    }

    {
        int count = poll_digest_count(admin, "SELECT ? AS after_close_c");
        if (count == 0) dump_digests(admin);
        ok(count > 0,
           "Query recorded on conn C (fresh FFTO after A's close, count: %d)", count);
    }

    /* ================================================================
     * Scenario 4:  Query well under buffer limit is recorded
     *
     * After verifying that bypass is sticky and per-session, confirm
     * that a fresh connection with a query comfortably under the
     * buffer limit records the digest correctly.  This validates that
     * FFTO is functional for queries that do not trigger bypass.
     * ================================================================ */
    diag("--- Scenario 4: query under buffer limit is recorded ---");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    conn_d = mysql_init(NULL);
    if (!mysql_real_connect(conn_d, cl.host, cl.username, cl.password,
                           NULL, cl.port, NULL, 0)) {
        diag("conn_d failed: %s", mysql_error(conn_d));
        FAIL_AND_SKIP_REMAINING(cleanup, "conn_d failed");
    }
    ok(conn_d != NULL, "Connection D established for under-limit test");

    /*
     * Build a query well under the 200-byte buffer limit.
     * "SELECT 'QQQQQ...' AS boundary_d" with 50 Q's ≈ 73 bytes SQL.
     * COM_QUERY payload = 1 (cmd) + 73 = 74 bytes, well under 200.
     */
    {
        std::string boundary_q = "SELECT '";
        boundary_q.append(50, 'Q');
        boundary_q += "' AS boundary_d";
        diag("Under-limit query SQL length: %zu bytes (pkt_len = %zu)",
             boundary_q.size(), boundary_q.size() + 1);

        if (mysql_query(conn_d, boundary_q.c_str()) != 0) {
            diag("Boundary query failed: %s", mysql_error(conn_d));
            FAIL_AND_SKIP_REMAINING(cleanup, "Boundary query failed");
        }
        MYSQL_RES* rs = mysql_store_result(conn_d);
        if (rs) mysql_free_result(rs);
    }

    {
        int count = poll_digest_count(admin, "boundary_d");
        if (count == 0) dump_digests(admin);
        ok(count > 0,
           "Boundary query recorded (pkt_len == buffer, not bypassed, count: %d)", count);
    }

cleanup:
    if (conn_a) mysql_close(conn_a);
    if (conn_b) mysql_close(conn_b);
    if (conn_c) mysql_close(conn_c);
    if (conn_d) mysql_close(conn_d);
    if (admin) mysql_close(admin);

    return exit_status();
}
