/**
 * @file test_ffto_mysql_errors-t.cpp
 * @brief FFTO E2E TAP test -- MySQL error recording in stats_mysql_errors.
 *
 * Validates that errors occurring during MySQL fast-forward sessions
 * are properly recorded in stats_mysql_errors with correct errno
 * and error message.
 *
 * @par Test scenarios
 *  1. Syntax error -> errno 1064 recorded
 *  2. Table not found -> errno 1146 recorded
 *  3. Recovery: successful query after error
 */

#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

static constexpr int kPlannedTests = 7;

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
 * @brief Check if a specific errno appears in stats_mysql_errors.
 * Polls up to 2 seconds. Returns true if found.
 */
static bool verify_mysql_error(MYSQL* admin, int expected_errno, const char* expected_msg_substr) {
    char query[1024];
    snprintf(query, sizeof(query),
        "SELECT err_no, last_error FROM stats_mysql_errors WHERE err_no = %d",
        expected_errno);

    for (int attempt = 0; attempt < 20; attempt++) {
        if (mysql_query(admin, query) != 0) { usleep(100000); continue; }
        MYSQL_RES* res = mysql_store_result(admin);
        if (!res) { usleep(100000); continue; }
        MYSQL_ROW row = mysql_fetch_row(res);
        if (row) {
            bool msg_ok = (expected_msg_substr == nullptr) ||
                          (row[1] && strstr(row[1], expected_msg_substr));
            mysql_free_result(res);
            return msg_ok;
        }
        mysql_free_result(res);
        usleep(100000);
    }
    return false;
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) { diag("Failed to get env vars."); return -1; }

    diag("=== FFTO MySQL Error Recording Test ===");
    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    MYSQL* conn = NULL;

    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
                           NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed"); return -1;
    }

    // Configure FF mode
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='true' "
                       "WHERE variable_name='mysql-ffto_enabled'");
    MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    /* Enable fast_forward on ALL mysql_users rows (frontend + backend).
     * Partial INSERT OR REPLACE only touches PK (username, backend) and leaves
     * the frontend credential row at fast_forward=0, so sessions never enter
     * FAST_FORWARD and MySQLFFTO is never constructed. */
    MYSQL_QUERY(admin, "UPDATE mysql_users SET fast_forward=1");
    MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");

    // Reset error stats
    MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_errors_reset");
    { MYSQL_RES* r = mysql_store_result(admin); if (r) mysql_free_result(r); }

    // Connect through ProxySQL in FF mode
    conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, cl.host, cl.mysql_username, cl.mysql_password,
                           "information_schema", cl.port, NULL, 0)) {
        FAIL_AND_SKIP_REMAINING(cleanup, "FF connection failed: %s", mysql_error(conn));
    }
    ok(conn != NULL, "Connected to MySQL via ProxySQL in FF mode");

    /* Scenario 1: Syntax error -> errno 1064 */
    diag("--- Scenario 1: syntax error ---");
    mysql_query(conn, "SELEC BAD SYNTAX");  // intentional error
    ok(verify_mysql_error(admin, 1064, "syntax"),
       "Error 1064 recorded in stats_mysql_errors");

    /* Scenario 2: Table not found -> errno 1146 */
    diag("--- Scenario 2: table not found ---");
    mysql_query(conn, "SELECT * FROM nonexistent_table_ffto_test");
    ok(verify_mysql_error(admin, 1146, NULL),
       "Error 1146 recorded in stats_mysql_errors");

    /* Scenario 3: Recovery -- successful query after errors */
    diag("--- Scenario 3: recovery after error ---");
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin); if (r) mysql_free_result(r);
    }
    if (mysql_query(conn, "SELECT 1") == 0) {
        MYSQL_RES* r = mysql_store_result(conn);
        if (r) mysql_free_result(r);
    }

    // Verify the successful query appears in digest stats
    {
        bool found = false;
        for (int i = 0; i < 20; i++) {
            if (mysql_query(admin, "SELECT count_star FROM stats_mysql_query_digest "
                 "WHERE digest_text LIKE '%SELECT %'") != 0) { usleep(100000); continue; }
            MYSQL_RES* res = mysql_store_result(admin);
            MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
            if (row && atoi(row[0]) > 0) found = true;
            if (res) mysql_free_result(res);
            if (found) break;
            usleep(100000);
        }
        ok(found, "Recovery: SELECT 1 recorded in digest after errors");
    }

    /* Verify error stats have count > 0 */
    {
        bool has_errors = false;
        if (mysql_query(admin, "SELECT count_star FROM stats_mysql_errors") == 0) {
            MYSQL_RES* res = mysql_store_result(admin);
            MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
            if (row && atoi(row[0]) > 0) has_errors = true;
            if (res) mysql_free_result(res);
        }
        ok(has_errors, "stats_mysql_errors has entries from FF session");
    }

    /* Verify errors have non-empty last_error message */
    {
        bool has_msg = false;
        if (mysql_query(admin, "SELECT last_error FROM stats_mysql_errors LIMIT 1") == 0) {
            MYSQL_RES* res = mysql_store_result(admin);
            MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
            if (row && row[0] && strlen(row[0]) > 0) has_msg = true;
            if (res) mysql_free_result(res);
        }
        ok(has_msg, "stats_mysql_errors entries have non-empty error messages");
    }

    /* Verify errors have valid err_no */
    {
        bool has_errno = false;
        if (mysql_query(admin, "SELECT err_no FROM stats_mysql_errors LIMIT 1") == 0) {
            MYSQL_RES* res = mysql_store_result(admin);
            MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
            if (row && atoi(row[0]) > 0) has_errno = true;
            if (res) mysql_free_result(res);
        }
        ok(has_errno, "stats_mysql_errors entries have non-zero err_no");
    }

cleanup:
    if (conn) mysql_close(conn);
    if (admin) mysql_close(admin);
    return exit_status();
}
