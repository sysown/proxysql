/**
 * @file test_ffto_pgsql_error_stats-t.cpp
 * @brief FFTO E2E TAP test -- PostgreSQL error recording in stats_pgsql_errors.
 *
 * Validates that errors occurring during PostgreSQL fast-forward sessions
 * are properly recorded in stats_pgsql_errors with correct SQLSTATE
 * and error message.
 *
 * @par Test scenarios
 *  1. Syntax error -> sqlstate 42601 recorded
 *  2. Undefined table -> sqlstate 42P01 recorded
 *  3. Error entries have non-empty messages and sqlstate
 */

#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "libpq-fe.h"
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

static constexpr int kPlannedTests = 5;

#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
    do { \
        diag(fmt, ##__VA_ARGS__); \
        int remaining = kPlannedTests - tests_last(); \
        if (remaining > 0) { \
            skip(remaining, "Skipping remaining assertions after setup failure"); \
        } \
        goto cleanup_label; \
    } while (0)

static bool verify_pgsql_error(MYSQL* admin, const char* expected_sqlstate) {
    char query[1024];
    snprintf(query, sizeof(query),
        "SELECT sqlstate, last_error FROM stats_pgsql_errors WHERE sqlstate = '%s'",
        expected_sqlstate);

    for (int attempt = 0; attempt < 20; attempt++) {
        if (mysql_query(admin, query) != 0) { usleep(100000); continue; }
        MYSQL_RES* res = mysql_store_result(admin);
        if (!res) { usleep(100000); continue; }
        MYSQL_ROW row = mysql_fetch_row(res);
        if (row) {
            mysql_free_result(res);
            return true;
        }
        mysql_free_result(res);
        usleep(100000);
    }
    return false;
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) { diag("Failed to get env vars."); return -1; }

    diag("=== FFTO PostgreSQL Error Stats Test ===");
    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    PGconn* conn = NULL;

    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
                           NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed"); return -1;
    }

    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='true' "
                       "WHERE variable_name='pgsql-ffto_enabled'");
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

    // Reset error stats
    MYSQL_QUERY(admin, "SELECT * FROM stats_pgsql_errors_reset");
    { MYSQL_RES* r = mysql_store_result(admin); if (r) mysql_free_result(r); }

    {
        char ci[1024];
        snprintf(ci, sizeof(ci), "host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
                 cl.pgsql_host, cl.pgsql_port, cl.pgsql_root_username, cl.pgsql_root_password);
        conn = PQconnectdb(ci);
    }
    if (PQstatus(conn) != CONNECTION_OK) {
        FAIL_AND_SKIP_REMAINING(cleanup, "PG connection failed: %s", PQerrorMessage(conn));
    }
    ok(conn != NULL, "Connected to PostgreSQL via ProxySQL in FF mode");

    /* Scenario 1: Syntax error -> SQLSTATE 42601 */
    diag("--- Scenario 1: syntax error ---");
    { PGresult* r = PQexec(conn, "SELEC BAD"); if (r) PQclear(r); }
    ok(verify_pgsql_error(admin, "42601"),
       "SQLSTATE 42601 recorded in stats_pgsql_errors");

    /* Scenario 2: Undefined table -> SQLSTATE 42P01 */
    diag("--- Scenario 2: undefined table ---");
    { PGresult* r = PQexec(conn, "SELECT * FROM nonexistent_table_ffto_test"); if (r) PQclear(r); }
    ok(verify_pgsql_error(admin, "42P01"),
       "SQLSTATE 42P01 recorded in stats_pgsql_errors");

    /* Verify entries have non-empty messages */
    {
        bool has_msg = false;
        if (mysql_query(admin, "SELECT last_error FROM stats_pgsql_errors LIMIT 1") == 0) {
            MYSQL_RES* res = mysql_store_result(admin);
            MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
            if (row && row[0] && strlen(row[0]) > 0) has_msg = true;
            if (res) mysql_free_result(res);
        }
        ok(has_msg, "stats_pgsql_errors entries have non-empty error messages");
    }

    /* Verify entries have non-empty sqlstate */
    {
        bool has_sqlstate = false;
        if (mysql_query(admin, "SELECT sqlstate FROM stats_pgsql_errors LIMIT 1") == 0) {
            MYSQL_RES* res = mysql_store_result(admin);
            MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
            if (row && row[0] && strlen(row[0]) > 0) has_sqlstate = true;
            if (res) mysql_free_result(res);
        }
        ok(has_sqlstate, "stats_pgsql_errors entries have non-empty sqlstate");
    }

cleanup:
    if (conn) PQfinish(conn);
    if (admin) mysql_close(admin);
    return exit_status();
}
