/**
 * @file test_ffto_pgsql_stmt_portal-t.cpp
 * @brief FFTO E2E TAP test — PostgreSQL statement and portal management.
 *
 * Validates that PgSQLFFTO correctly tracks named/unnamed statements
 * and portals via its m_statements and m_portals maps. Tests the
 * Parse → Bind → Execute → Close lifecycle and verifies correct
 * query attribution through statement name lookups.
 *
 * Uses pg_lite_client for raw protocol access to control statement
 * names, portal names, and Close messages directly.
 *
 * @par Test scenarios
 *  1. Named statement executed 20 times — verify count_star=20
 *  2. Close statement then re-prepare same name — verify tracking
 *  3. Unnamed statement (empty string) — verify default tracking
 *
 * @pre  ProxySQL running with a PostgreSQL backend.
 *
 * @see  PgSQLFFTO.cpp — m_statements, m_portals maps
 */

#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <cstdint>
/* pg_lite_client.h must come before mysql.h to avoid PROTOCOL_VERSION macro conflict */
#include "pg_lite_client.h"
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

/**
 * @brief Total number of planned TAP assertions.
 *
 * Breakdown:
 *  - Setup:                  1 (connect)
 *  - Scenario 1 (20x exec): 3 (verify_pg_digest)
 *  - Scenario 2 (re-prepare): 3 (verify_pg_digest)
 *  - Scenario 3 (unnamed):  3 (verify_pg_digest)
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

    diag("=== FFTO PostgreSQL Statement/Portal Management Test ===");
    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    PgConnection* pgc = NULL;

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

    try {
        pgc = new PgConnection(5000);
        pgc->connect(cl.pgsql_host, cl.pgsql_port, "postgres",
                     cl.pgsql_root_username, cl.pgsql_root_password);
    } catch (const PgException& e) {
        diag("PgConnection failed: %s", e.what());
        FAIL_AND_SKIP_REMAINING(cleanup, "PgConnection failed");
    }
    ok(pgc != NULL && pgc->isConnected(), "Connected via pg_lite_client");

    pgc->execute("DROP TABLE IF EXISTS ffto_pg_stmt");
    pgc->execute("CREATE TABLE ffto_pg_stmt (id INT PRIMARY KEY, val TEXT)");
    pgc->execute("INSERT INTO ffto_pg_stmt VALUES (1,'a'), (2,'b'), (3,'c')");

    /* ================================================================
     * Scenario 1:  Named statement executed 20 times
     *
     * FFTO maps statement name "my_sel" → SQL text. Each Execute
     * looks up the SQL via the portal → statement chain and records
     * the digest. All 20 executions share one digest entry.
     * ================================================================ */
    diag("--- Scenario 1: named statement x20 ---");
    clear_pg_stats(admin);

    try {
        pgc->prepareStatement("my_sel",
            "SELECT val FROM ffto_pg_stmt WHERE id = $1", true);

        for (int i = 0; i < 20; i++) {
            char id_str[8];
            snprintf(id_str, sizeof(id_str), "%d", (i % 3) + 1);
            pgc->bindStatement("my_sel", "",
                {{std::string(id_str), 0}}, {}, true);
            pgc->executePortal("", 0, true);
        }
    } catch (const PgException& e) {
        diag("Scenario 1 failed: %s", e.what());
        FAIL_AND_SKIP_REMAINING(cleanup, "Named statement test failed");
    }

    verify_pg_digest(admin, "SELECT val FROM ffto_pg_stmt WHERE id = $1", 20, 0, 20);

    /* ================================================================
     * Scenario 2:  Close statement then re-prepare same name
     *
     * Close "my_sel", then re-prepare it with different SQL.
     * FFTO should erase the old entry from m_statements on Close
     * and store the new SQL on the fresh Parse.
     * ================================================================ */
    diag("--- Scenario 2: close and re-prepare ---");
    clear_pg_stats(admin);

    try {
        /* Close the old statement */
        pgc->closeStatement("my_sel", true);

        /* Re-prepare with different SQL */
        pgc->prepareStatement("my_sel",
            "SELECT id,val FROM ffto_pg_stmt WHERE id = $1", true);

        pgc->bindStatement("my_sel", "",
            {{std::string("1"), 0}}, {}, true);
        pgc->executePortal("", 0, true);
    } catch (const PgException& e) {
        diag("Scenario 2 failed: %s", e.what());
        FAIL_AND_SKIP_REMAINING(cleanup, "Re-prepare test failed");
    }

    verify_pg_digest(admin, "SELECT id,val FROM ffto_pg_stmt WHERE id = $1", 1, 0, 1);

    /* ================================================================
     * Scenario 3:  Unnamed statement (empty string name)
     *
     * The PostgreSQL protocol allows an empty string as statement name
     * (the "unnamed" statement). FFTO should still track it correctly.
     * ================================================================ */
    diag("--- Scenario 3: unnamed statement ---");
    clear_pg_stats(admin);

    try {
        /* Unnamed statement (empty string name) */
        pgc->prepareStatement("",
            "INSERT INTO ffto_pg_stmt VALUES ($1, $2)", true);

        pgc->bindStatement("", "",
            {{std::string("10"), 0}, {std::string("unnamed_val"), 0}}, {}, true);
        pgc->executePortal("", 0, true);
    } catch (const PgException& e) {
        diag("Scenario 3 failed: %s", e.what());
        FAIL_AND_SKIP_REMAINING(cleanup, "Unnamed statement test failed");
    }

    verify_pg_digest(admin, "INSERT INTO ffto_pg_stmt VALUES ($1,$2)", 1, 1, 0);

cleanup:
    if (pgc) delete pgc;
    if (admin) mysql_close(admin);
    return exit_status();
}
