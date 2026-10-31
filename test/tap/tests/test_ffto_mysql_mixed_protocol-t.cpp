/**
 * @file test_ffto_mysql_mixed_protocol-t.cpp
 * @brief FFTO E2E TAP test — mixed text and binary protocol within
 *        the same session.
 *
 * Validates that the Fast Forward Traffic Observer (FFTO) correctly
 * handles alternating text protocol (COM_QUERY) and binary protocol
 * (COM_STMT_PREPARE / COM_STMT_EXECUTE / COM_STMT_CLOSE) commands
 * within a single fast-forward session.
 *
 * FFTO maintains a state machine that must cleanly transition between
 * text queries (which go directly to AWAITING_RESPONSE) and prepared
 * statement commands (which involve the m_statements map for stmt_id
 * tracking).  These tests exercise the transitions.
 *
 * @par Test scenarios
 *  1. Text SELECT followed by prepared SELECT — normalized to same digest
 *  2. Interleaved text and binary (INSERT, UPDATE, SELECT mix)
 *  3. Prepare → execute → close → re-prepare → execute same SQL
 *  4. Two prepared statements active simultaneously, interleaved
 *
 * @pre  ProxySQL running with a MySQL backend, reachable via the standard
 *       TAP environment variables.
 *
 * @see  MySQLFFTO.cpp — process_client_packet() handles COM_QUERY,
 *       COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_CLOSE
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
 *  - Setup:               1 (connect)
 *  - Scenario 1:          1 × 3 = 3 (SELECT digest, text + prepared aggregate)
 *  - Scenario 2:          3 × 3 = 9 (text INSERT, prepared INSERT, text UPDATE)
 *  - Scenario 3:          1 × 3 = 3 (re-prepared INSERT digest with count >= 2)
 *  - Scenario 4:          2 × 3 = 6 (two concurrent prepared stmts)
 *  Total = 1 + 3 + 9 + 3 + 6 = 22
 */
static constexpr int kPlannedTests = 22;

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
 * @copydetails verify_digest
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
 * @brief Execute a prepared INSERT with integer id and string value.
 *
 * Helper to reduce boilerplate for binary-protocol INSERT operations.
 *
 * @param stmt     Prepared statement handle (already prepared).
 * @param id       Integer primary key value.
 * @param val      String value for the 'val' column.
 * @return 0 on success, non-zero on failure.
 */
static int exec_prepared_insert(MYSQL_STMT* stmt, int id, const char* val) {
    MYSQL_BIND bind[2];
    unsigned long val_len = strlen(val);

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_LONG;
    bind[0].buffer = (char*)&id;
    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (char*)val;
    bind[1].buffer_length = val_len + 1;
    bind[1].length = &val_len;

    if (mysql_stmt_bind_param(stmt, bind)) return -1;
    if (mysql_stmt_execute(stmt)) return -1;
    return 0;
}

/**
 * @brief Execute a prepared SELECT with integer parameter, consume result.
 *
 * @param stmt  Prepared statement handle (already prepared for a SELECT).
 * @param id    Integer parameter value.
 * @return Number of rows fetched, or -1 on error.
 */
static int exec_prepared_select(MYSQL_STMT* stmt, int id) {
    MYSQL_BIND bind_param[1];
    memset(bind_param, 0, sizeof(bind_param));
    bind_param[0].buffer_type = MYSQL_TYPE_LONG;
    bind_param[0].buffer = (char*)&id;

    if (mysql_stmt_bind_param(stmt, bind_param)) return -1;
    if (mysql_stmt_execute(stmt)) return -1;

    /* Bind result and fetch */
    MYSQL_BIND bind_result[1];
    char result_val[256];
    unsigned long result_len = 0;
    memset(bind_result, 0, sizeof(bind_result));
    bind_result[0].buffer_type = MYSQL_TYPE_STRING;
    bind_result[0].buffer = result_val;
    bind_result[0].buffer_length = sizeof(result_val);
    bind_result[0].length = &result_len;

    if (mysql_stmt_bind_result(stmt, bind_result)) return -1;
    if (mysql_stmt_store_result(stmt)) return -1;

    int rows = 0;
    while (mysql_stmt_fetch(stmt) == 0) rows++;
    mysql_stmt_free_result(stmt);
    return rows;
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    diag("=== FFTO MySQL Mixed Protocol Test ===");
    diag("Validates FFTO state machine transitions when alternating");
    diag("between text protocol (COM_QUERY) and binary protocol");
    diag("(COM_STMT_PREPARE/EXECUTE/CLOSE) within the same session.");
    diag("======================================");

    plan(kPlannedTests);

    MYSQL* admin = mysql_init(NULL);
    MYSQL* conn = NULL;
    MYSQL_STMT* stmt1 = NULL;
    MYSQL_STMT* stmt2 = NULL;

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
    EXEC_QUERY(conn, "DROP TABLE IF EXISTS ffto_mixed");
    EXEC_QUERY(conn, "CREATE TABLE ffto_mixed ("
                     "id INT PRIMARY KEY, "
                     "val VARCHAR(255))");

    /* Seed initial data */
    EXEC_QUERY(conn, "INSERT INTO ffto_mixed VALUES (1, 'initial_1'), (2, 'initial_2')");

    /* ================================================================
     * Scenario 1:  Text SELECT followed by prepared SELECT
     *
     * Both use the same table and similar SQL, but text protocol uses
     * COM_QUERY while prepared uses COM_STMT_EXECUTE.  FFTO should
     * produce two separate digest entries because the SQL text differs
     * (literal value vs placeholder).
     * ================================================================ */
    diag("--- Scenario 1: text SELECT then prepared SELECT ---");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    /* Text protocol SELECT */
    if (mysql_query(conn, "SELECT val FROM ffto_mixed WHERE id = 1")) {
        diag("Text SELECT failed: %s", mysql_error(conn));
        FAIL_AND_SKIP_REMAINING(cleanup, "Text SELECT failed");
    }
    {
        MYSQL_RES* rs = mysql_store_result(conn);
        if (rs) mysql_free_result(rs);
    }

    /* Binary protocol SELECT */
    {
        const char* ps_sel = "SELECT val FROM ffto_mixed WHERE id = ?";
        stmt1 = mysql_stmt_init(conn);
        if (mysql_stmt_prepare(stmt1, ps_sel, strlen(ps_sel))) {
            diag("Prepare SELECT failed: %s", mysql_stmt_error(stmt1));
            FAIL_AND_SKIP_REMAINING(cleanup, "Prepare SELECT failed");
        }

        int rows = exec_prepared_select(stmt1, 2);
        diag("Prepared SELECT returned %d rows", rows);

        mysql_stmt_close(stmt1);
        stmt1 = NULL;
    }

    /*
     * Both queries normalize to the same digest text:
     * "SELECT val FROM ffto_mixed WHERE id = ?"
     * So they aggregate into one digest entry with count_star >= 2.
     */
    verify_digest(admin, "SELECT val FROM ffto_mixed WHERE id", 2, 0, 2);

    /* ================================================================
     * Scenario 2:  Interleaved text and binary protocol
     *
     * Pattern: text INSERT → prepared INSERT → text UPDATE → prepared SELECT
     * Tests that the FFTO state machine correctly resets between
     * different command types.
     * ================================================================ */
    diag("--- Scenario 2: interleaved text and binary ---");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    /* Text INSERT */
    EXEC_QUERY(conn, "INSERT INTO ffto_mixed VALUES (10, 'text_ins')");

    /* Prepared INSERT */
    {
        const char* ps_ins = "INSERT INTO ffto_mixed (id, val) VALUES (?, ?)";
        stmt1 = mysql_stmt_init(conn);
        if (mysql_stmt_prepare(stmt1, ps_ins, strlen(ps_ins))) {
            diag("Prepare INSERT failed: %s", mysql_stmt_error(stmt1));
            FAIL_AND_SKIP_REMAINING(cleanup, "Prepare INSERT failed");
        }
        if (exec_prepared_insert(stmt1, 11, "binary_ins")) {
            diag("Prepared INSERT exec failed: %s", mysql_stmt_error(stmt1));
            FAIL_AND_SKIP_REMAINING(cleanup, "Prepared INSERT exec failed");
        }
        mysql_stmt_close(stmt1);
        stmt1 = NULL;
    }

    /* Text UPDATE */
    EXEC_QUERY(conn, "UPDATE ffto_mixed SET val = 'updated' WHERE id = 10");

    /* Prepared SELECT */
    {
        const char* ps_sel = "SELECT val FROM ffto_mixed WHERE id = ?";
        stmt1 = mysql_stmt_init(conn);
        if (mysql_stmt_prepare(stmt1, ps_sel, strlen(ps_sel))) {
            diag("Prepare SELECT failed: %s", mysql_stmt_error(stmt1));
            FAIL_AND_SKIP_REMAINING(cleanup, "Prepare SELECT failed");
        }
        int rows = exec_prepared_select(stmt1, 11);
        if (rows < 0) {
            diag("Prepared SELECT after UPDATE failed: %s", mysql_stmt_error(stmt1));
        }
        mysql_stmt_close(stmt1);
        stmt1 = NULL;
    }

    /* Verify text INSERT (uses VALUES without column list) */
    verify_digest(admin, "INSERT INTO ffto_mixed VALUES", 1, 1, 0);
    /* Verify prepared INSERT (uses column list) */
    verify_digest(admin, "INSERT INTO ffto_mixed (id,val) VALUES", 1, 1, 0);
    /* Verify UPDATE tracked */
    verify_digest(admin, "UPDATE ffto_mixed SET val", 1, 1, 0);

    /* ================================================================
     * Scenario 3:  Prepare → execute → close → re-prepare → execute
     *
     * Tests the COM_STMT_CLOSE path which erases the stmt_id from
     * FFTO's m_statements map, followed by a fresh COM_STMT_PREPARE
     * that gets a new stmt_id for the same SQL.
     * ================================================================ */
    diag("--- Scenario 3: prepare/close/re-prepare cycle ---");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    /* First cycle: prepare, execute, close */
    {
        const char* ps_ins = "INSERT INTO ffto_mixed (id, val) VALUES (?, ?)";
        stmt1 = mysql_stmt_init(conn);
        if (mysql_stmt_prepare(stmt1, ps_ins, strlen(ps_ins))) {
            diag("Prepare (1st) failed: %s", mysql_stmt_error(stmt1));
            FAIL_AND_SKIP_REMAINING(cleanup, "Prepare (1st) failed");
        }
        if (exec_prepared_insert(stmt1, 20, "cycle_1")) {
            diag("Execute (1st) failed: %s", mysql_stmt_error(stmt1));
            FAIL_AND_SKIP_REMAINING(cleanup, "Execute (1st) failed");
        }
        mysql_stmt_close(stmt1);
        stmt1 = NULL;
    }

    /* Second cycle: re-prepare same SQL, execute again */
    {
        const char* ps_ins = "INSERT INTO ffto_mixed (id, val) VALUES (?, ?)";
        stmt1 = mysql_stmt_init(conn);
        if (mysql_stmt_prepare(stmt1, ps_ins, strlen(ps_ins))) {
            diag("Prepare (2nd) failed: %s", mysql_stmt_error(stmt1));
            FAIL_AND_SKIP_REMAINING(cleanup, "Prepare (2nd) failed");
        }
        if (exec_prepared_insert(stmt1, 21, "cycle_2")) {
            diag("Execute (2nd) failed: %s", mysql_stmt_error(stmt1));
            FAIL_AND_SKIP_REMAINING(cleanup, "Execute (2nd) failed");
        }
        mysql_stmt_close(stmt1);
        stmt1 = NULL;
    }

    /*
     * Both executions share the same digest because the SQL text is
     * identical. count_star should be >= 2, rows_affected should be 2.
     */
    verify_digest(admin, "INSERT INTO ffto_mixed (id,val) VALUES (?,?)", 2, 2, 0);

    /* ================================================================
     * Scenario 4:  Two prepared statements active simultaneously
     *
     * Prepares stmt1 (INSERT) and stmt2 (SELECT), then interleaves
     * their execution.  FFTO must maintain separate m_statements map
     * entries for each stmt_id and correctly attribute queries.
     * ================================================================ */
    diag("--- Scenario 4: two concurrent prepared statements ---");
    /* Use _reset table to atomically clear digest stats */
    {
        MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest_reset");
        MYSQL_RES* r = mysql_store_result(admin);
        if (r) mysql_free_result(r);
    }

    {
        const char* ps_ins = "INSERT INTO ffto_mixed (id, val) VALUES (?, ?)";
        const char* ps_sel = "SELECT val FROM ffto_mixed WHERE id = ?";

        stmt1 = mysql_stmt_init(conn);
        if (mysql_stmt_prepare(stmt1, ps_ins, strlen(ps_ins))) {
            diag("Prepare stmt1 failed: %s", mysql_stmt_error(stmt1));
            FAIL_AND_SKIP_REMAINING(cleanup, "Prepare stmt1 failed");
        }

        stmt2 = mysql_stmt_init(conn);
        if (mysql_stmt_prepare(stmt2, ps_sel, strlen(ps_sel))) {
            diag("Prepare stmt2 failed: %s", mysql_stmt_error(stmt2));
            FAIL_AND_SKIP_REMAINING(cleanup, "Prepare stmt2 failed");
        }

        /* Interleave: INSERT → SELECT → INSERT */
        if (exec_prepared_insert(stmt1, 30, "concurrent_1")) {
            diag("Concurrent INSERT 1 failed: %s", mysql_stmt_error(stmt1));
            FAIL_AND_SKIP_REMAINING(cleanup, "Concurrent INSERT 1 failed");
        }

        int rows = exec_prepared_select(stmt2, 30);
        diag("Concurrent SELECT returned %d rows", rows);

        if (exec_prepared_insert(stmt1, 31, "concurrent_2")) {
            diag("Concurrent INSERT 2 failed: %s", mysql_stmt_error(stmt1));
            FAIL_AND_SKIP_REMAINING(cleanup, "Concurrent INSERT 2 failed");
        }

        mysql_stmt_close(stmt1);
        stmt1 = NULL;
        mysql_stmt_close(stmt2);
        stmt2 = NULL;
    }

    verify_digest(admin, "INSERT INTO ffto_mixed (id,val) VALUES (?,?)", 2, 2, 0);
    verify_digest(admin, "SELECT val FROM ffto_mixed WHERE id", 1, 0, 1);

cleanup:
    if (stmt1) mysql_stmt_close(stmt1);
    if (stmt2) mysql_stmt_close(stmt2);
    if (conn) mysql_close(conn);
    if (admin) mysql_close(admin);

    return exit_status();
}
