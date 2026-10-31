#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "ffto_mysql_helpers.h"

static constexpr int kPlannedTests = 22;

#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
    do { \
        diag(fmt, ##__VA_ARGS__); \
        int remaining = kPlannedTests - tests_last(); \
        if (remaining > 0) { \
            skip(remaining, "Skipping remaining assertions after setup failure"); \
        } \
        goto cleanup_label; \
    } while (0)

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

void verify_digest(MYSQL* admin, const char* template_text, int expected_count, uint64_t expected_rows_affected = 0, uint64_t expected_rows_sent = 0) {
    char query[1024];
    // Use a more relaxed LIKE pattern to handle potential normalization differences
    snprintf(query, sizeof(query), "SELECT count_star, sum_rows_affected, sum_rows_sent, digest_text FROM stats_mysql_query_digest WHERE digest_text LIKE '%%%s%%'", template_text);
    int rc = run_q(admin, query);
    if (rc != 0) {
        ok(0, "Failed to query stats_mysql_query_digest for %s", template_text);
        ok(0, "Skipping rows_affected check due to query failure");
        ok(0, "Skipping rows_sent check due to query failure");
        return;
    }
    MYSQL_RES* res = mysql_store_result(admin);
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row) {
        int count = atoi(row[0]);
        uint64_t rows_affected = strtoull(row[1], NULL, 10);
        uint64_t rows_sent = strtoull(row[2], NULL, 10);

        ok(count >= expected_count, "Found digest: %s (count: %d, expected: %d)", row[3], count, expected_count);
        ok(rows_affected == expected_rows_affected, "Affected rows for %s: %llu (expected: %llu)", row[3], (unsigned long long)rows_affected, (unsigned long long)expected_rows_affected);
        ok(rows_sent == expected_rows_sent, "Sent rows for %s: %llu (expected: %llu)", row[3], (unsigned long long)rows_sent, (unsigned long long)expected_rows_sent);
    } else {
        ok(0, "Digest NOT found for pattern: %s", template_text);
        ok(0, "Skipping rows_affected check (digest not found)");
        ok(0, "Skipping rows_sent check (digest not found)");
        // Dump the table to see what's actually in there
        diag("Dumping stats_mysql_query_digest for debugging:");
        run_q(admin, "SELECT digest_text, count_star FROM stats_mysql_query_digest");
        MYSQL_RES* dump_res = mysql_store_result(admin);
        MYSQL_ROW dump_row;
        while (dump_res && (dump_row = mysql_fetch_row(dump_res))) {
            diag("  Actual digest in table: %s", dump_row[0]);
        }
        if (dump_res) mysql_free_result(dump_res);
    }
    mysql_free_result(res);
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    diag("=== FFTO MySQL Test ===");
    diag("This test validates FFTO (Fast Forward To Optimization) for MySQL.");
    diag("FFTO enables fast_forward mode where queries are passed directly to");
    diag("the backend without full result set buffering in ProxySQL.");
    diag("Tests verify query digests are recorded in stats_mysql_query_digest");
    diag("with correct count_star, sum_rows_affected, and sum_rows_sent metrics");
    diag("for CREATE, INSERT, SELECT, UPDATE, and DELETE operations.");
    diag("=======================");

    plan(kPlannedTests); // 1 + 18 + 3 = 22

    MYSQL* admin = mysql_init(NULL);
    MYSQL* conn = NULL;
    MYSQL_STMT* stmt = NULL;
    char server_query[1024];
    const char* ins_query = "INSERT INTO ffto_test (id, val) VALUES (?, ?)";
    MYSQL_BIND bind[2];
    int int_data = 10;
    char str_data[20] = "binary_val";
    unsigned long str_len = strlen(str_data);
    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed");
        return -1;
    }

    if (ffto_mysql_enable_ff(admin, cl.root_username) != 0) {
        diag("FATAL: failed to enable FFTO/fast_forward");
        return -1;
    }

    // Ensure backend server exists
    snprintf(server_query, sizeof(server_query), "INSERT OR REPLACE INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0, '%s', %d)", cl.mysql_host, cl.mysql_port);
    MYSQL_QUERY(admin, server_query);
    MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

    /* DELETE on the stats mirror does NOT clear in-memory digests. */
    if (ffto_mysql_reset_digests(admin) != 0) {
        diag("FATAL: failed to reset digests");
        return -1;
    }

    // USE ROOT FOR CLIENT CONNECTION
    conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, cl.host, cl.root_username, cl.root_password, NULL, cl.port, NULL, 0)) {
        diag("Client connection failed: %s", mysql_error(conn));
        return -1;
    }
    ok(conn != NULL, "Connected to ProxySQL in Fast Forward mode");
    /* Prime backend so status becomes FAST_FORWARD, then verify. */
    if (mysql_query(conn, "DO 1") != 0) {
        diag("DO 1 failed: %s", mysql_error(conn));
    }
    if (!ffto_mysql_session_is_ff(admin, cl.root_username)) {
        diag("FATAL: session never entered fast_forward after connect");
        return -1;
    }
    if (ffto_mysql_reset_digests(admin) != 0) {
        diag("FATAL: failed to reset digests after prime");
        return -1;
    }

    // Create and use test database
    EXEC_QUERY(conn, "CREATE DATABASE IF NOT EXISTS ffto_db");
    EXEC_QUERY(conn, "USE ffto_db");

    // --- Part 1: Text Protocol CRUD ---
    EXEC_QUERY(conn, "DROP TABLE IF EXISTS ffto_test");
    EXEC_QUERY(conn, "CREATE TABLE ffto_test (id INT PRIMARY KEY, val VARCHAR(255))");
    EXEC_QUERY(conn, "INSERT INTO ffto_test VALUES (1, 'val1'), (2, 'val2')");
    EXEC_QUERY(conn, "UPDATE ffto_test SET val = 'updated' WHERE id = 1");
    EXEC_QUERY(conn, "SELECT val FROM ffto_test WHERE id = 1");
    EXEC_QUERY(conn, "DELETE FROM ffto_test WHERE id = 2");

    // Verify Text Stats
    verify_digest(admin, "DROP TABLE IF EXISTS ffto_test", 1, 0, 0);
    verify_digest(admin, "CREATE TABLE ffto_test", 1, 0, 0);
    verify_digest(admin, "INSERT INTO ffto_test VALUES", 1, 2, 0);
    verify_digest(admin, "UPDATE ffto_test SET val", 1, 1, 0);
    verify_digest(admin, "SELECT val FROM ffto_test WHERE id", 1, 0, 1);
    verify_digest(admin, "DELETE FROM ffto_test WHERE id", 1, 1, 0);

    // --- Part 2: Binary Protocol (Prepared Statements) ---
    if (ffto_mysql_reset_digests(admin) != 0) {
        FAIL_AND_SKIP_REMAINING(cleanup, "Failed to reset digests before binary protocol");
    }

    stmt = mysql_stmt_init(conn);
    if (mysql_stmt_prepare(stmt, ins_query, strlen(ins_query))) {
        ok(0, "mysql_stmt_prepare failed");
        FAIL_AND_SKIP_REMAINING(cleanup, "mysql_stmt_prepare failed: %s", mysql_stmt_error(stmt));
    }

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_LONG;
    bind[0].buffer = (char *)&int_data;
    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (char *)str_data;
    bind[1].buffer_length = 20;
    bind[1].length = &str_len;

    if (mysql_stmt_bind_param(stmt, bind)) {
        ok(0, "mysql_stmt_bind_param failed");
        FAIL_AND_SKIP_REMAINING(cleanup, "mysql_stmt_bind_param failed: %s", mysql_stmt_error(stmt));
    }
    if (mysql_stmt_execute(stmt)) {
        ok(0, "mysql_stmt_execute (1) failed");
        FAIL_AND_SKIP_REMAINING(cleanup, "mysql_stmt_execute (1) failed: %s", mysql_stmt_error(stmt));
    }
    int_data = 11; // Change ID for second insert
    if (mysql_stmt_execute(stmt)) {
        ok(0, "mysql_stmt_execute (2) failed");
        FAIL_AND_SKIP_REMAINING(cleanup, "mysql_stmt_execute (2) failed: %s", mysql_stmt_error(stmt));
    }

    // Verify Binary Stats
    verify_digest(admin, "INSERT INTO ffto_test (id,val) VALUES (?,?)", 2, 2, 0);

cleanup:
    if (stmt) mysql_stmt_close(stmt);
    if (conn) mysql_close(conn);
    if (admin) mysql_close(admin);

    return exit_status();
}
