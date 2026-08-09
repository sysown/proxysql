#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <memory>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "mysql.h"

CommandLine cl;

static constexpr int kPlannedTests = 19;

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

void verify_pg_digest(MYSQL* admin, const char* template_text, int expected_count, uint64_t expected_rows_affected = 0, uint64_t expected_rows_sent = 0) {
    char query[1024];
    snprintf(query, sizeof(query), "SELECT count_star, sum_rows_affected, sum_rows_sent, digest_text FROM stats_pgsql_query_digest WHERE digest_text LIKE '%%%s%%'", template_text);
    int rc = run_q(admin, query);
    if (rc != 0) {
        ok(0, "Failed to query stats_pgsql_query_digest for %s", template_text);
        ok(0, "Skipping PG rows_affected check due to query failure");
        ok(0, "Skipping PG rows_sent check due to query failure");
        return;
    }
    MYSQL_RES* res = mysql_store_result(admin);
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row) {
        int count = atoi(row[0]);
        uint64_t rows_affected = strtoull(row[1], NULL, 10);
        uint64_t rows_sent = strtoull(row[2], NULL, 10);

        ok(count >= expected_count, "Found PG digest: %s (count: %d, expected: %d)", row[3], count, expected_count);
        ok(rows_affected == expected_rows_affected, "Affected rows for %s: %llu (expected: %llu)", row[3], (unsigned long long)rows_affected, (unsigned long long)expected_rows_affected);
        ok(rows_sent == expected_rows_sent, "Sent rows for %s: %llu (expected: %llu)", row[3], (unsigned long long)rows_sent, (unsigned long long)expected_rows_sent);
    } else {
        ok(0, "PG Digest NOT found for pattern: %s", template_text);
        ok(0, "Skipping PG rows_affected check (digest not found)");
        ok(0, "Skipping PG rows_sent check (digest not found)");
        diag("Dumping stats_pgsql_query_digest for debugging:");
        run_q(admin, "SELECT digest_text, count_star FROM stats_pgsql_query_digest");
        MYSQL_RES* dump_res = mysql_store_result(admin);
        MYSQL_ROW dump_row;
        while (dump_res && (dump_row = mysql_fetch_row(dump_res))) {
            diag("  Actual PG digest in table: %s", dump_row[0]);
        }
        if (dump_res) mysql_free_result(dump_res);
    }
    mysql_free_result(res);
}

int main(int argc, char** argv) {
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    plan(kPlannedTests); // 1 (connect) + 18 (simple) + 3 (extended) = 19

    diag("=== FFTO PostgreSQL Test ===");
    diag("This test validates FFTO (Fast Forward To Optimization) for PostgreSQL.");
    diag("FFTO enables fast_forward mode where queries are passed directly to");
    diag("the backend without full result set buffering in ProxySQL.");
    diag("Tests cover both Simple Query Protocol (using ? placeholders) and");
    diag("Extended Query Protocol (using $1, $2 named placeholders via PQprepare).");
    diag("Verifies query digests are recorded with correct count_star,");
    diag("sum_rows_affected, and sum_rows_sent metrics in stats_pgsql_query_digest.");
    diag("============================");

    MYSQL* admin = mysql_init(NULL);
    PGconn* conn = NULL;
    char server_query[1024];
    char conninfo[1024];
    const char* ext_query = "SELECT data FROM ffto_pg_test WHERE id = $1";
    PGresult* res_prep = NULL;
    const char* paramValues[1] = {"1"};
    PGresult* res_exec = NULL;
    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed");
        return -1;
    }

    // Configure FFTO and Fast Forward for PG
    MYSQL_QUERY(admin, "SET pgsql-ffto_enabled='true'");
    MYSQL_QUERY(admin, "SET pgsql-ffto_max_buffer_size=1048576");
    MYSQL_QUERY(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

    /* Enable fast_forward on ALL pgsql_users rows (frontend + backend).
     * Partial INSERT OR REPLACE only touches PK (username, backend) and leaves
     * the frontend credential row at fast_forward=0. */
    MYSQL_QUERY(admin, "UPDATE pgsql_users SET fast_forward=1");
    MYSQL_QUERY(admin, "LOAD PGSQL USERS TO RUNTIME");
    {
        if (mysql_query(admin, "SELECT COUNT(*) FROM runtime_pgsql_users "
                               "WHERE frontend=1 AND fast_forward=1") != 0) {
            diag("FATAL: runtime_pgsql_users check failed: %s", mysql_error(admin));
            return -1;
        }
        MYSQL_RES* r = mysql_store_result(admin);
        MYSQL_ROW row = r ? mysql_fetch_row(r) : NULL;
        int cnt = row && row[0] ? atoi(row[0]) : 0;
        if (r) mysql_free_result(r);
        if (cnt < 1) {
            diag("FATAL: no frontend pgsql_users with fast_forward=1 after LOAD");
            return -1;
        }
    }

    // Ensure backend server exists
    snprintf(server_query, sizeof(server_query), "INSERT OR REPLACE INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (0, '%s', %d)", cl.pgsql_server_host, cl.pgsql_server_port);
    MYSQL_QUERY(admin, server_query);
    MYSQL_QUERY(admin, "LOAD PGSQL SERVERS TO RUNTIME");

    /* TRUNCATE on the stats mirror does not clear in-memory digests. */
    MYSQL_QUERY(admin, "SELECT * FROM stats_pgsql_query_digest_reset");
    { MYSQL_RES* r = mysql_store_result(admin); if (r) mysql_free_result(r); }

    // Standard libpq connection using root (postgres)
    snprintf(conninfo, sizeof(conninfo), "host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
            cl.pgsql_host, cl.pgsql_port, cl.pgsql_root_username, cl.pgsql_root_password);

    conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("PG Connection failed: %s", PQerrorMessage(conn));
        return -1;
    }
    ok(conn != NULL, "Connected to PostgreSQL via ProxySQL");

    // --- Part 1: Simple Query Protocol ---
    EXEC_PG_QUERY(conn, "DROP TABLE IF EXISTS ffto_pg_test");
    EXEC_PG_QUERY(conn, "CREATE TABLE ffto_pg_test (id INT PRIMARY KEY, data TEXT)");
    EXEC_PG_QUERY(conn, "INSERT INTO ffto_pg_test VALUES (1, 'val1'), (2, 'val2')");
    EXEC_PG_QUERY(conn, "SELECT data FROM ffto_pg_test WHERE id = 1");
    EXEC_PG_QUERY(conn, "UPDATE ffto_pg_test SET data = 'updated' WHERE id = 1");
    EXEC_PG_QUERY(conn, "DELETE FROM ffto_pg_test WHERE id = 2");

    // Note: DROP TABLE statements are not tracked in stats_pgsql_query_digest
    verify_pg_digest(admin, "CREATE TABLE ffto_pg_test", 1, 0, 0);
    verify_pg_digest(admin, "INSERT INTO ffto_pg_test VALUES", 1, 2, 0);
    verify_pg_digest(admin, "SELECT data FROM ffto_pg_test WHERE id = ?", 1, 0, 1);  // Simple query uses ? not $1
    verify_pg_digest(admin, "UPDATE ffto_pg_test SET data", 1, 1, 0);
    verify_pg_digest(admin, "DELETE FROM ffto_pg_test WHERE id", 1, 1, 0);

    // --- Part 2: Extended Query Protocol ---
    MYSQL_QUERY(admin, "TRUNCATE TABLE stats_pgsql_query_digest");

    res_prep = PQprepare(conn, "stmt1", ext_query, 1, NULL);
    if (!res_prep) {
        ok(0, "PQprepare failed");
        FAIL_AND_SKIP_REMAINING(cleanup, "PQprepare returned no result: %s", PQerrorMessage(conn));
    }
    if (PQresultStatus(res_prep) != PGRES_COMMAND_OK) {
        ok(0, "PQprepare failed");
        PQclear(res_prep);
        FAIL_AND_SKIP_REMAINING(cleanup, "PQprepare failed: %s", PQerrorMessage(conn));
    }
    PQclear(res_prep);

    res_exec = PQexecPrepared(conn, "stmt1", 1, paramValues, NULL, NULL, 0);
    if (!res_exec) {
        ok(0, "PQexecPrepared failed");
        FAIL_AND_SKIP_REMAINING(cleanup, "PQexecPrepared returned no result: %s", PQerrorMessage(conn));
    }
    if (PQresultStatus(res_exec) != PGRES_TUPLES_OK) {
        ok(0, "PQexecPrepared failed");
        PQclear(res_exec);
        FAIL_AND_SKIP_REMAINING(cleanup, "PQexecPrepared failed: %s", PQerrorMessage(conn));
    }
    PQclear(res_exec);

    verify_pg_digest(admin, "SELECT data FROM ffto_pg_test WHERE id = $1", 1, 0, 1);

cleanup:
    if (conn) PQfinish(conn);
    if (admin) mysql_close(admin);

    return exit_status();
}
