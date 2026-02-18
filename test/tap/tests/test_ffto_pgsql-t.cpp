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

#define EXEC_PG_QUERY(conn, q) \
    { \
        PGresult* res_exec = PQexec(conn, q); \
        if (PQresultStatus(res_exec) != PGRES_COMMAND_OK && PQresultStatus(res_exec) != PGRES_TUPLES_OK) { \
            diag("PG Query failed: %s", PQerrorMessage(conn)); \
            ok(0, "PG Query failed: %s", q); \
            PQclear(res_exec); \
            return -1; \
        } \
        PQclear(res_exec); \
    }

void verify_pg_digest(MYSQL* admin, const char* template_text, int expected_count, uint64_t expected_rows_affected = 0, uint64_t expected_rows_sent = 0) {
    char query[1024];
    sprintf(query, "SELECT count_star, sum_rows_affected, sum_rows_sent, digest_text FROM stats_pgsql_query_digest WHERE digest_text LIKE '%%%s%%'", template_text);
    int rc = run_q(admin, query);
    if (rc != 0) {
        ok(0, "Failed to query stats_pgsql_query_digest for %s", template_text);
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

    plan(1 + (6*3) + (1*3)); // 1 (connect) + 18 (simple) + 3 (extended) = 22

    MYSQL* admin = mysql_init(NULL);
    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed");
        return -1;
    }

    // Configure FFTO and Fast Forward for PG
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='true' WHERE variable_name='pgsql-ffto_enabled'");
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='1048576' WHERE variable_name='pgsql-ffto_max_buffer_size'");
    MYSQL_QUERY(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

    // Ensure root user exists
    MYSQL_QUERY(admin, "INSERT OR REPLACE INTO pgsql_users (username, password, fast_forward) VALUES ('postgres', 'postgres', 1)");
    MYSQL_QUERY(admin, "LOAD PGSQL USERS TO RUNTIME");

    // Ensure backend server exists
    char server_query[1024];
    sprintf(server_query, "INSERT OR REPLACE INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (0, '%s', %d)", cl.pgsql_server_host, cl.pgsql_server_port);
    MYSQL_QUERY(admin, server_query);
    MYSQL_QUERY(admin, "LOAD PGSQL SERVERS TO RUNTIME");

    MYSQL_QUERY(admin, "DELETE FROM stats_pgsql_query_digest");

    // Standard libpq connection using root (postgres)
    char conninfo[1024];
    sprintf(conninfo, "host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable", 
            cl.pgsql_host, cl.pgsql_port, cl.pgsql_root_username, cl.pgsql_root_password);
    
    PGconn* conn = PQconnectdb(conninfo);
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

    verify_pg_digest(admin, "DROP TABLE IF EXISTS ffto_pg_test", 1, 0, 0); 
    verify_pg_digest(admin, "CREATE TABLE ffto_pg_test", 1, 0, 0);       
    verify_pg_digest(admin, "INSERT INTO ffto_pg_test VALUES", 1, 2, 0);
    verify_pg_digest(admin, "SELECT data FROM ffto_pg_test WHERE id = $1", 1, 0, 1); 
    verify_pg_digest(admin, "UPDATE ffto_pg_test SET data", 1, 1, 0);
    verify_pg_digest(admin, "DELETE FROM ffto_pg_test WHERE id", 1, 1, 0);

    // --- Part 2: Extended Query Protocol ---
    MYSQL_QUERY(admin, "DELETE FROM stats_pgsql_query_digest"); 

    const char* ext_query = "SELECT data FROM ffto_pg_test WHERE id = $1";
    PGresult* res_prep = PQprepare(conn, "stmt1", ext_query, 1, NULL);
    if (PQresultStatus(res_prep) != PGRES_COMMAND_OK) {
        diag("PQprepare failed: %s", PQerrorMessage(conn));
        return -1;
    }
    PQclear(res_prep);

    const char* paramValues[1] = {"1"};
    PGresult* res_exec = PQexecPrepared(conn, "stmt1", 1, paramValues, NULL, NULL, 0);
    if (PQresultStatus(res_exec) != PGRES_TUPLES_OK) {
        diag("PQexecPrepared failed: %s", PQerrorMessage(conn));
        return -1;
    }
    PQclear(res_exec);

    verify_pg_digest(admin, "SELECT data FROM ffto_pg_test WHERE id = $1", 1, 0, 1);

    PQfinish(conn);
    mysql_close(admin);

    return exit_status();
}
