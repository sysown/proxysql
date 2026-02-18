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

void verify_pg_digest(MYSQL* admin, const char* template_text, int expected_count) {
    char query[1024];
    sprintf(query, "SELECT count_star FROM stats_pgsql_query_digest WHERE digest_text LIKE '%%%s%%'", template_text);
    int rc = run_q(admin, query);
    if (rc != 0) {
        ok(0, "Failed to query stats_pgsql_query_digest");
        return;
    }
    MYSQL_RES* res = mysql_store_result(admin);
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row) {
        int count = atoi(row[0]);
        ok(count >= expected_count, "Found PG digest: %s (count: %d, expected: %d)", template_text, count, expected_count);
    } else {
        ok(0, "PG Digest NOT found: %s", template_text);
    }
    mysql_free_result(res);
}

int main(int argc, char** argv) {
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    // Plan:
    // 1. Connection setup
    // 2. Simple CRUD (4 queries)
    // 3. Extended Query (1 template)
    plan(6);

    MYSQL* admin = mysql_init(NULL);
    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed");
        return -1;
    }

    // Configure FFTO and Fast Forward for PG
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='true' WHERE variable_name='pgsql-ffto_enabled'");
    MYSQL_QUERY(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
    MYSQL_QUERY(admin, "UPDATE pgsql_users SET fast_forward=1");
    MYSQL_QUERY(admin, "LOAD PGSQL USERS TO RUNTIME");
    MYSQL_QUERY(admin, "DELETE FROM stats_pgsql_query_digest");

    // Standard libpq connection
    char conninfo[1024];
    sprintf(conninfo, "host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable", 
            cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password);
    
    PGconn* conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("PG Connection failed: %s", PQerrorMessage(conn));
        return -1;
    }
    ok(conn != NULL, "Connected to PostgreSQL via ProxySQL");

    // --- Part 1: Simple Query Protocol ---
    PQclear(PQexec(conn, "DROP TABLE IF EXISTS ffto_pg_test"));
    PQclear(PQexec(conn, "CREATE TABLE ffto_pg_test (id INT PRIMARY KEY, data TEXT)"));
    PQclear(PQexec(conn, "INSERT INTO ffto_pg_test VALUES (1, 'val1')"));
    PQclear(PQexec(conn, "SELECT data FROM ffto_pg_test WHERE id = 1"));

    verify_pg_digest(admin, "DROP TABLE IF EXISTS ffto_pg_test", 1);
    verify_pg_digest(admin, "CREATE TABLE ffto_pg_test", 1);
    verify_pg_digest(admin, "INSERT INTO ffto_pg_test VALUES", 1);
    verify_pg_digest(admin, "SELECT data FROM ffto_pg_test", 1);

    // --- Part 2: Extended Query Protocol ---
    const char* ext_query = "SELECT data FROM ffto_pg_test WHERE id = $1";
    PGresult* res = PQprepare(conn, "stmt1", ext_query, 1, NULL);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        diag("PQprepare failed: %s", PQerrorMessage(conn));
    }
    PQclear(res);

    const char* paramValues[1] = {"1"};
    res = PQexecPrepared(conn, "stmt1", 1, paramValues, NULL, NULL, 0);
    PQclear(res);

    verify_pg_digest(admin, "SELECT data FROM ffto_pg_test WHERE id = $1", 1);

    PQfinish(conn);
    mysql_close(admin);

    return exit_status();
}
