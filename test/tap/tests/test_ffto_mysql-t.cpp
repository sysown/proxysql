#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

void verify_digest(MYSQL* admin, const char* template_text, int expected_count) {
    char query[1024];
    sprintf(query, "SELECT count_star FROM stats_mysql_query_digest WHERE digest_text LIKE '%%%s%%'", template_text);
    int rc = run_q(admin, query);
    if (rc != 0) {
        ok(0, "Failed to query stats_mysql_query_digest");
        return;
    }
    MYSQL_RES* res = mysql_store_result(admin);
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row) {
        int count = atoi(row[0]);
        ok(count >= expected_count, "Found digest: %s (count: %d, expected: %d)", template_text, count, expected_count);
    } else {
        ok(0, "Digest NOT found: %s", template_text);
    }
    mysql_free_result(res);
}

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    // We plan for:
    // 1. Connection setup
    // 2. Text CRUD (6 queries)
    // 3. Binary Prepared Stmts (2 templates)
    // 4. Cleanup
    plan(10);

    MYSQL* admin = mysql_init(NULL);
    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed");
        return -1;
    }

    // Configure FFTO and Fast Forward
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='true' WHERE variable_name='mysql-ffto_enabled'");
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='1048576' WHERE variable_name='mysql-ffto_max_buffer_size'");
    MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    MYSQL_QUERY(admin, "UPDATE mysql_users SET fast_forward=1");
    MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");
    MYSQL_QUERY(admin, "DELETE FROM stats_mysql_query_digest"); // Reset stats

    MYSQL* conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
        diag("Client connection failed");
        return -1;
    }
    ok(conn != NULL, "Connected to ProxySQL in Fast Forward mode");

    // --- Part 1: Text Protocol CRUD ---
    mysql_query(conn, "DROP TABLE IF EXISTS ffto_test");
    mysql_query(conn, "CREATE TABLE ffto_test (id INT PRIMARY KEY, val VARCHAR(255))");
    mysql_query(conn, "INSERT INTO ffto_test VALUES (1, 'val1'), (2, 'val2')");
    mysql_query(conn, "UPDATE ffto_test SET val = 'updated' WHERE id = 1");
    mysql_query(conn, "SELECT val FROM ffto_test WHERE id = 1");
    mysql_query(conn, "DELETE FROM ffto_test WHERE id = 2");

    // Verify Text Stats
    verify_digest(admin, "DROP TABLE IF EXISTS ffto_test", 1);
    verify_digest(admin, "CREATE TABLE ffto_test", 1);
    verify_digest(admin, "INSERT INTO ffto_test VALUES", 1);
    verify_digest(admin, "UPDATE ffto_test SET val", 1);
    verify_digest(admin, "SELECT val FROM ffto_test WHERE id", 1);
    verify_digest(admin, "DELETE FROM ffto_test WHERE id", 1);

    // --- Part 2: Binary Protocol (Prepared Statements) ---
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    const char* ins_query = "INSERT INTO ffto_test (id, val) VALUES (?, ?)";
    mysql_stmt_prepare(stmt, ins_query, strlen(ins_query));

    MYSQL_BIND bind[2];
    int int_data = 10;
    char str_data[20] = "binary_val";
    unsigned long str_len = strlen(str_data);

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_LONG;
    bind[0].buffer = (char *)&int_data;
    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (char *)str_data;
    bind[1].buffer_length = 20;
    bind[1].length = &str_len;

    mysql_stmt_bind_param(stmt, bind);
    mysql_stmt_execute(stmt); // Run once
    mysql_stmt_execute(stmt); // Run twice to check count_star

    // Verify Binary Stats
    verify_digest(admin, "INSERT INTO ffto_test (id, val) VALUES (?, ?)", 2);

    mysql_stmt_close(stmt);

    mysql_close(conn);
    mysql_close(admin);

    return exit_status();
}
