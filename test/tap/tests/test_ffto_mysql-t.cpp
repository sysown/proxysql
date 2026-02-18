#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

#define EXEC_QUERY(conn, q) \
    if (mysql_query(conn, q)) { \
        diag("Query failed: %s", mysql_error(conn)); \
        ok(0, "Query failed: %s", q); \
        return -1; \
    } else { \
        MYSQL_RES* dummy_res = mysql_store_result(conn); \
        if (dummy_res) mysql_free_result(dummy_res); \
        else if (mysql_field_count(conn) > 0) { \
            diag("Error storing result: %s", mysql_error(conn)); \
            return -1; \
        } \
    }

void verify_digest(MYSQL* admin, const char* template_text, int expected_count, uint64_t expected_rows_affected = 0, uint64_t expected_rows_sent = 0) {
    char query[1024];
    // Use a more relaxed LIKE pattern to handle potential normalization differences
    sprintf(query, "SELECT count_star, sum_rows_affected, sum_rows_sent, digest_text FROM stats_mysql_query_digest WHERE digest_text LIKE '%%%s%%'", template_text);
    int rc = run_q(admin, query);
    if (rc != 0) {
        ok(0, "Failed to query stats_mysql_query_digest for %s", template_text);
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

    plan(1 + (6*3) + (1*3)); // 1 + 18 + 3 = 22

    MYSQL* admin = mysql_init(NULL);
    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed");
        return -1;
    }

    // Configure FFTO and Fast Forward
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='true' WHERE variable_name='mysql-ffto_enabled'");
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='1048576' WHERE variable_name='mysql-ffto_max_buffer_size'");
    MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    // Ensure root user has fast_forward enabled
    MYSQL_QUERY(admin, "INSERT OR REPLACE INTO mysql_users (username, password, default_hostgroup, fast_forward) VALUES ('root', 'root', 0, 1)");
    MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");

    // Ensure backend server exists
    char server_query[1024];
    sprintf(server_query, "INSERT OR REPLACE INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0, '%s', %d)", cl.mysql_host, cl.mysql_port);
    MYSQL_QUERY(admin, server_query);
    MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

    MYSQL_QUERY(admin, "DELETE FROM stats_mysql_query_digest"); // Reset stats

    // USE ROOT FOR CLIENT CONNECTION
    MYSQL* conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, cl.host, "root", "root", NULL, cl.port, NULL, 0)) {
        diag("Client connection failed: %s", mysql_error(conn));
        return -1;
    }
    ok(conn != NULL, "Connected to ProxySQL in Fast Forward mode");

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
    MYSQL_QUERY(admin, "DELETE FROM stats_mysql_query_digest"); 
    
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    const char* ins_query = "INSERT INTO ffto_test (id, val) VALUES (?, ?)";
    if (mysql_stmt_prepare(stmt, ins_query, strlen(ins_query))) {
        diag("mysql_stmt_prepare failed: %s", mysql_stmt_error(stmt));
        ok(0, "mysql_stmt_prepare failed");
        return -1;
    }

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

    if (mysql_stmt_bind_param(stmt, bind)) {
        diag("mysql_stmt_bind_param failed: %s", mysql_stmt_error(stmt));
        return -1;
    }
    if (mysql_stmt_execute(stmt)) {
        diag("mysql_stmt_execute (1) failed: %s", mysql_stmt_error(stmt));
        return -1;
    }
    int_data = 11; // Change ID for second insert
    if (mysql_stmt_execute(stmt)) {
        diag("mysql_stmt_execute (2) failed: %s", mysql_stmt_error(stmt));
        return -1;
    }

    // Verify Binary Stats
    verify_digest(admin, "INSERT INTO ffto_test (id,val) VALUES (?,?)", 2, 2, 0); 

    mysql_stmt_close(stmt);

    mysql_close(conn);
    mysql_close(admin);

    return exit_status();
}
