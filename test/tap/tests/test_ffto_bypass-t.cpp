#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    plan(15);

    diag("=== FFTO Bypass Test ===");
    diag("This test validates that queries larger than the FFTO max buffer size");
    diag("bypass the FFTO (Fast Forward To Optimization) mechanism entirely.");
    diag("========================");

    MYSQL* admin = mysql_init(NULL);
    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed");
        return -1;
    }
    ok(admin != NULL, "Connected to ProxySQL Admin");

    // Set a very small threshold: 100 bytes
    ok(mysql_query(admin, "SET mysql-ffto_enabled='true'") == 0, "Enable FFTO");
    ok(mysql_query(admin, "UPDATE global_variables SET variable_value='100' WHERE variable_name='mysql-ffto_max_buffer_size'") == 0, "Set FFTO max buffer size to 100");
    ok(mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") == 0, "Load variables to runtime");

    /* Enable fast_forward on ALL mysql_users rows (frontend + backend).
     * Partial INSERT OR REPLACE only updates the backend PK row and leaves
     * frontend credentials at fast_forward=0, so FFTO never runs. */
    ok(mysql_query(admin, "UPDATE mysql_users SET fast_forward=1, default_schema='information_schema'") == 0,
       "Enable fast_forward on all mysql_users");
    ok(mysql_query(admin, "LOAD MYSQL USERS TO RUNTIME") == 0, "Load users to runtime");

    // Ensure backend server exists
    char server_query[1024];
    snprintf(server_query, sizeof(server_query), "INSERT OR REPLACE INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0, '%s', %d)", cl.mysql_host, cl.mysql_port);
    mysql_query(admin, server_query);
    mysql_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");

    ok(mysql_query(admin, "TRUNCATE TABLE stats_mysql_query_digest") == 0, "Clear stats_mysql_query_digest using TRUNCATE");

    MYSQL* conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
        diag("Client connection failed: %s", mysql_error(conn));
        return -1;
    }
    ok(conn != NULL, "Connected to ProxySQL Data Port");

    ok(mysql_query(conn, "USE information_schema") == 0, "Execute USE information_schema");

    // 1. Send a SMALL query (should be recorded)
    const char* small_query = "SELECT 1111";
    ok(mysql_query(conn, small_query) == 0, "Send small query (should be recorded)");
    {
        MYSQL_RES* query_res = mysql_store_result(conn);
        if (query_res) mysql_free_result(query_res);
    }

    // Verify small query recorded - wait up to 2 seconds
    int count = 0;
    for (int i=0; i<20; i++) {
        mysql_query(admin, "SELECT count(*) FROM stats_mysql_query_digest WHERE digest_text = 'SELECT ?'");
        MYSQL_RES* res = mysql_store_result(admin);
        MYSQL_ROW row = mysql_fetch_row(res);
        count = row ? atoi(row[0]) : -1;
        if (res) mysql_free_result(res);
        if (count > 0) break;
        usleep(100000); // 100ms
    }
    if (count == 0) {
        diag("Small query NOT found. Dumping ALL digests in stats_mysql_query_digest:");
        mysql_query(admin, "SELECT digest_text, count_star FROM stats_mysql_query_digest");
        MYSQL_RES* dr = mysql_store_result(admin);
        MYSQL_ROW drw;
        while(dr && (drw = mysql_fetch_row(dr))) {
            diag("  Digest: %s, Count: %s", drw[0], drw[1]);
        }
        if (dr) mysql_free_result(dr);
    }
    ok(count > 0, "Small query was recorded by FFTO (count: %d)", count);

    // 2. Clear and verify it is empty
    ok(mysql_query(admin, "TRUNCATE TABLE stats_mysql_query_digest") == 0, "Clear stats_mysql_query_digest again using TRUNCATE");
    
    mysql_query(admin, "SELECT count(*) FROM stats_mysql_query_digest");
    MYSQL_RES* res = mysql_store_result(admin);
    MYSQL_ROW row = mysql_fetch_row(res);
    count = row ? atoi(row[0]) : -1;
    ok(count == 0, "Verified stats_mysql_query_digest is empty after TRUNCATE (count: %d)", count);
    if (res) mysql_free_result(res);

    // 3. Send LARGE query (should NOT be recorded)
    std::string large_query = "SELECT '";
    for(int i=0; i<200; i++) large_query += "x";
    large_query += "', 2222";

    ok(mysql_query(conn, large_query.c_str()) == 0, "Send large query (exceeding threshold, should NOT be recorded)");
    {
        MYSQL_RES* query_res = mysql_store_result(conn);
        if (query_res) mysql_free_result(query_res);
    }

    // Wait a bit to ensure it would have appeared if it was recorded
    usleep(500000); 

    // Verify that NO digest was recorded for the large query
    mysql_query(admin, "SELECT count(*), digest_text FROM stats_mysql_query_digest");
    res = mysql_store_result(admin);
    if (!res) {
        ok(0, "Failed to store result from stats query");
    } else {
        row = mysql_fetch_row(res);
        count = row ? atoi(row[0]) : -1;
        if (count != 0) {
            diag("Unexpected digests found in stats_mysql_query_digest:");
            mysql_data_seek(res, 0);
            while((row = mysql_fetch_row(res))) {
                diag("  Count: %s, Digest: %s", row[0], row[1]);
            }
        }
        ok(count == 0, "No digests recorded for queries exceeding threshold (count: %d)", count);
    }

    if (res) mysql_free_result(res);
    mysql_close(conn);
    mysql_close(admin);

    return exit_status();
}
