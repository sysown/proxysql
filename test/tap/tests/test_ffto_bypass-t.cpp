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

    plan(2);

    MYSQL* admin = mysql_init(NULL);
    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed");
        return -1;
    }

    // Set a very small threshold: 100 bytes
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='true' WHERE variable_name='mysql-ffto_enabled'");
    MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='100' WHERE variable_name='mysql-ffto_max_buffer_size'");
    MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    // Ensure user exists
    char user_query[1024];
    sprintf(user_query, "INSERT OR REPLACE INTO mysql_users (username, password, default_hostgroup, fast_forward) VALUES ('%s', '%s', 0, 1)", cl.username, cl.password);
    MYSQL_QUERY(admin, user_query);
    MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");

    // Ensure backend server exists
    char server_query[1024];
    sprintf(server_query, "INSERT OR REPLACE INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0, '%s', %d)", cl.mysql_host, cl.mysql_port);
    MYSQL_QUERY(admin, server_query);
    MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

    MYSQL_QUERY(admin, "DELETE FROM stats_mysql_query_digest");

    MYSQL* conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
        diag("Client connection failed");
        return -1;
    }
    ok(conn != NULL, "Connected to ProxySQL");

    // Send a query larger than 100 bytes
    std::string large_query = "SELECT '";
    for(int i=0; i<200; i++) large_query += "x";
    large_query += "'";
    
    MYSQL_QUERY(conn, large_query.c_str());

    // Verify that NO digest was recorded for this query because it was bypassed
    int rc = run_q(admin, "SELECT count(*) FROM stats_mysql_query_digest");
    MYSQL_RES* res = mysql_store_result(admin);
    MYSQL_ROW row = mysql_fetch_row(res);
    int count = atoi(row[0]);
    ok(count == 0, "No digests recorded for queries exceeding threshold (count: %d)", count);
    
    mysql_free_result(res);
    mysql_close(conn);
    mysql_close(admin);

    return exit_status();
}
