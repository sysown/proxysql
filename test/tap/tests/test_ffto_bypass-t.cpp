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
    MYSQL_QUERY(admin, "UPDATE mysql_users SET fast_forward=1");
    MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");
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
    
    mysql_query(conn, large_query.c_str());

    // Verify that NO digest was recorded for this query because it was bypassed
    int rc = run_q(admin, "SELECT count(*) FROM stats_mysql_query_digest WHERE digest_text LIKE '%xxxx%'");
    MYSQL_RES* res = mysql_store_result(admin);
    MYSQL_ROW row = mysql_fetch_row(res);
    int count = atoi(row[0]);
    ok(count == 0, "Query larger than threshold was correctly bypassed (count: %d)", count);
    
    mysql_free_result(res);
    mysql_close(conn);
    mysql_close(admin);

    return exit_status();
}
