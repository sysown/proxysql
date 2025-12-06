#include <algorithm>
/*
 * Fast Forward Switch Replication Deprecate EOF Test
 *
 * This test validates the fast forward replication feature with different
 * deprecate EOF variable combinations. The test ensures that ProxySQL
 * handles replication switching correctly under all combinations of
 * mysql-enable_client_deprecate_eof and mysql-enable_server_deprecate_eof.
 *
 * Test Strategy:
 * - Generate a large binlog on the backend.
 * - Run replication in a loop with different deprecate EOF combinations.
 * - Test all 4 combinations: true/true, true/false, false/true, false/false.
 * - Verify that replication works correctly in all scenarios.
 * - Fetch binary log at full speed without throttling.
 */

#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctime>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#ifndef BINLOG_DUMP_NON_BLOCK
#define BINLOG_DUMP_NON_BLOCK 1
#endif // BINLOG_DUMP_NON_BLOCK

using std::string;

struct DeprecateEOFConfig {
    bool client_deprecate_eof;
    bool server_deprecate_eof;
    std::string description;
};

int main() {
    // Define the 4 combinations of deprecate EOF settings
    std::vector<DeprecateEOFConfig> configs = {
        {true, true, "client=true, server=true"},
        {true, false, "client=true, server=false"},
        {false, true, "client=false, server=true"},
        {false, false, "client=false, server=false"}
    };

    plan(20);  // 4 base tests + 16 tests (4 configs × 4 tests each)

    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    // 1. Generate a large binlog file
    MYSQL* backend_conn = mysql_init(NULL);
    if (!mysql_real_connect(backend_conn, cl.host, cl.mysql_username, cl.mysql_password, "information_schema", cl.port, NULL, 0)) {
        diag("Backend connection failed: %s", mysql_error(backend_conn));
        return -1;
    }
    ok(1, "Connected to backend server");
    MYSQL_QUERY(backend_conn, "CREATE DATABASE IF NOT EXISTS test");
    MYSQL_QUERY(backend_conn, "USE test");
    MYSQL_QUERY(backend_conn, "CREATE TABLE IF NOT EXISTS dummy_log_table (id INT PRIMARY KEY AUTO_INCREMENT, data LONGTEXT)");
    MYSQL_QUERY(backend_conn, "INSERT INTO dummy_log_table (data) VALUES (REPEAT('a', 1024*50))");
    MYSQL_QUERY(backend_conn, "INSERT INTO dummy_log_table (data) VALUES (REPEAT('a', 1024*50))");
    MYSQL_QUERY(backend_conn, "INSERT INTO dummy_log_table (data) VALUES (REPEAT('a', 1024*50))");
    int rc = mysql_query(backend_conn, "FLUSH LOGS");
    ok(rc == 0, "Generated data and flushed logs on backend");

    // 2. Get binary log file name
    string binlog_file;
    if (mysql_query(backend_conn, "SHOW BINARY LOGS") == 0) {
        MYSQL_RES *res = mysql_store_result(backend_conn);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row && row[0]) {
                binlog_file = row[0];
            }
            mysql_free_result(res);
        }
    }
    mysql_close(backend_conn);
    ok(!binlog_file.empty(), "Retrieved binary log file name: %s", binlog_file.c_str());

    // 3. Connect to ProxySQL admin
    MYSQL* proxysql_admin = mysql_init(NULL);
    if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed: %s", mysql_error(proxysql_admin));
        return -1;
    }
    ok(1, "Connected to ProxySQL admin");

    // 4. Test each deprecate EOF configuration
    for (size_t i = 0; i < configs.size(); i++) {
        const auto& config = configs[i];

        // Set the deprecate EOF variables
        std::string client_value = config.client_deprecate_eof ? "true" : "false";
        std::string server_value = config.server_deprecate_eof ? "true" : "false";

        rc = mysql_query(proxysql_admin,
                         ("UPDATE global_variables SET variable_value='" + client_value + "' WHERE variable_name='mysql-enable_client_deprecate_eof'").c_str());
        ok(rc == 0, ("Set mysql-enable_client_deprecate_eof=" + client_value).c_str());

        rc = mysql_query(proxysql_admin,
                         ("UPDATE global_variables SET variable_value='" + server_value + "' WHERE variable_name='mysql-enable_server_deprecate_eof'").c_str());
        ok(rc == 0, ("Set mysql-enable_server_deprecate_eof=" + server_value).c_str());

        rc = mysql_query(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
        ok(rc == 0, "Loaded MYSQL variables to runtime");

        // Connect for binlog reading
        MYSQL* binlog_conn = mysql_init(NULL);
        if (!mysql_real_connect(binlog_conn, cl.host, cl.mysql_username, cl.mysql_password, NULL, cl.port, NULL, 0)) {
            diag("Binlog connection failed for config %s: %s", config.description.c_str(), mysql_error(binlog_conn));
            mysql_close(proxysql_admin);
            return -1;
        }

        MYSQL_QUERY(binlog_conn, "SET /* create_new_connection=1 */  @source_binlog_checksum='NONE'");
        MYSQL_RPL rpl {};
        rpl.file_name = const_cast<char*>(binlog_file.c_str());
        rpl.start_position = 4;
        rpl.server_id = 12345;
        rpl.flags = BINLOG_DUMP_NON_BLOCK;
        rc = mysql_binlog_open(binlog_conn, &rpl);
        if (rc != 0) {
            diag("mysql_binlog_open failed for config %s: %s", config.description.c_str(), mysql_error(binlog_conn));
            mysql_close(binlog_conn);
            mysql_close(proxysql_admin);
            return -1;
        }
        diag("mysql_binlog_open succeeded for config: %s", config.description.c_str());

        // Read binlog at full speed
        long bytes_read = 0;
        bool reached_EOF = false;
        long total_chunks = 0;

        while (true) {
            rc = mysql_binlog_fetch(binlog_conn, &rpl);
            if (rc != 0) break;
            bytes_read += rpl.size;
            total_chunks++;

            if (rpl.size == 0) {
                // when size is 0, we reached EOF
                reached_EOF = true;
                break;
            }
        }

        ok(reached_EOF == true, "Config %s: Reached EOF: %s, Total Chunks: %ld, Bytes: %ld",
           config.description.c_str(), (reached_EOF == true ? "TRUE" : "FALSE"), total_chunks, bytes_read);

        diag("Config %s: binlog fetch ended with rc=%d, error=%s", config.description.c_str(),
             rc, (rc == 0 ? "None" : mysql_error(binlog_conn)));
        mysql_binlog_close(binlog_conn, &rpl);
        mysql_close(binlog_conn);

        // Result summary
        diag("Config %s: completed - chunks=%ld, bytes=%ld", config.description.c_str(), total_chunks, bytes_read);
    }

    mysql_close(proxysql_admin);

    return exit_status();
}
