#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <string>
#include <sstream>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

/**
 * @file test_ansi_quotes_group_replication-t.cpp
 * @brief Test for ANSI_QUOTES SQL mode compatibility in MySQL Group Replication monitoring
 *
 * This test verifies that ProxySQL's internal monitor can successfully query
 * MySQL Group Replication members when the backend MySQL servers have
 * ANSI_QUOTES SQL mode enabled.
 *
 * The original bug was that the monitor query used:
 *   CONCAT(member_host, ":", member_port)
 *
 * When ANSI_QUOTES is enabled, double quotes are treated as identifier
 * delimiters (like backticks), causing:
 *   ERROR 1054 (42S22): Unknown column ':' in 'field list'
 *
 * The fix changed this to use single quotes:
 *   CONCAT(member_host, ':', member_port)
 *
 * This test performs 5 distinct checks:
 * 1. Can connect to all GR backends
 * 2. Can enable ANSI_QUOTES mode on all backends
 * 3. Monitor can run without errors with ANSI_QUOTES enabled
 * 4. Monitor successfully populates mysql_server_group_replication_log
 * 5. No ANSI_QUOTES-related errors appear in monitor logs
 */

struct BackendNode {
    string host;
    int port;
    MYSQL* conn;
};

/**
 * Connect to a MySQL backend
 */
int connect_to_backend(MYSQL*& mysql, const char* host, int port, const char* username, const char* password) {
    mysql = mysql_init(NULL);
    if (!mysql) {
        diag("Failed to initialize MySQL connection to %s:%d", host, port);
        return 1;
    }

    if (!mysql_real_connect(mysql, host, username, password, NULL, port, NULL, 0)) {
        diag("Failed to connect to MySQL backend %s:%d - Error: %s", host, port, mysql_error(mysql));
        mysql_close(mysql);
        mysql = NULL;
        return 1;
    }

    diag("Successfully connected to MySQL backend %s:%d", host, port);
    return 0;
}

/**
 * Enable or disable ANSI_QUOTES mode on a backend
 */
int set_ansi_quotes_mode(MYSQL* mysql, bool enable, const char* host, int port) {
    string query;
    if (enable) {
        query = "SET GLOBAL sql_mode = CONCAT(@@sql_mode, ',ANSI_QUOTES')";
        diag("Enabling ANSI_QUOTES mode on %s:%d", host, port);
    } else {
        query = "SET GLOBAL sql_mode = REPLACE(@@sql_mode, 'ANSI_QUOTES', '')";
        diag("Disabling ANSI_QUOTES mode on %s:%d", host, port);
    }

    if (mysql_query(mysql, query.c_str())) {
        diag("Failed to set SQL mode on %s:%d - Error: %s", host, port, mysql_error(mysql));
        return 1;
    }

    return 0;
}

/**
 * Wait for monitor to establish new connections with the updated SQL mode
 */
int wait_for_monitor(MYSQL* admin_mysql) {
    diag("Waiting for monitor to establish new connections with ANSI_QUOTES mode");
    diag("Waiting 8 seconds for monitor cycles...");
    sleep(8);
    diag("Monitor should now be using connections with ANSI_QUOTES enabled");
    return 0;
}

/**
 * Verify that the monitor has successfully populated the group replication log table
 * without any ANSI_QUOTES related errors.
 */
int verify_monitor_functionality(MYSQL* admin_mysql) {
    diag("Verifying that ProxySQL monitor is working with ANSI_QUOTES enabled");

    // Check that we have entries in the monitor log table
    const char* count_query = "SELECT COUNT(*) FROM mysql_server_group_replication_log WHERE error IS NULL OR error = ''";
    if (mysql_query(admin_mysql, count_query)) {
        diag("Failed to query monitor log table - Error: %s", mysql_error(admin_mysql));
        return 1;
    }

    MYSQL_RES* result = mysql_store_result(admin_mysql);
    if (!result) {
        diag("Failed to get result from monitor log query");
        return 1;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    int success_count = 0;
    if (row && row[0]) {
        success_count = atoi(row[0]);
    }
    mysql_free_result(result);

    if (success_count == 0) {
        diag("FAILED: No successful monitor entries found in mysql_server_group_replication_log");
        return 1;
    }

    diag("SUCCESS: Found %d successful monitor entries", success_count);

    // Double-check there are no ANSI_QUOTES related errors
    const char* error_query =
        "SELECT COUNT(*) FROM mysql_server_group_replication_log "
        "WHERE error IS NOT NULL AND error != '' AND "
        "(error LIKE '%Unknown column%' OR error LIKE '%ANSI_QUOTES%')";

    if (mysql_query(admin_mysql, error_query)) {
        diag("Failed to query for monitor errors - Error: %s", mysql_error(admin_mysql));
        return 1;
    }

    result = mysql_store_result(admin_mysql);
    if (!result) {
        diag("Failed to get error count result");
        return 1;
    }

    row = mysql_fetch_row(result);
    int error_count = 0;
    if (row && row[0]) {
        error_count = atoi(row[0]);
    }
    mysql_free_result(result);

    if (error_count > 0) {
        diag("FAILED: Found %d monitor errors related to ANSI_QUOTES", error_count);
        return 1;
    }

    diag("SUCCESS: No ANSI_QUOTES related errors found in monitor logs");
    return 0;
}

/**
 * Get all Group Replication backend nodes from mysql_servers table
 */
int get_gr_backends(MYSQL* admin_mysql, vector<BackendNode>& backends) {
    // Match the GR backends regardless of which infra we run against. Every GR
    // infra registers its nodes with a hostname like
    // "dbdeployerN.infra-dbdeployer-<infra>-gr" (e.g. mysql84/90/91/92/93/95-gr),
    // so filter on the common "infra-dbdeployer" marker instead of a hardcoded
    // infra name -- otherwise the test finds zero backends in every group but
    // mysql84-gr and fails at "Find Group Replication backends".
    const char* query =
        "SELECT DISTINCT hostname, port FROM mysql_servers "
        "WHERE hostname LIKE '%infra-dbdeployer%' "
        "ORDER BY hostname, port";

    if (mysql_query(admin_mysql, query)) {
        diag("Failed to query mysql_servers for GR backends - Error: %s", mysql_error(admin_mysql));
        return 1;
    }

    MYSQL_RES* result = mysql_store_result(admin_mysql);
    if (!result) {
        diag("Failed to get GR backend list");
        return 1;
    }

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        if (row[0] && row[1]) {
            BackendNode node;
            node.host = row[0];
            node.port = atoi(row[1]);
            node.conn = NULL;
            backends.push_back(node);
            diag("Found GR backend: %s:%d", node.host.c_str(), node.port);
        }
    }

    mysql_free_result(result);

    if (backends.empty()) {
        diag("No Group Replication backends found in mysql_servers table");
        return 1;
    }

    diag("Found %zu Group Replication backends", backends.size());
    return 0;
}

int test_ansi_quotes_group_replication() {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get environment variables");
        return 1;
    }

    diag("=== Starting ANSI_QUOTES Group Replication Monitor Test ===");

    // Test 1: Connect to ProxySQL admin interface
    MYSQL* admin_mysql = mysql_init(NULL);
    if (!admin_mysql) {
        diag("Failed to initialize ProxySQL admin connection");
        ok(0, "Initialize ProxySQL admin connection");
        return 1;
    }

    if (!mysql_real_connect(admin_mysql, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Failed to connect to ProxySQL admin - Error: %s", mysql_error(admin_mysql));
        ok(0, "Connect to ProxySQL admin interface");
        mysql_close(admin_mysql);
        return 1;
    }
    ok(1, "Connect to ProxySQL admin interface");
    diag("Connected to ProxySQL admin interface");

    // Test 2: Find all Group Replication backends
    vector<BackendNode> backends;
    if (get_gr_backends(admin_mysql, backends)) {
        ok(0, "Find Group Replication backends in mysql_servers table");
        mysql_close(admin_mysql);
        return 1;
    }
    ok(1, "Find Group Replication backends in mysql_servers table");

    // Derive the infrastructure-specific user (created by docker-compose-init.bash)
    // from a backend hostname, e.g. "dbdeployerN.infra-dbdeployer-<infra>-gr" ->
    // "infra-dbdeployer-<infra>-gr". Keeps the test infra-agnostic so it runs
    // across every GR group instead of only mysql84-gr.
    const string& backend_host = backends.front().host;
    size_t infra_dot = backend_host.find('.');
    string infra_user = (infra_dot != string::npos) ? backend_host.substr(infra_dot + 1) : backend_host;
    string backend_user = infra_user;
    string backend_password = infra_user;

    // Test 3: Connect to all backends
    vector<string> original_sql_modes;
    original_sql_modes.resize(backends.size());
    bool all_connected = true;

    for (size_t i = 0; i < backends.size(); i++) {
        if (connect_to_backend(backends[i].conn, backends[i].host.c_str(), backends[i].port,
                              backend_user.c_str(), backend_password.c_str())) {
            all_connected = false;
            break;
        }

        // Get original SQL mode for cleanup later
        if (mysql_query(backends[i].conn, "SELECT @@sql_mode")) {
            diag("Failed to get SQL mode from %s:%d", backends[i].host.c_str(), backends[i].port);
            all_connected = false;
            break;
        }

        MYSQL_RES* result = mysql_store_result(backends[i].conn);
        if (result) {
            MYSQL_ROW row = mysql_fetch_row(result);
            if (row && row[0]) {
                original_sql_modes[i] = row[0];
            }
            mysql_free_result(result);
        }
    }

    ok(all_connected, "Connect to all Group Replication backends with infrastructure user");
    if (!all_connected) {
        // Cleanup
        for (size_t i = 0; i < backends.size(); i++) {
            if (backends[i].conn) mysql_close(backends[i].conn);
        }
        mysql_close(admin_mysql);
        return 1;
    }

    // Test 4: Enable ANSI_QUOTES on all backends
    bool all_modes_set = true;
    for (size_t i = 0; i < backends.size(); i++) {
        if (set_ansi_quotes_mode(backends[i].conn, true, backends[i].host.c_str(), backends[i].port)) {
            all_modes_set = false;
            break;
        }
    }
    ok(all_modes_set, "Enable ANSI_QUOTES SQL mode on all Group Replication backends");
    if (!all_modes_set) {
        // Cleanup
        for (size_t i = 0; i < backends.size(); i++) {
            if (backends[i].conn) {
                set_ansi_quotes_mode(backends[i].conn, false, backends[i].host.c_str(), backends[i].port);
                mysql_close(backends[i].conn);
            }
        }
        mysql_close(admin_mysql);
        return 1;
    }

    // Test 5: Monitor should work with ANSI_QUOTES
    if (wait_for_monitor(admin_mysql)) {
        ok(0, "Wait for monitor to establish new connections with ANSI_QUOTES mode");
        // Cleanup
        for (size_t i = 0; i < backends.size(); i++) {
            if (backends[i].conn) {
                set_ansi_quotes_mode(backends[i].conn, false, backends[i].host.c_str(), backends[i].port);
                mysql_close(backends[i].conn);
            }
        }
        mysql_close(admin_mysql);
        return 1;
    }
    ok(1, "Wait for monitor to establish new connections with ANSI_QUOTES mode");

    // Test 6: Verify that the monitor is actually populating logs without errors
    if (verify_monitor_functionality(admin_mysql)) {
        ok(0, "Monitor successfully populates mysql_server_group_replication_log with ANSI_QUOTES enabled");
        // Cleanup
        for (size_t i = 0; i < backends.size(); i++) {
            if (backends[i].conn) {
                set_ansi_quotes_mode(backends[i].conn, false, backends[i].host.c_str(), backends[i].port);
                mysql_close(backends[i].conn);
            }
        }
        mysql_close(admin_mysql);
        return 1;
    }
    ok(1, "Monitor successfully populates mysql_server_group_replication_log with ANSI_QUOTES enabled");

    // Cleanup: Restore original SQL mode on all backends
    diag("Restoring original SQL modes on all backends");
    for (size_t i = 0; i < backends.size(); i++) {
        if (backends[i].conn) {
            string restore_query = "SET GLOBAL sql_mode = '" + original_sql_modes[i] + "'";
            mysql_query(backends[i].conn, restore_query.c_str());
            mysql_close(backends[i].conn);
        }
    }
    mysql_close(admin_mysql);

    diag("=== ANSI_QUOTES Group Replication Monitor Test completed successfully ===");
    return 0;
}

int main(int argc, char** argv) {
    // We perform 6 distinct checks
    plan(6);

    int result = test_ansi_quotes_group_replication();

    return exit_status();
}