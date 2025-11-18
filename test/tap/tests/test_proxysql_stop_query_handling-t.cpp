/**
 * @file test_proxysql_stop_query_handling-t.cpp
 * @brief This test verifies PROXYSQL STOP query handling fix for issue 5186.
 *        Tests that admin queries are properly handled during STOP state.
 * @date 2025-01-18
 */

#include <algorithm>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

// Helper function to execute query and check if it succeeds
bool execute_query_succeeds(MYSQL* mysql, const string& query) {
    if (mysql_query(mysql, query.c_str()) == 0) {
        mysql_free_result(mysql_store_result(mysql));
        return true;
    }
    return false;
}

// Helper function to execute query and check if it fails as expected
bool execute_query_fails(MYSQL* mysql, const string& query, const string& expected_error_substring = "") {
    int rc = mysql_query(mysql, query.c_str());
    if (rc != 0) {
        string error = mysql_error(mysql);
        if (expected_error_substring.empty() || error.find(expected_error_substring) != string::npos) {
            return true; // Failed as expected
        }
    }
    return false; // Should have failed but didn't
}

// Helper function to get row count from a query
int get_row_count(MYSQL* mysql, const string& query) {
    if (mysql_query(mysql, query.c_str()) == 0) {
        MYSQL_RES* result = mysql_store_result(mysql);
        if (result) {
            int count = mysql_num_rows(result);
            mysql_free_result(result);
            return count;
        }
    }
    return -1;
}

int main(int argc, char** argv) {
    CommandLine cl;

    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    // We expect 12 test cases:
    // 1. Test STOP command succeeds
    // 2-6. Test queries that should fail during STOP state (5 queries)
    // 7-10. Test queries that should succeed during STOP state (4 queries)
    // 11. Test START command succeeds
    // 12. Test that previously failing queries now succeed
    plan(12);

    MYSQL* proxysql_admin = mysql_init(NULL);
    if (!proxysql_admin) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        return -1;
    }

    // Connect to local ProxySQL admin interface
    if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        return -1;
    }

    // === TEST 1: Execute PROXYSQL STOP ===
    bool stop_success = execute_query_succeeds(proxysql_admin, "PROXYSQL STOP");
    ok(stop_success, "PROXYSQL STOP command should succeed");

    if (!stop_success) {
        diag("PROXYSQL STOP failed, cannot continue with remaining tests");
        mysql_close(proxysql_admin);
        return exit_status();
    }

    // Give some time for STOP to complete
    sleep(2);

    // === TESTS 2-6: Test queries that should FAIL during STOP state ===

    // TEST 2: runtime_mysql_query_rules should return empty resultset, not crash
    int row_count = get_row_count(proxysql_admin, "SELECT COUNT(*) FROM runtime_mysql_query_rules");
    ok(row_count == 0, "runtime_mysql_query_rules should return 0 rows during STOP state, actual: %d", row_count);

    // TEST 3: runtime_mysql_query_rules_fast_routing should return 0, not crash
    row_count = get_row_count(proxysql_admin, "SELECT COUNT(*) FROM runtime_mysql_query_rules_fast_routing");
    ok(row_count == 0, "runtime_mysql_query_rules_fast_routing should return 0 rows during STOP state, actual: %d", row_count);

    // TEST 4: runtime_mysql_users should return 0 rows, not crash
    row_count = get_row_count(proxysql_admin, "SELECT COUNT(*) FROM runtime_mysql_users");
    ok(row_count == 0, "runtime_mysql_users should return 0 rows during STOP state, actual: %d", row_count);

    // TEST 5: stats_mysql_query_digest should return 0 rows, not crash
    row_count = get_row_count(proxysql_admin, "SELECT COUNT(*) FROM stats_mysql_query_digest");
    ok(row_count == 0, "stats_mysql_query_digest should return 0 rows during STOP state, actual: %d", row_count);

    // TEST 6: LOAD MYSQL USERS TO RUNTIME should fail
    bool load_fails = execute_query_fails(proxysql_admin, "LOAD MYSQL USERS TO RUNTIME");
    ok(load_fails, "LOAD MYSQL USERS TO RUNTIME should fail during STOP state");

    // === TESTS 7-10: Test queries that should SUCCEED during STOP state ===

    // TEST 7: Basic arithmetic query should work
    bool basic_query_success = execute_query_succeeds(proxysql_admin, "SELECT 1+1");
    ok(basic_query_success, "Basic arithmetic query (SELECT 1+1) should work during STOP state");

    // TEST 8: Version query should work
    bool version_success = execute_query_succeeds(proxysql_admin, "SELECT @@version");
    ok(version_success, "Version query should work during STOP state");

    // TEST 9: SHOW PROMETHEUS METRICS should work (existing functionality)
    bool prometheus_success = execute_query_succeeds(proxysql_admin, "SHOW PROMETHEUS METRICS");
    ok(prometheus_success, "SHOW PROMETHEUS METRICS should work during STOP state");

    // TEST 10: Basic SELECT should work
    bool select_success = execute_query_succeeds(proxysql_admin, "SELECT DATABASE(), USER()");
    ok(select_success, "Basic SELECT should work during STOP state");

    // === TEST 11: Execute PROXYSQL START ===
    bool start_success = execute_query_succeeds(proxysql_admin, "PROXYSQL START");
    ok(start_success, "PROXYSQL START command should succeed");

    if (!start_success) {
        diag("PROXYSQL START failed, cannot continue with final test");
        mysql_close(proxysql_admin);
        return exit_status();
    }

    // Give some time for START to complete
    sleep(3);

    // === TEST 12: Test that previously failing queries now succeed ===

    // After START, runtime queries should work again
    row_count = get_row_count(proxysql_admin, "SELECT COUNT(*) FROM runtime_mysql_query_rules");
    ok(row_count >= 0, "runtime_mysql_query_rules should work again after START state, rows: %d", row_count);

    mysql_close(proxysql_admin);

    return exit_status();
}