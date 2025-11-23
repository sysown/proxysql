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

    // We expect 13 test cases:
    // 1. Test STOP command succeeds
    // 2-5. Test queries that work with null pointer protection during STOP state (4 queries)
    // 6. Test LOAD MYSQL USERS TO RUNTIME succeeds (MySQL Auth module is loaded)
    // 7. Test LOAD MYSQL QUERY RULES TO RUNTIME fails (Query Processor not started)
    // 8-11. Test queries that should succeed during STOP state (4 queries)
    // 12. Test START command succeeds
    // 13. Test that queries continue to work after START
    plan(13);

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

    // === TESTS 2-5: Test queries that work with null pointer protection during STOP state ===

    // TEST 2: runtime_mysql_query_rules should work normally with null pointer protection
    int row_count = get_row_count(proxysql_admin, "SELECT COUNT(*) FROM runtime_mysql_query_rules");
    ok(row_count >= 0, "runtime_mysql_query_rules should return valid count during STOP state, actual: %d", row_count);

    // TEST 3: runtime_mysql_query_rules_fast_routing should work normally with null pointer protection
    row_count = get_row_count(proxysql_admin, "SELECT COUNT(*) FROM runtime_mysql_query_rules_fast_routing");
    ok(row_count >= 0, "runtime_mysql_query_rules_fast_routing should return valid count during STOP state, actual: %d", row_count);

    // TEST 4: runtime_mysql_users should work normally with null pointer protection
    row_count = get_row_count(proxysql_admin, "SELECT COUNT(*) FROM runtime_mysql_users");
    ok(row_count >= 0, "runtime_mysql_users should return valid count during STOP state, actual: %d", row_count);

    // TEST 5: stats_mysql_query_digest should work normally with null pointer protection
    row_count = get_row_count(proxysql_admin, "SELECT COUNT(*) FROM stats_mysql_query_digest");
    ok(row_count >= 0, "stats_mysql_query_digest should return valid count during STOP state, actual: %d", row_count);

    // === TEST 6: Test modification queries during STOP state ===

    // TEST 6: LOAD MYSQL USERS TO RUNTIME should succeed (MySQL Auth module is loaded)
    bool load_users_success = execute_query_succeeds(proxysql_admin, "LOAD MYSQL USERS TO RUNTIME");
    ok(load_users_success, "LOAD MYSQL USERS TO RUNTIME should succeed during STOP state");

    // TEST 7: LOAD MYSQL QUERY RULES TO RUNTIME should fail (Query Processor not started)
    bool load_rules_fails = execute_query_fails(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME", "Global Query Processor not started");
    ok(load_rules_fails, "LOAD MYSQL QUERY RULES TO RUNTIME should fail during STOP state");

    // === TESTS 8-11: Test queries that should SUCCEED during STOP state ===

    // TEST 8: Basic arithmetic query should work
    bool basic_query_success = execute_query_succeeds(proxysql_admin, "SELECT 1+1");
    ok(basic_query_success, "Basic arithmetic query (SELECT 1+1) should work during STOP state");

    // TEST 9: Version query should work
    bool version_success = execute_query_succeeds(proxysql_admin, "SELECT @@version");
    ok(version_success, "Version query should work during STOP state");

    // TEST 10: SHOW PROMETHEUS METRICS should work (existing functionality)
    bool prometheus_success = execute_query_succeeds(proxysql_admin, "SHOW PROMETHEUS METRICS");
    ok(prometheus_success, "SHOW PROMETHEUS METRICS should work during STOP state");

    // TEST 11: Basic SELECT should work
    bool db_select_success = execute_query_succeeds(proxysql_admin, "SELECT DATABASE()");
    bool user_select_success = execute_query_succeeds(proxysql_admin, "SELECT USER()");
    ok(db_select_success && user_select_success, "Basic SELECT (DATABASE() and USER()) should work during STOP state");

    // === TEST 12: Execute PROXYSQL START ===
    bool start_success = execute_query_succeeds(proxysql_admin, "PROXYSQL START");
    ok(start_success, "PROXYSQL START command should succeed");

    if (!start_success) {
        diag("PROXYSQL START failed, cannot continue with final test");
        mysql_close(proxysql_admin);
        return exit_status();
    }

    // Give some time for START to complete
    sleep(3);

    // === TEST 13: Test that queries continue to work after START ===

    // After START, runtime queries should continue to work normally
    row_count = get_row_count(proxysql_admin, "SELECT COUNT(*) FROM runtime_mysql_query_rules");
    ok(row_count >= 0, "runtime_mysql_query_rules should continue to work after START, rows: %d", row_count);

    mysql_close(proxysql_admin);

    return exit_status();
}