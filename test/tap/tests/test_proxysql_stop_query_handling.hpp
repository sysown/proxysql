/**
 * @file test_proxysql_stop_query_handling.hpp
 * @brief Shared header for PROXYSQL STOP/START query handling tests.
 *        Provides reusable functions to test STOP/START behavior with various module configurations.
 * @date 2025-01-24
 */

#ifndef TEST_PROXYSQL_STOP_QUERY_HANDLING_HPP
#define TEST_PROXYSQL_STOP_QUERY_HANDLING_HPP

// Number of individual test cases performed by test_proxysql_stop_start_handling()
// Update this value if you add/remove tests in the function
#define PROXYSQL_STOP_START_TEST_COUNT 13

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

struct ProxySQLStopStartTestConfig {
    string test_name_prefix;
    int sleep_after_stop;
    int sleep_after_start;
    bool verbose_logging;

    ProxySQLStopStartTestConfig() :
        test_name_prefix(""),
        sleep_after_stop(2),
        sleep_after_start(3),
        verbose_logging(false) {}
};

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

/**
 * @brief Tests PROXYSQL STOP/START functionality with a connected admin interface
 *
 * This function performs the complete test sequence:
 * 1. Execute PROXYSQL STOP
 * 2. Test queries that work with null pointer protection during STOP state
 * 3. Test modification queries during STOP state
 * 4. Test basic queries that should succeed during STOP state
 * 5. Execute PROXYSQL START
 * 6. Verify queries continue to work after START
 *
 * @param admin_mysql Connected MYSQL admin interface
 * @param config Test configuration options
 * @return int Number of tests performed (PROXYSQL_STOP_START_TEST_COUNT), or -1 if critical failure
 */
int test_proxysql_stop_start_handling(MYSQL* admin_mysql, const ProxySQLStopStartTestConfig& config = ProxySQLStopStartTestConfig()) {
    string test_prefix = config.test_name_prefix.empty() ? "" : config.test_name_prefix + " - ";

    // === TEST 1: Execute PROXYSQL STOP ===
    bool stop_success = execute_query_succeeds(admin_mysql, "PROXYSQL STOP");
    ok(stop_success, "%sPROXYSQL STOP command should succeed", test_prefix.c_str());

    if (!stop_success) {
        diag("%sPROXYSQL STOP failed, cannot continue with remaining tests", test_prefix.c_str());
        return -1;
    }

    // Give some time for STOP to complete
    sleep(config.sleep_after_stop);

    // === TESTS 2-5: Test queries that work with null pointer protection during STOP state ===

    // TEST 2: runtime_mysql_query_rules should work normally with null pointer protection
    int row_count = get_row_count(admin_mysql, "SELECT COUNT(*) FROM runtime_mysql_query_rules");
    ok(row_count >= 0, "%sruntime_mysql_query_rules should return valid count during STOP state, actual: %d", test_prefix.c_str(), row_count);

    // TEST 3: runtime_mysql_query_rules_fast_routing should work normally with null pointer protection
    row_count = get_row_count(admin_mysql, "SELECT COUNT(*) FROM runtime_mysql_query_rules_fast_routing");
    ok(row_count >= 0, "%sruntime_mysql_query_rules_fast_routing should return valid count during STOP state, actual: %d", test_prefix.c_str(), row_count);

    // TEST 4: runtime_mysql_users should work normally with null pointer protection
    row_count = get_row_count(admin_mysql, "SELECT COUNT(*) FROM runtime_mysql_users");
    ok(row_count >= 0, "%sruntime_mysql_users should return valid count during STOP state, actual: %d", test_prefix.c_str(), row_count);

    // TEST 5: stats_mysql_query_digest should work normally with null pointer protection
    row_count = get_row_count(admin_mysql, "SELECT COUNT(*) FROM stats_mysql_query_digest");
    ok(row_count >= 0, "%sstats_mysql_query_digest should return valid count during STOP state, actual: %d", test_prefix.c_str(), row_count);

    // === TEST 6: Test modification queries during STOP state ===

    // TEST 6: LOAD MYSQL USERS TO RUNTIME should succeed (MySQL Auth module is loaded)
    bool load_users_success = execute_query_succeeds(admin_mysql, "LOAD MYSQL USERS TO RUNTIME");
    ok(load_users_success, "%sLOAD MYSQL USERS TO RUNTIME should succeed during STOP state", test_prefix.c_str());

    // TEST 7: LOAD MYSQL QUERY RULES TO RUNTIME should fail (Query Processor not started)
    bool load_rules_fails = execute_query_fails(admin_mysql, "LOAD MYSQL QUERY RULES TO RUNTIME", "Global Query Processor not started");
    ok(load_rules_fails, "%sLOAD MYSQL QUERY RULES TO RUNTIME should fail during STOP state", test_prefix.c_str());

    // === TESTS 8-11: Test queries that should SUCCEED during STOP state ===

    // TEST 8: Basic arithmetic query should work
    bool basic_query_success = execute_query_succeeds(admin_mysql, "SELECT 1+1");
    ok(basic_query_success, "%sBasic arithmetic query (SELECT 1+1) should work during STOP state", test_prefix.c_str());

    // TEST 9: Version query should work
    bool version_success = execute_query_succeeds(admin_mysql, "SELECT @@version");
    ok(version_success, "%sVersion query should work during STOP state", test_prefix.c_str());

    // TEST 10: SHOW PROMETHEUS METRICS should work (existing functionality)
    bool prometheus_success = execute_query_succeeds(admin_mysql, "SHOW PROMETHEUS METRICS");
    ok(prometheus_success, "%sSHOW PROMETHEUS METRICS should work during STOP state", test_prefix.c_str());

    // TEST 11: Basic SELECT should work
    bool db_select_success = execute_query_succeeds(admin_mysql, "SELECT DATABASE()");
    bool user_select_success = execute_query_succeeds(admin_mysql, "SELECT USER()");
    ok(db_select_success && user_select_success, "%sBasic SELECT (DATABASE() and USER()) should work during STOP state", test_prefix.c_str());

    // === TEST 12: Execute PROXYSQL START ===
    bool start_success = execute_query_succeeds(admin_mysql, "PROXYSQL START");
    ok(start_success, "%sPROXYSQL START command should succeed", test_prefix.c_str());

    if (!start_success) {
        diag("%sPROXYSQL START failed, cannot continue with final test", test_prefix.c_str());
        return -1;
    }

    // Give some time for START to complete
    sleep(config.sleep_after_start);

    // === TEST 13: Test that queries continue to work after START ===

    // After START, runtime queries should continue to work normally
    row_count = get_row_count(admin_mysql, "SELECT COUNT(*) FROM runtime_mysql_query_rules");
    ok(row_count >= 0, "%sruntime_mysql_query_rules should continue to work after START, rows: %d", test_prefix.c_str(), row_count);

    return PROXYSQL_STOP_START_TEST_COUNT; // Total number of tests performed
}

/**
 * @brief Connects to ProxySQL admin interface and runs STOP/START tests
 *
 * @param host ProxySQL host
 * @param admin_username Admin username
 * @param admin_password Admin password
 * @param admin_port Admin port
 * @param config Test configuration
 * @return int Number of tests performed, or -1 if connection failed
 */
int test_proxysql_stop_start_with_connection(const string& host, const string& admin_username,
                                            const string& admin_password, int admin_port,
                                            const ProxySQLStopStartTestConfig& config = ProxySQLStopStartTestConfig()) {
    MYSQL* proxysql_admin = mysql_init(NULL);
    if (!proxysql_admin) {
        fprintf(stderr, "File %s, line %d, Error: MySQL initialization failed\n", __FILE__, __LINE__);
        return -1;
    }

    // Connect to ProxySQL admin interface
    if (!mysql_real_connect(proxysql_admin, host.c_str(), admin_username.c_str(),
                           admin_password.c_str(), NULL, admin_port, NULL, 0)) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        mysql_close(proxysql_admin);
        return -1;
    }

    int result = test_proxysql_stop_start_handling(proxysql_admin, config);

    mysql_close(proxysql_admin);
    return result;
}

#endif // TEST_PROXYSQL_STOP_QUERY_HANDLING_HPP