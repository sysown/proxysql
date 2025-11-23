/**
 * @file reg_test_4960_monitor_modules-t.cpp
 * @brief TAP test for verifying monitor module enable/disable functionality from PR #4960.
 *
 * This test verifies that MySQL and PostgreSQL monitor modules can be enabled/disabled
 * via CLI arguments and that their status is correctly reflected in the global_variables table.
 */

#include <cstring>
#include <vector>
#include <string>
#include <thread>
#include <stdio.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <signal.h>
#include <sys/wait.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

struct MonitorTestCase {
    string name;
    vector<const char*> cli_args;
    string config_content;
    int mysql_admin_port;
    int mysql_worker_port;
    bool mysql_monitor_expected;
    bool pgsql_monitor_expected;
};

int connect_to_proxysql_admin(int port, MYSQL*& mysql) {
    mysql = mysql_init(NULL);
    if (!mysql) {
        diag("MySQL initialization failed");
        return -1;
    }

    // Set connection timeout
    unsigned int timeout = 5;
    mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
    mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT, &timeout);
    mysql_options(mysql, MYSQL_OPT_WRITE_TIMEOUT, &timeout);

    // Connect to ProxySQL admin
    if (!mysql_real_connect(mysql, "127.0.0.1", "admin", "admin", NULL, port, NULL, 0)) {
        diag("Failed to connect to ProxySQL admin on port %d: %s", port, mysql_error(mysql));
        mysql_close(mysql);
        mysql = NULL;
        return -1;
    }

    return 0;
}

int check_monitor_status(MYSQL* mysql, const string& monitor_name, bool expected_enabled) {
    string query = "SELECT variable_value FROM global_variables WHERE variable_name = '" + monitor_name + "'";

    int query_result = mysql_query(mysql, query.c_str());
    if (query_result != 0) {
        diag("Failed to execute query for %s: %s", monitor_name.c_str(), mysql_error(mysql));
        return -1;
    }

    MYSQL_RES* result = mysql_store_result(mysql);
    if (!result) {
        diag("Failed to store result for %s: %s", monitor_name.c_str(), mysql_error(mysql));
        return -1;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (!row) {
        diag("No result found for %s", monitor_name.c_str());
        mysql_free_result(result);
        return -1;
    }

    string variable_value = row[0] ? row[0] : "";
    bool actual_enabled = (variable_value == "true");

    mysql_free_result(result);

    if (actual_enabled != expected_enabled) {
        diag("Monitor status mismatch for %s: expected %s, got %s",
             monitor_name.c_str(),
             expected_enabled ? "true" : "false",
             actual_enabled ? "true" : "false");
        return 1;
    }

    return 0;
}

int launch_proxysql_instance(const MonitorTestCase& test_case, const CommandLine& cl) {
    const string test_datadir = string { cl.workdir } + "reg_test_4960_monitor_" + test_case.name;
    const string test_config_file = test_datadir + "/proxysql.cfg";

    // Clean up existing datadir if it exists
    string cleanup_cmd = "rm -rf " + test_datadir;
    int cleanup_result = system(cleanup_cmd.c_str());
    (void)cleanup_result;

    // Create test datadir
    string mkdir_cmd = "mkdir -p " + test_datadir;
    int mkdir_result = system(mkdir_cmd.c_str());
    (void)mkdir_result;

    // Create config file
    std::ofstream config_file(test_config_file);
    config_file << test_case.config_content;
    config_file.close();

    // Build command to start ProxySQL
    const string proxysql_path { string { getenv("WORKSPACE") } + "/src/proxysql" };
    string cmd = proxysql_path + " -f -c " + test_config_file;

    // Add CLI arguments
    for (const auto& arg : test_case.cli_args) {
        cmd += " " + string(arg);
    }

    // Start ProxySQL in background
    diag("  Starting ProxySQL with command: %s", cmd.c_str());
    int start_result = system((cmd + " &").c_str());
    (void)start_result;

    // Wait a bit for startup
    sleep(5);

    return EXIT_SUCCESS;
}

int run_monitor_test_case(const MonitorTestCase& test_case, const CommandLine& cl) {
    int result = EXIT_SUCCESS;

    diag("Running monitor test case: %s", test_case.name.c_str());
    diag("  Expected MySQL monitor: %s", test_case.mysql_monitor_expected ? "YES" : "NO");
    diag("  Expected PgSQL monitor: %s", test_case.pgsql_monitor_expected ? "YES" : "NO");

    // Display CLI arguments if any
    if (!test_case.cli_args.empty()) {
        diag("  CLI arguments:");
        for (size_t i = 0; i < test_case.cli_args.size(); i++) {
            diag("    %s", test_case.cli_args[i]);
        }
    }

    // Launch ProxySQL instance
    if (launch_proxysql_instance(test_case, cl) != EXIT_SUCCESS) {
        diag("Failed to launch ProxySQL for test case: %s", test_case.name.c_str());
        return EXIT_FAILURE;
    }

    // Wait for ProxySQL to be ready using the standard approach
    diag("  Waiting for ProxySQL admin interface to be ready...");
    conn_opts_t conn_opts {};
    conn_opts.host = "127.0.0.1";
    conn_opts.port = test_case.mysql_admin_port;
    conn_opts.user = "admin";
    conn_opts.pass = "admin";

    MYSQL* mysql = wait_for_proxysql(conn_opts, 15);
    if (mysql == nullptr) {
        diag("  ❌ Failed to connect to ProxySQL admin interface after 15 seconds");
        result = EXIT_FAILURE;
    } else {
        diag("  ✅ Connected to admin interface");

        // Check MySQL monitor status
        diag("  Checking MySQL monitor status...");
        int mysql_result = check_monitor_status(mysql, "mysql-monitor_enabled", test_case.mysql_monitor_expected);
        if (mysql_result == 0) {
            diag("  ✅ MySQL monitor status correct");
        } else if (mysql_result == 1) {
            diag("  ❌ MySQL monitor status incorrect");
            result = EXIT_FAILURE;
        } else {
            diag("  ❌ Error checking MySQL monitor status");
            result = EXIT_FAILURE;
        }

        // Check PgSQL monitor status
        diag("  Checking PgSQL monitor status...");
        int pgsql_result = check_monitor_status(mysql, "pgsql-monitor_enabled", test_case.pgsql_monitor_expected);
        if (pgsql_result == 0) {
            diag("  ✅ PgSQL monitor status correct");
        } else if (pgsql_result == 1) {
            diag("  ❌ PgSQL monitor status incorrect");
            result = EXIT_FAILURE;
        } else {
            diag("  ❌ Error checking PgSQL monitor status");
            result = EXIT_FAILURE;
        }

        mysql_close(mysql);
    }

    // Force cleanup
    string kill_cmd = "pkill -f \"proxysql.*" + string { cl.workdir } + "reg_test_4960_monitor_" + test_case.name + "\" 2>/dev/null || true";
    int kill_result = system(kill_cmd.c_str());
    (void)kill_result;

    // Cleanup ports
    string cleanup_admin = "fuser -k " + std::to_string(test_case.mysql_admin_port) + "/tcp 2>/dev/null || true";
    string cleanup_worker = "fuser -k " + std::to_string(test_case.mysql_worker_port) + "/tcp 2>/dev/null || true";
    int cleanup_admin_result = system(cleanup_admin.c_str());
    int cleanup_worker_result = system(cleanup_worker.c_str());
    (void)cleanup_admin_result;
    (void)cleanup_worker_result;

    diag("  Monitor test completed");

    return result;
}

int main(int argc, char** argv) {
    CommandLine cl;

    const char* WORKSPACE = getenv("WORKSPACE");

    if (cl.getEnv() || WORKSPACE == nullptr) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }

    // Define monitor test cases - 4 combinations of monitor enable/disable
    vector<MonitorTestCase> test_cases = {
        // Test 1: Both monitors enabled (default)
        {
            "both_enabled",
            {},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_monitor_both_enabled\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:14050\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:14051\"\n"
            "}\n",
            14050, 14051, true, true
        },

        // Test 2: MySQL monitor disabled, PgSQL monitor enabled
        {
            "mysql_disabled",
            {"--mysql-monitor", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_monitor_mysql_disabled\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:14052\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:14053\"\n"
            "}\n",
            14052, 14053, false, true
        },

        // Test 3: MySQL monitor enabled, PgSQL monitor disabled
        {
            "pgsql_disabled",
            {"--pgsql-monitor", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_monitor_pgsql_disabled\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:14054\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:14055\"\n"
            "}\n",
            14054, 14055, true, false
        },

        // Test 4: Both monitors disabled
        {
            "both_disabled",
            {"--mysql-monitor", "false", "--pgsql-monitor", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_monitor_both_disabled\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:14056\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:14057\"\n"
            "}\n",
            14056, 14057, false, false
        }
    };

    plan(test_cases.size());

    // Run all monitor test cases
    for (const auto& test_case : test_cases) {
        diag("============================================================");
        int result = run_monitor_test_case(test_case, cl);
        ok(result == EXIT_SUCCESS, "Monitor test case '%s' %s", test_case.name.c_str(),
           result == EXIT_SUCCESS ? "passed" : "failed");
    }
    diag("============================================================");

    return exit_status();
}