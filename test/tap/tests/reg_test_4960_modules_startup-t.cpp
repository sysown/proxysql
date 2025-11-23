/**
 * @file reg_test_4960_modules_startup-t.cpp
 * @brief TAP test for verifying module enable/disable functionality introduced in PR #4960.
 *
 * This test verifies that ProxySQL can start correctly with various combinations of
 * MySQL/PostgreSQL worker, admin, and monitor modules enabled or disabled via both
 * command line arguments and configuration file settings.
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

struct TestCase {
    string name;
    vector<const char*> cli_args;
    string config_content;
    int mysql_admin_port;
    int pgsql_admin_port;
    int mysql_worker_port;
    int pgsql_worker_port;
    bool should_start;
    bool mysql_admin_expected;
    bool pgsql_admin_expected;
    bool mysql_worker_expected;
    bool pgsql_worker_expected;
};

int launch_proxysql_instance(const TestCase& test_case, const CommandLine& cl, int& proxy_pid) {
    const string test_datadir = string { cl.workdir } + "reg_test_4960_node_" + test_case.name;
    const string test_config_file = test_datadir + "/proxysql.cfg";
    const string test_log_file = test_datadir + "/proxysql.log";

    diag("  Creating test environment:");
    diag("    Datadir: %s", test_datadir.c_str());
    diag("    Config file: %s", test_config_file.c_str());

    // Clean up existing datadir if it exists
    string cleanup_cmd = "rm -rf " + test_datadir;
    int cleanup_result = system(cleanup_cmd.c_str());
    (void)cleanup_result; // Suppress unused warning

    // Create test datadir
    string mkdir_cmd = "mkdir -p " + test_datadir;
    int mkdir_result = system(mkdir_cmd.c_str());
    (void)mkdir_result; // Suppress unused warning

    // Create config file
    std::ofstream config_file(test_config_file);
    config_file << test_case.config_content;
    config_file.close();

    diag("  Config file contents:");
    // Show config file contents (with proper indentation)
    std::istringstream config_stream(test_case.config_content);
    string config_line;
    while (std::getline(config_stream, config_line)) {
        diag("    %s", config_line.c_str());
    }

    // Launch ProxySQL using the same pattern as reg_test_3847_admin_lock-t.cpp
    std::thread launch_proxy([&cl, &test_case, &test_config_file, &test_log_file, &proxy_pid] (int& err_code) -> void {
        to_opts_t wexecvp_opts {};
        wexecvp_opts.poll_to_us = 100 * 1000;
        wexecvp_opts.waitpid_delay_us = 500 * 1000;
        wexecvp_opts.timeout_us = 20000 * 1000;  // 20s timeout
        wexecvp_opts.sigkill_to_us = 3000 * 1000;

        const string proxysql_path { string { getenv("WORKSPACE") } + "/src/proxysql" };
        vector<const char*> proxy_args = { "-f", "-c", test_config_file.c_str() };

        // Add test-specific CLI arguments
        for (const auto& arg : test_case.cli_args) {
            proxy_args.push_back(arg);
        }

        // Build and display the full command for manual testing (with timeout)
        string full_command = "timeout 30 " + proxysql_path;
        for (const auto& arg : proxy_args) {
            full_command += " " + string(arg);
        }
        diag("  Command to execute manually:");
        diag("    %s", full_command.c_str());

        string s_stdout {};
        string s_stderr {};

        diag("  Starting ProxySQL (with 30s timeout)...");
        int w_res = wexecvp(proxysql_path, proxy_args, wexecvp_opts, s_stdout, s_stderr);
        if (w_res != EXIT_SUCCESS) {
            diag("'wexecvp' failed with error: %d for test case: %s", w_res, test_case.name.c_str());
            diag("Command: %s", proxysql_path.c_str());
            for (size_t i = 0; i < proxy_args.size(); i++) {
                diag("  arg[%zu]: %s", i, proxy_args[i]);
            }
            if (!s_stderr.empty()) {
                diag("stderr: %s", s_stderr.c_str());
            }
        }

        // Write process output to log file
        try {
            std::ofstream os_logfile { test_log_file, std::ios::out };
            os_logfile << s_stderr;
        } catch (const std::exception& ex) {
            fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, ex.what());
        }

        err_code = w_res;
    }, std::ref(proxy_pid));

    launch_proxy.detach();

    // Wait for startup
    diag("  Waiting for ProxySQL to start (3 seconds)...");
    sleep(3);
    diag("  ProxySQL startup wait completed");

    return EXIT_SUCCESS;
}

bool check_port_listening(int port, int timeout = 2) {
    for (int i = 0; i < timeout; i++) {
        string cmd = "nc -z 127.0.0.1 " + std::to_string(port) + " 2>/dev/null";
        int result = system(cmd.c_str());
        diag("DEBUG: nc -z 127.0.0.1 %d returned %d", port, result);
        if (result == 0) {
            diag("DEBUG: Port %d is listening", port);
            return true;
        } else if (result != 0 && i == 0) {
            // Check if nc command exists (only on first attempt to avoid spam)
            string check_cmd = "which nc >/dev/null 2>&1";
            if (system(check_cmd.c_str()) != 0) {
                diag("ERROR: 'nc' (netcat) command not found. Please install netcat to run this test.");
                diag("On Ubuntu/Debian: sudo apt-get install netcat-openbsd");
                diag("On CentOS/RHEL: sudo yum install nc");
                diag("On Fedora: sudo dnf install nmap-ncat");
                exit(EXIT_FAILURE);
            }
            diag("DEBUG: Port %d is NOT listening (result=%d)", port, result);
        }
        sleep(1);
    }
    diag("DEBUG: Port %d timeout completed, returning false", port);
    return false;
}

int run_test_case(const TestCase& test_case, const CommandLine& cl) {
    int proxy_pid = -1;
    int result = EXIT_SUCCESS;

    diag("Running test case: %s", test_case.name.c_str());
    diag("  Expected MySQL admin: %s (port %d)",
         test_case.mysql_admin_expected ? "YES" : "NO", test_case.mysql_admin_port);
    diag("  Expected PgSQL admin: %s (port %d)",
         test_case.pgsql_admin_expected ? "YES" : "NO", test_case.pgsql_admin_port);
    diag("  Expected MySQL worker: %s (port %d)",
         test_case.mysql_worker_expected ? "YES" : "NO", test_case.mysql_worker_port);
    diag("  Expected PgSQL worker: %s (port %d)",
         test_case.pgsql_worker_expected ? "YES" : "NO", test_case.pgsql_worker_port);

    // Display CLI arguments if any
    if (!test_case.cli_args.empty()) {
        diag("  CLI arguments:");
        for (size_t i = 0; i < test_case.cli_args.size(); i++) {
            diag("    %s", test_case.cli_args[i]);
        }
    }

    // CLEANUP FIRST: Kill any existing ProxySQL processes that might be listening on our ports
    diag("  Pre-test cleanup: killing any existing ProxySQL processes on test ports...");
    string cleanup_mysql_admin = "fuser -k " + std::to_string(test_case.mysql_admin_port) + "/tcp 2>/dev/null || true";
    string cleanup_pgsql_admin = "fuser -k " + std::to_string(test_case.pgsql_admin_port) + "/tcp 2>/dev/null || true";
    string cleanup_mysql_worker = "fuser -k " + std::to_string(test_case.mysql_worker_port) + "/tcp 2>/dev/null || true";
    string cleanup_pgsql_worker = "fuser -k " + std::to_string(test_case.pgsql_worker_port) + "/tcp 2>/dev/null || true";

    int result1 = system(cleanup_mysql_admin.c_str());
    int result2 = system(cleanup_pgsql_admin.c_str());
    int result3 = system(cleanup_mysql_worker.c_str());
    int result4 = system(cleanup_pgsql_worker.c_str());
    (void)result1; (void)result2; (void)result3; (void)result4; // Suppress unused warnings

    // Also kill any remaining ProxySQL processes from previous test cases
    string kill_all_cmd = "pkill -f \"proxysql.*reg_test_4960_node_\" 2>/dev/null || true";
    int kill_result = system(kill_all_cmd.c_str());
    (void)kill_result; // Suppress unused warning
    sleep(2);  // Give time for cleanup to complete

    diag("  Pre-test cleanup completed");

    // Launch ProxySQL instance
    if (launch_proxysql_instance(test_case, cl, proxy_pid) != EXIT_SUCCESS) {
        diag("Failed to launch ProxySQL for test case: %s", test_case.name.c_str());
        return EXIT_FAILURE;
    }

    diag("  Checking admin and worker interfaces...");

    // Check if admin interfaces are listening as expected
    if (test_case.mysql_admin_expected) {
        diag("  Checking MySQL admin interface on port %d (should be listening)...", test_case.mysql_admin_port);
        if (!check_port_listening(test_case.mysql_admin_port)) {
            diag("  ❌ MySQL admin interface NOT listening on port %d for test: %s",
                 test_case.mysql_admin_port, test_case.name.c_str());
            result = EXIT_FAILURE;
        } else {
            diag("  ✅ MySQL admin interface IS listening on port %d", test_case.mysql_admin_port);
        }
    } else {
        diag("  Checking MySQL admin interface on port %d (should NOT be listening)...", test_case.mysql_admin_port);
        if (check_port_listening(test_case.mysql_admin_port, 1)) {
            diag("  ❌ MySQL admin interface unexpectedly listening on port %d for test: %s",
                 test_case.mysql_admin_port, test_case.name.c_str());
            result = EXIT_FAILURE;
        } else {
            diag("  ✅ MySQL admin interface correctly NOT listening on port %d", test_case.mysql_admin_port);
        }
    }

    if (test_case.pgsql_admin_expected) {
        diag("  Checking PgSQL admin interface on port %d (should be listening)...", test_case.pgsql_admin_port);
        if (!check_port_listening(test_case.pgsql_admin_port)) {
            diag("  ❌ PgSQL admin interface NOT listening on port %d for test: %s",
                 test_case.pgsql_admin_port, test_case.name.c_str());
            result = EXIT_FAILURE;
        } else {
            diag("  ✅ PgSQL admin interface IS listening on port %d", test_case.pgsql_admin_port);
        }
    } else {
        diag("  Checking PgSQL admin interface on port %d (should NOT be listening)...", test_case.pgsql_admin_port);
        if (check_port_listening(test_case.pgsql_admin_port, 1)) {
            diag("  ❌ PgSQL admin interface unexpectedly listening on port %d for test: %s",
                 test_case.pgsql_admin_port, test_case.name.c_str());
            result = EXIT_FAILURE;
        } else {
            diag("  ✅ PgSQL admin interface correctly NOT listening on port %d", test_case.pgsql_admin_port);
        }
    }

    // Check if worker interfaces are listening as expected
    if (test_case.mysql_worker_expected) {
        diag("  Checking MySQL worker interface on port %d (should be listening)...", test_case.mysql_worker_port);
        if (!check_port_listening(test_case.mysql_worker_port)) {
            diag("  ❌ MySQL worker interface NOT listening on port %d for test: %s",
                 test_case.mysql_worker_port, test_case.name.c_str());
            result = EXIT_FAILURE;
        } else {
            diag("  ✅ MySQL worker interface IS listening on port %d", test_case.mysql_worker_port);
        }
    } else {
        diag("  Checking MySQL worker interface on port %d (should NOT be listening)...", test_case.mysql_worker_port);
        if (check_port_listening(test_case.mysql_worker_port, 1)) {
            diag("  ❌ MySQL worker interface unexpectedly listening on port %d for test: %s",
                 test_case.mysql_worker_port, test_case.name.c_str());
            result = EXIT_FAILURE;
        } else {
            diag("  ✅ MySQL worker interface correctly NOT listening on port %d", test_case.mysql_worker_port);
        }
    }

    if (test_case.pgsql_worker_expected) {
        diag("  Checking PgSQL worker interface on port %d (should be listening)...", test_case.pgsql_worker_port);
        if (!check_port_listening(test_case.pgsql_worker_port)) {
            diag("  ❌ PgSQL worker interface NOT listening on port %d for test: %s",
                 test_case.pgsql_worker_port, test_case.name.c_str());
            result = EXIT_FAILURE;
        } else {
            diag("  ✅ PgSQL worker interface IS listening on port %d", test_case.pgsql_worker_port);
        }
    } else {
        diag("  Checking PgSQL worker interface on port %d (should NOT be listening)...", test_case.pgsql_worker_port);
        if (check_port_listening(test_case.pgsql_worker_port, 1)) {
            diag("  ❌ PgSQL worker interface unexpectedly listening on port %d for test: %s",
                 test_case.pgsql_worker_port, test_case.name.c_str());
            result = EXIT_FAILURE;
        } else {
            diag("  ✅ PgSQL worker interface correctly NOT listening on port %d", test_case.pgsql_worker_port);
        }
    }

    // Force kill any remaining ProxySQL processes to ensure cleanup
    diag("  Force killing any remaining ProxySQL processes...");
    string kill_cmd = "pkill -f \"proxysql.*" + string { cl.workdir } + "reg_test_4960_node_" + test_case.name + "\" 2>/dev/null || true";
    int force_kill_result = system(kill_cmd.c_str());
    (void)force_kill_result; // Suppress unused warning
    sleep(1);

    // Additional cleanup - kill by port if needed
    if (proxy_pid > 0) {
        diag("  Ensuring ProxySQL (PID: %d) is terminated...", proxy_pid);
        kill(proxy_pid, SIGKILL);  // Use SIGKILL to ensure termination
        sleep(1);
        int status;
        waitpid(proxy_pid, &status, WNOHANG);  // Non-blocking wait
    }

    // Additional post-test cleanup for safety
    int post_result1 = system(cleanup_mysql_admin.c_str());
    int post_result2 = system(cleanup_pgsql_admin.c_str());
    int post_result3 = system(cleanup_mysql_worker.c_str());
    int post_result4 = system(cleanup_pgsql_worker.c_str());
    (void)post_result1; (void)post_result2; (void)post_result3; (void)post_result4; // Suppress unused warnings

    diag("  Post-test cleanup completed");

    return result;
}

int main(int argc, char** argv) {
    CommandLine cl;

    const char* WORKSPACE = getenv("WORKSPACE");

    if (cl.getEnv() || WORKSPACE == nullptr) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }

    // Check for required system tools upfront
    diag("Checking for required system tools...");
    int nc_check_result = system("which nc >/dev/null 2>&1");
    (void)nc_check_result; // Suppress unused result warning
    if (nc_check_result != 0) {
        diag("ERROR: 'nc' (netcat) command not found. Please install netcat to run this test.");
        diag("On Ubuntu/Debian: sudo apt-get install netcat-openbsd");
        diag("On CentOS/RHEL: sudo yum install nc");
        diag("On Fedora: sudo dnf install nmap-ncat");
        plan(0);  // Skip all tests
        return exit_status();
    }
    diag("Required tools found.");

      // Define test cases for all 16 combinations of 4 boolean variables:
    // mysql-workers, pgsql-workers, mysql-admin, pgsql-admin
    vector<TestCase> test_cases = {
        // 0000: all disabled
        {
            "0000_all_disabled",
            {"--mysql-workers", "false", "--pgsql-workers", "false", "--mysql-admin", "false", "--pgsql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_0000_all_disabled\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13750\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13751\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13752\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13753\"\n"
            "}\n",
            13750, 13751, 13752, 13753, true, false, false, false, false
        },

        // 0001: only pgsql-admin enabled
        {
            "0001_pgsql_admin_only",
            {"--mysql-workers", "false", "--pgsql-workers", "false", "--mysql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_0001_pgsql_admin_only\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13754\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13755\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13756\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13757\"\n"
            "}\n",
            13754, 13755, 13756, 13757, true, false, true, false, false
        },

        // 0010: only mysql-admin enabled
        {
            "0010_mysql_admin_only",
            {"--mysql-workers", "false", "--pgsql-workers", "false", "--pgsql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_0010_mysql_admin_only\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13758\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13759\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13760\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13761\"\n"
            "}\n",
            13758, 13759, 13760, 13761, true, true, false, false, false
        },

        // 0011: mysql-admin + pgsql-admin enabled
        {
            "0011_admin_only",
            {"--mysql-workers", "false", "--pgsql-workers", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_0011_admin_only\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13762\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13763\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13764\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13765\"\n"
            "}\n",
            13762, 13763, 13764, 13765, true, true, true, false, false
        },

        // 0100: only pgsql-workers enabled
        {
            "0100_pgsql_workers_only",
            {"--mysql-workers", "false", "--mysql-admin", "false", "--pgsql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_0100_pgsql_workers_only\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13766\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13767\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13768\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13769\"\n"
            "}\n",
            13766, 13767, 13768, 13769, true, false, false, false, true
        },

        // 0101: pgsql-workers + pgsql-admin enabled
        {
            "0101_pgsql_workers_admin",
            {"--mysql-workers", "false", "--mysql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_0101_pgsql_workers_admin\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13770\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13771\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13772\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13773\"\n"
            "}\n",
            13770, 13771, 13772, 13773, true, false, true, false, true
        },

        // 0110: pgsql-workers + mysql-admin enabled
        {
            "0110_pgsql_workers_mysql_admin",
            {"--mysql-workers", "false", "--pgsql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_0110_pgsql_workers_mysql_admin\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13774\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13775\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13776\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13777\"\n"
            "}\n",
            13774, 13775, 13776, 13777, true, true, false, false, true
        },

        // 0111: pgsql-workers + mysql-admin + pgsql-admin enabled
        {
            "0111_pgsql_workers_all_admin",
            {"--mysql-workers", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_0111_pgsql_workers_all_admin\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13778\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13779\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13780\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13781\"\n"
            "}\n",
            13778, 13779, 13780, 13781, true, true, true, false, true
        },

        // 1000: only mysql-workers enabled
        {
            "1000_mysql_workers_only",
            {"--pgsql-workers", "false", "--mysql-admin", "false", "--pgsql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_1000_mysql_workers_only\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13782\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13783\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13784\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13785\"\n"
            "}\n",
            13782, 13783, 13784, 13785, true, false, false, true, false
        },

        // 1001: mysql-workers + pgsql-admin enabled
        {
            "1001_mysql_workers_pgsql_admin",
            {"--pgsql-workers", "false", "--mysql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_1001_mysql_workers_pgsql_admin\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13786\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13787\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13788\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13789\"\n"
            "}\n",
            13786, 13787, 13788, 13789, true, false, true, true, false
        },

        // 1010: mysql-workers + mysql-admin enabled
        {
            "1010_mysql_workers_admin",
            {"--pgsql-workers", "false", "--pgsql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_1010_mysql_workers_admin\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13790\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13791\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13792\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13793\"\n"
            "}\n",
            13790, 13791, 13792, 13793, true, true, false, true, false
        },

        // 1011: mysql-workers + mysql-admin + pgsql-admin enabled
        {
            "1011_mysql_workers_all_admin",
            {"--pgsql-workers", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_1011_mysql_workers_all_admin\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13794\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13795\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13796\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13797\"\n"
            "}\n",
            13794, 13795, 13796, 13797, true, true, true, true, false
        },

        // 1100: both workers enabled, no admin
        {
            "1100_workers_only",
            {"--mysql-admin", "false", "--pgsql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_1100_workers_only\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13798\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13799\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13800\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13801\"\n"
            "}\n",
            13798, 13799, 13800, 13801, true, false, false, true, true
        },

        // 1101: both workers + pgsql-admin enabled
        {
            "1101_workers_mysql_pgsql_admin",
            {"--mysql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_1101_workers_mysql_pgsql_admin\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13802\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13803\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13804\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13805\"\n"
            "}\n",
            13802, 13803, 13804, 13805, true, false, true, true, true
        },

        // 1110: both workers + mysql-admin enabled
        {
            "1110_workers_mysql_admin",
            {"--pgsql-admin", "false"},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_1110_workers_mysql_admin\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13806\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13807\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13808\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13809\"\n"
            "}\n",
            13806, 13807, 13808, 13809, true, true, false, true, true
        },

        // 1111: all enabled (default)
        {
            "1111_all_enabled",
            {},
            string { "datadir=\"" } + cl.workdir + "reg_test_4960_node_1111_all_enabled\"\n\n"
            "admin_variables=\n"
            "{\n"
            "    admin_credentials=\"admin:admin\"\n"
            "    mysql_ifaces=\"127.0.0.1:13810\"\n"
            "    pgsql_ifaces=\"127.0.0.1:13811\"\n"
            "}\n\n"
            "mysql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13812\"\n"
            "}\n\n"
            "pgsql_variables=\n"
            "{\n"
            "    interfaces=\"127.0.0.1:13813\"\n"
            "}\n",
            13810, 13811, 13812, 13813, true, true, true, true, true
        }
    };

    plan(test_cases.size());

    // Run all test cases
    for (const auto& test_case : test_cases) {
        diag("============================================================");
        int result = run_test_case(test_case, cl);
        ok(result == EXIT_SUCCESS, "Test case '%s' %s", test_case.name.c_str(),
           result == EXIT_SUCCESS ? "passed" : "failed");
    }
    diag("============================================================");

    return exit_status();
}