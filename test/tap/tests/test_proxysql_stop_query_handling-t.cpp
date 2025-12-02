/**
 * @file test_proxysql_stop_query_handling-t.cpp
 * @brief This test verifies PROXYSQL STOP query handling fix for issue 5186.
 *        Tests that admin queries are properly handled during STOP state.
 *        This is a wrapper around the shared test functions.
 * @date 2025-11-23
 */

#include "test_proxysql_stop_query_handling.hpp"

int main(int argc, char** argv) {
    CommandLine cl;

    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    // We expect PROXYSQL_STOP_START_TEST_COUNT test cases from the shared test function
    plan(PROXYSQL_STOP_START_TEST_COUNT);

    int result = test_proxysql_stop_start_with_connection(cl.host, cl.admin_username,
                                                        cl.admin_password, cl.admin_port);

    if (result == -1) {
        diag("Failed to connect to ProxySQL admin or critical test failure");
        return exit_status();
    }

    return exit_status();
}
