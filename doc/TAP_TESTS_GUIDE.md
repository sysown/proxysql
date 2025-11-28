# How to Write TAP Tests for ProxySQL

This guide provides instructions and best practices for writing Test Anything Protocol (TAP) tests for ProxySQL. The tests are written in C++ and leverage a common framework to interact with ProxySQL instances, check for expected behavior, and report results.

## Anatomy of a TAP Test File

A typical TAP test file (`*-t.cpp`) has the following structure:

1.  **Includes:** Essential headers are included.
    *   `"tap.h"`: The core TAP library for test reporting (`plan`, `ok`, `diag`, `exit_status`).
    *   `"command_line.h"`: A helper for reading connection parameters (host, port, user, password) from environment variables.
    *   `"utils.h"`: Provides various utility functions and macros, like `MYSQL_QUERY`.
    *   Protocol-specific headers: `"mysql.h"` for MySQL or `"libpq-fe.h"` for PostgreSQL tests.
    *   Standard C++ libraries (`<string>`, `<vector>`, `<chrono>`, etc.).

2.  **`main()` Function:** The entry point for the test.
    *   **`plan(N)`:** The first thing you should do is declare how many tests you plan to run. `N` is the total number of `ok()` calls in your test. This can be calculated dynamically if the number of tests depends on other factors.
    *   **`CommandLine cl;`:** An object to manage command-line and environment variables. `cl.getEnv()` reads the necessary configuration.
    *   **Connections:** Establish one or more connections to ProxySQL. Typically, you need at least two:
        *   An **admin connection** to configure ProxySQL, load settings, and check statistics tables.
        *   A **client connection** to the standard proxy port to simulate application behavior.
    *   **Setup (Arrange):** Prepare the test environment. This is a critical step to ensure your test is isolated and predictable. Common setup tasks include:
        *   Deleting existing rules or data from previous test runs (e.g., `DELETE FROM mysql_query_rules`).
        *   Setting global variables (`UPDATE global_variables SET ...`).
        *   Inserting new configuration (e.g., `INSERT INTO mysql_users ...`).
        *   Loading the new configuration into the running ProxySQL instance (e.g., `LOAD MYSQL USERS TO RUNTIME`).
    *   **Execution (Act):** Perform the actions you want to test. This could be running a specific query, killing a connection, or triggering a cluster sync.
    *   **Verification (Assert):** Check that the outcome of the action is what you expected. This is done using the `ok()` macro.
        *   `ok(condition, "description of the test");`
        *   The `condition` is a boolean expression. If true, the test passes. If false, it fails.
        *   The description should clearly state what is being tested.
    *   **`diag("message")`:** Print diagnostic messages to stderr. This is useful for showing the test's progress or debugging failures. These messages are not counted as test results.
    *   **Cleanup:** Restore the original state if necessary (e.g., `LOAD MYSQL VARIABLES FROM DISK`).
    *   **`return exit_status();`:** Finally, return the overall test status. The test runner uses this exit code.

## Key Principles for Good Tests

### 1. Be Isolated and Self-Contained

A test should not depend on the state left behind by other tests.

*   **GOOD:** Start by deleting any existing configuration relevant to your test.
    ```cpp
    // test_firewall-t.cpp
    MYSQL_QUERY(mysqladmin, "delete from mysql_firewall_whitelist_users");
    MYSQL_QUERY(mysqladmin, "delete from mysql_firewall_whitelist_rules");
    MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");
    ```
*   **GOOD:** If you modify global variables, reload them from disk at the end of the test.
    ```cpp
    // test_firewall-t.cpp
    MYSQL_QUERY(mysqladmin, "load mysql variables from disk");
    MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");
    ```

### 2. Verify State Through the Admin Interface

The most reliable way to check ProxySQL's internal state is by querying the `stats` and `runtime` tables.

*   **GOOD:** To check if a connection was created, query `stats_mysql_connection_pool`.
    ```cpp
    // test_connection_annotation-t.cpp
    MYSQL_QUERY(proxysql_admin, "SELECT ConnUsed, ConnFree FROM stats.stats_mysql_connection_pool WHERE hostgroup=1");
    // ... compare results before and after
    ```
*   **GOOD:** To check if a query hit the cache, query `stats_mysql_query_digest`.
    ```cpp
    // test_query_cache_soft_ttl_pct-t.cpp
    const string STATS_QUERY_DIGEST =
    	"SELECT hostgroup, SUM(count_star) FROM stats_mysql_query_digest "
    	"WHERE digest_text = 'SELECT SLEEP(?)' GROUP BY hostgroup";
    ```

### 3. Handle Asynchronicity

Many operations in ProxySQL are asynchronous (e.g., connection killing, cluster synchronization). Your test must account for this.

*   **GOOD:** Use a polling loop with a timeout to wait for a condition to become true. This is more robust than a fixed `sleep()`.
    ```cpp
    // test_cluster1-t.cpp
    int module_in_sync(...) {
        while (i < num_retries && rc != 1) {
            // ... query stats_proxysql_servers_checksums and check if all nodes have the same checksum ...
            sleep(1);
            i++;
        }
        return (rc == 1 ? 0 : 1); // Return 0 on success
    }
    ```
*   **ACCEPTABLE:** For simple cases where an action is expected to be fast, a short `sleep()` can be used.
    ```cpp
    // kill_connection-t.cpp
    std::string s = "KILL CONNECTION " + std::to_string(mythreadid[j]);
    MYSQL_QUERY(mysql, s.c_str());
    sleep(1); // Give ProxySQL a moment to process the kill
    int rc = run_q(other_mysql_conn, "DO 1");
    ok(rc != 0, "Connection should be killed");
    ```

### 4. Use Helper Functions and Macros

For complex or repetitive tasks, use helpers to make your test more readable and maintainable.

*   **GOOD:** The `test_cluster1-t.cpp` test defines `trigger_sync_and_check` to encapsulate the entire logic for testing one module's synchronization.
*   **GOOD:** The `pgsql-basic_tests-t.cpp` test defines a `PQEXEC` macro to wrap `PQexec` and add error checking, reducing boilerplate.

### 5. Structure Complex Tests Clearly

For features that require multiple steps or scenarios (like the REST API or PostgreSQL protocol tests), break the test into smaller functions.

*   **GOOD:** The `pgsql-basic_tests-t.cpp` has separate functions like `test_simple_query`, `test_insert_query`, `test_transaction_commit`, etc. This makes it easy to see what is being tested and to debug failures.
*   **GOOD:** The `reg_test_3223-restapi_return_codes-t.cpp` test defines its test cases in data structures (`std::vector` of structs) and then iterates over them. This data-driven approach is excellent for testing many variations of an input.

## Example Template

Here is a basic template to get you started.

```cpp
#include <string>
#include <vector>
#include <cstdio>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
    // 1. Declare the number of tests you will run.
    plan(3);

    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return exit_status();
    }

    // 2. Establish connections.
    MYSQL* admin = mysql_init(NULL);
    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Failed to connect to admin interface: %s", mysql_error(admin));
        return exit_status();
    }

    MYSQL* client = mysql_init(NULL);
    if (!mysql_real_connect(client, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
        diag("Failed to connect to client interface: %s", mysql_error(client));
        mysql_close(admin);
        return exit_status();
    }

    // 3. Arrange: Set up the test environment.
    diag("Setting up test: creating a new query rule.");
    MYSQL_QUERY(admin, "DELETE FROM mysql_query_rules WHERE rule_id=999");
    MYSQL_QUERY(admin, "INSERT INTO mysql_query_rules (rule_id, active, match_pattern, destination_hostgroup) VALUES (999, 1, '^SELECT 123', 1)");
    MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

    // 4. Act & Assert: Run the test and verify the outcome.
    diag("Running a query that should match the rule.");
    int rc = mysql_query(client, "SELECT 123");
    ok(rc == 0, "Query 'SELECT 123' should execute successfully.");

    // Verify state via statistics
    MYSQL_QUERY(admin, "SELECT hits FROM stats_mysql_query_rules WHERE rule_id=999");
    MYSQL_RES* res = mysql_store_result(admin);
    ok(res && mysql_num_rows(res) == 1, "Rule 999 should exist in stats.");
    if (res && mysql_num_rows(res) == 1) {
        MYSQL_ROW row = mysql_fetch_row(res);
        ok(atoi(row[0]) == 1, "Rule 999 should have exactly 1 hit.");
    }
    mysql_free_result(res);


    // 5. Cleanup
    diag("Cleaning up test rule.");
    MYSQL_QUERY(admin, "DELETE FROM mysql_query_rules WHERE rule_id=999");
    MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");


    // 6. Close connections and exit.
    mysql_close(admin);
    mysql_close(client);

    return exit_status();
}
```
