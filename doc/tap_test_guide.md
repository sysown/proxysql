# ProxySQL TAP Test

This guide explains how to write tests for ProxySQL using the TAP (Test Anything Protocol) framework.

## 1. Overview

ProxySQL uses the TAP framework for both unit and integration tests. All tests reside in the `test/tap/tests/` directory. Tests are distinguished by their naming convention:

- **Unit tests**: Prefixed with `unit-` (e.g., `unit-strip_schema_from_query-t.cpp`)
- **Integration tests**: Regular naming (e.g., `admin-listen_on_unix-t.cpp`, `test_firewall-t.cpp`)

This naming convention helps identify the test type at a glance and allows for easy filtering when running specific test suites.

## 2. TAP Framework Basics

### 2.1 What is TAP?

TAP (Test Anything Protocol) is a simple text-based interface between testing modules and test harnesses. It provides a standardized way to communicate test results, making it language-agnostic and easy to integrate with various testing tools.

### 2.2 Key TAP Functions

#### `plan(int count)`
Declares how many tests you plan to run. This should be called once at the beginning of your test.

```cpp
plan(15);  // Planning to run 15 tests
```

#### `ok(int pass, const char *fmt, ...)`
Reports a test result. The first argument is the pass/fail condition, followed by a printf-style message.

```cpp
ok(result == expected, "Test description: %s", details);
```

#### `diag(const char *fmt, ...)`
Prints diagnostic messages to stderr that don't count as tests. Useful for debugging and showing test progress.

```cpp
diag("Debug info: value = %d", value);
```

#### `skip(int how_many, const char *reason, ...)`
Skips a specified number of tests with a reason.

```cpp
if (!feature_available) {
    skip(3, "Feature not available in this build");
}
```

#### `exit_status(void)`
Returns the appropriate exit code based on test results. Should be called at the end of your main function.

```cpp
return exit_status();
```

### 2.3 Understanding TAP Output

```
1..15
ok 1 - Basic schema stripping: 'SELECT * FROM stats_mysql_query_digest'
ok 2 - Multiple schema references stripped
not ok 3 - Edge case handling
# Diagnostic message explaining failure
ok 4 - NULL input handled safely
...
ok 15 - Case insensitive schema match
```

- `1..N`: Test plan (N tests expected)
- `ok N - description`: Test N passed
- `not ok N - description`: Test N failed
- Lines starting with `#`: Diagnostic messages

### 2.4 Exit Codes

- `0`: All tests passed
- `1`: One or more tests failed
- `255`: Test suite bailed out (critical failure)

## 3. Unit Testing

Unit tests verify isolated functions without external dependencies. They test pure logic, data structures, and algorithms.

### 3.1 File Structure

```cpp
#include <stdlib.h>
#include "tap.h"
#include "unit_test.h"       // Common unit test header
#include "gen_utils.h"       // Header with function to test
// ... other project headers as needed

using std::string;
// ... other using declarations

int main(int argc, char** argv) {
    plan(N);  // N = number of tests
    
    // Define and execute tests
    
    return exit_status();
}
```

### 3.2 Best Practices

1. **Use table-driven testing** when testing the same function with multiple input/output combinations
2. **Descriptive test names**: Include meaningful descriptions in test case names and `ok()` calls
3. **Test edge cases**: Cover NULL inputs, empty strings, boundary conditions
4. **Test normal cases**: Verify expected behavior with typical inputs
5. **Test error cases**: Ensure functions handle invalid inputs gracefully
6. **Keep tests independent**: Each test should not depend on the state from previous tests

### 3.3 Example Template

Here's a complete example using table-driven testing:

```cpp
#include <stdlib.h>
#include "tap.h"
#include "unit_test.h"
#include "gen_utils.h"

using std::string;
using std::vector;

struct Args {
    const char* query;
    const char* schema;
    vector<string> tables;
    bool ansi_quotes = false;
};

struct TestCase {
    const char* name;
    Args args;
    const char* expected;
};

int main(int argc, char** argv) {
    TestCase test_table[] = {
        {
            "Basic schema stripping",
            {
                "SELECT * FROM stats.stats_mysql_query_digest",
                "stats",
            },
            "SELECT * FROM stats_mysql_query_digest",
        },
        {
            "Quoted identifiers",
            {
                "SELECT * FROM `stats`.`table1`",
                "stats",
            },
            "SELECT * FROM `table1`",
        },
        {
            "NULL query handled safely",
            {
                nullptr,
                "stats",
            },
            "",
        },
        {
            "String literals preserved",
            {
                "SELECT * FROM stats.t WHERE x='stats.y'",
                "stats",
            },
            "SELECT * FROM t WHERE x='stats.y'",
        },
    };

    int num_tests = sizeof(test_table) / sizeof(test_table[0]);
    plan(num_tests);

    for (int i = 0; i < num_tests; i++) {
        TestCase& tc = test_table[i];
        string result = strip_schema_from_query(tc.args.query, tc.args.schema, tc.args.tables, tc.args.ansi_quotes);
        ok(result == tc.expected, "%s: '%s'", tc.name, result.c_str());
    }

    return exit_status();
}
```

## 4. Integration Testing

Integration tests verify ProxySQL's runtime behavior by interacting with running instances. They test features like query routing, connection pooling, firewall rules, and cluster synchronization.

### 4.1 File Structure

A typical integration test file has the following structure:

1. **Includes:** Essential headers
    * `"tap.h"`: The core TAP library for test reporting
    * `"command_line.h"`: Helper for reading connection parameters from environment variables
    * `"utils.h"`: Provides utility functions and macros like `MYSQL_QUERY`
    * Protocol-specific headers: `"mysql.h"` for MySQL or `"libpq-fe.h"` for PostgreSQL tests
    * Standard C++ libraries (`<string>`, `<vector>`, `<chrono>`, etc.)

2. **`main()` Function:** The entry point for the test
    * **`plan(N)`:** Declare how many tests you plan to run. `N` is the total number of `ok()` calls
    * **`CommandLine cl;`:** Object to manage command-line and environment variables. `cl.getEnv()` reads the necessary configuration
    * **Connections:** Establish connections to ProxySQL:
        * An **admin connection** to configure ProxySQL, load settings, and check statistics tables
        * A **client connection** to the standard proxy port to simulate application behavior
    * **Setup (Arrange):** Prepare the test environment for isolation and predictability
    * **Execution (Act):** Perform the actions you want to test
    * **Verification (Assert):** Check that the outcome matches expectations using `ok()`
    * **Cleanup:** Restore the original state if necessary
    * **`return exit_status();`:** Return the overall test status

### 4.2 Best Practices

#### 4.2.1 Be Isolated and Self-Contained

A test should not depend on the state left behind by other tests.

* **GOOD:** Start by deleting any existing configuration relevant to your test.
    ```cpp
    // test_firewall-t.cpp
    MYSQL_QUERY(mysqladmin, "delete from mysql_firewall_whitelist_users");
    MYSQL_QUERY(mysqladmin, "delete from mysql_firewall_whitelist_rules");
    MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");
    ```
* **GOOD:** If you modify global variables, reload them from disk at the end of the test.
    ```cpp
    // test_firewall-t.cpp
    MYSQL_QUERY(mysqladmin, "load mysql variables from disk");
    MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");
    ```

#### 4.2.2 Verify State Through the Admin Interface

The most reliable way to check ProxySQL's internal state is by querying the `stats` and `runtime` tables.

* **GOOD:** To check if a connection was created, query `stats_mysql_connection_pool`.
    ```cpp
    // test_connection_annotation-t.cpp
    MYSQL_QUERY(proxysql_admin, "SELECT ConnUsed, ConnFree FROM stats.stats_mysql_connection_pool WHERE hostgroup=1");
    // ... compare results before and after
    ```
* **GOOD:** To check if a query hit the cache, query `stats_mysql_query_digest`.
    ```cpp
    // test_query_cache_soft_ttl_pct-t.cpp
    const string STATS_QUERY_DIGEST =
    	"SELECT hostgroup, SUM(count_star) FROM stats_mysql_query_digest "
    	"WHERE digest_text = 'SELECT SLEEP(?)' GROUP BY hostgroup";
    ```

#### 4.2.3 Handle Asynchronicity

Many operations in ProxySQL are asynchronous (e.g., connection killing, cluster synchronization). Your test must account for this.

* **GOOD:** Use a polling loop with a timeout to wait for a condition to become true. This is more robust than a fixed `sleep()`.
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
* **ACCEPTABLE:** For simple cases where an action is expected to be fast, a short `sleep()` can be used.
    ```cpp
    // kill_connection-t.cpp
    std::string s = "KILL CONNECTION " + std::to_string(mythreadid[j]);
    MYSQL_QUERY(mysql, s.c_str());
    sleep(1); // Give ProxySQL a moment to process the kill
    int rc = run_q(other_mysql_conn, "DO 1");
    ok(rc != 0, "Connection should be killed");
    ```

#### 4.2.4 Use Helper Functions and Macros

For complex or repetitive tasks, use helpers to make your test more readable and maintainable.

* **GOOD:** The `test_cluster1-t.cpp` test defines `trigger_sync_and_check` to encapsulate the entire logic for testing one module's synchronization.
* **GOOD:** The `pgsql-basic_tests-t.cpp` test defines a `PQEXEC` macro to wrap `PQexec` and add error checking, reducing boilerplate.

#### 4.2.5 Structure Complex Tests Clearly

For features that require multiple steps or scenarios, break the test into smaller functions.

* **GOOD:** The `pgsql-basic_tests-t.cpp` has separate functions like `test_simple_query`, `test_insert_query`, `test_transaction_commit`, etc. This makes it easy to see what is being tested and to debug failures.
* **GOOD:** The `reg_test_3223-restapi_return_codes-t.cpp` test defines its test cases in data structures (`std::vector` of structs) and then iterates over them. This table-driven approach is excellent for testing many variations of an input.

### 4.3 Example Template

Here is a basic template to get you started:

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

## 5. Building Tests

ProxySQL provides make targets for building TAP tests:

**For Release Builds:**
```sh
make build_tap_tests
```

**For Debug Builds:**
```sh
make build_tap_tests_debug
```

### 5.1 Makefile Chain

The build process flows through multiple Makefiles:

```
Makefile (root)
  └─> test/tap/Makefile
       ├─> test/tap/tap/Makefile (builds libtap.so)
       └─> test/tap/tests/Makefile (compiles test executables)
```

- **Root Makefile**: Defines `build_tap_tests` and `build_tap_tests_debug` targets
- **test/tap/Makefile**: Orchestrates building TAP library and test directories
- **test/tap/tests/Makefile**: Compiles individual test executables with proper linking

## 6. Running Tests

After building, run the test executable directly:

```sh
./test/tap/tests/unit-strip_schema_from_query-t
./test/tap/tests/test_firewall-t
```

## 7. Test Group Management (CI Run)

All TAP tests must be registered in `test/tap/groups/groups.json` to be executed in CI. This requirement applies to both unit tests and integration tests.

### 7.1 Understanding Test Groups

The CI system uses `groups.json` to:
- Track which tests exist and should be executed
- Organize tests into logical groups for parallel execution
- Enable selective test execution based on infrastructure requirements

For example:

- `default-g1`, `default-g2`, `default-g3`: Multiple instances running integration tests in parallel
- `mysql84-g1`, `mysql90-g1`, `mysql-multiplexing=false-g1`: Infrastructures with different MySQL versions and ProxySQL configuration.
- `unit-tests-g1`: Self-contained unit tests that don't require external infrastructure

The `-g1`, `-g2`, `-g3` suffixes represent different parallel execution instances. They share the same base infrastructure configuration but run independently to speed up CI execution.

**Important:** If you add a new test but don't register it in `groups.json`, **this will cause CI failure**.

### 7.2 Adding a Test

For unit tests that don't require external infrastructure:

```json
{
  "unit-your_function_name-t": ["unit-tests-g1"]
}
```

For integration tests that require a running ProxySQL instance and backend databases:

```json
{
  "test_your_feature-t": ["default-g1"]
}
```

If you are new to this project, you can assign tests to any of the default groups (`default-g1`, `default-g2`, `default-g3`, etc.). The distribution does not need to be perfectly balanced—the CI system will handle the workload. Additionally, ProxySQL maintainers periodically rearrange tests and improve group balance.

## 8. Common Pitfalls

1. **Forgetting to call `plan()`**: Always declare your test count. For table-driven tests, use `plan(num_tests)` where `num_tests` is the size of the test table
2. **Mismatched test count**: Ensure `plan(N)` matches actual number of `ok()` calls
3. **Not calling `exit_status()`**: Always return `exit_status()` from main
4. **Test dependencies**: Keep tests independent; don't rely on execution order
5. **Missing diagnostic information**: Use `diag()` to add context when debugging test failures
6. **Integration tests only**: Forgetting to clean up state, leaving ProxySQL in a modified configuration

## 9. Unit vs Integration

| Aspect | Unit Test | Integration Test |
|--------|-----------|------------------|
| **Purpose** | Test isolated functions/logic | Test ProxySQL runtime behavior |
| **Dependencies** | None (pure function testing) | Requires running ProxySQL instance |
| **Use Cases** | String parsing, data structures, algorithms | Query routing, connection pooling, firewall rules |
| **File naming** | `unit-*-t.cpp` | `*-t.cpp` |
| **Includes** | `unit_test.h`, function headers | `command_line.h`, `utils.h`, `mysql.h` |
| **Connections** | No external connections | MySQL/PostgreSQL connections to ProxySQL |
| **Setup** | None or minimal | Delete/insert config, load to runtime |
| **Test pattern** | Table-driven | Arrange-Act-Assert |
| **Verification** | Direct return value comparison | Query stats tables via admin interface |
| **Cleanup** | Usually not needed | Restore config, reload from disk |
| **Examples** | `unit-strip_schema_from_query-t.cpp` | `test_firewall-t.cpp`, `test_cluster1-t.cpp` |

For more examples, examine existing tests in the `test/tap/tests/` directory.
