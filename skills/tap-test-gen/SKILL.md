---
name: tap-test-gen
description: |
  TAP test development for ProxySQL. Triggers on requests to: write new unit or
  integration tests, add tests to CI groups, fix failing TAP tests, or understand
  test infrastructure. Provides templates, workflows, and CI registration guidance
  for the test/tap/tests/ directory.
---

# ProxySQL TAP Test Generation

## 1. Overview

ProxySQL uses the TAP (Test Anything Protocol) framework for testing. All tests reside in `test/tap/tests/`.

**Test Types:**
- **Unit tests**: Prefix `unit-*-t.cpp` - Test isolated functions, no external dependencies
- **Integration tests**: Regular naming `*-t.cpp` - Test ProxySQL runtime behavior with connections

**Key TAP Functions:**
- `plan(N)` - Declare number of tests
- `ok(condition, "message", ...)` - Report test result
- `diag("message", ...)` - Print diagnostic info
- `exit_status()` - Return appropriate exit code

## 2. Decision: Unit vs Integration

```
Is the code under test a pure function with no side effects?
├── YES → Unit Test
│   Examples: string parsing, data structures, query transformation
│   File: unit-{function_name}-t.cpp
│   Group: unit-tests-g1
│
└── NO → Integration Test
    Examples: query routing, connection pooling, firewall rules, cluster sync
    File: {feature_name}-t.cpp or test_{feature_name}-t.cpp
    Group: default-g1 (or version-specific groups)
```

## 3. Unit Test Workflow

### 3.1 File Structure

```cpp
#include <stdlib.h>
#include "tap.h"
#include "unit_test.h"
#include "header_with_function.h"  // Header containing function to test

using std::string;
using std::vector;

// Define test case structure
struct TestCase {
    const char* name;
    // Input arguments
    const char* input;
    // Expected output
    const char* expected;
};

int main(int argc, char** argv) {
    TestCase test_table[] = {
        {"Test case name", "input", "expected"},
        // ... more test cases
    };

    int num_tests = sizeof(test_table) / sizeof(test_table[0]);
    plan(num_tests);

    for (int i = 0; i < num_tests; i++) {
        TestCase& tc = test_table[i];
        auto result = function_under_test(tc.input);
        ok(result == tc.expected, "%s: got '%s'", tc.name, result.c_str());
    }

    return exit_status();
}
```

### 3.2 Best Practices

1. **Use table-driven testing** for multiple input/output combinations
2. **Test edge cases**: NULL, empty strings, boundary conditions
3. **Keep tests independent**: No state dependencies between test cases
4. **Descriptive names**: Include what's being tested in the name

## 4. Integration Test Workflow

### 4.1 File Structure

```cpp
#include <string>
#include <vector>
#include <cstdio>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
    // 1. Declare test count
    plan(N);

    // 2. Get environment configuration
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get environment variables");
        return exit_status();
    }

    // 3. Establish admin connection
    MYSQL* admin = mysql_init(NULL);
    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, 
                            NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection failed: %s", mysql_error(admin));
        return exit_status();
    }

    // 4. Establish client connection
    MYSQL* client = mysql_init(NULL);
    if (!mysql_real_connect(client, cl.host, cl.username, cl.password, 
                            NULL, cl.port, NULL, 0)) {
        diag("Client connection failed: %s", mysql_error(client));
        mysql_close(admin);
        return exit_status();
    }

    // 5. ARRANGE: Clean state and configure
    MYSQL_QUERY(admin, "DELETE FROM mysql_query_rules WHERE rule_id >= 900");
    MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

    // 6. ACT: Execute operations
    int rc = mysql_query(client, "SELECT 1");

    // 7. ASSERT: Verify outcomes
    ok(rc == 0, "Query should succeed");

    // Verify via stats tables
    MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_query_digest WHERE digest_text LIKE '%SELECT 1%'");
    MYSQL_RES* res = mysql_store_result(admin);
    ok(res && mysql_num_rows(res) > 0, "Query should appear in digest");
    mysql_free_result(res);

    // 8. CLEANUP: Restore state
    MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES FROM DISK");
    MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

    // 9. Close connections
    mysql_close(admin);
    mysql_close(client);

    return exit_status();
}
```

### 4.2 PostgreSQL Tests

For PostgreSQL tests, use `libpq`:

```cpp
#include "libpq-fe.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
    plan(N);

    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get environment variables");
        return exit_status();
    }

    // Connect to PostgreSQL via ProxySQL
    char conninfo[256];
    snprintf(conninfo, sizeof(conninfo), 
             "host=%s port=%d user=%s password=%s dbname=postgres",
             cl.host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password);
    
    PGconn* conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("Connection failed: %s", PQerrorMessage(conn));
        return exit_status();
    }

    // Execute queries
    PGresult* res = PQexec(conn, "SELECT 1");
    ok(PQresultStatus(res) == PGRES_TUPLES_OK, "Query should succeed");
    PQclear(res);

    PQfinish(conn);
    return exit_status();
}
```

## 5. CI Registration

**Every test MUST be registered in `test/tap/groups/groups.json`** - unregistered tests cause CI failure.

### 5.1 Adding a Test

**Unit test:**
```json
{
  "unit-your_function-t": ["unit-tests-g1"]
}
```

**Integration test (basic):**
```json
{
  "test_your_feature-t": ["default-g1"]
}
```

**Integration test (multiple configurations):**
```json
{
  "test_your_feature-t": [
    "default-g1",
    "mysql-multiplexing=false-g1",
    "mysql84-g1",
    "mysql90-g1"
  ]
}
```

### 5.2 Group Selection Guide

| Test Type | Recommended Groups |
|-----------|-------------------|
| Unit test (no infra) | `unit-tests-g1` |
| Basic integration | `default-g1` |
| MySQL version-specific | `mysql84-g1`, `mysql90-g1`, etc. |
| PostgreSQL | `default-g1` (pgsql infra included) |
| Configuration-sensitive | Add relevant `mysql-{setting}=value-g1` groups |

**Parallel groups (`-g1` to `-g4`):** Distribute tests across groups for CI load balancing. New tests can go in any `-g1` group; maintainers rebalance periodically.

## 6. Debugging Test Failures

| Issue Type | Examples | Reference |
|------------|----------|-----------|
| Test code | plan mismatch, missing cleanup, test dependencies | [tap_test_guide.md](references/tap_test_guide.md) Section 8 |
| Group registration | CI failure from unregistered test, wrong group | [tap_test_groups.md](references/tap_test_groups.md) Section 8 |
| CI infrastructure | passes locally but fails in CI, finding logs | [tap_test_infra.md](references/tap_test_infra.md) Section 7 |

## 7. Reference Navigation

Reference files in `references/` are symlinked to `doc/tap/` for single-source maintenance.

| Need | Read |
|------|------|
| TAP API details, full examples | [tap_test_guide.md](references/tap_test_guide.md) |
| CI test runner, execution flow, infrastructure types | [tap_test_infra.md](references/tap_test_infra.md) |
| Group hooks, filtering, creating new groups | [tap_test_groups.md](references/tap_test_groups.md) |

## 8. Pre-Commit Checklist

Before committing a new test:

- [ ] `plan(N)` matches the number of `ok()` calls
- [ ] Test cleans up after itself (restores config from disk)
- [ ] Test is registered in `test/tap/groups/groups.json`
- [ ] Test compiles: `make build_tap_tests` or `make build_tap_tests_debug`
- [ ] Test runs locally (for unit tests)
- [ ] Meaningful test descriptions in `ok()` calls
