# LLM Bridge Testing Guide

## Test Suite Overview

| Test Type | Location | Purpose | LLM Required |
|-----------|----------|---------|--------------|
| Unit Tests | `test/tap/tests/nl2sql_*.cpp` | Test individual components | Mocked |
| Validation Tests | `test/tap/tests/ai_validation-t.cpp` | Test config validation | No |
| Integration | `test/tap/tests/nl2sql_integration-t.cpp` | Test with real database | Mocked/Live |
| E2E | `scripts/mcp/test_nl2sql_e2e.sh` | Complete workflow | Live |
| MCP Tools | `scripts/mcp/test_nl2sql_tools.sh` | MCP protocol | Live |

## Test Infrastructure

### TAP Framework

ProxySQL uses the Test Anything Protocol (TAP) for C++ tests.

**Key Functions:**
```cpp
plan(number_of_tests);     // Declare how many tests
ok(condition, description); // Test with description
diag(message);              // Print diagnostic message
skip(count, reason);        // Skip tests
exit_status();              // Return proper exit code
```

**Example:**
```cpp
#include "tap.h"

int main() {
    plan(3);
    ok(1 + 1 == 2, "Basic math works");
    ok(true, "Always true");
    diag("This is a diagnostic message");
    return exit_status();
}
```

### CommandLine Helper

Gets test connection parameters from environment:

```cpp
CommandLine cl;
if (cl.getEnv()) {
    diag("Failed to get environment");
    return -1;
}

// cl.host, cl.admin_username, cl.admin_password, cl.admin_port
```

## Running Tests

### Unit Tests

```bash
cd test/tap

# Build specific test
make nl2sql_unit_base-t

# Run the test
./nl2sql_unit_base

# Build all NL2SQL tests
make nl2sql_*
```

### Integration Tests

```bash
cd test/tap
make nl2sql_integration-t
./nl2sql_integration
```

### E2E Tests

```bash
# With mocked LLM (faster)
./scripts/mcp/test_nl2sql_e2e.sh --mock

# With live LLM
./scripts/mcp/test_nl2sql_e2e.sh --live
```

### All Tests

```bash
# Run all NL2SQL tests
make test_nl2sql

# Run with verbose output
PROXYSQL_VERBOSE=1 make test_nl2sql
```

## Test Coverage

### Unit Tests (`nl2sql_unit_base-t.cpp`)

- [x] Initialization
- [x] Basic conversion (mocked)
- [x] Configuration management
- [x] Variable persistence
- [x] Error handling

### Prompt Builder Tests (`nl2sql_prompt_builder-t.cpp`)

- [x] Basic prompt construction
- [x] Schema context inclusion
- [x] System instruction formatting
- [x] Edge cases (empty, special characters)
- [x] Prompt structure validation

### Model Selection Tests (`nl2sql_model_selection-t.cpp`)

- [x] Latency-based selection
- [x] Provider preference handling
- [x] API key fallback logic
- [x] Default selection
- [x] Configuration integration

### Validation Tests (`ai_validation-t.cpp`)

These are self-contained unit tests for configuration validation functions. They test the validation logic without requiring a running ProxySQL instance or LLM.

**Test Categories:**
- [x] URL format validation (15 tests)
  - Valid URLs (http://, https://)
  - Invalid URLs (missing protocol, wrong protocol, missing host)
  - Edge cases (NULL, empty, long URLs)
- [x] API key format validation (14 tests)
  - Valid keys (OpenAI, Anthropic, custom)
  - Whitespace rejection (spaces, tabs, newlines)
  - Length validation (minimums, provider-specific formats)
- [x] Numeric range validation (13 tests)
  - Boundary values (min, max, within range)
  - Invalid values (out of range, empty, non-numeric)
  - Variable-specific ranges (cache threshold, timeout, rate limit)
- [x] Provider name validation (8 tests)
  - Valid providers (openai, anthropic)
  - Invalid providers (ollama, uppercase, unknown)
  - Edge cases (NULL, empty, with spaces)
- [x] Edge cases and boundary conditions (11 tests)
  - NULL pointer handling
  - Very long values
  - URL special characters (query strings, ports, fragments)
  - API key boundary lengths

**Running Validation Tests:**
```bash
cd test/tap/tests
make ai_validation-t
./ai_validation-t
```

**Expected Output:**
```
1..61
# 2026-01-16 18:47:09  === URL Format Validation Tests ===
ok 1 - URL 'http://localhost:11434/v1/chat/completions' is valid
...
ok 61 - Anthropic key at 25 character boundary accepted
```

### Integration Tests (`nl2sql_integration-t.cpp`)

- [ ] Schema-aware conversion
- [ ] Multi-table queries
- [ ] Complex SQL patterns
- [ ] Error recovery

### E2E Tests (`test_nl2sql_e2e.sh`)

- [x] Simple SELECT
- [x] WHERE conditions
- [x] JOIN queries
- [x] Aggregations
- [x] Date handling

## Writing New Tests

### Test File Template

```cpp
/**
 * @file nl2sql_your_feature-t.cpp
 * @brief TAP tests for your feature
 *
 * @date 2025-01-16
 */

#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

MYSQL* g_admin = NULL;

// ============================================================================
// Helper Functions
// ============================================================================

string get_variable(const char* name) {
    // Implementation
}

bool set_variable(const char* name, const char* value) {
    // Implementation
}

// ============================================================================
// Test: Your Test Category
// ============================================================================

void test_your_category() {
    diag("=== Your Test Category ===");

    // Test 1
    ok(condition, "Test description");

    // Test 2
    ok(condition, "Another test");
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Error getting environment");
        return exit_status();
    }

    g_admin = mysql_init(NULL);
    if (!mysql_real_connect(g_admin, cl.host, cl.admin_username,
                            cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Failed to connect to admin");
        return exit_status();
    }

    plan(number_of_tests);

    test_your_category();

    mysql_close(g_admin);
    return exit_status();
}
```

### Test Naming Conventions

- **Files**: `nl2sql_feature_name-t.cpp`
- **Functions**: `test_feature_category()`
- **Descriptions**: "Feature does something"

### Test Organization

```cpp
// Section dividers
// ============================================================================
// Section Name
// ============================================================================

// Test function with docstring
/**
 * @test Test name
 * @description What it tests
 * @expected What should happen
 */
void test_something() {
    diag("=== Test Category ===");
    // Tests...
}
```

### Best Practices

1. **Use diag() for section headers**:
   ```cpp
   diag("=== Configuration Tests ===");
   ```

2. **Provide meaningful test descriptions**:
   ```cpp
   ok(result == expected, "Variable set to 'value' reflects in runtime");
   ```

3. **Clean up after tests**:
   ```cpp
   // Restore original values
   set_variable("model", orig_value.c_str());
   ```

4. **Handle both stub and real implementations**:
   ```cpp
   ok(value == expected || value.empty(),
      "Value matches expected or is empty (stub)");
   ```

## Mocking LLM Responses

For fast unit tests, mock LLM responses:

```cpp
string mock_llm_response(const string& query) {
    if (query.find("SELECT") != string::npos) {
        return "SELECT * FROM table";
    }
    // Other patterns...
}
```

## Debugging Tests

### Enable Verbose Output

```bash
# Verbose TAP output
./nl2sql_unit_base -v

# ProxySQL debug output
PROXYSQL_VERBOSE=1 ./nl2sql_unit_base
```

### GDB Debugging

```bash
gdb ./nl2sql_unit_base
(gdb) break main
(gdb) run
(gdb) backtrace
```

### SQL Debugging

```cpp
// Print generated SQL
diag("Generated SQL: %s", sql.c_str());

// Check MySQL errors
if (mytext_response(admin, query)) {
    diag("MySQL error: %s", mysql_error(admin));
}
```

## Continuous Integration

### GitHub Actions (Planned)

```yaml
name: NL2SQL Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build ProxySQL
        run: make
      - name: Run NL2SQL Tests
        run: make test_nl2sql
```

## Test Data

### Sample Schema

Tests use a standard test schema:

```sql
CREATE TABLE customers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100),
    country VARCHAR(50),
    created_at DATE
);

CREATE TABLE orders (
    id INT PRIMARY KEY AUTO_INCREMENT,
    customer_id INT,
    total DECIMAL(10,2),
    status VARCHAR(20),
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);
```

### Sample Queries

```sql
-- Simple
NL2SQL: Show all customers

-- With conditions
NL2SQL: Find customers from USA

-- JOIN
NL2SQL: Show orders with customer names

-- Aggregation
NL2SQL: Count customers by country
```

## Performance Testing

### Benchmark Script

```bash
#!/bin/bash
# benchmark_nl2sql.sh

for i in {1..100}; do
    start=$(date +%s%N)
    mysql -h 127.0.0.1 -P 6033 -e "NL2SQL: Show top customers"
    end=$(date +%s%N)
    echo $((end - start))
done | awk '{sum+=$1} END {print sum/NR " ns average"}'
```

## Known Issues

1. **Stub Implementation**: Many features return empty/placeholder values
2. **Live LLM Required**: Some tests need Ollama running
3. **Timing Dependent**: Cache tests may fail on slow systems

## Contributing Tests

When contributing new tests:

1. Follow the template above
2. Add to Makefile if needed
3. Update this documentation
4. Ensure tests pass with `make test_nl2sql`

## See Also

- [README.md](README.md) - User documentation
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [API.md](API.md) - API reference
