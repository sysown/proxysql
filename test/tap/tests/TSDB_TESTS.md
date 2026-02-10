# TSDB Test Suite Documentation

This document describes the comprehensive test suite for the ProxySQL TSDB (Time Series Database) subsystem.

## Test Overview

The TSDB test suite validates:
1. **Thread-safe config access** - Ensures config changes don't race with sampler/monitor threads
2. **Numeric config validation** - Prevents division by zero and invalid values
3. **NULL field handling** - Handles NULL database results gracefully
4. **Path traversal prevention** - Blocks malicious metric names from escaping data directory
5. **HTTP endpoints** - Tests `/api/tsdb/status`, `/api/tsdb/query`, `/api/tsdb/metrics`, `/ui/`
6. **Admin commands** - Tests `TSDB STATUS` and `TSDB QUERY` commands
7. **Prometheus exporter** - Validates Prometheus text format output
8. **NULL pointer prevention** - Ensures no crashes when TSDB is disabled

## Test Files

| File | Type | Description |
|------|------|-------------|
| `test/tap/tests/test_tsdb-t.cpp` | C++ Unit Test | Comprehensive unit and integration tests |
| `test/tap/tests/test_tsdb.sh` | Shell Script | Integration test script with HTTP/Admin testing |

## Quick Start

### Prerequisites

1. ProxySQL must be running with admin interface accessible
2. HTTP interface must be enabled (default port 6080)
3. MySQL client must be installed
4. curl must be installed

### Running Tests

#### Option 1: Run Shell Script Tests

```bash
# Run with default ports (admin=6032, http=6080)
./test/tap/tests/test_tsdb.sh

# Run with custom ports
./test/tap/tests/test_tsdb.sh 6032 6080
```

#### Option 2: Run C++ Unit Tests

```bash
# From project root
cd test/tap/tests
make test_tsdb
./test_tsdb # or via prove: prove test_tsdb.sh
```

### Expected Output

```
===============================================================================
  TSDB Integration Test Suite
===============================================================================

Configuration:
  Admin Port: 6032
  HTTP Port:  6080
  Admin Host: 127.0.0.1
  Data Dir:   /tmp/proxysql_tsdb_test_XXXXX

[INFO] Setting up test environment...
[INFO] Test environment ready

[INFO] === TSDB Lifecycle Tests ===
[PASS] Enable TSDB
[PASS] TSDB is enabled after configuration
...

===============================================================================
  Test Summary
===============================================================================

  Total Tests:  42
  Passed:       42
  Failed:       0

All tests passed!
```

## Test Coverage Details

### 1. Thread-Safe Config Access

Tests that multiple threads can safely:
- Read TSDB configuration variables
- Write TSDB configuration variables
- Access config from sampler and monitor loops

**Validates:**
- `config_mutex` is properly used
- No data races on config reads/writes
- Sampler and monitor threads use copied config values

### 2. Numeric Config Validation

Tests that invalid numeric values are rejected:
- `raw_window_minutes` <= 0
- `sample_interval_seconds` < 1 or > 3600
- `retention_hours` < 1 or > 8760
- Negative values for any numeric config

**Validates:**
- Division by zero prevention in `write()`
- Proper error messages for invalid values
- Config validation happens before lock

### 3. NULL Field Handling

Tests that NULL database fields are handled:
- Query digest results (hostgroup, schema, user, digest)
- Monitor results (hostgroup_id, hostname, port)
- NULL values are replaced with defaults or skipped

**Validates:**
- No crashes on NULL field access
- Warning logs for skipped rows
- Safe atof() calls with NULL checks

### 4. Path Traversal Prevention

Tests that malicious metric names cannot escape data directory:
- `..` sequences replaced with `__`
- Backslashes replaced with underscores
- Filename length limited to 255 characters

**Validates:**
- `get_series_key()` sanitization
- No files created outside data directory
- POSIX filename limits respected

### 5. HTTP Endpoints

Tests that HTTP endpoints respect `ui_enabled` config:
- `/api/tsdb/status` - Returns 404 when UI disabled
- `/api/tsdb/query` - Returns 404 when UI disabled (also fixes NULL deref)
- `/ui/` - Returns 404 when UI disabled
- `/api/tsdb/metrics` - Prometheus exporter

**Validates:**
- Proper 404 responses when disabled
- Valid JSON/HTML responses when enabled
- NULL pointer checks before accessing `GloTSDB`

### 6. Admin Commands

Tests that TSDB admin commands work:
- `TSDB STATUS` - Returns current TSDB status
- `TSDB QUERY <metric>` - Queries a metric
- `TSDB QUERY <metric> FROM <ts> TO <ts>` - Query with time range

**Validates:**
- Commands execute successfully
- Proper resultset format
- Time range defaults to last hour

### 7. Prometheus Exporter

Tests that Prometheus endpoint works:
- `/api/tsdb/metrics` - Returns empty when no metric specified
- `/api/tsdb/metrics?metric=X` - Returns data for metric
- `/api/tsdb/metrics?metric=X&from=Y&to=Z` - Time range query
- Default time range is last 5 minutes

**Validates:**
- Prometheus text format output
- Proper content-type header
- Query parameter parsing

### 8. NULL Pointer Prevention

Tests that NULL pointers are handled:
- HTTP endpoints when TSDB disabled
- Admin commands when TSDB disabled
- No crashes on `GloTSDB->...` access

**Validates:**
- `!GloTSDB` checks before access
- Graceful 404 responses
- No segmentation faults

## Continuous Integration

To add these tests to CI:

```yaml
# .github/workflows/tsdb-tests.yml or similar
name: TSDB Tests

on: [push, pull_request]

jobs:
  tsdb-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build ProxySQL
        run: make -j$(nproc)
      - name: Start ProxySQL
        run: |
          src/proxysql --config-file proxysql.cfg --daemon
          sleep 5
      - name: Run TSDB Shell Tests
        run: ./test/tap/tests/test_tsdb.sh
      - name: Run TSDB Unit Tests
        run: prove test/tap/tests/test_tsdb-t.cpp
```

## Manual Testing

### Enable TSDB and Test Manually

```sql
-- Enable TSDB
SET tsdb-enabled='true';
SET tsdb-data_dir='/var/lib/proxysql/tsdb';
SET tsdb-ui-enabled='true';
LOAD TSDB VARIABLES TO RUNTIME;

-- Check status
TSDB STATUS;

-- Query metrics
TSDB QUERY proxysql_queries_total;

-- Test validation (should fail)
SET tsdb-raw_window_minutes='0';  -- Error: must be > 0

-- Test UI disable
SET tsdb-ui-enabled='false';
LOAD TSDB VARIABLES TO RUNTIME;
```

### Test HTTP Endpoints

```bash
# Status endpoint
curl -u admin:admin http://localhost:6080/api/tsdb/status

# Query endpoint
curl -u admin:admin "http://localhost:6080/api/tsdb/query?metric=proxysql_queries_total&from=$(($(date +%s%3N)-3600000))&to=$(date +%s%3N)"

# Prometheus exporter
curl -u admin:admin "http://localhost:6080/api/tsdb/metrics?metric=proxysql_queries_total"

# UI
curl -u admin:admin http://localhost:6080/ui/
```

## Troubleshooting

### Tests Fail to Connect

```bash
# Check ProxySQL is running
ps aux | grep proxysql

# Check admin interface is accessible
mysql -h127.0.0.1 -P6032 -uadmin -padmin -e "SELECT 1"

# Check HTTP interface is accessible
curl -u admin:admin http://localhost:6080/
```

### Tests Hang

```bash
# Check TSDB threads
pstack $(pidof proxysql) | grep -A 5 TSDB

# Check for deadlocks
gdb -p $(pidof proxysql) -batch -ex "info threads"
```

### Tests Show 404 for HTTP Endpoints

```bash
# Check if TSDB is enabled
mysql -h127.0.0.1 -P6032 -uadmin -padmin -e "SELECT @@tsdb-enabled"
mysql -h127.0.0.1 -P6032 -uadmin -padmin -e "SELECT @@tsdb-ui-enabled"

# Check HTTP server is running
mysql -h127.0.0.1 -P6032 -uadmin -padmin -e "SELECT @@admin-web_enabled"
```

## Contributing

When adding new TSDB features:
1. Add tests for the new functionality
2. Update this documentation
3. Ensure all existing tests still pass
4. Test with both TSDB enabled and disabled
