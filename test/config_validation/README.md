# Configuration Validation Test Suite

This directory contains a comprehensive test suite for ProxySQL's configuration validation framework.

## Test Overview

The test suite validates that the configuration framework correctly:
- ✅ Validates valid configuration files
- ❌ Detects invalid fields and typos
- 🔍 Provides helpful suggestions for common mistakes
- 📊 Works for both MySQL and PostgreSQL configurations

## Test Files

### Valid Configuration Files
- `valid_mysql_servers.ini` - Valid MySQL server configuration
- `valid_mysql_query_rules.ini` - Valid MySQL query rules configuration
- `valid_postgresql.ini` - Valid PostgreSQL configuration (servers, users, query rules)

### Invalid Configuration Files (Should Fail)
- `typo_mysql_servers.ini` - MySQL servers with typo in "address" field
- `typo_mysql_query_rules.ini` - MySQL query rules with typo in "match_pattern"
- `typo_pgsql_servers.ini` - PostgreSQL servers with typo in "address" field
- `invalid_field_mysql_servers.ini` - MySQL servers with completely invalid field
- `invalid_pgsql_users.ini` - PostgreSQL users with completely invalid field
- `mixed_valid_invalid.ini` - Mixed valid and invalid configurations

## Test Scripts

### 1. Comprehensive Test Suite (`test_config_validation.sh`)
**Purpose**: Full automated test suite with detailed reporting
**Usage**:
```bash
./test_config_validation.sh
```

**Features**:
- Runs all test scenarios automatically
- Tracks success/failure rates
- Provides verbose output for debugging
- Generates detailed test reports
- Color-coded output for easy reading

### 2. Quick Test (`quick_test.sh`)
**Purpose**: Fast manual testing of key scenarios
**Usage**:
```bash
./quick_test.sh
```

**Features**:
- Runs 7 key test scenarios quickly
- Shows exit codes for each test
- Minimal output for rapid testing

### 3. Manual Testing
You can also test individual files manually:
```bash
# Test valid configuration
../src/proxysql --validate-only valid_mysql_servers.ini

# Test invalid configuration (should show errors)
../src/proxysql --validate-only typo_mysql_servers.ini

# Test with strict mode (should fail fast)
../src/proxysql --strict-mode typo_mysql_servers.ini
```

## Expected Test Results

### ✅ Tests That Should PASS (Exit Code 0)
- `valid_mysql_servers.ini` - All fields correct
- `valid_mysql_query_rules.ini` - All query rule fields correct
- `valid_postgresql.ini` - All PostgreSQL fields correct

### ❌ Tests That Should FAIL (Exit Code 1)
- `typo_mysql_servers.ini` - "adddress" should suggest "address"
- `typo_mysql_query_rules.ini` - "match_patern" should suggest "match_pattern"
- `typo_pgsql_servers.ini` - "adddress" should suggest "address"
- `invalid_field_mysql_servers.ini` - "invalid_field" has no suggestion
- `invalid_pgsql_users.ini` - "invalid_user_field" has no suggestion
- `mixed_valid_invalid.ini` - Contains both valid and invalid entries

## Example Error Output

For typo detection (should show suggestions):
```
[FATAL] ProxySQL cannot start due to configuration errors
[ERROR] Invalid configuration in mysql_servers at entry 0: Unknown field 'adddress'
[ERROR]   Unknown field 'adddress'
[ERROR]   Did you mean 'address'?
```

For invalid fields (no suggestion available):
```
[FATAL] ProxySQL cannot start due to configuration errors
[ERROR] Invalid configuration in mysql_servers at entry 0: Unknown field 'invalid_field'
[ERROR]   Unknown field 'invalid_field'
```

## Test Coverage

### MySQL Configurations Tested
- ✅ mysql_servers (12 fields)
- ✅ mysql_query_rules (34 fields)
- ✅ mysql_users (13 fields)

### PostgreSQL Configurations Tested
- ✅ pgsql_servers (12 fields)
- ✅ pgsql_query_rules (34 fields)
- ✅ pgsql_users (13 fields)
- ✅ pgsql_replication_hostgroups (1 field)

### Error Types Tested
- ✅ Field typos (address/addres, pattern/patern)
- ✅ Completely invalid fields
- ✅ Mixed valid/invalid configurations
- ✅ Cross-database type validation

## Running Tests

### Prerequisites
1. ProxySQL must be built: `make -j4`
2. Test directory must be created: `mkdir -p test/config_validation`
3. Configuration files must be present in test directory

### Step-by-Step Testing

1. **Run quick tests first**:
   ```bash
   cd test/config_validation
   ./quick_test.sh
   ```

2. **Run comprehensive test suite**:
   ```bash
   ./test_config_validation.sh
   ```

3. **Manual verification**:
   ```bash
   # Test individual scenarios
   ../src/proxysql --validate-only valid_mysql_servers.ini
   ../src/proxysql --validate-only typo_mysql_servers.ini
   ```

### Interpreting Results

- **Exit Code 0**: Configuration validation passed
- **Exit Code 1**: Configuration validation failed
- **Timeout**: If test hangs (indicates potential issue)

## Debugging Tips

1. **Check for typos**: Review error messages for field name suggestions
2. **Verify field names**: Compare with documentation in `../doc/configuration_validation_framework.md`
3. **Check file paths**: Ensure ProxySQL binary path is correct
4. **Review logs**: Check `/tmp/config_validation_tests/` for detailed logs

## Adding New Tests

To add new test cases:

1. Create a new `.ini` file with the test configuration
2. Add it to the appropriate test script
3. Document the expected behavior:
   - Should it PASS or FAIL?
   - What error message should be shown?
   - Any specific suggestions expected?

Example test file structure:
```ini
mysql_servers:
(
    {
        # Test scenario description
        address = "192.168.1.100"
        port = 3306
        # Add or modify fields to test specific scenarios
        invalid_field_name = "test"  # This should cause failure
    }
)
```

## Integration with CI/CD

The test suite can be integrated into CI/CD pipelines:

```bash
#!/bin/bash
# Example CI test script

# Run validation tests
if ./test_config_validation.sh; then
    echo "All configuration validation tests passed!"
    exit 0
else
    echo "Configuration validation tests failed!"
    exit 1
fi
```

This ensures configuration quality in automated deployment processes.