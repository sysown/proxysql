# Configuration Validation Test Suite

## Overview

This test suite validates the `--strict` flag configuration validation feature for ProxySQL.
The feature adds comprehensive configuration validation at startup and runtime to detect
typos, invalid field names, deprecated variables, and invalid values.

**Issue:** https://github.com/sysown/proxysql/issues/5288

## Test Structure

```
test/config_validation/
├── test_config_validation.sh          # Original validation tests
├── test_strict_mode.sh                 # New comprehensive --strict flag tests
├── valid_mysql_servers.ini             # Valid MySQL server configuration
├── typo_mysql_servers.ini              # MySQL config with typo (adddress)
├── invalid_field_mysql_servers.ini     # MySQL config with invalid field
├── valid_mysql_query_rules.ini         # Valid MySQL query rules
├── typo_mysql_query_rules.ini          # Query rules with typo
├── valid_postgresql.ini                # Valid PostgreSQL configuration
├── typo_pgsql_servers.ini              # PostgreSQL with typo
├── invalid_pgsql_users.ini             # PostgreSQL users with invalid field
├── mixed_valid_invalid.ini             # Mixed valid/invalid configuration
├── deprecated_variables.ini            # Config with deprecated variables
├── invalid_regex_patterns.ini          # Config with invalid regex
├── module_dependent_config.ini         # Module-dependent settings
├── query_rule_with_typo.ini            # Issue #5288 example config
└── invalid_value_ranges.ini            # Invalid port/value ranges

test/tap/tests/
├── test_load_from_config_validation-t.cpp    # Existing LOAD CONFIG tests
├── test_strict_config_validation-t.cpp       # New MySQL validation tests
└── test_strict_pgsql_validation-t.cpp        # New PostgreSQL validation tests
```

## Shell Script Tests

### test_strict_mode.sh

**Purpose:** Comprehensive testing of the `--strict` flag implementation

**Test Groups (30+ tests):**

1. **CLI Alias Tests** (3 tests)
   - `--validate-config` with valid config
   - `--dry-run` alias with valid config
   - `--validate-config` with invalid config

2. **Non-Strict Mode Tests** (4 tests)
   - Valid config passes
   - Typo shows warning but passes
   - Invalid regex shows warning
   - Invalid value shows warning

3. **Strict Mode Tests** (5 tests)
   - Valid config passes
   - Typo causes fatal error
   - Unknown field causes fatal error
   - Invalid regex causes fatal error
   - Invalid value causes fatal error

4. **Combined Flag Tests** (4 tests)
   - `--strict --validate-config` (valid)
   - `--strict --validate-config` (invalid)
   - `--strict --dry-run` (valid)
   - `--strict --dry-run` (invalid)

5. **Suggestion Detection Tests** (2 tests)
   - 'adddress' -> 'address' suggestion
   - 'mathc_pattern' -> 'match_pattern' suggestion

6. **Module-Dependent Configuration Tests** (2 tests)
   - Module config without module loaded (should pass)
   - Module config in strict mode without module

7. **Multi-Section Configuration Tests** (2 tests)
   - Mixed valid/invalid (should fail)
   - All valid sections

8. **PostgreSQL Configuration Tests** (3 tests)
   - Valid PostgreSQL config
   - PostgreSQL with typo in strict mode
   - PostgreSQL users with invalid field

**Running the tests:**
```bash
cd /home/rene/proxysql_5263/test/config_validation
./test_strict_mode.sh
```

## C++ Integration Tests (TAP Framework)

### test_strict_config_validation-t.cpp

**Purpose:** Test MySQL configuration validation at runtime

**Test Cases (10 tests):**

1. Valid mysql_servers config loads successfully
2. Correct number of servers loaded
3. Config with typo loads with warning in non-strict mode
4. Invalid entry not loaded (typo detected)
5. Query rules with typo load with warning
6. Only valid rule loaded, invalid skipped
7. Query rules with invalid regex load with warnings
8. Only valid regex rule loaded
9. Valid query rules load successfully
10. All valid rules loaded

**Building and running:**
```bash
cd /home/rene/proxysql_5263/test/tap/tests
make test_strict_config_validation-t
./test_strict_config_validation-t
```

### test_strict_pgsql_validation-t.cpp

**Purpose:** Test PostgreSQL configuration validation at runtime

**Test Cases (12 tests):**

1. Valid pgsql_servers config loads successfully
2. Correct number of pgsql servers loaded
3. Config with typo loads with warning
4. Invalid entry not loaded (typo detected)
5. Valid pgsql_users config loads successfully
6. Correct number of pgsql users loaded
7. Config with typo loads with warning
8. Invalid entry not loaded (typo detected)
9. Valid pgsql_query_rules config loads successfully
10. Correct number of pgsql rules loaded
11. Config with typo loads with warning
12. Only valid rule loaded, invalid skipped

**Building and running:**
```bash
cd /home/rene/proxysql_5263/test/tap/tests
make test_strict_pgsql_validation-t
./test_strict_pgsql_validation-t
```

## Test Configuration Files

### MySQL Servers Configurations

| File | Description | Expected Result |
|------|-------------|-----------------|
| `valid_mysql_servers.ini` | Valid server definitions | Pass |
| `typo_mysql_servers.ini` | 'adddress' instead of 'address' | Warning/Fail (strict) |
| `invalid_field_mysql_servers.ini` | Unknown field 'invalid_field' | Warning/Fail (strict) |

### MySQL Query Rules Configurations

| File | Description | Expected Result |
|------|-------------|-----------------|
| `valid_mysql_query_rules.ini` | Valid query rules | Pass |
| `typo_mysql_query_rules.ini` | 'mathc_pattern' typo | Warning/Fail (strict) |
| `query_rule_with_typo.ini` | Issue #5288 example | Warning/Fail (strict) |
| `invalid_regex_patterns.ini` | Unclosed groups/brackets | Warning/Fail (strict) |

### PostgreSQL Configurations

| File | Description | Expected Result |
|------|-------------|-----------------|
| `valid_postgresql.ini` | Valid PostgreSQL config | Pass |
| `typo_pgsql_servers.ini` | Server typo | Warning/Fail (strict) |
| `invalid_pgsql_users.ini` | User invalid field | Warning/Fail (strict) |

### Special Configuration Files

| File | Description | Purpose |
|------|-------------|---------|
| `deprecated_variables.ini` | Contains deprecated variables | Tests deprecated var handling |
| `module_dependent_config.ini` | SQLite3-Server settings | Tests module-dependent validation |
| `invalid_value_ranges.ini` | Invalid ports/weights | Tests value range validation |
| `mixed_valid_invalid.ini` | Mix of valid/invalid entries | Tests partial failure handling |

## Expected Behaviors

### Non-Strict Mode (Default)

```
$ proxysql --config=config_with_typo.ini
[WARNING] Invalid configuration in mysql_servers at entry 0:
[WARNING]   Unknown field 'adddress'
[WARNING]   Did you mean 'address'?
[INFO] ProxySQL starting...
```

**Behavior:** Warnings logged, but ProxySQL starts

### Strict Mode

```
$ proxysql --strict --config=config_with_typo.ini
[ERROR] Invalid configuration in mysql_servers at entry 0:
[ERROR]   Unknown field 'adddress'
[ERROR]   Did you mean 'address'?
[FATAL] ProxySQL cannot start due to configuration errors
[INFO]  Remove --strict to start anyway (not recommended)
# Exit code: 1
```

**Behavior:** Errors logged, ProxySQL exits with failure

### Validate-Only Mode

```
$ proxysql --validate-config --config=config_with_typo.ini
[ERROR] Invalid configuration in mysql_servers at entry 0:
[ERROR]   Unknown field 'adddress'
[FATAL] Configuration validation failed
# Exit code: 1
```

**Behavior:** Validate and exit without starting

## Building All Tests

```bash
# Build the TAP test framework
cd /home/rene/proxysql_5263/test/tap
make

# Build specific tests
cd tests
make test_strict_config_validation-t
make test_strict_pgsql_validation-t
```

## Running All Tests

```bash
# Run shell script tests
cd /home/rene/proxysql_5263/test/config_validation
./test_strict_mode.sh

# Run C++ integration tests
cd /home/rene/proxysql_5263/test/tap/tests
./test_strict_config_validation-t
./test_strict_pgsql_validation-t

# Run existing validation tests
./test_load_from_config_validation-t
```

## Test Coverage Summary

| Feature | Shell Tests | C++ Tests | Coverage |
|---------|-------------|-----------|----------|
| CLI Aliases (--validate-config, --dry-run) | ✓ | - | Complete |
| Non-strict mode (warnings) | ✓ | ✓ | Complete |
| Strict mode (fatal errors) | ✓ | - | Complete |
| Typo detection with suggestions | ✓ | ✓ | Complete |
| Invalid regex detection | ✓ | ✓ | Complete |
| Invalid value range detection | ✓ | - | Complete |
| MySQL servers validation | ✓ | ✓ | Complete |
| MySQL users validation | - | ✓ | Partial |
| MySQL query rules validation | ✓ | ✓ | Complete |
| PostgreSQL servers validation | ✓ | ✓ | Complete |
| PostgreSQL users validation | ✓ | ✓ | Complete |
| PostgreSQL query rules validation | - | ✓ | Partial |
| Module-dependent config | ✓ | - | Partial |
| Runtime LOAD CONFIG validation | - | ✓ | Complete |

## Notes

- Shell tests test the full ProxySQL binary with different command-line options
- C++ tests use the TAP framework and test runtime validation through SQL commands
- Both test types are complementary and should be run together for complete coverage
- Tests assume ProxySQL is already built (`make` in the source directory)

## Future Enhancements

Potential additional tests:
1. Deprecated variable handling in strict mode (requires implementation)
2. Value range validation for all numeric fields
3. Integration tests with actual MySQL/PostgreSQL backends
4. Performance tests for large configuration files
5. Tests for proxysql_servers validation
6. Tests for mysql_hostgroup_attributes validation
