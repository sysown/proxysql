# Configuration Validation Test Suite

## Overview

This test suite validates the `--strict` flag configuration validation feature for ProxySQL.
The feature adds comprehensive configuration validation at startup and runtime to detect
typos, invalid field names, deprecated variables, and invalid values.

**Issue:** https://github.com/sysown/proxysql/issues/5288

## Test Architecture

The test suite is divided into two complementary test types, each testing different aspects:

| Test Type | Scope | ProxySQL State | What It Tests |
|-----------|-------|----------------|---------------|
| **Shell Script Tests** | Startup validation | Spawns new process | CLI flags, exit codes, strict mode |
| **TAP C++ Tests** | Runtime validation | Connects to running instance | LOAD CONFIG behavior, entry filtering |

### Key Design Decision

The `--strict` flag is set at **startup only** and affects both startup and runtime validation:
- Shell tests spawn ProxySQL with different flags to test startup behavior
- TAP tests connect to an already-running ProxySQL and test observable behavior
- TAP tests are **mode-agnostic** - they work whether ProxySQL was started with `--strict` or not

## Test Structure

```
test/config_validation/
├── test_config_validation.sh          # Original validation tests
├── test_strict_mode.sh                 # Startup + strict flag tests (30+ tests)
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
├── test_strict_config_validation-t.cpp       # MySQL runtime validation (mode-agnostic)
└── test_strict_pgsql_validation-t.cpp        # PostgreSQL runtime validation (mode-agnostic)
```

## Shell Script Tests (Startup & CLI Flags)

### test_strict_mode.sh

**Purpose:** Test `--strict` flag, CLI aliases, and startup validation

**How it works:** Spawns new ProxySQL processes with different command-line options

**Test Groups (30+ tests):**

1. **CLI Alias Tests** (3 tests)
   - `--validate-config` with valid config
   - `--dry-run` alias with valid config
   - `--validate-config` with invalid config

2. **Non-Strict Mode Tests** (4 tests)
   - Valid config passes
   - Typo shows warning but ProxySQL starts
   - Invalid regex shows warning
   - Invalid value shows warning

3. **Strict Mode Tests** (5 tests)
   - Valid config passes
   - Typo causes fatal error and exit
   - Unknown field causes fatal error and exit
   - Invalid regex causes fatal error and exit
   - Invalid value causes fatal error and exit

4. **Combined Flag Tests** (4 tests)
   - `--strict --validate-config` (valid/invalid)
   - `--strict --dry-run` (valid/invalid)

5. **Suggestion Detection Tests** (2 tests)
   - 'adddress' -> 'address' typo suggestion
   - 'mathc_pattern' -> 'match_pattern' typo suggestion

6. **Module-Dependent Configuration Tests** (2 tests)
   - Module config without module loaded (should pass)
   - Module config in strict mode without module

7. **Multi-Section Configuration Tests** (2 tests)
   - Mixed valid/invalid behavior
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

## C++ Integration Tests (Runtime Validation)

### test_strict_config_validation-t.cpp

**Purpose:** Test MySQL configuration validation at runtime

**How it works:** Connects to running ProxySQL, executes `LOAD ... FROM CONFIG` commands

**Mode-Agnostic Design:**
- Tests work whether ProxySQL was started with `--strict` or not
- Focus on **observable behavior**: what entries actually get loaded
- Uses conditional checks based on LOAD command result

**Test Cases (10 tests):**

1. Valid mysql_servers config - correct entries loaded
2. Config with typo - invalid entry not loaded (0 entries)
3. Mixed valid/invalid query rules - only valid loaded
4. Invalid regex patterns - only valid regex rule loaded
5. Valid query rules - all entries loaded
6. Valid entry followed by invalid entry - only valid loaded

**Building and running:**
```bash
cd /home/rene/proxysql_5263/test/tap/tests
make test_strict_config_validation-t
./test_strict_config_validation-t
```

### test_strict_pgsql_validation-t.cpp

**Purpose:** Test PostgreSQL configuration validation at runtime

**How it works:** Same as MySQL test but for PostgreSQL objects

**Test Cases (12 tests):**

1. Valid pgsql_servers - correct entries loaded
2. pgsql_servers with typo - invalid entry not loaded
3. Valid pgsql_users - correct entries loaded
4. pgsql_users with typo - invalid entry not loaded
5. Valid pgsql_query_rules - correct entries loaded
6. pgsql_query_rules with typo - only valid loaded

**Building and running:**
```bash
cd /home/rene/proxysql_5263/test/tap/tests
make test_strict_pgsql_validation-t
./test_strict_pgsql_validation-t
```

## Test Configuration Files

### MySQL Servers Configurations

| File | Description | Shell Test | TAP Test |
|------|-------------|------------|----------|
| `valid_mysql_servers.ini` | Valid server definitions | Pass ✓ | Entries loaded |
| `typo_mysql_servers.ini` | 'adddress' typo | Warn/Fail | 0 entries (skipped) |
| `invalid_field_mysql_servers.ini` | Unknown field | Warn/Fail | 0 entries (skipped) |

### MySQL Query Rules Configurations

| File | Description | Shell Test | TAP Test |
|------|-------------|------------|----------|
| `valid_mysql_query_rules.ini` | Valid query rules | Pass ✓ | All loaded |
| `typo_mysql_query_rules.ini` | 'mathc_pattern' typo | Warn/Fail | Only valid loaded |
| `query_rule_with_typo.ini` | Issue #5288 example | Warn/Fail | Only valid loaded |
| `invalid_regex_patterns.ini` | Unclosed groups/brackets | Warn/Fail | Only valid loaded |

### PostgreSQL Configurations

| File | Description | Shell Test | TAP Test |
|------|-------------|------------|----------|
| `valid_postgresql.ini` | Valid PostgreSQL config | Pass ✓ | All loaded |
| `typo_pgsql_servers.ini` | Server typo | Warn/Fail | 0 entries (skipped) |
| `invalid_pgsql_users.ini` | User invalid field | Warn/Fail | 0 entries (skipped) |

### Special Configuration Files

| File | Description | Purpose |
|------|-------------|---------|
| `deprecated_variables.ini` | Contains deprecated variables | Tests deprecated var handling |
| `module_dependent_config.ini` | SQLite3-Server settings | Tests module-dependent validation |
| `invalid_value_ranges.ini` | Invalid ports/weights | Tests value range validation |
| `mixed_valid_invalid.ini` | Mix of valid/invalid entries | Tests partial failure handling |

## Expected Behaviors

### Non-Strict Mode (Default - Startup)

```bash
$ proxysql --config=config_with_typo.ini
[WARNING] Invalid configuration in mysql_servers at entry 0:
[WARNING]   Unknown field 'adddress'
[WARNING]   Did you mean 'address'?
[INFO] ProxySQL starting...
# Exit code: 0, ProxySQL runs
```

**Shell test:** Expects exit code 0, warning in output
**TAP test:** Invalid entry skipped, 0 entries loaded

### Strict Mode (Startup)

```bash
$ proxysql --strict --config=config_with_typo.ini
[ERROR] Invalid configuration in mysql_servers at entry 0:
[ERROR]   Unknown field 'adddress'
[ERROR]   Did you mean 'address'?
[FATAL] ProxySQL cannot start due to configuration errors
[INFO]  Remove --strict to start anyway (not recommended)
# Exit code: 1
```

**Shell test:** Expects exit code 1, error in output
**TAP test:** Invalid entry skipped, 0 entries loaded

### Runtime LOAD CONFIG (Mode-Agnostic)

```sql
-- Mixed valid/invalid config
mysql> LOAD MYSQL SERVERS FROM CONFIG;
-- In non-strict: Succeeds with warning
-- In strict: May fail entirely

-- Observable result (both modes):
-- Invalid entries are NOT loaded
-- Valid entries ARE loaded
```

**TAP test focus:** Verifies observable result (invalid skipped, valid loaded)

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
# Run shell script tests (startup + CLI flags)
cd /home/rene/proxysql_5263/test/config_validation
./test_strict_mode.sh

# Run C++ integration tests (runtime validation)
cd /home/rene/proxysql_5263/test/tap/tests
./test_strict_config_validation-t
./test_strict_pgsql_validation-t

# Run existing validation tests
./test_load_from_config_validation-t
```

## Test Coverage Summary

| Feature | Shell Tests | TAP Tests | Coverage |
|---------|-------------|-----------|----------|
| **CLI & Startup** |
| CLI Aliases (--validate-config, --dry-run) | ✓ | - | Complete |
| Non-strict mode startup (warnings) | ✓ | - | Complete |
| Strict mode startup (fatal errors) | ✓ | - | Complete |
| Typo suggestions in output | ✓ | - | Complete |
| **Runtime Validation** |
| Invalid entries skipped | - | ✓ | Complete |
| Valid entries still loaded | - | ✓ | Complete |
| Mixed valid/invalid handling | - | ✓ | Complete |
| **Config Types** |
| MySQL servers validation | ✓ | ✓ | Complete |
| MySQL users validation | - | ✓ | Partial |
| MySQL query rules validation | ✓ | ✓ | Complete |
| PostgreSQL servers validation | ✓ | ✓ | Complete |
| PostgreSQL users validation | ✓ | ✓ | Complete |
| PostgreSQL query rules validation | - | ✓ | Partial |
| **Validation Types** |
| Typo detection | ✓ | ✓ | Complete |
| Invalid regex detection | ✓ | ✓ | Complete |
| Invalid value range detection | ✓ | - | Partial |
| Module-dependent config | ✓ | - | Partial |
| Runtime LOAD CONFIG validation | - | ✓ | Complete |

## Notes

- **Shell tests** spawn new ProxySQL processes with different CLI flags
- **TAP tests** connect to a running ProxySQL and test runtime behavior
- TAP tests are **mode-agnostic** - they test observable behavior regardless of startup mode
- Both test types are **complementary** - shell tests cover startup/CLI, TAP tests cover runtime
- Tests assume ProxySQL is already built (`make` in the source directory)

## Why Both Test Types?

1. **Shell Script Tests** - Essential for testing:
   - CLI flag parsing (`--strict`, `--validate-config`, `--dry-run`)
   - Exit codes and error messages
   - Startup validation behavior
   - Strict vs non-strict mode differences

2. **TAP C++ Tests** - Essential for testing:
   - Runtime `LOAD ... FROM CONFIG` validation
   - Entry filtering behavior (invalid skipped, valid loaded)
   - Mixed valid/invalid configuration handling
   - Integration with running ProxySQL instance

**Neither test type can replace the other** - they test different aspects of the system.

## Future Enhancements

Potential additional tests:
1. Deprecated variable handling in strict mode (requires implementation)
2. Value range validation for all numeric fields
3. Integration tests with actual MySQL/PostgreSQL backends
4. Performance tests for large configuration files
5. Tests for proxysql_servers validation
6. Tests for mysql_hostgroup_attributes validation
