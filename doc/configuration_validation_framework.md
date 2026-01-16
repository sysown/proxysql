# Configuration Validation Framework

## Overview

ProxySQL now includes a comprehensive configuration validation framework that detects invalid configuration fields and provides helpful suggestions to users. This feature helps catch configuration errors early, reduces runtime issues, and improves the overall user experience.

## Features

### 1. Field Validation
- Validates all fields in configuration sections against known valid fields
- Detects typos and invalid configuration options
- Supports all major MySQL configuration sections

### 2. Intelligent Suggestions
- Uses Levenshtein distance algorithm to find similar field names
- Provides helpful suggestions for common typos
- Reduces user frustration when fixing configuration errors

### 3. Multiple Validation Modes
- **Strict Mode**: Fails startup on any configuration error
- **Non-Strict Mode**: Reports warnings but continues startup
- **Validate-Only Mode**: Checks configuration and exits without starting

### 4. Comprehensive Coverage
- Validates MySQL query rules, servers, and users
- Covers replication hostgroups, Galera hostgroups, and hostgroup attributes
- Extensible to support additional configuration sections

## Usage

### Command Line Arguments

```bash
# Strict mode - fail on any configuration error
./proxysql --strict-mode

# Validate-only mode - check configuration and exit
./proxysql --validate-only

# Normal mode - report warnings but continue
./proxysql
```

### Example Error Messages

#### Strict Mode Error
```
[FATAL] ProxySQL cannot start due to configuration errors
[ERROR] Invalid configuration in mysql_servers at entry 0: Unknown field 'adddress'
[ERROR]   Unknown field 'adddress'
[ERROR]   Did you mean 'address'?
```

#### Non-Strict Mode Warning
```
[WARNING] Invalid configuration in mysql_query_rules at entry 1: Unknown field 'match_patern'. Unknown configuration field
[WARNING]   Did you mean 'match_pattern'?
```

#### Validate-Only Mode
```
[INFO] Configuration validation passed
```

## Supported Configuration Sections

### MySQL Configuration
- **mysql_query_rules**: `rule_id`, `active`, `username`, `schemaname`, `flagIN`, `client_addr`, `proxy_addr`, `proxy_port`, `digest`, `match_digest`, `match_pattern`, `negate_match_pattern`, `re_modifiers`, `flagOUT`, `replace_pattern`, `destination_hostgroup`, `cache_ttl`, `cache_empty_result`, `cache_timeout`, `reconnect`, `timeout`, `retries`, `delay`, `next_query_flagIN`, `mirror_flagOUT`, `mirror_hostgroup`, `error_msg`, `OK_msg`, `sticky_conn`, `multiplex`, `gtid_from_hostgroup`, `log`, `apply`, `attributes`, `comment`

- **mysql_servers**: `address`, `port`, `hostgroup_id`, `hostname`, `weight`, `max_connections`, `max_replication_lag`, `use_ssl`, `compression`, `status`, `max_latency_ms`, `comment`

- **mysql_users**: `username`, `password`, `default_hostgroup`, `max_connections`, `default_schema`, `schema_locked`, `transaction_persistent`, `fast_forward`, `backend`, `frontend`, `default_query_rule`, `compression`, `comment`

### Hostgroup Configuration
- **mysql_replication_hostgroups**: `comment`
- **mysql_group_replication_hostgroups**: `comment`
- **mysql_galera_hostgroups**: `comment`
- **mysql_hostgroup_attributes**: `hostgroup_id`, `disabled`, `comment`

## How It Works

### 1. Validation Process
The validation framework operates during configuration file loading:

1. **Field Discovery**: Each configuration section is parsed to identify all fields
2. **Validation Check**: Each field is checked against the list of valid fields
3. **Error Collection**: Invalid fields are collected with location information
4. **Suggestion Generation**: Similar valid field names are suggested using edit distance
5. **Error Reporting**: Results are reported based on the current validation mode

### 2. Error Handling Modes

#### Strict Mode (`--strict-mode`)
- Unknown configuration fields cause immediate startup failure
- All validation errors are treated as fatal
- Recommended for production environments to catch configuration issues early

#### Non-Strict Mode (Default)
- Unknown fields are reported as warnings
- ProxySQL continues normal startup process
- Useful for development and testing environments

#### Validate-Only Mode (`--validate-only`)
- ProxySQL validates configuration and exits
- Exit code 0 indicates valid configuration
- Exit code 1 indicates configuration errors
- Useful for CI/CD pipelines and automated configuration checks

### 3. Suggestion Algorithm
The framework uses the Levenshtein distance algorithm to find similar field names:

```
levenshtein("adddress", "address") = 1  # Single character deletion
levenshtein("match_patern", "match_pattern") = 1  # Single character insertion
```

Field suggestions are only made when the edit distance is ≤ 3.

## Configuration Examples

### Valid Configuration
```ini
mysql_servers:
(
    {
        address = "192.168.1.100"
        port = 3306
        hostgroup_id = 1
        comment = "MySQL primary server"
    }
)
```

### Configuration with Typo (Non-Strict Mode)
```ini
mysql_servers:
(
    {
        adddress = "192.168.1.100"  # Typo: "address" misspelled
        port = 3306
        hostgroup_id = 1
    }
)
```

Output:
```
[WARNING] Invalid configuration in mysql_servers at entry 0: Unknown field 'adddress'. Unknown configuration field
[WARNING]   Did you mean 'address'?
```

### Configuration with Invalid Field (Strict Mode)
```ini
mysql_query_rules:
(
    {
        rule_id = 1
        match_patern = "SELECT.*FROM users"  # Typo: "pattern" misspelled
        destination_hostgroup = 1
    }
)
```

Output:
```
[FATAL] ProxySQL cannot start due to configuration errors
[ERROR] Invalid configuration in mysql_query_rules at entry 0: Unknown field 'match_patern'
[ERROR]   Unknown field 'match_patern'
[ERROR]   Did you mean 'match_pattern'?
```

```

## Integration with Existing Systems

### CI/CD Pipeline Integration
```bash
#!/bin/bash
# Validate configuration before deployment
./proxysql --validate-only
if [ $? -eq 0 ]; then
    echo "Configuration validation passed"
    # Continue with deployment
else
    echo "Configuration validation failed"
    exit 1
fi
```

### Configuration Management Tools
```yaml
# Example Ansible playbook
- name: Validate ProxySQL configuration
  command: /usr/local/bin/proxysql --validate-only
  register: validation_result
  failed_when: validation_result.rc != 0
```

## Performance Impact

- **Minimal Overhead**: Validation adds only a small overhead during startup
- **Early Validation**: Errors are caught before any database connections are established
- **No Runtime Impact**: Validation occurs only during configuration loading

## Best Practices

### 1. Development Environment
- Use non-strict mode for development and testing
- Review all warnings to improve configuration quality

### 2. Production Environment
- Use strict mode in production to catch issues early
- Include validation in deployment scripts

### 3. Configuration Management
- Store configuration in version control
- Run validation checks as part of CI/CD pipeline
- Document all configuration options used

### 4. Error Resolution
- Pay attention to field suggestions in error messages
- Validate configuration changes before deploying to production
- Use the validate-only mode for rapid iteration

## Limitations

### Current Limitations

1. **Variable Validation**: Currently validates configuration structure but not variable values
   - Future versions will include type validation and range checking
   - Will validate numeric ranges, string formats, and data types

2. **Module Variables**: Dynamic module variables (mysql-*, pgsql-*, admin-*) are validated by their respective modules
   - These variables are validated by their respective modules using module-specific logic
   - The framework focuses on configuration structure validation

3. **Deprecation Detection**: Currently does not detect deprecated configuration options
   - Future versions will provide warnings for deprecated fields
   - Will include upgrade paths and migration suggestions

4. **Conditional Validation**: Some fields are only valid under specific conditions
   - Future versions will include conditional validation logic
   - Example: `compression` field only valid when `use_ssl = 1`

5. **Cross-Section Validation**: Does not validate relationships between sections
   - Future versions will include cross-section validation
   - Example: Validate that referenced hostgroups exist

### Planned Enhancements

1. **Value Validation**
   - Numeric range checking
   - String format validation (regex patterns)
   - Enum value validation
   - Required field validation

2. **Module Integration**
   - Dynamic validation of module-specific variables
   - Integration with MySQL, PgSQL, and Admin modules
   - Custom validation rules per module

3. **Deprecation Handling**
   - Detection of deprecated configuration options
   - Automatic upgrade suggestions
   - Migration path documentation

4. **Advanced Validation**
   - Conditional field validation
   - Cross-section relationship validation
   - Circular dependency detection

5. **Documentation Integration**
   - Automatic generation of configuration documentation
   - Field descriptions and examples
   - Configuration schema validation

## Troubleshooting

### Common Issues

#### 1. False Positives
```bash
# Issue: Valid field reported as unknown
[ERROR] Invalid configuration in mysql_servers at entry 0: Unknown field 'custom_field'
```
**Solution**: The field may not be in the current validation list. Check for typos or consider adding the field to the valid fields list.

#### 2. Performance Impact
```bash
# Issue: Slow startup due to validation
```
**Solution**: Validation has minimal impact. If performance issues occur, consider using the non-strict mode or disabling validation in development.

#### 3. Module Variables Not Validated
```bash
# Issue: mysql- variables not validated
[WARNING] Unknown variable 'mysql-max_connections'
```
**Solution**: Module variables are validated by their respective modules. Use the MySQL module's interfaces to manage these variables.

### Debug Information

#### Enable Debug Logging
```sql

```


#### Manual Validation
```bash
./proxysql --validate-only
echo $?
```

## Contributing

### Adding New Configuration Sections

To add validation for a new configuration section:

1. Define the valid fields in `ProxySQL_Config.cpp`
2. Add validation call in the appropriate config reader function
3. Update documentation with the new section and valid fields
4. Test with valid and invalid configurations

Example:
```cpp
static const std::unordered_set<std::string> valid_new_section_fields = {
    "field1", "field2", "field3"
};

// In config reader function
if (config_root.exists("new_section")) {
    const Setting &new_section = config_root["new_section"];
    validate_config_fields(new_section, "new_section", valid_new_section_fields);
}
```
