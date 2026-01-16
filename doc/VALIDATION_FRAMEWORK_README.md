# Configuration Validation Framework Documentation

This directory contains documentation for ProxySQL's Configuration Validation Framework.

## Documentation Files

### 📋 [configuration_validation_framework.md](./configuration_validation_framework.md)
**Complete Guide to Configuration Validation Framework**

This is the comprehensive documentation covering:
- **Overview**: Features and benefits of the validation framework
- **Usage**: Command-line arguments and examples
- **Configuration Sections**: All supported MySQL configurations
- **How It Works**: Technical details and algorithms
- **Integration**: CI/CD and configuration management tools
- **Best Practices**: Recommendations for different environments
- **Limitations**: Current constraints and future enhancements
- **Troubleshooting**: Common issues and solutions

## Quick Start

### Basic Usage
```bash
# Validate configuration only
./proxysql --validate-only

# Start with strict validation (fail on errors)
./proxysql --strict-mode

# Normal mode (warnings only)
./proxysql
```

### Global Variables
```sql
-- Enable strict validation
SET GLOBAL admin-strict_mode = 1;

-- Enable validate-only mode
SET GLOBAL admin-validate_only = 1;
```

## Key Features

### ✅ Field Validation
- Validates all configuration fields against known valid fields
- Detects typos and invalid options
- Supports MySQL query rules, servers, users, and hostgroups

### ✅ Intelligent Suggestions
- Levenshtein distance algorithm for typo detection
- Provides helpful suggestions for common mistakes
- Reduces configuration debugging time

### ✅ Multiple Validation Modes
- **Strict Mode**: Production-ready error detection
- **Non-Strict Mode**: Development-friendly with warnings
- **Validate-Only Mode**: CI/CD pipeline integration

### ✅ Comprehensive Coverage
- mysql_query_rules, mysql_servers, mysql_users
- mysql_replication_hostgroups, mysql_galera_hostgroups
- mysql_hostgroup_attributes, mysql_group_replication_hostgroups

## Integration Examples

### CI/CD Pipeline
```bash
#!/bin/bash
# Pre-deployment validation
./proxysql --validate-only || exit 1
```

### Configuration Management
```yaml
# Ansible example
- name: Validate ProxySQL config
  command: proxysql --validate-only
  register: validation_result
  failed_when: validation_result.rc != 0
```

## Getting Help

### Reporting Issues
- Visit the [ProxySQL GitHub Repository](https://github.com/sysown/proxysql)
- Search existing issues or create a new one
- Include version information and configuration details

### Community Support
- Join the [ProxySQL Slack Channel](https://proxysql.slack.com/)
- Participate in discussions on GitHub
- Review existing documentation and FAQ

---

*Last updated: v3.0.5288*  
*For the latest information, always refer to the main documentation file.*
