# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ProxySQL is a high-performance MySQL and PostgreSQL proxy server written in C++. The codebase uses C++11/17 and implements full wire protocol support for both databases, with sophisticated connection pooling, query routing, and monitoring capabilities.

## Architecture Documentation

For comprehensive understanding of the codebase:
- **`doc/architecture/ARCHITECTURE-OVERVIEW.md`** - Detailed architectural analysis including threading model, protocol handlers, and design patterns
- **`doc/architecture/PROJECT-LAYOUT.md`** - Complete directory structure mapping with module boundaries and build system overview

## Build Commands

```bash
# Standard build
make

# Debug build with full debugging symbols
make debug

# Clean build artifacts
make clean

# Build with dependencies
make build_deps && make

# Debug build with dependencies and tests
make build_deps_debug && make debug && make build_tap_test_debug
```

## Key Directories

- `src/` - Main source code (main.cpp, SQLite3_Server.cpp, proxy_tls.cpp)
- `lib/` - Core libraries and modules
- `include/` - Header files
- `deps/` - External dependencies
- `test/` - Test suites (tap tests, unit tests, integration tests)
- `docker/` - Docker configurations for testing environments

## Architecture Quick Reference

ProxySQL uses a multi-threaded, event-driven architecture with:
- **Dual Protocol Support**: MySQL and PostgreSQL wire protocol handlers
- **SQLite3 Configuration**: Three-tier configuration system (Disk → Memory → Runtime)
- **Connection Management**: Per-hostgroup connection pooling with multiplexing
- **Query Processing**: Rule-based routing, rewriting, and caching
- **Replication Support**: MySQL (Galera, Group Replication, Aurora) and PostgreSQL topologies
- **Monitoring**: Built-in health checks, Prometheus metrics, REST API

Main entry point: `src/main.cpp` - initializes proxy threads and configuration systems.

## Using Claude Code Agents for ProxySQL Development

Claude Code provides specialized agents to help with different aspects of ProxySQL development:

### Available Agents and Their Uses

1. **`gopher-scout`** - Codebase exploration and intelligence gathering
   - Use for: Understanding ProxySQL's C++ implementation details
   - Example: "Use gopher-scout to analyze how ProxySQL handles MySQL prepared statements"
   - Best for: Scanning through src/, lib/, and include/ directories for specific patterns

2. **`system-digest`** - Architecture and system design analysis
   - Use for: Understanding overall system architecture and dependencies
   - Example: "Use system-digest to analyze ProxySQL's threading model"
   - Best for: High-level architectural understanding

3. **`tdd-driven-builder`** - Test-driven development for ProxySQL features
   - Use for: Building new features or fixing bugs with TAP test coverage
   - Example: "Use tdd-driven-builder to add a new query routing rule feature"
   - Best for: Features requiring test coverage in test/tap/tests/

4. **`tool-forge`** - Creating development and administration tools
   - Use for: Building CLI tools for ProxySQL administration or testing
   - Example: "Use tool-forge to create a ProxySQL configuration validator"
   - Best for: Automation scripts and monitoring tools

5. **`gpt-qa`** - Building comprehensive test suites
   - Use for: Creating TAP tests for ProxySQL C++ code
   - Example: "Use gpt-qa to create tests for the new PostgreSQL authentication method"
   - Best for: Expanding test coverage in test/tap/tests/

### Agent Usage Examples

```bash
# When exploring the codebase
"Deploy gopher-scout to find all MySQL authentication implementations"

# When understanding architecture
"Use system-digest to analyze ProxySQL's connection pooling strategy"

# When implementing features
"Use tdd-driven-builder to implement support for MySQL 8.0 caching_sha2_password"

# When creating tools
"Use tool-forge to create a ProxySQL query log analyzer"

# When writing tests
"Use gpt-qa to create comprehensive tests for PgSQL prepared statements"
```

## Common Development Workflows

### Understanding Code Flow
```bash
# To understand MySQL query processing:
# 1. Start at lib/MySQL_Session.cpp for session handling
# 2. Follow to lib/MySQL_Protocol.cpp for protocol parsing
# 3. Check lib/Query_Processor.cpp for routing decisions
# 4. Review lib/MySQL_HostGroups_Manager.cpp for backend selection

# To understand PostgreSQL implementation:
# 1. Start at lib/PgSQL_Session.cpp
# 2. Check lib/PgSQL_Protocol.cpp for wire protocol
# 3. Review lib/PgSQL_Authentication.cpp for SASL/SCRAM
```

### Key Files for Common Tasks

**Adding a new configuration variable:**
- `lib/ProxySQL_Admin.cpp` - Admin interface queries
- `include/proxysql_structs.h` - Variable definitions
- `lib/ProxySQL_Config.cpp` - Configuration handling

**Implementing a new query rule:**
- `lib/Query_Processor.cpp` - Rule processing logic
- `lib/MySQL_Query_Processor.cpp` - MySQL-specific rules
- `include/query_processor.h` - Rule structures

**Adding monitoring metrics:**
- `lib/ProxySQL_Admin_Stats.cpp` - Statistics collection
- `lib/ProxySQL_RESTAPI_Server.cpp` - REST API exposure
- `lib/prometheus.cpp` - Prometheus metrics

## Testing

Tests are located in `test/` directory with TAP (Test Anything Protocol) format tests being the primary testing mechanism. 

```bash
# Build test environment
make build_tap_test_debug

# Run all TAP tests
cd test/tap/tests && ./run_tests.sh

# Run specific test
./test_mysql_connect-t

# Create new test
# Use test/tap/tests/test_template.cpp as starting point
```

## Debugging Tips

1. **Enable debug logging**: Set `mysql-verbose_query_error=true` in admin interface
2. **Core dumps**: Built with coredumper support, check `/var/lib/proxysql/`
3. **Memory debugging**: Debug builds include jemalloc leak detection
4. **Protocol tracing**: Use `PROXYSQL_TRACE` environment variable

## Current Branch

Working on branch: v3.0
Main branch for PRs: v2.7