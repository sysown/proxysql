# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ProxySQL is a high-performance MySQL proxy server written in C++. The codebase uses C++11/17 and includes extensive MySQL protocol handling, connection pooling, and query routing capabilities.

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

## Architecture Notes

ProxySQL uses a multi-threaded architecture with:
- MySQL protocol handlers for client/server communication
- SQLite3 embedded database for configuration storage
- Connection pooling and multiplexing
- Query routing based on rules and hostgroups
- Support for MySQL replication topologies (Galera, Group Replication, Aurora)

The main entry point is `src/main.cpp` which initializes the proxy threads and configuration systems.

## Testing

Tests are located in `test/` directory with TAP (Test Anything Protocol) format tests being the primary testing mechanism. Build test environment with `make build_tap_test_debug`.

## Current Branch

Working on branch: v3.0
Main branch for PRs: v2.7