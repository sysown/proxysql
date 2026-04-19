# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ProxySQL is a high-performance, protocol-aware proxy for MySQL (and forks like MariaDB, Percona Server) and PostgreSQL. Written in C++17, it provides connection pooling, query routing, caching, and monitoring. Licensed under GPL.

## Build Commands

The build system is GNU Make-based with a three-stage pipeline: `deps` → `lib` → `src`.

```bash
# Full release build (auto-detects -j based on nproc/hw.ncpu)
make

# Debug build (-O0, -ggdb, -DDEBUG)
make debug

# Build with ASAN (requires no jemalloc)
NOJEMALLOC=1 WITHASAN=1 make build_deps_debug && make debug && make build_tap_test_debug

# Build TAP tests (requires proxysql binary built first)
make build_tap_tests          # release
make build_tap_test_debug     # debug

# Clean
make clean                    # clean src/lib
make cleanall                 # clean everything including deps

# Build packages
make packages
```

### Feature Tiers

The same codebase produces three product tiers via feature flags:

| Tier | Flag | Version | Adds |
|------|------|---------|------|
| Stable | (default) | v3.0.x | Core proxy |
| Innovative | `PROXYSQL31=1` | v3.1.x | FFTO, TSDB |
| AI/MCP | `PROXYSQLGENAI=1` | v4.0.x | GenAI, MCP, Anomaly Detection |

`PROXYSQLGENAI=1` implies `PROXYSQL31=1`, which implies `PROXYSQLFFTO=1` and `PROXYSQLTSDB=1`.

### Build Flags

- `NOJEMALLOC=1` — disable jemalloc
- `WITHASAN=1` — enable AddressSanitizer (requires `NOJEMALLOC=1`)
- `WITHGCOV=1` — enable code coverage
- `PROXYSQLCLICKHOUSE=1` — enabled by default in current builds

## Testing

Tests use TAP (Test Anything Protocol) with Docker-based backend infrastructure.

### Running TAP tests — DO NOT manually set up Docker containers

**ALWAYS use `run-tests-isolated.bash`**. It handles infrastructure setup, ProxySQL start, test execution, and cleanup. Never manually create Docker networks, start containers, or run init scripts — the runner does all of that.

```bash
# Set up infrastructure (backends + ProxySQL container)
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=mysql84-g1 test/infra/control/ensure-infras.bash

# Run all tests for a TAP group
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=mysql84-g1 test/infra/control/run-tests-isolated.bash

# Build test binaries first (requires proxysql binary)
make build_tap_tests          # release
make build_tap_test_debug     # debug
```

Available TAP groups are defined in `test/tap/groups/groups.json`. Group names follow the pattern `<infra>-g<N>` (e.g., `mysql84-g1`, `legacy-g2`, `pgsql16-g1`).

### DO NOT

- **DO NOT** manually create Docker networks (`docker network create`)
- **DO NOT** manually start containers (`docker start`, `docker run`)
- **DO NOT** run `docker-compose-init.bash` directly — use `ensure-infras.bash`
- **DO NOT** symlink build artifacts between worktrees — build in each worktree separately
- **DO NOT** copy source files between worktrees or repos
- **DO NOT** run `cd test/tap/tests && make` and expect tests to pass without infrastructure

### Test file conventions

Test files follow the naming pattern `test_*.cpp` or `*-t.cpp` in `test/tap/tests/`.

Test binaries are built via a pattern rule in `test/tap/tests/Makefile`: `make <testname>-t` compiles `<testname>-t.cpp` into `<testname>-t`. No special Makefile target is needed for new tests — just add the `.cpp` file and register it in `groups.json`.

## Architecture

### Build Pipeline

```
deps/          → builds 25+ vendored dependencies as static libraries
lib/           → compiles ~121 .cpp files into libproxysql.a
src/main.cpp   → links against libproxysql.a to produce the proxysql binary
```

### Dual-Protocol Design

MySQL and PostgreSQL share parallel class hierarchies with the same architecture but protocol-specific implementations:

| Layer | MySQL | PostgreSQL |
|-------|-------|------------|
| Protocol | `MySQL_Protocol` | `PgSQL_Protocol` |
| Session | `MySQL_Session` | `PgSQL_Session` |
| Thread | `MySQL_Thread` | `PgSQL_Thread` |
| HostGroups | `MySQL_HostGroups_Manager` | `PgSQL_HostGroups_Manager` |
| Monitor | `MySQL_Monitor` | `PgSQL_Monitor` |
| Query Processor | `MySQL_Query_Processor` | `PgSQL_Query_Processor` |
| Logger | `MySQL_Logger` | `PgSQL_Logger` |

### Core Components

- **Admin Interface** (`ProxySQL_Admin.cpp`, `Admin_Handler.cpp`) — SQL-based configuration via SQLite3 backend. Supports runtime config changes without restart. Schema versions tracked in `ProxySQL_Admin_Tables_Definitions.h`.
- **HostGroups Manager** — Routes connections based on hostgroup assignments. Supports master-slave, Galera, Group Replication, and Aurora topologies.
- **Query Processor** — Parses queries, matches against routing rules, handles query caching via `Query_Cache`.
- **Monitor** — Health-checks backends for replication lag, read-only status, and connectivity.
- **Threading** — Event-based I/O using libev. `Base_Thread` base class with protocol-specific thread managers.
- **HTTP/REST** (`ProxySQL_HTTP_Server`, `ProxySQL_RESTAPI_Server`) — Metrics and management endpoints.

### Key Dependencies (in deps/)

- `jemalloc` — memory allocator
- `sqlite3` — admin config storage
- `mariadb-client-library` — MySQL protocol
- `postgresql` — PostgreSQL protocol
- `re2`, `pcre` — regex engines
- `libev` — event loop
- `libinjection` — SQL injection detection
- `lz4`, `zstd` — compression
- `curl`, `libmicrohttpd`, `libhttpserver` — HTTP
- `prometheus-cpp` — metrics
- `libscram` — SCRAM authentication

### Conditional Components

- **FFTO** (Fast Forward Traffic Observer) — `MySQLFFTO.cpp`, `PgSQLFFTO.cpp`
- **TSDB** — Time-series metrics with embedded dashboard
- **GenAI/MCP** — `GenAI_Thread`, `MCP_Thread`, `LLM_Bridge`, `Anomaly_Detector`, tool handlers
- **ClickHouse** — Native ClickHouse protocol support

## Code Layout

- `include/` — All headers (.h/.hpp). Include guards use `#ifndef __CLASS_*_H`.
- `lib/` — Core library sources (~121 files). One class per file typically.
- `src/main.cpp` — Entry point, daemon init, thread spawning (~95K lines).
- `test/tap/` — TAP test framework and tests.
- `test/infra/` — Docker-based test environments.
- `.github/workflows/` — CI/CD pipelines (selftests, TAP tests, package builds, CodeQL). **See `doc/GH-Actions/README.md` for the architecture overview** — ProxySQL uses a two-branch caller/reusable split (`CI-*.yml` on `v3.0`, `ci-*.yml` on the `GH-Actions` branch) and the doc is the authoritative reference for how it fits together.

## Agent Guidelines

See `doc/agents/` for detailed guidance on working with AI coding agents:
- `doc/agents/project-conventions.md` — ProxySQL-specific rules (directories, build, test harness, git workflow)
- `doc/agents/task-assignment-template.md` — Template for writing issues assignable to AI agents
- `doc/agents/common-mistakes.md` — Known agent failure patterns with prevention and detection

### Unit Test Harness

Unit tests live in `test/tap/tests/unit/` and link against `libproxysql.a` via a custom test harness. Tests must use `test_globals.h` and `test_init.h` — see `doc/agents/project-conventions.md` for the full pattern.

## Coding Conventions

- Class names: `PascalCase` with protocol prefixes (`MySQL_`, `PgSQL_`, `ProxySQL_`)
- Member variables: `snake_case`
- Constants/macros: `UPPER_SNAKE_CASE`
- C++17 required; conditional compilation via `#ifdef PROXYSQLGENAI`, `#ifdef PROXYSQL31`, etc.
- Performance-critical code — consider implications of changes to hot paths
- RAII for resource management; jemalloc for allocation
- Pthread mutexes for synchronization; `std::atomic<>` for counters
