# ProxySQL 3.0.6 / 4.0.6 Release Notes (DRAFT)

> **Status:** DRAFT - Work in progress
> **Last updated:** 2026-02-23
> **Commit range:** `7e9e00997d7d9fa4811c86c3a3bec9c886386e1f` (excluded) to current HEAD
> **Total commits in range:** 725+

---

## Version Overview

ProxySQL 3.0.x and 4.0.x share the same codebase. The key difference is:

| Feature | 3.0.6 | 4.0.6 |
|---------|-------|-------|
| Core proxy functionality | ✅ | ✅ |
| MySQL protocol support | ✅ | ✅ |
| PostgreSQL protocol support | ✅ | ✅ |
| Query routing & caching | ✅ | ✅ |
| Monitoring & metrics | ✅ | ✅ |
| **MCP Server** | ❌ | ✅ |
| **GenAI Integration** | ❌ | ✅ |
| **RAG Capabilities** | ❌ | ✅ |
| **NL2SQL** | ❌ | ✅ |
| **Vector Search** | ❌ | ✅ |

To build 4.0.6 with GenAI features: `make PROXYSQLGENAI=1`

---

## Major New Features

### Features for Both 3.0.6 and 4.0.6

#### Fast Forward Traffic Observer (FFTO)

Real-time traffic inspection and analysis for MySQL and PostgreSQL backends, capturing detailed metrics without impacting query performance.

**Key capabilities:**
- Non-intrusive traffic observation for MySQL and PostgreSQL
- Binary protocol support for prepared statements
- Capture of `affected_rows` and `rows_sent` metrics
- Session-level tracking and metrics aggregation

**New tables:**
- `ffto_metrics` - Traffic observation statistics
- `ffto_sessions` - Active session tracking

#### Time Series Database (TSDB)

Built-in time series storage for historical metrics, enabling trend analysis and capacity planning.

**Key capabilities:**
- Persistent storage of historical metrics
- REST API for external access
- Web UI dashboard
- Prometheus-compatible metrics ingestion

**New admin commands:**
- `SHOW TSDB STATUS`
- `SHOW TSDB VARIABLES`

#### Noise Testing Framework

New framework for testing ProxySQL under realistic load conditions with background traffic simulation.

#### Query Processor Enhancements

- New `{mysql,pgsql}-query_processor_first_comment_parsing` variable
- Optimizer hints `/*+ */` handling in query tokenizers
- Improved query digest generation

---

### Features Exclusive to 4.0.6 (GenAI Build)

> ⚠️ **Note:** These features require building with `PROXYSQLGENAI=1`

#### Model Context Protocol (MCP) Server

Built-in MCP server enabling AI agents and LLMs to interact with ProxySQL's administration interface.

**Key capabilities:**
- Execute SQL queries through MCP tools (`run_sql_readonly`, `run_sql_write`)
- Access `stats` tables for monitoring
- Profile-based routing with `target_id` support
- SSL/HTTPS transport support

**New configuration variables:**
- `mcp_enabled`, `mcp_port`, `mcp_socket_dir`, `mcp_ssl_enabled`

**New tables:**
- `mcp_query_rules`, `mcp_query_digests`

#### GenAI Integration & RAG

Comprehensive GenAI integration with Retrieval-Augmented Generation support.

**Key capabilities:**
- Vector database integration (sqlite-vec)
- Embedding generation and storage
- Anomaly detection for query patterns
- NL2SQL (Natural Language to SQL)
- Document ingestion for RAG

**New tables:**
- `genai_embeddings`, `genai_documents`, `genai_models`, `vector_db`

**New configuration variables:**
- `genai_enabled`, `genai_api_key`, `genai_model`

---

## Bug Fixes

### PostgreSQL

- Fix PostgreSQL deadlock with Close Statement flood exceeding `threshold_resultset_size`
- Fix PostgreSQL prepared statement purge race condition
- Fix uninitialized memory read in pgsql tokenizer
- Fix crash on macOS/FreeBSD when running PostgreSQL queries
- Fix wrong index in connection cleanup loops (MySQL and PgSQL)
- PGSQL advanced logging improvements and hardening

### MySQL

- Fix MySQL Monitor assertion failure in DEBUG builds
- Fix SQLite3 server support for MySQL client '8.1.0'
- Fix MySQL 8.4 build on macOS with C++20 compatibility patch

### Core

- Fix SIGSEGV caused by double-finalize of `sqlite3_stmt`
- Fix memory corruption and stack overflow in FFTO due to large queries
- Fix race condition in `monitor_connect_thread`
- Fix uninitialized `mondb` pointer in MySQL_Monitor_State_Data constructor
- Fix memory leak in stats processlist functions
- Security: Fix SQL injection vulnerabilities in SQLite catalog queries

### Query Processor

- Fix: Handle optimizer hints `/*+ */` correctly in query tokenizers
- Tokenizer: Fix type mismatch for grouping limit variables

---

## Improvements

### Performance

- Optimize query logging performance (PR #5243)
- Improve async ping mmsd ownership tracking and pool validation
- RAII-based `prepare_v2` API migration across codebase

### Refactoring

- Migrate RSA key generation to OpenSSL 3.0 EVP_PKEY API
- Migrate `prepare_v2` to RAII API in MySQL_Logger, MySQL_Monitor, PgSQL_Monitor
- Improve macOS build system OpenSSL detection

---

## New Configuration Variables

### Both Versions (3.0.6 & 4.0.6)

| Variable | Description |
|----------|-------------|
| `mysql-query_processor_first_comment_parsing` | Control comment parsing in query processor |
| `pgsql-query_processor_first_comment_parsing` | Control comment parsing in query processor |
| `tsdb_enabled` | Enable/disable TSDB |
| `tsdb_retention_days` | TSDB data retention period |

### 4.0.6 Only (GenAI Build)

| Variable | Description |
|----------|-------------|
| `mcp_enabled` | Enable/disable MCP server |
| `mcp_port` | MCP server TCP port |
| `mcp_socket_dir` | MCP Unix socket directory |
| `mcp_ssl_enabled` | Enable MCP SSL/HTTPS |
| `genai_enabled` | Enable/disable GenAI features |
| `genai_api_key` | API key for LLM services |
| `genai_model` | Model identifier for completions |

---

## Build System Changes

- Rust toolchain now optional, only required when `PROXYSQLGENAI=1`
- Dynamic linking architecture improvements with rpath configuration
- libtap transitioned to static archive with bundled dependencies
- macOS compatibility improvements (headers, types, Makefile linking)
- Docker build image versions updated

---

## Testing

- Noise injection framework for realistic load testing
- New TAP tests for FFTO, MCP, GenAI, TSDB, RAG
- PostgreSQL and MySQL v2 noise routines
- Expanded test coverage across protocols

---

## Documentation

- FFTO design documentation (`doc/ffto_design.md`)
- MCP documentation (`doc/MCP/`)
- TSDB documentation (`doc/tsdb/`)
- RAG documentation (`doc/rag-documentation.md`)
- macOS build instructions (`doc/BUILD-MACOS.md`)

---

## Contributors

This release includes contributions from:

- **René Cannaò** (604+ commits)
- **Rahim Kanji** (56 commits)
- **Wazir Ahmed** (25 commits)
- **Miro Stauder** (11 commits)
- **Javier Jaramago Fernández** (10 commits)
- **Jesmar Cannaò** (6 commits)
- **Juan Manuel Fernández García-Minguillán** (4 commits)
- **vramesha** (3 commits)
- **Evgeny Kuzin** (2 commits)

---

## TODO / Pending Review

- [ ] Verify all commit references are accurate
- [ ] Add PR numbers for all merged changes
- [ ] Update commit count when final
- [ ] Review version-specific feature list
- [ ] Add upgrade notes if needed
- [ ] Final review of breaking changes

---

## Changelog Files

For detailed commit lists, see:
- `doc/release-notes/CHANGELOG-3.0.6-4.0.6-commits.md` - All commits categorized
- `doc/release-notes/CHANGELOG-3.0.6-4.0.6-detailed.md` - Full commit details
