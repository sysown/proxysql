# ProxySQL 3.0.4 Release Notes

This release of ProxySQL 3.0.4 includes significant improvements to PostgreSQL support, MySQL protocol handling, monitoring accuracy, and security.

Release commit: `faa64a570d19fe35af43494db0babdee3e3cdc89`

## New Features:

### PostgreSQL Improvements:

- **PostgreSQL-Specific Tokenizer for Query Digest Generation** (285fb1b4, #5254)
    - Adds PostgreSQL dialect support: dollar-quoted strings (`$$...$$`), identifier quoting, and dialect-specific comment rules
    - Improved tokenizer for PostgreSQL with nested comments support (f5079037)
    - Adds dedicated handling for double-quoted PostgreSQL identifiers and type cast syntax (`value::type`) (e70fcbf0)
    - Processes array literals (`ARRAY[...]` and `{...}`) and prefixed literals (`E''`, `U&''`, `x''`, `b''`)
- **SSL Support for Backend Connections in PostgreSQL Monitor** (7205f424, #5237)
    - PostgreSQL monitor now supports client certificates for SSL/TLS connections to backend servers
    - Adds new metrics `PgSQL_Monitor_ssl_connections_OK` and `PgSQL_Monitor_non_ssl_connections_OK` for connection status visibility (fae283cf)

### MySQL Protocol Enhancements:

- **Special Handling for Unexpected `COM_PING` Packets** (d0e88599, #5257)
    - Implements workaround for unexpected `COM_PING` packets received during query processing
    - Queues `COM_PING` packets as counters and sends corresponding OK packets after query completion
    - Improves logging with client address, session status, and data stream status (6fea828e)
- **Handling of `SELECT @@version` and `SELECT VERSION()` Without Backend** (df287b20, #4889)
    - ProxySQL now responds directly to `SELECT @@version` and `SELECT VERSION()` queries without backend connection
    - Returns hardcoded server version (currently 8.0.0), reducing unnecessary backend load
- **Client-Side `wait_timeout` Support** (abe16e66, #4901)
    - Adds support for client-specified `wait_timeout` values, previously ignored by ProxySQL
    - Terminates client connections (not backend) when client timeout is reached
    - Clamps client timeout to not exceed global `mysql-wait_timeout`
- **Fast Forward Grace Close Feature to Prevent Data Loss** (44aa606c, #5203)
    - Implements graceful connection closure for fast-forward sessions
    - Ensures all pending data is flushed to client before closing connection
    - Prevents data loss during connection termination in replication scenarios

### Monitoring & Diagnostics:

- **TCP Keepalive Warnings When Disabled** (cf454b8e, #5228)
    - Adds warning messages when TCP keepalive is disabled on connections
    - Helps administrators identify potential connection stability issues
    - Includes detailed connection information for troubleshooting


## Bug Fixes:

### MySQL:

- **Make `cur_cmd_cmnt` Thread-Safe** (91e20648, #5259)
    - Fixes thread-safety issue where `cur_cmd_cmnt` (current command comment) was shared across threads
- **Fix `cache_empty_result=0` Not Caching Non-Empty Resultsets** (2987242d, #5250)
    - Corrects behavior of `cache_empty_result` field in query rules
    - When set to "0", now correctly caches non-empty resultsets while skipping empty resultsets
    - Previously prevented caching of any resultsets regardless of row count
- **Incorrect Affected Rows Reporting for DDL Queries** (05960b5d, #5232)
    - Fixes issue #4855 where `mysql_affected_rows()` in ProxySQL Admin interface incorrectly reported affected rows for DDL queries
    - DDL queries now correctly return 0 affected rows instead of previous DML's count

### Monitoring:

- **Fix Artificially High Ping Latency in MySQL Backend Monitoring** (24e02e95, #5199)
    - Addresses artificially high ping latency measurements
    - Introduces batching for task dispatching (batches of 30) with `poll()` calls between batches
    - Reduces monitor ping `poll()` timeout from 100ms to 10ms for more responsive monitoring

### Security & Configuration:

- **Fix SQL Injection Vulnerability in `Read_Global_Variables_from_configfile()`** (0b2bc1bf, #5247)
    - Replaces `sprintf`-based SQL query construction with prepared statements using bound parameters
    - Fixes automatic prefix stripping for `mysql_variables`, `pgsql_variables`, and `admin_variables` config parsing (b4683569)
    - Handles cases where users mistakenly include module prefixes (e.g., "mysql-") in variable names


## Improvements:

### Performance Optimizations:

- **Improve Fast Forward Replication `CLIENT_DEPRECATE_EOF` Validation** (5485bb02, #5240)
    - Enhances validation logic for fast forward replication with `CLIENT_DEPRECATE_EOF` capability flag
    - Ensures proper handling of replication packets and improves compatibility with MySQL 8.0+ clients
- **Refactored Prepared-Statement Cache Design (Lock-Free Hot Path)** (c0f99c0e, #5225)
    - Implements lock-free hot path for prepared statement cache operations
    - Reduces contention and improves performance for high-concurrency workloads
    - Optimizes transaction command parsing to avoid unnecessary tokenization (e744c2bb)
    - Replaces `std::string` with `char[]` to avoid heap allocation in hot paths (7a3a5c71)
- **GTID: Refactor Reconnect Logic & Prevent `events_count` Reset** (50c60284, #5226)
    - Refactors GTID reconnect logic to prevent `events_count` from being reset during reconnection attempts
    - Preserves replication state and reduces unnecessary replication restarts


## Documentation:

- **Comprehensive Documentation Additions** (cf8cbfd8, #5258)
    - Query rules capture groups and backreferences documentation (6966b79d)
    - "Closing killed client connection" warnings documentation (de214cb5)
    - `coredump_filters` feature documentation addressing issue #5213
    - `vacuum_stats()` and `stats_pgsql_stat_activity` Doxygen documentation with bug fix (efe0d4fe)
- **Permanent Fast-Forward Sessions and `check_data_flow()` Documentation** (ec1247f2, #5245)
    - Documents behavior of permanent fast-forward sessions
    - Documents `MySQL_Data_Stream::check_data_flow()` method
    - Explains when bidirectional data checks are skipped for specific session types (4044a407)
- **Claude Code Agent Definitions and Architecture Documentation** (291e5f02, #5115)
    - Adds architecture documentation for Claude Code agent integration
    - Includes automation framework and internal documentation
- **Comprehensive Doxygen Documentation for GTID Refactoring** (9a55e974, #5229)
    - Adds detailed Doxygen documentation for GTID-related code changes
- **TAP Test Writing Guide and GitHub Automation Improvements** (49899601, #5215)
    - Provides comprehensive guide for writing TAP tests for ProxySQL
    - Improves GitHub automation workflows


## Testing:

- **Add Comments to `SELECT @@version` Queries to Bypass ProxySQL Interception** (66119b74, #5251)
    - Adds `/* set_testing */` comments to `SELECT @@version` queries in test files
    - Prevents ProxySQL interception, allowing queries to reach backend MySQL servers for testing
- **Add Fast Forward Replication Deprecate EOF Test and Update Test Infrastructure** (9df7407f, #5241)
    - Adds comprehensive test coverage for fast forward replication `CLIENT_DEPRECATE_EOF` validation
    - Updates test infrastructure to better handle replication scenarios
- **Add Delay to Let ProxySQL Process `mysql_stmt_close()`** (fa74de3c, #5198)
    - Adds appropriate delays in tests to allow ProxySQL time to process `mysql_stmt_close()` operations
    - Prevents race conditions in prepared statement tests
- **Regroup Tests to Balance Group Test Time** (458ff778, #5207)
    - Reorganizes test groups to balance execution time across test runners
    - Improves CI pipeline efficiency and reduces overall test runtime


## Build/Packaging:

- **Add OpenSUSE 16 Packaging Support** (bce71a95, #5230)
    - Adds packaging support for OpenSUSE 16
    - Expands supported distribution matrix for ProxySQL installations


## Other Changes:

- **Bump Version to 3.0.4 at Beginning of Development Cycle** (ba664785, #5200)
    - Updates version number to 3.0.4 at start of development cycle for clarity and version tracking


## Hashes

The release commit is: `faa64a570d19fe35af43494db0babdee3e3cdc89`