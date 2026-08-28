# ProxySQL 3.0.4 Release Notes

This release of ProxySQL 3.0.4 brings significant enhancements to PostgreSQL compatibility, MySQL protocol robustness, monitoring accuracy, and security hardening. With improved SSL/TLS support for PostgreSQL backends, better handling of edge-case MySQL protocol packets, and numerous performance optimizations, this release strengthens ProxySQL's position as a reliable database proxy for both MySQL and PostgreSQL ecosystems.

Release commit: `faa64a570d19fe35af43494db0babdee3e3cdc89`

## Highlights

This release focuses on several key areas:

- **Enhanced PostgreSQL Support**: A PostgreSQL-specific tokenizer improves query digest generation, while SSL/TLS support for backend connections strengthens security in PostgreSQL monitoring.
- **MySQL Protocol Robustness**: Special handling for unexpected `COM_PING` packets prevents connection issues, and direct response to `SELECT @@version` queries reduces backend load.
- **Monitoring Improvements**: Fixes for artificially high ping latency provide more accurate health checks, and TCP keepalive warnings help identify potential connection stability issues.
- **Security Hardening**: A critical SQL injection vulnerability in configuration parsing has been fixed using prepared statements with bound parameters.
- **Performance Optimizations**: Lock-free hot paths for prepared statement cache operations reduce contention in high-concurrency environments.

## New Features

### PostgreSQL Improvements

ProxySQL's PostgreSQL support sees two major enhancements in this release:

**PostgreSQL-Specific Tokenizer for Query Digest Generation** (285fb1b4, #5254)
The new tokenizer adds comprehensive PostgreSQL dialect support, including dollar-quoted strings (`$$...$$`), double-quoted identifiers, type cast syntax (`value::type`), array literals (`ARRAY[...]` and `{...}`), and prefixed literals (`E''`, `U&''`, `x''`, `b''`). This improves query fingerprinting accuracy for PostgreSQL workloads, ensuring similar queries are properly grouped together for caching and analysis. The tokenizer also handles nested comments and PostgreSQL-specific comment rules, providing more reliable query parsing.

**SSL Support for Backend Connections in PostgreSQL Monitor** (7205f424, #5237)
The PostgreSQL monitor now supports client certificates for SSL/TLS connections to backend servers, enhancing security for monitored connections. New metrics `PgSQL_Monitor_ssl_connections_OK` and `PgSQL_Monitor_non_ssl_connections_OK` provide visibility into connection status, helping administrators verify SSL/TLS configuration and troubleshoot connection issues.

### MySQL Protocol Enhancements

Several improvements make ProxySQL more robust when handling MySQL protocol edge cases:

**Special Handling for Unexpected `COM_PING` Packets** (d0e88599, #5257)
Some MySQL clients occasionally send `COM_PING` packets during query processing, which previously caused connection issues. ProxySQL now queues these unexpected `COM_PING` packets as counters and sends corresponding OK packets after query completion, maintaining connection stability without interrupting normal query flow. Enhanced logging includes client address, session status, and data stream status for better debugging.

**Handling of `SELECT @@version` and `SELECT VERSION()` Without Backend** (df287b20, #4889)
To reduce unnecessary backend load, ProxySQL now responds directly to `SELECT @@version` and `SELECT VERSION()` queries without establishing backend connections. It returns a hardcoded server version (currently 8.0.0), which is sufficient for most client compatibility checks while conserving backend resources.

**Client-Side `wait_timeout` Support** (abe16e66, #4901)
Previously, ProxySQL ignored client-specified `wait_timeout` values, using only the global `mysql-wait_timeout` setting. Now, ProxySQL respects client timeout requests, terminating client connections (but not backend connections) when the client timeout is reached. As a safety measure, client timeouts are clamped to not exceed the global `mysql-wait_timeout` value.

**Fast Forward Grace Close Feature to Prevent Data Loss** (44aa606c, #5203)
For fast-forward replication sessions, ProxySQL now implements graceful connection closure that ensures all pending data is flushed to the client before closing the connection. This prevents data loss during connection termination in replication scenarios, improving data consistency and reliability.

### Monitoring & Diagnostics

Improved visibility into connection health and configuration issues:

**TCP Keepalive Warnings When Disabled** (cf454b8e, #5228)
When TCP keepalive is disabled on connections, ProxySQL now emits warning messages to help administrators identify potential connection stability issues. These warnings include detailed connection information for troubleshooting, making it easier to detect misconfigured environments that might experience unexpected connection drops.

## Bug Fixes

This release addresses several critical issues affecting thread safety, caching behavior, monitoring accuracy, and security:

### MySQL

**Make `cur_cmd_cmnt` Thread-Safe** (91e20648, #5259)
The `cur_cmd_cmnt` (current command comment) variable was shared across threads, creating potential race conditions in multi-threaded environments. This fix ensures thread-safe access, preventing inconsistent behavior when multiple threads process queries simultaneously.

**Fix `cache_empty_result=0` Not Caching Non-Empty Resultsets** (2987242d, #5250)
The `cache_empty_result` field in query rules had incorrect behavior when set to "0". Previously, it prevented caching of any resultsets regardless of row count. Now, it correctly caches non-empty resultsets while skipping empty resultsets, aligning with the documented behavior and improving cache efficiency.

**Incorrect Affected Rows Reporting for DDL Queries** (05960b5d, #5232)
Issue #4855 identified that `mysql_affected_rows()` in the ProxySQL Admin interface incorrectly reported affected rows for DDL queries, showing the previous DML's count instead of 0. DDL queries now correctly return 0 affected rows, providing accurate metadata to administrative tools and scripts.

### Monitoring

**Fix Artificially High Ping Latency in MySQL Backend Monitoring** (24e02e95, #5199)
The MySQL backend monitor was reporting artificially high ping latency due to inefficient task dispatching. This fix introduces batching (batches of 30) with `poll()` calls between batches and reduces the monitor ping `poll()` timeout from 100ms to 10ms. These changes provide more responsive monitoring with accurate latency measurements.

### Security & Configuration

**Fix SQL Injection Vulnerability in `Read_Global_Variables_from_configfile()`** (0b2bc1bf, #5247)
A critical security vulnerability in configuration parsing has been addressed by replacing `sprintf`-based SQL query construction with prepared statements using bound parameters. The fix also handles automatic prefix stripping for `mysql_variables`, `pgsql_variables`, and `admin_variables` config parsing, preventing SQL injection attacks when users mistakenly include module prefixes (e.g., "mysql-") in variable names.

## Improvements

Performance and stability enhancements across replication, prepared statements, and GTID handling:

### Performance Optimizations

**Improve Fast Forward Replication `CLIENT_DEPRECATE_EOF` Validation** (5485bb02, #5240)
Enhanced validation logic for fast forward replication with the `CLIENT_DEPRECATE_EOF` capability flag ensures proper handling of replication packets and improves compatibility with MySQL 8.0+ clients. This prevents protocol mismatches and connection issues in replication scenarios.

**Refactored Prepared-Statement Cache Design (Lock-Free Hot Path)** (c0f99c0e, #5225)
Significant performance improvements for high-concurrency workloads through a lock-free hot path for prepared statement cache operations. The redesign reduces contention by optimizing transaction command parsing to avoid unnecessary tokenization and replacing `std::string` with `char[]` to eliminate heap allocation in hot paths.

**GTID: Refactor Reconnect Logic & Prevent `events_count` Reset** (50c60284, #5226)
Refactored GTID reconnect logic prevents `events_count` from being reset during reconnection attempts, preserving replication state and reducing unnecessary replication restarts. This improves replication stability and reduces overhead during network interruptions.

## Documentation

Extended documentation improves code maintainability and provides better guidance for developers and administrators:

**Comprehensive Documentation Additions** (cf8cbfd8, #5258)
Extended documentation includes query rules capture groups and backreferences, "Closing killed client connection" warnings, `coredump_filters` feature addressing issue #5213, and `vacuum_stats()` with `stats_pgsql_stat_activity` Doxygen documentation including bug fixes.

**Permanent Fast-Forward Sessions and `check_data_flow()` Documentation** (ec1247f2, #5245)
Documents behavior of permanent fast-forward sessions and the `MySQL_Data_Stream::check_data_flow()` method, explaining when bidirectional data checks are skipped for specific session types.

**Claude Code Agent Definitions and Architecture Documentation** (291e5f02, #5115)
Adds architecture documentation for Claude Code agent integration, including automation framework and internal documentation for AI-assisted development workflows.

**Comprehensive Doxygen Documentation for GTID Refactoring** (9a55e974, #5229)
Detailed Doxygen documentation for GTID-related code changes, improving code maintainability and developer onboarding.

**TAP Test Writing Guide and GitHub Automation Improvements** (49899601, #5215)
Provides a comprehensive guide for writing TAP tests for ProxySQL and improves GitHub automation workflows for continuous integration.

## Testing

Enhanced test coverage and infrastructure improvements ensure reliability:

**Add Comments to `SELECT @@version` Queries to Bypass ProxySQL Interception** (66119b74, #5251)
Adds `/* set_testing */` comments to `SELECT @@version` queries in test files, preventing ProxySQL interception and allowing queries to reach backend MySQL servers for accurate testing.

**Add Fast Forward Replication Deprecate EOF Test and Update Test Infrastructure** (9df7407f, #5241)
Adds comprehensive test coverage for fast forward replication `CLIENT_DEPRECATE_EOF` validation and updates test infrastructure to better handle replication scenarios.

**Add Delay to Let ProxySQL Process `mysql_stmt_close()`** (fa74de3c, #5198)
Adds appropriate delays in tests to allow ProxySQL time to process `mysql_stmt_close()` operations, preventing race conditions in prepared statement tests.

**Regroup Tests to Balance Group Test Time** (458ff778, #5207)
Reorganizes test groups to balance execution time across test runners, improving CI pipeline efficiency and reducing overall test runtime.

## Build/Packaging

Expanded platform support for broader deployment options:

**Add OpenSUSE 16 Packaging Support** (bce71a95, #5230)
Adds packaging support for OpenSUSE 16, expanding the supported distribution matrix for ProxySQL installations and making it easier for OpenSUSE users to deploy ProxySQL.

## Other Changes

Administrative updates for better development workflow:

**Bump Version to 3.0.4 at Beginning of Development Cycle** (ba664785, #5200)
Updates version number to 3.0.4 at the start of the development cycle for clarity and version tracking, ensuring consistent version references throughout the development process.

## Hashes

The release commit is: `faa64a570d19fe35af43494db0babdee3e3cdc89`