# ProxySQL 3.0.4 Detailed Changelog

This changelog lists all pull requests merged since ProxySQL 3.0.3.

## Bug Fixes
- **PR #5259**: [Fix: Make cur_cmd_cmnt thread-safe](https://github.com/sysown/proxysql/pull/5259)
- **PR #5258**: [Documentation additions and bug fix for vacuum_stats()](https://github.com/sysown/proxysql/pull/5258)
  - ## Summary
- **PR #5250**: [Fix cache_empty_result=0 not caching non-empty resultsets (issue #5248)](https://github.com/sysown/proxysql/pull/5250)
  - ## Summary
- **PR #5247**: [Fix: Automatic prefix stripping for mysql_variables, pgsql_variables, and admin_variables config parsing](https://github.com/sysown/proxysql/pull/5247)
  - ## Summary
- **PR #5199**: [Fix artificially high ping latency in MySQL backend monitoring](https://github.com/sysown/proxysql/pull/5199)
  - ### Changes Made
- **PR #5232**: [Fix issue 4855: Incorrect affected rows reporting for DDL queries](https://github.com/sysown/proxysql/pull/5232)
  - ## Summary
- **PR #5228**: [Add TCP keepalive warnings when disabled (issue #5212)](https://github.com/sysown/proxysql/pull/5228)
  - ## Summary

## Documentation
- **PR #5245**: [Permanent FF sessions + check_data_flow docs](https://github.com/sysown/proxysql/pull/5245)
  - ### Features

## Improvements
- **PR #5240**: [Improve fast forward replication CLIENT_DEPRECATE_EOF validation (closes #5062)](https://github.com/sysown/proxysql/pull/5240)
  - ## Summary

## New Features
- **PR #5257**: [Add special handling for unexpected COM_PING packets](https://github.com/sysown/proxysql/pull/5257)
  - ## Description
- **PR #5254**: [Add PostgreSQL-Specific Tokenizer for Query Digest Generation](https://github.com/sysown/proxysql/pull/5254)
  - ## Summary
- **PR #5237**: [Add SSL support for backend connections in PGSQL monitor](https://github.com/sysown/proxysql/pull/5237)
  - PostgreSQL monitor now **supports client certificates** for SSL/TLS connections to backend servers.
- **PR #5251**: [Add comments to select @@version queries to bypass ProxySQL interception](https://github.com/sysown/proxysql/pull/5251)
  - ## Summary
- **PR #4889**: [Added handling of SELECT @@version   and  SELECT VERSION() without backend](https://github.com/sysown/proxysql/pull/4889)
  - Added handling of SELECT @@version   and  SELECT VERSION() without backend.
- **PR #5241**: [Add fast forward replication deprecate EOF test and update test infrastructure (closes #5062)](https://github.com/sysown/proxysql/pull/5241)
  - ## Summary
- **PR #5230**: [add opensuse16 packaging](https://github.com/sysown/proxysql/pull/5230)
  - fixes issue #5183
- **PR #5115**: [[skip-ci] V3.0.agentics - Add Claude Code Agent Definitions and Architecture Documentation](https://github.com/sysown/proxysql/pull/5115)
  - ## Summary
- **PR #5229**: [docs: Add comprehensive Doxygen documentation for GTID refactoring](https://github.com/sysown/proxysql/pull/5229)
  - ## Summary
- **PR #5215**: [Add TAP test writing guide and GitHub automation improvements](https://github.com/sysown/proxysql/pull/5215)
  - ## Summary
- **PR #5203**: [Implement Fast Forward Grace Close Feature to Prevent Data Loss](https://github.com/sysown/proxysql/pull/5203)
  - ## Summary

## Other
- **PR #4901**: [[WIP] Setting client side wait_timeout](https://github.com/sysown/proxysql/pull/4901)
  - Setting client side wait_timeout – current ProxySQL ignores wait_timeout set by the client. If a client specifies a value for wait_timeout , ProxySQL should terminate the client connection (but not the backend connection) when said timeout is reached instead of ProxySQL’s global mysql-wait_timeout . As a further enhancement, the wait timeout specified by the client shouldn’t exceed ProxySQL’s wait_timeout . The implementation also requires adequate TAP test to verify the functionality.
- **PR #5200**: [bump version to 3.0.4 at the beginning of the development cycle](https://github.com/sysown/proxysql/pull/5200)

## Refactoring
- **PR #5225**: [Refactored Prepared-Statement Cache Design (Lock-Free Hot Path) - Part 2](https://github.com/sysown/proxysql/pull/5225)
  - ### Summary
- **PR #5226**: [gtid: Refactor reconnect logic & prevent `events_count` reset](https://github.com/sysown/proxysql/pull/5226)
  - - This patch was originally added by commit 0a70fd5 and reverted by 8d1b5b5, prior to the release of `v3.0.3`.

## Testing
- **PR #5198**: [Add delay to let ProxySQL process mysql_stmt_close()](https://github.com/sysown/proxysql/pull/5198)
  - Add delay to `test_prepare_statement_memory_usage-t` allowing ProxySQL time to process `mysql_stmt_close()`.
- **PR #5207**: [regroup tests to balance group test time](https://github.com/sysown/proxysql/pull/5207)
  - Test groups have unbalanced test run duration,

