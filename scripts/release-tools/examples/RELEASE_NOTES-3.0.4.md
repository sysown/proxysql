# ProxySQL 3.0.4 Release Notes

ProxySQL 3.0.4 includes numerous bug fixes, improvements, and new features.

## New Features
- Add special handling for unexpected COM_PING packets [#5257](https://github.com/sysown/proxysql/pull/5257)
- Add PostgreSQL-Specific Tokenizer for Query Digest Generation [#5254](https://github.com/sysown/proxysql/pull/5254)
- Add SSL support for backend connections in PGSQL monitor [#5237](https://github.com/sysown/proxysql/pull/5237)
- Add comments to select @@version queries to bypass ProxySQL interception [#5251](https://github.com/sysown/proxysql/pull/5251)
- Added handling of SELECT @@version   and  SELECT VERSION() without backend [#4889](https://github.com/sysown/proxysql/pull/4889)
- Add fast forward replication deprecate EOF test and update test infrastructure (closes #5062) [#5241](https://github.com/sysown/proxysql/pull/5241)
- add opensuse16 packaging [#5230](https://github.com/sysown/proxysql/pull/5230)
- [skip-ci] V3.0.agentics - Add Claude Code Agent Definitions and Architecture Documentation [#5115](https://github.com/sysown/proxysql/pull/5115)
- docs: Add comprehensive Doxygen documentation for GTID refactoring [#5229](https://github.com/sysown/proxysql/pull/5229)
- Add TAP test writing guide and GitHub automation improvements [#5215](https://github.com/sysown/proxysql/pull/5215)
- Implement Fast Forward Grace Close Feature to Prevent Data Loss [#5203](https://github.com/sysown/proxysql/pull/5203)

## Bug Fixes
- Fix: Make cur_cmd_cmnt thread-safe [#5259](https://github.com/sysown/proxysql/pull/5259)
- Documentation additions and bug fix for vacuum_stats() [#5258](https://github.com/sysown/proxysql/pull/5258)
- Fix cache_empty_result=0 not caching non-empty resultsets (issue #5248) [#5250](https://github.com/sysown/proxysql/pull/5250)
- Fix: Automatic prefix stripping for mysql_variables, pgsql_variables, and admin_variables config parsing [#5247](https://github.com/sysown/proxysql/pull/5247)
- Fix artificially high ping latency in MySQL backend monitoring [#5199](https://github.com/sysown/proxysql/pull/5199)
- Fix issue 4855: Incorrect affected rows reporting for DDL queries [#5232](https://github.com/sysown/proxysql/pull/5232)
- Add TCP keepalive warnings when disabled (issue #5212) [#5228](https://github.com/sysown/proxysql/pull/5228)

## Improvements
- Improve fast forward replication CLIENT_DEPRECATE_EOF validation (closes #5062) [#5240](https://github.com/sysown/proxysql/pull/5240)
- Refactored Prepared-Statement Cache Design (Lock-Free Hot Path) - Part 2 [#5225](https://github.com/sysown/proxysql/pull/5225)
- gtid: Refactor reconnect logic & prevent `events_count` reset [#5226](https://github.com/sysown/proxysql/pull/5226)

## Documentation
- Permanent FF sessions + check_data_flow docs [#5245](https://github.com/sysown/proxysql/pull/5245)

## Testing
- Add delay to let ProxySQL process mysql_stmt_close() [#5198](https://github.com/sysown/proxysql/pull/5198)
- regroup tests to balance group test time [#5207](https://github.com/sysown/proxysql/pull/5207)

