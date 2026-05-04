# ProxySQL 3.0.4 Release Notes

This release of ProxySQL 3.0.4 includes new features, bug fixes, and improvements across PostgreSQL, MySQL, monitoring, and configuration management.

Release commit: `faa64a570d19fe35af43494db0babdee3e3cdc89`

## New Features:

### PostgreSQL:
- Add PostgreSQL-Specific Tokenizer for Query Digest Generation (0f7ff1f3, #5254)
- Add SSL support for backend connections in PGSQL monitor (d1b003a0, #5237)

### MySQL:
- Add special handling for unexpected COM_PING packets (e73ba2b6, #5257)
- Added handling of SELECT @@version and SELECT VERSION() without backend (0d55ab5e, #4889)
- [WIP] Setting client side wait_timeout (2b900b34, #4901)
- Implement Fast Forward Grace Close Feature to Prevent Data Loss (83300374, #5203)

### Monitoring:
- Add TCP keepalive warnings when disabled (issue #5212) (0c3582f1, #5228)


## Bug Fixes:

### MySQL:
- Fix: Make cur_cmd_cmnt thread-safe (91e20648, #5259)
- Fix cache_empty_result=0 not caching non-empty resultsets (issue #5248) (2987242d, #5250)
- Fix issue 4855: Incorrect affected rows reporting for DDL queries (d188715a, #5232)

### Monitoring:
- Fix artificially high ping latency in MySQL backend monitoring (24e02e95, #5199)

### Security:
- Fix SQL injection vulnerability in Read_Global_Variables_from_configfile (automatic prefix stripping) (0b2bc1bf, #5247)


## Improvements:

### Performance:
- Improve fast forward replication CLIENT_DEPRECATE_EOF validation (closes #5062) (5485bb02, #5240)
- Refactored Prepared-Statement Cache Design (Lock-Free Hot Path) - Part 2 (9c0e14a5, #5225)
- gtid: Refactor reconnect logic & prevent `events_count` reset (20975923, #5226)


## Documentation:
- Documentation additions and bug fix for vacuum_stats() (cf8cbfd8, #5258)
- Permanent FF sessions + check_data_flow docs (ec1247f2, #5245)
- [skip-ci] V3.0.agentics - Add Claude Code Agent Definitions and Architecture Documentation (291e5f02, #5115)
- docs: Add comprehensive Doxygen documentation for GTID refactoring (9a55e974, #5229)
- Add TAP test writing guide and GitHub automation improvements (49899601, #5215)


## Testing:
- Add comments to select @@version queries to bypass ProxySQL interception (66119b74, #5251)
- Add fast forward replication deprecate EOF test and update test infrastructure (closes #5062) (9df7407f, #5241)
- Add delay to let ProxySQL process mysql_stmt_close() (fa74de3c, #5198)
- regroup tests to balance group test time (41b0e96c, #5207)


## Build/Packaging:
- add opensuse16 packaging (bce71a95, #5230)


## Other Changes:
- bump version to 3.0.4 at the beginning of the development cycle (ba664785, #5200)


## Hashes

The release commit is: `faa64a570d19fe35af43494db0babdee3e3cdc89`