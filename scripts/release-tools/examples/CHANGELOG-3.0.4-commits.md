# ProxySQL 3.0.4 Detailed Changelog

This changelog includes all individual commits since ProxySQL 3.0.3.

- e73ba2b6 Fix changing server defaults for 'reg_test_unexp_ping_pkt'
  - Fixed was changing server defaults ('max_allowed_packet') in the same
- 7efc85ce Fix TAP 'groups.json' file syntax
- b9cf5b16 Remove empty spaces at end of lines for TAP tests 'groups.json'
- 91e20648 Fixed an issue where cur_cmd_cmnt was shared across threads
- 54e2b3e6 Add new test 'reg_test_unexp_ping_pkt-t' to TAP groups
- 6fea828e Improve logging in unexpected COM_PING packet handling
  Logging messages now include 'client address', 'session status' and
- 503b0975 Add new TAP test exercising unexpected COM_PING packets logic
  Also fixes 'random_string' utility function for large strings, avoiding
- d0e88599 Add special handling for unexpected COM_PING packets
  Implements a workaround for the handling of unexpected 'COM_PING'
- cf8cbfd8 Document coredump_filters feature (issue #5213)
  Add comprehensive documentation for the on‑demand core dump generation
- efe0d4fe Add extensive doxygen documentation for vacuum_stats and stats_pgsql_stat_activity
  This commit documents:
- de214cb5 Add comprehensive documentation for "Closing killed client connection" warnings
- febb650a Added Multiple Keep Comments test
- 6966b79d Add documentation for query rules capture groups and backreferences
- 5e75264b Updated TAP test
- 5b3805ad Refactored comment handling
  * Removed is_cmd (/*!) handling
- e70fcbf0 * Add dedicated handling for double-quoted PostgreSQL identifiers * Added crash payload testing * Fixed unterminated comments handling
- fd53642f Added pgsql-query_digests_stages_test-t to groups.json
- f9b9ede6 Fixed TAP test
- 39728b2d Add missing pgsql_tokenizer.cpp
- 1b16a393 Added TAP test
- 42864e88 Improved Tokenizer for PostgreSQL
  - Added `process_pg_typecast()` to handle PostgreSQL type cast syntax (::)
- 66119b74 Add comments to select @@version queries to bypass ProxySQL interception
  ProxySQL now responds directly to `select @@version` queries, which prevents
- 2987242d Fix cache_empty_result=0 not caching non-empty resultsets (issue #5248)
  The `cache_empty_result` field in query rules has three possible values:
- d1b003a0 Added TAP test to groups.json
- 0b2bc1bf Fix SQL injection vulnerability in Read_Global_Variables_from_configfile
  Replace sprintf-based SQL query construction with prepared statements using
- 0e7b5e2b Added TAP test
- fae283cf Add SSL and non-SSL connection OK metrics for PostgreSQL monitor connections Adds two new metrics, ssl_connections_OK and non_ssl_connections_OK, to improve visibility into PostgreSQL monitor connection status.
- a2068286 Add test_load_from_config_prefix_stripping-t to test groups
  Adds the new prefix stripping validation test to the default-g4 test group
- 6c97d3d2 Add extensive Doxygen documentation for ProxySQL_Config and Read_Global_Variables_from_configfile
  This commit adds detailed Doxygen documentation for:
- 7ebdf561 Fix automatic prefix stripping to work with libconfig lookup
  The previous implementation stripped the prefix before calling
- b4683569 Add automatic prefix stripping for mysql_variables, pgsql_variables, and admin_variables config parsing
  When users mistakenly include the module prefix (e.g., mysql-log_unhealthy_connections)
- ec1247f2 Add Doxygen docs for MySQL_Data_Stream::check_data_flow()
- 4044a407 Skip bidirectional data check for permanent fast-forward sessions
  Allow permanent fast-forward sessions (SESSION_FORWARD_TYPE_PERMANENT)
- 689bece9 Add CONTRIBUTING.md guide for community contributors
  - Comprehensive contribution guidelines for ProxySQL
- f5079037 Added nested comments support for PostgreSQL
- 895c814c Added utility functions to support pgsql query digest testing
- 285fb1b4 Add PostgreSQL dialect support: dollar-quoted strings, identifier quoting, and dialect-specific comment rules
  This change introduces PostgreSQL-aware tokenization by adding support for dollar-quoted strings, PostgreSQL’s double-quoted identifiers, and its comment rules. The tokenizer now correctly parses $$…$$ and $tag$…$tag$, treats " as an identifier delimiter in PostgreSQL, disables MySQL-only # comments, and accepts -- as a comment starter without requiring a trailing space. All new behavior is fully isolated behind the dialect flag to avoid impacting MySQL parsing.
- 2b900b34 Update test groups configuration
- 5a7b2218 Fix metrics collection for wait_timeout counters
  The get_status_variable() function was only scanning worker threads
- fbf5f2d7 Improve wait_timeout warning messages with detailed connection information
  Enhance logging clarity:
- dc4694d6 Refactor idle session scanning and improve test precision
  Code improvements:
- 0c5e75a0 Fix wait_timeout timeout calculations and add proper newline characters
  Key improvements:
- 0c9c938d Fix mysql-set_wait_timeout-t.cpp compilation and JSON testing
  - Replace <json/json.h> include with <json.hpp> and proper nlohmann namespace
- 6539587c test: Add comprehensive wait_timeout JSON validation tests
  - Add JSON parsing helper for PROXYSQL INTERNAL SESSION responses
- df515f91 session: Add wait_timeout to proxysql internal session JSON
  - Include wait_timeout value in session JSON output for monitoring/debugging
- 0a9dc9dd session: Add input validation for client wait_timeout with silent clamping
  - Add range validation for client SET wait_timeout commands
- 86cc7cd3 session: Fix wait_timeout member variable declaration and usage
  - Add wait_timeout member variable declaration to Base_Session class
- 9df7407f Add fast forward replication deprecate EOF test and update test infrastructure
  - Add comprehensive test `fast_forward_switch_replication_deprecate_eof.cpp` that validates
- 5485bb02 Improve fast forward replication CLIENT_DEPRECATE_EOF validation
  Enhance the match_ff_req_options function to better handle CLIENT_DEPRECATE_EOF
- 7205f424 Add SSL support for backend connections in PGSQL monitor
- 9c0e14a5 Replace rand() with lock-free Xoshiro128++ PRNG
- 1251e4d5 Add Xoshiro128++ pseudo-random number generator to replace rand()
- 291e5f02 Add AI disclaimer to ENHANCEMENT-OPPORTUNITIES.md
- 54091905 Restructure AI-generated documentation with verification framework
  - Move AI-generated docs to doc/ai-generated/ folder for clear separation
- 652acb5d cont
- 39f94b0f simplify for pr
- 644174a3 Add reg_test_4855_affected_rows_ddl to TAP test groups
  Include the regression test for issue 4855 in the g1 test group configuration
- f5128d76 Fix TAP test for issue 4855 affected rows DDL bug
  Improve the TAP test to be SQLite-compatible and comprehensive:
- a54a0ad8 Fix TAP test to use correct TAP framework functions
  - Replace made-up fail()/pass() functions with ok() and diag()
- 9df1e475 Clean up: Remove incorrect standalone test file
- 19c635b7 Fix TAP test to use proper ProxySQL connection patterns
  - Use CommandLine cl object with getEnv() for configuration
- b6b60e1a Add proper TAP test for issue 4855 fix
  - TAP test connects to ProxySQL Admin interface on port 6032
- bf4b1d92 Update TAP test for issue 4855 with standalone version
  - Updated main TAP test to remove proxy_sqlite3 wrapper dependency
- a577491f Refactor issue 4855 fix: Use sqlite3_total_changes64 difference approach
  PROBLEM:
- 05960b5d Fix issue 4855: Reset affected_rows to 0 for DDL queries in Admin interface
  Problem:
- d0ef6918 Add mysql-select_version_without_backend-t to TAP group
- 0c3582f1 Add TCP keepalive warnings test to TAP test groups
  Added reg_test_5212_tcp_keepalive_warnings-t to the default test group
- 1a48aadf Code cleanup
- bce71a95 add opensuse16 packaging
- 9a55e974 docs: Add comprehensive Doxygen documentation for GTID refactoring
  - Document addGtidInterval() function with parameter details and reconnection behavior
- 6a700cd5 Add comprehensive Doxygen documentation to get_matching_lines_from_filename()
  - Document purpose, parameters, return values, and behavior
- 19176909 Rename TAP test file to remove mysql- prefix
  - Rename mysql-reg_test_5212_tcp_keepalive_warnings-t.cpp to reg_test_5212_tcp_keepalive_warnings-t.cpp
- b1a1930e Add working TAP test for TCP keepalive warnings (issue #5212)
  - Implement get_matching_lines_from_filename() with efficient queue-based processing
- e54e3c8d Add TAP test for TCP keepalive warnings with line-limited get_matching_lines()
  - Add TAP test mysql-reg_test_5212_tcp_keepalive_warnings-t.cpp to verify TCP keepalive warnings
- 6ed82ef8 Fix crash in TCP keepalive warnings for issue #5212
  - Fix crash by using get_variable_int() instead of get_variable_string() for boolean use_tcp_keepalive variable
- cf454b8e Add TCP keepalive warnings for issue #5212
  - Add warnings in flush_mysql_variables___database_to_runtime() when mysql-use_tcp_keepalive=false
- 27923c19 Use emplace instead of insert
- 50c60284 gtid: Refactor reconnect logic & prevent `events_count` reset
  - This patch was originally added by commit 0a70fd5 and
- 187edfe1 Change assert to warning
- c0f99c0e Refactor: Improved Prepared-Statement Cache Design (Lock-Free Hot Path) #5211
  Concurrency and Memory Management
- 49899601 chore: Ignore GEMINI.md
  This file is generated by the Gemini CLI and is not part of the project.
- 546c1012 docs: Add TAP test writing guide for ProxySQL.
- 83300374 Use right user in fast_forward_grace_close
- 140745a9 Change default schema in fast_forward_grace_close
- 494dbf37 Minor enhancement in TAP fast_forward_grace_close
  Added `CREATE DATABASE IF NOT EXISTS test`
- 41b0e96c create missing database test in tap test
- 952bd39f cleanup redundant group folders
- 458ff778 regroup tests to balace group test time
- ee824c0b Removing debugging code
- 3329a671 Add extensive documentation for fast forward grace close feature
- 846c4de5 Replace spaces with tabs in fast_forward_grace_close.cpp
- dd60d266 Add fast_forward_grace_close test to groups.json
- ae939666 Add TAP test for fast forward grace close feature
  - Rename and modify test to use MySQL C API mysql_binlog_* functions
- 44aa606c Implement fast forward grace close feature to prevent data loss
  Problem: In fast forward mode, ProxySQL forwards packets directly from client
- d8444472 Replaced use of the generic write_generic() helper with direct packet construction for selected PostgreSQL protocol messages to reduce overhead and improve performance.
- ba664785 bump version to 3.0.4 at the beginning of the development cycle
- e744c2bb Optimize transaction command parsing to avoid unnecessary tokenization
  Previously, the parser always tokenized the full command, even when we only
- 7c665b9f Checking the data stream on both ends doesn’t apply to frontend connections, since response data is buffered during extended queries. Fixed TAP test
- 24e02e95 Changing monitor ping poll() timeout to 10ms
- 6a80c3f2 Implemented explicit task memory ownership management in Monitor_Poll.
- 50fae0b0 Current check on file descriptors (fd) is not reliable or necessary
- 1c3c4295 Improve ping accuracy
  - Introduced batching for ping task dispatch (default: 30 servers per batch)
- fa74de3c Add delay to let ProxySQL process mysql_stmt_close()
- 7a3a5c71 Optimize hot path: replace std::string with char[] to avoid heap
- 61ba1824 Introduce inline functions for efficient ASCII whitespace detection and uint32-to-string conversion
- 9eb934e7 Buffer response until Extended Query frame completes; send early only if resultset threshold is reached.
- 9fa3d75f Backport PQsendPipelineSync from PostgreSQL 17 and update code to use it
  - Backport PQsendPipelineSync to PostgreSQL 16.3, enabling pipeline
- 45cb1673 .aider file
- 3c08cc5f Syntax Convention library tweak, it now provides loarders and merely needs to have it's script dir in path. The  sub agents when loaded may then go and popualte and additional prompt conventions they need as they areloaded.
- 36ebee53 purge
- d946b6e3 updates from internal docs
- 89849d0d patch
- 5f15d971 patch
- 4dad6424 doc update
- 9e337ce7 TEST-PIPELINE.md doc
- e2e8d8c4 doc cleanup - remove agenetic verbage and mermaid patch
- ab2a3292 Visual Guide v0.1 checkin
- fbbefb91 initial arch entry point for agents
- a753e64c initial agent definitions
- dd0e8529 Git ignore update
- d24b81e6 Initial checkin - Claude and npl convention readmes
- 4a10ce65 Add TAP test for select @@version without backend
  Signed-off-by: Wazir Ahmed <wazir@proxysql.com>
- 97eb19c0 fix: Close idle session based on effective timeout
  - effective_timeout = min (mysql-wait_timeout, session-wait_timeout)
- fd9ce84b Add TAP test for session wait timeout
  Signed-off-by: Wazir Ahmed <wazir@proxysql.com>
- 1545fd24 Removed range check.
- d7ec497a Now taking effective timeout taking as minimum of global timeout and session timeout
- 2b5bd110 Using mysql_thread___server_version directly
- b589e58d Using global mysql version
- abe16e66 Parsing and setting wait timeout for session
- df287b20 Added handling of SELECT @@version   and  SELECT VERSION() without backend
