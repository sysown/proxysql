# ProxySQL 3.0.6 / 4.0.6 - Detailed Changelog

> **Generated:** 2026-02-23
> **Commit range:** `7e9e00997d7d9fa4811c86c3a3bec9c886386e1f`..HEAD
> **Total commits:** 725

---

## All Commits (Most Recent First)

### 6be9dd1bf - 2026-02-23
**fix: Address AI code review feedback from PR #5410**
*Rene Cannao <rene@proxysql.com>*

### 178f679fa - 2026-02-23
**fix: Handle optimizer hints /*+ */ correctly in query tokenizers**
*Rene Cannao <rene@proxysql.com>*

### 630277ed3 - 2026-02-22
**fix: Fix pgsql-issue5384-t test and skip failing tests**
*Rene Cannao <rene@proxysql.com>*

### 26d3d1fce - 2026-02-22
**fix: Skip failing tests in issue5384-t due to feature regression**
*Rene Cannao <rene@proxysql.com>*

### b143f61b9 - 2026-02-22
**fix: Fix issue5384-t test - column name and result handling**
*Rene Cannao <rene@proxysql.com>*

### 05b723c25 - 2026-02-22
**test: Add descriptive diag messages to all test_ffto_* tests**
*Rene Cannao <rene@proxysql.com>*

### 96b1a8ff3 - 2026-02-22
**fix: Fix test_ffto_pgsql-t test failures**
*Rene Cannao <rene@proxysql.com>*

### fbcfd4613 - 2026-02-22
**test: Add descriptive diag messages to all test_mcp_* shell scripts**
*Rene Cannao <rene@proxysql.com>*

### 27294a0ac - 2026-02-22
**test: Increase PROXYSQLTEST 1 rows from 20 to 100 in mcp_show_queries_topk-t**
*Rene Cannao <rene@proxysql.com>*

### b5843e1a8 - 2026-02-22
**test: Add visual output for top queries in mcp_show_queries_topk-t**
*Rene Cannao <rene@proxysql.com>*

### 89646984e - 2026-02-22
**fix: Check transport success instead of is_success for disabled tool test**
*Rene Cannao <rene@proxysql.com>*

### b4c80bb31 - 2026-02-22
**fix: Disable CTE test in mcp_query_run_sql_readonly-t for MySQL 5.7**
*Rene Cannao <rene@proxysql.com>*

### fa6b89093 - 2026-02-22
**fix: Fix mcp_module-t test failures**
*Rene Cannao <rene@proxysql.com>*

### 4203cbeec - 2026-02-22
**test: Add descriptive diag() messages to all MCP TAP tests**
*Rene Cannao <rene@proxysql.com>*

### 76822032a - 2026-02-22
**feat: Add SSL/HTTPS support to MCPClient and fix mcp_stats_refresh-t**
*Rene Cannao <rene@proxysql.com>*

### 70647fb42 - 2026-02-22
**fix: Remove unused legacy mcp-mysql_* variables**
*Rene Cannao <rene@proxysql.com>*

### 723c2daab - 2026-02-22
**fix: Add missing get_mcp_variable function to mcp_runtime_variables-t**
*Rene Cannao <rene@proxysql.com>*

### 9b5d52308 - 2026-02-22
**fix: Use legacy prepare_v2 for conditional statement preparation**
*Rene Cannao <rene@proxysql.com>*

### de60fe2b3 - 2026-02-22
**fix: Use db->execute() for runtime_global_variables inserts**
*Rene Cannao <rene@proxysql.com>*

### 893ccd2aa - 2026-02-22
**test: Add mcp_runtime_variables-t to verify runtime_global_variables**
*Rene Cannao <rene@proxysql.com>*

### 7479f2168 - 2026-02-22
**fix: Only prepare runtime_global_variables stmt when runtime=true**
*Rene Cannao <rene@proxysql.com>*

### 8b1fb84d5 - 2026-02-22
**fix: Populate runtime_global_variables for MCP variables**
*Rene Cannao <rene@proxysql.com>*

### 89da8324e - 2026-02-22
**test: Add retry mechanism for MCP server startup in mcp_stats_refresh-t**
*Rene Cannao <rene@proxysql.com>*

### a44c0149f - 2026-02-22
**test: Add missing MCP tests to ai-g1 group in groups.json**
*Rene Cannao <rene@proxysql.com>*

### e53d2c76f - 2026-02-22
**Address PR #5410 review findings across FFTO, sessions, TAP, and docs**
*Rene Cannao <rene@proxysql.com>*

### 79c0b383e - 2026-02-22
**integration: fix pre-CI issues in unified branch**
*Rene Cannao <rene@proxysql.com>*

### acef17a8c - 2026-02-22
**Merge branch 'v3.0-ff_inspect' into v3.0-unified-large-pr**
*Rene Cannao <rene@proxysql.com>*

### e2ebc0c44 - 2026-02-22
**Merge branch 'v4.0-mcp-stats2' into v3.0-unified-large-pr**
*Rene Cannao <rene@proxysql.com>*

### 09e049953 - 2026-02-22
**Merge branch 'v3.0-noise-testing' into v3.0-unified-large-pr**
*Rene Cannao <rene@proxysql.com>*

### 54bcb5eec - 2026-02-22
**Merge branch 'v3.0-5384' into v3.0-unified-large-pr**
*Rene Cannao <rene@proxysql.com>*

### 9f0d9d99c - 2026-02-22
**test: add test_noise_injection-t to default-g3 group in groups.json**
*Rene Cannao <rene@proxysql.com>*

### 378c13cdd - 2026-02-22
**test: add existence checks for DB and tables in v2 noise routines**
*Rene Cannao <rene@proxysql.com>*

### e8253cac1 - 2026-02-22
**test: extend summary reports for v2 noise routines**
*Rene Cannao <rene@proxysql.com>*

### 3710bb621 - 2026-02-22
**test: implement multi-table and protocol support in v2 noise routines**
*Rene Cannao <rene@proxysql.com>*

### 00fef8d82 - 2026-02-22
**test: expand v2 noise routines with multi-table and protocol support**
*Rene Cannao <rene@proxysql.com>*

### 06a067baf - 2026-02-22
**test: expand noise injection to more PostgreSQL tests**
*Rene Cannao <rene@proxysql.com>*

### 0ffeeacd8 - 2026-02-22
**test: harden MySQL and PgSQL v2 noise routines**
*Rene Cannao <rene@proxysql.com>*

### 3a2513c73 - 2026-02-22
**test: inject MySQL v2 and Prometheus noise into PostgreSQL tests**
*Rene Cannao <rene@proxysql.com>*

### 90462f6d5 - 2026-02-22
**ffto: harden MySQL/PgSQL observer state handling and align tests/docs**
*Rene Cannao <rene@proxysql.com>*

### f36eb318b - 2026-02-22
**test: implement and document internal_noise_mysql_traffic_v2**
*Rene Cannao <rene@proxysql.com>*

### 0691b8a85 - 2026-02-22
**build: address reviewer feedback and finalize dynamic linking architecture**
*Rene Cannao <rene@proxysql.com>*

### 5519080ac - 2026-02-22
**mcp stats: address review findings and remove --genai CLI flag**
*Rene Cannao <rene@proxysql.com>*

### 598846852 - 2026-02-22
**Query Processor: re-initialize parser on rewritten queries and enhance test coverage**
*Rene Cannao <rene@proxysql.com>*

### 788be4adb - 2026-02-22
**build: restore dynamic linking and configure rpath for shared dependencies**
*Rene Cannao <rene@proxysql.com>*

### 4f94815e3 - 2026-02-22
**build: update .gitignore to exclude test artifacts and temp build files**
*Rene Cannao <rene@proxysql.com>*

### ba893e7ce - 2026-02-22
**build: transition libtap to static archive and bundle dependencies**
*Rene Cannao <rene@proxysql.com>*

### 2b710e518 - 2026-02-22
**Merge pull request #5401 from sysown/v3.0_fix-pgsql-extended-query-routing_5387**
*René Cannaò <rene@proxysql.com>*

### 63e46acfa - 2026-02-22
**Merge pull request #5409 from sysown/v3.0-ai260221**
*René Cannaò <rene@proxysql.com>*

### a00abfa36 - 2026-02-22
**test: expand noise injection to 20+ TAP tests and update build system**
*Rene Cannao <rene@proxysql.com>*

### df76a3dc0 - 2026-02-22
**test: implement comprehensive noise injection across MySQL TAP tests**
*Rene Cannao <rene@proxysql.com>*

### d1d7f4df9 - 2026-02-22
**test: implement configurable delays and unambiguous logging in noise v2**
*Rene Cannao <rene@proxysql.com>*

### 09284faea - 2026-02-22
**test: refine PgSQL noise v2 and update integrated tests**
*Rene Cannao <rene@proxysql.com>*

### ceb89fb91 - 2026-02-21
**test: inject background noise into multiple TAP tests**
*Rene Cannao <rene@proxysql.com>*

### f15a7028a - 2026-02-21
**test: implement detailed noise failure reporting and enhanced REST poller**
*Rene Cannao <rene@proxysql.com>*

### 925cc1a90 - 2026-02-21
**test: add test_noise_injection-t to verify noise framework**
*Rene Cannao <rene@proxysql.com>*

### 43d535465 - 2026-02-21
**test: enhance noise framework with specialized parameters and REST poller**
*Rene Cannao <rene@proxysql.com>*

### 03f5f9b31 - 2026-02-21
**test: fix test_admin_stats-t failure by clearing persistent history**
*Rene Cannao <rene@proxysql.com>*

### 3ccf0982e - 2026-02-21
**AI: Fix retry logic bug and synchronize TAP tests**
*Rene Cannao <rene@proxysql.com>*

### 3240a3a94 - 2026-02-21
**Fix SIGSEGV caused by double-finalize of sqlite3_stmt**
*Rene Cannao <rene@proxysql.com>*

### d2f27dab7 - 2026-02-21
**Merge pull request #5404 from sysown/v3.0-misc0221**
*René Cannaò <rene@proxysql.com>*

### 2b857cd4b - 2026-02-21
**Update NOISE_TESTING.md with dynamic options and TAP plan details**
*Rene Cannao <rene@proxysql.com>*

### 496f67c7a - 2026-02-21
**Enhance Noise Injection robustness and error handling**
*Rene Cannao <rene@proxysql.com>*

### 1dbd2d860 - 2026-02-21
**Implement Robust Noise Injection Framework for TAP Tests**
*Rene Cannao <rene@proxysql.com>*

### ddc06660a - 2026-02-21
**Integrate background noise into major TAP tests**
*Rene Cannao <rene@proxysql.com>*

### 0f3fa7bb0 - 2026-02-21
**Add cross-protocol internal noise routines (MySQL + PgSQL)**
*Rene Cannao <rene@proxysql.com>*

### 3abc81925 - 2026-02-21
**Expand internal noise routines and add PostgreSQL support**
*Rene Cannao <rene@proxysql.com>*

### 3018a3e0e - 2026-02-21
**Implement Noise Injection framework for TAP tests**
*Rene Cannao <rene@proxysql.com>*

### 932e07464 - 2026-02-21
**Fix reg_test_3847_admin_lock-t by using correct admin credentials and adding diagnostics**
*Rene Cannao <rene@proxysql.com>*

### a1f97a4e4 - 2026-02-21
**Fix test_match_eof_conn_cap failures due to audit log buffering and rotation**
*Rene Cannao <rene@proxysql.com>*

### 8073b19e0 - 2026-02-21
**Fix test_cluster_sync-t failure by skipping non-existent global variable**
*Rene Cannao <rene@proxysql.com>*

### fafe114cf - 2026-02-21
**Fix Prometheus metrics TAP test and add Doxygen documentation**
*Rene Cannao <rene@proxysql.com>*

### 2dda65ca0 - 2026-02-21
**Move deprecated TAP test to test/tap/deprecated/**
*Rene Cannao <rene@proxysql.com>*

### 0f2d606dd - 2026-02-21
**Update test_log_last_insert_id-t to handle query log buffering**
*Rene Cannao <rene@proxysql.com>*

### 364767819 - 2026-02-20
**Merge pull request #5399 from sysown/v3.0_3596_3597**
*René Cannaò <rene@proxysql.com>*

### 7b33b282b - 2026-02-20
**Fix compilation error in issue5384-t TAP test**
*Rene Cannao <rene@proxysql.com>*

### 1dbe9fde9 - 2026-02-20
**Merge pull request #5385 from sysown/v3.0-2233**
*René Cannaò <rene@proxysql.com>*

### 458b0db31 - 2026-02-20
**Fix reg_test_2233: Use match_pattern in diagnostic query**
*Jesmar Cannaò <jesmar@sysown.com>*

### 1375d4fe8 - 2026-02-20
**Fix reg_test_2233: Set default_schema='main' for test user**
*Jesmar Cannaò <jesmar@sysown.com>*

### 1c25787b8 - 2026-02-20
**Introduce {mysql,pgsql}-query_processor_first_comment_parsing variable (#5384)**
*Rene Cannao <rene@proxysql.com>*

### ca73b9ece - 2026-02-20
**Tokenizer: fix type mismatch for grouping limit variables**
*Rene Cannao <rene@proxysql.com>*

### b64f2e561 - 2026-02-20
**Merge pull request #5389 from sysown/v3.0-5243**
*René Cannaò <rene@proxysql.com>*

### 797d4b580 - 2026-02-20
**mcp stats: move show_users to in-memory auth snapshots**
*Rene Cannao <rene@proxysql.com>*

### 51a039507 - 2026-02-19
**Comprehensive FFTO Enhancements: Performance, Robustness, and Security**
*Rene Cannao <rene@proxysql.com>*

### 1258a1f2f - 2026-02-19
**Address PR reviews: improve performance, safety, and robustness of FFTO**
*Rene Cannao <rene@proxysql.com>*

### db04a54c9 - 2026-02-19
**Fix memory corruption and stack overflow in FFTO due to large queries**
*Rene Cannao <rene@proxysql.com>*

### 194e20b3e - 2026-02-20
**Revert "Reset current_hostgroup to default when no query rule matches"**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 3f7479bd0 - 2026-02-19
**Improve reg_test_2233: Add cleanup and user creation**
*Jesmar Cannaò <jesmar@sysown.com>*

### 5d786520b - 2026-02-19
**Merge remote-tracking branch 'origin/v3.0' into merge/v3.0-into-v3.0-5243**
*Rene Cannao <rene@proxysql.com>*

### 5d45d1745 - 2026-02-19
**mcp stats: split connection metrics from debug free-pool snapshots**
*Rene Cannao <rene@proxysql.com>*

### f93432ab0 - 2026-02-19
**TAP MCP stats: add mixed-load profile/churn runners and enhance mixed stress configurability**
*Rene Cannao <rene@proxysql.com>*

### deccf0ae0 - 2026-02-19
**TAP MCP stats: add MySQL stress test and mixed MySQL+PgSQL concurrent stress test**
*Rene Cannao <rene@proxysql.com>*

### 9e157d2aa - 2026-02-19
**Merge pull request #5383 from sysown/v3.0-tsdb-feature**
*René Cannaò <rene@proxysql.com>*

### e762f91cd - 2026-02-19
**MCP stats: add in-memory processlist filtering and PgSQL concurrency stress TAP**
*Rene Cannao <rene@proxysql.com>*

### 9c6945fae - 2026-02-19
**Merge branch 'v3.0' into v3.0-tsdb-feature**
*René Cannaò <rene@proxysql.com>*

### c1035dd90 - 2026-02-19
**Update .gitignore to ignore .gemini and other workspace files**
*Rene Cannao <rene@proxysql.com>*

### 9a630a949 - 2026-02-18
**Add extended Doxygen documentation for FFTO classes**
*Rene Cannao <rene@proxysql.com>*

### ea7cbaff5 - 2026-02-18
**Finalize FFTO TAP test setup and add startup debug log**
*Rene Cannao <rene@proxysql.com>*

### 40aff577a - 2026-02-18
**Complete FFTO implementation with verified metrics and robust error handling**
*Rene Cannao <rene@proxysql.com>*

### 70b61a86e - 2026-02-18
**MCP stats: implement in-memory show_queries Top-K path**
*Rene Cannao <rene@proxysql.com>*

### bad7ce40c - 2026-02-18
**Merge pull request #5391 from sysown/v3.0_pgsql_advanced_logging**
*René Cannaò <rene@proxysql.com>*

### c126e63a2 - 2026-02-18
**mcp stats: refresh stats tables under admin mutex before direct reads**
*Rene Cannao <rene@proxysql.com>*

### f3d4153e7 - 2026-02-18
**Final FFTO implementation and verification fixes**
*Rene Cannao <rene@proxysql.com>*

### 33fce1ca3 - 2026-02-18
**MCP stats: address review findings and add detailed docs**
*Rene Cannao <rene@proxysql.com>*

### 4a6809b60 - 2026-02-18
**Merge branch 'v3.0' into v3.0-tsdb-feature**
*René Cannaò <rene@proxysql.com>*

### ef397f9f1 - 2026-02-18
**Fix TSDB variable patterns and backend monitor runtime source**
*Rene Cannao <rene@proxysql.com>*

### 2a1b19916 - 2026-02-18
**test(tap): register pgsql_query_logging_autodump-t in test groups**
*Rene Cannao <rene@proxysql.com>*

### 5256f3d77 - 2026-02-18
**Merge pull request #5388 from sysown/v3.0_fix-pgsql-extended-query-routing_5387**
*René Cannaò <rene@proxysql.com>*

### c5f370ba4 - 2026-02-18
**Fix crash on NULL resultset in admin_large_pkts test**
*Rene Cannao <rene@proxysql.com>*

### 42acaf8ae - 2026-02-18
**Add reg_test_5389-flush_logs_no_drop to test groups**
*Rene Cannao <rene@proxysql.com>*

### 82a28a2e6 - 2026-02-18
**fix(pgsql-eventslog): close remaining minor review findings in logger internals**
*Rene Cannao <rene@proxysql.com>*

### 43117471b - 2026-02-18
**Fix TAP plan count and variable-restore fallback**
*Rene Cannao <rene@proxysql.com>*

### 2c4287b7a - 2026-02-18
**Fix TAP plan count in flush logs race test**
*Rene Cannao <rene@proxysql.com>*

### 3dfd6a97d - 2026-02-18
**Fix FFTO metric parity: capture and report affected_rows and rows_sent**
*Rene Cannao <rene@proxysql.com>*

### 17092487c - 2026-02-18
**Add protocol-labeled logger counters and FLUSH LOGS race TAP**
*Rene Cannao <rene@proxysql.com>*

### ab7d9187c - 2026-02-18
**test(pgsql-eventslog): improve autodump assertion diagnostics and runtime cleanup**
*Rene Cannao <rene@proxysql.com>*

### 6db089883 - 2026-02-18
**fix(admin): improve PGSQL eventslog dump failure reporting and stats insert path**
*Rene Cannao <rene@proxysql.com>*

### 0aa3c5e15 - 2026-02-18
**fix(pgsql-eventslog): harden event ownership and keep newest rows in memory table**
*Rene Cannao <rene@proxysql.com>*

### c5191d21f - 2026-02-18
**logger: avoid log drops during rotate close/open window**
*Rene Cannao <rene@proxysql.com>*

### eba795d72 - 2026-02-18
**fix(pgsql-eventslog): make dump-to-memory sizing protocol-agnostic across admin ports**
*Rene Cannao <rene@proxysql.com>*

### 6f5a22f66 - 2026-02-18
**docs(internal): update PGSQL advanced logging architecture validation section with auto-dump E2E coverage**
*Rene Cannao <rene@proxysql.com>*

### 97e5cfee9 - 2026-02-18
**docs(doxygen): expand PostgreSQL logger API documentation for new advanced logging components**
*Rene Cannao <rene@proxysql.com>*

### 258699547 - 2026-02-18
**tap(pgsql): add end-to-end test for eventslog automatic buffer-to-disk sync**
*Rene Cannao <rene@proxysql.com>*

### 20d6282a6 - 2026-02-18
**build(clean): ignore and remove generated MySQL parser artifacts**
*Rene Cannao <rene@proxysql.com>*

### 2759006f7 - 2026-02-18
**Cleanup FFTO tests: remove redundant subdirectories and orchestration scripts**
*Rene Cannao <rene@proxysql.com>*

### 1edf1f8e8 - 2026-02-18
**Add PostgreSQL advanced logging TAP coverage and rewrite architecture doc**
*Rene Cannao <rene@proxysql.com>*

### b4e85f179 - 2026-02-18
**Expose PostgreSQL eventslog metrics in stats and Prometheus**
*Rene Cannao <rene@proxysql.com>*

### b100235fb - 2026-02-18
**Add PGSQL eventslog dump commands and periodic disk sync scheduling**
*Rene Cannao <rene@proxysql.com>*

### acbd7d0df - 2026-02-18
**Implement PostgreSQL eventslog circular buffer and sink pipeline**
*Rene Cannao <rene@proxysql.com>*

### 69acd4b43 - 2026-02-18
**Implement FFTO TAP testing suite**
*Rene Cannao <rene@proxysql.com>*

### 2a46c239b - 2026-02-18
**Add PostgreSQL advanced eventslog schema and variable scaffolding**
*Rene Cannao <rene@proxysql.com>*

### 3ca390dac - 2026-02-18
**Fix binary protocol support for prepared statements in FFTO**
*Rene Cannao <rene@proxysql.com>*

### 83a631bb1 - 2026-02-18
**Enhance FFTO documentation with verification steps and performance details**
*Rene Cannao <rene@proxysql.com>*

### 3a3be5a55 - 2026-02-18
**Implement Fast Forward Traffic Observer (FFTO) for MySQL and PostgreSQL**
*Rene Cannao <rene@proxysql.com>*

### 1f0756b59 - 2026-02-18
** Correct bytes_sent tracking for extended query protocol**
*Rahim Kanji <rahim.kanji@outlook.com>*

### eaadabbb8 - 2026-02-18
**logger: fix thread-context map race in buffered logging**
*Rene Cannao <rene@proxysql.com>*

### caf324f91 - 2026-02-18
**logger: harden buffered logging flush/rotation semantics**
*Rene Cannao <rene@proxysql.com>*

### 568fe1524 - 2026-02-18
**Merge pull request #5364 from mevishalr/feature/query-logging-improvements**
*René Cannaò <rene@proxysql.com>*

### 762afaa44 - 2026-02-18
**Merge branch 'v3.0' into v4.0-mcp-stats**
*René Cannaò <rene@proxysql.com>*

### 488255923 - 2026-02-18
**Cleanup: Uncomment delete statsdb_disk in ProxySQL_Statistics destructor**
*Rene Cannao <rene@proxysql.com>*

### 700459f67 - 2026-02-18
**tsdb: address AI code review feedback, fix memory safety and logic bugs**
*Rene Cannao <rene@proxysql.com>*

### 50858d03a - 2026-02-17
**Adding tests in tap group**
*Rene Cannao <rene@proxysql.com>*

### 10ff1322b - 2026-02-17
**Merge pull request #5386 from sysown/v3.0-MCP_multi**
*René Cannaò <rene@proxysql.com>*

### 49da3fb07 - 2026-02-18
**Created new group 'pgsql17-repl'**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 3bb233e80 - 2026-02-17
**tsdb: commit missing REST API safety fixes**
*Rene Cannao <rene@proxysql.com>*

### ab1173ea4 - 2026-02-18
**Add TAP test for query rules routing**
*Rahim Kanji <rahim.kanji@outlook.com>*

### db5f1ea49 - 2026-02-17
**Track query count for extended query protocol executions**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 1b3d20388 - 2026-02-17
**Reset current_hostgroup to default when no query rule matches**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 253d09865 - 2026-02-17
**security: fix SQL injection vulnerabilities in SQLite catalog queries**
*Rene Cannao <rene@proxysql.com>*

### 0da772a4c - 2026-02-17
**tap groups: add new MCP test assignments to ai-g1 group**
*Rene Cannao <rene@proxysql.com>*

### 2fa1401b0 - 2026-02-17
**MCP query+harvest hardening: HGM-based target routing, weighted backend selection, pgsql schema fix, and TAP robustness**
*Rene Cannao <rene@proxysql.com>*

### e1d420187 - 2026-02-17
**Simplify reg_test_2233: Use only SQLite3 Server as backend**
*Jesmar Cannaò <jesmar@sysown.com>*

### b8c6b4f57 - 2026-02-17
**tsdb: address code review comments and improve stability**
*Rene Cannao <rene@proxysql.com>*

### 9ffc3f8d7 - 2026-02-17
**mcp tests: add phase-B TAP coverage and optional real Claude CLI E2E runner**
*Rene Cannao <rene@proxysql.com>*

### ade0130e6 - 2026-02-17
**discoveryagent: update Claude Code headless flow for target_id-scoped MCP tools**
*Rene Cannao <rene@proxysql.com>*

### 2538e303c - 2026-02-17
**tap ai: add dual-backend static-harvest fixtures and target_id coverage test**
*Rene Cannao <rene@proxysql.com>*

### 9685cdaa4 - 2026-02-17
**mcp discovery: enforce target-scoped run model and add protocol-aware static harvesting (mysql+pgsql)**
*Rene Cannao <rene@proxysql.com>*

### 7e54883ba - 2026-02-17
**mcp query debugging: surface rule-id context for blocks and add backend failure SQL details**
*Rene Cannao <rene@proxysql.com>*

### c133d716b - 2026-02-17
**Improve reg_test_2233: Add SQLite3 Server support and documentation**
*Jesmar Cannaò <jesmar@sysown.com>*

### 8fbd570c7 - 2026-02-17
**mcp variables: stop writing runtime_global_variables during LOAD MCP VARIABLES TO RUNTIME**
*Rene Cannao <rene@proxysql.com>*

### f15460348 - 2026-02-17
**mcp query diagnostics: include runtime hostgroup status breakdown when target lacks ONLINE backend**
*Rene Cannao <rene@proxysql.com>*

### f4bc1943f - 2026-02-17
**mcp query diagnostics: restore strict ONLINE requirement and explain target non-executable failures**
*Rene Cannao <rene@proxysql.com>*

### 49f811a63 - 2026-02-16
**mcp query: stop misclassifying reachable targets as non-executable**
*Rene Cannao <rene@proxysql.com>*

### 6a788e48c - 2026-02-16
**mcp: make /mcp/query self-healing when targets/backends appear after startup**
*Rene Cannao <rene@proxysql.com>*

### 998bd8238 - 2026-02-16
**MCP TAP startup: fix tool-handler initialization order, improve MCP PROFILES observability, and seed monitor users**
*Rene Cannao <rene@proxysql.com>*

### af0411bd4 - 2026-02-16
**MCP: add target-aware rules/stats tests, explain_sql rule coverage, and AI local docker TAP infra**
*Rene Cannao <rene@proxysql.com>*

### 28b1114cd - 2026-02-16
**Merge pull request #5353 from sysown/v3.0_pgsql-prepared-statement-refcount-race-5352**
*René Cannaò <rene@proxysql.com>*

### acd955b9d - 2026-02-16
**Merge pull request #5382 from sysown/v3.0-webui_2602**
*René Cannaò <rene@proxysql.com>*

### 4f615da7c - 2026-02-16
**Remove commented build rule for reg_test_2233**
*Jesmar Cannaò <jesmar@sysown.com>*

### db40505d1 - 2026-02-16
**Fix #2233: Mirror sessions destination_hostgroup overwritten by fast routing**
*jesmarcannao <jesmarcannao@users.noreply.github.com>*

### b46fb575e - 2026-02-16
**TAP MCP client: port PR5372 coverage to MCP profiles/target_id routing model**
*Rene Cannao <rene@proxysql.com>*

### 67cb1b72b - 2026-02-16
**MCP TAP: pass target_id explicitly in query-rules test payloads**
*Rene Cannao <rene@proxysql.com>*

### 4a8b22403 - 2026-02-16
**MCP TAP/docs: migrate tests and documentation from legacy MCP mysql vars to profile-based routing**
*Rene Cannao <rene@proxysql.com>*

### 013864b36 - 2026-02-16
**MCP: introduce profile-based target/auth routing and unified LOAD/SAVE MCP PROFILES commands**
*Rene Cannao <rene@proxysql.com>*

### 95b46cf21 - 2026-02-16
**tests: add TSDB API and UI verification test**
*Rene Cannao <rene@proxysql.com>*

### 2267ef245 - 2026-02-16
**doc: update TSDB documentation**
*Rene Cannao <rene@proxysql.com>*

### 5f5b7d604 - 2026-02-16
**tsdb: improve administrative interface and command support**
*Rene Cannao <rene@proxysql.com>*

### a09db8318 - 2026-02-16
**tsdb: fix SET command validation by adding tsdb- prefix support**
*Rene Cannao <rene@proxysql.com>*

### 6587bfdd4 - 2026-02-16
**tsdb: trigger stats refresh on SHOW TSDB STATUS**
*Rene Cannao <rene@proxysql.com>*

### 2d51aeff6 - 2026-02-16
**tsdb: correctly implement SHOW TSDB commands and variable initialization**
*Rene Cannao <rene@proxysql.com>*

### 6404d7b36 - 2026-02-16
**tsdb: implement SHOW TSDB VARIABLES and SHOW TSDB STATUS**
*Rene Cannao <rene@proxysql.com>*

### 685b92cea - 2026-02-16
**tsdb: fix crash due to invalid SQL in tsdb_backend_health macro**
*Rene Cannao <rene@proxysql.com>*

### c3e1a02fe - 2026-02-16
**tsdb: fix crash due to invalid SQL in table definition macros**
*Rene Cannao <rene@proxysql.com>*

### c73011b30 - 2026-02-16
**tsdb: implement REST API and basic UI dashboard**
*Rene Cannao <rene@proxysql.com>*

### 4e0f94a34 - 2026-02-16
**tsdb: fix compilation error in ProxySQL_Admin.cpp**
*Rene Cannao <rene@proxysql.com>*

### a236a1378 - 2026-02-16
**tsdb: dedicated module for TSDB variables with tsdb- prefix and optimized background tasks**
*Rene Cannao <rene@proxysql.com>*

### da877c378 - 2026-02-16
**tsdb: align admin variable lifecycle, full prometheus ingestion, docs and tap coverage**
*Rene Cannao <rene@proxysql.com>*

### f17e99983 - 2026-02-16
**Implement SQLite-based TSDB subsystem**
*Rene Cannao <rene@proxysql.com>*

### 5de836a4c - 2026-02-15
**Merge pull request #5373 from sysown/v3.0_improve_mysql_monitoring_5256**
*René Cannaò <rene@proxysql.com>*

### 3b578db4b - 2026-02-15
**Merge pull request #5374 from sysown/v3.0-test0213**
*René Cannaò <rene@proxysql.com>*

### 83209da48 - 2026-02-15
**Merge pull request #5356 from sysown/v3.0-5355**
*René Cannaò <rene@proxysql.com>*

### 37e72ea3f - 2026-02-14
**Fix PROXY protocol detection in MySQL_Data_Stream::read_from_net**
*Rene Cannao <rene@proxysql.com>*

### 11a43bf76 - 2026-02-14
**Fix uninitialized max_allowed_pkt in MySQL_Connection constructor**
*Rene Cannao <rene@proxysql.com>*

### ca4f858b2 - 2026-02-14
**Fix uninitialized memory read in pgsql tokenizer**
*Rene Cannao <rene@proxysql.com>*

### 85952373d - 2026-02-14
**Fix uninitialized mondb pointer in MySQL_Monitor_State_Data constructor**
*Rene Cannao <rene@proxysql.com>*

### d42d89ae3 - 2026-02-14
**Fix TAP test when statement count after worker threads is below cache limit. Calculate dynamically how many statements to create to ensure we exceed CACHE_LIMIT (1024) and trigger a purge.**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 8ca6323ee - 2026-02-14
**Merge remote-tracking branch 'Master/v3.0' into v3.0_pgsql-prepared-statement-refcount-race-5352**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 200fdecb8 - 2026-02-13
**Apply AI agent review fixes to PR #5374**
*Rene Cannao <rene@proxysql.com>*

### 1cccfb322 - 2026-02-13
**Fix connection cleanup in failure paths**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 941e6b732 - 2026-02-13
**Fix filters_rwlock initialization race condition**
*Rene Cannao <rene@proxysql.com>*

### 3c85c593c - 2026-02-13
**Add GloMTH initialization wait to all monitor and server threads**
*Rene Cannao <rene@proxysql.com>*

### aa53d990e - 2026-02-13
**Add GloMTH initialization wait to all monitor threads**
*Rene Cannao <rene@proxysql.com>*

### f4cd34be5 - 2026-02-13
**Fix race condition in monitor_connect_thread**
*Rene Cannao <rene@proxysql.com>*

### 33ce4217f - 2026-02-13
**Merge remote-tracking branch 'v3.0' into v3.0_improve_mysql_monitoring_5256**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 9eac5f642 - 2026-02-13
**Improve async ping mmsd ownership tracking and pool validation**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 09d0dcb80 - 2026-02-13
**Fix uninitialized tmp_charset in Data_Stream constructors**
*Rene Cannao <rene@proxysql.com>*

### 7c67eb25f - 2026-02-13
**Fix uninitialized fd and status in Data_Stream constructors**
*Rene Cannao <rene@proxysql.com>*

### 2af3b0d33 - 2026-02-13
**Add notes about Valgrind and SQLite memory management**
*Rene Cannao <rene@proxysql.com>*

### 4e39297ef - 2026-02-13
**Fix more Valgrind uninitialized value errors**
*Rene Cannao <rene@proxysql.com>*

### fdbea2a32 - 2026-02-13
**Fix uninitialized memory in Command_Counter::_counters**
*Rene Cannao <rene@proxysql.com>*

### c2f82b3d4 - 2026-02-13
**Fix more Valgrind uninitialized value errors**
*Rene Cannao <rene@proxysql.com>*

### ee7ee0b38 - 2026-02-13
**Fix multiple Valgrind-reported uninitialized memory issues**
*Rene Cannao <rene@proxysql.com>*

### af58865b0 - 2026-02-13
**Fix uninitialized memory in QueryParserArgs.buf**
*Rene Cannao <rene@proxysql.com>*

### cc53ddca2 - 2026-02-13
**Merge branch 'v3.0-openssl-fix' into v3.0-test0213**
*Rene Cannao <rene@proxysql.com>*

### 52718df11 - 2026-02-13
**Fix memory leak in stats processlist functions**
*Rene Cannao <rene.cannao@gmail.com>*

### 0654efd62 - 2026-02-13
**Merge pull request #5371 from sysown/v3.0-fixes0212**
*René Cannaò <rene@proxysql.com>*

### 71143c2e8 - 2026-02-13
**Address AI review comments**
*vramesha <vramesha@akamai.com>*

### 746eca9f7 - 2026-02-13
**More sprintf to snprintf conversions and indentation fixes**
*Rene Cannao <rene.cannao@gmail.com>*

### 3e3733787 - 2026-02-12
**Use RAII for sqlite3 statements across codebase**
*Rene Cannao <rene.cannao@gmail.com>*

### 335be9ec7 - 2026-02-12
**Fix unsafe sprintf and error message handling**
*Rene Cannao <rene.cannao@gmail.com>*

### 61ce0a96e - 2026-02-12
**Remove redundant sqlite3_finalize calls in pgSQL stats**
*Rene Cannao <rene.cannao@gmail.com>*

### afd6dffb0 - 2026-02-12
**Fix admin shutdown races and implement graceful teardown**
*Rene Cannao <rene.cannao@gmail.com>*

### 368a9e3a6 - 2026-02-12
**Fix log_buffer debug leak during shutdown**
*Rene Cannao <rene.cannao@gmail.com>*

### ba86be70a - 2026-02-12
**Fixed some bugs in PR 5358**
*Rene Cannao <rene.cannao@gmail.com>*

### bed851471 - 2026-02-13
**Fix MySQL Monitor assertion failure in DEBUG builds**
*Rahim Kanji <rahim.kanji@outlook.com>*

### da7c8e5cf - 2026-02-12
**Fix missing variable**
*Rene Cannao <rene@proxysql.com>*

### 4ae5bd852 - 2026-02-12
**Revert "fix: prevent dangling pointer in flush_*_variables___runtime_to_database"**
*Rene Cannao <rene@proxysql.com>*

### 02ea4f90b - 2026-02-12
**Merge pull request #5360 from sysown/v3.0-5359**
*René Cannaò <rene@proxysql.com>*

### e82ff6f8a - 2026-02-12
**Merge pull request #5361 from sysown/v3.0-5069**
*René Cannaò <rene@proxysql.com>*

### a69b92593 - 2026-02-12
**Minor typo fixes**
*Rene Cannao <rene@proxysql.com>*

### 314547343 - 2026-02-12
**Merge pull request #5367 from sysown/v3.0_pgsql-meta-cmd-admin-5365**
*René Cannaò <rene@proxysql.com>*

### 946052099 - 2026-02-11
**Add more tests**
*Rahim Kanji <rahim.kanji@outlook.com>*

### e76d9dc13 - 2026-02-11
**Cleanup**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 091942e9d - 2026-02-11
**Address AI review suggestions**
*vramesha <vramesha@akamai.com>*

### ba5afd0bb - 2026-02-11
**Add TAP test**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 331b0d6bc - 2026-02-11
**Add support for PostgreSQL psql meta-commands in admin interface**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 15a4ed66e - 2026-02-11
**Optimize query logging performance (#5243)**
*vramesha <vramesha@akamai.com>*

### 2d3d12b9a - 2026-02-10
**Address review comments from gemini and coderabbit**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 471ebca74 - 2026-02-10
**fix: GENAI modules fails to initialise**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### ae92ae265 - 2026-02-10
**Merge branch 'v3.0' into v4.0-mcp-stats**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 7f19b642c - 2026-02-10
**MCP: Rewrite stats tool handlers based on updated spec**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### e94f9281c - 2026-02-10
**feat: add friend declaration for MetricsCollector to access MyHostGroups**
*René Cannaò <rene.cannao@gmail.com>*

### d90be4080 - 2026-02-09
**Add documentation for Prometheus protocol labels feature**
*Rene Cannao <rene@proxysql.com>*

### 3ab964010 - 2026-02-09
**Add protocol labels to Query Cache metrics and enable PostgreSQL QC metrics**
*Rene Cannao <rene@proxysql.com>*

### 778e01174 - 2026-02-09
**Add protocol labels to Thread Handler metrics and enable PostgreSQL metrics**
*Rene Cannao <rene@proxysql.com>*

### fa35bda62 - 2026-02-09
**Merge pull request #5069 from evkuzin/v3.0-fix-prometheus-metrics-dumplication**
*René Cannaò <rene@proxysql.com>*

### 17054cd14 - 2026-02-09
**fix: memory leak in pull_global_variables_from_peer**
*Rene Cannao <rene@proxysql.com>*

### deb19a021 - 2026-02-09
**fix: remove double-finalization in stats___save_mysql_query_digest_to_sqlite**
*Rene Cannao <rene@proxysql.com>*

### a20b2704f - 2026-02-09
**fix: prevent dangling pointer in flush_*_variables___runtime_to_database**
*Rene Cannao <rene@proxysql.com>*

### fcaa90413 - 2026-02-09
**fix: crash on macOS/FreeBSD when running PostgreSQL queries**
*René Cannaò <rene.cannao@gmail.com>*

### 0e605f417 - 2026-02-09
**build: fix anomaly_detection-t linking for PROXYSQLGENAI**
*Rene Cannao <rene@proxysql.com>*

### ac71e12a9 - 2026-02-09
**refactor: migrate RSA key generation to OpenSSL 3.0 EVP_PKEY API**
*Rene Cannao <rene@proxysql.com>*

### 6f415dfdb - 2026-02-09
**fix: correct RAII migration issues - variable naming and redundant declarations**
*Rene Cannao <rene@proxysql.com>*

### 7c0ff770f - 2026-02-09
**refactor: migrate prepare_v2 SIMPLE cases in ProxySQL_Admin_Stats.cpp**
*Rene Cannao <rene@proxysql.com>*

### ee85b11ad - 2026-02-09
**refactor: migrate prepare_v2 SIMPLE case in PgSQL_HostGroups_Manager.cpp**
*Rene Cannao <rene@proxysql.com>*

### e4704c5a5 - 2026-02-09
**refactor: migrate prepare_v2 SIMPLE cases in PgSQL_Monitor.cpp**
*Rene Cannao <rene@proxysql.com>*

### 73555410e - 2026-02-09
**refactor: migrate prepare_v2 SIMPLE case in FlushDigestTableToDisk template**
*Rene Cannao <rene@proxysql.com>*

### 2e907bdd3 - 2026-02-09
**refactor: migrate prepare_v2 SIMPLE cases in ProxySQL_Cluster.cpp**
*Rene Cannao <rene@proxysql.com>*

### e3ee45436 - 2026-02-09
**fix: remove duplicate 'int rc' declarations in prepare_v2 migrated functions**
*Rene Cannao <rene@proxysql.com>*

### 5b6381b32 - 2026-02-09
**refactor: migrate remaining prepare_v2 SIMPLE cases in ProxySQL_Admin**
*Rene Cannao <rene@proxysql.com>*

### 2a83a3097 - 2026-02-09
**refactor: migrate more prepare_v2 SIMPLE cases in ProxySQL_Admin**
*Rene Cannao <rene@proxysql.com>*

### ca9b72a9d - 2026-02-09
**refactor: migrate more prepare_v2 SIMPLE cases in ProxySQL_Admin**
*Rene Cannao <rene@proxysql.com>*

### e56da24c8 - 2026-02-09
**refactor: migrate more prepare_v2 SIMPLE cases in ProxySQL_Admin**
*Rene Cannao <rene@proxysql.com>*

### 575449cdf - 2026-02-09
**refactor: migrate all prepare_v2 SIMPLE cases to RAII API in ProxySQL_Admin**
*Rene Cannao <rene@proxysql.com>*

### f779a6059 - 2026-02-09
**refactor: migrate remaining prepare_v2 SIMPLE cases in MySQL_Monitor**
*Rene Cannao <rene@proxysql.com>*

### bdba0b44a - 2026-02-09
**refactor: migrate all prepare_v2 SIMPLE cases to RAII API in MySQL_Monitor**
*Rene Cannao <rene@proxysql.com>*

### 854ab4fbb - 2026-02-09
**refactor: migrate generate_pgsql_hostgroup_attributes_table() to RAII prepare_v2**
*Rene Cannao <rene@proxysql.com>*

### 9939fe17e - 2026-02-09
**refactor: migrate generate_pgsql_servers_table() to RAII prepare_v2**
*Rene Cannao <rene@proxysql.com>*

### 41564acaa - 2026-02-09
**Fix #5355: Add null pointer check in RequestEnd() to prevent use-after-free crash**
*Rene Cannao <rene@proxysql.com>*

### 7c2c6121e - 2026-02-09
**refactor: migrate prepare_v2 to RAII API in ProxySQL_Admin_Tests2**
*Rene Cannao <rene@proxysql.com>*

### 2c8c27bf6 - 2026-02-09
**refactor: migrate prepare_v2 to RAII API in Admin_FlushVariables**
*Rene Cannao <rene@proxysql.com>*

### 926208906 - 2026-02-09
**refactor: migrate prepare_v2 to RAII API in MySQL_Logger**
*Rene Cannao <rene@proxysql.com>*

### 4161372da - 2026-02-09
**refactor: migrate simple prepare_v2 cases to RAII-based API**
*Rene Cannao <rene@proxysql.com>*

### df1c4e792 - 2026-02-09
**fix: medium priority warnings - write-strings and unused variables**
*Rene Cannao <rene@proxysql.com>*

### 80195edb8 - 2026-02-09
**Merge pull request #5354 from sysown/v3.0-mac3**
*René Cannaò <rene@proxysql.com>*

### 4c788dcbb - 2026-02-09
**fix: signed/unsigned comparison warnings (-Wsign-compare)**
*Rene Cannao <rene@proxysql.com>*

### 9e83a81b4 - 2026-02-09
**fix: critical use-after-free in child_telnet function**
*Rene Cannao <rene@proxysql.com>*

### 11251a9ad - 2026-02-09
**Merge pull request #5349 from sysown/v3.0.6-fix_rustc_check**
*René Cannaò <rene@proxysql.com>*

### c092e557b - 2026-02-09
**build_deps with PROXYSQLGENAI=1 when needed**
*Miro Stauder <miro@proxysql.com>*

### c45fabdb6 - 2026-02-09
**fix: correct macOS executable SHA1 implementation**
*René Cannaò <rene.cannao@gmail.com>*

### 557bdb621 - 2026-02-09
**Added missing iterator advancement**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 267b24e17 - 2026-02-09
**Added regression test**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 3d3831565 - 2026-02-07
**add --locked to cargo build to ensure reproducibility**
*Miro Stauder <miro@proxysql.com>*

### 844a645db - 2026-02-07
**update fedora build image versions**
*Miro Stauder <miro@proxysql.com>*

### dde69e763 - 2026-02-07
**add sqlite-rembed to cleanall**
*Miro Stauder <miro@proxysql.com>*

### 18c9c35b1 - 2026-02-07
**replace 'which' with 'type' to check for rustc toolchain**
*Miro Stauder <miro@proxysql.com>*

### 230985e93 - 2026-02-08
**Fix: PostgreSQL prepared statement purge race condition**
*Rahim Kanji <rahim.kanji@outlook.com>*

### e3bdd3c07 - 2026-02-07
**main: add macOS support for executable SHA1 calculation**
*René Cannaò <rene.cannao@gmail.com>*

### bcbbab88a - 2026-02-07
**Merge pull request #5351 from sysown/v3.0_mac2**
*René Cannaò <rene@proxysql.com>*

### 9410a60f6 - 2026-02-07
**build: make Rust toolchain optional, only required for PROXYSQLGENAI**
*René Cannaò <rene.cannao@gmail.com>*

### acdd4c91b - 2026-02-07
**build: replace grep -oP with sed -E for macOS compatibility**
*René Cannaò <rene.cannao@gmail.com>*

### 8655f398e - 2026-02-07
**Merge pull request #5350 from sysown/v3.0-scram_strtok**
*René Cannaò <rene@proxysql.com>*

### 763d4df53 - 2026-02-07
**chore: add scram.c.diff patch reference for security fix v3.0**
*René Cannaò <rene.cannao@gmail.com>*

### 933168ee2 - 2026-02-07
**Merge pull request #5348 from orbisai0security/fix-strtok-security-vulnerability-scram**
*René Cannaò <rene@proxysql.com>*

### c29c77fef - 2026-02-07
**fix: resolve high vulnerability c.lang.security.insecure-use-strtok-fn.insecure-use-strtok-fn**
*orbisai0security <orbisai0security@users.noreply.github.com>*

### a360dc22a - 2026-02-06
**Merge pull request #5308 from sysown/v3.0_mac**
*René Cannaò <rene@proxysql.com>*

### 010296583 - 2026-02-06
**Convert PostgreSQL patches to unified diff format**
*Rene Cannao <rene@proxysql.com>*

### 48f1b3cfe - 2026-02-06
**Merge pull request #5095 from Gonlo2/fix-overflow-if-first-server-is-invalid**
*René Cannaò <rene@proxysql.com>*

### 2865b144f - 2026-02-06
**Merge pull request #5094 from Gonlo2/fix-delete-con-incorrect-index**
*René Cannaò <rene@proxysql.com>*

### de0a9b9c2 - 2026-02-06
**Merge pull request #5093 from Gonlo2/fix-usage-deleted-con**
*René Cannaò <rene@proxysql.com>*

### 41088f912 - 2026-02-06
**Merge pull request #5319 from sysown/v3.0.6-fix_reg_test_5233_set_warning-t**
*René Cannaò <rene@proxysql.com>*

### 6a2f77784 - 2026-02-06
**doc: Document existing `stats` tables and `/mcp/stats` tools & implementation**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 77fe58280 - 2026-02-06
**Merge pull request #5317 from sysown/v3.0.6-implement_FLUSH_STATS**
*René Cannaò <rene@proxysql.com>*

### abddff335 - 2026-02-06
**Merge pull request #5344 from sysown/fix/remove-wrong-index-connection-cleanup**
*René Cannaò <rene@proxysql.com>*

### ce9fdc9d7 - 2026-02-05
**Merge branch 'v3.0' into v3.0.6-implement_FLUSH_STATS**
*René Cannaò <rene@proxysql.com>*

### e3026cbc6 - 2026-02-05
**Fix wrong index in connection cleanup loops (MySQL and PgSQL)**
*Rene Cannao <rene@proxysql.com>*

### 2b0c74189 - 2026-02-05
**Add TAP test for FLUSH STATS commands**
*Rene Cannao <rene@proxysql.com>*

### 8e58ce592 - 2026-02-05
**Merge pull request #5337 from wazir-ahmed/v4.0-rag-system-prompt-2**
*René Cannaò <rene@proxysql.com>*

### 052436332 - 2026-02-05
**Merge pull request #5339 from sysown/v3.0-merge-v4.0-genai**
*René Cannaò <rene@proxysql.com>*

### adb059c4b - 2026-02-04
**mcp/stats: Add doxygen documentation for tool handlers**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 643b322f2 - 2026-02-03
**MCP: Add stats endpoint and tools**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### b5807fe14 - 2026-02-04
**RAG: Improve system prompt, replace hardcoded values with env vars**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### beff62835 - 2026-02-04
**Merge pull request #5340 from sysown/fix-genai-critical-issues**
*René Cannaò <rene@proxysql.com>*

### fdccb7c03 - 2026-02-03
**Export PROXYSQLGENAI to support building all packages with GenAI**
*Rene Cannao <rene@proxysql.com>*

### b141af922 - 2026-02-03
**Prevent double version increment when PROXYSQLGENAI is enabled**
*Rene Cannao <rene@proxysql.com>*

### a94b7d6b2 - 2026-02-03
**Add PROXYSQLGENAI support to docker builds**
*Rene Cannao <rene@proxysql.com>*

### 27f13ca18 - 2026-02-03
**Merge pull request #5096 from Gonlo2/fix-close-ssl-con**
*René Cannaò <rene@proxysql.com>*

### 432cdfe49 - 2026-02-03
**Modify Makefile to increment major version when PROXYSQLGENAI is enabled**
*Rene Cannao <rene@proxysql.com>*

### 79756e78d - 2026-02-03
**Fix missing #endif for PROXYSQLGENAI guard in Admin_Handler.cpp**
*Rene Cannao <rene@proxysql.com>*

### a17593b99 - 2026-02-03
**Add rand5_admin_1 test group environment configuration**
*Rene Cannao <rene@proxysql.com>*

### 70c404901 - 2026-02-03
**Add test group environment configurations**
*Rene Cannao <rene@proxysql.com>*

### dd9b761ad - 2026-02-03
**Add GenAI test files to test groups configuration**
*Rene Cannao <rene@proxysql.com>*

### 1af768f93 - 2026-02-03
**Fix critical issues in GenAI code (PR #5339)**
*Rene Cannao <rene@proxysql.com>*

### 2b9570825 - 2026-02-03
**Merge branch 'v3.0' into v3.0-merge-v4.0-genai**
*René Cannaò <rene@proxysql.com>*

### a57b43286 - 2026-02-03
**Fix TAP test builds with PROXYSQLGENAI**
*Rene Cannao <rene@proxysql.com>*

### b965fc6df - 2026-02-03
**Fix PROXYSQLGENAI build - resolve circular includes and missing headers**
*Rene Cannao <rene@proxysql.com>*

### 69ea21ef4 - 2026-02-03
**Merge pull request #5329 from sysown/v3.0.6-add_fedora43**
*René Cannaò <rene@proxysql.com>*

### e3c13f5fb - 2026-02-03
**Merge pull request #5338 from sysown/copilot/sub-pr-5329**
*René Cannaò <rene@proxysql.com>*

### b269d9c71 - 2026-02-03
**Remove Fedora 41 support (EOL)**
*copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>*

### 3da50e059 - 2026-02-03
**Initial plan**
*copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>*

### 48bc7dd7b - 2026-02-03
**Merge v4.0 GenAI features into v3.0 with conditional compilation**
*Rene Cannao <rene@proxysql.com>*

### 09bd69eed - 2026-01-30
**RAG: Improve system prompt, include SQLite server interface**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 53bd4b606 - 2026-01-29
**Merge pull request #5334 from sysown/v4.0_rag_ingest_sqlite_server**
*René Cannaò <rene@proxysql.com>*

### e00617be1 - 2026-01-29
**Merge pull request #5333 from wazir-ahmed/v4.0-config-embedding-model**
*René Cannaò <rene@proxysql.com>*

### e7c50b037 - 2026-01-29
**Merge pull request #5331 from sysown/v4.0-rag_tools_stats**
*René Cannaò <rene@proxysql.com>*

### 02f2ff5e2 - 2026-01-29
**Fix logging system: remove stderr bypass, thread-safe timestamps, and std::tolower UB**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 10026891c - 2026-01-28
**RAG: Convert vector similarity search into a subquery**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### c5db31bf9 - 2026-01-27
**test: Improve testing for MCP and RAG tools**
*Javier Jaramago Fernández <jaramago.fernandez.javier@gmail.com>*

### e351a0df7 - 2026-01-28
**feat: Add leading comments (--) detection for 'run_sql_readonly'**
*Javier Jaramago Fernández <jaramago.fernandez.javier@gmail.com>*

### cc1d93d08 - 2026-01-23
**implement admin command 'PROXYSQL FLUSH STATS' for DEBUG builds**
*Miro Stauder <miro@proxysql.com>*

### 79ee743a4 - 2026-01-28
**Add detailed logging and per-source commits to rag_ingest**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 8d022a0fc - 2026-01-28
**RAG: Add 'model' request parameter for embedding service**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### fec97bbab - 2026-01-27
**fix: Fix GENAI variable loading during 'ProxySQL_Admin::init'**
*Javier Jaramago Fernández <jaramago.fernandez.javier@gmail.com>*

### a5ef787c7 - 2026-01-26
**feat: Improve logging for MCP and RAG tools**
*Javier Jaramago Fernández <jaramago.fernandez.javier@gmail.com>*

### b392b91a6 - 2026-01-27
**Merge pull request #5330 from sysown/v4.0_rag_ingest_sqlite_server**
*René Cannaò <rene@proxysql.com>*

### 4d4bb9dec - 2026-01-26
**fix: Improved MCP rule testing and helpers**
*Javier Jaramago Fernández <jaramago.fernandez.javier@gmail.com>*

### e9cabc0d3 - 2026-01-27
**Merge remote-tracking branch 'v4.0' into v4.0_rag_ingest_sqlite_server**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 8a1732d15 - 2026-01-27
**Add SQLite Server verification on connect**
*Rahim Kanji <rahim.kanji@outlook.com>*

### fe76479cf - 2026-01-27
**add fedora43, remove fedora40**
*Miro Stauder <miro@proxysql.com>*

### bc7098893 - 2026-01-27
**Added Chunking and Embedding guide**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 888eb24b1 - 2026-01-27
**Merge pull request #5328 from sysown/v4.0_rag_ingest_2**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 591f4bc9b - 2026-01-27
**RAG: Add system prompt for agentic workflow**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 1b322ed2b - 2026-01-26
**add comprehensive test suite for SQLite Server via MySQL protocol**
*Rahim Kanji <rahim.kanji@outlook.com>*

### d66248eb4 - 2026-01-26
**add verbose logging for bulk embedding operations**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 211179bdc - 2026-01-26
**rag_ingest: Rewrite to use MySQL protocol (Sqlite_Server) instead of SQLite3 API**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 8ef8503d1 - 2026-01-26
**Merge pull request #5323 from wazir-ahmed/v4.0_rag_ingest_2**
*René Cannaò <rene@proxysql.com>*

### 1a7668b73 - 2026-01-26
**fix: SQLite3 server support for MySQL client '8.1.0'**
*Javier Jaramago Fernández <jaramago.fernandez.javier@gmail.com>*

### 3d3dc1732 - 2026-01-23
**fix test logic and stats reset**
*Miro Stauder <miro@proxysql.com>*

### c5c726ea9 - 2026-01-25
**Merge pull request #5321 from sysown/v4.0-mcp_rules_test**
*René Cannaò <rene@proxysql.com>*

### 87d8c2507 - 2026-01-25
**Reapply "fix: 'SQLITE_CONFIG_URI' not being set on 'LoadPlugins'"**
*Rene Cannao <rene@proxysql.com>*

### 342272367 - 2026-01-25
**Merge pull request #5324 from sysown/v4.0_rag_ingest_2**
*René Cannaò <rene@proxysql.com>*

### 35b316d4f - 2026-01-25
**Fix absolute paths in documentation**
*Rene Cannao <rene@proxysql.com>*

### a5edd4ad9 - 2026-01-25
**Add comprehensive RAG ingestion usage guide**
*Rene Cannao <rene@proxysql.com>*

### e4f4dc95c - 2026-01-25
**RAG: bm25 and MATCH do not work with table alias**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### c52c621b2 - 2026-01-25
**MCP: Add mcp-rag_endpoint_auth config**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### eb495f42e - 2026-01-25
**AI: Fix vector_db table creation**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 22c4e94d5 - 2026-01-25
**AI: Fix sqlite-vec extension loading**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 7167f9524 - 2026-01-25
**AI: Enable extensions for vector_db**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 4031f8539 - 2026-01-24
**AI: Fix vector_db initialization**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### cecb975f6 - 2026-01-23
**fix: LOAD GENAI TO RUNTIME does not initialize the module**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 50de53653 - 2026-01-23
**MCP: Fix crash during server restarts**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 48260cbf0 - 2026-01-23
**Revert "fix: 'SQLITE_CONFIG_URI' not being set on 'LoadPlugins'"**
*Rene Cannao <rene@proxysql.com>*

### 51e91378c - 2026-01-23
**test: Add/Improve TAP tests for MCP query_rules/digests**
*Javier Jaramago Fernández <jaramago.fernandez.javier@gmail.com>*

### 5fd779464 - 2026-01-23
**Add embedding testing plan documentation**
*Rene Cannao <rene@proxysql.com>*

### 08e7c8ce9 - 2026-01-23
**chore: Remove data files mistakenly added to root folder**
*Javier Jaramago Fernández <jaramago.fernandez.javier@gmail.com>*

### df221617c - 2026-01-23
**fix: 'SQLITE_CONFIG_URI' not being set on 'LoadPlugins'**
*Javier Jaramago Fernández <jaramago.fernandez.javier@gmail.com>*

### ff50e834f - 2026-01-23
**Implement batch embedding generation in rag_ingest**
*Rene Cannao <rene@proxysql.com>*

### 6166adaf0 - 2026-01-23
**Merge pull request #5318 from rahim-kanji/v4.0_rag_ingest**
*René Cannaò <rene.cannao@gmail.com>*

### 07154ca66 - 2026-01-23
**Empty commit to differentiate from v4.0_rag_ingest_2**
*Rene Cannao <rene@proxysql.com>*

### 42a67ebaf - 2026-01-23
**Merge rahim/v4.0_rag_ingest into v4.0_rag_ingest_2**
*Rene Cannao <rene@proxysql.com>*

### 950f163bf - 2026-01-23
**Fix compilation issues: use static libcurl and improve includes**
*Rene Cannao <rene@proxysql.com>*

### 38e5e8e56 - 2026-01-23
**Fix critical issues from coderabbitai review**
*Rene Cannao <rene@proxysql.com>*

### 9ba3df0ce - 2026-01-23
**Address AI code review feedback from PR #5318**
*Rene Cannao <rene@proxysql.com>*

### 1f38d9210 - 2026-01-23
**Merge pull request #5313 from sysown/pr-5312-fixes**
*René Cannaò <rene@proxysql.com>*

### d28444a02 - 2026-01-23
**Merge remote-tracking branch 'v4.0' into v4.0_rag_ingest**
*Rahim Kanji <rahim.kanji@outlook.com>*

### bc33c3329 - 2026-01-22
**Add vec embedding handling with stub and OpenAI providers Added rag_sync_state implementation**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 3ccfa2bcc - 2026-01-23
**Address AI code review feedback for PR #5313**
*Rene Cannao <rene@proxysql.com>*

### c914feb23 - 2026-01-22
**Fix security issues identified in PR #5312 code review**
*Rene Cannao <rene@proxysql.com>*

### 4075e7cf6 - 2026-01-22
**Merge pull request #5312 from ProxySQL/v3.1-vec**
*René Cannaò <rene@proxysql.com>*

### 19d29a734 - 2026-01-22
**Merge pull request #28 from ProxySQL/v3.1-vec-loadplugin-fix**
*René Cannaò <rene.cannao@gmail.com>*

### 03e58146e - 2026-01-22
**fix: Re-enable SQLite3DB::LoadPlugin() with allow_load_plugin flag**
*Rene Cannao <rene@proxysql.com>*

### 3f1397c01 - 2026-01-22
**Merge pull request #27 from ProxySQL/v3.1-MCP2_QR**
*René Cannaò <rene.cannao@gmail.com>*

### a3afde347 - 2026-01-22
**fix: Address copilot review concerns for Discovery_Schema.cpp**
*Rene Cannao <rene@proxysql.com>*

### 7b6966b9c - 2026-01-22
**fix: Complete JSON escaping in fingerprint_mcp_args**
*Rene Cannao <rene@proxysql.com>*

### f2536f01d - 2026-01-22
**Merge v3.1-vec into v3.1-MCP2_QR**
*Rene Cannao <rene@proxysql.com>*

### 5d4318b54 - 2026-01-22
**fix: Address coderabbitai review concerns for PR #27**
*Rene Cannao <rene@proxysql.com>*

### d47e196fc - 2026-01-22
**Added rag_chunks and rag_fts_chunks test**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 2f6b058f7 - 2026-01-22
**Added test_rag_ingest.sh**
*Rahim Kanji <rahim.kanji@outlook.com>*

### fb3673dd9 - 2026-01-22
**added sample sql files**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 57d8c3f3b - 2026-01-21
**Make rag_ingest compile**
*Rahim Kanji <rahim.kanji@outlook.com>*

### b16d16fb2 - 2026-01-22
**Merge pull request #26 from ProxySQL/v3.1-vec-resolved**
*René Cannaò <rene.cannao@gmail.com>*

### ffe569036 - 2026-01-22
**fix: Address coderabbitai review - use-after-free, missing responses, SQL injection**
*Rene Cannao <rene@proxysql.com>*

### 5ece56351 - 2026-01-22
**fix: Correct SQL prepared statement API usage and template variable access**
*Rene Cannao <rene@proxysql.com>*

### 9f07e9631 - 2026-01-22
**fix: Use prepared statements in ProxySQL_Admin_Stats to prevent SQL injection**
*Rene Cannao <rene@proxysql.com>*

### 3bcee2270 - 2026-01-22
**fix: Execute MCP query rules DELETE+INSERT as explicit transaction**
*Rene Cannao <rene@proxysql.com>*

### 188aef90f - 2026-01-21
**fix: Use delete instead of free for SQLite3_result in load_mcp_query_rules_to_runtime**
*Rene Cannao <rene@proxysql.com>*

### bbc04974f - 2026-01-21
**fix: Fix mysql_query failure path and affected_rows race condition**
*Rene Cannao <rene@proxysql.com>*

### b3edc6524 - 2026-01-21
**fix: Escape SQL strings in harvest_view_definitions**
*Rene Cannao <rene@proxysql.com>*

### 6835713f1 - 2026-01-21
**fix: Correct column indexes in build_quick_profiles**
*Rene Cannao <rene@proxysql.com>*

### e9abee625 - 2026-01-21
**fix: Execute prepared statement in execute_parameterized_query**
*Rene Cannao <rene@proxysql.com>*

### 6305537ba - 2026-01-21
**fix: Use delete instead of free for SQLite3_result deallocation**
*Rene Cannao <rene@proxysql.com>*

### 5e121399a - 2026-01-21
**fix: Add AFTER UPDATE trigger to keep catalog_fts index in sync for upserts**
*Rene Cannao <rene@proxysql.com>*

### 5dd5dbe6b - 2026-01-21
**fix: Add missing assert(proxy_sqlite3_bind_blob) in sqlite3db.cpp**
*Rene Cannao <rene@proxysql.com>*

### 18cc24620 - 2026-01-21
**fix: Add missing proxy declarations to MAIN_PROXY_SQLITE3 branch**
*Rene Cannao <rene@proxysql.com>*

### bd6d34f52 - 2026-01-21
**fix: Address SQL injection vulnerabilities from PR #26 review**
*Rene Cannao <rene@proxysql.com>*

### d7b2fea89 - 2026-01-21
**fix: Remove MAIN_PROXY_SQLITE3 defines from tests (v3.1-MCP2 compatibility)**
*Rene Cannao <rene@proxysql.com>*

### 52142c464 - 2026-01-21
**fix: Multiple issues with MCP query_(rules/digests)**
*Javier Jaramago Fernández <jaramago.fernandez.javier@gmail.com>*

### b4f521c63 - 2026-01-21
**Merge v3.1-MCP2 into v3.1-vec**
*Rene Cannao <rene@proxysql.com>*

### f257c6ac8 - 2026-01-21
**Merge pull request #25 from ProxySQL/v3.1-vec_21**
*René Cannaò <rene.cannao@gmail.com>*

### 2d95f936c - 2026-01-21
**Merge pull request #5311 from sysown/v4.0-update-docker-build-image-versions**
*Miro Stauder <miro@proxysql.com>*

### 9e980d924 - 2026-01-21
**update docker build image versions in docker-compose.yml**
*Miro Stauder <miro@proxysql.com>*

### 02918d18b - 2026-01-21
**Fix PR #25 Review: All AI code reviewer feedback addressed**
*Rene Cannao <rene@proxysql.com>*

### a10c09bcc - 2026-01-21
**Fix PR #21 review: Security, memory safety, thread safety, and code cleanup**
*Rene Cannao <rene@proxysql.com>*

### fd5d433a2 - 2026-01-21
**fix: Missing <string> header in ai_llm_retry_scenarios-t**
*Rene Cannao <rene@proxysql.com>*

### 2a614f817 - 2026-01-21
**fix: Missing headers and format strings in vector_db_performance-t**
*Rene Cannao <rene@proxysql.com>*

### 0dc353174 - 2026-01-21
**fix: Linking issues for anomaly_detection-t TAP test**
*Rene Cannao <rene@proxysql.com>*

### af28598b2 - 2026-01-21
**Merge pull request #19 from ProxySQL/v3.1-MCP2_QR**
*René Cannaò <rene.cannao@gmail.com>*

### 709649232 - 2026-01-21
**fix: Address AI code review concerns from PR #19**
*Rene Cannao <rene@proxysql.com>*

### a831670a7 - 2026-01-21
**Merge pull request #21 from rahim-kanji/v3.1_fts-support**
*René Cannaò <rene.cannao@gmail.com>*

### f45506e0b - 2026-01-21
**fix: Missing <string> header in ai_llm_retry_scenarios-t**
*Rene Cannao <rene@proxysql.com>*

### d61381643 - 2026-01-21
**fix: Missing headers and format strings in vector_db_performance-t**
*Rene Cannao <rene@proxysql.com>*

### b9a70f85a - 2026-01-21
**fix: Linking issues for anomaly_detection-t TAP test**
*Rene Cannao <rene@proxysql.com>*

### 7231ffd4a - 2026-01-21
**Merge pull request #18 from ProxySQL/v3.1-MCP2_RAG1**
*René Cannaò <rene.cannao@gmail.com>*

### ceaaa013d - 2026-01-21
**Merge pull request #22 from ProxySQL/sqlite3-proxy-replacements**
*René Cannaò <rene.cannao@gmail.com>*

### 93517540a - 2026-01-21
**Added Makefile for rag_ingest**
*Rahim Kanji <rahim.kanji@outlook.com>*

### ea60d85aa - 2026-01-21
**Merge remote-tracking branch 'v3.1-vec' into v3.1_rag**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 75a62f334 - 2026-01-21
**Merge branch 'v4.0' into v3.1-vec**
*René Cannaò <rene@proxysql.com>*

### dd885bd1f - 2026-01-21
**bump version to 4.0.0**
*René Cannaò <rene.cannao@gmail.com>*

### 6ce053848 - 2026-01-21
**Keep main.cpp only; remove accidental backup from commits**
*Rene Cannao <rene@proxysql.com>*

### 62bc15fd8 - 2026-01-21
**Improve macOS build system OpenSSL detection and documentation**
*René Cannaò <rene.cannao@gmail.com>*

### f877366a6 - 2026-01-21
**Restore commented SQLite3DB::LoadPlugin reference with TODO**
*Rene Cannao <rene@proxysql.com>*

### 4f0e6e0a4 - 2026-01-21
**Disable sqlite3 plugin function replacement; warn instead**
*Rene Cannao <rene@proxysql.com>*

### 0db022a17 - 2026-01-21
**Apply fixes**
*Rene Cannao <rene@proxysql.com>*

### bd16436ea - 2026-01-21
**Fix MySQL 8.4 build on macOS with C++20 compatibility patch**
*René Cannaò <rene.cannao@gmail.com>*

### 7bf912105 - 2026-01-20
**sqlite3: fix duplicate proxy declarations and add forward declarations**
*Rene Cannao <rene@proxysql.com>*

### 2dfd61a95 - 2026-01-20
**Replace remaining direct sqlite3_* calls with proxy_sqlite3_* equivalents (address code-review)**
*Rene Cannao <rene@proxysql.com>*

### a24b8adaa - 2026-01-20
**Use proxy_sqlite3_* for SQLite calls in Anomaly_Detector.cpp (address PR review)**
*Rene Cannao <rene@proxysql.com>*

### d10cdd3db - 2026-01-20
**Updated macOS build instructions in INSTALL.md and added doc/BUILD-MACOS.md**
*René Cannaò <rene.cannao@gmail.com>*

### d43ae6e12 - 2026-01-20
**Surgical fixes for macOS compatibility: headers, types, and Makefile linking**
*René Cannaò <rene.cannao@gmail.com>*

### 8dc4246bd - 2026-01-20
**Introduce canonical proxy_sqlite3 symbol TU; update lib Makefile; remove MAIN_PROXY_SQLITE3 from main.cpp**
*Rene Cannao <rene@proxysql.com>*

### fdb8dfb15 - 2026-01-20
**Build system: Darwin-specific fixes and strict platform parity**
*René Cannaò <rene.cannao@gmail.com>*

### 18dd24943 - 2026-01-20
**Merge remote-tracking branch 'v3.1-vec' into v3.1_fts-support**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 7a7872f07 - 2026-01-20
**Organize RAG test files properly and update .gitignore**
*Rene Cannao <rene@proxysql.com>*

### 9311477fb - 2026-01-20
**Merge pull request #16 from rahim-kanji/v3.1_mcp-http-ssl-toggle**
*René Cannaò <rene.cannao@gmail.com>*

### 23aaf80cd - 2026-01-20
**fix: Address AI code review concerns for PR #19**
*Rene Cannao <rene@proxysql.com>*

### 8e2230c3e - 2026-01-20
**Add FTS_User_Guide.md**
*Rahim Kanji <rahim.kanji@outlook.com>*

### acd05b60a - 2026-01-20
**Organize RAG test files properly**
*Rene Cannao <rene@proxysql.com>*

### 0d5691874 - 2026-01-20
**Add full-text search (FTS) tools to MCP query server**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 5d08deca7 - 2026-01-20
**Fix AI agent review issues**
*Rene Cannao <rene@proxysql.com>*

### ed65b6905 - 2026-01-20
**Remove mistakenly created Doxygen files**
*Rene Cannao <rene@proxysql.com>*

### e450f1b30 - 2026-01-20
**MCP: Handle DELETE method**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 68a41d6db - 2026-01-20
**MCP: Add handler for prompts and resources**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 2f38def40 - 2026-01-20
**MCP: Handle client notifications properly**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### 155a77f96 - 2026-01-20
**MCP: Bump protocolVersion to 2025-06-18**
*Wazir Ahmed <wazirahmedf@gmail.com>*

### bf429f0a5 - 2026-01-20
**Fixed multiple issues**
*Rahim Kanji <rahim.kanji@outlook.com>*

### a1d9d2f1b - 2026-01-19
**docs: Add comprehensive documentation to MCP features**
*Rene Cannao <rene@proxysql.com>*

### ad166c6b8 - 2026-01-19
**docs: Add comprehensive Doxygen documentation for RAG subsystem**
*Rene Cannao <rene@proxysql.com>*

### 55715ecc4 - 2026-01-19
**feat: Complete RAG implementation according to blueprint specifications**
*Rene Cannao <rene@proxysql.com>*

### c092fdbd3 - 2026-01-19
**fix: Load re_modifiers field from database in load_mcp_query_rules()**
*Rene Cannao <rene@proxysql.com>*

### cc3cc2553 - 2026-01-19
**fix: Remove unused reset parameter from stats___mcp_query_rules()**
*Rene Cannao <rene@proxysql.com>*

### 8c9aecce9 - 2026-01-19
**feat: Add LOAD MCP QUERY RULES FROM DISK / TO MEMORY commands**
*Rene Cannao <rene@proxysql.com>*

### 7e6f9f0ab - 2026-01-19
**fix: Add MCP query rules LOAD/SAVE command handlers**
*Rene Cannao <rene@proxysql.com>*

### 1dc5eb658 - 2026-01-19
**fix: Fix RAG implementation compilation issues**
*Rene Cannao <rene@proxysql.com>*

### 3daaa5c59 - 2026-01-19
**feat: Implement RAG (Retrieval-Augmented Generation) subsystem**
*Rene Cannao <rene@proxysql.com>*

### 803115f50 - 2026-01-19
**Add RAG capability blueprint documents**
*Rene Cannao <rene@proxysql.com>*

### 994bafa31 - 2026-01-19
**Merge pull request #17 from ProxySQL/v3.1-MCP2_doc**
*René Cannaò <rene.cannao@gmail.com>*

### 5b8bb1952 - 2026-01-19
**Merge remote-tracking branch 'wqv3.1-vec' into v3.1_mcp-http-ssl-toggle**
*Rahim Kanji <rahim.kanji@outlook.com>*

### aced26336 - 2026-01-19
**docs: Update MCP documentation to reflect current implementation**
*Rene Cannao <rene@proxysql.com>*

### f01fc7958 - 2026-01-19
**feat: Add runtime_mcp_query_rules table and fix stats_mcp_query_rules schema**
*Rene Cannao <rene@proxysql.com>*

### 9b66224df - 2026-01-19
**Fix critical double-free bug, SQL injection vulnerability, and hardcoded path**
*Rahim Kanji <rahim.kanji@outlook.com>*

### f7397f633 - 2026-01-19
**Fix catalog search to use FTS5 and enhance test suite**
*Rahim Kanji <rahim.kanji@outlook.com>*

### f9c5a00f8 - 2026-01-19
**chore: Delete temporary discovery output files**
*Rene Cannao <rene@proxysql.com>*

### f449c4236 - 2026-01-19
**fix: Improve question learning fallback and error logging**
*Rene Cannao <rene@proxysql.com>*

### 5b502c086 - 2026-01-19
**feat: Add question learning capability to demo agent**
*Rene Cannao <rene@proxysql.com>*

### d228142de - 2026-01-19
**chore: Remove temporary discovery output files and add tmp/ to gitignore**
*Rene Cannao <rene@proxysql.com>*

### ee74384c7 - 2026-01-19
**fix: Prevent llm.search from returning huge object lists in list mode**
*Rene Cannao <rene@proxysql.com>*

### ba6cfdc8b - 2026-01-19
**feat: Update demo agent prompt to always pass schema parameter**
*Rene Cannao <rene@proxysql.com>*

### 7e522aa2c - 2026-01-19
**feat: Add schema parameter to run_sql_readonly with per-connection tracking**
*Rene Cannao <rene@proxysql.com>*

### a0e72aed0 - 2026-01-19
**feat: Add related_objects support to two-phase discovery**
*Rene Cannao <rene@proxysql.com>*

### 7faf99329 - 2026-01-19
**feat: Update demo agent script to leverage include_objects and add --help**
*Rene Cannao <rene@proxysql.com>*

### ee13e4bf1 - 2026-01-19
**feat: Add include_objects parameter to llm_search for complete object retrieval**
*Rene Cannao <rene@proxysql.com>*

### 73d3431c9 - 2026-01-18
**fix: Use heredocs for system prompt to preserve special characters**
*Rene Cannao <rene@proxysql.com>*

### 1b42cfbd2 - 2026-01-18
**feat: Add empty query support to llm_search for listing all artifacts**
*Rene Cannao <rene@proxysql.com>*

### be675d416 - 2026-01-18
**wip: Add interactive MCP query agent demo script using Claude Code**
*Rene Cannao <rene@proxysql.com>*

### 5668c8680 - 2026-01-18
**fix: Implement FTS indexing for LLM artifacts and fix reserved keyword issue**
*Rene Cannao <rene@proxysql.com>*

### 2250b762a - 2026-01-18
**feat: Add query_tool_calls table to log MCP tool invocations**
*Rene Cannao <rene@proxysql.com>*

### 8a395b9b4 - 2026-01-18
**style: Add spaces around commas in SQL CREATE TABLE statements**
*Rene Cannao <rene@proxysql.com>*

### 7c9328017 - 2026-01-18
**fix: Escape SQL reserved keyword 'limit' in llm_search_log table**
*Rene Cannao <rene@proxysql.com>*

### 77643859e - 2026-01-18
**feat: Add timing columns to stats_mcp_query_tools_counters**
*Rene Cannao <rene@proxysql.com>*

### fb66af7c1 - 2026-01-18
**feat: Expose MCP catalog database in ProxySQL Admin interface**
*Rene Cannao <rene@proxysql.com>*

### 7564306e1 - 2026-01-18
**Handledwq "notifications/initialized" method**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 4a858521c - 2026-01-18
**Fix JSON-RPC ID type**
*Rahim Kanji <rahim.kanji@outlook.com>*

### a15be695e - 2026-01-18
** Add GET/OPTIONS handlers for MCP HTTP transport**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 35b0b224f - 2026-01-18
**refactor: Remove mcp-catalog_path variable and hardcode catalog path**
*Rene Cannao <rene@proxysql.com>*

### a816a756d - 2026-01-18
**feat: Add MCP query tool usage counters to stats schema**
*Rene Cannao <rene@proxysql.com>*

### 393967f51 - 2026-01-18
**fix: Use row->cnt instead of row->fields_count**
*Rene Cannao <rene@proxysql.com>*

### df0527c04 - 2026-01-18
**refactor: list_schemas to use catalog instead of live database**
*Rene Cannao <rene@proxysql.com>*

### 527a748d1 - 2026-01-18
**refactor: Remove describe_table tool completely**
*Rene Cannao <rene@proxysql.com>*

### 623675b36 - 2026-01-18
**feat: Add schema name resolver and deprecate direct DB tools**
*Rene Cannao <rene@proxysql.com>*

### 757cdaff1 - 2026-01-18
**fix: Improve error logging and fix llm.domain_set_members**
*Rene Cannao <rene@proxysql.com>*

### ddc4e6570 - 2026-01-18
**Add plain HTTP support for MCP server and fix SSL/port restart issues**
*Rahim Kanji <rahim.kanji@outlook.com>*

### d962caea7 - 2026-01-18
**feat: Improve MCP error logging with request payloads**
*Rene Cannao <rene@proxysql.com>*

### 53ecda773 - 2026-01-18
**fix: Add comprehensive error handling and logging for MCP tools**
*Rene Cannao <rene@proxysql.com>*

### 1b7335acf - 2026-01-18
**Fix two-phase discovery documentation and scripts**
*Rene Cannao <rene@proxysql.com>*

### f9270e6c8 - 2026-01-18
**fix: Correct two_phase_discovery.py usage example in docs**
*Rene Cannao <rene@proxysql.com>*

### 6f23d5bcd - 2026-01-18
**feat: Implement two-phase schema discovery architecture**
*Rene Cannao <rene@proxysql.com>*

### 7de3f0c51 - 2026-01-17
**feat: Add schema separation to MCP catalog and discovery scope constraint**
*Rene Cannao <rene@proxysql.com>*

### 25cd0b71f - 2026-01-17
**chore: Add comprehensive gitignore for discovery output files**
*Rene Cannao <rene@proxysql.com>*

### 6fd58a6fd - 2026-01-17
**docs: Update README for v1.3 improvements**
*Rene Cannao <rene@proxysql.com>*

### 3895fe5ad - 2026-01-17
**feat: Add Priority 1 improvements from META agent analysis (v1.3)**
*Rene Cannao <rene@proxysql.com>*

### 24d2bb2c8 - 2026-01-17
**fix: Enforce MCP catalog usage and prohibit Write tool for agent findings**
*Rene Cannao <rene@proxysql.com>*

### 7ade08f57 - 2026-01-17
**chore: Remove accidentally committed discovery output file**
*Rene Cannao <rene@proxysql.com>*

### da0b5a5cf - 2026-01-17
**fix: Correct log message from 4-agent to 6-agent discovery**
*Rene Cannao <rene@proxysql.com>*

### 39b9ce6d5 - 2026-01-17
**feat: Add Question Catalog generation to all agents**
*Rene Cannao <rene@proxysql.com>*

### 130981d1b - 2026-01-17
**feat: Add SECURITY and META agents to multi-agent discovery**
*Rene Cannao <rene@proxysql.com>*

### 82d7f0c87 - 2026-01-17
**chore: Ignore discovery output files and remove accidentally committed file**
*Rene Cannao <rene@proxysql.com>*

### 4df56f1c4 - 2026-01-17
**fix: Increase default timeout to 1 hour and improve error handling**
*Rene Cannao <rene@proxysql.com>*

### aed042ba0 - 2026-01-17
**feat: Replace single-agent with multi-agent database discovery**
*Rene Cannao <rene@proxysql.com>*

### 91ea6f5e4 - 2026-01-17
**Merge pull request #10 from ProxySQL/v3.1-MCP1_discovery**
*René Cannaò <rene.cannao@gmail.com>*

### 61ad3c430 - 2026-01-17
**Merge pull request #13 from ProxySQL/v3.1-MCP1_genAI**
*René Cannaò <rene.cannao@gmail.com>*

### 1193a55e7 - 2026-01-17
**docs: Remove Version History section from LLM Bridge README**
*Rene Cannao <rene@proxysql.com>*

### 5afb71ca9 - 2026-01-17
**docs: Rename NL2SQL documentation to LLM Bridge**
*Rene Cannao <rene@proxysql.com>*

### a3f0bade4 - 2026-01-17
**feat: Convert NL2SQL to generic LLM bridge**
*Rene Cannao <rene@proxysql.com>*

### 3fe8a48f7 - 2026-01-17
**Fix genai variable handling and add API key masking**
*Rene Cannao <rene@proxysql.com>*

### 1eb42c57d - 2026-01-17
**fix: Add GenAI variables to runtime_global_variables population**
*Rene Cannao <rene@proxysql.com>*

### 6ffb59b85 - 2026-01-17
**fix: Use db parameter instead of hardcoded admindb in GenAI database_to_runtime**
*Rene Cannao <rene@proxysql.com>*

### 4018a0ad3 - 2026-01-17
**fix: Follow MCP pattern for GenAI variables runtime table population**
*Rene Cannao <rene@proxysql.com>*

### 1ea67900a - 2026-01-17
**fix: Populate runtime_global_variables for GenAI variables on startup**
*Rene Cannao <rene@proxysql.com>*

### 51fd51e3f - 2026-01-17
**fix: Add missing GenAI_Thread.h include and fix variables reference**
*Rene Cannao <rene@proxysql.com>*

### 349320a67 - 2026-01-17
**docs: Fix NL2SQL documentation with genai variables and async architecture**
*Rene Cannao <rene@proxysql.com>*

### a7dac5ef3 - 2026-01-16
**feat: Make NL2SQL use async GenAI path instead of blocking calls**
*Rene Cannao <rene@proxysql.com>*

### 527bfed29 - 2026-01-16
**fix: Migrate AI variables to GenAI module for proper architecture**
*Rene Cannao <rene@proxysql.com>*

### 3f25fb6c4 - 2026-01-16
**Enhance anomaly detector unit tests with additional edge case coverage**
*Rene Cannao <rene@proxysql.com>*

### 2888ee3f4 - 2026-01-16
**Fix gemini-code-assist recommendations and implement comprehensive anomaly detection tests**
*Rene Cannao <rene@proxysql.com>*

### 7665b3b3c - 2026-01-16
**Merge pull request #12 from ProxySQL/v3.1-MCP1_discovery_cc1**
*René Cannaò <rene.cannao@gmail.com>*

### ae4200dbc - 2026-01-16
**Enhance AI features with improved validation, memory safety, error handling, and performance monitoring**
*Rene Cannao <rene@proxysql.com>*

### 01f08ea90 - 2026-01-17
**Fix a crash (SIGABRT) that occurred when reloading MCP variables while the    MCP server was already running. The issue was caused by improper cleanup of    handler objects during reinitialization.**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 3032dffed - 2026-01-16
**test: Add NL2SQL internal functionality unit tests**
*Rene Cannao <rene@proxysql.com>*

### 8a6b7480b - 2026-01-16
**docs: Update NL2SQL documentation for v0.2.0 features**
*Rene Cannao <rene@proxysql.com>*

### 49092e9c8 - 2026-01-16
**test: Add unit tests for AI configuration validation**
*Rene Cannao <rene@proxysql.com>*

### 8f38b8a57 - 2026-01-16
**feat: Add exponential backoff retry for transient LLM failures**
*Rene Cannao <rene@proxysql.com>*

### d0dc36ac0 - 2026-01-16
**feat: Add structured logging with timing and request IDs**
*Rene Cannao <rene@proxysql.com>*

### 45e592b62 - 2026-01-16
**feat: Add structured error messages with context to NL2SQL**
*Rene Cannao <rene@proxysql.com>*

### 40b2608c2 - 2026-01-16
**feat: Add configuration validation to AI_Features_Manager**
*Rene Cannao <rene@proxysql.com>*

### 36b11223b - 2026-01-16
**feat: Improve SQL validation with multi-factor scoring**
*Rene Cannao <rene@proxysql.com>*

### 897d306d2 - 2026-01-16
**Refactor: Simplify NL2SQL to use only generic providers**
*Rene Cannao <rene@proxysql.com>*

### c5a7fc31f - 2026-01-16
**Add external LLM setup guide and live testing script**
*Rene Cannao <rene@proxysql.com>*

### 3b7033f44 - 2026-01-16
**Add vector features verification script**
*Rene Cannao <rene@proxysql.com>*

### 1a8b406d9 - 2026-01-16
**fix: Correct SQL query for AI variables in vector features test**
*Rene Cannao <rene@proxysql.com>*

### 637b2a669 - 2026-01-16
**feat: Implement NL2SQL vector cache and complete Anomaly threat pattern management**
*Rene Cannao <rene@proxysql.com>*

### 782f6cb66 - 2026-01-16
**feat: Implement threat pattern management and improve statistics**
*Rene Cannao <rene@proxysql.com>*

### f5c18fd8d - 2026-01-16
**scripts: Add threat pattern documentation script**
*Rene Cannao <rene@proxysql.com>*

### 4b0cb9d95 - 2026-01-16
**test: Add vector features unit test**
*Rene Cannao <rene@proxysql.com>*

### 1c7cd8c2b - 2026-01-16
**fix: Correct PROXY_DEBUG constant from AI_GENERIC to GENAI**
*Rene Cannao <rene@proxysql.com>*

### f226c0e68 - 2026-01-16
**feat: Implement embedding-based threat similarity for Anomaly Detection**
*Rene Cannao <rene@proxysql.com>*

### fec7d6409 - 2026-01-16
**feat: Implement NL2SQL vector cache with GenAI embedding generation**
*Rene Cannao <rene@proxysql.com>*

### 0be971518 - 2026-01-16
**test: Add comprehensive tests and documentation for Anomaly Detection**
*Rene Cannao <rene@proxysql.com>*

### 52a70b0b0 - 2026-01-16
**feat: Implement AI-based Anomaly Detection for ProxySQL**
*Rene Cannao <rene@proxysql.com>*

### 3f44229e2 - 2026-01-16
**feat: Add MCP AI Tool Handler for NL2SQL with test script**
*Rene Cannao <rene@proxysql.com>*

### 83c398307 - 2026-01-16
**chore: Remove stale database discovery report files from root**
*Rene Cannao <rene@proxysql.com>*

### eccb2bfe4 - 2026-01-16
**test: Add integration tests for NL2SQL**
*Rene Cannao <rene@proxysql.com>*

### 6d2b0ab30 - 2026-01-16
**test: Fix vector keyword conflict in NL2SQL unit tests**
*Rene Cannao <rene@proxysql.com>*

### e2d71ec4a - 2026-01-16
**docs: Add comprehensive NL2SQL user and developer documentation**
*Rene Cannao <rene@proxysql.com>*

### aee9c3117 - 2026-01-16
**test: Add E2E test script for NL2SQL**
*Rene Cannao <rene@proxysql.com>*

### a61f709c7 - 2026-01-16
**test: Add comprehensive TAP unit tests for NL2SQL**
*Rene Cannao <rene@proxysql.com>*

### af68f347d - 2026-01-16
**fix: Add missing verbosity level to proxy_debug call in Anomaly_Detector**
*Rene Cannao <rene@proxysql.com>*

### 4f45c2594 - 2026-01-16
**docs: Add comprehensive doxygen comments to NL2SQL headers and LLM_Clients**
*Rene Cannao <rene@proxysql.com>*

### 6dd2613d6 - 2026-01-16
**Move discovery docs to examples directory**
*Rene Cannao <rene@proxysql.com>*

### bc4fff12c - 2026-01-16
**feat: Add NL2SQL query interception in MySQL_Session**
*Rene Cannao <rene@proxysql.com>*

### 147a05978 - 2026-01-16
**feat: Add NL2SQL converter with hybrid LLM support**
*Rene Cannao <rene@proxysql.com>*

### d9346fe64 - 2026-01-16
**feat: Add AI features manager foundation**
*Rene Cannao <rene@proxysql.com>*

### 2637d28f3 - 2026-01-16
**Merge pull request #5299 from sysown/v3.0_pg-cancel-terminate-backend-param-support_5298**
*René Cannaò <rene@proxysql.com>*

### 3bcb9e0bd - 2026-01-16
**Merge pull request #5301 from sysown/v3.0_fix-pgsql-threshold-deadlock_5300**
*René Cannaò <rene@proxysql.com>*

### d1050228a - 2026-01-16
**Merge pull request #5294 from sysown/v3.0_fix_reg_test_5233_set_warning-t_test**
*René Cannaò <rene@proxysql.com>*

### 9f377eec4 - 2026-01-16
**Merge pull request #5302 from sysown/v3.0.6-bump_version**
*René Cannaò <rene@proxysql.com>*

### fdee58a26 - 2026-01-16
**Add comprehensive database discovery outputs and enhance headless discovery**
*Rene Cannao <rene@proxysql.com>*

### b41a135e0 - 2026-01-15
**bump version to 3.0.6 at the beginning of the development cycle**
*Miro Stauder <miro@proxysql.com>*

### c2337d22b - 2026-01-15
**Added regression test**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 9ec045ca7 - 2026-01-15
**Fix PostgreSQL deadlock with Close Statement flood exceeding threshold_resultset_size**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 67cbe4645 - 2026-01-14
**Simplify PID extraction**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 5066ddd18 - 2026-01-14
**Removed isdigit**
*Rahim Kanji <rahim.kanji@outlook.com>*

### ce42c188f - 2026-01-14
**Improvements**
*Rahim Kanji <rahim.kanji@outlook.com>*

### a892d9a05 - 2026-01-14
**Add pgsql-parameterized_kill_queries_test-t test to groups.json**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 22afe6cb6 - 2026-01-14
**Add test**
*Rahim Kanji <rahim.kanji@outlook.com>*

### a1e10e305 - 2026-01-14
**Add parameterized PID support for pg_cancel_backend/pg_terminate_backend**
*Rahim Kanji <rahim.kanji@outlook.com>*

### b627f836f - 2026-01-14
**Refactor: Reorganize headless discovery scripts to dedicated directory**
*Rene Cannao <rene@proxysql.com>*

### d73ce0c41 - 2026-01-14
**Add headless database discovery scripts**
*Rene Cannao <rene@proxysql.com>*

### 14de472a3 - 2026-01-14
**Add multi-agent database discovery system**
*Rene Cannao <rene@proxysql.com>*

### f85290036 - 2026-01-13
**Fix: Correct MCP catalog JSON parsing to handle special characters**
*Rene Cannao <rene@proxysql.com>*

### 1d046148d - 2026-01-13
**Fix: Address code review feedback from coderabbitai and gemini-code-assist**
*Rene Cannao <rene@proxysql.com>*

### 304bb5abf - 2026-01-13
**Merge pull request #11 from ProxySQL/v3.1-MCP1_discovery_2**
*René Cannaò <rene.cannao@gmail.com>*

### 606fe2e93 - 2026-01-13
**Fix: Address code review feedback from gemini-code-assist**
*Rene Cannao <rene@proxysql.com>*

### 2ceaac049 - 2026-01-13
**docs: Add logging section to bridge README**
*Rene Cannao <rene@proxysql.com>*

### 49e964bb0 - 2026-01-13
**Fix: Make ProxySQL MCP server return MCP-compliant tool responses**
*Rene Cannao <rene@proxysql.com>*

### 9b4aea047 - 2026-01-13
**Fix: Wrap tools/call responses in MCP-compliant content format**
*Rene Cannao <rene@proxysql.com>*

### 77099f7af - 2026-01-13
**Debug: Add minimal logging to track stdout writes and tool calls**
*Rene Cannao <rene@proxysql.com>*

### a47567fee - 2026-01-13
**Revert: Restore original bridge completely**
*Rene Cannao <rene@proxysql.com>*

### 23e5efca5 - 2026-01-13
**Test: Don't redirect sys.stderr, write logs directly to file**
*Rene Cannao <rene@proxysql.com>*

### f4a4af8d8 - 2026-01-13
**Fix: Write directly to stdout.buffer to bypass TextIOWrapper issues**
*Rene Cannao <rene@proxysql.com>*

### ad54f92dc - 2026-01-13
**Revert: Simplify tool handlers back to original pass-through**
*Rene Cannao <rene@proxysql.com>*

### 2b5134632 - 2026-01-13
**Fix: Wrap tool results in TextContent format for MCP protocol compliance**
*Rene Cannao <rene@proxysql.com>*

### 55dd5ba57 - 2026-01-13
**Debug: Add detailed stdout write logging to troubleshoot Claude Code timeout**
*Rene Cannao <rene@proxysql.com>*

### f5606986f - 2026-01-13
**Fix: Replace stdout with truly unbuffered wrapper to prevent response buffering**
*Rene Cannao <rene@proxysql.com>*

### edac8eb5e - 2026-01-13
**Fix: Add verbose logging and fix stdout buffering issue in MCP stdio bridge**
*Rene Cannao <rene@proxysql.com>*

### 6d83ff168 - 2026-01-13
**Fix: unwrap ProxySQL response format in MCP tools and fix config syntax**
*Rene Cannao <rene@proxysql.com>*

### fc6b462be - 2026-01-13
**Fix: unwrap ProxySQL nested response format**
*Rene Cannao <rene@proxysql.com>*

### 4491f3ce0 - 2026-01-13
**Add debug logging to MCP bridge for troubleshooting**
*Rene Cannao <rene@proxysql.com>*

### 01c182cca - 2026-01-13
**Add stdio MCP bridge for Claude Code integration**
*Rene Cannao <rene@proxysql.com>*

### 9d6a2173b - 2026-01-13
**Enhance Rich CLI with configurable LLM chat path and better tracing**
*Rene Cannao <rene@proxysql.com>*

### f2ca750c0 - 2026-01-13
**Add MCP Database Discovery Agent (initial commit)**
*Rene Cannao <rene@proxysql.com>*

### d504c93b4 - 2026-01-13
**Fix formatting in proxysql.cfg**
*René Cannaò <rene.cannao@gmail.com>*

### b9175f848 - 2026-01-12
**Fixed reg_test_5233_set_warning-t**
*Rahim Kanji <rahim.kanji@outlook.com>*

### 119ca5003 - 2026-01-12
**Fix compilation errors in debug build**
*Rene Cannao <rene@proxysql.com>*

### 95a164d21 - 2026-01-12
**Merge pull request #9 from ProxySQL/v3.1-MCP1**
*René Cannaò <rene.cannao@gmail.com>*

### 313f637cf - 2026-01-12
**Merge branch 'v3.1-vec' into v3.1-MCP1**
*René Cannaò <rene.cannao@gmail.com>*

### 2ef44e7c3 - 2026-01-12
**Add MCP implementation plans for FTS and Vector Embeddings**
*Rene Cannao <rene@proxysql.com>*

### d51aadffb - 2026-01-12
**Merge pull request #7 from ProxySQL/v3.1-vec_genAI_module**
*René Cannaò <rene.cannao@gmail.com>*

### 07dc887af - 2026-01-12
**Add MCP Tool Discovery Guide**
*Rene Cannao <rene@proxysql.com>*

### 5846cd8b4 - 2026-01-12
**Add Database Discovery Agent architecture documentation**
*Rene Cannao <rene@proxysql.com>*

### ef5b99edb - 2026-01-12
**Fix MCP tool bugs: NULL value handling and query validation**
*Rene Cannao <rene@proxysql.com>*

### 22db1a5fd - 2026-01-12
**Fix JSON value extraction in Query_Tool_Handler::execute_tool**
*Rene Cannao <rene@proxysql.com>*

### acb4c57db - 2026-01-12
**Fix case sensitivity issues in MySQL_Tool_Handler::execute_query**
*Rene Cannao <rene@proxysql.com>*

### 904283330 - 2026-01-12
**Fix critical use-after-free bug in MySQL_Tool_Handler::execute_query**
*Rene Cannao <rene@proxysql.com>*

### de33d177b - 2026-01-12
**Fix verbose mode in test_mcp_tools.sh**
*Rene Cannao <rene@proxysql.com>*

### 25cda31f0 - 2026-01-12
**Update test_mcp_tools.sh with dynamic tool discovery**
*Rene Cannao <rene@proxysql.com>*

### ced10dd05 - 2026-01-12
**Implement per-endpoint authentication for MCP endpoints**
*Rene Cannao <rene@proxysql.com>*

### c86a048d9 - 2026-01-12
**Implement MCP multi-endpoint architecture with dedicated tool handlers**
*Rene Cannao <rene@proxysql.com>*

### 093511920 - 2026-01-11
**Add environment variable printing to MCP scripts**
*Rene Cannao <rene@proxysql.com>*

### 7f957088e - 2026-01-11
**Fix configure_mcp.sh to allow empty MySQL passwords**
*Rene Cannao <rene@proxysql.com>*

### 991f0138d - 2026-01-11
**Reinitialize MySQL Tool Handler when MCP variables change**
*Rene Cannao <rene@proxysql.com>*

### 49e6ac5bc - 2026-01-11
**Revert configure_mcp.sh to respect environment variables**
*Rene Cannao <rene@proxysql.com>*

### 40cff23c3 - 2026-01-11
**Initialize MySQL Tool Handler and fix default MySQL port**
*Rene Cannao <rene@proxysql.com>*

### aeafa61a1 - 2026-01-11
**Fix test_mcp_tools.sh to use correct MCP endpoint paths**
*Rene Cannao <rene@proxysql.com>*

### d17fe1dba - 2026-01-11
**Fix configure_mcp.sh error handling and endpoint paths**
*Rene Cannao <rene@proxysql.com>*

### 60d4a7378 - 2026-01-11
**Implement automatic MCP server start/stop and add environment variable support**
*Rene Cannao <rene@proxysql.com>*

### a5f712e7d - 2026-01-11
**Add MCP variables documentation**
*Rene Cannao <rene@proxysql.com>*

### 33a100c1d - 2026-01-11
**Use relative path mcp_catalog.db in MCP test instead of absolute /var/lib/proxysql path**
*Rene Cannao <rene@proxysql.com>*

### 5a85ef04f - 2026-01-11
**Fix MCP variables persistence and add DISK command support**
*Rene Cannao <rene@proxysql.com>*

### b70b07ead - 2026-01-11
**Skip checksum generation for MCP until feature is complete**
*Rene Cannao <rene@proxysql.com>*

### 2e7109d89 - 2026-01-11
**Fix lock ordering in flush_mcp_variables___database_to_runtime**
*Rene Cannao <rene@proxysql.com>*

### 2874c9ad5 - 2026-01-11
**Fix flush_mcp_variables___database_to_runtime to populate runtime_global_variables**
*Rene Cannao <rene@proxysql.com>*

### ef0783178 - 2026-01-11
**Add MCP module to admin bootstrap and SHOW MCP VARIABLES command**
*Rene Cannao <rene@proxysql.com>*

### 28742554b - 2026-01-11
**Use relative catalog path instead of absolute path**
*Rene Cannao <rene@proxysql.com>*

### c53b28e42 - 2026-01-11
**Add comprehensive documentation to MCP README**
*Rene Cannao <rene@proxysql.com>*

### b3646b479 - 2026-01-11
**Fix argument parsing and documentation in setup_test_db.sh**
*Rene Cannao <rene@proxysql.com>*

### 3d827144e - 2026-01-11
**Add required environment variables section to README**
*Rene Cannao <rene@proxysql.com>*

### ad2e2a24d - 2026-01-11
**Add native MySQL mode support to test database setup**
*Rene Cannao <rene@proxysql.com>*

### e9a6dd0b3 - 2026-01-11
**Add comprehensive MCP testing suite in scripts/mcp/**
*Rene Cannao <rene@proxysql.com>*

### 06aa6d6ef - 2026-01-11
**Add comprehensive Doxygen documentation for connection pool**
*Rene Cannao <rene@proxysql.com>*

### 4eab51984 - 2026-01-11
**Implement MySQL connection pool for MySQL_Tool_Handler**
*Rene Cannao <rene@proxysql.com>*

### 221ff2399 - 2026-01-11
**Add MySQL exploration MCP tools with SQLite catalog**
*Rene Cannao <rene@proxysql.com>*

### b032c3f69 - 2026-01-11
**Fix boolean literal handling in SET command for MCP variables**
*Rene Cannao <rene@proxysql.com>*

### 81c53896b - 2026-01-11
**Fix MCP module TAP test failures**
*Rene Cannao <rene@proxysql.com>*

### 245e61ee8 - 2026-01-11
**Make MCP_Threads_Handler a standalone independent class**
*Rene Cannao <rene@proxysql.com>*

### de3fd05a5 - 2026-01-11
**Reverted change to test/tap/tests/.env**
*Rene Cannao <rene@proxysql.com>*

### 87fff9e04 - 2026-01-11
**Add MCP (Model Context Protocol) module skeleton**
*Rene Cannao <rene@proxysql.com>*

### 33a87c66a - 2026-01-10
**Fix critical issues identified by gemini-code-assist**
*Rene Cannao <rene@proxysql.com>*

### b77d38c2c - 2026-01-10
**Add comprehensive GenAI module documentation**
*Rene Cannao <rene@proxysql.com>*

### bdd2ef70e - 2026-01-10
**Add comprehensive TAP tests for GenAI async architecture**
*Rene Cannao <rene@proxysql.com>*

### db2485be3 - 2026-01-10
**Add comprehensive doxygen documentation to GenAI async module**
*Rene Cannao <rene@proxysql.com>*

### 840502712 - 2026-01-10
**Integrate GenAI async event handling into main MySQL session loop**
*Rene Cannao <rene@proxysql.com>*

### 0ff2e38e2 - 2026-01-09
**Implement async GenAI module with socketpair-based non-blocking architecture**
*Rene Cannao <rene@proxysql.com>*

### bbad8ab4f - 2026-01-09
**Fix GenAI variable naming and add comprehensive TAP tests**
*Rene Cannao <rene@proxysql.com>*

### a82f58e22 - 2026-01-09
**Refactor GenAI module for autonomous JSON query processing**
*Rene Cannao <rene@proxysql.com>*

### cc3e97b7b - 2026-01-09
**Merge EMBED and RERANK into unified GENAI: query syntax**
*Rene Cannao <rene@proxysql.com>*

### 39939f598 - 2026-01-09
**Add experimental GenAI RERANK: query support for MySQL**
*Rene Cannao <rene@proxysql.com>*

### 253591d26 - 2026-01-09
**Add experimental GenAI EMBED: query support for MySQL**
*Rene Cannao <rene@proxysql.com>*

### b5598d8d5 - 2026-01-09
**Add comprehensive ProxySQL_Poll usage documentation throughout codebase**
*Rene Cannao <rene.cannao@gmail.com>*

### fa301948b - 2026-01-09
**Remove genai_demo_event binary from tracking and update .gitignore**
*Rene Cannao <rene@proxysql.com>*

### 1da9e384d - 2026-01-09
**Add poll() fallback for GenAI module when epoll is not available**
*Rene Cannao <rene@proxysql.com>*

### 960704066 - 2026-01-09
**Implement real GenAI module with embedding and rerank support**
*Rene Cannao <rene@proxysql.com>*

### f0a32c00b - 2026-01-09
**Add rerank support to GenAI prototype via llama-server**
*Rene Cannao <rene@proxysql.com>*

### aa5361092 - 2026-01-09
**Add batch embedding support and scale up GenAI prototype**
*Rene Cannao <rene@proxysql.com>*

### 2c0f3a2e6 - 2026-01-09
**Evolve genai_demo_event to working POC with real embeddings**
*Rene Cannao <rene@proxysql.com>*

### 012142eee - 2026-01-08
**Fix event-driven GenAI demo and add early termination**
*Rene Cannao <rene@proxysql.com>*

### 11d183a34 - 2026-01-08
**Add event-driven GenAI demo**
*Rene Cannao <rene@proxysql.com>*

### 89285aa43 - 2026-01-08
**Add comprehensive Doxygen documentation to genai_demo.cpp**
*Rene Cannao <rene@proxysql.com>*

### 5dad6255d - 2026-01-08
**Add GenAI module prototype**
*Rene Cannao <rene@proxysql.com>*

### 99dbd0a35 - 2026-01-08
**Add TAP test for GenAI module**
*Rene Cannao <rene@proxysql.com>*

### a50a5487a - 2026-01-08
**Merge pull request #6 from ProxySQL/v3.1-vec4**
*René Cannaò <rene.cannao@gmail.com>*

### 62cbd6c71 - 2026-01-08
**Fix issues identified in AI code review**
*Rene Cannao <rene@proxysql.com>*

### 59f0b8b1f - 2026-01-08
**Fix GenAI module admin commands - correct character check**
*Rene Cannao <rene@proxysql.com>*

### c476f56f9 - 2026-01-07
**Add initial GenAI module placeholder**
*Rene Cannao <rene@proxysql.com>*

### ecfff0963 - 2026-01-07
**Add NLP search demo script with comprehensive search capabilities**
*Rene Cannao <rene@proxysql.com>*

### d37d29148 - 2026-01-03
**Implement comprehensive StackExchange posts processing with search capabilities**
*Rene Cannao <rene@proxysql.com>*

### d94dc036e - 2026-01-03
**Add StackExchange posts processing script with JSON storage**
*Rene Cannao <rene@proxysql.com>*

### 5a6520ad7 - 2025-12-25
**Ignore extracted sqlite-rembed source directory**
*Rene Cannao <rene@proxysql.com>*

### cbf27eb60 - 2025-12-25
**Add vec0 KNN LIMIT constraint documentation for Posts embeddings**
*Rene Cannao <rene@proxysql.com>*

### 5786c7918 - 2025-12-24
**Merge pull request #4 from ProxySQL/v3.1-fts1**
*René Cannaò <rene.cannao@gmail.com>*

### 0b0ad0236 - 2025-12-24
**Merge pull request #3 from ProxySQL/v3.1-vec3**
*René Cannaò <rene.cannao@gmail.com>*

### 221831afc - 2025-12-24
**Add usage examples to script documentation and help output**
*Rene Cannao <rene@proxysql.com>*

### 4aba7137b - 2025-12-24
**Add --local-ollama option for local Ollama server support**
*Rene Cannao <rene@proxysql.com>*

### 0372556f2 - 2025-12-24
**Enable SQLite FTS5 support for full-text search**
*Rene Cannao <rene@proxysql.com>*

### ffdb334dc - 2025-12-24
**Add WHERE filters to prevent empty input errors and fix SQL syntax**
*Rene Cannao <rene@proxysql.com>*

### 36a59f3f5 - 2025-12-24
**Add Posts embeddings processing script with exponential backoff**
*Rene Cannao <rene@proxysql.com>*

### de2211400 - 2025-12-24
**Merge pull request #2 from ProxySQL/v3.1-vec2**
*René Cannaò <rene.cannao@gmail.com>*

### 17b9e0a4d - 2025-12-24
**Merge pull request #1 from ProxySQL/v3.1-vec1**
*René Cannaò <rene.cannao@gmail.com>*

### 8e8363576 - 2025-12-23
**Add Posts embeddings setup documentation with optimized batch processing**
*Rene Cannao <rene@proxysql.com>*

### 95a95cb47 - 2025-12-23
**Add script to copy StackExchange Posts table from MySQL to SQLite3 server**
*Rene Cannao <rene@proxysql.com>*

### 612ef326b - 2025-12-23
**Fix sqlite-rembed demonstration scripts and add environment variable support**
*Rene Cannao <rene@proxysql.com>*

### e75bd7c84 - 2025-12-23
**Add comprehensive sqlite-rembed examples and documentation**
*Rene Cannao <rene@proxysql.com>*

### 194b71889 - 2025-12-22
**Update sqlite-rembed integration documentation for tar.gz packaging**
*Rene Cannao <rene@proxysql.com>*

### 9f30d85e1 - 2025-12-22
**Add tar.gz packaging for sqlite-rembed dependency**
*Rene Cannao <rene@proxysql.com>*

### 01d654692 - 2025-12-22
**Integrate sqlite-rembed for text embedding generation**
*Rene Cannao <rene@proxysql.com>*

### ea09e9156 - 2025-12-22
**Remove inline vector search testing documentation**
*Rene Cannao <rene@proxysql.com>*

### 223dcf51d - 2025-12-22
**Add vector search testing framework with modular scripts**
*Rene Cannao <rene@proxysql.com>*

### d4f838519 - 2025-12-22
**Add comprehensive vector search testing guide**
*Rene Cannao <rene@proxysql.com>*

### a1dc68833 - 2025-12-22
**Add accurate SQLite3 Server documentation**
*Rene Cannao <rene@proxysql.com>*

### d55947b49 - 2025-12-22
**Add comprehensive documentation for sqlite-vec integration**
*Rene Cannao <rene@proxysql.com>*

### fbd0d9732 - 2025-12-22
**Add sqlite-vec static extension for vector search in ProxySQL**
*Rene Cannao <rene@proxysql.com>*

### f561d83ba - 2025-07-29
**Avoid usage of deleted connection**
*Juan Manuel Fernández García-Minguillán <jmfernandez@tuenti.com>*

### 172bf9f48 - 2025-07-15
**Fix int overflow if the first server is invalid**
*Juan Manuel Fernández García-Minguillán <jmfernandez@tuenti.com>*

### db4f7d9c7 - 2025-07-24
**Fix delete connection with incorrect index**
*Juan Manuel Fernández García-Minguillán <jmfernandez@tuenti.com>*

### 855474213 - 2025-08-04
**Avoid send close in ssl connections**
*Juan Manuel Fernández García-Minguillán <jmfernandez@tuenti.com>*

### 949eda1cc - 2025-08-11
**generate postgres metrics in addition to mysql metrics**
*Evgeny Kuzin <evgeny.kuzin@outlook.com>*

### 2b44aaa58 - 2025-08-08
**add protocol labels for shared metrics between mysql and psql**
*Evgeny Kuzin <evgeny.kuzin@outlook.com>*
