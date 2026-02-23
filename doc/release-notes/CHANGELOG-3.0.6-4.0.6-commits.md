# ProxySQL 3.0.6 / 4.0.6 - Categorized Commits

> **Generated:** 2026-02-23
> **Total commits:** 725

---

## Summary by Type

| **Build** | 14 |
| **Docs** | 11 |
| **Feature** | 242 |
| **Fix** | 192 |
| **Improvement** | 38 |
| **Other** | 93 |
| **Test** | 33 |

**Total: 623 commits**

---


## Build


### Core (14 commits)

- `0691b8a85` build: address reviewer feedback and finalize dynamic linking architecture 
- `788be4adb` build: restore dynamic linking and configure rpath for shared dependencies 
- `ba893e7ce` build: transition libtap to static archive and bundle dependencies 
- `9410a60f6` build: make Rust toolchain optional, only required for PROXYSQLGENAI 
- `acdd4c91b` build: replace grep -oP with sed -E for macOS compatibility 
- `432cdfe49` Modify Makefile to increment major version when PROXYSQLGENAI is enabled 
- `08e7c8ce9` chore: Remove data files mistakenly added to root folder 
- `9e980d924` update docker build image versions in docker-compose.yml 
- `93517540a` Added Makefile for rag_ingest 
- `d43ae6e12` Surgical fixes for macOS compatibility: headers, types, and Makefile linking 
- `f9c5a00f8` chore: Delete temporary discovery output files 
- `7ade08f57` chore: Remove accidentally committed discovery output file 
- `82d7f0c87` chore: Ignore discovery output files and remove accidentally committed file 
- `83c398307` chore: Remove stale database discovery report files from root 

## Docs


### Core (6 commits)

- `d10cdd3db` Updated macOS build instructions in INSTALL.md and added doc/BUILD-MACOS.md 
- `ed65b6905` Remove mistakenly created Doxygen files 
- `6fd58a6fd` docs: Update README for v1.3 improvements 
- `1193a55e7` docs: Remove Version History section from LLM Bridge README 
- `5afb71ca9` docs: Rename NL2SQL documentation to LLM Bridge 
- `8a6b7480b` docs: Update NL2SQL documentation for v0.2.0 features 

### MCP (2 commits)

- `6a2f77784` doc: Document existing `stats` tables and `/mcp/stats` tools & implementation 
- `aced26336` docs: Update MCP documentation to reflect current implementation 

### RAG (1 commits)

- `ea09e9156` Remove inline vector search testing documentation 

### SQLite (1 commits)

- `194b71889` Update sqlite-rembed integration documentation for tar.gz packaging 

### TSDB (1 commits)

- `2267ef245` doc: update TSDB documentation 

## Feature


### Admin (3 commits)

- `afd6dffb0` Fix admin shutdown races and implement graceful teardown 
- `a17593b99` Add rand5_admin_1 test group environment configuration 
- `cc1d93d08` implement admin command 'PROXYSQL FLUSH STATS' for DEBUG builds 

### Core (85 commits)

- `f36eb318b` test: implement and document internal_noise_mysql_traffic_v2 
- `3f7479bd0` Improve reg_test_2233: Add cleanup and user creation 
- `42acaf8ae` Add reg_test_5389-flush_logs_no_drop to test groups 
- `17092487c` Add protocol-labeled logger counters and FLUSH LOGS race TAP 
- `ab1173ea4` Add TAP test for query rules routing 
- `2538e303c` tap ai: add dual-backend static-harvest fixtures and target_id coverage test 
- `c133d716b` Improve reg_test_2233: Add SQLite3 Server support and documentation 
- `946052099` Add more tests 
- `ba5afd0bb` Add TAP test 
- `41564acaa` Fix #5355: Add null pointer check in RequestEnd() to prevent use-after-free crash #5355
- `3d3831565` add --locked to cargo build to ensure reproducibility 
- `e3bdd3c07` main: add macOS support for executable SHA1 calculation 
- `763d4df53` chore: add scram.c.diff patch reference for security fix v3.0 
- `a94b7d6b2` Add PROXYSQLGENAI support to docker builds 
- `70c404901` Add test group environment configurations 
- `e351a0df7` feat: Add leading comments (--) detection for 'run_sql_readonly' 
- `79ee743a4` Add detailed logging and per-source commits to rag_ingest 
- `fe76479cf` add fedora43, remove fedora40 
- `03e58146e` fix: Re-enable SQLite3DB::LoadPlugin() with allow_load_plugin flag 
- `5e121399a` fix: Add AFTER UPDATE trigger to keep catalog_fts index in sync for upserts 
- `5dd5dbe6b` fix: Add missing assert(proxy_sqlite3_bind_blob) in sqlite3db.cpp 
- `18cc24620` fix: Add missing proxy declarations to MAIN_PROXY_SQLITE3 branch 
- `7bf912105` sqlite3: fix duplicate proxy declarations and add forward declarations 
- `8dc4246bd` Introduce canonical proxy_sqlite3 symbol TU; update lib Makefile; remove MAIN_PROXY_SQLITE3 from main.cpp 
- `8e2230c3e` Add FTS_User_Guide.md 
- `5b502c086` feat: Add question learning capability to demo agent 
- `d228142de` chore: Remove temporary discovery output files and add tmp/ to gitignore 
- `ba6cfdc8b` feat: Update demo agent prompt to always pass schema parameter 
- `7e522aa2c` feat: Add schema parameter to run_sql_readonly with per-connection tracking 
- `a0e72aed0` feat: Add related_objects support to two-phase discovery 
- `7faf99329` feat: Update demo agent script to leverage include_objects and add --help 
- `ee13e4bf1` feat: Add include_objects parameter to llm_search for complete object retrieval 
- `1b42cfbd2` feat: Add empty query support to llm_search for listing all artifacts 
- `5668c8680` fix: Implement FTS indexing for LLM artifacts and fix reserved keyword issue 
- `8a395b9b4` style: Add spaces around commas in SQL CREATE TABLE statements 
- `623675b36` feat: Add schema name resolver and deprecate direct DB tools 
- `6f23d5bcd` feat: Implement two-phase schema discovery architecture 
- `25cd0b71f` chore: Add comprehensive gitignore for discovery output files 
- `3895fe5ad` feat: Add Priority 1 improvements from META agent analysis (v1.3) 
- `39b9ce6d5` feat: Add Question Catalog generation to all agents 
- `130981d1b` feat: Add SECURITY and META agents to multi-agent discovery 
- `aed042ba0` feat: Replace single-agent with multi-agent database discovery 
- `a3f0bade4` feat: Convert NL2SQL to generic LLM bridge 
- `3032dffed` test: Add NL2SQL internal functionality unit tests 
- `49092e9c8` test: Add unit tests for AI configuration validation 
- `8f38b8a57` feat: Add exponential backoff retry for transient LLM failures 
- `d0dc36ac0` feat: Add structured logging with timing and request IDs 
- `45e592b62` feat: Add structured error messages with context to NL2SQL 
- `36b11223b` feat: Improve SQL validation with multi-factor scoring 
- `c5a7fc31f` Add external LLM setup guide and live testing script 
- `3b7033f44` Add vector features verification script 
- `637b2a669` feat: Implement NL2SQL vector cache and complete Anomaly threat pattern management 
- `782f6cb66` feat: Implement threat pattern management and improve statistics 
- `f5c18fd8d` scripts: Add threat pattern documentation script 
- `4b0cb9d95` test: Add vector features unit test 
- `eccb2bfe4` test: Add integration tests for NL2SQL 
- `e2d71ec4a` docs: Add comprehensive NL2SQL user and developer documentation 
- `aee9c3117` test: Add E2E test script for NL2SQL 
- `a61f709c7` test: Add comprehensive TAP unit tests for NL2SQL 
- `4f45c2594` docs: Add comprehensive doxygen comments to NL2SQL headers and LLM_Clients 
- `bc4fff12c` feat: Add NL2SQL query interception in MySQL_Session 
- `147a05978` feat: Add NL2SQL converter with hybrid LLM support 
- `d9346fe64` feat: Add AI features manager foundation 
- `fdee58a26` Add comprehensive database discovery outputs and enhance headless discovery 
- `22afe6cb6` Add test 
- `a1e10e305` Add parameterized PID support for pg_cancel_backend/pg_terminate_backend 
- `d73ce0c41` Add headless database discovery scripts 
- `14de472a3` Add multi-agent database discovery system 
- `2ceaac049` docs: Add logging section to bridge README 
- `77099f7af` Debug: Add minimal logging to track stdout writes and tool calls 
- `55dd5ba57` Debug: Add detailed stdout write logging to troubleshoot Claude Code timeout 
- `5846cd8b4` Add Database Discovery Agent architecture documentation 
- `3d827144e` Add required environment variables section to README 
- `06aa6d6ef` Add comprehensive Doxygen documentation for connection pool 
- `b5598d8d5` Add comprehensive ProxySQL_Poll usage documentation throughout codebase 
- `ecfff0963` Add NLP search demo script with comprehensive search capabilities 
- `d37d29148` Implement comprehensive StackExchange posts processing with search capabilities 
- `d94dc036e` Add StackExchange posts processing script with JSON storage 
- `cbf27eb60` Add vec0 KNN LIMIT constraint documentation for Posts embeddings 
- `221831afc` Add usage examples to script documentation and help output 
- `4aba7137b` Add --local-ollama option for local Ollama server support 
- `ffdb334dc` Add WHERE filters to prevent empty input errors and fix SQL syntax 
- `36a59f3f5` Add Posts embeddings processing script with exponential backoff 
- `8e8363576` Add Posts embeddings setup documentation with optimized batch processing 
- `a1dc68833` Add accurate SQLite3 Server documentation 

### FFTO (5 commits)

- `05b723c25` test: Add descriptive diag messages to all test_ffto_* tests 
- `9a630a949` Add extended Doxygen documentation for FFTO classes 
- `ea7cbaff5` Finalize FFTO TAP test setup and add startup debug log 
- `69acd4b43` Implement FFTO TAP testing suite 
- `3a3be5a55` Implement Fast Forward Traffic Observer (FFTO) for MySQL and PostgreSQL 

### GenAI (24 commits)

- `dd9b761ad` Add GenAI test files to test groups configuration 
- `3fe8a48f7` Fix genai variable handling and add API key masking 
- `1eb42c57d` fix: Add GenAI variables to runtime_global_variables population 
- `51fd51e3f` fix: Add missing GenAI_Thread.h include and fix variables reference 
- `a7dac5ef3` feat: Make NL2SQL use async GenAI path instead of blocking calls 
- `40b2608c2` feat: Add configuration validation to AI_Features_Manager 
- `fec7d6409` feat: Implement NL2SQL vector cache with GenAI embedding generation 
- `b77d38c2c` Add comprehensive GenAI module documentation 
- `bdd2ef70e` Add comprehensive TAP tests for GenAI async architecture 
- `db2485be3` Add comprehensive doxygen documentation to GenAI async module 
- `0ff2e38e2` Implement async GenAI module with socketpair-based non-blocking architecture 
- `bbad8ab4f` Fix GenAI variable naming and add comprehensive TAP tests 
- `39939f598` Add experimental GenAI RERANK: query support for MySQL 
- `253591d26` Add experimental GenAI EMBED: query support for MySQL 
- `1da9e384d` Add poll() fallback for GenAI module when epoll is not available 
- `960704066` Implement real GenAI module with embedding and rerank support 
- `f0a32c00b` Add rerank support to GenAI prototype via llama-server 
- `aa5361092` Add batch embedding support and scale up GenAI prototype 
- `012142eee` Fix event-driven GenAI demo and add early termination 
- `11d183a34` Add event-driven GenAI demo 
- `89285aa43` Add comprehensive Doxygen documentation to genai_demo.cpp 
- `5dad6255d` Add GenAI module prototype 
- `99dbd0a35` Add TAP test for GenAI module 
- `c476f56f9` Add initial GenAI module placeholder 

### MCP (54 commits)

- `fbcfd4613` test: Add descriptive diag messages to all test_mcp_* shell scripts 
- `b5843e1a8` test: Add visual output for top queries in mcp_show_queries_topk-t 
- `4203cbeec` test: Add descriptive diag() messages to all MCP TAP tests 
- `723c2daab` fix: Add missing get_mcp_variable function to mcp_runtime_variables-t 
- `893ccd2aa` test: Add mcp_runtime_variables-t to verify runtime_global_variables 
- `89da8324e` test: Add retry mechanism for MCP server startup in mcp_stats_refresh-t 
- `a44c0149f` test: Add missing MCP tests to ai-g1 group in groups.json 
- `f93432ab0` TAP MCP stats: add mixed-load profile/churn runners and enhance mixed stress configurability 
- `70b61a86e` MCP stats: implement in-memory show_queries Top-K path 
- `33fce1ca3` MCP stats: address review findings and add detailed docs 
- `0da772a4c` tap groups: add new MCP test assignments to ai-g1 group 
- `9ffc3f8d7` mcp tests: add phase-B TAP coverage and optional real Claude CLI E2E runner 
- `7e54883ba` mcp query debugging: surface rule-id context for blocks and add backend failure SQL details 
- `af0411bd4` MCP: add target-aware rules/stats tests, explain_sql rule coverage, and AI local docker TAP infra 
- `013864b36` MCP: introduce profile-based target/auth routing and unified LOAD/SAVE MCP PROFILES commands 
- `adb059c4b` mcp/stats: Add doxygen documentation for tool handlers 
- `643b322f2` MCP: Add stats endpoint and tools 
- `a5ef787c7` feat: Improve logging for MCP and RAG tools 
- `c52c621b2` MCP: Add mcp-rag_endpoint_auth config 
- `51e91378c` test: Add/Improve TAP tests for MCP query_rules/digests 
- `0d5691874` Add full-text search (FTS) tools to MCP query server 
- `68a41d6db` MCP: Add handler for prompts and resources 
- `a1d9d2f1b` docs: Add comprehensive documentation to MCP features 
- `8c9aecce9` feat: Add LOAD MCP QUERY RULES FROM DISK / TO MEMORY commands 
- `7e6f9f0ab` fix: Add MCP query rules LOAD/SAVE command handlers 
- `f01fc7958` feat: Add runtime_mcp_query_rules table and fix stats_mcp_query_rules schema 
- `be675d416` wip: Add interactive MCP query agent demo script using Claude Code 
- `2250b762a` feat: Add query_tool_calls table to log MCP tool invocations 
- `77643859e` feat: Add timing columns to stats_mcp_query_tools_counters 
- `fb66af7c1` feat: Expose MCP catalog database in ProxySQL Admin interface 
- `a15be695e`  Add GET/OPTIONS handlers for MCP HTTP transport 
- `a816a756d` feat: Add MCP query tool usage counters to stats schema 
- `ddc4e6570` Add plain HTTP support for MCP server and fix SSL/port restart issues 
- `d962caea7` feat: Improve MCP error logging with request payloads 
- `53ecda773` fix: Add comprehensive error handling and logging for MCP tools 
- `7de3f0c51` feat: Add schema separation to MCP catalog and discovery scope constraint 
- `3f44229e2` feat: Add MCP AI Tool Handler for NL2SQL with test script 
- `edac8eb5e` Fix: Add verbose logging and fix stdout buffering issue in MCP stdio bridge 
- `4491f3ce0` Add debug logging to MCP bridge for troubleshooting 
- `01c182cca` Add stdio MCP bridge for Claude Code integration 
- `f2ca750c0` Add MCP Database Discovery Agent (initial commit) 
- `2ef44e7c3` Add MCP implementation plans for FTS and Vector Embeddings 
- `07dc887af` Add MCP Tool Discovery Guide 
- `ced10dd05` Implement per-endpoint authentication for MCP endpoints 
- `c86a048d9` Implement MCP multi-endpoint architecture with dedicated tool handlers 
- `093511920` Add environment variable printing to MCP scripts 
- `60d4a7378` Implement automatic MCP server start/stop and add environment variable support 
- `a5f712e7d` Add MCP variables documentation 
- `5a85ef04f` Fix MCP variables persistence and add DISK command support 
- `ef0783178` Add MCP module to admin bootstrap and SHOW MCP VARIABLES command 
- `c53b28e42` Add comprehensive documentation to MCP README 
- `e9a6dd0b3` Add comprehensive MCP testing suite in scripts/mcp/ 
- `221ff2399` Add MySQL exploration MCP tools with SQLite catalog 
- `87fff9e04` Add MCP (Model Context Protocol) module skeleton 

### Monitoring (6 commits)

- `fafe114cf` Fix Prometheus metrics TAP test and add Doxygen documentation 
- `3c85c593c` Add GloMTH initialization wait to all monitor and server threads 
- `aa53d990e` Add GloMTH initialization wait to all monitor threads 
- `e94f9281c` feat: add friend declaration for MetricsCollector to access MyHostGroups 
- `d90be4080` Add documentation for Prometheus protocol labels feature 
- `2b0c74189` Add TAP test for FLUSH STATS commands 

### MySQL (5 commits)

- `1b322ed2b` add comprehensive test suite for SQLite Server via MySQL protocol 
- `ad2e2a24d` Add native MySQL mode support to test database setup 
- `4eab51984` Implement MySQL connection pool for MySQL_Tool_Handler 
- `95a95cb47` Add script to copy StackExchange Posts table from MySQL to SQLite3 server 
- `2b44aaa58` add protocol labels for shared metrics between mysql and psql 

### Noise (9 commits)

- `9f0d9d99c` test: add test_noise_injection-t to default-g3 group in groups.json 
- `378c13cdd` test: add existence checks for DB and tables in v2 noise routines 
- `3710bb621` test: implement multi-table and protocol support in v2 noise routines 
- `df76a3dc0` test: implement comprehensive noise injection across MySQL TAP tests 
- `d1d7f4df9` test: implement configurable delays and unambiguous logging in noise v2 
- `f15a7028a` test: implement detailed noise failure reporting and enhanced REST poller 
- `925cc1a90` test: add test_noise_injection-t to verify noise framework 
- `1dbd2d860` Implement Robust Noise Injection Framework for TAP Tests 
- `3018a3e0e` Implement Noise Injection framework for TAP tests 

### PostgreSQL (17 commits)

- `0f3fa7bb0` Add cross-protocol internal noise routines (MySQL + PgSQL) 
- `3abc81925` Expand internal noise routines and add PostgreSQL support 
- `1c25787b8` Introduce {mysql,pgsql}-query_processor_first_comment_parsing variable (#5384) #5384
- `deccf0ae0` TAP MCP stats: add MySQL stress test and mixed MySQL+PgSQL concurrent stress test 
- `e762f91cd` MCP stats: add in-memory processlist filtering and PgSQL concurrency stress TAP 
- `97e5cfee9` docs(doxygen): expand PostgreSQL logger API documentation for new advanced logging components 
- `258699547` tap(pgsql): add end-to-end test for eventslog automatic buffer-to-disk sync 
- `1edf1f8e8` Add PostgreSQL advanced logging TAP coverage and rewrite architecture doc 
- `b100235fb` Add PGSQL eventslog dump commands and periodic disk sync scheduling 
- `acbd7d0df` Implement PostgreSQL eventslog circular buffer and sink pipeline 
- `2a46c239b` Add PostgreSQL advanced eventslog schema and variable scaffolding 
- `49da3fb07` Created new group 'pgsql17-repl' 
- `9685cdaa4` mcp discovery: enforce target-scoped run model and add protocol-aware static harvesting (mysql+pgsql) 
- `331b0d6bc` Add support for PostgreSQL psql meta-commands in admin interface 
- `3ab964010` Add protocol labels to Query Cache metrics and enable PostgreSQL QC metrics 
- `778e01174` Add protocol labels to Thread Handler metrics and enable PostgreSQL metrics 
- `a892d9a05` Add pgsql-parameterized_kill_queries_test-t test to groups.json 

### RAG (19 commits)

- `8d022a0fc` RAG: Add 'model' request parameter for embedding service 
- `591f4bc9b` RAG: Add system prompt for agentic workflow 
- `d66248eb4` add verbose logging for bulk embedding operations 
- `a5edd4ad9` Add comprehensive RAG ingestion usage guide 
- `7167f9524` AI: Enable extensions for vector_db 
- `5fd779464` Add embedding testing plan documentation 
- `ff50e834f` Implement batch embedding generation in rag_ingest 
- `bc33c3329` Add vec embedding handling with stub and OpenAI providers Added rag_sync_state implementation 
- `ad166c6b8` docs: Add comprehensive Doxygen documentation for RAG subsystem 
- `55715ecc4` feat: Complete RAG implementation according to blueprint specifications 
- `3daaa5c59` feat: Implement RAG (Retrieval-Augmented Generation) subsystem 
- `803115f50` Add RAG capability blueprint documents 
- `2888ee3f4` Fix gemini-code-assist recommendations and implement comprehensive anomaly detection tests 
- `f226c0e68` feat: Implement embedding-based threat similarity for Anomaly Detection 
- `0be971518` test: Add comprehensive tests and documentation for Anomaly Detection 
- `52a70b0b0` feat: Implement AI-based Anomaly Detection for ProxySQL 
- `af68f347d` fix: Add missing verbosity level to proxy_debug call in Anomaly_Detector 
- `223dcf51d` Add vector search testing framework with modular scripts 
- `d4f838519` Add comprehensive vector search testing guide 

### SQLite (9 commits)

- `2af3b0d33` Add notes about Valgrind and SQLite memory management 
- `dde69e763` add sqlite-rembed to cleanall 
- `8a1732d15` Add SQLite Server verification on connect 
- `0372556f2` Enable SQLite FTS5 support for full-text search 
- `612ef326b` Fix sqlite-rembed demonstration scripts and add environment variable support 
- `e75bd7c84` Add comprehensive sqlite-rembed examples and documentation 
- `9f30d85e1` Add tar.gz packaging for sqlite-rembed dependency 
- `d55947b49` Add comprehensive documentation for sqlite-vec integration 
- `fbd0d9732` Add sqlite-vec static extension for vector search in ProxySQL 

### SSL (1 commits)

- `76822032a` feat: Add SSL/HTTPS support to MCPClient and fix mcp_stats_refresh-t 

### TSDB (5 commits)

- `95b46cf21` tests: add TSDB API and UI verification test 
- `2d51aeff6` tsdb: correctly implement SHOW TSDB commands and variable initialization 
- `6404d7b36` tsdb: implement SHOW TSDB VARIABLES and SHOW TSDB STATUS 
- `c73011b30` tsdb: implement REST API and basic UI dashboard 
- `f17e99983` Implement SQLite-based TSDB subsystem 

## Fix


### Admin (5 commits)

- `03f5f9b31` test: fix test_admin_stats-t failure by clearing persistent history 
- `932e07464` Fix reg_test_3847_admin_lock-t by using correct admin credentials and adding diagnostics 
- `c5f370ba4` Fix crash on NULL resultset in admin_large_pkts test 
- `79756e78d` Fix missing #endif for PROXYSQLGENAI guard in Admin_Handler.cpp 
- `9f07e9631` fix: Use prepared statements in ProxySQL_Admin_Stats to prevent SQL injection 

### Core (101 commits)

- `6be9dd1bf` fix: Address AI code review feedback from PR #5410 #5410
- `26d3d1fce` fix: Skip failing tests in issue5384-t due to feature regression 
- `b143f61b9` fix: Fix issue5384-t test - column name and result handling 
- `89646984e` fix: Check transport success instead of is_success for disabled tool test 
- `9b5d52308` fix: Use legacy prepare_v2 for conditional statement preparation 
- `de60fe2b3` fix: Use db->execute() for runtime_global_variables inserts 
- `7479f2168` fix: Only prepare runtime_global_variables stmt when runtime=true 
- `79c0b383e` integration: fix pre-CI issues in unified branch 
- `3ccf0982e` AI: Fix retry logic bug and synchronize TAP tests 
- `3240a3a94` Fix SIGSEGV caused by double-finalize of sqlite3_stmt 
- `a1f97a4e4` Fix test_match_eof_conn_cap failures due to audit log buffering and rotation 
- `8073b19e0` Fix test_cluster_sync-t failure by skipping non-existent global variable 
- `7b33b282b` Fix compilation error in issue5384-t TAP test 
- `458b0db31` Fix reg_test_2233: Use match_pattern in diagnostic query 
- `1375d4fe8` Fix reg_test_2233: Set default_schema='main' for test user 
- `43117471b` Fix TAP plan count and variable-restore fallback 
- `2c4287b7a` Fix TAP plan count in flush logs race test 
- `eaadabbb8` logger: fix thread-context map race in buffered logging 
- `db40505d1` Fix #2233: Mirror sessions destination_hostgroup overwritten by fast routing #2233
- `37e72ea3f` Fix PROXY protocol detection in MySQL_Data_Stream::read_from_net 
- `11a43bf76` Fix uninitialized max_allowed_pkt in MySQL_Connection constructor 
- `d42d89ae3` Fix TAP test when statement count after worker threads is below cache limit. Calculate dynamically how many statements to create to ensure we exceed CACHE_LIMIT (1024) and trigger a purge. 
- `1cccfb322` Fix connection cleanup in failure paths 
- `941e6b732` Fix filters_rwlock initialization race condition 
- `09d0dcb80` Fix uninitialized tmp_charset in Data_Stream constructors 
- `7c67eb25f` Fix uninitialized fd and status in Data_Stream constructors 
- `4e39297ef` Fix more Valgrind uninitialized value errors 
- `fdbea2a32` Fix uninitialized memory in Command_Counter::_counters 
- `c2f82b3d4` Fix more Valgrind uninitialized value errors 
- `ee7ee0b38` Fix multiple Valgrind-reported uninitialized memory issues 
- `af58865b0` Fix uninitialized memory in QueryParserArgs.buf 
- `335be9ec7` Fix unsafe sprintf and error message handling 
- `368a9e3a6` Fix log_buffer debug leak during shutdown 
- `da7c8e5cf` Fix missing variable 
- `4ae5bd852` Revert "fix: prevent dangling pointer in flush_*_variables___runtime_to_database" 
- `17054cd14` fix: memory leak in pull_global_variables_from_peer 
- `a20b2704f` fix: prevent dangling pointer in flush_*_variables___runtime_to_database 
- `6f415dfdb` fix: correct RAII migration issues - variable naming and redundant declarations 
- `e3ee45436` fix: remove duplicate 'int rc' declarations in prepare_v2 migrated functions 
- `df1c4e792` fix: medium priority warnings - write-strings and unused variables 
- `4c788dcbb` fix: signed/unsigned comparison warnings (-Wsign-compare) 
- `9e83a81b4` fix: critical use-after-free in child_telnet function 
- `c45fabdb6` fix: correct macOS executable SHA1 implementation 
- `c29c77fef` fix: resolve high vulnerability c.lang.security.insecure-use-strtok-fn.insecure-use-strtok-fn 
- `a57b43286` Fix TAP test builds with PROXYSQLGENAI 
- `b965fc6df` Fix PROXYSQLGENAI build - resolve circular includes and missing headers 
- `02f2ff5e2` Fix logging system: remove stderr bypass, thread-safe timestamps, and std::tolower UB 
- `87d8c2507` Reapply "fix: 'SQLITE_CONFIG_URI' not being set on 'LoadPlugins'" 
- `35b316d4f` Fix absolute paths in documentation 
- `48260cbf0` Revert "fix: 'SQLITE_CONFIG_URI' not being set on 'LoadPlugins'" 
- `df221617c` fix: 'SQLITE_CONFIG_URI' not being set on 'LoadPlugins' 
- `950f163bf` Fix compilation issues: use static libcurl and improve includes 
- `38e5e8e56` Fix critical issues from coderabbitai review 
- `c914feb23` Fix security issues identified in PR #5312 code review #5312
- `a3afde347` fix: Address copilot review concerns for Discovery_Schema.cpp 
- `5d4318b54` fix: Address coderabbitai review concerns for PR #27 
- `ffe569036` fix: Address coderabbitai review - use-after-free, missing responses, SQL injection 
- `5ece56351` fix: Correct SQL prepared statement API usage and template variable access 
- `bbc04974f` fix: Fix mysql_query failure path and affected_rows race condition 
- `b3edc6524` fix: Escape SQL strings in harvest_view_definitions 
- `6835713f1` fix: Correct column indexes in build_quick_profiles 
- `e9abee625` fix: Execute prepared statement in execute_parameterized_query 
- `6305537ba` fix: Use delete instead of free for SQLite3_result deallocation 
- `bd6d34f52` fix: Address SQL injection vulnerabilities from PR #26 review 
- `d7b2fea89` fix: Remove MAIN_PROXY_SQLITE3 defines from tests (v3.1-MCP2 compatibility) 
- `02918d18b` Fix PR #25 Review: All AI code reviewer feedback addressed 
- `a10c09bcc` Fix PR #21 review: Security, memory safety, thread safety, and code cleanup 
- `709649232` fix: Address AI code review concerns from PR #19 
- `23aaf80cd` fix: Address AI code review concerns for PR #19 
- `5d08deca7` Fix AI agent review issues 
- `9b66224df` Fix critical double-free bug, SQL injection vulnerability, and hardcoded path 
- `f7397f633` Fix catalog search to use FTS5 and enhance test suite 
- `f449c4236` fix: Improve question learning fallback and error logging 
- `ee74384c7` fix: Prevent llm.search from returning huge object lists in list mode 
- `73d3431c9` fix: Use heredocs for system prompt to preserve special characters 
- `7c9328017` fix: Escape SQL reserved keyword 'limit' in llm_search_log table 
- `4a858521c` Fix JSON-RPC ID type 
- `393967f51` fix: Use row->cnt instead of row->fields_count 
- `757cdaff1` fix: Improve error logging and fix llm.domain_set_members 
- `1b7335acf` Fix two-phase discovery documentation and scripts 
- `f9270e6c8` fix: Correct two_phase_discovery.py usage example in docs 
- `da0b5a5cf` fix: Correct log message from 4-agent to 6-agent discovery 
- `4df56f1c4` fix: Increase default timeout to 1 hour and improve error handling 
- `1a8b406d9` fix: Correct SQL query for AI variables in vector features test 
- `6d2b0ab30` test: Fix vector keyword conflict in NL2SQL unit tests 
- `1d046148d` Fix: Address code review feedback from coderabbitai and gemini-code-assist 
- `606fe2e93` Fix: Address code review feedback from gemini-code-assist 
- `f4a4af8d8` Fix: Write directly to stdout.buffer to bypass TextIOWrapper issues 
- `f5606986f` Fix: Replace stdout with truly unbuffered wrapper to prevent response buffering 
- `fc6b462be` Fix: unwrap ProxySQL nested response format 
- `d504c93b4` Fix formatting in proxysql.cfg 
- `119ca5003` Fix compilation errors in debug build 
- `22db1a5fd` Fix JSON value extraction in Query_Tool_Handler::execute_tool 
- `acb4c57db` Fix case sensitivity issues in MySQL_Tool_Handler::execute_query 
- `904283330` Fix critical use-after-free bug in MySQL_Tool_Handler::execute_query 
- `d17fe1dba` Fix configure_mcp.sh error handling and endpoint paths 
- `b3646b479` Fix argument parsing and documentation in setup_test_db.sh 
- `33a87c66a` Fix critical issues identified by gemini-code-assist 
- `62cbd6c71` Fix issues identified in AI code review 
- `172bf9f48` Fix int overflow if the first server is invalid 
- `db4f7d9c7` Fix delete connection with incorrect index 

### FFTO (5 commits)

- `96b1a8ff3` fix: Fix test_ffto_pgsql-t test failures 
- `db04a54c9` Fix memory corruption and stack overflow in FFTO due to large queries 
- `40aff577a` Complete FFTO implementation with verified metrics and robust error handling 
- `3dfd6a97d` Fix FFTO metric parity: capture and report affected_rows and rows_sent 
- `3ca390dac` Fix binary protocol support for prepared statements in FFTO 

### GenAI (13 commits)

- `471ebca74` fix: GENAI modules fails to initialise 
- `1af768f93` Fix critical issues in GenAI code (PR #5339) #5339
- `fec97bbab` fix: Fix GENAI variable loading during 'ProxySQL_Admin::init' 
- `cecb975f6` fix: LOAD GENAI TO RUNTIME does not initialize the module 
- `fd5d433a2` fix: Missing <string> header in ai_llm_retry_scenarios-t 
- `f45506e0b` fix: Missing <string> header in ai_llm_retry_scenarios-t 
- `6ffb59b85` fix: Use db parameter instead of hardcoded admindb in GenAI database_to_runtime 
- `4018a0ad3` fix: Follow MCP pattern for GenAI variables runtime table population 
- `1ea67900a` fix: Populate runtime_global_variables for GenAI variables on startup 
- `349320a67` docs: Fix NL2SQL documentation with genai variables and async architecture 
- `527bfed29` fix: Migrate AI variables to GenAI module for proper architecture 
- `1c7cd8c2b` fix: Correct PROXY_DEBUG constant from AI_GENERIC to GENAI 
- `59f0b8b1f` Fix GenAI module admin commands - correct character check 

### MCP (27 commits)

- `b4c80bb31` fix: Disable CTE test in mcp_query_run_sql_readonly-t for MySQL 5.7 
- `fa6b89093` fix: Fix mcp_module-t test failures 
- `70647fb42` fix: Remove unused legacy mcp-mysql_* variables 
- `8b1fb84d5` fix: Populate runtime_global_variables for MCP variables 
- `998bd8238` MCP TAP startup: fix tool-handler initialization order, improve MCP PROFILES observability, and seed monitor users 
- `4d4bb9dec` fix: Improved MCP rule testing and helpers 
- `50de53653` MCP: Fix crash during server restarts 
- `7b6966b9c` fix: Complete JSON escaping in fingerprint_mcp_args 
- `3bcee2270` fix: Execute MCP query rules DELETE+INSERT as explicit transaction 
- `188aef90f` fix: Use delete instead of free for SQLite3_result in load_mcp_query_rules_to_runtime 
- `52142c464` fix: Multiple issues with MCP query_(rules/digests) 
- `c092fdbd3` fix: Load re_modifiers field from database in load_mcp_query_rules() 
- `cc3cc2553` fix: Remove unused reset parameter from stats___mcp_query_rules() 
- `24d2bb2c8` fix: Enforce MCP catalog usage and prohibit Write tool for agent findings 
- `01f08ea90` Fix a crash (SIGABRT) that occurred when reloading MCP variables while the    MCP server was already running. The issue was caused by improper cleanup of    handler objects during reinitialization. 
- `f85290036` Fix: Correct MCP catalog JSON parsing to handle special characters 
- `49e964bb0` Fix: Make ProxySQL MCP server return MCP-compliant tool responses 
- `9b4aea047` Fix: Wrap tools/call responses in MCP-compliant content format 
- `2b5134632` Fix: Wrap tool results in TextContent format for MCP protocol compliance 
- `6d83ff168` Fix: unwrap ProxySQL response format in MCP tools and fix config syntax 
- `ef5b99edb` Fix MCP tool bugs: NULL value handling and query validation 
- `de33d177b` Fix verbose mode in test_mcp_tools.sh 
- `aeafa61a1` Fix test_mcp_tools.sh to use correct MCP endpoint paths 
- `2e7109d89` Fix lock ordering in flush_mcp_variables___database_to_runtime 
- `2874c9ad5` Fix flush_mcp_variables___database_to_runtime to populate runtime_global_variables 
- `b032c3f69` Fix boolean literal handling in SET command for MCP variables 
- `81c53896b` Fix MCP module TAP test failures 

### Monitoring (5 commits)

- `85952373d` Fix uninitialized mondb pointer in MySQL_Monitor_State_Data constructor 
- `f4cd34be5` Fix race condition in monitor_connect_thread 
- `52718df11` Fix memory leak in stats processlist functions 
- `3d3dc1732` fix test logic and stats reset 
- `ae4200dbc` Enhance AI features with improved validation, memory safety, error handling, and performance monitoring 

### MySQL (5 commits)

- `bed851471` Fix MySQL Monitor assertion failure in DEBUG builds 
- `1a7668b73` fix: SQLite3 server support for MySQL client '8.1.0' 
- `bd16436ea` Fix MySQL 8.4 build on macOS with C++20 compatibility patch 
- `7f957088e` Fix configure_mcp.sh to allow empty MySQL passwords 
- `40cff23c3` Initialize MySQL Tool Handler and fix default MySQL port 

### Noise (1 commits)

- `496f67c7a` Enhance Noise Injection robustness and error handling 

### PostgreSQL (11 commits)

- `630277ed3` fix: Fix pgsql-issue5384-t test and skip failing tests 
- `82a28a2e6` fix(pgsql-eventslog): close remaining minor review findings in logger internals 
- `6db089883` fix(admin): improve PGSQL eventslog dump failure reporting and stats insert path 
- `0aa3c5e15` fix(pgsql-eventslog): harden event ownership and keep newest rows in memory table 
- `eba795d72` fix(pgsql-eventslog): make dump-to-memory sizing protocol-agnostic across admin ports 
- `2fa1401b0` MCP query+harvest hardening: HGM-based target routing, weighted backend selection, pgsql schema fix, and TAP robustness 
- `ca4f858b2` Fix uninitialized memory read in pgsql tokenizer 
- `fcaa90413` fix: crash on macOS/FreeBSD when running PostgreSQL queries 
- `230985e93` Fix: PostgreSQL prepared statement purge race condition 
- `e3026cbc6` Fix wrong index in connection cleanup loops (MySQL and PgSQL) 
- `9ec045ca7` Fix PostgreSQL deadlock with Close Statement flood exceeding threshold_resultset_size 

### QueryProcessor (3 commits)

- `178f679fa` fix: Handle optimizer hints /*+ */ correctly in query tokenizers 
- `ca73b9ece` Tokenizer: fix type mismatch for grouping limit variables 
- `deb19a021` fix: remove double-finalization in stats___save_mysql_query_digest_to_sqlite 

### RAG (8 commits)

- `0e605f417` build: fix anomaly_detection-t linking for PROXYSQLGENAI 
- `eb495f42e` AI: Fix vector_db table creation 
- `4031f8539` AI: Fix vector_db initialization 
- `2a614f817` fix: Missing headers and format strings in vector_db_performance-t 
- `0dc353174` fix: Linking issues for anomaly_detection-t TAP test 
- `d61381643` fix: Missing headers and format strings in vector_db_performance-t 
- `b9a70f85a` fix: Linking issues for anomaly_detection-t TAP test 
- `1dc5eb658` fix: Fix RAG implementation compilation issues 

### SQLite (2 commits)

- `253d09865` security: fix SQL injection vulnerabilities in SQLite catalog queries 
- `22c4e94d5` AI: Fix sqlite-vec extension loading 

### TSDB (6 commits)

- `ef397f9f1` Fix TSDB variable patterns and backend monitor runtime source 
- `700459f67` tsdb: address AI code review feedback, fix memory safety and logic bugs 
- `a09db8318` tsdb: fix SET command validation by adding tsdb- prefix support 
- `685b92cea` tsdb: fix crash due to invalid SQL in tsdb_backend_health macro 
- `c3e1a02fe` tsdb: fix crash due to invalid SQL in table definition macros 
- `4e0f94a34` tsdb: fix compilation error in ProxySQL_Admin.cpp 

## Improvement


### Admin (8 commits)

- `7c0ff770f` refactor: migrate prepare_v2 SIMPLE cases in ProxySQL_Admin_Stats.cpp 
- `5b6381b32` refactor: migrate remaining prepare_v2 SIMPLE cases in ProxySQL_Admin 
- `2a83a3097` refactor: migrate more prepare_v2 SIMPLE cases in ProxySQL_Admin 
- `ca9b72a9d` refactor: migrate more prepare_v2 SIMPLE cases in ProxySQL_Admin 
- `e56da24c8` refactor: migrate more prepare_v2 SIMPLE cases in ProxySQL_Admin 
- `575449cdf` refactor: migrate all prepare_v2 SIMPLE cases to RAII API in ProxySQL_Admin 
- `7c2c6121e` refactor: migrate prepare_v2 to RAII API in ProxySQL_Admin_Tests2 
- `2c8c27bf6` refactor: migrate prepare_v2 to RAII API in Admin_FlushVariables 

### Core (14 commits)

- `9eac5f642` Improve async ping mmsd ownership tracking and pool validation 
- `e76d9dc13` Cleanup 
- `15a4ed66e` Optimize query logging performance (#5243) #5243
- `ac71e12a9` refactor: migrate RSA key generation to OpenSSL 3.0 EVP_PKEY API 
- `73555410e` refactor: migrate prepare_v2 SIMPLE case in FlushDigestTableToDisk template 
- `2e907bdd3` refactor: migrate prepare_v2 SIMPLE cases in ProxySQL_Cluster.cpp 
- `926208906` refactor: migrate prepare_v2 to RAII API in MySQL_Logger 
- `4161372da` refactor: migrate simple prepare_v2 cases to RAII-based API 
- `62bc15fd8` Improve macOS build system OpenSSL detection and documentation 
- `df0527c04` refactor: list_schemas to use catalog instead of live database 
- `527a748d1` refactor: Remove describe_table tool completely 
- `897d306d2` Refactor: Simplify NL2SQL to use only generic providers 
- `b627f836f` Refactor: Reorganize headless discovery scripts to dedicated directory 
- `9d6a2173b` Enhance Rich CLI with configurable LLM chat path and better tracing 

### FFTO (3 commits)

- `51a039507` Comprehensive FFTO Enhancements: Performance, Robustness, and Security 
- `1258a1f2f` Address PR reviews: improve performance, safety, and robustness of FFTO 
- `83a631bb1` Enhance FFTO documentation with verification steps and performance details 

### MCP (1 commits)

- `35b0b224f` refactor: Remove mcp-catalog_path variable and hardcode catalog path 

### Monitoring (3 commits)

- `e4704c5a5` refactor: migrate prepare_v2 SIMPLE cases in PgSQL_Monitor.cpp 
- `f779a6059` refactor: migrate remaining prepare_v2 SIMPLE cases in MySQL_Monitor 
- `bdba0b44a` refactor: migrate all prepare_v2 SIMPLE cases to RAII API in MySQL_Monitor 

### PostgreSQL (3 commits)

- `ee85b11ad` refactor: migrate prepare_v2 SIMPLE case in PgSQL_HostGroups_Manager.cpp 
- `854ab4fbb` refactor: migrate generate_pgsql_hostgroup_attributes_table() to RAII prepare_v2 
- `9939fe17e` refactor: migrate generate_pgsql_servers_table() to RAII prepare_v2 

### RAG (3 commits)

- `b5807fe14` RAG: Improve system prompt, replace hardcoded values with env vars 
- `09bd69eed` RAG: Improve system prompt, include SQLite server interface 
- `3f25fb6c4` Enhance anomaly detector unit tests with additional edge case coverage 

### TSDB (3 commits)

- `488255923` Cleanup: Uncomment delete statsdb_disk in ProxySQL_Statistics destructor 
- `b8c6b4f57` tsdb: address code review comments and improve stability 
- `5f5b7d604` tsdb: improve administrative interface and command support 

## Other


### Core (51 commits)

- `0f2d606dd` Update test_log_last_insert_id-t to handle query log buffering 
- `194e20b3e` Revert "Reset current_hostgroup to default when no query rule matches" 
- `c1035dd90` Update .gitignore to ignore .gemini and other workspace files 
- `c5191d21f` logger: avoid log drops during rotate close/open window 
- `1f0756b59`  Correct bytes_sent tracking for extended query protocol 
- `caf324f91` logger: harden buffered logging flush/rotation semantics 
- `db5f1ea49` Track query count for extended query protocol executions 
- `1b3d20388` Reset current_hostgroup to default when no query rule matches 
- `e1d420187` Simplify reg_test_2233: Use only SQLite3 Server as backend 
- `4f615da7c` Remove commented build rule for reg_test_2233 
- `200fdecb8` Apply AI agent review fixes to PR #5374 #5374
- `71143c2e8` Address AI review comments 
- `746eca9f7` More sprintf to snprintf conversions and indentation fixes 
- `3e3733787` Use RAII for sqlite3 statements across codebase 
- `ba86be70a` Fixed some bugs in PR 5358 
- `a69b92593` Minor typo fixes 
- `091942e9d` Address AI review suggestions 
- `2d3d12b9a` Address review comments from gemini and coderabbit 
- `c092e557b` build_deps with PROXYSQLGENAI=1 when needed 
- `557bdb621` Added missing iterator advancement 
- `844a645db` update fedora build image versions 
- `18c9c35b1` replace 'which' with 'type' to check for rustc toolchain 
- `b141af922` Prevent double version increment when PROXYSQLGENAI is enabled 
- `b269d9c71` Remove Fedora 41 support (EOL) 
- `3da50e059` Initial plan 
- `07154ca66` Empty commit to differentiate from v4.0_rag_ingest_2 
- `9ba3df0ce` Address AI code review feedback from PR #5318 #5318
- `3ccfa2bcc` Address AI code review feedback for PR #5313 #5313
- `2f6b058f7` Added test_rag_ingest.sh 
- `fb3673dd9` added sample sql files 
- `57d8c3f3b` Make rag_ingest compile 
- `dd885bd1f` bump version to 4.0.0 
- `6ce053848` Keep main.cpp only; remove accidental backup from commits 
- `f877366a6` Restore commented SQLite3DB::LoadPlugin reference with TODO 
- `4f0e6e0a4` Disable sqlite3 plugin function replacement; warn instead 
- `0db022a17` Apply fixes 
- `2dfd61a95` Replace remaining direct sqlite3_* calls with proxy_sqlite3_* equivalents (address code-review) 
- `fdb8dfb15` Build system: Darwin-specific fixes and strict platform parity 
- `bf429f0a5` Fixed multiple issues 
- `7564306e1` Handledwq "notifications/initialized" method 
- `6dd2613d6` Move discovery docs to examples directory 
- `b41a135e0` bump version to 3.0.6 at the beginning of the development cycle 
- `67cbe4645` Simplify PID extraction 
- `5066ddd18` Removed isdigit 
- `ce42c188f` Improvements 
- `a47567fee` Revert: Restore original bridge completely 
- `ad54f92dc` Revert: Simplify tool handlers back to original pass-through 
- `b9175f848` Fixed reg_test_5233_set_warning-t 
- `49e6ac5bc` Revert configure_mcp.sh to respect environment variables 
- `28742554b` Use relative catalog path instead of absolute path 
- `f561d83ba` Avoid usage of deleted connection 

### FFTO (1 commits)

- `f3d4153e7` Final FFTO implementation and verification fixes 

### GenAI (6 commits)

- `5519080ac` mcp stats: address review findings and remove --genai CLI flag 
- `fdccb7c03` Export PROXYSQLGENAI to support building all packages with GenAI 
- `840502712` Integrate GenAI async event handling into main MySQL session loop 
- `a82f58e22` Refactor GenAI module for autonomous JSON query processing 
- `fa301948b` Remove genai_demo_event binary from tracking and update .gitignore 
- `2c0f3a2e6` Evolve genai_demo_event to working POC with real embeddings 

### MCP (17 commits)

- `797d4b580` mcp stats: move show_users to in-memory auth snapshots 
- `5d45d1745` mcp stats: split connection metrics from debug free-pool snapshots 
- `c126e63a2` mcp stats: refresh stats tables under admin mutex before direct reads 
- `ade0130e6` discoveryagent: update Claude Code headless flow for target_id-scoped MCP tools 
- `8fbd570c7` mcp variables: stop writing runtime_global_variables during LOAD MCP VARIABLES TO RUNTIME 
- `f15460348` mcp query diagnostics: include runtime hostgroup status breakdown when target lacks ONLINE backend 
- `f4bc1943f` mcp query diagnostics: restore strict ONLINE requirement and explain target non-executable failures 
- `49f811a63` mcp query: stop misclassifying reachable targets as non-executable 
- `6a788e48c` mcp: make /mcp/query self-healing when targets/backends appear after startup 
- `7f19b642c` MCP: Rewrite stats tool handlers based on updated spec 
- `e450f1b30` MCP: Handle DELETE method 
- `2f38def40` MCP: Handle client notifications properly 
- `155a77f96` MCP: Bump protocolVersion to 2025-06-18 
- `25cda31f0` Update test_mcp_tools.sh with dynamic tool discovery 
- `991f0138d` Reinitialize MySQL Tool Handler when MCP variables change 
- `b70b07ead` Skip checksum generation for MCP until feature is complete 
- `245e61ee8` Make MCP_Threads_Handler a standalone independent class 

### Monitoring (1 commits)

- `b4e85f179` Expose PostgreSQL eventslog metrics in stats and Prometheus 

### MySQL (3 commits)

- `20d6282a6` build(clean): ignore and remove generated MySQL parser artifacts 
- `211179bdc` rag_ingest: Rewrite to use MySQL protocol (Sqlite_Server) instead of SQLite3 API 
- `949eda1cc` generate postgres metrics in addition to mysql metrics 

### PostgreSQL (4 commits)

- `90462f6d5` ffto: harden MySQL/PgSQL observer state handling and align tests/docs 
- `6f5a22f66` docs(internal): update PGSQL advanced logging architecture validation section with auto-dump E2E coverage 
- `61ce0a96e` Remove redundant sqlite3_finalize calls in pgSQL stats 
- `010296583` Convert PostgreSQL patches to unified diff format 

### RAG (3 commits)

- `10026891c` RAG: Convert vector similarity search into a subquery 
- `bc7098893` Added Chunking and Embedding guide 
- `e4f4dc95c` RAG: bm25 and MATCH do not work with table alias 

### SQLite (3 commits)

- `a24b8adaa` Use proxy_sqlite3_* for SQLite calls in Anomaly_Detector.cpp (address PR review) 
- `5a6520ad7` Ignore extracted sqlite-rembed source directory 
- `01d654692` Integrate sqlite-rembed for text embedding generation 

### SSL (1 commits)

- `855474213` Avoid send close in ssl connections 

### TSDB (3 commits)

- `3bb233e80` tsdb: commit missing REST API safety fixes 
- `6587bfdd4` tsdb: trigger stats refresh on SHOW TSDB STATUS 
- `a236a1378` tsdb: dedicated module for TSDB variables with tsdb- prefix and optimized background tasks 

## Test


### Core (8 commits)

- `4f94815e3` build: update .gitignore to exclude test artifacts and temp build files 
- `2dda65ca0` Move deprecated TAP test to test/tap/deprecated/ 
- `50858d03a` Adding tests in tap group 
- `267b24e17` Added regression test 
- `d47e196fc` Added rag_chunks and rag_fts_chunks test 
- `c2337d22b` Added regression test 
- `23e5efca5` Test: Don't redirect sys.stderr, write logs directly to file 
- `de3fd05a5` Reverted change to test/tap/tests/.env 

### FFTO (2 commits)

- `e53d2c76f` Address PR #5410 review findings across FFTO, sessions, TAP, and docs #5410
- `2759006f7` Cleanup FFTO tests: remove redundant subdirectories and orchestration scripts 

### MCP (6 commits)

- `27294a0ac` test: Increase PROXYSQLTEST 1 rows from 20 to 100 in mcp_show_queries_topk-t 
- `b46fb575e` TAP MCP client: port PR5372 coverage to MCP profiles/target_id routing model 
- `67cb1b72b` MCP TAP: pass target_id explicitly in query-rules test payloads 
- `4a8b22403` MCP TAP/docs: migrate tests and documentation from legacy MCP mysql vars to profile-based routing 
- `c5db31bf9` test: Improve testing for MCP and RAG tools 
- `33a100c1d` Use relative path mcp_catalog.db in MCP test instead of absolute /var/lib/proxysql path 

### Noise (7 commits)

- `e8253cac1` test: extend summary reports for v2 noise routines 
- `00fef8d82` test: expand v2 noise routines with multi-table and protocol support 
- `a00abfa36` test: expand noise injection to 20+ TAP tests and update build system 
- `ceb89fb91` test: inject background noise into multiple TAP tests 
- `43d535465` test: enhance noise framework with specialized parameters and REST poller 
- `2b857cd4b` Update NOISE_TESTING.md with dynamic options and TAP plan details 
- `ddc06660a` Integrate background noise into major TAP tests 

### PostgreSQL (6 commits)

- `06a067baf` test: expand noise injection to more PostgreSQL tests 
- `0ffeeacd8` test: harden MySQL and PgSQL v2 noise routines 
- `3a2513c73` test: inject MySQL v2 and Prometheus noise into PostgreSQL tests 
- `09284faea` test: refine PgSQL noise v2 and update integrated tests 
- `2a1b19916` test(tap): register pgsql_query_logging_autodump-t in test groups 
- `ab7d9187c` test(pgsql-eventslog): improve autodump assertion diagnostics and runtime cleanup 

### QueryProcessor (1 commits)

- `598846852` Query Processor: re-initialize parser on rewritten queries and enhance test coverage 

### RAG (2 commits)

- `7a7872f07` Organize RAG test files properly and update .gitignore 
- `acd05b60a` Organize RAG test files properly 

### TSDB (1 commits)

- `da877c378` tsdb: align admin variable lifecycle, full prometheus ingestion, docs and tap coverage 
