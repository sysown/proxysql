# AI TAP Shards Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Keep each
> checkbox test-first and commit only after the listed verification is green.

**Goal:** Make `CI-ai-g1` and `CI-ai-g2` trustworthy and green under the
label-selected ASAN integration build while retaining every one of their 22
registered tests.

**Architecture:** Treat the failures as one end-to-end contract. The central
build must hand off every declared executable; the runner must reject missing
or duplicate programs; the AI group must establish one authenticated HTTP MCP
baseline; production must atomically publish loaded MCP variables; and each
registered test must exercise the current interface deterministically.

**Tech stack:** C++17, GNU Make, SQLite, libcurl, Bash, Python `unittest`, TAP,
and the repository's Docker-isolated TAP runner.

## Global constraints

- Preserve the exact 22 `ai-g1` and 22 `ai-g2` entries in
  `test/tap/groups/groups.json`.
- Do not remove, silently omit, or unconditionally skip a registered test.
- A full shard succeeds only when declared = discovered = executed = passed.
- Use `PROXYSQL40=1` consistently for all relevant builds.
- Run integration programs only through `test/scripts/run-tests-isolated.bash`.
- Keep `.github/workflows/CI-unit-tests-asan-coverage.yml` unchanged.
- Do not include MySQL 9.0/9.5 binlog failures in this PR.

## Task 1: Publish MCP runtime variables atomically

**Files:**

- Modify: `test/tap/tests/unit/genai_plugin_load_unit-t.cpp`
- Modify: `plugins/genai/src/plugin_main.cpp`
- Modify: `plugins/genai/include/genai_plugin.h`

### Steps

- [ ] Extend the lifecycle fixture schema with
  `runtime_global_variables(variable_name TEXT PRIMARY KEY, variable_value TEXT)`
  and seed an unrelated `mysql-threads` row.
- [ ] Add lifecycle TAP assertions for this sequence:
  1. load `mcp-timeout_ms=45000` and observe all 14 `mcp-*` rows;
  2. reload `mcp-timeout_ms=46000` and observe exactly 14 rows, with no
     duplicate and with `mysql-threads` unchanged;
  3. install an aborting SQLite trigger for the timeout insert, attempt a load
     of `47000`, and observe a command error plus the previous `46000` runtime
     view and active handler value.
- [ ] Force a clean rebuild and run the unit binary before production changes:

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 genai_plugin_load_unit-t -B
  test/tap/tests/unit/genai_plugin_load_unit-t
  ```

  Expected RED: only the new runtime-publication/rollback assertions fail.

- [ ] In `mcp_load_variables_from_admindb`, collect the complete desired
  `mcp-*` snapshot and the previous handler snapshot as owned
  `std::vector<std::pair<std::string, std::string>>` values.
- [ ] Apply every desired value through `MCP_Threads_Handler::set_variable()`
  and reject the load if any value is invalid.
- [ ] Publish values read back from the handler in one SQLite transaction:
  delete only `mcp-*` rows, bind and insert the complete snapshot, and commit
  only after every statement succeeds.
- [ ] On either handler application or SQL publication failure, restore all
  previous handler values. Let SQLite roll back the uncommitted runtime view.
- [ ] Update the declaration comment to state the atomic handler/runtime-table
  contract and failure behavior.
- [ ] Rebuild and run the affected and adjacent suites:

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 \
    genai_plugin_load_unit-t genai_thread_unit-t genai_mcp_thread_unit-t -B
  test/tap/tests/unit/genai_plugin_load_unit-t
  test/tap/tests/unit/genai_thread_unit-t
  test/tap/tests/unit/genai_mcp_thread_unit-t
  ```

  Expected GREEN: every TAP assertion passes and all three processes exit 0.

- [ ] Commit:

  ```bash
  git add plugins/genai test/tap/tests/unit/genai_plugin_load_unit-t.cpp
  git commit -m "fix(mcp): publish loaded runtime variables atomically"
  ```

## Task 2: Make MCP readiness authenticated and protocol-aware

**Files:**

- Create: `test/tap/tests/unit/mcp_client_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/tap/mcp_client.cpp`

### Steps

- [ ] Add a loopback fixture that binds an ephemeral port, accepts one HTTP
  request, records its headers, and returns a caller-provided status/body.
- [ ] Add three TAP cases for `MCPClient::check_server()`:
  authenticated HTTP 200 JSON-RPC success sends
  `Authorization: Bearer tap-token`; HTTP 401 returns false; malformed JSON at
  HTTP 200 returns false.
- [ ] Register a focused Makefile target linking `mcp_client.cpp`, libcurl,
  pthreads, and the existing JSON dependency.
- [ ] Build and run before changing the client:

  ```bash
  make -C test/tap/tests/unit PROXYSQL40=1 mcp_client_unit-t -B
  test/tap/tests/unit/mcp_client_unit-t
  ```

  Expected RED: the header and HTTP-status assertions fail.

- [ ] Reuse the same bearer-header construction used by normal tool calls in
  `check_server()` whenever `auth_token` is non-empty.
- [ ] Require `CURLE_OK`, HTTP status 200, valid JSON, matching JSON-RPC id, and
  a `result` member; log transport, HTTP, parse, and protocol failures
  separately.
- [ ] Rebuild and rerun the unit target; all cases must pass.
- [ ] Commit:

  ```bash
  git add test/tap/tap/mcp_client.cpp test/tap/tests/unit/Makefile \
    test/tap/tests/unit/mcp_client_unit-t.cpp
  git commit -m "fix(tap): authenticate MCP readiness probes"
  ```

## Task 3: Establish one authenticated AI MCP baseline

**Files:**

- Modify: `test/tap/groups/test_ai_group_shards.py`
- Modify: `test/tap/groups/ai/mcp-config.sql`
- Modify: `test/tap/groups/ai/env.sh`
- Modify: `test/tap/groups/ai-g1/env.sh`
- Modify: `test/tap/groups/ai-g2/env.sh`
- Modify: `test/tap/tests/mcp_mixed_mysql_pgsql_concurrency_stress-t.cpp`
- Modify: `test/tap/tests/mcp_mysql_concurrency_stress-t.cpp`
- Modify: `test/tap/tests/mcp_pgsql_concurrency_stress-t.cpp`
- Modify: `test/tap/tests/mcp_mixed_stats_cap_churn-t.cpp`
- Modify: `test/tap/tests/mcp_mixed_stats_profile_matrix-t.cpp`
- Modify: `test/tap/tests/mcp_query_rules-t.cpp`
- Modify: `test/tap/tests/mcp_query_run_sql_readonly-t.cpp`
- Modify: `test/tap/tests/mcp_query_run_sql_readonly_bypass-t.cpp`
- Modify: `test/tap/tests/mcp_show_connections_commands_inmemory-t.cpp`
- Modify: `test/tap/tests/mcp_show_queries_topk-t.cpp`
- Modify: `test/tap/tests/mcp_stats_refresh-t.cpp`
- Modify: `test/tap/tests/test_stats_mcp_tables-t.cpp`

### Steps

- [ ] Extend the Python contract test to assert exact unchanged shard
  membership, HTTP (`mcp-use_ssl=false`), one non-empty token applied to all
  endpoint-auth variables, both `TAP_MCP_PORT`/`TAP_MCPPORT`, and
  `TAP_MCP_AUTH_TOKEN` in every inherited environment.
- [ ] Run:

  ```bash
  python3 -m unittest test/tap/groups/test_ai_group_shards.py -v
  ```

  Expected RED: the transport/token/environment assertions fail while exact
  membership remains green.

- [ ] Export one stable test token and both port spellings from the AI group;
  keep shard env files consistent with the parent.
- [ ] In `mcp-config.sql`, set HTTP plus that token for config, stats, query,
  admin, cache, AI, and RAG endpoints before enabling MCP and saving to disk.
- [ ] Update each listed client test to set `cl.mcp_auth_token`, configure the
  endpoint it calls with the escaped canonical token, and restore the disk
  baseline during cleanup rather than clearing authentication.
- [ ] Preserve negative-auth coverage by replacing credentials only for the
  negative case and restoring the canonical value on every exit path.
- [ ] Remove automatic HTTP-to-HTTPS probing from non-TLS tests; use the group
  HTTP endpoint directly.
- [ ] Rerun the Python contract test, then build the affected TAP binaries:

  ```bash
  python3 -m unittest test/tap/groups/test_ai_group_shards.py -v
  make -C test/tap PROXYSQL40=1 \
    mcp_query_rules-t mcp_query_run_sql_readonly-t \
    mcp_query_run_sql_readonly_bypass-t test_stats_mcp_tables-t
  ```

- [ ] Run each affected program through the isolated runner with the matching
  AI group and require process/TAP success.
- [ ] Commit:

  ```bash
  git add test/tap/groups test/tap/tests
  git commit -m "fix(tap): standardize authenticated AI MCP setup"
  ```

## Task 4: Restore maintained shell-test prerequisites

**Files:**

- Create: `test/tap/tests/mcp_rules_testing/mcp_test_helpers.sh`
- Create: `test/tap/groups/test_ai_shell_contract.py`
- Modify: `test/tap/tests/test_mcp_claude_headless_flow-t.sh`
- Modify: `test/tap/tests/test_mcp_llm_discovery_phaseb-t.sh`
- Modify: `test/tap/tests/test_mcp_rag_metrics-t.sh`
- Modify: `test/tap/tests/test_mcp_static_harvest-t.sh`
- Modify files under: `test/tap/tests/mcp_headless_testing/`
- Modify files under: `test/tap/tests/rag_stats_testing/`

### Steps

- [ ] Add static contract tests proving the shared helper exists, uses
  `TAP_ADMINHOST`, accepts either MCP port spelling, emits a bearer header,
  defaults to HTTP, has no hard-coded admin `127.0.0.1`, has no `sqlite3`
  executable dependency, and refers only to fixtures below `test/tap/tests`.
- [ ] Run the new unittest and record the expected missing-helper/path/SQLite
  failures.
- [ ] Restore the helper at the path all four programs source. Provide TAP
  planning/results, admin SQL, authenticated JSON-RPC calls, readiness checks,
  and explicit prerequisite diagnostics.
- [ ] Move or recreate the headless dry-run fixtures below
  `test/tap/tests/mcp_headless_testing`; default to the isolated `proxysql`
  host. Keep live Claude execution opt-in while ensuring the local dry-run
  remains a real passing assertion path.
- [ ] Make discovery, RAG, and static-harvest scripts consume the canonical
  group host/scheme/token/profile contract and restore modified state.
- [ ] Replace the RAG fixture's `sqlite3` CLI calls with an embedded Python
  `sqlite3` script that returns nonzero on schema/data failure.
- [ ] Rerun the contract test and `bash -n` over the helper and four programs.
- [ ] Execute all four through the isolated AI shard runner and require every
  declared TAP assertion to pass.
- [ ] Commit:

  ```bash
  git add test/tap/groups/test_ai_shell_contract.py \
    test/tap/tests/mcp_rules_testing test/tap/tests/mcp_headless_testing \
    test/tap/tests/rag_stats_testing test/tap/tests/test_mcp_*-t.sh
  git commit -m "fix(tap): restore portable MCP shell fixtures"
  ```

## Task 5: Align stale GenAI, NL2SQL, and vector feature tests

**Files:**

- Modify: `test/tap/tests/genai_module-t.cpp`
- Modify: `test/tap/tests/nl2sql_unit_base-t.cpp`
- Modify: `test/tap/tests/vector_features-t.cpp`

### Steps

- [ ] Rewrite `genai_module-t` expectations around the canonical `genai-*`
  variables: exact current count, representative defaults, supported
  `LOAD/SAVE GENAI VARIABLES` aliases, value changes, and persistence. Delete
  all `genai-var1`/`genai-var2` compatibility expectations.
- [ ] Replace NL2SQL suffix concatenation with full canonical names:
  `genai-llm_enabled`, `genai-llm_provider`,
  `genai-llm_provider_model`, `genai-llm_cache_similarity_threshold`, and
  `genai-llm_timeout_ms`. Validate the runtime values through supported admin
  commands and remove the placeholder manager-exists assertion.
- [ ] Replace removed `mysql_servers.ai_*` checks in `vector_features-t` with
  canonical vector-path/dimension, cache, similarity, and anomaly variables;
  assert load/save persistence and reject tautologies or empty-as-success.
- [ ] Build all three before changing their expectations and preserve the
  existing failures as RED evidence, then rebuild after each rewrite.
- [ ] Execute each program with the isolated runner and require exact TAP plan
  completion with exit 0.
- [ ] Commit:

  ```bash
  git add test/tap/tests/genai_module-t.cpp \
    test/tap/tests/nl2sql_unit_base-t.cpp test/tap/tests/vector_features-t.cpp
  git commit -m "fix(tap): test current GenAI and vector interfaces"
  ```

## Task 6: Make vector performance coverage deterministic

**Files:**

- Modify: `test/tap/tests/vector_db_performance-t.cpp`

### Steps

- [ ] Add a focused regression showing that the existing four-byte mock hash
  can produce a false high-similarity match for a distinct query, and retain
  the current relative-timing assertions long enough to observe their failure.
- [ ] Replace the mock embedding with a deterministic full-dimension generator
  seeded by a stable FNV-1a hash and advanced with a fixed integer PRNG.
- [ ] Assert exact-query result correctness, unrelated-query miss at `0.99`,
  vector/result shape, successful representative small/medium/large workloads,
  and only broad absolute completion bounds. Remove relative timing ordering.
- [ ] Build and run through the isolated runner twice to prove deterministic
  success.
- [ ] Commit:

  ```bash
  git add test/tap/tests/vector_db_performance-t.cpp
  git commit -m "fix(tap): make vector performance checks deterministic"
  ```

## Task 7: Reconcile declared tests across the complete handoff

**Files:**

- Create: `test/scripts/lib/group_reconciliation.py`
- Create: `test/scripts/tests/test_group_reconciliation.py`
- Modify: `test/scripts/bin/proxysql-tester.py`

### Steps

- [ ] Add pure Python unit cases for: 22 declared/16 discovered reports six
  exact missing names; duplicate basenames report duplicates; a result with no
  exit status reports skipped; nonzero reports failed; all passing is clean;
  and an explicit selected subset validates only that subset.
- [ ] Define a `GroupReconciliation` dataclass with `passed`, `failed`,
  `skipped`, `missing`, `duplicates`, and an `ok` property, plus:

  ```python
  reconcile_group_results(
      declared: set[str],
      discovered: list[str],
      results: list[tuple[str, int | None]],
  ) -> GroupReconciliation
  ```

- [ ] Run:

  ```bash
  python3 -m unittest test/scripts/tests/test_group_reconciliation.py -v
  ```

  Expected RED: import/module failure before implementation.

- [ ] Accumulate discovered basenames and execution results across every
  `tap_tests_*` work directory in `proxysql-tester.py`, then reconcile once
  against the group membership after version/include/exclude selection.
- [ ] Log exact sorted sets for missing, duplicate, skipped, and failed tests;
  increment the run status for any nonempty error set. Remove the current
  per-directory expectation intersection that hides globally missing programs.
- [ ] Run the unit suite plus `python3 -m py_compile` on the runner.
- [ ] Commit:

  ```bash
  git add test/scripts/lib/group_reconciliation.py \
    test/scripts/tests/test_group_reconciliation.py \
    test/scripts/bin/proxysql-tester.py
  git commit -m "fix(tap): fail shards with missing test programs"
  ```

## Task 8: Build and stage all eleven declared GenAI units

**Files:**

- Create: `test/tap/groups/test_ai_unit_handoff.py`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/tap/Makefile`
- Create during the build: `test/tap/tap_tests_ai_unit/manifest.txt`

### Steps

- [ ] Parse `groups.json` in the new contract test and assert that the staged
  manifest/Makefile contract names exactly these eleven group-declared units:
  `genai_config_query_unit-t`, `genai_discovery_schema_unit-t`,
  `genai_fts_string_unit-t`, `genai_llm_clients_unit-t`,
  `genai_mcp_endpoint_unit-t`, `genai_mcp_thread_unit-t`,
  `genai_mysql_catalog_unit-t`, `genai_query_handler_unit-t`,
  `genai_rag_fetch_from_source_unit-t`, `genai_stats_parsing_unit-t`, and
  `genai_thread_unit-t`.
- [ ] Also assert the stage path matches `tap_tests_*` and that the three
  unrelated GenAI unit binaries are absent.
- [ ] Run the contract test before Makefile changes and observe RED.
- [ ] Refactor common GenAI plugin source compilation into path-preserving
  object files and one static archive that inherits `OPT`, coverage, sanitizer,
  and debug flags.
- [ ] Link only the eleven declared programs against that archive in a
  sequential `ai_genai_unit_tests` target; do not re-enable the complete
  `unit_tests` GenAI set.
- [ ] Under `PROXYSQL40=1 WITHGCOV=1 SKIP_GENAI_UNIT_TESTS=1`, make the top-level
  TAP build invoke that target, stage executable hardlinks/copies under
  `test/tap/tap_tests_ai_unit`, write the sorted manifest, and compare it to
  the expected list before succeeding.
- [ ] Run the contract test and a clean forced build of the focused target:

  ```bash
  python3 -m unittest test/tap/groups/test_ai_unit_handoff.py -v
  make -C test/tap PROXYSQL40=1 WITHGCOV=1 SKIP_GENAI_UNIT_TESTS=1 \
    ai_genai_unit_tests -B -j1
  find test/tap/tap_tests_ai_unit -maxdepth 1 -type f -printf '%f\n' | sort
  ```

  Expected GREEN: exactly eleven executables plus `manifest.txt`, with all
  executable names matching the AI group contract.
- [ ] Run all eleven staged units and require exit 0/TAP completion.
- [ ] Commit:

  ```bash
  git add test/tap/Makefile test/tap/tests/unit/Makefile \
    test/tap/groups/test_ai_unit_handoff.py
  git commit -m "build(tap): hand off declared GenAI unit tests"
  ```

## Task 9: Verify the consolidated repair and update PR #6107

**Files:**

- Modify if needed: files from Tasks 1–8 only
- Update remotely: PR #6107 title and description

### Steps

- [ ] Run all static/unit contract suites:

  ```bash
  python3 -m unittest \
    test/tap/groups/test_ai_group_shards.py \
    test/tap/groups/test_ai_shell_contract.py \
    test/tap/groups/test_ai_unit_handoff.py \
    test/scripts/tests/test_group_reconciliation.py -v
  git diff --check
  ```

- [ ] Force-rebuild and execute the production-adjacent GenAI/MCP unit suites,
  the MCP client unit, and all eleven staged group units.
- [ ] Run every directly repaired integration program through
  `run-tests-isolated.bash`; do not invoke a test binary against shared/manual
  Docker infrastructure.
- [ ] Run the full unfiltered `ai-g1` and `ai-g2` groups and capture the final
  reconciliation. Both must report 22 declared, 22 discovered, 22 executed,
  and 22 passed.
- [ ] Inspect output for `AddressSanitizer`, `LeakSanitizer`, `runtime error:`,
  and incomplete TAP plans. Treat any occurrence as a failure to investigate.
- [ ] Confirm the central build diff does not touch
  `CI-unit-tests-asan-coverage` and does not include MySQL 9.0/9.5 binlog code.
- [ ] Retitle PR #6107 to
  `fix(genai): make AI TAP shards complete and reliable` and rewrite its body to
  explain the six repaired layers, exact shard totals, local verification,
  ASAN status, issue coverage, and excluded binlog scope. Close an older issue
  only when every failure recorded in it is resolved.
- [ ] Push the complete branch, preserve the `ci:asan` label, and trigger the
  intended labeled pipeline with an empty commit only after the label is
  present if a deliberate rerun is required.
- [ ] Inspect all required PR checks and logs. Do not describe a failure as
  pre-existing; either fix an in-scope AI failure or document a concrete,
  evidence-backed out-of-scope cause.

