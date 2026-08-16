# AI GCOV TAP Shards Design

## Goal

Run every registered AI TAP in GitHub Actions and upload its GCOV data without
turning one job into an excessively long serial run. Add a focused TAP that
executes `PROXYSQLTEST 52` and verifies that its temporary configuration is
cleaned up.

## Design

The existing `ai-g1` registration contains 44 tests but has no CI workflow.
Split the registrations into two disjoint groups of 22. The split keeps related
test families together where possible and puts the largest stress workloads on
opposite shards:

| Group | Main responsibilities |
| --- | --- |
| `ai-g1` | GenAI foundations; mixed MySQL/PgSQL concurrency; MCP module, rule, runtime, Top-K, and cap-churn checks; NL2SQL integration/internal; TSDB API; vector features. |
| `ai-g2` | Remaining GenAI units; dedicated MySQL and PgSQL concurrency; MCP SQL, semantic, connection, and refresh checks; NL2SQL model/prompt/base; TSDB variables; vector database performance. |

`ai-g1` retains these 22 tests:

```
ai_llm_retry_scenarios-t
ai_validation-t
genai_config_query_unit-t
genai_discovery_schema_unit-t
genai_fts_string_unit-t
genai_llm_clients_unit-t
genai_mcp_endpoint_unit-t
genai_mcp_thread_unit-t
genai_module-t
llm_bridge_accuracy-t
mcp_mixed_mysql_pgsql_concurrency_stress-t
mcp_mixed_stats_cap_churn-t
mcp_mixed_stats_profile_matrix-t
mcp_module-t
mcp_query_rules-t
mcp_query_run_sql_readonly_bypass-t
mcp_runtime_variables-t
mcp_show_queries_topk-t
nl2sql_integration-t
nl2sql_internal-t
test_tsdb_api-t
vector_features-t
```

All remaining current `ai-g1` registrations move to `ai-g2`. This preserves
exactly 22 tests in each group and ensures every test belongs to exactly one AI
shard.

Each group needs an environment file. `ai-g1/env.sh` currently adds the
GenAI-plugin variables beyond the parent `ai/env.sh`; `ai-g2/env.sh` must set
the same variables so ProxySQL loads the plugin before the TAPs run.

Add `CI-ai-g1.yml` and `CI-ai-g2.yml` on v3.0. Each is a standard
`workflow_run` caller, modeled on `CI-legacy-g2-genai.yml`, and calls a
same-named reusable workflow from `GH-Actions`. Add the corresponding reusable
workflows on `GH-Actions`, modeled on `ci-legacy-g2-genai.yml`, with these
differences only:

- `TAP_GROUP` and `INFRA_ID` are the selected AI shard;
- workflow/check/artifact names identify the selected AI shard;
- the Codecov upload name is unique (`tap-ai-g1-coverage` or
  `tap-ai-g2-coverage`).

Both reusable workflows consume the existing `ubuntu24-tap-genai-gcov` build
handoff and start the inherited `ai` infrastructure: MySQL 8.4 and PostgreSQL
16. They run independently, so their infrastructure and coverage counters are
isolated.

Once both callers exist, remove `ai` from
`ALLOWLIST_NO_WORKFLOW` in `test/tap/groups/lint_group_coverage.py`.

For `PROXYSQLTEST 52`, create a dedicated MySQL TAP instead of adding a bare
command to `admin_various_commands2-t.cpp`. It records the starting number of
`mysql_servers` rows for hostgroup 5211, runs `PROXYSQLTEST 52`, requires an OK
response, and verifies that both the admin table and runtime view return to the
starting state. Register it in one existing GCOV-enabled MySQL 8.4 group.

## Validation

- JSON and group-registration linting pass.
- A small structural test verifies exactly 22 disjoint registrations in each
  AI group and that both workflow callers name the matching reusable workflow.
- The focused `PROXYSQLTEST 52` TAP passes in its MySQL 8.4 group.
- Both AI workflows complete, upload distinct LCOV reports, and the Codecov
  report shows nonzero coverage for the existing Top-K validator invoked by
  `mcp_show_queries_topk-t`.

## Non-goals

The unreachable hostgroup benchmark code following its unconditional
`return 0;` statements is not made artificially reachable. It remains a
separate source-cleanup or explicit-exclusion decision.
