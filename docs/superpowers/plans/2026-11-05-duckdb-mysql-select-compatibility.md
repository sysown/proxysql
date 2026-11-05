# DuckDB MySQL SELECT Compatibility Implementation Plan

> **Retired on 2026-11-06.** Historical implementation record only. The custom
> lexer, translator, opt-in variable and tests have been removed. #6280 requires
> new SQL recognition to use currently vendored ParserSQL; missing grammar is
> deferred upstream. See the [current handoff](../specs/2026-11-05-duckdb-mysql-replica-design.md)
> and #6284. The design below does not describe supported functionality.

> **For agentic workers:** Use superpowers:executing-plans to implement this plan inline. Preserve the existing isolated worktree.

**Goal:** Provide an opt-in, tested core of MySQL analytical SELECT syntax.
**Architecture:** A token-aware translator runs only for opted-in MySQL sessions; existing execution and result handling remain shared with native DuckDB.
**Tech Stack:** C++17, DuckDB 1.4.5, MySQL 8.4, TAP.
**Spec:** docs/superpowers/specs/2026-11-05-duckdb-mysql-select-compatibility-design.md

## Global Constraints

- No internal routing or automatic fallback.
- Native DuckDB and PostgreSQL behavior remain the defaults.
- Translation must never modify string/identifier contents accidentally or execute twice.
- Use existing Admin variables and LOAD/SAVE lifecycle; no new dependency.

## Review Focus

- String escapes, quotes, comments and SQL-like literal contents.
- Parentheses, nested SELECT scopes, CTEs and ORDER BY NULL placement.
- Unsupported syntax/format directives must fail explicitly.
- Compatibility remains isolated to opted-in MySQL sessions.
- Ordinary backend routing must handle authentication and session setup.

### Task 1: Translator and semantic regression suite

**Files:** Create `plugins/duckdb/include/duckdb_mysql_compat.h`, `plugins/duckdb/src/duckdb_mysql_compat.cpp`, `test/tap/tests/unit/duckdb_mysql_compat_unit-t.cpp`; modify plugin/unit Makefiles and groups.json.
**Interface:** `bool duckdb_translate_mysql_select(const std::string& sql, std::string& translated, std::string& error)`; non-SELECT statements pass through unchanged; errors leave translated empty.

- [x] Write table-driven DuckDB execution assertions for the supported syntax and negative cases, using literal expected results.
- [x] Build and run the test, observing missing translator/failing compatibility cases.
- [x] Implement a lexer and recursive token rendering with bounded nesting, contextual function/cast/LIMIT translation and NULL ordering.
- [x] Run the translator suite and compare fixture results to MySQL 8.4.

### Task 2: Opt-in listener integration and routing validation

**Files:** Modify DuckDB config, listener/session state and handler, Admin startup-only settings, and existing configuration tests. Create `test/tap/tests/test_duckdb_mysql_compat-t.cpp`; register in duckdb-e2e-g1.
**Consumes:** Task 1 translator. **Produces:** startup-only `duckdb-mysql_compatibility=false` and compatible SELECT execution for opted-in MySQL listener sessions.

- [x] Add tests for variable validation/defaults, enabled/disabled behavior and MySQL differential queries.
- [x] Observe failures before wiring the setting and handler.
- [x] Integrate translation before query execution and retain the existing error/result path.
- [x] Compare direct-listener and ordinary-backend-hostgroup results; restore persistent test state.
- [x] Run relevant DuckDB units, existing listener/Admin tests and replica live test, recording baseline failures.
- [x] Perform independent review, resolve concrete findings, update spec/handoff with validation and limits.
