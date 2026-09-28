# DuckDB Global Variables Runtime Implementation Plan

**Goal:** Replace DuckDB's dedicated scalar tables with the standard
`duckdb-*` global-variable namespace and make LOAD/runtime reporting reflect
effective engine and listener state.

**Base:** `v3.0@80941ae5e2cb29963c8bb14c46a7a441ae4f08d2`

## 1. Configuration value semantics

- Extend `DuckDBConfigStore` with copy/snapshot support and canonical boolean
  and empty-path handling.
- Add unit tests for canonical values, complete-candidate validation, and
  preservation of the original store on rejected candidates.
- Run `duckdb_config_unit-t` and confirm the new tests fail before production
  changes, then pass after the minimum implementation.

## 2. Effective engine configuration

- Extend `DuckDBEngine` with an internal control connection guarded by the
  engine configuration mutex.
- Add APIs to read effective settings and apply validated live changes with
  readback and reversible rollback.
- Preserve current sessions when lowering `max_connections` while enforcing
  new admission.
- Add engine tests for memory, threads, external access, connection limits,
  existing-connection visibility, and lifecycle races; run red then green.

## 3. Standard Admin variable path

- Rewrite `duckdb_admin_schema` to register commands and a refresh callback
  against the existing `runtime_global_variables`; register no DuckDB scalar
  tables.
- Seed defaults in `main.global_variables`, read/write only the `duckdb-*`
  slices, support sparse Main, validate before apply, reject changed
  lifecycle-only values, and publish effective Runtime transactionally.
- Implement scoped Main/Disk commands and legacy-table migration.
- Replace Admin-schema unit tests with failing tests for standard prefixes,
  migration, separation, failure semantics, and truthful status/runtime, then
  make them pass.

## 4. Direct managed SET and listener/status truth

- Route recognized client changes to managed DuckDB global settings through
  the internal engine control API; reject unsupported transitions.
- Expose actual listener specifications and use actual engine path in status.
- Add session/listener/status unit coverage and run it red then green.

## 5. Full plugin regressions

- Rewrite `test_duckdb_admin_tables-t.cpp` for standard global tables.
- Add real MySQL-protocol plugin assertions for current_setting(), an existing
  second connection, direct SET visibility, invalid/mixed LOAD, unsupported
  settings, connection admission, persistence, restart, and status path.
- Use temporary database/config directories and loopback listeners only.

## 6. Documentation

- Replace all dedicated-table examples in `doc/duckdb/` with `duckdb-*`
  filters/updates in global tables.
- Document live/lifecycle settings, canonical Runtime values, LOAD failure and
  possible partial-application reporting, direct SET behavior, Disk commands,
  and restart persistence.

## 7. Verification

- Run focused DuckDB unit tests.
- Build core and plugin with matching release settings and `PROXYSQL40=1`, then
  run isolated real plugin tests.
- Build core and plugin with matching DEBUG settings and `PROXYSQL40=1`, then
  rerun focused tests proportionate to the changed paths.
- Run `git diff --check`, verify no MySQLX/WebUI changes, record exact commands,
  exit statuses, revision, and any gaps.

No merge or push is part of this plan.
