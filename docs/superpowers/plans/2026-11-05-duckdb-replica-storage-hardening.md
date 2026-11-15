# DuckDB replica storage hardening implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline in the existing worktree.

**Goal:** Make snapshot/apply/reset identify the correct DuckDB catalog, and make RESET atomic and truthful.
**Architecture:** Fully qualify persisted and replicated objects using the connection's current catalog. RESET reads the persisted table manifest, drops those tables and metadata in one transaction, and clears lifecycle status only after storage succeeds.
**Tech Stack:** C++17, DuckDB 1.4.5, MySQL 8.4, TAP.
**Spec:** docs/superpowers/specs/2026-11-05-duckdb-mysql-replica-design.md sections 4, 6, 7 and 11.

## Global Constraints

- Preserve opt-in SELECT compatibility and ordinary backend routing.
- RESET is legal only after STOP, preserves unrelated tables and reports actual failures.
- Snapshot data/metadata/position and apply data/position remain atomic.

## Review Focus

- Catalog equals source schema or reserved metadata schema; punctuation and quotes in catalog/schema names.
- RESET failure after an earlier DROP must roll back all changes and preserve the checkpoint/manifest.
- Configuration edits must not change which persisted tables RESET removes.
- Missing schemas/metadata make a fresh RESET idempotent; genuine DROP failures must surface.
- Snapshot rollback must not issue destructive cleanup outside its transaction.

### Task 1: Catalog qualification

**Files:** replica header/types/snapshot/binlog, a small DuckDB-specific catalog helper header, existing live TAP and a new replica storage unit target.
**Interfaces:** `duckdb_replica_current_catalog(duckdb_connection,std::string&,std::string&)`; `duckdb_replica_qualified_name(catalog,schema,table)`; optional catalog argument to `duckdb_replica_create_table_sql`.

- [x] Make live source schema equal the DuckDB database filename; use explicit three-part names for client assertions. Observe snapshot failure before the fix.
- [x] Add storage-level tests for colliding catalog/schema names and quoted names.
- [x] Qualify all replica SQL, metadata lookups and appender creation with the catalog.
- [x] Run live NONE/CRC32 scenarios across rotation/restart/resnapshot and storage units.

### Task 2: Transactional RESET and rollback safety

**Files:** replica snapshot/admin/lifecycle, storage units and lifecycle units.
**Interfaces:** `duckdb_replica_drop_snapshot(DuckDBEngine&)`; `DuckDBReplica::reset(std::string&, const std::function<std::string()>& = {})`.

- [x] Add a real foreign-key DROP failure fixture. Assert error, full rollback, intact manifest/position and unrelated tables.
- [x] Add RESET-after-config-edit and fresh RESET idempotence cases; use persisted manifest as authority.
- [x] Add lifecycle callback failure tests before implementation; preserve state on storage failure and refuse callback while running.
- [x] Drop manifest-owned tables and metadata transactionally; reset status only after successful commit. Remove post-rollback table deletion from snapshot failures.
- [x] Run the affected DuckDB suite, live tests and compatibility regression; review and update the handoff.

## Completed validation

- Nine DuckDB unit binaries: 371 assertions, including lifecycle/config 61 and storage 16.
- Live MySQL 8.4.8 / DuckDB 1.4.5: 31 assertions with NONE and CRC32, including rotation, restart, failed RESET, manifest ownership after config edits and snapshot rollback safety.
- SELECT compatibility differential regression: 39; Admin tables: 22; MySQL listener: 17.
- PostgreSQL listener retains exactly the six previously reproduced base failures at assertions 19..24.
- Restoring the original post-rollback DROP loop makes the unrelated inactive-table regression fail; restoring the fix passes.
- Review caught case-sensitive reserved-schema checks; both boundaries now share a case-insensitive guard. Added config mixed/upper-case and direct snapshot-boundary regressions, observed failing before the fix and passing after it.
- Read-only review cleared the follow-up with no remaining Critical or Important findings.

Further hardening remains in the handoff: abrupt crash injection, concurrent snapshot writes, positions above 4 GB, read-only protection, load and packaging.
