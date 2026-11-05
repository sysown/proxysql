# DuckDB typed MySQL results implementation plan

> **Superseded implementation details (2026-11-06).** The reconciliation adopts
> #6303's shared `DuckDBColumnType` and protocol-aware result converter for both
> MySQL and PostgreSQL. Native MySQL temporal metadata, exceptional scalar
> fallback, observed byte lengths and selective positional wrapping are retained
> on that foundation. The custom compatibility mode is removed. Prepared
> frontend protocol belongs to #6298; #6282 implements only the DuckDB adapter.
> See [current handoff](../specs/2026-11-05-duckdb-mysql-replica-design.md).

> **For agentic workers:** Use superpowers:executing-plans inline in the existing feature worktree.

**Goal:** Deliver typed scalar MySQL results as the next client-compatibility feature.
**Architecture:** Keep materialized SQLite value rows and attach plugin-owned MySQL descriptors to the execution outcome. Use existing MySQL field/row packet generators. Selectively stringify unsupported columns for MySQL, leaving PostgreSQL's path intact.
**Tech Stack:** C++17, DuckDB 1.4.5 C API, existing ProxySQL protocol APIs, TAP.
**Spec:** docs/superpowers/specs/2026-11-05-duckdb-mysql-typed-results-design.md.

## Constraints and review focus

- Preserve exact binary/NUL/NULL values and 128-bit numeric digits; no silent narrowing.
- Empty results must still expose logical types; conservative nullability/origin attributes.
- Per-column text fallback for nonfinite floats/infinite or out-of-range dates; avoid invalid typed values.
- Mixed scalar/composite output preserves scalar types, order and duplicate names; execute side effects once.
- PostgreSQL retains existing values/metadata; MySQL EOF/deprecate-EOF, sequence wrapping and large rows remain valid.

### Task 1: Scalar descriptors and MySQL wire output

**Files:** duckdb_result.h/.cpp, duckdb_session.h/.cpp; existing result/session units; new test_duckdb_mysql_types-t.cpp; TAP Makefile/groups.

- [x] Add an isolated live MySQL metadata test; observe text-column failure before implementing.
- [x] Add plugin-owned descriptors, map DuckDB logical types and gather data-dependent fallbacks/max lengths during conversion.
- [x] Preserve floating-point round trips and numeric MySQL booleans while retaining PostgreSQL behavior.
- [x] Carry descriptors through execution; emit typed field packets and existing length-aware row packets with correct status/capability handling.
- [x] Add selective positional wrapping for unsupported MySQL columns; cover mixed types and duplicate labels.
- [x] Extend focused unit and live coverage, including empty results, wide numbers, exceptional values, routing and large packets.

### Task 2: Validation, review and handoff

- [x] Run affected DuckDB unit and direct/routed live tests; existing compatibility, replica, Admin and both listener regressions.
- [x] Request read-only review, fix material findings and rerun affected checks.
- [x] Document delivered types/limits, mark prepared-statement protocol as the following feature, and commit validated work.

## Completed validation

- Observed RED native integer field type253 before implementation.
- Typed live driver checks31, through direct and ordinary routed sessions, plus opt-in translation; includes binary/NUL, 16MiB rows, 300 columns, exact numeric boundaries and DML RETURNING.
- Nine units379 (result44 and session101); existing compatibility39, replica31, Admin22 and MySQL listener17 pass.
- PostgreSQL retains exactly the six previously reproduced extended-query baseline failures19..24.
- Read-only review cleared material findings; stale comments corrected and DuckDB allocated column names freed.
- Prepared-statement protocol is the next separate feature. No benchmarks or throughput optimization performed.
