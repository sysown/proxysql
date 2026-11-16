# DuckDB Prepared Execution Adapter Implementation Plan — #6282

> **For agentic workers:** Use superpowers:executing-plans under the user-approved implementation goal.
> Consume the reviewed core contract; do not create a competing frontend.

**Goal:** Let real MySQL and PostgreSQL parameterized clients execute native and
supported translated analytical queries on embedded DuckDB with typed binding.

**Architecture:** Implement core's versioned EmbeddedExecutionAdapter using native
DuckDB preparation/binding/results. Core retains frontend IDs, packets, portals,
formats, limits and cleanup policy. SQL translation remains the #6284 component.

**Tech Stack:** C++17, DuckDB C API, shared #6298 framework, ParserSQL, TAP/libpq/MySQL clients.

**Spec:** ../specs/2026-11-15-duckdb-mysql-query-compatibility-design.md
(section: Integrated prepared-execution design)

## Global constraints

- User approved implementation; isolated feature worktree from current v3.0.
- D1 consumes the frozen core contract; MySQL wire integration waits for K1–K4,
  PostgreSQL for K5. Verify dependency commits before implementation.
- Native parameter binding only; no SQL interpolation or plugin statement-ID map.
- SQL recognition uses vendored ParserSQL only, with explicit refusal of gaps.
- Preserve native mode, single execution, transaction ownership, metadata and
  default external-access policy. No CDC/routing/DBTrail/benchmark expansion.

## Review focus

Parameter identity through translation; value/metadata fidelity; connection affinity;
conversion failures after DML; schema changes and disconnect cleanup. D1–D3 test these.

## Files

- Create plugins/duckdb/include/duckdb_prepared_adapter.h and
  plugins/duckdb/src/duckdb_prepared_adapter.cpp: native implementation of the
  published core adapter contract, not a new frontend API.
- Modify plugins/duckdb/{Makefile,include/duckdb_session.h,src/duckdb_session.cpp,
  src/duckdb_result.cpp,src/duckdb_plugin.cpp} only where required for registration,
  metadata reuse and execution/session ownership.
- Test test/tap/tests/unit/duckdb_prepared_adapter_unit-t.cpp and
  test/tap/tests/test_duckdb_prepared_mysql-t.cpp / test_duckdb_prepared_pgsql-t.cpp.
- Register targets/groups and update doc/duckdb/{protocol-compatibility,user-guide}.md.

## D1: Native lifecycle and typed execution

Consumes: roadmap Task 0 MyDuck native-adapter/type-mapping findings and K1's
published types, operations, ownership, capabilities and errors.
Produces: DuckDB implementation of that exact interface; no alternate signatures.

- [ ] Review the pinned MyDuck adapter/execution path and type/conversion tests.
  Map reusable cases to this adapter and identify dependencies we will not adopt.
- [ ] Add failing adapter tests for native prepare, parameter/result description,
  bind, execute, fetch, reset and destruction on one session-owned connection.
- [ ] Implement using DuckDB native APIs. Cover exact integer ranges/signedness,
  decimal scale, floating point, temporal values, NULL/empty and arbitrary binary.
- [ ] Preserve shared typed-result mappings; negotiate unsupported parameter/result
  types explicitly. Do not narrow wide numerics or invent metadata.
- [ ] Test repeated binds/reset, changed parameter types, errors, cancellation and
  disconnect; core and adapter must finalize each native handle exactly once.
- [ ] Test BEGIN/COMMIT/ROLLBACK, DML RETURNING and result conversion failures:
  execute once and avoid reporting failure after an unintended committed mutation.
- [ ] Define schema invalidation/reprepare behavior matching core, including
  changes to result shape and parameter inference. Review and commit unit proof.

## D2: MySQL prepared clients and translated analytical queries

Consumes: D1; stable core MySQL/endpoint contract K1–K4; compatibility Tasks 1–4.
Produces: working native and supported MySQL-dialect prepared execution via core.

- [ ] Add failing real-client PREPARE/EXECUTE/CLOSE/RESET tests, early metadata,
  reused type arrays, NULL bitmap boundaries, binary/long-data values and errors.
- [ ] Register the DuckDB adapter and dispatch through core. Bind typed arguments
  natively on execution; no frontend ID registry or packet decoder in DuckDB.
- [ ] At prepare, translate approved analytical SQL while preserving output labels
  and source parameter identity. Preserve order, or provide an explicit mapping
  required by core. Reject transformations that duplicate/drop/reorder parameters
  without a tested mapping.
- [ ] If admission depends on parameter types/values unavailable at prepare,
  record requirements and validate at bind/execute before effects; otherwise
  reject clearly. Do not assume the type from one execution on the next.
- [ ] Define what happens when schema, database or semantic session settings
  change between prepare and execute: validate/reprepare or fail explicitly.
- [ ] Run native and translated repeated executions directly and through ordinary
  hostgroup routing, including backend reconnect/reprepare and capability errors.
- [ ] Review and commit a MySQL milestone without claiming PostgreSQL completion.

## D3: PostgreSQL prepared integration and final acceptance

Consumes: D1 and core K5/K6; D2's engine lifecycle evidence.
Produces: reviewed DuckDB adapter for both shared frontends.

- [ ] Add failing real libpq parameterized/extended tests for named/unnamed
  statements and portals, supported parameter/result text/binary combinations,
  NULL/empty/binary data, and max-row suspension/resume.
- [ ] Register the same native adapter behind the core PgSQL frontend. PostgreSQL
  endpoint retains native DuckDB SQL; MySQL translation is not applied to it.
- [ ] Verify Sync recovery after errors, failed transaction status, close/reset,
  multiple portals, metadata changes and disconnect cleanup.
- [ ] Run direct clients and relevant ordinary proxy-route tests where supported;
  preserve legacy rejection for unsupported negotiated capabilities.
- [ ] Run existing DuckDB text/result/Admin/config/security regressions plus core
  remote-backend prepared regressions; publish precise support/limit tables.
- [ ] Obtain final independent review and open a DuckDB integration PR depending
  explicitly on the core commits. Close #6282 only when both protocol gates pass.
