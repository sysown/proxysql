# Shared Prepared-Statement Framework Implementation Plan — #6298

> **For agentic workers:** Use superpowers:executing-plans under the user-approved implementation goal.
> This is a core-owned project; coordinate shared headers with the DuckDB task.

**Goal:** Support parameterized clients on Admin, SQLite3 server and embedded
engines through shared MySQL/PostgreSQL frontend machinery with endpoint policy intact.

**Architecture:** Core owns protocol state, IDs/names/portals, typed decoding and
encoding, lifetime and limits. Native engine adapters implement execution behind
one versioned contract. Prove that contract with SQLite before integrating DuckDB.

**Tech Stack:** C++17, existing protocol/prepared codecs, SQLite3, ParserSQL and TAP.

**Spec:** ../specs/2026-11-15-duckdb-mysql-query-compatibility-design.md
(section: Integrated prepared-execution design)

## Global constraints

- User approved implementation; use an isolated feature worktree based on current v3.0.
- Preserve ordinary remote-backend MySQL/PostgreSQL prepared behavior.
- New SQL recognition uses vendored ParserSQL only. Do not equate native SQLite
  preparation with authorization to execute an Admin statement.
- Bind parameters natively. Binary/NULL/text/decimal values have distinct types.
- No DuckDB-local frontend implementation; no CDC, routing or benchmark expansion.
- Protocol pagination does not imply bounded-memory engine execution or completion
  of the separate streaming-result project #6287.

## Review focus

Malformed packets/type reuse; empty versus NULL versus binary; resource cleanup
on every error; Admin policy bypass; plugin ABI mismatch and backend proxy regressions.
Tasks K1–K6 assign coverage for each of these classes.

## Files

Proposed new core units:
- include/Embedded_Execution.h: engine contract, capabilities, typed descriptors,
  ownership, version and error structures.
- include/Embedded_Prepared.h and lib/Embedded_Prepared.cpp: session registry,
  lifecycle, limits and endpoint policy dispatch.
- lib/Embedded_MySQL_Prepared.cpp and lib/Embedded_PgSQL_Prepared.cpp: distinct
  protocol frontends over that registry; reuse existing codecs where contracts fit.
- lib/Embedded_SQLite_Adapter.cpp: SQLite prepare/bind/step/reset/finalize adapter.
- doc/embedded-prepared-statements.md: published contract/capability documentation.
- test/tap/tests/unit/embedded_prepared_unit-t.cpp and
  embedded_sqlite_adapter_unit-t.cpp: lifecycle/policy/engine tests.
- test/tap/tests/test_embedded_prepared_mysql-t.cpp and
  test_embedded_prepared_pgsql-t.cpp: isolated real-client acceptance.

Existing integration: include/{MySQL_Session.h,PgSQL_Session.h,ProxySQL_Plugin.h},
lib/{MySQL_Session.cpp,PgSQL_Session.cpp,MySQL_Protocol.cpp,PgSQL_Protocol.cpp,
Admin_Handler.cpp}, src/SQLite3_Server.cpp, relevant build files and TAP groups.
Names are proposed; contract review may consolidate units while preserving ownership.

## K1: Audit and freeze the engine/policy contract

Consumes: roadmap Task 0 MyDuck reuse matrix, existing proxy prepared codecs/state,
endpoint handlers and #6298.
Produces: versioned EmbeddedExecutionAdapter contract in Embedded_Execution.h.
Required operations: prepare, describe_parameters, describe_result, bind, execute,
fetch, reset and finalize. Define exact C++ signatures and typed values before
any frontend or DuckDB consumer is implemented; do not guess a future plugin ABI.

- [ ] Review MyDuck prepared/session/type-mapping findings and relevant driver
  tests; adopt useful patterns without importing its protocol/SQL-engine stack.
- [ ] Inventory reusable MySQL bind/row codecs, PostgreSQL formats and statement
  state; identify proxy-only assumptions and capture baseline regression results.
- [ ] Specify statement/session affinity, handle ownership, execution transaction
  ownership, errors/SQLSTATE mapping and capability negotiation.
- [ ] Specify metadata lifetime (owned), row-buffer lifetime (valid until next fetch),
  parameter ownership and exact conversion/overflow refusal rules.
- [ ] Set documented per-session/global limits for statements, portals, buffered
  long data and result materialization. Tests use small injected limits; production
  defaults require contract review and must not remain unspecified at handoff.
- [ ] Define versioned endpoint registration. If plugin services/descriptor layout
  changes, follow ABI-version rules; test supported older plugins and explicit
  rejection of incompatible binaries. No silent layout changes.
- [ ] Add contract tests with a recording fake adapter for ownership, execution
  count, affinity, error cleanup and exhausted limits; publish the reviewed header.
- [ ] Deliver a contract PR/commit and capability/error table before K2 or D1.

## K2: Shared lifecycle and MySQL execution on SQLite

Consumes: K1 contract. Produces: working SQLite3-server PREPARE/EXECUTE/CLOSE/RESET.

- [ ] Add failing adapter tests for native SQLite bind/step/reset/finalize, empty
  and NULL values, binary NUL bytes, metadata and rollback/commit ownership.
- [ ] Implement Embedded_SQLite_Adapter and session registry; finalize resources
  on close/reset/disconnect and define schema invalidation/reprepare behavior.
- [ ] Add failing wire tests for prepare metadata, binary rows, repeated execute
  with reused parameter types, mixed signedness, malformed/truncated packets,
  unknown IDs, conversion overflow and injection-shaped bound values.
- [ ] Integrate core MySQL frontend with SQLite3 server; preserve remote-backend
  dispatch and existing transaction/status behavior. Never reconstruct bound SQL.
- [ ] Run unit targets and real mysql_stmt client tests; review and commit K2.

## K3: Long data, cursor policy and lifecycle completeness

Consumes: K2 registry/frontend. Produces: explicit, enforced capability behavior.

- [ ] Test SEND_LONG_DATA chunk concatenation, empty chunks, invalid indexes,
  limit overflow, reset/cancel and cleanup after failed execution.
- [ ] Implement bounded core long-data accumulation and native binding.
- [ ] Define supported cursor types/FETCH behavior in the contract. Support
  read-only cursors only for adapters advertising the capability; reject other
  flags clearly before execution. Test fetch sizes, EOF, reset and disconnect.
- [ ] Test schema change and execute failure without duplicate effects or leaked
  handles. Run existing long-data/metadata proxy regressions, review and commit.

## K4: Admin integration with explicit policy

Consumes: K2/K3. Produces: parameterized Admin queries within Admin authorization.

- [ ] Test permitted Admin SELECT and supported parameterized SQL DML using
  isolated config tables; verify the same policy as corresponding text execution.
- [ ] Test read-only users, managed configuration tables, side-effecting PRAGMAs
  and SQLite connection features cannot bypass Admin restrictions.
- [ ] For non-SQL Admin commands, either route through a documented prepared
  command contract or reject explicitly at prepare. No pretending LOAD/SAVE are
  ordinary SQLite SQL and no silent acceptance of unsupported command shapes.
- [ ] Integrate with existing Admin dispatch/locks/side effects; run Admin and
  SQLite client regressions, publish endpoint capability differences and commit.

## K5: PostgreSQL extended-query frontend

Consumes: K1 contract and common lifecycle validated by K2–K4.
Produces: SQLite/Admin supported extended execution using the shared engine seam.

- [ ] Add failing libpq/protocol tests for Parse/Bind/Describe/Execute/Close/Flush/Sync,
  named and unnamed statements/portals, format-count validation and typed NULLs.
- [ ] Implement parameter OID inference/refusal, text/binary format negotiation,
  result descriptions, and binary encoding only for supported type/format pairs.
- [ ] Implement portal row limits/suspension/resume, correct completion messages,
  and recovery that discards messages through Sync after extended-query errors.
- [ ] Test failed transactions, implicit extended-cycle transaction boundaries,
  multiple portals, close/reset/disconnect and schema invalidation.
- [ ] Run real libpq prepared clients plus existing PgSQL proxy prepared/portal
  regressions; review and commit with a protocol-specific capability table.

## K6: Publish the stable DuckDB handoff and cross-endpoint acceptance

Consumes: K1–K5. Produces: reviewed core contract ready for #6282.

- [ ] Publish supported values/encodings, endpoint policies, lifecycle diagrams,
  resource limits, invalidation rules and example native adapter integration.
- [ ] Run the same repeated-bind/NULL/binary/empty/error/schema/reset/disconnect
  cases across Admin and SQLite for each supported frontend.
- [ ] Run ordinary MySQL/PostgreSQL proxy prepared regressions, existing text
  endpoint tests and plugin ABI/loading tests. Record failures/skips explicitly.
- [ ] Obtain independent review of ownership, policy, binary codecs and regression
  boundaries; resolve material findings and open narrowly scoped core PRs.

MySQL DuckDB integration may start after its reviewed K1–K4 contract is available;
PostgreSQL DuckDB wire integration waits for K5. Do not report #6298 complete until
both protocol and endpoint acceptance criteria, including K6, are satisfied.
