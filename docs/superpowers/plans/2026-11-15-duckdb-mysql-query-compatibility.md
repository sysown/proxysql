# DuckDB Query Compatibility and Prepared Execution Roadmap

> **For agentic workers:** Use superpowers:executing-plans for inline execution
> under the user-approved implementation goal. Implement task-by-task; obtain a final independent
> review. Implementation is now authorized; Codex resolves design details and validates milestones.

**Goal:** Deliver scoped MySQL analytical SQL compatibility (#6284), the shared
Admin/SQLite/embedded prepared framework (#6298), and the DuckDB native adapter
(#6282), with typed binding and real-client acceptance on both protocols.

**Architecture:** Parse complete MySQL ASTs with vendored ParserSQL, apply a typed
admission policy, then emit DuckDB SQL into the existing execution/result path.
Keep native SQL available and prepared frontend handling owned by core #6298.

**Tech Stack:** C++17, vendored ParserSQL (currently 1.1.1 in this worktree), DuckDB,
existing MySQL/PostgreSQL protocol machinery, TAP and isolated MySQL fixtures.

**Spec:** ../specs/2026-11-15-duckdb-mysql-query-compatibility-design.md

## Global constraints

- User approved implementation. Use a feature branch/worktree based on current v3.0.
- Use only currently vendored ParserSQL for new SQL recognition; no custom parser,
  lexer, prefix-recognition workaround or new parser dependency.
- Missing grammar is fixed/tracked upstream; do not silently widen the subset.
- Native mode remains default; default external access remains disabled.
- No CDC expansion, DBTrail integration, internal routing, fallback or benchmarking.
- Core #6298 precedes adapter #6282; no plugin-local prepared protocol/state cache.

## Review focus

- Partial ASTs/trailing statements must not slip through admission (Tasks 1/2).
- Correct syntax with incompatible collation/coercion must be refused (Tasks 2/4).
- Duplicate names, quoting and comments must preserve structure (Tasks 2/3).
- Unsupported functions must never execute side effects during analysis (Tasks 2/4).
- Native execution/security guards and both protocols must remain stable (Tasks 3/4).

## File ownership

- Create plugins/duckdb/include/duckdb_mysql_select_compat.h and
  plugins/duckdb/src/duckdb_mysql_select_compat.cpp: ParserSQL admission and
  DuckDB rendering only. No private tokenizer, statement cache or wire handling.
- Create test/tap/tests/unit/duckdb_mysql_select_compat_unit-t.cpp: parser/transform
  fixtures, semantic refusal and exact emission checks where syntax matters.
- Create test/tap/tests/test_duckdb_mysql_select_compat-t.cpp: real MySQL oracle,
  direct embedded execution and ordinary same-instance hostgroup routing.
- Modify plugins/duckdb/{Makefile,include/duckdb_config.h,src/duckdb_config.cpp,
  include/duckdb_listener.h,src/duckdb_listener.cpp,include/duckdb_session.h,
  src/duckdb_session.cpp,src/duckdb_admin_schema.cpp} for opt-in integration.
- Modify test/tap/tests/{Makefile,unit/Makefile}, test/tap/groups/groups.json,
  affected config/Admin/listener/session tests and doc/duckdb documentation.

## Task 0: MyDuck Server prior-art audit — shared prerequisite

Source: https://github.com/apecloud/myduckserver (MyDuck Server).
Produces: doc/duckdb/prior-art.md with a feature/reuse matrix consumed by
compatibility Task 1, core K1 and adapter D1. This is one focused audit, not
three independent rediscoveries and not a return to CDC/benchmark evaluation.

- [ ] Pin the reviewed commit and dependencies. Inspect actual implementation
  and tests in transpiler/, compatibility/, myfunc/, adapter/, backend/, catalog/,
  charset/, pgserver/ and relevant client harnesses; README claims are not proof.
- [ ] Trace one text SELECT and one parameterized execution through parse/analyze,
  rewrite/emission, binding, execution and result encoding. Distinguish behavior
  implemented in MyDuck from behavior inherited from its MySQL/PostgreSQL stacks.
- [ ] Map quoting/LIMIT/functions, coercion/collation/time semantics, session
  initialization, result types, prepared parameter/metadata handling, invalidation
  and cleanup to concrete files/tests. Include explicit gaps and known refusals.
- [ ] For each useful pattern choose reuse/adapt/defer/reject, give the reason,
  and link a pinned source/test plus the receiving #6284/#6298/#6282 task.
  Review license/notice requirements before copying code or test fixtures.
- [ ] Adapt relevant behavioral cases into our differential/driver test corpus;
  independently verify answers against MySQL and DuckDB rather than using MyDuck
  alone as the correctness oracle.
- [ ] Preserve constraints: no import of SQLGlot, Vitess, a Go SQL engine or another
  recognizer into ProxySQL. Translate lessons to vendored ParserSQL and our native
  binding/core framework. Parser shortcomings remain upstream issues.
- [ ] Review the reuse matrix before freezing new compatibility rules or the
  shared adapter interface; then commit the audit and traceable test cases.

## Task 1: Baseline and executable parser/semantics contract

Consumes: current v3.0; deps/parsersql/README.md and packaged ParserSQL headers;
#6280/#6284 constraints; the approved design.
Produces: a supported-query matrix in doc/duckdb/mysql-query-compatibility.md and
parser capability fixtures in the new unit target.

- [ ] Review merged changes since b5971e540, resolve dependency paths and record
  baseline plugin/unit/wire results. Do not reuse old branch test counts blindly.
- [ ] Exercise the actual vendored Parser<Dialect::MySQL>::parse/parse_all,
  ParseResult, AST traversal/transformation and emitter APIs with target SELECTs.
  Verify complete input and distinguish full ASTs from classified/partial results.
- [ ] Publish the matrix for identifier quoting, LIMIT forms, basic typed SELECTs,
  candidate functions, CTE/subquery/window support and explicit refusal cases.
- [ ] Identify which session/type facts each operation requires and where they
  can be obtained without running the user query. Unknown facts must stay unknown.
- [ ] Add reproducer fixtures for unavailable grammar; record upstream gaps.
  Run the capability target and confirm expected support/refusal per fixture.
- [ ] Review the matrix before implementing translations; commit the contract
  and capability coverage as a distinct deliverable.

## Task 2: Pure admission and translation

Consumes: Task 1's approved operation/type matrix and audited ParserSQL APIs.
Proposed interface in duckdb_mysql_select_compat.h:

- DuckDBMySQLSelectContext: effective SQL/session settings and a read-only relation
  metadata resolver; represent unavailable facts explicitly.
- DuckDBMySQLSelectTranslation: decision (supported/unsupported/invalid), owned
  emitted SQL, stable diagnostic/reason code and required-context diagnostics.
- duckdb_translate_mysql_select(const std::string&, const
  DuckDBMySQLSelectContext&) -> DuckDBMySQLSelectTranslation.

Produces: a side-effect-free translation function consumed by Task 3. Exact context
field types follow the Task 1 audit; finalize them in this header before consumers
are written. No DuckDB connection execution is permitted inside this function.

- [ ] Add failing tests for backtick escaping, literal/comment preservation,
  aliases/duplicate names, nested admitted expressions and LIMIT offset/count.
- [ ] Add refusal tests for multiple/trailing statements, partial ASTs, user
  variables, unknown functions, nextval-like side effects and unsupported nested
  branches. Assert that analysis performs no execution/side-effect callback.
- [ ] Add type/session tests for collation/coercion ambiguity, NULL ordering,
  integer division, date ranges and timezone-sensitive expressions. Admit only
  cases explicitly established in the matrix.
- [ ] Run focused tests and verify intended failures; implement typed admission
  and AST-based transformation/rendering, preserving original output labels.
- [ ] Reparse emitted SQL with DuckDB native preparation in test code; verify
  focused unit outcomes and existing result/session units, then commit.

## Task 3: Opt-in endpoint integration

Consumes: the Task 2 translation result and context interface.
Produces: native versus mysql_analytical endpoint behavior through existing query
execution, configuration and result conversion. The old lexer flag is not revived.

- [ ] Add failing config/lifecycle tests for proposed duckdb-mysql_dialect values,
  native default, invalid values and startup-only changes.
- [ ] Add session tests proving native mode bypasses translation, analytical mode
  uses ParserSQL admission, and unsupported input fails before execution.
- [ ] Populate only session/type facts the endpoint actually knows. Do not treat
  compatibility SET no-ops as evidence that MySQL session semantics are implemented.
- [ ] Wire config/listener/session state and link the existing ParserSQL dependency
  into the plugin; keep PostgreSQL native and inherited security guards in force.
- [ ] Verify native DDL/DML and RETURNING still execute once; reject analytical
  mutations/side-effecting SELECTs outside the matrix; run affected unit targets.
- [ ] Document activation, limitations and stable unsupported diagnostics; commit.

## Task 4: MySQL differential and frontend acceptance

Consumes: the matrix, translator and opt-in endpoint mode.
Produces: real-source evidence and a reviewable feature PR for #6284.

- [ ] Build a dedicated MySQL fixture and equivalent DuckDB tables with INT,
  unsigned BIGINT, DECIMAL, DATE/DATETIME, binary/Unicode and nullable columns.
  Include empty sets, duplicates, negative values and boundary cases.
- [ ] Run every supported matrix query on MySQL and translated DuckDB; compare
  exact values/nulls/multiplicity and documented metadata. Compare ordered rows
  only where SQL specifies deterministic order; otherwise compare multisets.
- [ ] Exercise direct and ordinary routed MySQL connections, including authentication
  and setup SQL. Refusals must be explicit and leave side-effect fixtures unchanged.
- [ ] Cover joins, grouping, aliases, identifiers and LIMIT; add function/date-format
  cases only when the matrix admits their exact types/formats/settings.
- [ ] Run affected unit/config/Admin tests plus existing MySQL, PostgreSQL and
  typed-result wire regressions. Record skips and unsupported cases accurately.
- [ ] Obtain independent code review, fix material findings and rerun affected
  checks. Open a separate PR against current v3.0; do not close #6284 broadly if
  only its first analytical subset has been implemented.

## Shared core and DuckDB prepared execution — included delivery scope

These are separate implementation subplans within this roadmap, not deferred
placeholder work:

- [Shared core framework #6298](2026-11-15-shared-prepared-framework.md): K1 contract,
  K2 SQLite/MySQL execution, K3 long data/cursors/lifetime, K4 Admin policy,
  K5 PostgreSQL extended execution and K6 cross-endpoint acceptance.
- [DuckDB adapter #6282](2026-11-15-duckdb-prepared-adapter.md): D1 native lifecycle,
  D2 MySQL native/translated prepared execution and D3 PostgreSQL integration.

### Dependency and delivery order

1. Complete the shared MyDuck prior-art audit (Task 0), then run compatibility
   Task 1 and core K1 as separate baseline/contract work.
2. Compatibility Tasks 2–4 deliver useful COM_QUERY support independently of core.
3. Core K2–K4 prove MySQL shared execution and Admin policy using SQLite.
4. DuckDB D1 consumes the frozen contract; D2 requires the MySQL core capability
   gate and the compatibility component. Core K5 may progress independently.
5. DuckDB D3 waits for the PostgreSQL core gate; K6 and D3 finish cross-endpoint,
   real-driver and ordinary-proxy regression acceptance.

The user explicitly authorized implementation workers on 2026-11-16. Codex owns
shared contract review and integration; workers use isolated worktrees and never
modify another owner's branch. The initial internal contract does not change the
plugin ABI. Reconcile any parallel #6298 implementation before publishing ABI
changes; the initial issue-reference search found no separate implementation PR.

### Proposed PR boundaries

- Parser audit/support contract and analytical COM_QUERY compatibility (#6284).
- Shared contract and SQLite/MySQL execution; Admin/lifecycle; PostgreSQL frontend
  as reviewable core increments (#6298), preserving existing proxy behavior.
- DuckDB adapter/MySQL milestone, then PostgreSQL integration (#6282), with the
  required core commits identified explicitly.

### Combined definition of done

- Supported analytical SELECT fixtures match MySQL via direct and routed clients.
- Admin and SQLite use the shared prepared layer with endpoint policies intact.
- DuckDB uses that layer for native and supported translated MySQL prepared SQL,
  and native PostgreSQL extended SQL, with no plugin-local frontend duplication.
- Parameter types/NULLs/binary values, metadata, execution count, transaction and
  portal behavior, schema changes, limits and resource cleanup meet the published
  capability contract. Unsupported behavior fails explicitly.
- Existing remote-backend proxy prepared and native text execution regressions pass.
- Parser gaps, platform limitations and protocol/type exclusions are documented.

BI/ORM discovery (#6285) remains a subsequent feature. CDC expansion, DBTrail
integration, managed Parquet activation and throughput work remain excluded.

## Implementation decisions

Codex reviews and freezes the initial operation matrix and opt-in endpoint mode
before their consumers are implemented, informed by the MyDuck reuse matrix. Execution uses user-requested OpenCode opencode-go Beam Free / Deepseek v4.1 flash
or GPT-6.1 Terra workers where practical. Codex owns design, integration and
independent validation. No implementation task is complete merely by approval.

## ParserSQL development authorization — 2026-11-16

The user authorized local ParserSQL modifications during implementation. Keep the
released archive unchanged, carry reproducible local patches with pinned upstream
base/head and regression tests, and consolidate all parser changes into the final
upstream ParserSQL PR. Upstream merge/tag/release is not a prerequisite for this
goal. Production recognition still uses only the vendored ParserSQL code.
