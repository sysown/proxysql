# MySQL analytical queries on embedded DuckDB — implementation design

Status: implementation approved by user on 2026-11-16; tracked by active session goal.
Baseline: merged v3.0, observed at 663e84aa6; do not implement on the retired
feature/duckdb-mysql-replica branch without first creating a fresh worktree.
Parent: https://github.com/sysown/proxysql/issues/6280
Compatibility: https://github.com/sysown/proxysql/issues/6284

## Approved delivery goal

Let existing MySQL clients execute a documented core of analytical SELECTs on
ProxySQL's embedded DuckDB without rewriting those supported queries. Translate
only through the currently vendored ParserSQL, preserve the supported MySQL
semantics and typed results, and reject unsupported behavior before execution.
Prove equivalent results against MySQL through direct and ordinary routed
connections. Keep DuckDB-native SQL available.

The overall delivery goal includes #6284 SQL compatibility, #6298 shared core
prepared execution and #6282 DuckDB integration. COM_QUERY compatibility is the
first independent milestone; prepared execution follows the shared core contract
and is not a plugin-local protocol project.

## Why this work

Query compatibility benefits every ingestion path: native replication, imported
local tables and DBTrail-produced Parquet. Ingestion selection is independent.
The native applier already merged; its correctness maintenance continues as a
separate, narrow workstream. No CDC expansion, alternative evaluation or throughput
benchmarking belongs in this phase.

## Approaches and proposed choice

1. ParserSQL AST admission/transformation plus a DuckDB SQL renderer: recommended.
   It preserves structure and provides a place to check meaning before execution.
2. Text/regex substitutions: rejected by #6280 and unsafe around quoted text,
   comments, nesting and context-dependent expressions.
3. Full MySQL emulation: outside this milestone; it would make a bounded useful
   feature depend on session, DML, collation and storage behavior not yet provided.

The user selected query compatibility as the next priority. The exact initial
operation list and endpoint activation policy below remain proposals for review.

## First milestone contract

Candidate support slices, admitted only after the parser/semantic audit:

- One complete read-only SELECT, including projections, aliases, safe predicates,
  joins, grouping/aggregates and explicit ordering over supported types.
- Backtick-delimited identifiers, preserving case/name resolution and escaping.
- MySQL LIMIT offset,count, preserving the row selection and ordering semantics.
- A bounded function set: begin with operations already equivalent under explicit
  type rules; consider DATE_FORMAT of DATE/DATETIME with literal %Y-%m as the first
  dialect-specific function. Unknown format tokens, timezone-dependent behavior
  and implicit coercions are refused until separately specified and tested.
- CTEs, subqueries and window functions are candidates only when the vendored
  parser yields full ASTs and every enclosed operation passes admission.

No candidate is promised merely because the parser accepts it. The first task
publishes an operation-by-operation matrix: supported, semantics deferred, or
parser blocked. At least the identifier/LIMIT slices must be deliverable to call
this a compatibility feature; a matrix consisting solely of rejections is not
completion. If either slice is blocked, report the blocker and revise scope with
the user rather than inventing downstream recognition.

Proposed activation: startup-only duckdb-mysql_dialect=native|mysql_analytical,
with native as the default. This is distinct from MySQL's session sql_mode and
from the removed duckdb-mysql_compatibility lexer switch. PostgreSQL remains
native. Existing discovery/session/security handling remains intact.
In analytical mode, new SQL goes through ParserSQL; mutating statements and
side-effecting SELECT functions outside the approved contract fail explicitly.
Do not bypass Admin-managed configuration policy or quietly accept unsupported
session settings. No new internal routing or automatic fallback is introduced.

## Correctness boundaries

Only a complete SELECT AST covering the full packet may be translated. ERROR,
PARTIAL, classification-only, trailing input and multiple statements are never
eligible. Consume quoted strings and comments exclusively through ParserSQL.
Do not infer an operation's semantics from function spelling alone.

Admission uses effective session settings and available relation/type metadata.
Missing provenance is an explicit unknown, not a guessed MySQL collation or type.
VARCHAR projection can be safe while its comparison/grouping is not. Character
collation/padding, implicit numeric casts, integer division, overflow, zero dates,
NULL ordering, time zones and nondeterministic aggregation need explicit rules.
Unsupported branches are refused even if their runtime evaluation seems unlikely.
No expression or source query may be executed to discover its semantics.

Compare exact integers/decimals, binary/Unicode/NULL values and multiplicity.
Compare sequence only for deterministic ORDER BY; use multisets otherwise.
Metadata assertions use the documented MySQL-facing mapping, not an assumption
that every MySQL expression exposes identical metadata on the two engines.
Native mode must preserve existing DDL/DML, execute-once RETURNING safety,
configuration guards, typed results and PostgreSQL behavior.

## Ownership and later milestones

- #6284: parser-aware SQL admission, translation, session compatibility contract.
- #6298: core statement IDs, frontend state machines, parameter decoding,
  binary result encoding, cleanup, limits and engine-neutral adapter contract.
- #6282: DuckDB native prepare/describe/bind/execute/fetch/reset/finalize through
  that contract. Bind natively; never interpolate parameters into SQL text.
- #6285: BI/ORM discovery and relevant driver initialization after the necessary
  execution capabilities exist.

Translation precedes native preparation. Prepared integration must preserve the
original parameter identity/order or provide an explicit mapping tested with
repeated binds. No DuckDB-local prepared registry/state machine is allowed.

## Definition of done

The supported matrix and restrictions are public; ParserSQL gaps have reproducer
cases and upstream references; admitted queries match MySQL on edge-case fixtures;
unsupported cases cannot execute side effects; direct/routed client tests and
native/MySQL/PostgreSQL regression suites pass. The opt-in mode and its lifecycle
are documented. This does not claim complete MySQL compatibility or completion
of #6280, #6282, #6285 or #6298.

## Integrated prepared-execution design

Core #6298 is part of this roadmap, not an assumed external implementation.
The user authorized this session to implement the integrated roadmap. An initial
issue-reference search found no separate framework implementation PR; the first
slice therefore introduces an internal contract in isolated worktrees without
changing the plugin ABI or any other owner's branch. Codex reviews and freezes
the shared contract before frontend and native-adapter consumers use it. Reconcile
any subsequently discovered parallel implementation before public ABI changes.

Core provides distinct MySQL and PostgreSQL frontend state machines over one
engine-neutral execution interface. It owns statement IDs, statement/portal names,
parameter decoding/type reuse, long-data buffers, binary/text result encoding,
resource limits, session registry, cleanup and error resynchronization. Remote
backend proxy execution stays on its existing path.

The contract explicitly separates SQL text, typed parameters, owned parameter/result
metadata, engine-native handles, row batches and errors. Text and binary payloads
are distinct; decimal precision/scale and temporal semantics cannot be reduced to
untyped strings. Core encodes borrowed row buffers before the adapter fetches again.
Native handles remain bound to the creating engine session. Capabilities cover
long data, cursors/FETCH, format combinations and result types; unsupported
capabilities are refused before effects. Protocol fetch pagination does not promise
streaming or bounded-memory materialization by every engine.

Required engine operations are prepare, parameter/result description, bind,
execute, fetch, reset and finalize. The core contract task fixes their C++ signatures,
ownership and resource defaults before consumers are written. Registration across
the plugin boundary must be versioned and validated; preserve compatible older
plugins or reject incompatible ones clearly rather than changing struct layout silently.

SQLite is the reference native adapter. Admin reuses it only after endpoint policy
approves the statement: authorization/read-only rules, managed settings, locks and
command side effects cannot be bypassed by SQLite preparation. Non-SQL commands
need an explicit supported contract or an actionable prepare-time refusal.

MySQL scope includes PREPARE/EXECUTE/CLOSE/RESET, type reuse, NULL bitmaps, binary
rows, bounded SEND_LONG_DATA and explicit cursor/FETCH capability behavior.
PostgreSQL scope includes Parse/Bind/Describe/Execute/Close/Flush/Sync, named and
unnamed statements/portals, supported parameter/result formats, max-row suspension,
transaction status and discard-through-Sync recovery.

DuckDB #6282 implements the same contract using native preparation and binding.
It reuses the logical/value fidelity foundation rather than adding packet handling.
Translation happens before native preparation. Placeholder identity must survive,
or core must receive a tested mapping. Parameter-dependent semantic checks happen
at bind/execute before effects; unsupported inference is refused. Schema, selected
database or semantic-session changes require validation/reprepare or an explicit
error. DML/result-conversion failure must not introduce unintended committed effects.

Acceptance spans real MySQL and libpq clients on Admin, SQLite and DuckDB,
including repeated binds, NULL/empty/binary data, metadata before execution,
errors, cleanup, limits and schema invalidation. DuckDB MySQL tests cover native
and translated queries through direct and ordinary routed connections; PostgreSQL
keeps native DuckDB SQL. Existing remote-backend prepared regressions must pass.

Linked implementation plans:
- ../plans/2026-11-15-shared-prepared-framework.md
- ../plans/2026-11-15-duckdb-prepared-adapter.md

## Required prior art: MyDuck Server

Review https://github.com/apecloud/myduckserver before designing new SQL rules or
freezing the shared execution contract. Its advertised MySQL/DuckDB compatibility
makes it directly relevant; evaluate actual code and tests, not feature claims.
The initial repository inspection confirms separate transpiler, compatibility,
function, adapter, catalog and PostgreSQL areas. Its dependencies include Go SQL
stacks and SQLGlot; those are evidence to investigate, not dependencies approved
for ProxySQL.

One pinned audit must deliver a reuse matrix covering text translation, functions,
coercion/collation/time behavior, session setup, prepared binding/metadata, result
types and cleanup. Each adopted pattern/case is linked to an implementation task
and independently checked against the source database. Check license/attribution
requirements before copying code or tests. Reuse ideas and behavioral coverage
where appropriate; keep our ParserSQL-only recognition and core/frontend ownership.
This audit is a prerequisite shared by #6284, #6298 and #6282, not a separate CDC
or alternative-product exploration project.
