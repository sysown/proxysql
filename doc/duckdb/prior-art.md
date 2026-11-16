# MyDuck Server Reuse Audit (Task 0)

Status: source-grounded audit for roadmap Task 0. This document is consumed by
compatibility Task 1 (#6284), core contract task K1 (#6298), and adapter task
D1 (#6282). Implementation of the roadmap is authorized; this audit itself
contains no production code changes.

## 1. Purpose and scope

This audit reviews MyDuck Server as prior art for ProxySQL's embedded DuckDB
MySQL/PostgreSQL compatibility work. It separates:

- behavior that ProxySQL can learn from and test independently;
- implementation patterns that can inform ownership and lifecycle design;
- dependencies and mechanisms that ProxySQL must not adopt.

ProxySQL constraints remain in force:

- new SQL recognition uses only the vendored ParserSQL 1.1.1;
- no SQLGlot, Vitess, Go SQL engine, or other recognizer is introduced;
- parameter binding is native; no SQL interpolation;
- MyDuck is never treated as the sole correctness oracle;
- core #6298 owns frontend protocol state; plugin #6282 owns only the DuckDB
  native adapter; #6284 owns ParserSQL admission and DuckDB rendering.

## 2. Source pin and dependency inventory

Reviewed source:

- Repository: `https://github.com/apecloud/myduckserver`
- Pinned commit: `6e3427591fd8895df9585969e7256f958fb639bb`
  (`6e34275 fix(pg): reflect physical dataset columns for Superset (#506)`)
- Local read-only clone: `/tmp/myduck-compat-audit-20261116`
- License: Apache License 2.0, copyright `Copyright 2024-2025 ApeCloud, Ltd.`
  (see [LICENSE](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/LICENSE)).
- Some files carry an additional Dolthub copyright, notably
  [transpiler/README.md](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/transpiler/README.md)
  and [pgserver/duck_handler.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/pgserver/duck_handler.go).

Dependency evidence from `go.mod` at the pinned commit (not approved for
ProxySQL):

| Dependency | Version in pinned source | Role in MyDuck | ProxySQL stance |
|---|---|---|---|
| `github.com/duckdb/duckdb-go/v2` | `v2.10505.0` | DuckDB Go driver | ProxySQL uses DuckDB C API directly |
| `github.com/dolthub/vitess` | `v0.0.0-20260819175407-19559ab533b7` | MySQL parser/protocol/server | Not approved; ProxySQL has its own MySQL protocol |
| `github.com/go-sql-driver/mysql` | `v1.9.3` | MySQL client harness | Test-only concept, not runtime dependency |
| `github.com/dolthub/go-mysql-server` | `v0.20.1-0.20260817180248-8ba7438d98bb`, replaced by ApeCloud fork `v0.0.0-20260824193556-7477d05ca7a3` | MySQL frontend/storage adapter | Not approved |
| `github.com/cockroachdb/cockroachdb-parser` | `v0.23.2` | PostgreSQL SQL parser | Not approved |
| `github.com/jackc/pgx/v5` | `v5.9.2` | PostgreSQL protocol types | Reference only |
| `github.com/apache/arrow-go/v18` | `v18.5.1` | Arrow type conversion | Reference only |
| Python `sqlglot` | external process | SQL translation | Explicitly rejected |
| `golang.org/x/text` | `v0.37.0` | Charset encoding | Reference for charset cases |

`vitess.io/vitess v0.21.1` is also a direct dependency. The Go toolchain
requirement is `go 1.26.2`. Inspect replacements as well as requirements when
reproducing this pin.

Evidence standard used in this audit:

- README claims are treated as product claims only.
- Findings below cite inspected source symbols and tests.
- No heavy Go build, Docker service, or model/service configuration was run.
- MyDuck output is never used as the sole expected value; expected semantics
  must be independently checked against MySQL and DuckDB.

## 3. Method

Inspected source areas named by the roadmap:

- `transpiler/`
- `compatibility/`
- `myfunc/`
- `adapter/`
- `backend/`
- `catalog/`
- `charset/`
- `pgserver/`

Also inspected `pgtypes/` because it contains the DuckDB/PostgreSQL type mapping
used by the PG prepared path. Read test definitions where present, including
`transpiler/translate_test.go`, `adapter/adapter_test.go`, and compatibility
client harnesses. Did not run MyDuck tests or builds.

## 4. Ownership model conclusion

MyDuck is a standalone MySQL/PostgreSQL-compatible server whose execution engine
is DuckDB. ProxySQL is a proxy with its own protocol frontends and its own
embedded DuckDB plugin. Therefore the reusable value is not MyDuck's server
stack; it is its observed translation rules, type mappings, prepared-statement
metadata probing, session/charset policies, and test cases.

Ownership in ProxySQL must remain:

| Layer | Owner | Responsibility | MyDuck counterpart (reference only) |
|---|---|---|---|
| SQL recognition/admission/rendering | #6284 `duckdb_mysql_select_compat` | ParserSQL AST admission, typed refusal, DuckDB SQL emission | `transpiler/translate.go`, `transpiler/converter.go` |
| Frontend protocol and state | core #6298 + existing ProxySQL MySQL/PG handlers | packet codecs, statement/portal IDs, long data, formats, limits, cleanup | go-mysql-server/Vitess and pgserver handlers |
| Native engine execution | #6282 DuckDB adapter | native prepare/describe/bind/execute/fetch/reset/finalize using DuckDB C API | `pgserver/duck_handler.go` DuckDB probing |
| Session/security policy | ProxySQL existing session/config code | read-only, external access, sensitive SQL rejection | `backend/handler.go`, `catalog/sensitive_sql.go` |

ProxySQL must not import MyDuck's frontend or SQL engine. MyDuck's
`TranslateWithSQLGlot` is a negative example: it shells out to Python SQLGlot,
keeps only the first statement, and performs regex pre-mutation before parsing.
ProxySQL's design explicitly forbids that class of recognizer and requires
complete-AST admission through vendored ParserSQL.

## 5. Findings

### 5.1 MySQL text translation

Source:
[transpiler/translate.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/transpiler/translate.go)

Key symbols:

- `TranslateWithSQLGlot(sql string) (string, error)` (line 1582)
- `newTranslateService()` (line 55)
- `transpile_mysql_to_duckdb(sql string) string` (embedded Python, around the
  `def transpile_mysql_to_duckdb` block)
- `normalize_mysql_aggregates` (embedded Python transform)
- `rewrite_mysql_for_duckdb` (embedded Python transform)

Observed behavior:

- Uses `sqlglot.parse(sql, read="mysql")`, then transforms the AST and renders
  with `sql(dialect="duckdb")`.
- Pre-mutates SQL with regex for identifiers such as `t.AND`, `REPLACE INTO`,
  `UPDATE ... LIMIT ... OFFSET`, and `DELETE ... LIMIT ... OFFSET`.
- Keeps only `trees[0]`; multiple statements are silently discarded.
- Rewrites many MySQL functions and aggregates to DuckDB equivalents.
- Wraps non-aggregated SELECT columns in `ANY_VALUE(...)` when an aggregate is
  present and there is no explicit `GROUP BY`.

Useful cases to adapt independently:

- backtick identifier preservation and escaping;
- MySQL `LIMIT offset, count` and `LIMIT count OFFSET offset`;
- aggregate-column wrapping semantics;
- function rewrites such as `CHAR_LENGTH`, `FIND_IN_SET`, `SUBSTRING_INDEX`,
  `JSON_*`, `FORMAT`, `TIME_FORMAT`, `FROM_UNIXTIME`, `MOD`, `SPACE`,
  `UNHEX`, `MD5`, `SHA2`, `BIT_LENGTH`, `OCTET_LENGTH`, `ASCII`, `CHAR`,
  `ELT`, `FIELD`, `ADDDATE`, `CONV`, `GREATEST`/`LEAST` null safety.

Decision: reject SQLGlot and the Python subprocess; adapt behavioral cases and
expected outputs into ParserSQL-based fixtures after independent MySQL/DuckDB
verification.

### 5.2 Quote and string normalization

Source:
[transpiler/converter.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/transpiler/converter.go)

Key symbols:

- `NormalizeStrings(q string) string` (line 52)
- `DenormalizeStrings(q string) string` (line 172)
- `stringParserState` and related state constants (line 34)

Observed behavior:

- Converts MySQL backticks to PostgreSQL double quotes and MySQL double-quoted
  strings to single quotes.
- Tracks single, double, backtick, and escaped states.

Decision: reject as a recognition mechanism; adapt quote/escape edge cases,
including doubled backticks and strings containing quote-like characters, into
ParserSQL tests.

### 5.3 MySQL/DuckDB type mapping

Source:
[catalog/type_mapping.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/catalog/type_mapping.go)

Key symbols:

- `AnnotatedDuckType` (line 18)
- `MySQLType` (line 31)
- `DuckdbDataType(mysqlType sql.Type) (AnnotatedDuckType, error)` (line 139)
- `mysqlDataType(duckType AnnotatedDuckType, numericPrecision uint8, numericScale uint8) (sql.Type, error)` (line 222)
- `newDateTimeType`, `newEnumType`, `newSetType`, `newVectorType`,
  `newDecimalType`, `newMediumIntType`

Observed behavior:

- Comprehensive MySQL-to-DuckDB mapping for signed/unsigned integers,
  `MEDIUMINT`, `YEAR`, `DECIMAL` with precision/scale truncation to 38,
  `TIMESTAMP` precision buckets, `TIME` as DuckDB `INTERVAL`, `ENUM`,
  `SET`, `BIT`, `JSON`, `VECTOR`, `VARCHAR`/`BLOB`/`VARBINARY`/`BINARY`.
- Reverse mapping includes TODO noting type mappings are not lossless and that
  original type metadata should be stored in column comments.

Useful cases:

- unsigned `BIGINT` boundary handling;
- `DECIMAL(38,...)` truncation and scale adjustment;
- `DATETIME`/`TIMESTAMP` precision buckets;
- `ENUM` empty-string tolerance in non-strict MySQL mode;
- `SET` stored as `VARCHAR`;
- `BIT` stored as unsigned integer.

Decision: adapt mapping table and edge cases into ProxySQL's typed result and
metadata contract; do not copy Go code.

### 5.4 Charset and collation conversion

Source:
[charset/charset.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/charset/charset.go)

Key symbols:

- `IsSupported(id sql.CharacterSetID) bool` (line 18)
- `IsUTF8(id sql.CharacterSetID) bool` (line 33)
- `IsSupportedNonUTF8(id sql.CharacterSetID) bool` (line 41)
- `getEncoding(id sql.CharacterSetID) (encoding.Encoding, error)` (line 45)
- `Encode`, `Decode`, `EncodeBytes`, `DecodeBytes` (lines 75-113)

Observed behavior:

- Supports `ascii`, `latin1` as Windows-1252, `utf8mb3`/`utf8mb4`, `ucs2`,
  `utf16`, `utf16le`, `utf32`, `gb2312`, `gbk`, `gb18030`, `big5`.
- UTF-8 charsets use a no-allocation fast path.

Useful cases:

- `latin1` versus `cp1252` byte expectations;
- non-UTF8 round trips;
- collation coercibility for function results.

Decision: adapt charset cases; ProxySQL's existing charset implementation remains
the owner, but the MySQL/DuckDB boundary must be tested with these charsets.

### 5.5 MySQL frontend and prepared execution

Source:
[backend/handler.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/backend/handler.go)

Key symbols:

- `MyHandler` (line 36)
- `ComQuery` (line 151)
- `ComMultiQuery` (line 105)
- `ComStmtExecute` (line 195)
- `ComPrepare` (line 231)
- `ComPrepareParsed` (line 242)
- `ComBind` (line 253)
- `ComExecuteBound` (line 264)
- `ComParsedQuery` (line 289)

Observed behavior:

- MySQL prepared statements pass through Vitess/go-mysql-server and then to
  DuckDB. Security filtering (`RejectSensitiveSQL`) occurs before parsing.
- `ComPrepareParsed` accepts a Vitess-parsed statement and delegates to
  go-mysql-server.
- This is a full MySQL server implementation, not a proxy adapter.

Useful cases:

- prepared metadata before execution;
- repeated execute with reused parameter types;
- `SEND_LONG_DATA` chunking and reset;
- connection close cleanup.

Decision: adapt lifecycle and security-gating cases; reject frontend adoption.
ProxySQL's core #6298 owns the MySQL frontend protocol and state.

### 5.6 Adapter and execution snapshot lifecycle

Source:
[adapter/adapter.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/adapter/adapter.go)

Key symbols:

- `ConnectionHolder` (line 21)
- `ExecutionSnapshotHolder` (line 60)
- `ExecutionSnapshotLeaseHolder` (line 73)
- `LeasedRows` (line 128)
- `LeasedRow` (line 186)
- `GetExecutionSnapshotWithLease` (function in the same file)
- `FinalizeCommit`, `FinalizeRollback`, `FinalizeRollbackWithCleanup`

Observed behavior:

- Uses leased physical connections/transactions and releases them only at
  terminal result boundaries.
- Distinguishes legacy holders from lease-aware holders.
- Keeps identity-safe close/finalize semantics.

Useful cases:

- lease release exactly once on EOF or explicit close;
- lease retained during driver call;
- admission failure releases lease before driver call;
- transaction binding mismatch releases lease before driver call.

Decision: adapt lifecycle test scenarios into core #6298; ProxySQL already has
similar lease helpers, but the MyDuck tests provide a compact regression corpus.

### 5.7 PostgreSQL extended execution and DuckDB probing

Source:
[pgserver/duck_handler.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/pgserver/duck_handler.go)

Key symbols:

- `DuckHandler` (line 86)
- `ComBind(ctx, c, prepared, bindVars)` (line 109)
- `ComExecuteBound(ctx, conn, portal, callback)` (line 141)
- `ComPrepareParsed(ctx, c, query, parsed)` (line 162)
- `prepareDuckDBStatementMetadata(ctx, conn, query)` (line 607)
- `postgresPlaceholderCount` (referenced in `ComPrepareParsed`)
- `postgresDuckDBStatementType` (referenced in `ComPrepareParsed`)

Observed behavior:

- At `Parse`, if a transaction is active, DuckDB is not probed beside the
  active transaction; instead statement type and placeholder count are inferred
  from the AST/lexical count. Parameter OIDs become unknown/zero.
- If no transaction is active, a short-lived raw DuckDB probe supplies exact
  statement and parameter types.
- For `SELECT`, result metadata is obtained by executing with `NULL` parameters
  and `LIMIT 0`.
- For `SHOW`/`CALL`/`PRAGMA`, the query is executed directly to obtain result
  types.
- For other statements, an "affected rows" field is returned.
- `ComBind` binds `driver.NamedValue` ordinals to a DuckDB prepared statement.
- `ComExecuteBound` runs the prepared SQL with bound variables.

Useful cases:

- parameter type inference at prepare versus bind;
- transaction-safe metadata probing;
- result metadata without executing the user's full query;
- unnamed/NULL parameter OID handling.

Decision: adapt metadata/lifecycle cases for #6282; reject direct reuse of
Go driver probing. ProxySQL's adapter must use the native DuckDB C API and
core's contract.

### 5.8 PostgreSQL type mapping

Source:
[pgtypes/pgtypes.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/pgtypes/pgtypes.go)

Key symbols:

- `DuckdbTypeToPostgresOID` (map)
- `PostgresOIDToDuckDBTypeName` (map)
- `postgresTypeSizes` (map)
- `PostgresTypeToArrowType`
- `duckdbTypeNameToPostgresTypeName`

Observed behavior:

- Maps DuckDB types to PostgreSQL OIDs, including unsigned integer
  approximations (`UTINYINT -> int2`, `USMALLINT -> int4`, `UINTEGER -> int8`,
  `UBIGINT -> numeric`).
- Maps PostgreSQL OIDs back to DuckDB type names, including array types.
- Temporal and decimal mappings include precision/scale handling.

Useful cases:

- unsigned integer representation on PostgreSQL clients;
- decimal precision/scale negotiation;
- temporal OID selection.

Decision: adapt type mapping table for #6282 PostgreSQL integration; verify
against libpq clients.

### 5.9 Comment and statement handling

Source:
[pgserver/stmt.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/pgserver/stmt.go)

Key symbols:

- `RemoveLeadingComments` (line 109)
- `RemoveComments` (line 157)
- `GuessStatementTag` (line 94)
- `GetStatementTag` (line 38)

Observed behavior:

- Implements nested block comments, dollar-quoted strings, escape handling,
  and statement tag guessing.

Useful cases:

- nested comments in SQL text;
- dollar-quoted strings;
- statement tag classification.

Decision: adapt comment edge cases into ParserSQL admission tests; reject regex
transformation as the recognition path.

### 5.10 Custom functions

Source:
[myfunc/ps.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/myfunc/ps.go),
[myfunc/registry.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/myfunc/registry.go)

Key symbols:

- `PSCurrentThreadID` (line 9)
- `ExtraBuiltIns` (registry.go line 5)

Observed behavior:

- Adds a non-deterministic `ps_current_thread_id()` function returning the
  connection ID.

Decision: defer. Not needed for #6284/#6298/#6282 first milestones. If
ProxySQL later exposes performance-schema-like functions, add them through
DuckDB's native function registration, not through MyDuck's go-mysql-server
function API.

### 5.11 Differential client harness

Source:
[compatibility/mysql/go/mysql.go](https://github.com/apecloud/myduckserver/blob/6e3427591fd8895df9585969e7256f958fb639bb/compatibility/mysql/go/mysql.go)

Key symbols:

- `Tests.readTestsFromFile` (line 45)
- `Tests.runTest` (line 69)

Observed behavior:

- Simple file-driven harness comparing row values as strings.

Decision: adapt harness style for ProxySQL's TAP/driver tests; expected values
must come from MySQL and DuckDB independently.

## 6. Reuse/adapt/defer/reject matrix

| # | Pattern / finding | MyDuck source (pinned) | Decision | Target task | Testable case |
|---|---|---|---|---|---|
| 1 | SQLGlot AST rewrite and Python subprocess | `transpiler/translate.go:TranslateWithSQLGlot` | Reject | #6284 | Refuse dependency; ParserSQL-only recognition |
| 2 | Regex pre-mutation of SQL before parsing | `transpiler/translate.go:transpile_mysql_to_duckdb` | Reject | #6284 | Quoted identifiers/comments must not be altered by regex |
| 3 | Keep only first statement from multi-statement input | `transpiler/translate.go` (`trees[0]`) | Reject | #6284 | Multiple/trailing statements return unsupported before execution |
| 4 | Backtick identifier preservation and escaping | `transpiler/converter.go:NormalizeStrings` | Adapt | #6284 | `` SELECT `a``b` FROM t `` preserves identifier and case |
| 5 | MySQL `LIMIT offset, count` | `transpiler/translate.go` rewrite tests | Adapt | #6284 | `LIMIT 2, 3` selects rows 3-5 in MySQL order |
| 6 | Aggregate non-GROUP BY column wrapping | `transpiler/translate.go` (`normalize_mysql_aggregates`) | Adapt | #6284 | `SELECT pk, SUM(c) FROM t WHERE pk=0` matches MySQL with `ONLY_FULL_GROUP_BY` disabled |
| 7 | Function rewrite corpus | `transpiler/translate_test.go` | Adapt | #6284 | Each admitted function matches MySQL exact output and nullability |
| 8 | MySQL/DuckDB type mapping | `catalog/type_mapping.go:DuckdbDataType` | Adapt | #6282 D1/D2 | Unsigned BIGINT, DECIMAL scale, DATETIME precision boundaries |
| 9 | Charset encode/decode | `charset/charset.go:Encode`/`Decode` | Adapt | #6284/#6282 | `latin1`/`gbk` round trips and comparison bytes |
| 10 | Prepared metadata via NULL-parameter probe | `pgserver/duck_handler.go:ComPrepareParsed` | Adapt with caution | #6282 D1 | Metadata without executing full user query or side effects |
| 11 | Transaction-safe placeholder counting | `pgserver/duck_handler.go:ComPrepareParsed` | Adapt | #6282 D1 | Prepare inside transaction does not probe DuckDB on a second connection |
| 12 | Lease release at terminal result boundary | `adapter/adapter.go:LeasedRows` | Adapt | #6298 K2/K3 | Lease released exactly once on EOF or close |
| 13 | Security rejection before parsing | `backend/handler.go:ComQuery` | Adapt | #6284 Task 3 | Sensitive SQL rejected before ParserSQL admission |
| 14 | Custom `ps_current_thread_id` function | `myfunc/ps.go` | Defer | Future | Not in first milestones |
| 15 | PostgreSQL type OID mapping | `pgtypes/pgtypes.go:DuckdbTypeToPostgresOID` | Adapt | #6282 D3 | libpq binary/text parameter and result OIDs |
| 16 | Regex comment removal | `pgserver/stmt.go:RemoveComments` | Adapt cases only | #6284 | Nested comments and dollar quotes preserved by parser |
| 17 | go-mysql-server frontend | `backend/handler.go:MyHandler` | Reject | #6298 | ProxySQL owns protocol frontend |
| 18 | Vitess/cockroachdb parsers | `go.mod` | Reject | All | No alternate recognizer |

## 7. Core execution adapter versus frontend protocol versus SQL transformer

### 7.1 SQL transformer (#6284)

The transformer is a pure function over complete ParserSQL ASTs. It must not open
a DuckDB connection or execute the user query. Its job is:

- parse complete MySQL input;
- reject partial, trailing, multi-statement, or classification-only input;
- resolve only facts already available in the session context;
- emit DuckDB SQL with preserved labels and parameter identity;
- return stable reason codes for refusal.

MyDuck's translator does not meet this contract: it executes Python, mutates
text with regex, keeps only the first statement, and relies on SQLGlot's
MySQL parser. Those are reasons to reject it, while its test cases remain useful.

### 7.2 Frontend protocol (core #6298)

Core owns:

- MySQL and PostgreSQL protocol state machines;
- statement IDs, statement/portal names;
- parameter decoding, type reuse, long data;
- binary/text result encoding;
- resource limits and cleanup;
- session registry and policy.

MyDuck's `backend/handler.go` shows a Vitess/go-mysql-server frontend. That is
not reusable in ProxySQL because ProxySQL already authenticates and speaks both
protocols. The reusable part is the sequence of validation and lifecycle calls,
not the frontend implementation.

### 7.3 DuckDB native adapter (#6282)

The adapter implements core's versioned contract using native DuckDB APIs. It
owns only engine-native prepare, describe, bind, execute, fetch, reset, and
finalize. MyDuck's `pgserver/duck_handler.go` demonstrates useful probing
discipline, especially transaction-safe metadata inference, but ProxySQL must
use the DuckDB C API directly and must not use a separate Go driver connection.

### 7.4 Relevant MyDuck limitations

1. SQLGlot dependency and Python subprocess make deployment and security
   review heavier and are explicitly outside ProxySQL's allowed dependencies.
2. Regex pre-mutation is unsafe around quoted strings, comments, and nesting.
3. Keeping only the first parsed statement hides trailing statements.
4. Type mappings are acknowledged as non-lossless in MyDuck's own code.
5. Prepared result metadata for `SELECT` is obtained by executing with NULL
   parameters; ProxySQL must ensure analysis and metadata probing do not run
   user side effects or untrusted full queries.
6. MyDuck's MySQL frontend is a full server; ProxySQL is a proxy and already
   owns protocol behavior.
7. MyDuck's PostgreSQL path depends on cockroachdb parser and pgx, which
   ProxySQL does not use for recognition.

## 8. High-value differential and client regression cases

These cases must be independently verified against MySQL and DuckDB. They are
candidates for #6284 Task 4 and #6282 D2/D3.

1. Backtick identifiers: `` SELECT `a``b`, `Order` FROM t `` must preserve names
   and case according to MySQL identifier rules.
2. MySQL `LIMIT 2, 3` and `LIMIT 3 OFFSET 2` must select the same rows under
   the same `ORDER BY`.
3. Unsigned `BIGINT` values near `2^63` and `2^64-1` must not be narrowed or
   misreported in result metadata.
4. `DECIMAL` values with precision 38 and mixed scales must retain scale in
   both text and binary result paths.
5. `DATETIME`/`TIMESTAMP` with 0, 3, and 6 fractional digits must preserve
   precision and timezone policy.
6. `ONLY_FULL_GROUP_BY` disabled behavior: non-grouped selected columns in an
   aggregate query must follow MySQL's `ANY_VALUE`-equivalent semantics.
7. `JSON_LENGTH`, `JSON_ARRAYAGG`, and `JSON_MERGE_PATCH` must match MySQL
   JSON type and nullability.
8. String comparison and grouping under `utf8mb4` and `latin1` must preserve
   MySQL collation/padding expectations or be explicitly refused.
9. Prepared statements with NULL, empty string, empty binary, and NUL bytes
   must round-trip through MySQL and PostgreSQL clients.
10. Multiple statements and trailing input must be rejected before execution and
    must not partially execute.

## 9. License and attribution

MyDuck Server is Apache 2.0. Some files additionally reflect Dolthub copyright.
ProxySQL should not copy MyDuck code or test fixtures without preserving the
applicable license and notice. This audit recommends idea and case reuse only.
If a future task copies any source or fixture text, it must record the source
path, pinned commit, and license in the receiving file and review attribution
before merge.

## 10. Inspected sources

Primary files inspected:

- `transpiler/translate.go`
- `transpiler/converter.go`
- `transpiler/translate_test.go`
- `transpiler/converter_test.go`
- `catalog/type_mapping.go`
- `charset/charset.go`
- `backend/handler.go`
- `adapter/adapter.go`
- `adapter/adapter_test.go`
- `pgserver/duck_handler.go`
- `pgserver/stmt.go`
- `pgtypes/pgtypes.go`
- `myfunc/ps.go`
- `myfunc/registry.go`
- `compatibility/mysql/go/mysql.go`
- `go.mod`

Supporting context from ProxySQL worktree:

- `docs/superpowers/plans/2026-11-15-duckdb-mysql-query-compatibility.md`
- `docs/superpowers/plans/2026-11-15-duckdb-prepared-adapter.md`
- `docs/superpowers/plans/2026-11-15-shared-prepared-framework.md`
- `docs/superpowers/specs/2026-11-15-duckdb-mysql-query-compatibility-design.md`
- `doc/duckdb/index.md`
- `deps/parsersql/README.md`

## 11. Checks performed

- Confirmed pinned commit hash in the read-only clone:
  `6e3427591fd8895df9585969e7256f958fb639bb`.
- Confirmed Apache 2.0 license and ApeCloud copyright.
- Confirmed SQLGlot/Vitess/cockroachdb-parser/go-mysql-server dependencies in
  `go.mod`.
- Read source symbols and test definitions; no MyDuck build or service was run.
- No production or test code was modified.
- After writing this file, run `git diff --check` and `git status --short`.

## 12. Unresolved questions

1. Which MySQL collations must be supported versus explicitly refused in the
   first #6284 matrix? The audit identifies the need but does not define the
   final supported set.
2. Whether ProxySQL should expose any performance-schema-like functions such as
   `ps_current_thread_id()`; deferred.
3. Resolved for the vendored DuckDB 2.0.0 API: `duckdb_prepared_statement_column_count`,
   `duckdb_prepared_statement_column_name`, `duckdb_prepared_statement_column_type`
   and `duckdb_prepared_statement_column_logical_type` expose result metadata
   without execution (`deps/duckdb/duckdb/src/include/duckdb.h:5901-5956`).
   The adapter must use these APIs and explicitly refuse unresolved metadata;
   it must not adopt MyDuck's execution-based metadata probes.
4. Whether MyDuck's `latin1` as Windows-1252 assumption matches ProxySQL's
   existing charset behavior.
5. Whether any copied fixture text will require license notice changes in
   ProxySQL's repository; to be resolved before any copy is made.
