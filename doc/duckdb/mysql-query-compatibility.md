# MySQL analytical SELECT compatibility contract (ParserSQL 1.1.1)

Status: Task 1 baseline contract and parser capability audit. This document
publishes what the vendored parser can prove, what it silently changes, and the
bounded subset proposed for later admission/translation. It does **not** claim
DuckDB semantic equivalence and does not authorize production translation.

- Worktree baseline: `663e84aa6f498cc18bc6a81e0d6c98c68b43504d`
  (merged v3.0; same commit as the design baseline).
- Vendored parser: ParserSQL `1.1.1` tarball plus `utf8-identifiers.patch`.
  Tarball SHA-256:
  `3c4f4916c38d89ad9ea584e6f6ba7caaf38d0daba8b3053cd088f98bb572fe38`.
- Capability target:
  `test/tap/tests/unit/duckdb_mysql_select_compat_unit-t.cpp`.
- Native DuckDB SQL remains the default endpoint mode. Nothing in this task
  executes a query, opens a DuckDB connection, probes metadata, or changes a
  production source file.

The roadmap plan mentions a review at `b5971e540`; this worktree does not use
that older branch state. The reviewed baseline above is the merged v3.0 commit
recorded by the design, consistent with current worktree history.

## 1. Contract vocabulary

| Term | Meaning in this document |
|---|---|
| Parser status | `ParseResult::OK`, `PARTIAL`, or `ERROR` as returned by ParserSQL. |
| Complete input | `full_input == true` and no remaining bytes; a single trailing semicolon is accepted. |
| Complete SELECT AST | Complete input, non-null AST, known `StmtType::SELECT`, and the expected root node. |
| Parser gate | The necessary parser-side checks in §2.3. It is not semantic admission. |
| Semantic admission | Task 2's typed/collation/session decision over the complete AST. |
| Candidate | Proposed for the first bounded subset, still subject to every Task 2 check. |
| Deferred | ParserSQL represents it, but this milestone deliberately does not admit it. |
| Refused | Must fail explicitly before execution under the current contract. |
| Parser gap | The vendored grammar cannot produce a trustworthy complete AST, or silently changes meaning. Fix upstream or refuse. |
| Out of scope | DML/DDL, non-SELECT statements, or endpoint/security-policy boundaries. |

A parser success is **not** semantic support. The audit found multiple inputs
where `status == OK`, `full_input == true`, and an AST exists, yet the emitted SQL
is wrong (`<=>` becomes `>`, `&&` becomes `&`, `BINARY 'a'` becomes an alias).
These are parser blockers, not merely missing admission rules. An operator
allowlist cannot distinguish a corrupted `<=>` AST from a legitimate `>` AST.
Fix these cases upstream and bump the vendored dependency before enabling
production translation; do not reconstruct recognition downstream.

## 2. Actual ParserSQL API behavior

### 2.1 Entry points

`Parser<Dialect::MySQL>` was exercised through the packaged headers:

- `parse(const char*, size_t) -> ParseResult`
  - Resets the arena.
  - Scans once for MySQL user variables before dispatch.
  - Accepts one statement; a single trailing semicolon is consumed.
  - Leaves later statements in `ParseResult::remaining`.
- `parse_all(const char*, size_t) -> BatchParseResult`
  - Frames every non-empty statement, sharing one arena until reset.
  - Skips empty and comment-only segments.
  - Includes a statement's terminating semicolon in `ParsedStatement::source`.
  - Returns an `ERROR` record for a malformed segment and makes
    `BatchParseResult::ok()` false.
  - An empty input is a successful empty batch.
- `ParseResult` fields used here:
  - `status`, `stmt_type`, `ast`;
  - `remaining`, `full_input`, `has_user_variables`;
  - `error.offset`, `error.message`.
- `Emitter<Dialect::MySQL>(arena, EmitMode::NORMAL, bindings)`
  - Renders the AST from the same arena.
  - Normalises whitespace, keyword case, implicit `AS`, and MySQL
    `LIMIT offset, count` to `LIMIT count OFFSET offset`.
  - Does **not** retain comments.
- AST traversal/transformation:
  - `walk_ast` (iterative pre-order, `AstVisitContext` with root depth zero,
    limits for nodes/depth).
  - `clone_ast` (owned deep copy, detects cycles/invalid references).
  - `replace_ast_subtree` (validated replacement preserving sibling position).
  - `make_owned_node` (arena-owned value/source text).
- MySQL user-variable API:
  - `ParseResult::has_user_variables`;
  - `classify_mysql_user_variable_usage(result)`
    (`NO_USER_VARIABLE`, `READ_ONLY`, `UNSAFE_OR_UNKNOWN`).

### 2.2 Observed framing traps

| Input | Parser result | Admission consequence |
|---|---|---|
| `SELECT 1` | OK, SELECT, complete, single root | eligible for parser gate |
| `SELECT 1;` | OK, SELECT, complete | eligible; trailing semicolon consumed |
| `SELECT 1; SELECT 2` | OK, SELECT, `full_input=false`, `remaining="SELECT 2"` | refused |
| `SELECT 1 SELECT 2` | OK, SELECT, `full_input=false` | refused |
| `SELECT 1;;` | OK, SELECT, `full_input=false`, `remaining=";"` | refused |
| `SELECT 1 garbage` | OK, complete, AST alias `garbage` | valid implicit alias, not trailing garbage |
| `;` | OK, `UNKNOWN`, complete, no AST | refused by the AST/statement-type check |
| comment-only | ERROR, no AST | refused |
| unterminated block comment | ERROR, no AST | refused |
| `SELECT /*!40101 1 */` | ERROR, partial AST | parser gap |
| `SELECT 1 /*! + 1 */` | OK, complete, emits `SELECT 1` | parser blocker: MySQL returns `2` |
| `TABLE t` | OK, `SELECT`, complete, root is not `NODE_SELECT_STMT` | refused by strict root check |
| `SELECT COUNT(DISTINCT a) FROM t` | OK, `full_input=false`, AST present, emits `SELECT ` | refused; parser gap |

Therefore the single-statement admission gate is:

```cpp
result.status == ParseResult::OK &&
result.full_input &&
!result.has_remaining() &&
result.ast != nullptr &&
result.stmt_type == StmtType::SELECT &&
result.ast->type == NodeType::NODE_SELECT_STMT
```

For `parse_all`, also require `statements.size() == 1` and the same per-statement
checks. A CTE or compound query has a different root and needs its own
root-aware gate in a later task; it must not be accepted by widening this one
implicitly.

### 2.3 Facts the parser does not establish

The parser does not know and must not guess:

- `ANSI_QUOTES`: the MySQL parser always reads `"text"` as a string literal.
- `NO_BACKSLASH_ESCAPES`: string escape interpretation depends on SQL mode.
- `PIPES_AS_CONCAT`: `||` is parsed but its MySQL meaning is session-dependent.
- `ONLY_FULL_GROUP_BY`: parser accepts non-grouped projections regardless.
- Column types, precision/scale, nullability, signedness, charset/collation.
- Table/column existence, name resolution, or duplicate-name validity.
- Session time zone, `lc_time_names`, date formatting, collation coercibility.
- Function existence, argument types, return types, determinism or side effects.
- Prepared parameter values/types (placeholders are syntax only).
- System-variable identity: `@@version` becomes an ordinary `NODE_COLUMN_REF`
  with value `@@version`, and `has_user_variables` stays false.

Any missing fact is an explicit unknown in Task 2, never an inferred MySQL rule.

## 3. Capability matrix

The matrix separates the parser result from the proposed semantic disposition.
"Emission" is ParserSQL's own normalised text, not DuckDB SQL. Candidate rows
still require the Task 2 type/collation/session checks listed in the last column.

### 3.1 Framing, comments, and aliases

| Construct | Parser result | AST/emission evidence | Disposition | Required facts/restrictions |
|---|---|---|---|---|
| Single SELECT, optional trailing `;` | OK, complete, SELECT root | byte-stable emission | Candidate | Only one statement; no trailing bytes. |
| Multiple/trailing statements | OK/partial with `remaining` | second statement present in `remaining` | Refused | `full_input` must be true and remaining empty. |
| Implicit alias | OK, complete | `SELECT 1 garbage` emits `SELECT 1 AS garbage` | Candidate | Alias must come from the AST, not text splitting. |
| `--`, `#`, `/* */` comments | Consumed, complete | emitter drops all comments | Candidate | Comments are framing only; emitted SQL is not text-preserving. |
| Comment-only / unterminated comment | ERROR | no AST | Refused | No statement. |
| Versioned `/*!...*/` / MariaDB `/*M!...*/` comments | Can be silently discarded with OK/complete AST | `SELECT 1 /*! + 1 */` emits `SELECT 1` | Parser blocked | Upstream provenance is required to refuse them reliably; see §4. |
| Duplicate output labels | OK, complete | `SELECT a AS x, b AS x` preserved | Candidate | Task 2 must verify MySQL label/metadata behavior. |
| Duplicate columns | OK, complete | `SELECT a, a` preserved | Candidate | AST order and multiplicity preserved. |
| Quoted alias | OK, complete | `` SELECT 1 AS `x``y` `` preserved | Candidate | Identifier decoding/collation rules still apply. |

### 3.2 Identifiers and quoting

| Construct | Parser result | AST/emission evidence | Disposition | Required facts/restrictions |
|---|---|---|---|---|
| Backtick identifier | OK, complete | `NODE_COLUMN_REF`/`NODE_IDENTIFIER`, `FLAG_IDENT_DELIMITED` | Candidate | `lower_case_table_names`, schema, and relation metadata. |
| Doubled backtick | OK, complete | value `a``b`, source `` `a``b` `` preserved | Candidate | Must preserve exact identifier identity. |
| Qualified `` `db`.`t` `` | OK, complete | both parts delimited | Candidate | Selected schema and catalog resolver must confirm the relation. |
| Quoted reserved word | OK, complete | `` `select` `` preserved | Candidate | Treat as identifier, not keyword. |
| `"text"` | OK as string literal | `NODE_LITERAL_STRING`, no identifier | Deferred | Only if `ANSI_QUOTES` is known off; if on or unknown, refuse. |
| Catalog/table alias | OK, complete | implicit `AS` added by emitter | Candidate | Duplicate alias rules and reference resolution. |

### 3.3 LIMIT

| Construct | Parser result | AST/emission evidence | Disposition | Required facts/restrictions |
|---|---|---|---|---|
| `LIMIT count` | OK, complete | one bound child | Candidate | Non-negative integer literal; no expressions. |
| `LIMIT count OFFSET offset` | OK, complete | two bound children | Candidate | Non-negative integer literals. |
| `LIMIT offset, count` | OK, complete | `FLAG_LIMIT_COMMA`; children are count then offset | Candidate | Emit as `LIMIT count OFFSET offset`, preserving row selection. |
| `LIMIT ?, ?` | OK, complete | two `NODE_PLACEHOLDER` children | Refused | Text COM_QUERY has no bound values; prepared path is later. |
| `LIMIT 1, 2, 3` | OK but partial | `remaining=", 3"` | Parser gap | Refused until grammar rejects or represents it completely. |
| `LIMIT 1.5` | ERROR | no AST | Refused | Integer-only rule. |
| `LIMIT 18446744073709551615` | OK, complete | literal preserved | Deferred | Bound/type mapping into DuckDB must be established. |

Deterministic row selection requires an explicit `ORDER BY`. Without it, LIMIT
selects an engine-dependent subset and must not be offered as equivalence.

### 3.4 Projections and typed SELECT

| Construct | Parser result | AST/emission evidence | Disposition | Required facts/restrictions |
|---|---|---|---|---|
| Plain columns, `*`, literals | OK, complete | column/literal nodes | Candidate | Relation metadata and exact types. |
| Integer/decimal/float literals | OK, complete | literal source preserved | Candidate | Literal type/scale/range rules; no implicit narrowing. |
| `CAST(... AS type)` | OK, complete | `NODE_TYPE_CAST` plus type name | Deferred | Exact MySQL-to-DuckDB type mapping and overflow/rounding rules. |
| `0x..`, `X'..'`, `b'..'` | OK, complete | literal source preserved | Deferred | Binary/bit type mapping and result metadata. |
| `_utf8mb4'abc'` | OK, complete | introducer preserved | Deferred | Charset conversion and result bytes. |
| `COLLATE ...` | OK, complete | collation name preserved | Deferred | Collation support and coercibility; refuse if unknown. |
| `DATE '...'`, `TIME '...'`, `TIMESTAMP '...'` | OK but silently misparsed as alias | emits `SELECT DATE AS '...'` | Parser gap | Refused; see §4. |
| `N'...'` | OK but silently misparsed as alias | emits `SELECT N AS '...'` | Parser gap | Refused; see §4. |
| Unary `BINARY expr` | OK but silently misparsed as alias | emits `SELECT BINARY AS '...'` | Parser gap | Refused; see §4. |

String projection may be safe while string comparison/grouping is not. A
candidate projection does not authorize comparison, ordering, grouping, or
coercion on that value unless collation/type rules are established.

### 3.5 Predicates and operators

| Construct | Parser result | AST/emission evidence | Disposition | Required facts/restrictions |
|---|---|---|---|---|
| `=`, `<>`, `!=`, `<`, `<=`, `>`, `>=` | OK, complete | operator preserved | Candidate | Same-type or explicitly defined comparison; no implicit string/number coercion. |
| `IS NULL`, `IS NOT NULL` | OK, complete | predicate nodes | Candidate | Nullability metadata. |
| `BETWEEN`, `IN (list)`, `NOT IN` | OK, complete | list nodes | Candidate | Type/collation rules for each comparison. |
| `LIKE` | OK, complete | preserved | Deferred | Escape/collation/padding rules; `ESCAPE` is a parser gap. |
| `AND`, `OR`, `NOT` | OK, complete | preserved | Candidate | Three-valued logic and type rules. |
| `XOR` | OK, complete | preserved | Deferred | Explicit MySQL boolean semantics required. |
| `DIV`, `MOD`, `%` | OK, complete | preserved | Deferred | Integer division/remainder rules and operand types. |
| `<=>` | OK but silently becomes `>` | emits `a > b` | Parser gap | Refused; null-safe equality is corrupted. |
| `&&` | OK but silently becomes `&` | emits `a & b` | Parser gap | Refused; logical AND becomes bitwise AND. |
| `||` | OK, complete | preserved | Refused | MySQL meaning depends on `PIPES_AS_CONCAT`; DuckDB differs. |
| `REGEXP` / `RLIKE` | Partial when mixed | `remaining` after first expression | Parser gap | Refused. |
| `SOUNDS LIKE`, `MEMBER OF` | OK, complete | preserved | Deferred | Not in the first subset. |
| Row-value `(a,b) IN ((...))` | OK, complete | tuple nodes | Deferred | Type/row comparison rules. |
| `= ANY (subquery)` | Partial | `remaining` starts at subquery | Parser gap | Refused. |
| `= ALL (subquery)` | OK, complete | subquery node | Deferred | Subqueries deferred; ALL branch still needs semantic rules. |
| `IS UNKNOWN` | Partial | `remaining="UNKNOWN"` | Parser gap | Refused. |
| `LIKE ... ESCAPE` | Partial | `remaining` starts at `ESCAPE` | Parser gap | Refused. |
| `NULLS FIRST/LAST` | Partial | trailing text | Refused | Not MySQL grammar in the supported baseline. |

### 3.6 Joins

| Construct | Parser result | AST/emission evidence | Disposition | Required facts/restrictions |
|---|---|---|---|---|
| `INNER JOIN ... ON` | OK, complete | `NODE_JOIN_CLAUSE` | Candidate | Equality join over admitted typed columns; relation metadata. |
| `LEFT [OUTER] JOIN ... ON` | OK, complete | join clause preserved | Candidate | Nullability/type rules and deterministic ordering. |
| `CROSS JOIN`, comma join | OK, complete | preserved | Candidate | Cardinality rules; no implicit predicate. |
| `JOIN ... USING (col)` | OK, complete | preserved | Candidate | Resolved column identity and duplicate-column result rules. |
| Multiple joins | OK, complete | nested join clauses | Candidate | Every branch must pass admission. |
| `NATURAL JOIN` | OK, complete | preserved | Deferred | Implicit column sets require metadata and duplicate rules. |
| `STRAIGHT_JOIN` after FROM | Partial | `remaining` starts at `STRAIGHT_JOIN` | Parser gap | Refused. |
| `FULL OUTER JOIN` | OK, complete | preserved | Refused | Not MySQL grammar; parser acceptance is not support. |

### 3.7 Grouping, ordering, aggregates, and functions

| Construct | Parser result | AST/emission evidence | Disposition | Required facts/restrictions |
|---|---|---|---|---|
| `GROUP BY` | OK, complete | group-by node | Candidate | Grouping keys must be admitted expressions; string grouping needs collation. |
| `HAVING` | OK, complete | having node | Candidate | Aggregate and type rules. |
| `ORDER BY col [ASC|DESC]` | OK, complete | order items | Candidate | Determinism, null ordering, collation/type rules. |
| `WITH ROLLUP` | OK, complete | group-by value `WITH ROLLUP` | Deferred | DuckDB rollup/summary semantics and null labeling need rules. |
| `COUNT(*)` | OK, complete | function call | Candidate | Multiplicity semantics. |
| `COUNT(expr)`, `SUM`, `AVG`, `MIN`, `MAX` | OK, complete | function calls | Candidate | Exact numeric types; overflow/scale/date rules; no implicit coercion. |
| `COUNT(DISTINCT ...)`, `SUM(DISTINCT ...)`, `AVG(DISTINCT ...)` | OK but partial | `full_input=false`, emits `SELECT ` | Parser gap | Refused until upstream fix; see §4. |
| `GROUP_CONCAT(...)` | OK, complete | preserved | Deferred | Separator/order/result limits and collation. |
| `DATE_FORMAT(d, '%Y-%m')` | OK, complete | preserved | Deferred | First dialect-specific candidate after date/time and format-token rules. |
| `COALESCE`, `IFNULL`, `NULLIF` | OK, complete | preserved | Deferred | Return-type and coercion rules. |
| `IF`, `CASE` | OK, complete | preserved | Deferred | Branch type unification. |
| `CURRENT_DATE`, `CURRENT_TIMESTAMP`, `NOW()` | OK, complete | preserved | Deferred | Session time zone and statement-time semantics. |
| Unknown function | OK, complete | function call preserved | Refused | Explicit function allowlist required; spelling is not proof. |
| `NEXTVAL`, `SETVAL`, other side-effecting functions | OK, complete | function calls preserved | Refused | Never execute during analysis; deny side-effect/unknown functions before execution. |

Aggregate admission must also define `ONLY_FULL_GROUP_BY` behavior. The parser
accepts non-grouped projections regardless of session mode; that is not a
semantic admission.

### 3.8 CTEs, subqueries, windows, and compounds

| Construct | Parser result | AST/emission evidence | Disposition | Required facts/restrictions |
|---|---|---|---|---|
| Simple CTE | OK, complete | root `NODE_CTE`, `NODE_CTE_DEFINITION` | Deferred | Root-aware gate; every CTE body and the outer query must pass admission. |
| Recursive CTE | OK, complete | `FLAG_CTE_RECURSIVE`, compound body | Deferred | Termination/type consistency and recursive semantics. |
| CTE column list | OK, complete | `NODE_CTE_COLUMNS` | Deferred | Arity/name resolution. |
| Derived table | OK, complete | `NODE_SUBQUERY` in FROM | Deferred | Alias/column metadata and nested admission. |
| `IN (subquery)` | OK, complete | subquery node | Deferred | Nested admission, null semantics, type comparison. |
| Scalar subquery | OK, complete | subquery node | Deferred | Cardinality and type rules. |
| Correlated `EXISTS` | OK, complete | subquery node | Deferred | Correlation resolution. |
| Window function | OK, complete | `NODE_WINDOW_FUNCTION` | Deferred | Partition/order determinism, frame, null ordering, result type. |
| Named `WINDOW` clause | OK, complete | `NODE_WINDOW_CLAUSE` | Deferred | Name resolution and frame validation. |
| `UNION [ALL|DISTINCT]` | OK, complete | root `NODE_COMPOUND_QUERY` | Deferred | Root-aware gate, column count/type unification, duplicate semantics. |

The first analytical subset should not include any of these until the
corresponding root-aware and nested-admission rules exist.

### 3.9 User variables, placeholders, and system variables

| Construct | Parser result | AST/emission evidence | Disposition | Required facts/restrictions |
|---|---|---|---|---|
| `@a` read | OK, complete | `has_user_variables=true`, `NODE_USER_VARIABLE` | Refused | User-variable state belongs to the session; not admitted for analytical execution. |
| `@a` in arithmetic | OK, complete | user variable node | Refused | Same. |
| Quoted user variable | OK, complete | decoded identity, source retained | Refused | Same. |
| `@a := 1` | Partial | `remaining="1"` | Parser gap / Refused | Assignment syntax is not completely represented. |
| `?` placeholder | OK, complete | `NODE_PLACEHOLDER` | Refused | COM_QUERY text path has no values; prepared path is a separate task. |
| `@@version` | OK, complete | `NODE_COLUMN_REF` value `@@version` | Refused | Parser does not flag it as a system variable; explicit identity policy required. |

### 3.10 Non-SELECT and endpoint boundaries

| Construct | Parser result | AST/emission evidence | Disposition | Required facts/restrictions |
|---|---|---|---|---|
| `INSERT` / `UPDATE` / `DELETE` | OK, complete, non-SELECT stmt | non-SELECT AST root | Out of scope | Must not enter the analytical SELECT path. |
| `TABLE t` | OK, classified SELECT, non-SELECT root | root is not `NODE_SELECT_STMT` | Out of scope | Strict root gate refuses it. |
| `SELECT ... FOR UPDATE/SHARE` | OK, complete | `NODE_LOCKING_CLAUSE` | Refused | Locking is outside the read-only analytical contract. |
| `SELECT ... INTO OUTFILE` | Partial | `remaining` starts at `INTO` | Refused | No file side effects. |
| `SELECT 1 INTO @x` | Partial | `remaining="INTO @x"` | Parser gap / Refused | User-variable assignment. |
| Index/partition hints | OK, complete | table-ref text preserved | Refused | DuckDB has no equivalent; do not silently drop. |
| `SQL_CALC_FOUND_ROWS` | OK, complete | select-option text preserved | Refused | Requires MySQL connection state, not translation. |

## 4. ParserSQL limitations and upstream reproducers

These are actual ParserSQL 1.1.1 behaviors observed with the packaged headers
and `libsqlparser.a`. No upstream issue was filed by this task. When filing,
use the upstream repository `https://github.com/ProxySQL/ParserSQL` at tag
`v1.1.1` and add a regression test beside the existing MySQL parser tests
(`tests/test_select.cpp`, `tests/test_mysql_grammar.cpp`,
`tests/test_mysql_query_expressions.cpp` as appropriate).

| # | Reproducer SQL | Observed ParserSQL 1.1.1 behavior | Why admission must not rely on it |
|---|---|---|---|
| 1 | `SELECT COUNT(DISTINCT a) FROM t` | `OK`, `full_input=false`, `remaining="DISTINCT a) FROM t"`, AST non-null, emits `SELECT ` | Status/AST presence alone would produce broken SQL. |
| 2 | `SELECT SUM(DISTINCT a) FROM t` | Same partial shape as #1 | Aggregate DISTINCT is unusable. |
| 3 | `SELECT AVG(DISTINCT a) FROM t` | Same partial shape as #1 | Aggregate DISTINCT is unusable. |
| 4 | `SELECT a <=> b FROM t` | `OK`, complete, emits `SELECT a > b FROM t` | Silent semantic corruption of null-safe equality. |
| 5 | `SELECT a && b FROM t` | `OK`, complete, emits `SELECT a & b FROM t` | Logical AND silently becomes bitwise AND. |
| 6 | `SELECT BINARY 'a'` | `OK`, complete, emits `SELECT BINARY AS 'a'` | Unary operator silently becomes an alias. |
| 7 | `SELECT DATE '2024-01-01'` | `OK`, complete, emits `SELECT DATE AS '2024-01-01'` | Standard date literal silently becomes an alias. |
| 8 | `SELECT TIME '10:00:00'` | `OK`, complete, emits `SELECT TIME AS '10:00:00'` | Same class as #7. |
| 9 | `SELECT TIMESTAMP '2024-01-01 10:00:00'` | `OK`, complete, emits alias | Same class as #7. |
| 10 | `SELECT N'abc'` | `OK`, complete, emits `SELECT N AS 'abc'` | National string literal silently becomes an alias. |
| 11 | `SELECT a REGEXP 'x', a RLIKE 'x' FROM t` | `OK`, `full_input=false`, `remaining="'x' FROM t"` | Mixed regexp forms are partial. |
| 12 | `SELECT * FROM t WHERE a LIKE '%x%' ESCAPE '!'` | `OK`, `full_input=false`, `remaining="ESCAPE '!'"` | Valid MySQL ESCAPE clause is dropped. |
| 13 | `SELECT * FROM t WHERE a IS UNKNOWN` | `OK`, `full_input=false`, `remaining="UNKNOWN"` | Valid MySQL truth test is partial. |
| 14 | `SELECT * FROM t WHERE a = ANY (SELECT a FROM u)` | `OK`, `full_input=false`, `remaining="SELECT a FROM u)"` | `ALL` works but `ANY` does not. |
| 15 | `SELECT 1 /*! + 1 */` | `OK`, complete, emits `SELECT 1`; independently tested MySQL 8.0.46 returns `2` | Executable contents disappear; no reliable provenance flag in this version. `SELECT /*!40101 1 */` happens to fail because no expression remains. |
| 16 | `SELECT HIGH_PRIORITY a FROM t` | `OK`, complete, emits `SELECT HIGH_PRIORITY AS a FROM t` | Select option silently becomes a column and alias. |
| 17 | `SELECT SQL_NO_CACHE a FROM t` | `OK`, complete, emits `SELECT SQL_NO_CACHE AS a FROM t` | Same class as #16. |
| 18 | `SELECT * FROM t1 STRAIGHT_JOIN t2 ON t1.id = t2.id` | `OK`, `full_input=false`, `remaining="STRAIGHT_JOIN ..."` | MySQL join keyword is not framed. |
| 19 | `SELECT @a := 1` | `OK`, `full_input=false`, `remaining="1"` | User-variable assignment is partial. |
| 20 | `SELECT 1 INTO @x` | `OK`, `full_input=false`, `remaining="INTO @x"` | INTO user variable is partial. |
| 21 | `SELECT * FROM t LIMIT 1, 2, 3` | `OK`, `full_input=false`, `remaining=", 3"` | Extra LIMIT value is not rejected by the parser. |
| 22 | `TABLE t` | `OK`, complete, `StmtType::SELECT`, root is not `NODE_SELECT_STMT` | Statement type alone is insufficient. |
| 23 | `;` | `OK`, complete, `StmtType::UNKNOWN`, no AST | Status/complete input alone is insufficient. |
| 24 | `SELECT 1;;` | `OK`, `full_input=false`, `remaining=";"` | A second semicolon is not silently accepted. |

Minimum C++ reproducer shape:

```cpp
sql_parser::Parser<sql_parser::Dialect::MySQL> parser;
const char* sql = "SELECT COUNT(DISTINCT a) FROM t";
auto result = parser.parse(sql, std::strlen(sql));
// Expect OK/PARTIAL/ERROR plus full_input, remaining, AST root and emission
// to be recorded explicitly. Do not assert only status.
```

## 5. Required context and where it can come from

No fact below may be discovered by executing the user query. Task 2 should
consume already-known session/catalog state; unknown remains unknown and causes
an explicit refusal.

| Fact | Needed by | Source without running the query |
|---|---|---|
| Selected schema/database | identifier resolution | session `COM_INIT_DB`/default database state |
| Relation existence and column names | projections, joins, aliases | catalog/relation metadata resolver |
| Column type, signedness, precision/scale | arithmetic, casts, aggregates, metadata | catalog metadata, not query execution |
| Nullability | joins, predicates, ORDER BY, aggregates | catalog metadata |
| Charset and collation per column/expression | string comparison/grouping/order | catalog + session collation state |
| `sql_mode` (`ANSI_QUOTES`, `NO_BACKSLASH_ESCAPES`, `PIPES_AS_CONCAT`, `ONLY_FULL_GROUP_BY`, strict modes) | quoting, escapes, `||`, grouping | effective session settings |
| `lower_case_table_names` and identifier case rules | table/column resolution | server/session configuration |
| `time_zone`, `lc_time_names`, date/time precision | date/time functions and casts | effective session settings |
| Function existence/arity/return type/determinism | function admission | maintained allowlist/function metadata |
| Collation coercibility | comparisons and function results | explicit rules supplied by Task 2 |
| Prepared parameter count/types | placeholder queries | protocol/prepared-statement layer (not this task) |
| User-variable values | `@var` | session variable state; not admitted for the analytical subset |
| System-variable identity | `@@var` | explicit session policy; parser does not distinguish it |
| DuckDB target type availability | emission and result metadata | DuckDB capability catalog, read-only |
| Endpoint mode/security policy | whether analytical path is active | Admin-managed configuration; native default |

## 6. Proposed bounded initial admission subset

This is a proposal for Task 2, not implementation. It deliberately excludes
anything the audit cannot prove end-to-end. The first subset is:

1. Exactly one MySQL `SELECT` statement with a `NODE_SELECT_STMT` root, complete
   input, no remaining text, and no second statement.
2. Projection of plain columns, `*`, integer/decimal literals, and simple
   parentheses over those values, with aliases preserved from the AST.
3. One relation or `INNER`/`LEFT`/`CROSS` joins with `ON`/`USING` over admitted
   same-family typed columns; no implicit string/number coercion.
4. `WHERE`/`HAVING` using `=`, `<>`, `!=`, `<`, `<=`, `>`, `>=`, `AND`, `OR`,
   `NOT`, `IS NULL`, `IS NOT NULL`, `BETWEEN`, `IN (literal list)` only when all
   operand types are admitted and string comparison collation is known.
5. `GROUP BY` and explicit `ORDER BY` over admitted expressions. LIMIT is
   admitted only with integer literals and, for claimed row equivalence, an
   explicit deterministic `ORDER BY`.
6. `COUNT(*)`, `COUNT(expr)`, `SUM`, `AVG`, `MIN`, `MAX` over exact admitted
   types. `DISTINCT` inside aggregates is excluded by the parser gap.
7. Backtick identifiers, including doubled backticks, with all quoting and
   case rules resolved from session/catalog state.
8. No CTE, compound query, subquery, window function, `COLLATE`, `BINARY`,
   versioned comment, index/partition hint, user variable, system variable,
   placeholder, locking clause, `INTO`, or unknown/side-effecting function.

The identifier and LIMIT slices have useful AST coverage, but enabling even
these slices waits for the upstream silent-corruption/provenance fixes and a
reviewed dependency update. String
projection may be permitted while string comparison/grouping/ordering remains
refused until collation/padding rules exist.

## 7. Verification commands and results

The assigned worktree does not contain an extracted ParserSQL source tree
(`deps/parsersql/parsersql` is a symlink to an absent `parsersql-1.1.1`), so the
standalone compile used the read-only merged-worktree headers and archive. The
vendored tarball SHA-256 is identical in both worktrees. No Makefile was
modified.

`test/tap/tap/tap.cpp` exists in the assigned worktree. `tap_noise_stubs.cpp` is
not a source file in this tree; the unit Makefile generates it inline. The
standalone run used an equivalent temporary stub outside the repository.

```bash
cat > /tmp/opencode/tap_noise_stubs.cpp <<'EOF'
#include <vector>
#include <string>
#include <mutex>
std::vector<std::string> noise_failures;
std::mutex noise_failure_mutex;
extern "C" { void stop_noise_tools(){} int get_noise_tools_count(){return 0;} }
EOF

cd /home/rene/.codex/worktrees/1382/duckdb-mysql-replica
g++ -std=c++17 -O0 -g \
  -I/home/rene/.codex/worktrees/1382/duckdb-mysql-replica/test/tap/tap \
  -I/mnt/data/rene/proxysql3/worktrees/duckdb-mysql-replica/deps/parsersql/parsersql/include \
  test/tap/tests/unit/duckdb_mysql_select_compat_unit-t.cpp \
  test/tap/tap/tap.cpp /tmp/opencode/tap_noise_stubs.cpp \
  /mnt/data/rene/proxysql3/worktrees/duckdb-mysql-replica/deps/parsersql/parsersql/libsqlparser.a \
  -lpthread -o /tmp/opencode/duckdb_mysql_select_compat_unit-t

/tmp/opencode/duckdb_mysql_select_compat_unit-t > /tmp/opencode/test.out
grep -c '^ok'     /tmp/opencode/test.out
grep -c '^not ok' /tmp/opencode/test.out
tail -1 /tmp/opencode/test.out
```

Recorded result:

- compile exit: `0` (only the existing `tap.cpp` `CLOCKS_PER_SEC` warning);
- `^ok`: `818` (worker run before two root review fixtures);
- `^not ok`: `0`;
- plan line: `1..818` (worker run);
- runtime: under one second.

Repository hygiene commands:

```bash
git -C /home/rene/.codex/worktrees/1382/duckdb-mysql-replica diff --check
git -C /home/rene/.codex/worktrees/1382/duckdb-mysql-replica status --short
```

## 8. Unresolved risks and follow-up requirements

1. **Silent parser corruption blocks production admission.** `<=>`, `&&` and
   executable comments can return complete ASTs for different semantics.
   Operator allowlists alone cannot detect this; fix and test ParserSQL upstream,
   then update the vendored release. Upstream work is in progress in a separate
   clone; no parser workaround or dependency modification has been introduced here.
2. **Aggregate DISTINCT is blocked** by ParserSQL 1.1.1 until the partial-AST
   gap is fixed upstream. Do not emulate it with text rewriting.
3. **SQL mode is invisible to the parser.** `ANSI_QUOTES`,
   `NO_BACKSLASH_ESCAPES`, and `PIPES_AS_CONCAT` must be known session facts or
   the affected queries must be refused.
4. **System variables are indistinguishable from columns** in the AST
   (`@@version` as `NODE_COLUMN_REF`). Admission needs an explicit identifier
   policy in addition to `has_user_variables`.
5. **Root shapes differ.** CTE and compound queries do not have a
   `NODE_SELECT_STMT` root; a future root-aware gate must still enforce nested
   admission and single-statement framing.
6. **Comments are not preserved** by the emitter. Anything that requires
   byte-for-byte preservation of comments must not use this emission path.
7. **This audit does not prove MySQL/DuckDB result equivalence.** Type,
   collation, timezone, division, NULL-ordering and overflow rules remain
   Task 2/Task 4 obligations with independent MySQL and DuckDB oracles.
8. **No production translation is implemented or claimed.** The capability
   target is the authoritative executable record of what was observed; the
   matrix records the proposed admission boundary.

### Independent review additions

Codex added the two executable-comment reproductions above, connected this target
to the standard unit Makefile, and independently rebuilt/reran it. The baseline
records ParserSQL 1.1.1 behavior intentionally; update these expectations together
with an upstream dependency bump. This characterization target is not a production
SQL admission implementation. Independent root validation: `make -C test/tap/tests/unit PROXYSQL40=1
duckdb_mysql_select_compat_unit-t` rebuilt the target successfully; executing it
passed all 834 checks (zero failures). Further implementation results are recorded
in the implementation ledger.
