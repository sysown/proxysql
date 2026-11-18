# MySQL analytical SELECT compatibility contract

Status: the original Task 1 audit below records ParserSQL 1.1.1 behavior. The
current dependency also applies the local analytical AST patch; historical gap
rows are not current test expectations. The capability fixture has been updated
to the patched parser. The pure translator is enabled by the opt-in `mysql_analytical` listener mode;
see the current subset below and the configuration reference.

- Worktree baseline: `663e84aa6f498cc18bc6a81e0d6c98c68b43504d`
  (merged v3.0; same commit as the design baseline).
- Vendored parser: original ParserSQL `1.1.1` tarball plus
  `utf8-identifiers.patch` and `mysql-analytical-ast.patch`.
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
| `\|\|` | OK, complete | preserved | Refused | MySQL meaning depends on `PIPES_AS_CONCAT`; DuckDB differs. |
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
| `COUNT(expr)`, `SUM`, `MIN`, `MAX` | OK, complete | function calls | Admitted (bounded) | Exact integer/decimal columns only; see the SUM and AVG rules below. |
| `AVG` | OK, complete | function call | Admitted (bounded, exact rewrite) | Native DuckDB AVG is DOUBLE; the translator emits exact decimal arithmetic. See below. |
| `COUNT(DISTINCT ...)`, `SUM(DISTINCT ...)`, `AVG(DISTINCT ...)` | OK but partial | `full_input=false`, emits `SELECT ` | Parser gap | Refused until upstream fix; see §4. |
| `GROUP_CONCAT(...)` | OK, complete | preserved | Deferred | Separator/order/result limits and collation. |
| `DATE_FORMAT(d, '%Y-%m')` | OK, complete | preserved | Admitted (bounded) | SELECT-list only; first argument is a resolved DATE column, or a DATETIME column the replica recorded as a MySQL DATETIME (see below) and the format is the exact single-quoted literal `'%Y-%m'`. See the current slice and its stated value-domain limit below. |
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
an explicit refusal when the operation requires that fact. These are required
inputs, not guarantees that current providers expose every fact; the metadata
prerequisite below records their actual availability.

| Fact | Needed by | Source without running the query |
|---|---|---|
| Selected schema/database | identifier resolution | Explicitly tracked native namespace; the current plugin COM_INIT_DB acknowledgement does not establish this fact. |
| Relation existence and column names | projections, joins, aliases | catalog/relation metadata resolver |
| Column type, signedness, precision/scale | arithmetic, casts, aggregates, metadata | Native catalog facts; original MySQL type provenance remains unknown unless independently established. |
| Nullability | joins, predicates, ORDER BY, aggregates | catalog metadata |
| Charset and collation per column/expression | string comparison/grouping/order | catalog + session collation state |
| `sql_mode` (`ANSI_QUOTES`, `NO_BACKSLASH_ESCAPES`, `PIPES_AS_CONCAT`, `ONLY_FULL_GROUP_BY`, strict modes) | quoting, escapes, `\|\|`, grouping | effective session settings |
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
6. `COUNT(*)`, `COUNT(expr)`, `SUM`, `MIN`, `MAX` over exact admitted
   types. `DISTINCT` inside aggregates is excluded by the parser gap.
7. Backtick identifiers, including doubled backticks, with all quoting and
   case rules resolved from session/catalog state.
8. No CTE, compound query, subquery, window function, `COLLATE`, `BINARY`,
   versioned comment, index/partition hint, user variable, system variable,
   placeholder, locking clause, `INTO`, or unknown/side-effecting function.

The identifier and LIMIT slices require the silent-corruption/provenance fixes
now carried in the reproducible local ParserSQL analytical patch. The user
authorized this local development workflow on 2026-11-16; upstream publication
is tracked for the final ParserSQL PR and is not an implementation gate. String
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

## 8. Current boundaries and ParserSQL change tracking

The original operator/provenance gaps are fixed by the vendored local patch;
production code does not compensate with a private lexer. The capability fixture
now passes 843 assertions. The patch also bounds recursive expression/query
parsing at 128 active entries; the current focused upstream suite passes 199
checks, including MySQL/PostgreSQL depth, reuse and configuration boundaries.
These bounds do not claim to cover every unrelated DDL grammar.

The analytical translator uses ParserSQL token framing and a complete SELECT AST.
Session-sensitive syntax, comments, variables and unsupported root shapes remain
refused. Aggregate DISTINCT remains a parser/semantic follow-up. The original
matrix above is historical evidence, and its candidate rows do not imply current
admission. Actual differential results cover only the fixture inputs described
in the linked baselines.

[ParserSQL PR #72](https://github.com/ProxySQL/ParserSQL/pull/72) tracks the upstream
provenance/operator work. The reproducible local patch starts at the original
1.1.1 release, applies after the UTF-8 patch, and includes the additional recursive
query/expression guard. All changes and regression tests are retained in
`deps/parsersql/mysql-analytical-ast.patch`; consolidate them into the final
ParserSQL PR at the end of this goal. Upstream publication is not a development
gate under the user's 2026-11-16 authorization.

## Native metadata prerequisite (2026-11-16)

The read-only `duckdb_mysql_select_metadata` component provides facts for the
translator through DuckDB's table-description C API. It executes no user
SQL, caches no metadata, and requires the caller's connection ownership guard.
It supplies native facts; admission, canonical name resolution and execution
protection remain separate responsibilities.

| Fact | Available evidence | Translation boundary |
| --- | --- | --- |
| Column names and logical types | Native catalog names/type IDs, decimal width and scale | Native facts do not establish original MySQL types or collations. |
| Catalog/schema/table identity | Requested identifiers; explicit versus default-connection catalog provenance | Request spelling is not a canonical resolved name. |
| Nullability and MySQL provenance | Explicitly unknown | Do not infer nullability, source type or collation from DuckDB storage types. |
| Client encoding | MySQL handshake and supported `SET NAMES`/`SET CHARACTER SET` tracking | A client encoding is not a column's source collation. |
| Effective MySQL modes and namespace | No general MySQL semantics established by plugin compatibility acknowledgements | Generic defaults, `SELECT DATABASE()` and `COM_INIT_DB` acknowledgements are insufficient provenance. |

Each lookup returns owned data with at most 4,096 columns and an 8 MiB logical
payload cap, further constrained by the caller's remaining budget. Native error
diagnostics also respect that budget and have a separate 4 KiB maximum. Invalid
requests, native lookup errors and exhausted budgets remain distinct; native
error messages are not parsed to guess whether a relation exists. Fixed container
overhead and native engine allocations are outside this logical payload budget.

The component's 26 TAP checks cover odd/Unicode identifiers, physical types,
unknown provenance, request spelling versus native column spelling, missing
relations, malformed names, budget/column limits, fresh metadata after DDL and
preservation of an existing client transaction. The canonical static build and
ASan/UBSan run pass with the DuckDB library itself uninstrumented.

## Current pure translator slice

`duckdb_translate_mysql_select` consumes only the locally patched ParserSQL AST.
It emits owned DuckDB SQL and stable refusal reasons without executing a query;
its caller supplies bounded relation facts. The implemented slice covers one
resolved table, aliases and qualified column references, typed projections,
nonnegative signed-range integer and NULL literals, nonnegative exact decimal
literals, signed-integer comparisons, exact decimal comparisons, NULL
predicates, AND/OR, COUNT and integer MIN/MAX, integer-key GROUP BY with
aggregate HAVING predicates, exact integer and DECIMAL SUM/AVG, numeric ordering
with explicit MySQL NULL placement, integer-literal LIMIT with a proven strictly
unique ordering key (the full group-key tuple establishes uniqueness for grouped
rows), and the `DATE_FORMAT(column, '%Y-%m')` projection described below.
Identifiers and duplicate labels are preserved.

Unknown types, ambiguous ORDER BY aliases, comments, session-sensitive quoting,
string literals/comparison/ordering, arithmetic, non-integer grouping, joins,
subqueries, CTEs, windows, variables and unknown functions are currently
refused. SUM/AVG above the proved decimal precision, SUM/AVG over non-numeric
columns, aggregate DISTINCT and SUM/AVG in HAVING remain refused. Later roadmap
slices remain outstanding; these refusals do not complete the goal.

### Source column facts

The context carries `DuckDBMySQLColumn::source` (original MySQL type kind: date,
datetime, timestamp or other; charset; collation). It is filled only from the
replica's `proxysql_replica.columns` record and only when that record is proven
to describe the live native column (see the Admin reference), and is otherwise
unknown. Operations that need it are admitted only for proven columns: today
DATE_FORMAT of a DATETIME column (below); unknown facts change no other behavior. It is what lets later slices tell a
DATETIME (no time zone) from a TIMESTAMP (rendered in the session time zone),
and know whether a text comparison is byte-exact.

### Built-in function spelling

MySQL resolves `COUNT (*)` only when `IGNORE_SPACE` is enabled, and a spaced
`MIN (column)` can resolve to a stored routine. The translator does not know the
session SQL mode, so it admits COUNT, MIN, MAX, SUM and AVG only when ParserSQL's
tokenizer, run over the call's AST source span, shows a bare name token
immediately followed by `(`. Spaced, tab-separated, quoted or qualified
spellings are refused in SELECT and HAVING. Mixed-case contiguous spellings are
admitted. ParserSQL normalises the function node's value to the upper-case name,
so `sum(...)` and `sUm(...)` take the same path.

### SUM and AVG

`SUM(column)` and `AVG(column)` are admitted in the SELECT list wherever
COUNT/MIN/MAX are admitted: as the only aggregate form without GROUP BY, or next
to the admitted integer grouping keys. The argument must be one resolved plain
column, optionally qualified by the admitted table alias or backtick-quoted.
DISTINCT, literals, placeholders, arithmetic or any other expression inside the
call, and text, binary, DATE, DATETIME and unknown columns are refused.
`SUM(DISTINCT ...)` and `AVG(DISTINCT ...)` do not even reach the translator as
complete statements: ParserSQL 1.1.1 reports a partial parse, so the stable
reason is `incomplete_or_non_select`.

The only admitted argument types are:

- mapped `signed_integer` (19 integer digits),
- mapped `unsigned_integer` (20 integer digits),
- mapped `exact_decimal` with a valid precision/scale and precision at most 19.

The precision-19 limit is an overflow proof, not a formatting preference.
A single DuckDB table cannot hold 2^63 rows (the physical row-count bound this
project relies on; DuckDB row identifiers are themselves signed 64-bit). A
`DECIMAL(p,s)` value is below `10^(p-s)` in magnitude, so
`|SUM| < 2^63 * 10^(p-s)` and the scaled integer `SUM * 10^s` is below
`2^63 * 10^p <= 9.23e18 * 1e19 < 10^38`. DuckDB's `SUM(DECIMAL)` is
`DECIMAL(38,s)` and errors on overflow; for `p <= 19` no admitted input can
reach that width. `DECIMAL(20..38,s)` and the native `DECIMAL(39,0)` mapping are
refused before execution. MySQL itself would widen the result to
`DECIMAL(p+22,s)` (capped at 65) and could continue, which is exactly the
difference this rule avoids.

`SUM` is emitted natively:

- integer columns: `SUM("col")`; DuckDB returns HUGEINT.
- decimal columns: `SUM("col")`; DuckDB returns DECIMAL(38,s).

HUGEINT cannot overflow under the same row bound: the largest unsigned sum is
below `2^63 * (2^64 - 1) = 2^127 - 2^63`, which is below the signed HUGEINT
maximum `2^127 - 1`; signed sums are smaller.

Value text matches MySQL byte-for-byte in both cases: MySQL's integer SUM is a
plain integer DECIMAL(...,0), and MySQL's decimal SUM keeps exactly `s`
fractional digits, as does DuckDB's `DECIMAL(38,s)`. Metadata does not match:
the plugin maps HUGEINT to `NEWDECIMAL` length 40 (precision 39, scale 0) while
MySQL reports length 42 for signed and 43 for unsigned BIGINT SUM; a decimal
SUM is reported with precision 38 while MySQL reports `p+22`. The decimal type
category, scale and value text agree. The mapped relation type carries no
integer width, so TINYINT, SMALLINT and INT columns are treated as the full
signed or unsigned 64-bit width; MySQL reports a narrower SUM metadata length
for those source types, but the value text is unchanged because every value
fits.

Native DuckDB `AVG` is DOUBLE and loses exact-value precision, so it is never
emitted. `AVG(column)` is rewritten to exact integer arithmetic over the same
aggregates. With `p` and `s` from the mapped column and target scale `r = s + 4`
(MySQL's default `div_precision_increment`):

```text
K = SUM(column) * 10^s          (DECIMAL text with the point removed, cast to HUGEINT;
                                 this equals the stored integer and avoids a decimal
                                 multiplication that could overflow DECIMAL(38,s))
C = COUNT(column)
A = K // C                      (truncating integer division)
R = K % C
Q = A * 10^4 + round_half_away(R * 10^4 / C)
result = Q * 10^-r              (DECIMAL multiply, then cast to DECIMAL(p+4, r))
```

The half-away-from-zero step is integer arithmetic: for negative `R` the
magnitude is `(abs(R) * 20000 + C) // (2 * C)` and the sign is restored; `//`
truncates toward zero in DuckDB. Every integer intermediate fits HUGEINT:
`K < 10^38`, `abs(R) < 2^63`, `abs(R) * 20000 < 2e23`, and `abs(Q) < 10^23`
because an average never exceeds the largest column value. Recovering `K` from
DuckDB's decimal text is exact: a `DECIMAL(38,s)` value always renders exactly
`s` fraction digits (including trailing zeros and a missing leading zero for
fraction-only values), so removing the point and parsing the remaining sign and
digits yields the stored integer. A decimal multiplication by `10^s` would
instead require a raw product of up to `K * 10^s`, which can exceed the
128-bit DECIMAL(38) intermediate even when the value fits, so it is not used.
`Q * 10^-r` is an exact decimal multiplication by a fraction-only
`DECIMAL(r+1,r)` whose stored integer is 1, so no rounding is introduced. The
final cast is exact because the value needs at most `p-s` integer and exactly
`r` fractional digits.

The result is `DECIMAL(p+4, s+4)`, matching MySQL's AVG precision and scale for
BIGINT, BIGINT UNSIGNED and decimal columns. The mapped integer kind has no
width, so TINYINT, SMALLINT and INT columns use the 19- or 20-digit width and
report a wider AVG precision than MySQL; the value text is unchanged. One
exception for the decimal case: when `p == s` (a fraction-only
column), DuckDB's text conversion of a `DECIMAL(r+4,r+4)` value omits the
leading zero (`.003333` instead of MySQL's `0.003333`). Such an AVG is emitted
as `DECIMAL(r+1, r)`, one precision digit wider than MySQL; the value text is
identical. This mirrors the existing fraction-only column projection rule.

`div_precision_increment` is assumed to be MySQL's default 4. The analytical
endpoint's SET interceptor only accepts `SET NAMES`, `SET CHARACTER SET` and
`SET autocommit`; a `SET div_precision_increment` is not acknowledged or applied
by any session code and reaches DuckDB as an unknown setting, so the emitted
scale cannot be changed through the supported client path. The translator still
does not read the variable and does not claim support for a server whose
default differs.

NULL propagation is the native aggregate one on both engines: empty input and a
group whose admitted column is all NULL produce NULL SUM and AVG; COUNT of the
same values is 0, and the emitted AVG arithmetic then stays NULL rather than
dividing by zero. No `CASE` guard is needed because DuckDB's integer `//` and
`%` on a NULL numerator return NULL before the zero count is evaluated.

SUM and AVG are deliberately refused in HAVING. The comparison and `IS [NOT]
NULL` shapes that admit COUNT/MIN/MAX refuse them with the stable reason
`unsupported_having_aggregate`; other HAVING shapes keep their existing
`unsupported_ast` refusal. COUNT, MIN and MAX keep their existing HAVING
behavior.

Because AVG emits a derived `DECIMAL(p+4, s+4)`, a source column precision or
scale change changes the emitted result type. Prepared statements re-translate
on every execute and refresh the native handle; if an old handle were reused
with different metadata the native check fails and MySQL error 1615 is
surfaced. See
[protocol compatibility](protocol-compatibility.md#prepared-queries).

### DATE_FORMAT year-month projection

`DATE_FORMAT(column, '%Y-%m')` is the first admitted dialect-specific function,
and only as a SELECT-list projection. The function name must be immediately
followed by `(` with the same contiguous spelling rule as COUNT/MIN/MAX, so
spaced names require an unknown `IGNORE_SPACE` mode and are refused; quoted
names are refused as well. Mixed case is admitted.

The first argument must be a resolved plain column (optionally qualified by the
admitted table alias) whose mapped context type kind is `date`, or `datetime`
with proven source type DATETIME. Text, binary, integer and decimal columns,
literals and expressions are refused. The replica stores both MySQL DATETIME and
MySQL TIMESTAMP in a native `TIMESTAMP`, and MySQL renders a TIMESTAMP in the
session time zone, which the translator does not know, so a month near a boundary
could differ (shown against the oracle in the baseline). A native `datetime`
column is therefore admitted only when its recorded source type is DATETIME. A
recorded TIMESTAMP is refused with `session_time_zone_dependent`; a column with no
proven source (native tables, replicas snapshotted before provenance existed,
altered columns) is refused with `session_time_zone_unknown` and the
required-context hint `source_column_type_provenance`.
The second argument must be one single-quoted string literal whose exact source
bytes are `'%Y-%m'`; escaped, prefixed, charset-introduced, double-quoted
(identifier under a possible `ANSI_QUOTES`) and concatenated formats are
refused, as are other arities and placeholders in either argument. The function
is refused in WHERE, HAVING, GROUP BY and ORDER BY, and when combined with an
aggregate or GROUP BY in this slice.

The projection is emitted as `strftime(column, '%Y-%m')`. DuckDB's numeric
`strftime` directives are locale-independent, return `VARCHAR`, ignore
fractional seconds and do not convert timezone-naive values, so the result maps
to MySQL text metadata. Without an alias the result label is the exact original
source text of the expression, including mixed case and spaces inside the
argument list; with an alias it is the alias. The existing 255-byte implicit
function-label limit applies: longer labels are refused rather than truncated.

The admitted value domain is MySQL's DATE range, `1000-01-01` through
`9999-12-31`. Zero and invalid dates cannot be stored as a DuckDB DATE, so they
cannot appear in an admitted projection. Real calendar dates below 1000 format
identically on both engines (`0001-01`, `0099-12`), but they are not MySQL DATE
column values in strict mode; negative years, years above 9999 and any value
outside MySQL's range are outside the admitted domain. The translator is pure
and cannot inspect stored values, so this range is a precondition on the mapped
data, not a per-row check. NULL input returns NULL.

### Exact decimals

Decimal literals must be plain digit/dot tokens (no exponent, no sign) with at
most 38 digits and scale 30. They are emitted as a cast from the validated token
text, so no approximate intermediate value is used. A comparison involving a
decimal operand casts both sides to a common `DECIMAL(p,s)`, where `s` is the
larger scale and `p` is the larger integer-digit capacity plus `s`. Signed
integer columns count as 19 integer digits and unsigned as 20. Comparisons
needing precision above 38 are refused. So are decimal comparisons with text,
floating point, NULL literals or native 128-bit integers (`DECIMAL(39,0)`
mappings). Decimal parameters, arithmetic, decimal MIN/MAX and grouping are
also refused; SUM and AVG follow the separate precision rule above.

DuckDB renders a fraction-only `DECIMAL(p,p)` value as `.50`, while MySQL renders
`0.50`. Projections of such columns, including expanded `*`, are emitted as
`CAST(column AS DECIMAL(p+1,p))` under the original label. Value and scale are
unchanged, but **the reported precision is one larger than the column's**.
`*` is expanded only when such a column is present. Expansion uses ordered
native metadata and is refused if two names fold to the same identifier.

Because these casts depend on current column metadata, prepared statements
regenerate them at every execution. See
[protocol compatibility](protocol-compatibility.md#prepared-queries).
Native catalog facts describe the MySQL-facing mapping of native objects, not
original replication-source metadata. Text projection does not establish a
collation suitable for comparison. See the [actual translator differential
baseline](mysql-translation-baseline.md) for tested results and its limits.
