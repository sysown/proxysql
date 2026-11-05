# DuckDB MySQL SELECT compatibility — first pass

Date: 2026-11-05
Base: `748306f2b`
Status: implemented and validated for the documented core

## Intent and scope

The user selected a documented core of analytical SELECT syntax rather than
an application-specific workload. Regular ProxySQL hostgroups can point to
the same instance's DuckDB MySQL listener; internal routing and automatic
fallback are deferred indefinitely.

Implement compatibility at the DuckDB MySQL listener, after existing driver
intercepts and before execution. Preserve the existing DuckDB engine, result
path and PostgreSQL listener. Applier hardening remains a separate workstream.

## Approach

A token-aware, bounded translator handles known MySQL differences and leaves
ordinary analytical SQL to DuckDB's parser. This avoids rewriting literals,
comments or quoted identifiers as SQL. A full MySQL AST/parser is deferred;
regular-expression substitution cannot safely distinguish these contexts.
The implementation uses the repository's C++17 toolchain and DuckDB 1.4.5.

Implementation decisions: add startup-only `duckdb-mysql_compatibility=false`;
when enabled, connection sessions use the compatibility translator for SELECT
and WITH ... SELECT only. Existing native SQL remains the default. DDL and
other statement classes retain their existing path. No fallback is introduced.

## Supported core

- Projections and aliases; WHERE predicates; INNER/LEFT joins; GROUP BY,
  HAVING; ORDER BY; LIMIT/OFFSET; derived tables and SELECT CTEs.
- Backtick identifiers (including doubled backticks), MySQL single/double
  quoted strings and default-mode backslash escapes except embedded NUL.
- Null-safe equality `<=>` with explicit grouping when combined with another
  comparison; ambiguous comparison chains are rejected, including CASE operands.
- Boolean `&&` and `||`, MySQL LIKE/NOT LIKE default backslash escapes, adjacent
  string literals, and `LIMIT offset,count` with nonnegative integer literals.
- SIGNED/UNSIGNED integer casts with 64-bit reinterpretation, for inputs in
  [-2^63,2^64-1]. Inputs are evaluated once, including aggregate expressions;
  out-of-range inputs fail instead of emulating MySQL's warning/clamping rules.
- Projected BOOLEAN values render as 1/0; VARCHAR 'true' and SQL NULL keep
  their values. Result metadata now uses native MySQL scalar types; see the typed-results design.
- Existing DuckDB equivalents: COUNT, SUM, MIN, MAX, AVG, CASE, IF, IFNULL,
  COALESCE, ROUND, ABS, YEAR, MONTH and DAY.
- Two-argument DATEDIFF uses date-only values and MySQL argument order.
- DATE_FORMAT with a literal format and documented calendar/time directives;
  week/year-week directives are rejected until independently implemented.
- ORDER BY defaults to MySQL's NULL-first ASC and NULL-last DESC, emitted in
  SQL rather than changing engine-global settings.

## Limits and rejection

The first pass targets valid values and binary/case-sensitive comparisons.
It does not emulate MySQL collations, implicit coercion/warnings, invalid or
zero dates, SQL modes, stored functions, user variables, executable comments,
locking reads, GROUP_CONCAT syntax, timezone conversion, or prepared statements.
Known unsupported forms receive a clear compatibility error before execution.
A later parser/binder error also returns through the existing MySQL error path.
Do not claim full MySQL semantic compatibility for arbitrary expressions.

Use a nesting limit, reject multiple statements, preserve identifier/literal
contents, and execute a translated query once. Configuration is per listener
lifecycle; changing it requires reopening the plugin. PostgreSQL remains native.

## Acceptance

Compare hand-chosen expected values and MySQL 8.4 results against DuckDB through
both the direct listener and a regular ProxySQL backend hostgroup targeting
that listener. Cover nested scopes, mixed case, comments, string escapes,
NULLs, decimal aggregates, joins, dates, pagination and unsupported forms.
Run the existing DuckDB units, Admin and listener tests, and replica regression.
Document the six independently reproduced PostgreSQL baseline failures.

## Enabling the mode

The setting is startup-only and defaults to false. Stage and persist it through
Admin, then restart the instance:

```sql
UPDATE global_variables SET variable_value='true'
WHERE variable_name='duckdb-mysql_compatibility';
SAVE DUCKDB VARIABLES TO DISK;
PROXYSQL RESTART;
```

A LOAD while the listener is open rejects a changed value and leaves Runtime
unchanged. PostgreSQL sessions always use native DuckDB SQL. Existing MySQL
sessions with compatibility disabled retain native quoting and boolean output.

Supported DATE_FORMAT directives: `%Y %y %m %c %d %e %H %k %h %I %l %i %s %S
%f %p %a %W %b %M %j %w %r %T %%`. The format must be a literal. Week numbering,
locale/timezone changes and invalid-date warning behavior are excluded.

## Verification (2026-11-05)

- Translator execution/negative suite: 53 passing TAP assertions.
- All eight DuckDB unit binaries: 349 passing assertions, including native
  boolean behavior and opt-in numeric boolean output.
- MySQL 8.4.8 differential TAP: 39 passing assertions through the direct
  DuckDB listener and a standard query rule targeting 127.0.0.1:6031.
- Existing replica regression: 24 passing assertions with compatibility
  disabled; existing Admin/MySQL listener suites remain covered.
- Fixture isolation was checked with pre-existing hostgroup/rule/user rows;
  setup refused the collision and preserved all three. A file-backed-engine
  run passed and left no fixture schemas.
- Independent review findings around comparison precedence, LIKE escapes,
  integer casts and fixture cleanup were reproduced and corrected.

MySQL result metadata now exposes native scalar types; use explicit column aliases for rewritten
expressions, since their default labels may reflect translated DuckDB SQL.
The six PostgreSQL extended-query rejection failures remain the independently
reproduced baseline failures, outside this change.
