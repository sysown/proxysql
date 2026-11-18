# MySQL to DuckDB translator differential baseline

This is a standalone experiment against the actual pure translator, not a test of
ProxySQL routing or the production metadata provider. The probe passes each source
query to `duckdb_translate_mysql_select`; it executes only admitted SQL and uses
the translator's owned result for DuckDB. Its negative control copies the emitted
comma-LIMIT SQL and deliberately changes its offset, proving the row comparator
catches that error. The original fifty-eight unsupported or invalid queries plus
twenty-seven join-specific refusal checks are checked for refusal and never sent
to either database.

On 2026-11-18, MySQL `8.0.46-0ubuntu0.24.04.5` and DuckDB `v2.0.0` matched
all 171 candidate queries, with zero unexpected mismatches. The negative control
was detected. The original 129 cases cover escaped table and column names, duplicate aliases,
table alias and qualified references, `*` over signed and unsigned integers,
text, binary and NULL values, `COUNT(*)` and `COUNT(column)`, literal `001`
and NULL labels, ascending and descending NULL order, comma LIMIT, and a signed
integer predicate. Additional cases cover integer-key GROUP BY, COUNT/MIN/MAX, HAVING, nullable
and multi-key groups, grouped LIMIT, unsigned extrema and empty grouped/aggregate
results, metadata label boundaries, exact decimals, and binary text comparison
and ordering. The decimal cases cover
literal labels such as `001.2300`, `.50` and `1.`, scale 30 and 38-digit
boundaries, decimal comparisons with signed and unsigned integer extremes,
mixed scales, NULL filtering, fraction-only projection through a column,
aliases, duplicates and `*`, and native HUGEINT/UHUGEINT projection. The
fixture contains signed BIGINT extremes, the unsigned BIGINT maximum, UTF-8
and binary bytes `00 ff`.

Fourteen of the 129 cases exercise `DATE_FORMAT(column, '%Y-%m')` over a DATE
column and a DATETIME(6) column the resolver declares as a recorded DATETIME: plain and aliased projections, mixed-case and spaced
spellings, qualified and backtick references, a backtick source label, mixed
and duplicate-alias projections, comma LIMIT, NULL positions, an empty result
and the 255-byte implicit label boundary. The fixture rows use `1000-01-01`,
the leap day `2024-02-29` at midnight, `2024-03-01 23:59:59.999999`,
`9999-12-31 23:59:59.999999` and NULL, so they stay inside MySQL's
DATE/DATETIME range. A real MySQL `TIMESTAMP` column (`ts`) is declared as a
recorded TIMESTAMP and only appears in the two refusal checks
(`session_time_zone_dependent`); a separate check shows why: with
`time_zone='+05:00'` MySQL formats the boundary row `2024-02-29 23:00:00 UTC` as
`2024-03` while the emitted `strftime` on the naive value gives `2024-02`, and the
probe passes only if they differ. A separate direct expression check compares
`DATE_FORMAT('0001-01-01','%Y-%m')` and
`DATE_FORMAT('0099-12-31 23:59:59','%Y-%m')` with the emitted `strftime`
expression and passes, so years below 1000 have no known difference; they are
still outside the admitted column domain because MySQL DATE cannot store them
in strict mode. Zero dates cannot be stored in DuckDB at all.

Forty of the 129 cases exercise text comparison and ordering. The `text_probe`
fixture stores `t` and `u` as `VARCHAR` with `utf8mb4_0900_bin`, `ai` with
`utf8mb4_0900_ai_ci` and `pad` with `utf8mb4_bin`. Rows cover the empty string,
one space, `a` and `a ` (NO PAD must keep them distinct), leading space,
embedded tab and a raw `0x01`, `é`, `e` plus U+0301 combining acute, emoji
U+1F600, U+10000, `ab`/`abc` prefixes, `A` versus `a`, `Z`, `_`, `1`, `it's`,
`a"b`, `ß`, `ss`, NULL, and a stored `a` NUL `b`. Byte values are inserted by
hex so the fixture does not depend on the client encoding. Cases cover every
admitted comparison operator with the literal on either side, column-to-column
comparisons, AND/OR/IS NULL combinations, projection, and ascending/descending
ordering with NULL placement, `LIMIT`, comma LIMIT and text predicates. The
embedded-NUL row participates in predicates and ordering but is not projected
as text, because the probe's C-API text conversion would escape it.
Every text query matched MySQL's rows, order, labels and coarse type category.

Three separate checks use direct MySQL and DuckDB queries on the same rows and
pass only when the results differ: `ai = 'A'` returns two MySQL rows and one
DuckDB row; `ORDER BY ai, id` over the non-NULL `ai` rows differs; and
`pad = 'a '` returns two MySQL rows (`a` and `a `) and one DuckDB row. These
prove why `utf8mb4_0900_ai_ci` and PAD SPACE `utf8mb4_bin` must stay refused.
`utf8mb4_0900_as_cs` is also non-binary UCA ordering and has no proven
equivalent, so it stays refused without a separate engine check.

The date cases project DATE_FORMAT's VARCHAR result, not a raw DATETIME(6)
column: DuckDB's C API text conversion omits trailing fractional zeros
(`2024-02-29 00:00:00`) while MySQL's text protocol always returns six
fractional digits for DATETIME(6). That pre-existing difference is outside the
translated value under test and is not compared here.

Forty-two of the 171 cases exercise joins. The `join_left`, `join_right` and
`join_third` fixtures form a three-table relation with NULL keys, duplicate join
keys that fan out, rows unmatched on both sides, an empty fourth table,
signed/unsigned and `DECIMAL(10,2)` keys, a proven `utf8mb4_0900_bin` text key,
and a self join. Cases cover INNER and LEFT [OUTER] JOIN with projection, WHERE
on either side, ON literal filters, AND/OR/IS NULL predicates, `ON 1=1`, a
WHERE filter on the nullable side, three-table chains, self join with distinct
aliases, `*` and `alias.*`, duplicate labels (`id, id`), column-name case
(`l.ID` labelled `ID`), ascending/descending text ordering, deterministic LIMIT
when every relation's key is ordered (other limits are refused), grouping by
left and right keys, multi-key groups, HAVING, and joined COUNT/MIN/MAX/SUM/AVG including
decimal and unsigned arguments and an empty LEFT side. MySQL and DuckDB matched
on labels, NULL positions, value bytes, row multiplicity and deterministic order.
Twenty-six join refusal checks cover USING, NATURAL (including NATURAL LEFT), comma,
CROSS, RIGHT, FULL, derived table, scalar subquery, ambiguous column, unknown
column, unknown/hidden alias, duplicate alias, the same table twice, four
relations, text/number key, unknown-provenance text key, date key,
nondeterministic LIMIT (missing the left or right key), STRAIGHT_JOIN, a
parenthesized join group, a three-part column, an unknown `z.*` alias and a join
without ON. A multi-relation placeholder is refused
as well. A separate check proves the text/number refusal is necessary: MySQL
compares `text_probe.t = 1` as DOUBLE and returns the stored text row, while
DuckDB rejects the typed comparison.

Three of the original 129 cases exercise database-qualified names against a
second database (`other_db.other_probe` projection, predicate and `COUNT(*)`):
MySQL resolves a qualified name in its own database regardless of the selected
one. The probe's
refusal checks add an unqualified relation with no database selected
(`no_database_selected`), a reserved schema (`reserved_database`) and a
three-part name, all without an engine call. The selected-database behavior itself
(`USE`, `COM_INIT_DB`, prepared statements, reset) was checked against the oracle
and is covered by the live client rather than by this translator probe.

Twenty-five of the 129 cases exercise SUM and AVG. The `sumavg_probe` fixture has
signed BIGINT and unsigned BIGINT extremes, `DECIMAL(19,2)`, `DECIMAL(18,4)`,
`DECIMAL(20,2)` and `DECIMAL(19,0)` columns, fraction-only `DECIMAL(2,2)` in
`sumavg_probe`, and fraction-only `DECIMAL(19,19)` in `scale_probe`, nullable
values, an all-NULL row, an all-NULL group, an empty result, multi-key
groups and two 32-row groups whose single nonzero value makes AVG land exactly
on a rounding tie at scales 4, 6 and 8. Both the positive and negative tie are
covered. Cases include unaliased and aliased labels, mixed case, backtick and
qualified arguments, grouped and ungrouped queries, ORDER BY/LIMIT, duplicate
aggregate aliases, single rows at the signed/unsigned/decimal extrema, and
empty or all-NULL inputs. SUM integer and decimal values, AVG values for every
admitted scale, NULL positions, row order/multiplicity and labels match. The
26 new refusal checks cover DISTINCT, text and DATE arguments, literals,
arithmetic arguments, spaced/quoted names, placeholders, `DECIMAL(38,30)`,
`DECIMAL(20,2)`, the 39-digit HUGEINT mapping, HAVING aggregates, nested
aggregates, mixed projections and aggregates in WHERE/ORDER BY.

Three differences were found and handled by the emission rather than admitted
natively: DuckDB's native AVG is DOUBLE (so it is never used), DuckDB renders a
fraction-only decimal without a leading zero (so a fraction-only AVG is emitted
one precision digit wider), and DuckDB's DECIMAL multiply can overflow its
128-bit intermediate for very large scaled sums while MySQL widens its result
(so AVG recovers the exact stored integer from DuckDB's exact decimal text
instead of multiplying by a power of ten). A fourth difference, decimal SUM
overflow above precision 19, is avoided by refusing those columns before
execution. Result metadata precision is not compared by this probe and does
differ for SUM and for fraction-only AVG; see the compatibility contract.

The comparison checks exact result labels, NULL positions, value bytes without
decimal normalization, row order and multiplicity, and coarse type categories:
integer, decimal, date, datetime, text, binary and SQL NULL. Native HUGEINT and
UHUGEINT count as decimal, matching the plugin's `DECIMAL(39,0)` mapping.
Unknown categories fail. It does not compare integer width or signedness,
decimal precision/scale, MySQL flags/collations, or proxy wire metadata.

The separate `tools/probes/duckdb_mysql_parameter_differential.cpp` probe
compares natively bound signed-integer predicate parameters (NULL, INT64
extremes, narrow-column comparisons and distinct positions) against MySQL
server-side prepared statements. It was built with the same command, using that
source file instead, and passed all seven cases on 2026-11-18. Text is compared
as bytes for these fixtures; the parameter probe does not cover embedded NUL
text. The match says nothing about untested inputs or the broader
analytical subset. The SQL mode, connection collation and time zone are fixed by
the probe; MySQL/engine version changes require a fresh run.

The resolver is deliberately fixture-specific. It derives names, known source
and target types and the strictly unique non-NULL `id` key from the schema this
probe itself creates. It does not infer MySQL source facts from a native DuckDB
catalog. The native metadata/context provider is not exercised here. Inputs whose
SQL mode or collation would affect meaning remain outside this evidence. The
parser recursion guard must be included and separately validated before any
production admission path uses the translator.

The probe requires an explicit absolute socket path to an owned private MySQL
server. It connects as root without a password, creates only a PID-named database,
and drops that database on normal exit and caught errors. A killed process or
cleanup failure can leave the printed database behind. DuckDB runs in memory.
Do not use a shared or production server.

From the repository root with its locally patched vendored ParserSQL built,
the build and run are:

```sh
ROOT=/mnt/data/rene/proxysql3/worktrees/duckdb-mysql-replica
MDB="$ROOT/deps/mariadb-client-library/mariadb-connector-c-3.3.8-src"
SSL="$ROOT/deps/libssl/openssl-3.5.9"
g++ -std=c++17 -Wall -Wextra -Werror \
  -Iplugins/duckdb/include -I"$ROOT/deps/parsersql/parsersql/include" \
  -I"$MDB/include" -I"$ROOT/deps/duckdb/duckdb/src/include" \
  tools/probes/duckdb_mysql_translation_differential.cpp \
  plugins/duckdb/src/duckdb_mysql_select_compat.cpp \
  "$ROOT/deps/parsersql/parsersql/libsqlparser.a" \
  -L"$ROOT/deps/duckdb/duckdb/build/release/src" \
  -Wl,-rpath,"$ROOT/deps/duckdb/duckdb/build/release/src" \
  -lduckdb "$MDB/libmariadb/libmariadbclient.a" \
  "$SSL/libssl.a" "$SSL/libcrypto.a" -lz -ldl -lpthread \
  -o /tmp/duckdb-query-implementation/translation-probe
/tmp/duckdb-query-implementation/translation-probe \
  /tmp/duckdb-query-implementation/mysql-oracle.sock
```
