# MySQL to DuckDB translator differential baseline

This is a standalone experiment against the actual pure translator, not a test of
ProxySQL routing or the production metadata provider. The probe passes each source
query to `duckdb_translate_mysql_select`; it executes only admitted SQL and uses
the translator's owned result for DuckDB. Its negative control copies the emitted
comma-LIMIT SQL and deliberately changes its offset, proving the row comparator
catches that error. Three unsupported or invalid queries are checked for refusal
and never sent to either database.

On 2026-11-16, MySQL `8.0.46-0ubuntu0.24.04.5` and DuckDB `v2.0.0` matched
all 11 candidate queries, with zero unexpected mismatches. The negative control
was detected. Cases cover escaped table and column names, duplicate aliases,
table alias and qualified references, `*` over signed and unsigned integers,
text, binary and NULL values, `COUNT(*)` and `COUNT(column)`, literal `001`
and NULL labels, ascending and descending NULL order, comma LIMIT, and a signed
integer predicate. The fixture contains signed BIGINT extremes, the unsigned
BIGINT maximum, UTF-8 and binary bytes `00 ff`.

The comparison checks exact result labels, NULL positions, value bytes, row order
and multiplicity, and coarse type categories: integer, decimal, date, datetime,
text, binary and SQL NULL. Unknown categories fail. It does not compare integer
width or signedness, decimal precision/scale, MySQL flags/collations, or proxy
wire metadata. Text is compared as bytes for these fixtures; embedded NUL text
is not covered. The match says nothing about untested inputs or the broader
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
