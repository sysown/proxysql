# DuckDB Protocol Compatibility

The plugin uses MySQL and PostgreSQL frontend protocols as transports for
DuckDB SQL. It is not a MySQL or PostgreSQL server implementation, and it does
not attempt complete dialect or wire-feature compatibility.

## Support matrix

| Capability | MySQL endpoint | PostgreSQL endpoint |
|---|---|---|
| Authentication | `mysql_users` | `pgsql_users` |
| Simple text query | Supported | Supported |
| Client prepared statements | Native SQL reads and writes, plus opt-in analytical SELECT translation | Native SQL reads and writes |
| Extended-query protocol | N/A | Supported for the prepared subset |
| Multiple statements in one request | Rejected | Rejected |
| Transaction status | Protocol OK/status behavior | `ReadyForQuery` I/T/E |
| Result metadata | Typed numeric, binary and core temporal columns | Typed numeric, boolean and BYTEA columns |

## Prepared queries

Both listeners support native prepared reads and writes through the shared
ABI 17 execution service with `PROXYSQL40=1`. The same database access mode
and session configuration rules apply to prepared and ordinary native SQL. With startup-only
`duckdb-mysql_dialect=mysql_analytical`, the MySQL listener translates the
[bounded analytical subset](mysql-query-compatibility.md) for text and
prepared queries. Analytical placeholders are admitted only as WHERE comparison
operands against signed integer columns of at most 64 bits. They are emitted
as `CAST(? AS BIGINT)` against `CAST(column AS BIGINT)`, and bound natively.
Only NULL and signed 64-bit values may be bound to them. Other kinds return
1235/`0A000`, and a parameter count mismatch is an invalid-parameter error.
Placeholders in projections, HAVING, GROUP BY, ORDER BY, LIMIT, against
decimal, unsigned or text columns, or on both sides of one comparison are
refused at prepare. Text COM_QUERY never admits placeholders. The native mode
retains its documented typed-parameter support.

Before every analytical prepared execution, the original SQL is re-admitted
against current metadata inside the same private read-only transaction. The
freshly translated SQL is prepared as a new native statement, so casts that
depend on column precision or scale never come from an earlier schema. If the
new statement's parameter or result names, types, precision or scale, or its
parameter positions or column count, differ from the existing statement
(nullability is not compared, since the native adapter does not report it),
execution fails with 1615
(reprepare) before any row is produced. Otherwise the new native handle replaces
the old one. A widened or rescaled column referenced only in a predicate
therefore keeps working without client action. A projected column whose scale
changes requires reprepare. This costs one native prepare per analytical
execution, and the translated SQL is retained only for that one operation.

Analytical preparation also records the session's MySQL database and the
resolved canonical `catalog.schema.table` identity. Re-admission at execute uses
the recorded database, not the client's current one, because MySQL keeps a
prepared statement in the database it was prepared in. A changed relation
identity is treated exactly like changed metadata: 1615 before execution. The
connection's own DuckDB schema therefore cannot redirect a prepared statement,
and `USE` never invalidates or retargets a live handle.

Native prepared DML can run in autocommit or within a client transaction.
Plain DML returns the affected-row count. DML with `RETURNING` sends rows,
and autocommit writes are committed after result materialization succeeds.
The translated analytical subset requires an idle autocommit session. Cursor
operations, cancellation, and some temporal and nested value mappings remain
unsupported. MySQL clients must negotiate UTF-8 or issue a separate
`SET NAMES utf8`, `utf8mb3`, or `utf8mb4`. PostgreSQL requires UTF8.

Output metadata must be known at native preparation. Expressions such as
`SELECT ? + 0` and `SELECT length(?)` can be refused when DuckDB cannot resolve
their output types; selecting typed table columns with parameters in predicates
works. PostgreSQL can use `CAST($1 AS BIGINT)` with an explicit parameter OID.
Typed table results support boolean, decimal and blob, with signed and unsigned
integers, floating point, text and NULL within the supported mappings. Native
HUGEINT/UHUGEINT and integer SUM results use exact DECIMAL/NUMERIC(39,0), including
typed predicate binding and checked overflow.

Translated analytical operations run in a private read-only transaction.
Engine external access remains disabled by default across both dialect modes.

## One statement per request

Every request is prepared before execution. DuckDB rejects preparation of
multiple statements in one request. This is intentional: a previous direct
execution path could execute all statements but expose only the last result,
making earlier side effects invisible to the client.

Send each statement separately:

```sql
-- First request
CREATE TABLE t(i INTEGER);

-- Second request
INSERT INTO t VALUES (1);
```

A comment-only request also fails because there is no statement to prepare.

## Compatibility queries

The following common discovery commands are intercepted or rewritten:

- `SELECT @@version`
- `SELECT VERSION()`
- `SELECT DATABASE()`
- `SELECT CURRENT_DATABASE()`
- `SHOW TABLES`
- `SHOW DATABASES`
- `SHOW SCHEMAS`
- `SET autocommit=1` when autocommit is already enabled
- a single `SET NAMES ...` command

Matching is case-insensitive and tolerates normal whitespace and a trailing
statement terminator. Longer identifiers and packets with a second statement
are not accepted by prefix alone.

In the analytical MySQL dialect, `SELECT DATABASE()` returns the selected MySQL
database (SQL `NULL` before one is selected) and `SHOW TABLES` lists the
selected database. Native connections keep the previous behavior:
`DATABASE()` returns the engine path (`memory` for in-memory databases) and
`SHOW TABLES` lists DuckDB's `main` schema.

`SHOW DATABASES` returns DuckDB catalogs. `SHOW SCHEMAS` reads schema metadata.
Other statements, including DuckDB-native `SET` commands, go to DuckDB.

## Database namespace (analytical MySQL)

Both DuckDB listeners use the dedicated `PROXYSQL_SESSION_DUCKDB` core session
type. They authenticate using frontend credentials and dispatch to DuckDB's
handler. Monitoring credentials are scoped to the legacy listeners.
Authentication audit events use the `DuckDB_*` prefix for MySQL and
`PGSQL_DuckDB_*` for PostgreSQL.

With `duckdb-mysql_dialect=mysql_analytical`, MySQL database names select
schemas of the replica's single DuckDB catalog. See
[the compatibility contract](mysql-query-compatibility.md#database-namespace-mysql_analytical)
for the exact admitted spellings, error codes and limits. Operationally:

- `USE db` (COM_QUERY) is validated against `information_schema.schemata` with
  an exact name match, then selected with a session-scoped `SET schema` bound as
  a value. Unknown or reserved schemas fail with 1049 / `42000` and leave the
  selection unchanged.
- After validating the credentials, the listener selects an explicitly requested
  handshake database before sending success. An unknown or reserved database
  returns 1049 / `42000`.
- Relative names resolve in the selected database; qualified `database.table`
  names resolve in their own database; three-part names are refused as a MySQL
  syntax error.
- Prepared statements retain the database they were prepared in and re-resolve
  their canonical relation identity at every execute.
- `COM_RESET_CONNECTION` keeps the current database name and re-selects it on
  the replacement native connection.

For `COM_INIT_DB`, core calls the registered DuckDB namespace selector before
updating the session database or sending success. An unknown or reserved name
returns 1049 / `42000` and preserves the current database. ProxySQL's ordinary
frontend still acknowledges its own database switch immediately. It sends
`COM_INIT_DB` to the DuckDB backend when it needs the connection for the next
statement, so that statement reports any failure to select the database.

The plugin Makefile must define `PROXYSQLED25519` whenever the core does:
`mysql_connection.h` adds members to `MySQL_Connection` under that macro, and a plugin
compiled without it reads `userinfo` at a shifted offset (it saw a NULL pointer).

`SHOW DATABASES` still lists DuckDB catalogs rather than the replica's MySQL
databases; changing it is out of scope for this slice and is reported as an
observation, not a compatibility guarantee. Observed on a `:memory:` replica:
the single row `memory`. A file-backed replica reports the catalog name DuckDB
derives from the file, not the replicated MySQL database names (which are
schemas in that catalog).

## SQL dialect

Use DuckDB SQL. Syntax specific to MySQL or PostgreSQL can fail even though the
connection uses that product's wire protocol. Client libraries may also issue
session initialization SQL automatically; only the narrow compatibility list
above is guaranteed to be absorbed or translated.

Following [#6280](https://github.com/sysown/proxysql/issues/6280), new SQL
recognition must use the currently vendored ParserSQL. Missing grammar is
deferred upstream; a new lexer or syntax recognizer is not an alternative.
The branch's experimental custom SELECT translator and
`duckdb-mysql_compatibility` setting have been removed. Native DuckDB analytical
SELECTs remain available. Scoped dialect work belongs to
[#6284](https://github.com/sysown/proxysql/issues/6284); autocommit work in
[#6281](https://github.com/sysown/proxysql/issues/6281) waits for ParserSQL #68/#69.
Inherited discovery/configuration guards remain in place.

## Result metadata and conversion

The following table describes the simple text-query path. Numeric, boolean and
binary results carry native type metadata, but values use text transfer. Prepared
execution uses its protocol binary or negotiated formats and has a narrower type subset.

| DuckDB type | MySQL metadata | PostgreSQL metadata |
| --- | --- | --- |
| BOOLEAN | TINYINT(1), values 0/1 | BOOLEAN, values f/t |
| TINYINT / SMALLINT | TINY / SHORT | SMALLINT |
| INTEGER / BIGINT | LONG / LONGLONG | INTEGER / BIGINT |
| UTINYINT / USMALLINT / UINTEGER | Corresponding integer type, unsigned flag | SMALLINT / INTEGER / BIGINT |
| UBIGINT | LONGLONG, unsigned flag | NUMERIC(20,0) |
| HUGEINT / UHUGEINT | NEWDECIMAL, unsigned flag for UHUGEINT | NUMERIC(39,0) |
| FLOAT / DOUBLE | FLOAT / DOUBLE | REAL / DOUBLE PRECISION |
| DECIMAL(p,s) | NEWDECIMAL with precision and scale | NUMERIC(p,s) |
| BLOB | LONG_BLOB, binary charset and flag | BYTEA, hex text encoding |
| DATE / TIME / TIMESTAMP (microseconds) | DATE / TIME / DATETIME | TEXT |

MySQL expression nullability is reported as unknown rather than claiming
NOT NULL. Typed NULLs and zero-row results retain their numeric metadata.
MySQL columns containing nonfinite floating-point values, infinite dates or
timestamps, or dates outside years 1..9999 use text metadata for the whole
column. PostgreSQL floating-point NaN and infinity retain numeric metadata.
Other temporal variants and unmapped types retain text metadata. Text uses
UTF-8 metadata; unbounded text/blob lengths describe the largest returned byte
length rather than an invented declared bound.

A VARCHAR wrapper casts only unsupported columns. Supported neighboring
columns keep their types, order and original labels, including duplicate labels.

BLOB values preserve arbitrary bytes, including embedded NUL and non-UTF-8
bytes. MySQL receives the raw bytes with length information. PostgreSQL receives
the standard BYTEA text representation (`\x` followed by hexadecimal digits),
which clients such as libpq decode with `PQunescapeBytea`. Empty binary values
remain distinct from SQL NULL.

The direct conversion path supports common scalar values including booleans,
signed and unsigned integers, floats, doubles, dates, time, timestamps,
decimals, intervals, UUID, VARCHAR, and BLOB.

`TIMESTAMP_S`, `TIMESTAMP_MS`, and `TIMESTAMP_NS` convert directly using DuckDB's
native value formatter. Nanosecond precision, pre-epoch values, infinities, and
NULL are preserved, including in DML `RETURNING`. These values retain text
metadata to preserve DuckDB's precision and range; neighboring numeric columns
keep their numeric metadata.
Values outside DuckDB's text-formatting range return conversion errors.

`TIME WITH TIME ZONE` (`TIMETZ`) converts directly using DuckDB's native
formatter, including in DML `RETURNING`. Text metadata preserves fractional
seconds and signed offsets, including offsets with seconds. SQL NULL and
adjacent numeric metadata are preserved.

`TIMESTAMP WITH TIME ZONE` (`TIMESTAMPTZ`) converts directly using the
originating connection's native DuckDB cast. With ICU loaded, formatting respects
the session TimeZone and Calendar, including daylight-saving transitions.
Without ICU, DuckDB's built-in UTC formatting applies. Values retain text
metadata, microsecond precision, infinities and NULL, including in `RETURNING`;
adjacent numeric columns retain their numeric metadata.

UUID values convert directly to canonical lowercase strings, including in DML
`RETURNING`. UUID columns retain text metadata; adjacent numeric columns retain
their numeric metadata. SQL NULL remains a protocol null.

`TIME_NS`, `ENUM`, and `BIT` also convert directly, including DML `RETURNING`.
`TIME_NS` preserves nanosecond precision, ENUM returns the full label (including
empty labels and embedded NUL bytes), and BIT returns its sequence of `0`/`1`
characters with leading zeroes intact. These columns retain text metadata;
SQL NULL and neighboring numeric metadata are preserved.

Other DuckDB types are detected from the prepared statement before execution.
For a two-column result whose second type needs fallback, the plugin attempts
to execute a positional wrapper equivalent to:

```sql
SELECT col_0, col_1::VARCHAR FROM (<original query>) AS result(col_0, col_1)
```

This commonly renders `LIST`, `STRUCT`, `MAP`, `ARRAY`, and `UNION` as
readable text. The decision occurs
before execution, so volatile expressions and side effects execute exactly
once.

Some DML `RETURNING` statements cannot be placed in that wrapper. If the result
cannot be rendered, the plugin rejects the statement before execution with
SQLSTATE `0A000` (MySQL error 1235). No mutation or default-expression evaluation
occurs. Cast unsupported result expressions explicitly to `VARCHAR`, for
example `INSERT INTO t VALUES (...) RETURNING id::VARCHAR`. SQL NULL remains a
real protocol null.

## Errors

MySQL clients receive a MySQL error packet. PostgreSQL clients receive an
ErrorResponse with a mapped SQLSTATE where DuckDB exposes an unambiguous error
category, including syntax, numeric range, conversion, division by zero,
transaction, constraint, connection, I/O, cancellation, memory, permissions,
and invalid parameter categories. Unclassified DuckDB errors use `XX000`.

## Transactions

On the MySQL listener, `SET autocommit=0` is refused (MySQL error 1235 / SQLSTATE
`0A000`): native implicit transactions are not implemented. `SET autocommit=1`
is accepted when already enabled.

Text `BEGIN`, `COMMIT`, and `ROLLBACK` commands execute in DuckDB. PostgreSQL
`ReadyForQuery` reports:

- `I` — idle/no active transaction
- `T` — active valid transaction
- `E` — active invalidated transaction

## Current omissions

- A refused database is reported at the next statement, not at `COM_INIT_DB` or a
  routed `USE` (see above).
- `SHOW DATABASES` reports DuckDB catalogs, not the replica's databases.
- `SHOW TABLES FROM db` and a prepared `SELECT DATABASE()` stay outside the
  admitted subset and are refused before execution.
- Analytical `SELECT` against a dropped current database is refused with 1235
  instead of MySQL's 1049.
- No query timeout or `duckdb_interrupt()` policy.
- No general MySQL/PostgreSQL dialect translation.
- No structured protocol error when the connection cap rejects a newly
  accepted socket.
