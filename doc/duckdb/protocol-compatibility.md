# DuckDB Protocol Compatibility

The plugin uses MySQL and PostgreSQL frontend protocols as transports for
DuckDB SQL. It is not a MySQL or PostgreSQL server implementation, and it does
not attempt complete dialect or wire-feature compatibility.

## Support matrix

| Capability | MySQL endpoint | PostgreSQL endpoint |
|---|---|---|
| Authentication | `mysql_users` | `pgsql_users` |
| Simple text query | Supported | Supported |
| Client prepared statements | Not supported | Not supported |
| Extended-query protocol | N/A | Rejected with SQLSTATE `0A000` |
| Multiple statements in one request | Rejected | Rejected |
| Transaction status | Protocol OK/status behavior | `ReadyForQuery` I/T/E |
| Result metadata | All columns are strings | All columns are `TEXTOID` |

## Simple-query requirement

Use non-prepared client APIs. For PostgreSQL, the driver must use the simple
Query message. A normal extended flow (`Parse`, `Bind`, `Describe`, `Execute`)
receives one `Feature not supported` error. The plugin then discards frontend
messages until `Sync`, sends one `ReadyForQuery`, and resumes normal processing.
This follows PostgreSQL error-resynchronization rules without pretending that
prepared execution is available.

For MySQL, use `COM_QUERY`-based APIs. `COM_STMT_PREPARE` and
`COM_STMT_EXECUTE` are outside the initial plugin surface.

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
- `SET autocommit=0` and `SET autocommit=1`
- a single `SET NAMES ...` command

Matching is case-insensitive and tolerates normal whitespace and a trailing
statement terminator. Longer identifiers and packets with a second statement
are not accepted by prefix alone.

`SHOW DATABASES` returns DuckDB catalogs. `SHOW SCHEMAS` reads schema metadata.
Other statements, including DuckDB-native `SET` commands, go to DuckDB.

## SQL dialect

Use DuckDB SQL. Syntax specific to MySQL or PostgreSQL can fail even though the
connection uses that product's wire protocol. Client libraries may also issue
session initialization SQL automatically; only the narrow compatibility list
above is guaranteed to be absorbed or translated.

## Result metadata and conversion

Both protocol serializers label every column as text. Applications that depend
on numeric, timestamp, array, or binary type metadata must parse returned text
or wait for a future typed-result implementation.

The direct conversion path supports common scalar values including booleans,
signed and unsigned integers, floats, doubles, dates, time, timestamps,
decimals, intervals, VARCHAR, and BLOB.

Other DuckDB types are detected from the prepared statement before execution.
The plugin attempts to execute a wrapper equivalent to:

```sql
SELECT COLUMNS(*)::VARCHAR FROM (<original query>)
```

This commonly renders `LIST`, `STRUCT`, `MAP`, `ARRAY`, `UNION`, UUID, ENUM,
BIT, and specialized timestamp variants as readable text. The decision occurs
before execution, so volatile expressions and side effects execute exactly
once.

Some DML `RETURNING` statements cannot be placed in that wrapper. In that
fallback path the original statement executes once, but an unsupported result
column can be returned as NULL. SQL NULL itself is otherwise preserved as a
real protocol null.

## Errors

MySQL clients receive a MySQL error packet. PostgreSQL clients receive an
ErrorResponse with a mapped SQLSTATE where DuckDB exposes an unambiguous error
category, including syntax, numeric range, conversion, division by zero,
transaction, constraint, connection, I/O, cancellation, memory, permissions,
and invalid parameter categories. Unclassified DuckDB errors use `XX000`.

## Transactions

Text `BEGIN`, `COMMIT`, and `ROLLBACK` commands execute in DuckDB. PostgreSQL
`ReadyForQuery` reports:

- `I` — idle/no active transaction
- `T` — active valid transaction
- `E` — active invalidated transaction

## Current omissions

- No client-visible prepared statements.
- No query timeout or `duckdb_interrupt()` policy.
- No typed result metadata.
- No general MySQL/PostgreSQL dialect translation.
- No structured protocol error when the connection cap rejects a newly
  accepted socket.
