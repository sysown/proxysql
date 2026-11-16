# DuckDB Plugin User Guide

## What a connection represents

The plugin opens one shared DuckDB database and creates one DuckDB connection
per client connection. MySQL and PostgreSQL clients can therefore read and
modify the same tables. Transactions and session settings belong to the
individual connection, while database contents are shared.

With `database_path=:memory:`, the database is shared by all plugin sessions in
the ProxySQL process but disappears when the process stops. It is not a
separate in-memory database per client.

## Connecting

MySQL protocol, default port 6031:

```bash
mysql -h 127.0.0.1 -P 6031 -u USERNAME -p
```

PostgreSQL protocol, default port 6034:

```bash
psql -h 127.0.0.1 -p 6034 -U USERNAME main
```

Use a user present in `mysql_users` or `pgsql_users` for the selected
protocol. These listeners are independent of ProxySQL Admin on 6032 and the
normal MySQL proxy listener on 6033.

## Running DuckDB SQL

After authentication, write DuckDB SQL. ProxySQL does not translate general
MySQL or PostgreSQL dialect syntax into DuckDB syntax.

```sql
CREATE OR REPLACE TABLE events (
    event_time TIMESTAMP,
    category VARCHAR,
    value DOUBLE
);

INSERT INTO events VALUES
    (TIMESTAMP '2026-09-01 10:00:00', 'api', 12.5),
    (TIMESTAMP '2026-09-01 10:05:00', 'worker', 7.0),
    (TIMESTAMP '2026-09-01 10:10:00', 'api', 4.5);

SELECT category, COUNT(*) AS events, SUM(value) AS total
FROM events
GROUP BY category
ORDER BY category;
```

Compatibility intercepts exist for a small set of client-discovery queries,
including version, current database, and SHOW metadata commands. They are not
a general dialect compatibility layer.

## Transactions

DuckDB transaction commands can be issued as ordinary text queries. Each line
below must be sent as a separate request; interactive clients normally split
them at the statement terminator:

```sql
BEGIN;
INSERT INTO events VALUES (CURRENT_TIMESTAMP, 'batch', 20);
COMMIT;
```

On the PostgreSQL protocol, `ReadyForQuery` reports idle, in-transaction, or
failed-transaction state by tracking supported text transaction commands and
their outcomes. After an error
invalidates an explicit transaction, issue `ROLLBACK` before continuing.

## Session settings

DuckDB session settings are sent to the engine and apply only to the client's
own connection. In this example, `SET` and `SELECT` are two separate requests:

```sql
SET search_path='main';
SELECT current_setting('search_path');
```

Every client `SET` and `RESET` runs in session scope. Engine-wide settings are
shared by all clients of the embedded database, so clients cannot change them:
`SET GLOBAL`, engine-wide options such as `memory_limit`/`max_memory`,
`threads`/`worker_threads`, `max_temp_directory_size` and
`enable_external_access`, engine-wide configuration `PRAGMA`s, and `EXPLAIN` of a `SET`,
`RESET` or `PRAGMA` statement all return an error. The settings ProxySQL
manages are changed through their `duckdb-*` Admin variables
(`duckdb-memory_limit`, `duckdb-threads`, `duckdb-enable_external_access`)
followed by `LOAD DUCKDB VARIABLES TO RUNTIME`. Other engine-wide settings have
no Admin variable and cannot be changed by clients. `SET VARIABLE` user
variables are unaffected. Session-local `PRAGMA` commands such as
`PRAGMA enable_optimizer` are allowed; configuration assignments written as
`PRAGMA name=value` are refused, so use `SET SESSION` for session settings.

Only narrow client-compatibility commands are accepted as no-ops:

- `SET autocommit=0`
- `SET autocommit=1`
- a single `SET NAMES ...` command

Other `SET` statements are not swallowed. A `SET NAMES` packet containing a
second statement is rejected by the normal one-statement preparation path.

## Metadata commands

The plugin recognizes:

```sql
SHOW TABLES;
SHOW DATABASES;
SHOW SCHEMAS;
SELECT DATABASE();
SELECT CURRENT_DATABASE();
SELECT VERSION();
SELECT @@version;
```

`SHOW DATABASES` lists DuckDB catalogs. `SHOW SCHEMAS` lists schemas; they are
not aliases for the same metadata query. `SELECT DATABASE()` / `SELECT
CURRENT_DATABASE()` return `memory` for `:memory:` and the configured
`database_path` otherwise.

## Result values

Both frontend protocols expose numeric column types, including decimal scale
and unsigned ranges. Booleans use MySQL TINYINT with 0/1 values or PostgreSQL
BOOLEAN with f/t values. BLOBs use MySQL binary metadata or PostgreSQL BYTEA with
hex text encoding. MySQL DATE, TIME and microsecond TIMESTAMP use native temporal
metadata; exceptional dates/floats use text fallback. Other temporal variants
and unmapped columns use text metadata. SQL NULL is
preserved as a real null value, and embedded NUL bytes in supported strings are
length-aware internally. See [Protocol compatibility](protocol-compatibility.md)
for the type mappings and text fallbacks.

Finite `DOUBLE` values are rendered with enough significant digits to preserve
their value when parsed back as a double by a client.

Second-, millisecond-, and nanosecond-resolution timestamps convert directly,
including in `RETURNING` results. They retain text metadata and preserve the
original timestamp precision without casting neighboring columns to text.

`TIME WITH TIME ZONE` (`TIMETZ`) also converts directly, preserving fractional
seconds and UTC offsets, including in `RETURNING`. It retains text metadata.

`TIMESTAMP WITH TIME ZONE` (`TIMESTAMPTZ`) converts directly with text metadata,
including in `RETURNING`. With ICU loaded, the connection's TimeZone and Calendar
settings control the display. The stored instant is preserved. Loading ICU
requires external access; see [Extension behavior](security.md#extension-behavior).

UUID values also convert directly, including in `RETURNING`, as canonical
lowercase strings with text metadata.

`TIME_NS`, `ENUM`, and `BIT` support direct `RETURNING` results with text
metadata. Nanosecond precision, enum labels, and leading zeroes in bit strings
are preserved.

Many DuckDB values are rendered directly. For types outside the direct
compatibility list, the plugin prepares a wrapper that casts only unsupported columns to
`VARCHAR` before executing the statement. This makes common nested and special
types readable without executing the original statement twice. A DML
`RETURNING` shape that cannot be wrapped is rejected before execution when its
result type is unsupported. Cast the returned expression to `VARCHAR`; see
[Protocol compatibility](protocol-compatibility.md).

## One statement per request

A client request must contain exactly one SQL statement. For example, this is
rejected:

```sql
DROP TABLE events; SELECT 1;
```

Use separate client calls. This prevents an earlier statement from executing
while only the last statement's result is shown.

## Persistent and in-memory databases

Choose persistence with `database_path`:

- `:memory:` — process-lifetime database, shared by all connections.
- a filesystem path — persistent DuckDB database.

Changing the stored path does not move existing data and does not switch the
already-open engine. Save the setting, stop traffic, restart ProxySQL, and then
verify the new database explicitly.

## Client-library guidance

Choose APIs that issue simple text queries:

- MySQL: `mysql_query`, `mysql_real_query`, or equivalent non-prepared APIs.
- PostgreSQL: `PQexec` or a driver mode that uses the simple Query message.

Client-side prepared-statement APIs are not available yet. The core framework
is tracked in [#6298](https://github.com/sysown/proxysql/issues/6298), followed by
the DuckDB adapter in [#6282](https://github.com/sysown/proxysql/issues/6282).
New dialect compatibility in [#6284](https://github.com/sysown/proxysql/issues/6284)
must use vendored ParserSQL; the experimental custom SELECT translator has been
removed. Use native DuckDB SQL.
PostgreSQL drivers often choose extended protocol automatically for parameters;
configure simple-query mode or send fully formed trusted SQL where appropriate.
Never replace parameter binding with unsafe string concatenation for untrusted
input.

## Closing sessions

Close clients normally. The plugin joins connection threads during shutdown
before closing the shared engine. At the configured connection limit, a newly
accepted socket is closed before a session is created; clients may report a
generic connection reset rather than a structured protocol error.
