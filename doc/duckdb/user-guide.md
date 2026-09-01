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

DuckDB transaction commands can be issued as ordinary text queries:

```sql
BEGIN;
INSERT INTO events VALUES (CURRENT_TIMESTAMP, 'batch', 20);
COMMIT;
```

On the PostgreSQL protocol, `ReadyForQuery` reports idle, in-transaction, or
failed-transaction state based on the actual DuckDB connection. After an error
invalidates an explicit transaction, issue `ROLLBACK` before continuing.

## Session settings

DuckDB-native settings are sent to the engine:

```sql
SET threads=4;
SELECT current_setting('threads');
```

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
not aliases for the same metadata query.

## Result values

Both frontend protocols currently describe all columns as text. SQL NULL is
preserved as a real null value, and embedded NUL bytes in supported strings are
length-aware internally.

Many DuckDB values are rendered directly. For types outside the direct
compatibility list, the plugin prepares a wrapper that casts result columns to
`VARCHAR` before executing the statement. This makes common nested and special
types readable without executing the original statement twice. A DML
`RETURNING` shape that cannot be wrapped can still return NULL for an
unsupported result type; see [Protocol compatibility](protocol-compatibility.md).

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

Do not use client-side prepared-statement APIs for this initial plugin version.
PostgreSQL drivers often choose extended protocol automatically for parameters;
configure simple-query mode or send fully formed trusted SQL where appropriate.
Never replace parameter binding with unsafe string concatenation for untrusted
input.

## Closing sessions

Close clients normally. The plugin joins connection threads during shutdown
before closing the shared engine. At the configured connection limit, a newly
accepted socket is closed before a session is created; clients may report a
generic connection reset rather than a structured protocol error.
