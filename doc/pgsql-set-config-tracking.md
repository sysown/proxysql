# PostgreSQL `set_config()` tracking

ProxySQL records the session settings a client changes with `SET`, so that a pooled
backend connection always carries the settings of the client using it. `set_config()`
changes the same settings. With the ParserSQL SET parser, ProxySQL treats it the way it
treats `SET`: it records a call it can follow exactly, and locks the session on its
hostgroup for any other call, so the backend connection is never handed to another client
with a setting ProxySQL does not know about.

## When it is active

Only with the ParserSQL SET parser, the same condition as for the ParserSQL `SET` walker:

```sql
UPDATE global_variables SET variable_value = '3' WHERE variable_name = 'pgsql-set_parser_algorithm';
-- or: UPDATE global_variables SET variable_value = '1' WHERE variable_name = 'pgsql-query_processor_parser';
LOAD PGSQL VARIABLES TO RUNTIME;
```

It no longer needs query digests: the classifier runs on the query text, so `set_config()`
is tracked even with `pgsql-query_digests=false` and `pgsql-commands_stats=false`. With the
default settings (`pgsql-set_parser_algorithm=2`, `pgsql-query_processor_parser=0`)
`set_config()` is forwarded as an ordinary query, untracked and without a lock, as in
earlier versions.

## What is recorded

The bare call, with literal arguments and a session-level `is_local`:

```sql
SELECT set_config('DateStyle', 'ISO, DMY', false)
SELECT pg_catalog.set_config('search_path', 'app, public', false) AS sp   -- schema prefix, alias
SELECT pg_catalog.set_config('search_path', 'app, public', 'off'); -- quoted boolean
```

- The name must be a setting ProxySQL tracks, spelled as PostgreSQL names it (any case).
  `set_config('application_name', ...)` is forwarded without tracking or a lock, as
  `SET application_name` is.
- The value goes through the same check as a `SET` of that setting. A value the check
  refuses gets `22023 invalid value for parameter "<name>": "<value>"`, as a refused `SET` does.
- A NULL value resets the setting to the client's connect-time value, like
  `SET ... TO DEFAULT`.
- `search_path` is read as PostgreSQL reads a `set_config()` value: a raw list where only
  double quotes are special, so `'a, b'` is two schemas. ProxySQL records it as `SET` would
  write it, every name double-quoted.
- A `set_config('TimeZone', ...)` call with a non-NULL value is forwarded to PostgreSQL and pins the session on
  its hostgroup instead of being recorded: ProxySQL cannot prove a zone name exists, so it
  never records its value locally. This includes `INTERVAL` values, which are forwarded
  and locked instead of being replayed on another pooled connection.

Over the simple protocol ProxySQL answers the call itself: one text column (`set_config`, or
the alias), whose value is the value ProxySQL recorded, then ParameterStatus when a reported
setting changed. Over the extended protocol it records the value, sends the ParameterStatus,
and forwards the statement; PostgreSQL builds the row. Inside a transaction the change is
undone by `ROLLBACK` and `ROLLBACK TO SAVEPOINT`, as for `SET`.

## What locks the session on its hostgroup

- `is_local` true (`true`, `'on'`, `'yes'`, `'1'`, ...), as `SET LOCAL` does.
- A setting ProxySQL does not track (`statement_timeout`, custom names such as `app.tenant`).
- Any argument that is not a literal: `$1` parameters, casts, expressions, subqueries.
- Any other shape: other columns or clauses next to the call, `SELECT * FROM set_config(...)`,
  `EXPLAIN ANALYZE`, `PREPARE ... AS`, a call inside a CTE, subquery, `CASE` or `WHERE`, two
  calls, a call in a multi-statement query.
- `UPDATE pg_settings` anywhere in a statement, and a `DO` block whose body mentions
  `set_config` or `pg_settings`.
- A NULL value when the client has no connect-time value for the setting.
- A `set_config('TimeZone', ...)` call with a non-NULL value: ProxySQL cannot prove a zone name exists, so it
  forwards the statement and pins the session instead of recording the value.
- Any `set_config()` in a query that holds a backslash, from a client whose
  `standard_conforming_strings` is `off`. A backslash is the only thing that setting changes, so
  the same client's other calls are recorded as usual.

A session that is already locked forwards `set_config()` untracked.

## Errors answered by ProxySQL

A bare tracked call with a NULL value over the extended protocol is refused with
`0A000 feature_not_supported` before its value is recorded or sent to the backend.

PostgreSQL's own error is returned without a backend round trip, with its SQLSTATE and
primary message: a wrong argument type (`42883 function set_config(...) does not exist`),
an `is_local` string that is no boolean (`22P02`), a NULL name (`22004`) and an empty name
(`42704`). Over the extended protocol the first two come from PostgreSQL at Parse. HINT and
position fields are not sent.

A value the setting's check refuses gets `22023` with ProxySQL's generic text,
`invalid value for parameter "<name>": "<value>"`. The SQLSTATE is PostgreSQL's; its wording
differs for some settings (`parameter "enable_sort" requires a Boolean value`,
`4 is outside the valid range for parameter "extra_float_digits" (-15 .. 3)`).

## Known differences

| input | PostgreSQL returns | ProxySQL returns |
| --- | --- | --- |
| search_path `'A,   b'` | `A,   b` | `"a", "b"` |

## Limits

`set_config()` calls ProxySQL cannot see in the query text are not tracked: calls made
inside functions, triggers or dynamic SQL in PL/pgSQL.

Unqualified calls are forwarded and pinned when `search_path` explicitly mentions `pg_catalog`,
or did when the statement was parsed. A conservative match can also pin schema names containing
`pg_catalog`. Calls with argument types that could select a user overload, including a quoted
`is_local`, are also forwarded and pinned. Default-path calls with string name/value arguments
and a Boolean literal remain tracked; explicitly qualified `pg_catalog.set_config()` calls do too.

Over the extended protocol a NULL value is not tracked and is refused with 0A000. Simple-protocol
NULL records the client's connect-time value when one exists; otherwise it locks and forwards the call. `SET ... TO DEFAULT` and `RESET` over
the extended protocol behave as before.
