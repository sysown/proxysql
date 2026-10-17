# Literal MySQL user-variable tracking

`mysql-user_variable_tracking` is an opt-in, conservative way to keep a
small, proven subset of MySQL user-defined variables multiplexable. It tracks
parsed literal syntax, then materializes it when ProxySQL assigns a
different pooled backend to the same frontend session. It is intended for
request metadata and similar values, not as a general user-variable evaluator.

## Enable mode 1

`mysql-user_variable_tracking` is an integer variable. Its default is `0` and
the currently accepted range is `0..1`:

| Value | Meaning |
| --- | --- |
| `0` | Existing user-variable behavior; no literal tracking. |
| `1` | Enable conservative literal tracking when a ParserSQL prerequisite is active. |

Values above `1` are rejected; the integer form reserves future modes without
changing mode `1` semantics. Mode `1` requires either
`mysql-set_parser_algorithm=3` or `mysql-query_processor_parser=1`. If neither
is active, ProxySQL leaves mode `1` inactive and uses the existing safe
fallback. Each `LOAD MYSQL VARIABLES TO RUNTIME` in this state emits one fixed,
aggregate-safe warning that names both alternative parser settings without any
statement literal values. Subsequent fallback `SET` statements do not repeat
the prerequisite warning. ProxySQL does not change either parser setting for
you.

For example, this enables the feature through the ParserSQL SET parser:

```sql
UPDATE global_variables
SET variable_value = '1'
WHERE variable_name = 'mysql-user_variable_tracking';

UPDATE global_variables
SET variable_value = '3'
WHERE variable_name = 'mysql-set_parser_algorithm';

LOAD MYSQL VARIABLES TO RUNTIME;
```

Using `mysql-query_processor_parser=1` instead of setting
`mysql-set_parser_algorithm=3` is also sufficient. With the default
`mysql-set_query_lock_on_hostgroup=1`, an inactive, unsupported, or unsafe
user-variable operation follows the established fallback and locks the
hostgroup.

## Statements that are tracked

Only a text-protocol, single-statement `SET` with complete ParserSQL input
coverage is eligible. User-variable right-hand sides must be one of these
exact forms:

- single- or double-quoted string literals;
- unsigned integers, or a direct unary `+` or `-` on an integer;
- unsigned fixed-point or exponent-form decimals, or a direct unary `+` or
  `-` on one;
- hexadecimal `0x...` or `X'...'` literals, including a direct unary sign;
- bit `0b...` or `B'...'` literals, including a direct unary sign;
- `NULL`.

The unary sign exception applies only directly to an integer, decimal,
hexadecimal, or bit literal. Parentheses, casts,
introducers, `COLLATE`, identifiers, system- or user-variable references,
functions, subqueries, operators, parameter markers, prepared statements,
multi-statements, malformed input, and every other expression form are outside
mode `1`.

Analysis is all-or-nothing: one ineligible target or value makes the whole
`SET` fall back. Targets are normalized case-insensitively, preserve a
ParserSQL-validated replay spelling, and have MySQL's 64-byte decoded-name
limit. Tracked names must be ASCII so case-insensitive canonicalization remains
unambiguous; quoted target names containing a backslash are not eligible because
their identity depends on SQL mode. Source order is retained, including
repeated names, and the last successful assignment is the map entry.

This is a supported deployment statement (shown exactly as accepted):

```sql
SET @browser_lang = 'en-US', @browser_time = '2026-08-11 18:11:12', @browser_timezone = 'GMT+2', @ip_address = '167.235.198.244'
```

ProxySQL stages the complete assignment group against the frontend's resource
limits, commits the desired frontend state, and returns `OK` locally. It does
not acquire a backend or send the original `SET`. Before a subsequent backend
query, the normal synchronization path materializes only assignments that differ
from the selected backend's known state. Backend maps change only after that
synchronization succeeds. A backend error while materializing a literal fails
that subsequent query and retires the backend; backend semantic validation is
therefore deferred until the state is needed.

### Mixed user/session-variable assignments

Mode `1` also tracks statements containing literal user-variable assignments
and either of these session variables:

- `max_execution_time`: an unsigned decimal integer from 0 to 4294967295;
- `wait_timeout`: an unsigned decimal integer from 1 to 1728000 seconds.

Implicit session scope, `SESSION`, `LOCAL`, `@@`, `@@session.`, and `@@local.`
are accepted. System-variable values must be plain decimal integer literals;
quoted values, signs, expressions, and `DEFAULT` retain fallback. Repeated
assignments retain source order and the last value wins.

```sql
SET @client_tag = 'web-6d8f9c7b5-x2k4p', SESSION max_execution_time = 1000;
SET @client_tag = 'web-6d8f9c7b5-x2k4p', SESSION max_execution_time = 1000, SESSION wait_timeout = 600;
```

ProxySQL validates the whole statement, commits both kinds of desired frontend
state, and returns `OK` locally. Neither the original SQL nor `wait_timeout`
is sent to a backend. `max_execution_time` uses the existing system-variable
synchronization path; user variables use the existing user-variable replay path.
An attached backend, including one with an active transaction, is unchanged
until the next backend query requires synchronization.

Other system variables, global/persistent assignments, and context changes
(including `sql_mode`, charset/collation, `NAMES`, and `CHARACTER SET`) retain
whole-statement fallback. Unsupported syntax or resource-limit failure forwards
the original statement through the existing hostgroup-locking policy, without
partially committing desired state. ParserSQL 1.1.1 already provides the required
AST; no dependency release is needed.

As with standalone `wait_timeout`, the frontend timeout is enforced together
with the global `mysql-wait_timeout` limit. The backend's `@@wait_timeout` remains
unchanged. No extra backend reset or retirement is needed for a parsed mixed SET.

## Pooling and replay

Each frontend connection holds its desired variable map; each backend
connection holds the state ProxySQL knows is materialized there. Maps are
bounded independently to 128 distinct variables and 64 KiB of stored replay
target plus literal text. Reassigning a name replaces its prior entry and
updates the byte count. A `SET` that would exceed either bound is not partially
tracked and uses the normal safe fallback.

Pool selection includes these maps. A backend with matching entries is
preferred. If a backend contains a name absent from the frontend map, ProxySQL
uses the existing reset/`COM_CHANGE_USER` path: user variables cannot be safely
"unset" merely by assigning `NULL`.

Before the client query, ProxySQL synchronizes ordinary session variables
(including charset, collation, and `sql_mode`) before user variables. Missing
or mismatched values are replayed in deterministic map order as internal
commands such as:

```sql
SET @name1=<raw-literal-1>,@name2=<raw-literal-2>
```

The replay is batched to the backend packet budget; if all entries do not fit,
ProxySQL sends deterministic bounded batches. If the backend's
`max_allowed_pkt` field is zero or not yet known, replay conservatively uses
MySQL's 1024-byte server minimum. The four-byte packet header and one-byte
`COM_QUERY` command leave at most 1019 bytes of SQL text for each replay batch
in that case. An individual assignment that cannot fit that ceiling cannot be
split: ProxySQL fails the pending client query and retires the backend.

Backend map entries are committed only after each replay `SET` succeeds. Any
replay failure likewise fails the pending client query and retires the backend
rather than running the query with incorrect state. Hashes only accelerate
matching: equality also requires the exact literal kind, replay target, and raw
literal.

## Reads, unsafe operations, and context changes

ParserSQL classifies real user-variable use as `NO_USER_VARIABLE`, `READ_ONLY`,
or `UNSAFE_OR_UNKNOWN`. Strings and comments do not count as a user variable.
Proven read-only uses, including reads of an uninitialized variable, remain
multiplexable after the desired map has been synchronized. Writes and unknown
forms—including `SELECT @x := ...`, `SELECT ... INTO @x`, nonliteral `SET`s,
prepared statements, parameter markers, incomplete parses, and unsupported AST
shapes—first synchronize existing tracked state and then take the existing
connection-bound fallback. With the default lock policy this locks the
hostgroup; an explicit query-rule multiplex policy retains its usual effect.

Raw literal text is valid only in the interpretation context where MySQL
accepted it. If a frontend with tracked state changes `sql_mode`,
`character_set_client`, `character_set_connection`, `collation_connection`,
`SET NAMES`, or `SET CHARACTER SET`, ProxySQL synchronizes the old state first
and takes the connection-bound fallback before applying that change. The same
safeguard applies when backend session tracking reports one of those context
changes. This avoids attempting to evaluate or reinterpret literals in
ProxySQL.

Do not use mode `1` when stored procedures, stored functions, or triggers can
write user variables invisibly. MySQL session tracking does not report such
writes, so ProxySQL cannot update its backend map; a later pooled use could see
stale state. Backend-side code may read synchronized user variables, but hidden
writes are unsupported.

## Runtime and lifecycle behavior

Disabling `mysql-user_variable_tracking`, or removing both ParserSQL
prerequisites, immediately prevents new tracked assignments. Existing frontend
sessions that already committed tracked state drain safely: ProxySQL continues
classification and synchronization for that state until `COM_RESET_CONNECTION`,
`COM_CHANGE_USER`, or disconnect. New assignments during the drain use the
normal fallback.

`COM_RESET_CONNECTION` and `COM_CHANGE_USER` clear the frontend session state.
Backend `COM_CHANGE_USER`, backend connection reset/reconnect, and backend
destruction clear the corresponding backend map. An unsupported `SET` forwarded
to the backend never partially updates the tracked frontend map.

## Observability and confidentiality

The following counters are available in `stats_mysql_global` and as Prometheus
counters:

- `User_variable_assignments_tracked` /
  `proxysql_mysql_user_variable_assignments_tracked_total`: committed supported
  assignment targets.
- `User_variable_replay_commands` /
  `proxysql_mysql_user_variable_replay_commands_total`: internal replay `SET`
  batches executed.
- `User_variable_replay_failures` /
  `proxysql_mysql_user_variable_replay_failures_total`: failed replay batches.
- `User_variable_fallback_unsupported` /
  `proxysql_mysql_user_variable_fallback_unsupported_total`: unsupported
  user-variable `SET` fallbacks.
- `User_variable_fallback_limits` /
  `proxysql_mysql_user_variable_fallback_limits_total`: resource-limit
  fallbacks.

`PROXYSQL INTERNAL SESSION` exposes aggregate-only diagnostics under
`user_variables`: `count`, `stored_bytes`, and a process-keyed aggregate
fingerprint when the fingerprint key is available. It deliberately exposes no
variable names, replay targets, raw literals, values, or per-entry hashes.
