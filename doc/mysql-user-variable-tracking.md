# Literal MySQL user-variable tracking

`mysql-user_variable_tracking` is an opt-in, conservative way to keep a
small, proven subset of MySQL user-defined variables multiplexable. It tracks
the literal syntax that MySQL accepted, then replays it when ProxySQL assigns a
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
is active, ProxySQL leaves mode `1` inactive, emits a configuration warning on
`LOAD MYSQL VARIABLES TO RUNTIME`, and uses the existing safe fallback. It does
not change either parser setting for you.

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
coverage is eligible. Every target must be a MySQL user variable and every
right-hand side must be one of these exact forms:

- single- or double-quoted string literals;
- unsigned integers, or a direct unary `+` or `-` on an integer;
- unsigned fixed-point or exponent-form decimals, or a direct unary `+` or
  `-` on one;
- hexadecimal `0x...` or `X'...'` literals;
- bit `0b...` or `B'...'` literals;
- `NULL`.

The unary sign exception applies only to integer and decimal literals. It does
not make signed hexadecimal or bit literals eligible. Parentheses, casts,
introducers, `COLLATE`, identifiers, system- or user-variable references,
functions, subqueries, operators, parameter markers, prepared statements,
multi-statements, malformed input, and every other expression form are outside
mode `1`.

Analysis is all-or-nothing: one ineligible target or value makes the whole
`SET` fall back. Mixed system and user-variable assignments are therefore not
partially tracked. Targets are normalized case-insensitively, preserve a
ParserSQL-validated replay spelling, and have MySQL's 64-byte decoded-name
limit; quoted target names containing a backslash are not eligible because
their identity depends on SQL mode. Source order is retained, including
repeated names, and the last successful assignment is the map entry.

This is a supported deployment statement (shown exactly as accepted):

```sql
SET @browser_lang = 'en-US', @browser_time = '2026-08-11 18:11:12', @browser_timezone = 'GMT+2', @ip_address = '167.235.198.244'
```

ProxySQL forwards the original statement to MySQL. It stages, but does not
commit, the resulting assignments before that backend returns `OK`. On `OK` it
atomically commits the complete assignment group to both the frontend map and
the selected backend map. A backend error, retry, or other query-error path
discards pending assignments, so the original backend result remains
authoritative.

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
ProxySQL sends deterministic bounded batches. Backend map entries are committed
only after each replay `SET` succeeds. A replay failure fails the pending client
query and retires the backend rather than running the query with incorrect
state. Hashes only accelerate matching: equality also requires the exact
literal kind, replay target, and raw literal.

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
destruction clear the corresponding backend map. A failed original `SET` clears
only its pending data; it never changes a committed map.

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
