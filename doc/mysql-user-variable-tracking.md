# Literal MySQL user-variable tracking

`mysql-user_variable_tracking` is an opt-in, conservative way to keep a
small, proven subset of MySQL user-defined variables multiplexable. It tracks
literal assignments in the frontend session and applies them only when a real
query needs a backend connection. Autocommit changes that end a transaction
still take effect immediately. It is intended for request metadata and similar
values, not as a general user-variable evaluator.

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
coverage is eligible. User-variable assignments can be combined with session
variables already supported by ProxySQL session tracking. Each user-variable
right-hand side must be one of these exact forms:

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
`SET` fall back; neither class of variable is partially tracked. Session
assignments use the existing variable registry and normalization rules, including
boolean, numeric, string, charset, collation, and transaction-setting handling.
Global and persistent assignments are ineligible. Targets are normalized case-insensitively, preserve a
ParserSQL-validated replay spelling, and have MySQL's 64-byte decoded-name
limit. Tracked names must be ASCII so case-insensitive canonicalization remains
unambiguous; quoted target names containing a backslash are not eligible because
their identity depends on SQL mode. Source order is retained, including
repeated names, and the last successful assignment is the map entry.

This is a supported deployment statement (shown exactly as accepted):

```sql
SET @browser_lang = 'en-US', @browser_time = '2026-08-11 18:11:12', @browser_timezone = 'GMT+2', @ip_address = '167.235.198.244'
```

A supported `SET` is validated as a whole, committed atomically to frontend
state, and acknowledged locally. Ordinary variable assignments do not acquire a
backend or send a query, even if the default hostgroup has no servers or a backend
is already attached. Existing transaction effects of `autocommit` are preserved:
an OFF-to-ON assignment that commits an active transaction runs that operation
immediately on the backend holding the transaction, before acknowledging the SET.
The other variables remain tracked locally until the next real query. When an
immediate commit is required, the staged frontend changes take effect only after
it succeeds; a commit error discards them and preserves the prior desired values.
Intermediate autocommit assignments are retained, so `autocommit=1, autocommit=0`
still commits an active transaction that began with autocommit disabled.
Repeated assignments replace the desired values. The next real query selects its
normal destination; ProxySQL synchronizes session and user variables on that
connection before executing the query.

For example, both statements below complete without backend access:

```sql
SET @client_tag='first';
SET @client_tag='web', SESSION group_concat_max_len=4096, sql_safe_updates=ON;
```

A subsequent routed query sees `web`, `4096`, and `1` on whichever backend it
uses. Server-specific validation errors can therefore surface during pre-query
synchronization, as with ordinary tracked session variables.

## Pooling and replay

Each frontend connection holds its desired variable map; each backend
connection holds the state ProxySQL knows is materialized there. Maps are
bounded independently to 128 distinct variables and 64 KiB of stored replay
target, literal text, and any captured database name. Reassigning a name replaces its prior entry and
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
SET @name1=<captured-literal-1>,@name2=<captured-literal-2>
```

The replay is batched to the packet budget, including rendered expressions.
When the backend packet limit is unknown (the server handshake does not advertise
it), ProxySQL uses `mysql-max_allowed_packet`, just as for ordinary queries.
A smaller server limit is enforced by the server and handled as a replay error.
An individual assignment that exceeds the available budget fails the pending
query and retires the backend.

Backend map entries are committed only after each replay `SET` succeeds. Any
replay failure likewise fails the pending client query and retires the backend
rather than running the query with incorrect state. Hashes only accelerate
matching: equality also requires the exact literal kind, replay target, and raw
literal and captured interpretation context.

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

String literals retain the charset, collation, and SQL mode under which they
were assigned. Replay uses hex bytes and explicit charset conversions and
collation, so later `sql_mode`, charset, `SET NAMES`, or collation changes remain
local without reinterpreting previous values. Double-quoted identifiers under
`ANSI_QUOTES` are ineligible as string literals. Backend session-tracking
notifications that report an unexpected interpretation-context change still
activate the connection-bound safeguard.

`SET CHARACTER SET` can derive connection collation from database defaults that
are unknown to the frontend. ProxySQL captures the selected schema and its name
encoding at that SET, and resolves its default collation on the backend selected
by the next real query. This metadata lookup never runs while handling the local
SET. An intervening `USE` or `SET NAMES` does not overwrite the captured source.
An explicit tracked `character_set_database` override is resolved using that
charset's server default collation instead. As with deferred session-variable
validation, resolution observes the backend's defaults at execution time.

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
destruction clear the corresponding backend map. An ineligible `SET` never
changes the frontend map; it follows the existing connection-bound fallback.

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
