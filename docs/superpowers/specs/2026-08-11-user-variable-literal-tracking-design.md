# Literal User-Variable Tracking Design

**Date:** 2026-08-11
**Status:** Approved for implementation planning

## Problem

ProxySQL currently treats every MySQL user-defined variable as untracked session
state. A statement such as:

```sql
SET @browser_lang = 'en-US',
    @browser_time = '2026-08-11 18:11:12',
    @browser_timezone = 'GMT+2',
    @ip_address = '167.235.198.244'
```

falls through `MySQL_Session::unable_to_parse_set_statement()`. With
`mysql-set_query_lock_on_hostgroup=1`, ProxySQL locks the frontend session to the
current hostgroup and disables multiplexing on its backend connection. This is
safe, but disproportionately expensive for applications that only use literal
user-variable assignments as request metadata.

ParserSQL already represents SET targets and right-hand-side expressions as
typed AST nodes. ProxySQL can use that type information to distinguish a small,
safe subset of assignments from arbitrary expressions, track the resulting
session state, and synchronize it across pooled backend connections.

## Goals

- Preserve multiplexing and query routing for supported literal user-variable
  assignments.
- Preserve MySQL's value, type, character-set, collation, escaping, and error
  semantics by forwarding the client's first SET to a backend.
- Synchronize tracked user variables across backend connections and hostgroups.
- Prevent user-variable state from leaking between frontend sessions.
- Fall back to the current user-variable safety behavior whenever ProxySQL
  cannot prove an operation belongs to the supported subset, including
  hostgroup locking when `mysql-set_query_lock_on_hostgroup=1`.
- Make the feature explicitly opt-in and dependent on ParserSQL.
- Leave integer configuration values above the first implemented mode available
  for future semantics.

## Non-goals

- Evaluating expressions in ProxySQL.
- Tracking assignments performed by SELECT, prepared statements, stored
  procedures, stored functions, or triggers.
- Detecting user-variable mutations that occur entirely inside a backend.
- Supporting multi-statements containing SET plus another statement.
- Changing behavior when the feature is disabled.
- Relaxing safety for partially parsed or unknown SQL.

## Configuration

Add an integer MySQL variable:

| Variable | Default | Initial range | Meaning |
|---|---:|---:|---|
| `mysql-user_variable_tracking` | `0` | `0..1` | `0`: current behavior; `1`: conservative literal tracking |

Mode `1` is active only when either:

- `mysql-set_parser_algorithm=3`, or
- `mysql-query_processor_parser=1` selects ParserSQL for the full query path.

If mode `1` is loaded without either prerequisite, ProxySQL emits a
configuration warning and continues using the current fallback behavior. With
the default `mysql-set_query_lock_on_hostgroup=1`, that fallback pins the
session. ProxySQL does not silently force another parser setting.

Runtime disabling prevents new assignments from entering tracked state. A
session that already has tracked state continues synchronizing that state until
`COM_RESET_CONNECTION`, `COM_CHANGE_USER`, or disconnect. This avoids losing
state in the middle of a live frontend session. Moving away from the ParserSQL
prerequisite has the same drain behavior for existing state and makes new SET
assignments use the current fallback. The session latches ParserSQL-based usage
classification when its first tracked assignment commits, so later runtime
configuration changes cannot leave its existing reads unclassified.

Only values with implemented semantics are accepted by the variable validator.
The maximum may be extended when future modes are designed.

## Supported SQL

Mode `1` accepts a text-protocol SET only when all of the following are true:

1. ParserSQL returns a complete, successful parse covering the full input.
2. The statement is a single SET statement, not a prepared or multi-statement
   command.
3. Every assignment target is a MySQL user variable.
4. Every right-hand side is one of the supported literal forms.
5. The full resulting state remains within the resource limits.

The supported right-hand sides are:

- single-quoted and double-quoted string literals;
- signed or unsigned integer literals;
- signed or unsigned fixed-point and exponent-form numeric literals;
- `0x...` and `X'...'` hexadecimal literals;
- `0b...` and `B'...'` bit literals;
- `NULL`.

A sign is accepted only as a direct unary `+` or `-` applied to a numeric,
hexadecimal, or bit literal. Parenthesized values, casts, character-set
introducers, COLLATE clauses, identifiers, system-variable references,
user-variable references, functions, subqueries, operators, placeholders, and
all other expression nodes are unsupported in mode `1`.

Multiple literal user-variable assignments in one SET are supported and handled
atomically. A statement mixing user variables with system variables is not
supported in mode `1`; it follows the existing unknown-SET fallback. This keeps the
initial implementation from combining ProxySQL-intercepted system-variable
semantics with backend-confirmed user-variable semantics in one statement.
Assignments retain source order, including repeated assignments to the same
name; the final successful assignment becomes the committed map entry.

Variable names are limited to the forms ParserSQL can losslessly normalize and
re-emit, are compared case-insensitively, and must satisfy MySQL's 64-byte name
limit. An unrepresentable or malformed name makes the whole statement
unsupported.

## ParserSQL Contract

ParserSQL, rather than the ProxySQL adapter, owns lexical and AST distinctions
between literals and expressions. Required ParserSQL work lands upstream first,
with focused parser tests, and ProxySQL then consumes a tagged release by
updating the vendored archive.

The AST must distinguish at least:

- integer;
- floating/fixed/exponent number;
- string;
- hexadecimal;
- bit;
- NULL;
- unary sign;
- nonliteral expression.

The ProxySQL adapter adds a typed analysis result rather than extending the
existing lossy `map<string, vector<string>>` SET interface:

```cpp
enum class UserVariableSetStatus {
    NOT_USER_VARIABLE_SET,
    SUPPORTED,
    UNSUPPORTED,
    PARSE_ERROR
};

enum class UserVariableLiteralKind {
    STRING,
    INTEGER,
    DECIMAL,
    HEXADECIMAL,
    BIT,
    NULL_VALUE
};

struct UserVariableAssignment {
    std::string canonical_name;
    std::string replay_target;
    std::string raw_literal;
    UserVariableLiteralKind kind;
    uint64_t hash;
};

struct UserVariableSetAnalysis {
    UserVariableSetStatus status;
    std::vector<UserVariableAssignment> assignments;
};
```

`canonical_name` is the case-insensitive map key. `replay_target` is a
ParserSQL-validated, safely reconstructed `@...` target. `raw_literal` is the
exact source span for the RHS, including quotes and escapes. ProxySQL never
constructs a replay target from unchecked client text.

The analysis is all-or-nothing. It returns `SUPPORTED` only after validating
every assignment and full-input coverage. It never returns a partial assignment
list for ProxySQL to apply.

## State Model

Both frontend and backend `MySQL_Connection` objects receive a bounded map:

```text
canonical variable name -> {
    replay target,
    raw literal,
    literal kind,
    hash
}
```

The frontend map is ProxySQL's view of the logical client session. The backend
map is ProxySQL's view of the state already materialized on that physical MySQL
connection. Hashes accelerate comparison, but correctness never relies on a
hash alone: equal entries must also have the same literal kind, replay target,
and raw literal.

The initial limits for mode `1` are:

- at most 128 distinct variables per frontend session;
- at most 64 KiB total stored replay-target and literal text per frontend
session.

The same limits apply to backend maps. Reassigning an existing name replaces
its prior entry and updates accounting. A SET that would exceed either limit is
not partially tracked: ProxySQL synchronizes any previously tracked state to the
selected backend, forwards the SET, and invokes the existing unknown-SET safety
path.

## Initial SET Data Flow

For a supported literal SET:

1. ParserSQL produces a complete `UserVariableSetAnalysis`.
2. ProxySQL validates resource limits against the staged post-SET frontend map.
3. ProxySQL stores the analysis as pending query state; it does not mutate the
   committed map yet.
4. ProxySQL forwards the client's original SQL to the selected backend.
5. A backend error discards the pending state and returns the original error to
   the client.
6. A successful backend response atomically applies all pending entries to both
   the frontend map and that backend's map.
7. The query-completion status classifier is told that this was a supported
   tracked SET, so it does not set
   `STATUS_MYSQL_CONNECTION_USER_VARIABLE`.
8. Subject to the normal transaction and status checks, the backend can return
   to the pool.

Forwarding is intentional. It keeps MySQL authoritative for SQL mode, literal
validation, warnings, conversion, and version-specific behavior. ProxySQL stores
replayable syntax, not an independently evaluated value.

## Backend Selection and Synchronization

The existing connection-pool matching model is extended to include the
user-variable maps:

- `number_of_matching_session_variables()` counts equal user-variable entries
  and mismatches so a backend with the closest state is preferred.
- `requires_CHANGE_USER()` returns true when a backend has any user-variable
  name absent from the frontend map. Resetting is required because merely
  assigning NULL is not guaranteed to reproduce every aspect of an
  uninitialized variable's lifecycle and type.
- A successful backend `COM_CHANGE_USER` or reset clears its user-variable map.

After acquiring a backend, ProxySQL performs synchronization in this order:

1. username and schema;
2. ordinary tracked session variables, including charset, collation, and
   `sql_mode`;
3. tracked user variables;
4. the client query.

Ordering user variables after ordinary session state ensures the replayed raw
literals are interpreted in the same relevant session context as the original
assignment.

Missing and mismatched user variables are replayed in one deterministic,
batched SET command when the command fits the backend packet limit:

```sql
SET @name1=<raw-literal-1>, @name2=<raw-literal-2>
```

If batching cannot fit, ProxySQL sends deterministic bounded batches. Backend
map entries are committed only after each internal SET succeeds. A replay error
does not change the frontend map; it fails the pending client query and marks
the backend for reset or retirement according to the existing internal SET
error path.

Connections with matching maps need no replay. Connections with extra state are
eligible for the existing reset path rather than becoming permanently unusable.

## Query-Use Classification

Queries without an `@` byte avoid the additional usage-classification parse.
Tracked state is still synchronized before their execution because backend-side
code may read user variables.

A query containing `@` is parsed by a ParserSQL user-variable usage classifier.
The initial classifier has three results:

- `NO_USER_VARIABLE`: occurrences were only strings, comments, or unrelated
  syntax;
- `READ_ONLY`: every real user-variable AST occurrence is a read;
- `UNSAFE_OR_UNKNOWN`: the query writes a user variable, is partial, is
  malformed, is a multi-statement, or contains an AST shape whose semantics are
  not explicitly supported.

`READ_ONLY` queries, including reads of an uninitialized name, remain
multiplexable. Pool selection guarantees that a chosen backend either has the
frontend's value or has no stale extra value. The regular post-query status
classifier receives the safe classification and does not set
`STATUS_MYSQL_CONNECTION_USER_VARIABLE`.

`UNSAFE_OR_UNKNOWN` queries synchronize the current tracked map first and then
use the existing unknown-state fallback before execution. With the default
`mysql-set_query_lock_on_hostgroup=1`, this locks the hostgroup. This category
includes:

- `SELECT @x := ...` and other assignments outside SET;
- `SELECT ... INTO @x`;
- nonliteral SET assignments;
- prepared statements that use user variables;
- placeholders;
- partial or failed parses;
- unsupported AST forms.

After the fallback makes backend session state connection-bound, the selected
backend is authoritative for user-variable state and ProxySQL stops modifying
the maps for subsequent user-variable assignments.

## Hidden Backend Mutations

The MySQL session-state notification protocol reports system variables but not
user-defined variables. ProxySQL therefore cannot observe a user variable
modified entirely inside a stored procedure, stored function, or trigger.

Mode `1` supports backend-side code reading synchronized user variables, which
is a principal use case for request metadata. It does not support such code
modifying them. This constraint is documented prominently with the
configuration variable. The opt-in default prevents existing deployments from
silently accepting this narrower safety model. A hidden mutation invalidates
the backend map and can cause a later client to receive stale state, so the
constraint is a correctness and isolation requirement, not merely an
observability limitation.

## Reset and Runtime Lifecycle

- Frontend `COM_RESET_CONNECTION` clears the frontend map.
- Frontend `COM_CHANGE_USER` clears the old logical session map before the new
  identity becomes active.
- Backend `COM_CHANGE_USER`, connection reset, reconnect, and destruction clear
  the backend map.
- A failed original SET discards only its pending assignments.
- A supported reassignment becomes visible only after backend success.
- Once a session's fallback makes backend state connection-bound, existing
  tracked state remains available for diagnostics and cleanup but is no longer
  updated.

## Error Handling and Safety

- No parse result is trusted without complete input coverage.
- No statement is partially tracked.
- The original backend error is returned for a failed client SET.
- Replay failures fail the pending query rather than running it with incorrect
  state.
- Parser prerequisite failures, limits, and unsupported syntax all fail closed
  through the existing unknown-state fallback. It locks the hostgroup when
  `mysql-set_query_lock_on_hostgroup=1` and retains the pre-2.0.6 connection
  status behavior when that variable is `0`.
- Query rules that explicitly disable multiplexing continue to take precedence.
- Existing `mysql-set_query_lock_on_hostgroup` semantics remain authoritative
  for every fallback.
- New feature-specific warnings, debug reasons, and metrics never include
  user-variable values. Existing general query logging and parse-failure
  logging policies are unchanged.

## Observability

Add counters for:

- supported assignments committed;
- replay SET commands issued;
- replay failures;
- fallbacks caused by unsupported user-variable syntax;
- fallbacks caused by resource limits.

`PROXYSQL INTERNAL SESSION` reports user-variable counts, total tracked bytes,
and process-keyed aggregate state fingerprints. It does not expose variable
names, replay targets, literal values, or raw per-entry hashes because request
metadata may include credentials, tokens, or personally identifiable data.

The existing warning for an unknown SET remains for unsupported statements and
continues to honor `mysql-parse_failure_logs_digest`. A distinct debug reason
identifies ParserSQL prerequisite, unsupported AST, resource limit, or replay
failure without adding literal contents beyond existing query-logging policy.

## Compatibility

- Mode `0` has no behavioral change and remains the default.
- Parser algorithms 1 and 2 retain current behavior.
- ParserSQL mode without user-variable tracking retains current behavior.
- Supported mode-1 SET statements continue reaching MySQL, so server errors and
  warnings remain authoritative.
- Query-rule `multiplex` overrides and globally disabled multiplexing remain
  unchanged.
- MySQL and MariaDB version differences are handled by forwarding and replaying
  exact validated literal syntax. Cross-backend incompatibility surfaces as a
  replay error instead of silently changing state.

## Testing Strategy

### ParserSQL tests

- AST node type and exact source coverage for every supported literal spelling.
- Signed integer, fixed-point, exponent, hexadecimal, and bit variants.
- Escaped strings containing commas, quotes, backslashes, and `@`.
- Multi-assignment user-variable SET statements.
- Canonicalization and the 64-byte name limit.
- Rejection or nonliteral classification for functions, subqueries, variables,
  operators, casts, COLLATE, introducers, placeholders, malformed input, and
  multi-statements.
- Read-only versus write classification in SELECT and other supported statement
  types.

### ProxySQL unit tests

- Frontend/backend map insert, replace, hashing, and byte accounting.
- Limit preflight is atomic.
- Pool matching includes equal and unequal user-variable maps.
- Extra backend names require reset.
- Backend reset clears state.
- Replay batching is deterministic and safely quotes targets.
- Pending assignments commit only on success.
- Status-flag suppression occurs only for supported SET and proven read-only
  usage.

### TAP integration tests

- The reported four-variable SET produces no unknown-SET warning and does not
  lock the hostgroup.
- Values remain correct while forcing different backend connections and
  hostgroups between queries.
- String charset/collation, numeric type, hex, bit, NULL, overwrite, and
  uninitialized reads match a direct MySQL connection.
- Two frontend clients cannot observe each other's variables.
- A backend with extra state is reset before serving a frontend without it.
- Failed original assignments do not update tracked state.
- Replay errors do not execute the pending query with stale state.
- `COM_RESET_CONNECTION` and `COM_CHANGE_USER` clear state.
- Nonliteral SET, mixed system/user SET, `:=` outside SET, INTO, prepared
  statements, partial parses, limits, and missing ParserSQL prerequisites retain
  the existing safe fallback behavior.
- Runtime disable drains existing state safely and prevents new tracking.
- Query-rule multiplex overrides retain their existing behavior.

Run coverage across the repository's supported MySQL and MariaDB test groups,
including configurations with multiplexing disabled and alternate digest/parser
settings.

## Expected Code Areas

- ParserSQL tokenizer, AST, SET parser, user-variable usage classifier, and
  upstream tests; then the vendored ParserSQL release archive in ProxySQL.
- `include/Query_Processor_ParserSQL.h` and
  `lib/Query_Processor_ParserSQL.cpp` for the typed adapter contract.
- `include/mysql_connection.h` and `lib/mysql_connection.cpp` for maps, pool
  matching, reset behavior, and diagnostics.
- `include/MySQL_Session.h` and `lib/MySQL_Session.cpp` for pending SET state,
  synchronization, fallback, and result handling.
- `include/MySQL_Thread.h`, `include/proxysql_structs.h`,
  `lib/MySQL_Thread.cpp`, and admin validation for the new integer variable.
- TAP and unit-test registration files.

## Acceptance Criteria

The feature is complete when all of the following hold:

1. With defaults, behavior is unchanged.
2. With mode `1` and ParserSQL enabled, the reported literal SET remains
   multiplexable and routable.
3. Every supported value is reproduced with MySQL-equivalent value and type on
   another backend connection.
4. No backend user-variable state leaks to another frontend session.
5. Every unsupported, ambiguous, oversized, or partially parsed operation uses
   the current fallback, including hostgroup pinning when
   `mysql-set_query_lock_on_hostgroup=1`.
6. Failed original or replay SET commands never commit incorrect map state.
7. Reset and change-user operations clear the correct state.
8. Tests pass across supported backend versions and relevant configuration
   groups.
