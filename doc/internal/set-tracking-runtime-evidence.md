# MySQL tracked SET runtime evidence

Review branch: `docs/invariants-expansion` (PR #6491). Source baseline:
`35e51765d32be27f2c6a4f25b3687142675f68ab` (2026-10-18). This note traces
the current user-defined-variable implementation. The traditional system-SET
parser is being reviewed separately. All behavior below is source-observed or
explicitly identified as a consequence/design judgment. **No executable tests,
daemon, backend fixture, or build were run for this note.** No build artifacts
were borrowed from another worktree. The vendored ParserSQL archive was read
with `tar -xO`, without extracting or building it.

## Controlling requirement and current mismatch

The maintainer's requested contract is that an admitted, supported tracked SET
updates frontend logical session state and returns without borrowing a backend.
Later routed execution establishes the backend differences it needs. Repeating
an identical SET, including SET NAMES, must not itself generate backend work.
This does not authorize swallowing invalid SQL, actual transaction effects,
unsupported expressions, or unsafe interpretation contexts.

The current user-variable implementation has the opposite ownership boundary:
the frontend path preflights a copy, saves assignments as pending, and forwards
the original statement through routing; frontend state becomes committed only
after backend success. See
[frontend admission](../../lib/MySQL_Session.cpp#L8512),
[routing epilogue](../../lib/MySQL_Session.cpp#L9664), and
[post-success commit](../../lib/MySQL_Session.cpp#L7307).
The old [feature document](../mysql-user-variable-tracking.md) describes that
backend-OK design; it is evidence of existing intent/history, not the controlling
requirement for this review. Historical PR #6480 and PR #6043 are not treated as
proof that current behavior meets the maintainer's requirement.

## State ownership and consumers

| Owner / producer | State it owns or produces | Consumer / consequence |
| --- | --- | --- |
| ParserSQL, then `parsersql_analyze_user_variable_set_mysql()` | A complete AST classification and an owned `UserVariableSetAnalysis`: normalized name, exact replay target, exact raw literal, literal kind, hash | Frontend QPO handler decides admission; parser arena can reset because the adapter copies source text into strings. [Analysis contract](../../include/MySQL_User_Variables.h#L32), [producer](../../lib/Query_Processor_ParserSQL.cpp#L716), [copy/reset](../../lib/Query_Processor_ParserSQL.cpp#L791) |
| `MySQL_Connection::user_variables` on the frontend connection | Desired committed state, a map bounded to 128 names and 64 KiB of replay target plus literal bytes | Pool fit, backend delta verifier, diagnostics. The same connection class owns a separate map on each backend. [Member](../../include/mysql_connection.h#L149), [state representation](../../include/MySQL_User_Variables.h#L98) |
| `MySQL_Session` | `pending_user_variable_set`, current-query safety/fallback/context flags, tracking latch, backend-authority flag, replay batches/index | Query-success handler commits pending data; request/error/reset paths clear pending data; gates and replay use session lifetime flags. [Members](../../include/MySQL_Session.h#L462) |
| `MySQL_User_Variable_State::stage()` | Copy of the old map with assignments applied in source order; output becomes visible only after every assignment passes limits | Admission throws this copy away; `commit_post_ok()` stages both maps again; replay stages each acknowledged batch. [Implementation](../../lib/MySQL_User_Variables.cpp#L81) |
| `mysql_user_variable_commit_post_ok()` | Two staged maps, frontend and selected backend | Moves both into place only when both stages succeed; it is called from `RunQuery` success, not from admission. [Helper](../../lib/mysql_connection.cpp#L3207), [caller](../../lib/MySQL_Session.cpp#L7310) |
| Backend map | ProxySQL's knowledge of already materialized user variables | `requires_CHANGE_USER()` rejects extra names; pool scoring compares desired entries; replay adds/replaces differing entries only after command success. [Reset requirement](../../lib/mysql_connection.cpp#L784), [fit](../../lib/mysql_connection.cpp#L849), [replay acknowledgement](../../lib/MySQL_User_Variables.cpp#L182) |
| `RequestEnd()` | Current request completion, not desired-session-state ownership | Applies legacy backend status detection using current-query safety, clears pending/current-query flags, then ends the request. It does not clear committed frontend state. [Completion](../../lib/MySQL_Session.cpp#L10579) |

Literal equality is collision-safe: hash equality is insufficient without equal
kind, replay target, and raw literal. Consequently exact identical assignments
compare equal for backend replay, while different spellings can still count as
differences. This equality is currently **not used to eliminate the original
frontend SET**. [Entry equality](../../lib/MySQL_User_Variables.cpp#L76),
[delta omission](../../lib/MySQL_User_Variables.cpp#L157),
[frontend admission](../../lib/MySQL_Session.cpp#L8519).

## Admission, supported subset, and gates

1. The runtime variable defaults to `0`; SET parser defaults to `2`, full-query
   parser to `0`, and SET hostgroup locking to `1`.
   [Defaults](../../lib/MySQL_Thread.cpp#L1449).
   Its registered integer range is `0..1`, alongside parser/lock variables;
   there is no `PROXYSQL31`/`PROXYSQL40` guard around this registration or the
   user-variable state machine. [Registry](../../lib/MySQL_Thread.cpp#L3107),
   [core object list](../../lib/Makefile#L145).
2. New tracking requires mode `1`, either SET parser `3` or full-query parser
   `1`, plain text COM_QUERY, and no connection-bound fallback. The session
   supplies `locked_on_hostgroup >= 0 || user_variable_backend_authoritative`
   as the fallback gate. [Pure gate](../../lib/mysql_connection.cpp#L3193),
   [session gate](../../lib/MySQL_Session.cpp#L3155),
   [text/protocol check](../../lib/MySQL_Session.cpp#L8503).
   Prepared execution goes directly to the epilogue at
   [8438](../../lib/MySQL_Session.cpp#L8438); preparation is excluded by
   `prepare_stmt_type` at [8503](../../lib/MySQL_Session.cpp#L8503).
3. Raw input containing an at-sign is analyzed independently of digest
   availability. An eligible SET needs an OK parse, full input, SET AST, at
   least one user target, **only** user targets, valid ASCII names up to 64
   decoded bytes, no backslash in quoted target names, and supported literal
   RHS forms. [Raw admission](../../lib/MySQL_Session.cpp#L8505),
   [complete-parse gate](../../lib/Query_Processor_ParserSQL.cpp#L725),
   [all-target gate](../../lib/Query_Processor_ParserSQL.cpp#L740),
   [target/RHS validation](../../lib/Query_Processor_ParserSQL.cpp#L757).
4. Supported RHS forms are string, integer, decimal, hexadecimal, bit and NULL
   AST literals, plus direct unary `+`/`-` on numeric/hex/bit literals.
   Parenthesized forms, functions, casts, references, operators and other
   shapes are not accepted by this helper.
   [Literal classifier](../../lib/Query_Processor_ParserSQL.cpp#L654).
5. One non-user target rejects the whole user analysis. Thus a general mixed
   system/user group never composes the existing trackers: it takes unsafe
   fallback before the traditional system walker. This includes otherwise
   trackable ordinary system assignments; no general tracker-composition
   mechanism is present in this path.
   [Early rejection](../../lib/Query_Processor_ParserSQL.cpp#L749),
   [fallback dispatch](../../lib/MySQL_Session.cpp#L8539).
6. Resource preflight stages the **frontend** map only, into a temporary local
   variable that is discarded. Passing it saves pending analysis and marks the
   current query safe. Exceeding limits increments a fallback counter, invokes
   normal unparsed-SET policy, and routes the original query instead of
   partially committing tracked state.
   [Preflight and dispositions](../../lib/MySQL_Session.cpp#L8519),
   [bounds](../../include/MySQL_User_Variables.h#L100),
   [copy-based staging](../../lib/MySQL_User_Variables.cpp#L81).
7. Runtime refresh updates the worker's mode/parser values. Removing mode or
   prerequisites stops new admission, but a successfully committed frontend
   sets `user_variable_tracking_latched`, which keeps classification and replay
   active until session reset. New frontend sessions do not have that latch.
   [Refresh](../../lib/MySQL_Thread.cpp#L5414),
   [drain gate](../../lib/MySQL_Session.cpp#L3146),
   [latch set](../../lib/MySQL_Session.cpp#L7314),
   [latch reset](../../lib/MySQL_Session.cpp#L1216).
8. A LOAD with mode `1` and neither prerequisite emits the fixed warning from
   [Admin_FlushVariables.cpp:674](../../lib/Admin_FlushVariables.cpp#L674).
   This feature gate is independent of optional backend
   `session_track_variables`; that separate facility reports some context
   changes, but is not required by the admission gate.

## Concrete trace: fresh frontend, empty default hostgroup

Assume a normal MySQL frontend, no established transaction, no hostgroup lock,
mode `1`, SET parser `3` or full-query parser `1`, ordinary packet size, no
rewrite/terminal query-rule response/fast-forward rule, and a nonnegative default
hostgroup with no backend server configured. Submit exactly:

```sql
SET @client_tag='web'
```

1. `STATE_SLEEP` chooses `current_hostgroup = default_hostgroup` while there is
   no transaction-persistent hostgroup or lock.
   [5995–6018](../../lib/MySQL_Session.cpp#L5995).
2. `CurrentQuery.begin()` precedes `handler_special_queries()` and then
   `process_query()`. The example is not one of the special handled forms; the
   returned QPO enters `handler___...MYSQL_COM_QUERY_qpo()`.
   [6090–6140](../../lib/MySQL_Session.cpp#L6090).
   QPO rewrite and packet/terminal OK/error policy run before UDV admission.
   [8416–8435](../../lib/MySQL_Session.cpp#L8416).
3. The raw SQL has an at-sign and passes the text/query/mode gates. The analyzer
   returns `SUPPORTED` with canonical name `client_tag`, target `@client_tag`,
   raw literal `'web'`, and STRING kind. It copies these strings before
   resetting its parser. [8512–8518](../../lib/MySQL_Session.cpp#L8512),
   [791–803](../../lib/Query_Processor_ParserSQL.cpp#L791).
4. Staging the initially empty frontend map succeeds. The candidate contains
   one entry and 16 stored bytes (11-byte target plus five-byte raw literal).
   **That candidate is not installed.** The code saves only the analysis in
   `pending_user_variable_set`, marks safe, and jumps to
   `__exit_set_destination_hostgroup`.
   [8519–8527](../../lib/MySQL_Session.cpp#L8519),
   [byte accounting](../../lib/MySQL_User_Variables.cpp#L72).
5. The epilogue applies `next_query_flagIN`, applicable destination hostgroup,
   transaction persistence, GTID writer fallback and hostgroup-lock conflict
   checks; it returns `false`, not a local OK.
   [9664–9689](../../lib/MySQL_Session.cpp#L9664).
6. The caller may run SQLi/plugin policy and create a mirror session, then calls
   `find_or_create_backend(current_hostgroup)`, sets `PROCESSING_QUERY`, assigns
   connect/query retry and delay policy, and transfers the original packet to
   `mysql_real_query`. [6141–6207](../../lib/MySQL_Session.cpp#L6141),
   [6256–6293](../../lib/MySQL_Session.cpp#L6256).
7. `PROCESSING_QUERY` establishes a max-connect deadline; an uninitialized
   backend stream pushes processing status and enters `CONNECTING_SERVER`.
   [7166–7184](../../lib/MySQL_Session.cpp#L7166).
8. `CONNECTING_SERVER` calls the normal connection-acquisition helper. Local
   pool lookup is followed by global pool lookup; the global path selects a
   server and returns null when there is no target.
   [4203–4224](../../lib/MySQL_Session.cpp#L4203),
   [10040–10053](../../lib/MySQL_Session.cpp#L10040),
   [10070–10094](../../lib/MySQL_Session.cpp#L10070),
   [global pool owner](../../lib/MySQL_HostGroups_Manager.cpp#L3021).
9. No connection increments acquisition failure, enters the waiter mechanism
   on applicable tiers, adjusts poll timeout, and returns to the connection
   wait/retry path. [10127–10174](../../lib/MySQL_Session.cpp#L10127),
   [4221–4224](../../lib/MySQL_Session.cpp#L4221).
10. At max-connect timeout the client receives ProxySQL error `9001`,
    `Max connect timeout reached while reaching hostgroup ...`; `RequestEnd()`
    clears pending state. The frontend map remains empty, since no
    `RunQuery` success occurred. [4127–4200](../../lib/MySQL_Session.cpp#L4127),
    [pending clear](../../lib/MySQL_Session.cpp#L10595).

**Source-derived outcome:** backend availability is required for this supported
SET to succeed. With the default max-connect timeout it can wait about ten
seconds before failing (default `10000` ms at
[MySQL_Thread.cpp:1370](../../lib/MySQL_Thread.cpp#L1370)). The intended local
contract would instead commit the frontend logical entry and return promptly
without any pool checkout attempt. A later routed query may legitimately fail
for lack of backend; that is a separate operation.

## Repeating the same SET

**Same frontend with a usable attached backend:** every occurrence re-enters
the same preflight/pending/goto branch. There is no equality/no-op check there.
The backend verifier first compares the old committed desired map against the
backend map; if they match, it returns without an *internal replay*. The
ordinary execution path still calls `RunQuery()` with the original packet,
which calls `async_query()` for PROCESSING_QUERY. Every backend success again
commits both maps and increments the assignment counter by the number of
targets. [Frontend path](../../lib/MySQL_Session.cpp#L8519),
[backend no-delta return](../../lib/MySQL_Session.cpp#L3179),
[ordinary execution](../../lib/MySQL_Session.cpp#L7293),
[wire-query invocation](../../lib/MySQL_Session.cpp#L6814),
[commit/counter](../../lib/MySQL_Session.cpp#L7307).
The replay-command counter can remain unchanged while the original SET still
performs backend work; checking only that counter would miss the defect.

An attached backend retained because of a transaction still runs the original
SET. Active transactions are not excluded from the literal admission gate;
later pool release and transaction-persistence checks still apply. If the
frontend is already hostgroup-locked or backend-authoritative, new user-variable
tracking admission is disabled altogether and the statement follows the
connection-bound/legacy path.
[Admission gate](../../lib/MySQL_Session.cpp#L3155),
[release conditions](../../lib/MySQL_Session.cpp#L10891).

**Same frontend after multiplexing released its backend:** exact map fit may
find a matching pooled connection and eliminate replay. It does not eliminate
checkout or execution of the original SET. [Local pool consumer](../../lib/MySQL_Thread.cpp#L7300),
[global pool consumer](../../lib/MySrvConnList.cpp#L118).

**Fresh frontend repeating another frontend's SET:** its desired map starts
empty. A pooled backend that already has `client_tag` is treated as having an
extra name and requires CHANGE_USER, because pool fit sees the old empty
frontend map, not the pending candidate. A clean backend may be selected
instead. Either way the original SET executes before the new frontend map is
committed. With no backend configured, this fresh frontend follows the failed
trace above. [Extra-name reset](../../lib/mysql_connection.cpp#L784),
[reset dispatch](../../lib/MySQL_Session.cpp#L3403),
[post-reset map clear](../../lib/MySQL_Session.cpp#L4648).

## Backend establishment and deferred delta replay

The implementation already has much of the consumer side needed for deferred
materialization, although admission currently runs an original backend SET too:

- Backend identity/schema/reset verification runs first. Backend-only UDV names
  require CHANGE_USER; assigning NULL is not used to remove a name.
  [Verifier](../../lib/MySQL_Session.cpp#L7194),
  [requires_CHANGE_USER](../../lib/mysql_connection.cpp#L784).
- At ready/generic backend state it verifies init_connect, LDAP UDV,
  autocommit, multi-statement mode, GTID/session tracking, SET NAMES and ordinary
  tracked variables, **then** user variables, before RunQuery.
  [Ordering](../../lib/MySQL_Session.cpp#L7200).
- The UDV verifier reads the frontend committed map, not pending assignments.
  Delta planning iterates the canonical-name map deterministically, omits exact
  matches, and renders `SET target=raw_literal,...`. It does not evaluate values.
  [Verifier](../../lib/MySQL_Session.cpp#L3174),
  [planner](../../lib/MySQL_User_Variables.cpp#L150).
- Packet budget uses the backend `max_allowed_pkt`, subtracting MySQL header
  plus COM_QUERY byte. A zero field uses 1024 total / 1019 query bytes. The
  connection initializes that field to zero.
  [Budget consumer](../../lib/MySQL_Session.cpp#L3189),
  [budget owner](../../lib/MySQL_User_Variables.cpp#L202),
  [initial value](../../lib/mysql_connection.cpp#L476).
- The planner refuses an individually oversized assignment with no partial
  plan; otherwise it splits deterministic batches. Successful internal commands
  update the backend map batch by batch, increment replay-command count, and
  resume the saved processing status only after the last batch.
  [Planner bounds](../../lib/MySQL_User_Variables.cpp#L163),
  [replay I/O/completion](../../lib/MySQL_Session.cpp#L7651),
  [map acknowledgement](../../lib/MySQL_User_Variables.cpp#L182).
- Packet/planning/replay or acknowledgement failure generates an error for the
  waiting frontend operation, ends the request, destroys the backend, clears
  replay work and the saved-status stack. It does not execute the client query
  against partly synchronized state or return that backend to the pool.
  [Pre-send failure](../../lib/MySQL_Session.cpp#L3193),
  [command failure](../../lib/MySQL_Session.cpp#L7700),
  [retirement owner](../../lib/MySQL_Session.cpp#L3223).

Important limits/consequences supported by this source:

1. A map can pass the 64-KiB admission bound but contain an assignment larger
   than a later backend's replay budget. Current admission does not promise
   fit on all later backends. This is a later-query failure boundary that needs
   an explicit policy/test; it is not a reason to make every small supported
   SET borrow a backend. [Admission](../../lib/MySQL_Session.cpp#L8520),
   [later budget check](../../lib/MySQL_Session.cpp#L3189).
2. Original SET processing synchronizes **old** desired state first. A SET
   shrinking/replacing an old large value can fail replay of that old value
   before its own small replacement executes on a new backend. This follows
   from the verifier reading committed state while the replacement is pending.
   [Old-state consumer](../../lib/MySQL_Session.cpp#L3179),
   [pending producer](../../lib/MySQL_Session.cpp#L8525),
   [ordering before RunQuery](../../lib/MySQL_Session.cpp#L7239).
3. Staging checks limits at each assignment, not only the final group state.
   A valid final map can transiently overflow if a new name/value is inserted
   before a later shrinking replacement. Canonical replay order can produce
   that condition. Replay can then execute successfully at MySQL but fail
   metadata staging and retire the backend. The helper test explicitly expects
   this retirement. [Stage order](../../lib/MySQL_User_Variables.cpp#L84),
   [replay order](../../lib/MySQL_User_Variables.cpp#L157),
   [acknowledgement limit](../../lib/MySQL_User_Variables.cpp#L191),
   [encoded fixture](../../test/tap/tests/unit/mysql_user_variables_unit-t.cpp#L178).
   This is an availability/fit issue, not evidence that the failure path leaks
   the retired backend.

## Group atomicity, errors, and retry lifetime

**What is atomic:** analysis returns assignments only after every target/value
passes; the map stage mutates a private candidate; post-OK helper stages both
maps before moving either into place. Duplicate targets preserve source order
in analysis and last assignment wins in map state.
[Analysis accumulation](../../lib/Query_Processor_ParserSQL.cpp#L749),
[staging](../../lib/MySQL_User_Variables.cpp#L81),
[two-map commit](../../lib/mysql_connection.cpp#L3207).
This proves tracker-map atomicity, not SQL-engine atomicity for every rejected
multi-assignment statement. The suite's backend-rejection case has only one
assignment; it does not test a valid prefix plus backend-invalid later literal.
[Existing rejection test](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1004).

**Current terminal-error policy:** connect `-1/-2`, original query `rc==-1`,
`RequestEnd()`, session reset, and fast-forward handoff clear pending analysis.
Committed maps are not updated by a failed original SET.
[Connect failure](../../lib/MySQL_Session.cpp#L4376),
[query failure](../../lib/MySQL_Session.cpp#L7419),
[request end](../../lib/MySQL_Session.cpp#L10595),
[reset](../../lib/MySQL_Session.cpp#L1212),
[handoff](../../lib/MySQL_Session.cpp#L5836).
After a successful original SET, an unexpected map-limit failure preserves both
old maps and marks backend authority/UDV status, increments fallback, and
hostgroup-locks under configured default policy.
[Success-side fallback](../../lib/MySQL_Session.cpp#L7317).

**Source-supported retry hazard (not reproduced here):**

1. A clean unlocked frontend admits supported SET and saves pending analysis.
2. An initial async-connect failure clears pending/safety before checking
   connect retries. With remaining budget and an eligible error it destroys
   the failed connection and re-enters CONNECTING_SERVER.
   [Clear](../../lib/MySQL_Session.cpp#L4379),
   [retry](../../lib/MySQL_Session.cpp#L4550).
   Likewise original-query failure clears pending/safety before retry decisions.
   [Clear before retry](../../lib/MySQL_Session.cpp#L7420),
   [retry dispatch](../../lib/MySQL_Session.cpp#L7463).
3. Allowed query retries retain configured budget and transaction/progress
   guards: reusable, not active/uncertain transaction, no multiplex pin, no
   transferred result, no more-results progress.
   [Existing guard](../../lib/MySQL_Session.cpp#L6594),
   [uncertain transaction considered active](../../lib/mysql_connection.cpp#L2910).
   Those guards must be preserved under invariants I-4 through I-8.
4. A retry resumes the processing state and original packet, not frontend QPO
   admission, so it does not recreate pending assignments. If the replacement
   execution succeeds, the `pending_user_variable_set` condition at
   [7307](../../lib/MySQL_Session.cpp#L7307) is false. Neither map records that
   SET, and the tracked-assignment counter does not reflect it.
5. Under default `set_query_lock_on_hostgroup=1`, the legacy SET detector sets
   USER_VARIABLE only when `locked_on_hostgroup > -1`. A supported original SET
   did not create such a lock. Clearing the safe flag therefore does **not**
   independently pin this clean retry backend.
   [Legacy branch](../../lib/mysql_connection.cpp#L3106),
   [default-policy branch](../../lib/mysql_connection.cpp#L3128),
   [RequestEnd consumer](../../lib/MySQL_Session.cpp#L10592).
6. If no independent transaction/pin/reuse restriction intervenes, finishQuery
   can return that backend to the pool with actual UDV state absent from its
   metadata. A fresh empty frontend can then appear to match it without reset;
   the original frontend also lacks the desired state needed for replay on a
   different backend. This is an isolation and session-state-loss risk under
   those explicit conditions.
   [Release predicate/return](../../lib/MySQL_Session.cpp#L10891),
   [map-based reset predicate](../../lib/mysql_connection.cpp#L784),
   [pool match](../../lib/MySQL_Thread.cpp#L7300).

A session-level regression must force the first attempt to fail, prove the
second original SET succeeds, inspect frontend state, then force exact physical
backend reuse by another frontend and check that no value leaks. Helper tests
for `commit_post_ok()` cannot expose this control-flow loss. Fixing the intended
frontend-local contract removes the supported-SET need for these execution
retries; legitimate routed operations still need I-8's policy and guards.

## Unsafe use, interpretation context, and lifecycle

Proven no-UDV/read-only queries receive a safe disposition; unsafe shapes first
use the normal backend synchronization path, then execute as connection-bound
fallback. The adapter delegates usage classification to vendored ParserSQL.
[Disposition](../../lib/Query_Processor_ParserSQL.cpp#L825),
[frontend fallback](../../lib/MySQL_Session.cpp#L8568).
Within `deps/parsersql/parsersql-1.1.1.tar.gz`, archive member
`ParserSQL-1.1.1/src/sql_parser/parser.cpp:1343-1422` owns the explicit read
ancestor allowlist, forbidden function/CALL/DO/placeholder/subquery shapes,
write-target/INTO detection, and incomplete-parse refusal. The downstream
adapter is the consumer at
[Query_Processor_ParserSQL.cpp:806](../../lib/Query_Processor_ParserSQL.cpp#L806).

The successful unsafe/context-change result unconditionally sets backend UDV
status and backend-authority state, even under explicit query-rule multiplex
values. Default unparsed-SET policy also creates a hostgroup lock. Explicit
multiplex policies retain their narrower hostgroup-lock behavior; `multiplex=1`
only clears the independent NO_MULTIPLEX bit and does not clear USER_VARIABLE.
[Binding policy](../../lib/Query_Processor_ParserSQL.cpp#L887),
[success consumer](../../lib/MySQL_Session.cpp#L7333),
[lock policy](../../lib/MySQL_Session.cpp#L10992),
[status flags](../../lib/mysql_connection.cpp#L3230),
[release pin](../../lib/mysql_connection.cpp#L2961).
This evidence does not justify treating arbitrary unsupported SQL as a local
success, or broadening overrides beyond their established scope.

For a nonempty frontend map, a text SET **that reaches the QPO handler**
touching `sql_mode`, `character_set_client`, `character_set_connection`,
`collation_connection`, SET NAMES or SET CHARACTER SET takes fallback before
ordinary system-SET handling. The detector checks the target/form; it does
**not** compare old and requested values. Consequently repeated SET sql_mode
requesting the current value, or a commented SET NAMES form reaching QPO, still
takes backend work and becomes backend-authoritative after success.
[Frontend context interception](../../lib/MySQL_Session.cpp#L8556),
[context names](../../lib/Query_Processor_ParserSQL.cpp#L861),
[form detector](../../lib/Query_Processor_ParserSQL.cpp#L951),
[binding](../../lib/MySQL_Session.cpp#L7333).
Avoiding reinterpretation of raw literals after a real context change is a
legitimate problem; binding every syntactically context-related SET reaching
this path, including effective no-ops, does not satisfy the requested
no-backend-work contract.

**Earlier SET NAMES fast path is a different, currently unsafe-context case.**
`handler_special_queries()` runs before QPO
([6094](../../lib/MySQL_Session.cpp#L6094)). Its plain short SET NAMES path
(packet under 100 bytes, matching prefix, no comma, valid charset/collation)
changes frontend charset, emits local OK and returns, without consulting UDV
state or setting its context-change/backend-authority flags.
[Fast-path conditions](../../lib/MySQL_Session.cpp#L1879),
[local mutation/completion](../../lib/MySQL_Session.cpp#L1956).
Thus plain `SET NAMES latin1` is not evidence that every SET NAMES forwards.
The context integration test uses `/* uv_hg_b */ SET NAMES latin1`, which avoids
this prefix path; it does not test the plain form.
[Commented test](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1111).

With previously tracked UDVs, no independent lock/authority flag, tracking mode
still enabled and session-variable notifications disabled, the local fast path
leaves both the old UDV map and tracking latch intact: `RequestEnd(NULL)` clears
only request flags/pending data. New user-variable SET admission remains enabled
(`locked_on_hostgroup` and `user_variable_backend_authoritative` are still false),
and `must_classify_and_sync_user_variables()` remains enabled by the latch.
[Request cleanup](../../lib/MySQL_Session.cpp#L10595),
[admission gate](../../lib/MySQL_Session.cpp#L3155),
[latch gate](../../lib/MySQL_Session.cpp#L3146).
The next routed operation establishes the new charset **before** user-variable
replay ([7230](../../lib/MySQL_Session.cpp#L7230)); old raw string literals can
therefore be replayed under a changed interpretation context. Entries carry no
context snapshot ([entry fields](../../include/MySQL_User_Variables.h#L46)).
An already materialized backend can retain an old user-variable value/charset
while a new backend receives a replay in the new charset, although their maps
compare equal. This is a source-supported consistency risk, not a demonstrated
runtime result here. It is tracking continuation after a bypassed context change,
not merely a deliberate suspension of new tracking.

If backend system-variable session tracking reports one of the four context
names while frontend UDV state is nonempty, it also marks backend authority and
UDV status. It checks presence of a reported name, not equality of old/new
context. [Backend notification consumer](../../lib/MySQL_Session.cpp#L6879).
Hidden server-side UDV writes are not captured by these maps: a no-at-sign
query takes the fast SAFE disposition and the implementation does not learn
the written value from this system-variable context map. The old feature doc
explicitly excludes invisible writes. Supporting those would need an explicit
new ownership/detection policy; accepting literal SET locally is not permission
to claim hidden-write replay is solved.
[No-at-sign disposition](../../lib/Query_Processor_ParserSQL.cpp#L836),
[notification processing](../../lib/MySQL_Session.cpp#L6879).

Session reset clears pending/current-query/latch/authority/replay state and
calls frontend connection reset, which clears its map. Both frontend
COM_RESET_CONNECTION and COM_CHANGE_USER use it; destruction calls reset.
Backend successful CHANGE_USER clears backend metadata only after command
success. Backend cleanup/reset and reuse obey active-transaction, pin, health,
idle-protocol and reusable conditions; the UDV map does not override them.
[Session reset](../../lib/MySQL_Session.cpp#L1207),
[frontend map reset](../../lib/MySQL_Session.cpp#L1288),
[connection map clear](../../lib/mysql_connection.cpp#L3485),
[frontend reset command](../../lib/MySQL_Session.cpp#L9844),
[change-user command](../../lib/MySQL_Session.cpp#L9760),
[destructor](../../lib/MySQL_Session.cpp#L1298),
[backend reset success](../../lib/MySQL_Session.cpp#L4648),
[cleanup release/destroy predicate](../../lib/mysql_data_stream.cpp#L1936).
Do not replace these safeguards with mandatory reset for matching safe state,
or make active/uncertain transactions shareable to avoid a SET dependency.

## Direct and indirect backend dependencies of admitted literal SET

| Dependency | Why the admitted SET currently reaches it | Required distinction |
| --- | --- | --- |
| Query rules, rewrite, explicit OK/error, packet limit | Processed before admission at [8416](../../lib/MySQL_Session.cpp#L8416) | Local tracking can retain legitimate query-policy rejection; no need to bypass it to remove checkout |
| Destination hostgroup, transaction persistence, tracked GTID fallback, lock conflict | Supported SET jumps to [9664](../../lib/MySQL_Session.cpp#L9664) | Logical session update should not require a viable route; later execution still obeys routing/transaction ownership |
| SQLi/plugin policy, optional mirror execution | Caller continues after `false` at [6141](../../lib/MySQL_Session.cpp#L6141) and [6205](../../lib/MySQL_Session.cpp#L6205) | Current continuation can generate additional work even before ordinary execution; policy/mirror behavior needs explicit handling in a local-completion change |
| Backend availability, pooling/limits/waiters, server health/lag/GTID, backend authentication, connect retries/timeouts | Normal acquisition at [4203](../../lib/MySQL_Session.cpp#L4203), [9920](../../lib/MySQL_Session.cpp#L9920), [10040](../../lib/MySQL_Session.cpp#L10040) | Supported SET should not be hostage to these; the later routed operation legitimately is |
| Username/schema/reset and all ordinary tracked-session synchronization | Pre-execution verification begins at [7194](../../lib/MySQL_Session.cpp#L7194) | Materialization should run for the later routed operation; dirty names still require safe sanitization |
| Old UDV replay, packet budget, replay network/result errors | [3174](../../lib/MySQL_Session.cpp#L3174), called before the original SET at [7239](../../lib/MySQL_Session.cpp#L7239) | Current SET can fail replay of a value it intends to replace; frontend-local update eliminates this obsolete intermediate requirement |
| Original SQL validation, execution, warnings and OK/error | [RunQuery](../../lib/MySQL_Session.cpp#L6814), [post-result path](../../lib/MySQL_Session.cpp#L7306) | An admitted local subset needs sufficient local validation/context handling; unsupported/backend-dependent syntax must retain explicit behavior |
| Backend-map post-success staging and pin fallback | [7307](../../lib/MySQL_Session.cpp#L7307) | Frontend logical admission must not depend on selected backend metadata capacity |
| Transaction status and pool release | [10891](../../lib/MySQL_Session.cpp#L10891) | Preserve transaction ownership and all release guards regardless of local SET completion |

## What current tests prove, and what they encode incorrectly for this review

The runtime test requires an ONLINE backend and opens a direct connection before
configuring its fixture; it cannot exercise a backend-free default hostgroup
as written. It enables tracking plus SET parser 3 and creates two routed
hostgroups pointing to that backend.
[Fixture prerequisite](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L594),
[configuration](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L527).

Useful session-level coverage present in the source includes values and field
types for literals, two-hostgroup replay with proven distinct physical IDs,
backend-side readers without at-sign SQL, metadata preservation, pooled reuse
isolation, reset/change-user/disconnect, unsupported fallback, prepared SET,
limits, mode/parser drain, and multiplex overrides.
[Literal/routing checks](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L648),
[metadata](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L726),
[isolation](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L849),
[reset](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L900),
[fallback](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L930),
[limits](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1020),
[drain](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1223),
[overrides](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1316),
[change user](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1371).

Tests that explicitly encode the current forwarding/post-OK design:

- `test_user_variable_routing_disposition()` asserts supported preflighted SET
  forwards through the QPO routing epilogue.
  [Unit assertion](../../test/tap/tests/unit/parsersql_unit-t.cpp#L691).
- `test_user_variable_post_ok_atomic_commit()` tests the two-map post-OK helper
  and its failure behavior. It is a helper test, not a session/network proof of
  when commitment happens. [Unit test](../../test/tap/tests/unit/parsersql_unit-t.cpp#L709).
- The runtime case expects backend rejection of `SET @backend_rejected=1e999999999`
  and no committed frontend entry/counter. This explicitly relies on backend
  validation of a form the AST classifier calls supported. A local design must
  define validation/rejection of such a literal rather than silently convert
  this into an unconditional local OK.
  [Runtime assertion](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1004).
- Mixed system/user SET is placed in the fallback set and required to preserve
  aggregate state and bind. That encodes non-composition rather than the
  requested composition of supported trackers.
  [Mixed fixture](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L935),
  [binding assertion](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L960).
- Context tests require a tracked frontend to bind after sql_mode or commented
  SET NAMES changes that reach QPO. Their useful byte/charset/collation checks can be retained, but they
  do not cover same-context no-ops.
  [Context assertions](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1089).

Replay helper tests establish deterministic omission/batching, bounded plans,
per-acknowledged-batch metadata commit, error decisions and fallback budget.
They do **not** prove the session sends only those commands, prevents the client
query on failure, retires the exact backend, or preserves transaction ownership.
[Planner helpers](../../test/tap/tests/unit/mysql_user_variables_unit-t.cpp#L101),
[completion helpers](../../test/tap/tests/unit/mysql_user_variables_unit-t.cpp#L133).
The runtime counter test asserts zero replay failures for its controlled traffic,
not actual replay-failure I/O handling.
[Counter test](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1436).

## Exact missing behavioral tests

1. **Fresh frontend; no backend configured in default hostgroup.** Enable each
   supported parser gate in turn. Submit the example SET, assert prompt OK,
   frontend aggregate count/bytes/fingerprint update, no attached backend, zero
   checkout attempts and zero backend commands. Repeat it and change it several
   times. A later explicitly routed SELECT on a configured hostgroup must
   materialize only the final desired literal and return it.
2. **Attached backend; repeated exact supported SET.** Prove backend ID and
   transaction/pin state first. Repeated exact SETs must update/retain logical
   frontend state without any backend command or acquisition. Measure original
   commands as well as replay commands; `User_variable_replay_commands == 0`
   alone is insufficient. Then execute a backend reader and prove the required
   delta occurred immediately before it.
3. **Fresh frontend matching a pooled backend.** Establish desired logical state
   locally before checkout, force an exactly matching pooled backend ID, and
   prove reuse needs neither reset nor replay. Separately force an extra-name
   backend and prove sanitization before execution and no private value leakage.
4. **Tracker composition.** Use mixed user/system groups with a representative
   matrix of all existing supported system trackers/scopes, source ordering and
   duplicate targets; no max_execution_time/wait_timeout-only carveout. Assert
   local group success/visibility and later backend materialization. Include a
   later unsupported/invalid/context-sensitive target and prove an explicit
   whole-group disposition with no partially installed logical group.
5. **SET NAMES/context no-op and real change.** With and without tracked UDVs,
   test plain short and commented/long forms separately, and repeat the effective
   current SET NAMES/sql_mode/client-charset/collation.
   Assert no backend work for proven no-ops. For a real interpretation change,
   compare bytes, charset, collation/coercibility and quote/backslash behavior
   across distinct physical backends with direct MySQL, and assert the chosen
   safe handling. The plain short SET NAMES case must verify that prior UDV
   literals are not reinterpreted while the tracking latch continues. Do not claim merely
   recognizing a context target proves that its effective value changed.
6. **Local validation boundaries.** Overflowing numeric/exponent literals,
   SQL-mode-dependent double quotes/backslashes, invalid names, malformed or
   partial SQL, multi-statements, expressions, introducers, COLLATE and prepared
   statements. Distinguish locally supported/validated updates from explicit
   errors or backend-bound unsupported handling; invalid SQL must not be
   blanket-acknowledged. Include valid-prefix/backend-invalid-later groups and
   compare authoritative results before asserting SQL-level group atomicity.
7. **Actual replay failure and budget.** Force a real second backend with
   missing/different values, multiple bounded batches, unknown/zero packet field,
   an individually oversized assignment, backend SQL error, transport failure,
   and metadata staging failure after an earlier successful batch. Prove the
   client query never executes, the frontend desired map survives, and the exact
   failed backend is retired. Include shrink/replace of old large values and a
   valid final map whose canonical replay transiently exceeds metadata bounds.
8. **Retries and isolation.** Force both first-connect failure and first-query
   failure, allow the configured eligible retry, then assert map/counter
   truthfulness, replay after a switch, and exact-ID cross-frontend isolation.
   Separately prove an established/uncertain transaction is never retried on a
   replacement backend; preserve configured retry allowance for a clean first
   borrower operation rather than imposing a blanket retry ban.
9. **Transaction effects and status.** Update supported literal desired state
   during an active transaction, inspect local OK status and retained physical
   transaction ownership, materialize before the next actual operation, and
   verify rollback/commit behavior against direct MySQL. Separately cover mixed
   autocommit/transaction characteristics and unsupported transactional SQL;
   local tracked SET must not accidentally acknowledge an actual commit effect
   without executing the required protocol operation. Existing tests begin a
   transaction only after values have already been SET.
   [Current transaction coverage](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L823).
10. **Lifecycle before first materialization.** Reset, change user, disconnect,
    runtime mode/parser disable and fast-forward transition after local desired
    state exists but before any backend checkout. Prove clearing/drain/explicit
    transition behavior and no private state leakage. Keep the existing
    post-materialization lifecycle coverage as well.

The integration measurements should use an isolated/scoped fixture, exact
backend IDs and a backend command observer or suitable counters. Observing a
correct later SELECT alone cannot distinguish frontend-local admission from
the current eager original SET. Source-level policy/helper assertions are
complementary; they cannot replace these session semantics checks.

## Unresolved questions for implementation review

- What exact literal subset can ProxySQL validate locally in the frontend's
  logical SQL mode/charset without an execution round-trip? The current adapter
  takes SQL text/length and classifies syntax; the numeric-rejection test shows
  that its `SUPPORTED` result alone is not a server-value-validity proof.
  [Signature/acceptance](../../lib/Query_Processor_ParserSQL.cpp#L716),
  [numeric fixture](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1008).
- How should a real context change preserve already assigned raw-literal
  meaning while permitting backend-free updates where safe? Current entries
  store no per-entry context snapshot or materialized value/type/charset data.
  [Entry fields](../../include/MySQL_User_Variables.h#L46).
- How will the unified SET disposition compose all supported system and user
  trackers atomically while retaining legitimate backend-bound/transactional
  cases? The present user-only early reject precedes ordinary SET handling.
  [Early dispatch](../../lib/MySQL_Session.cpp#L8514).
- What must happen when a rule switches a frontend with desired state into
  permanent fast-forward? The current handoff clears pending work and enters
  the raw forwarding path; it does not establish UDV desired state via the
  normal pre-RunQuery verifier. This needs an explicit supported transition or
  rejection policy, not an assumption that desired state is already present on
  the newly selected backend.
  [Handoff](../../lib/MySQL_Session.cpp#L5836),
  [transition](../../lib/MySQL_Session.cpp#L5896),
  [raw path](../../lib/MySQL_Session.cpp#L5710).
- What is the desired resource-fit policy when frontend state fits its hard
  bound but a later backend cannot replay it, or the final map fits but
  intermediate metadata staging does not? The current safe retirement avoids
  reuse of inconsistent metadata; it does not provide broad availability.
  [Planner/acknowledgement](../../lib/MySQL_User_Variables.cpp#L150).

All proposed behavior must retain the maintainer-agreed pooling and retry
contracts I-4 through I-8 in the main workspace's
`doc/agents/invariants.md`: exclusive ownership/session isolation,
active-or-uncertain transaction retention, cleanup without accidental commit,
direct safe reuse without mandatory reset, truthful reset metadata, and
configured retry with transaction/progress guards. Nothing in frontend-local
SET handling requires weakening those contracts.
