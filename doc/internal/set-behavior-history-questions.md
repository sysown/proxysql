# SET/session-variable behavior: twelve-month intent questionnaire

Status: awaiting maintainer answers. Prepared 2026-10-18 on
`docs/invariants-expansion`, in [PR #6491](https://github.com/sysown/proxysql/pull/6491).

Scope assumed from the current discussion: MySQL SET/session-variable behavior,
with a separate PostgreSQL section. This is not a whole-product behavior audit.
The scope clarification is pending; no unanswered question is treated as approval.

The window is 2025-10-18 through 2026-10-18. The comparison is from
`70228332135431229940279e49b6db186c6e4241` (last first-parent integration before
the window) to `a832cbb22be47fffc7a7caf9b82d1f8e76b27171` (this PR's source
endpoint before these notes). Changes are included by their integration into
the branch, not just their original author date. Closed, unmerged PR #6480 and
other unmerged branches are excluded.

Answer using the stable IDs, for example `W1=yes, W4=B, E1=B`. A yes/no answer
confirms or rejects the exact behavior described. A/B choices identify an
intended policy; neither option is preselected or recommended. Answers can be
provided in batches. Leave an ID unanswered if you want to discuss it first.

The choices are design decisions, not instructions to implement an immediate
patch. Supporting a previously unsupported case still requires correct protocol,
transaction, error, and ownership handling.

## MySQL client wait_timeout

These changes entered mainline in December 2025 through
[PR #4901](https://github.com/sysown/proxysql/pull/4901). Previously the recognized
client SET was ignored; the frontend idle timer used the global policy.

| ID | Question | Answers |
| --- | --- | --- |
| W1 | Should client `SET wait_timeout=N` control the **frontend connection's idle expiry**, without changing the backend server's wait_timeout? | Yes / No |
| W2 | Should the global `mysql-wait_timeout` remain a hard upper bound, even when the client successfully sets a larger session value? | Yes / No |
| W3 | Should out-of-range client values receive local OK and be clamped to **1 second through 20 days**, including `0` becoming 1 second? | A: keep clamping; B: reject out-of-range values |
| W4 | For a client that **never sets wait_timeout**, what should happen when an operator raises the global timeout? Current code retains the session-initialization value as a cap. | A: keep that initialization cap; B: follow the new global value |

W4 is a consequence of copying the global value into the session and taking the
minimum of that saved value and the current global policy. Lowering the global
value still takes effect. This differs from the pre-feature global-only timer;
the existing tests mainly configure the global value before opening each client.

## MySQL backend SET errors

[PR #5708](https://github.com/sysown/proxysql/pull/5708), integrated May 2026,
added errors 1231 and 1210 to the tolerated errors during materialization of
ordinary tracked system variables. Previously these value/argument errors,
outside the existing named exceptions, returned an error and destroyed the
affected backend. The new path marks the
variable absent on that connection and resumes the waiting client operation.

| ID | Question | Answers |
| --- | --- | --- |
| E1 | When a backend rejects a tracked variable's **value or arguments** with 1231/1210, should the waiting client query continue without that setting? The implementation applies this broadly, beyond the wsrep cases that motivated it. | A: tolerate these codes for all tracked variables; B: tolerate only explicitly identified unsupported-variable/backend cases and report other failures |
| E2 | Should one such rejection suppress **all later values of that variable** for that backend connection object's lifetime, including ordinary session resets? | A: keep that lifetime suppression; B: allow another attempt when the desired value changes |

These questions concern newly tolerated value errors. They do not propose
changing the older handling of a genuinely nonexistent backend variable by
accident. Skipping an unsupported feature and silently omitting a requested
execution constraint have different consequences.
The ordinary MySQL connection reset clears values/hashes but does not clear
`var_absent`; replacing the connection object initializes that flag again.

## MySQL backend notifications and tracking modes

[PR #5166](https://github.com/sysown/proxysql/pull/5166), integrated April 2026,
introduced optional backend notifications for system-variable changes, disabled
by default. It can learn changes made inside server-side routines and updates
the frontend and backend maps for recognized variables.

| ID | Question | Answers |
| --- | --- | --- |
| N1 | With notifications enabled, should recognized values reported by the backend become the frontend's desired values, including changes made by stored routines? | Yes / No |
| N2 | Should OPTIONAL mode do no system-variable notification tracking when `mysql-enable_server_deprecate_eof=false`? | Yes / No |
| N3 | Should ENFORCED mode override that false setting and request backend deprecate-EOF anyway? | Yes / No |
| N4 | For ordinary proxied sessions in ENFORCED mode, should a backend lacking either required capability be excluded from selection for **30 seconds**, so even unrelated queries may fail if no eligible server remains? | Yes / No |
| N5 | When notifications are disabled at runtime, how should already connected sessions behave? Current code immediately stops consuming those notifications but keeps the values already recorded. | A: stop immediately, as today; B: continue tracking existing sessions until reset/disconnect |
| N6 | Should `mysql-enable_server_deprecate_eof=false` prevent ProxySQL from **enabling GTID session tracking**, even when ordinary notification tracking is disabled, or ENFORCED mode requested deprecate-EOF? This extra gate entered with #5166. | A: keep the configuration gate; B: decide from the negotiated backend capability instead |

N6 is separate from N2/N3: the GTID verifier checks the configuration flag, not
just whether the connection actually negotiated the needed capabilities.

September's MariaDB GTID work added another independent source of backend SETs:
[PR #6275](https://github.com/sysown/proxysql/pull/6275).

| ID | Question | Answers |
| --- | --- | --- |
| N7 | When MariaDB GTID collection is needed, may ProxySQL add `last_gtid` to backend `session_track_system_variables` even while `mysql-session_track_variables=DISABLED`? | Yes / No |

## Parser selection and classification

These questions concern behavior introduced by selecting ParserSQL in May 2026
and subsequent scope/dispatch changes. The default SET algorithm remains 2;
the new query-processor parser setting defaults to 0.

| ID | Question | Answers |
| --- | --- | --- |
| P1 | If `query_processor_parser=1` but `set_parser_algorithm=1` or `2`, which should parse ordinary system SETs **reaching the general parser**? The explicit SET setting currently wins. | A: explicit SET algorithm wins; B: query-processor ParserSQL forces algorithm 3 |
| P2 | Must supported SET literal values preserve the **same whitespace and quoting meaning across parser algorithms**? ParserSQL preserves source text that legacy preprocessing can collapse. | Yes / No |
| P3 | For a statement rejected by **ParserSQL's new session-only target-scope check**, should a GLOBAL/PERSIST/PERSIST_ONLY target request the normal hostgroup-locking fallback? Many standalone non-session SETs already used fallback before this change. | A: retain configured conservative binding; B: avoid a lasting pin when the whole statement is proven to have no session-state effects |
| P4 | Should recognized MariaDB `SET STATEMENT ... FOR ...` execute as one temporary statement wrapper **without itself requesting a lasting hostgroup lock**? This changed from fallback/binding in May. | Yes / No |
| P5 | Should switching query-processor parser mode preserve digest text, digest hash, and digest-based rule matching for the same SQL and digest settings? October changed parser mode to use tokenizer parity. | Yes / No |

P3 retains the configured lock policy and each query-rule override's scope. Its
second choice is conditional on proven effects; it does not permit unknown
SQL or a mixed session/global statement to escape ownership safeguards. P4 does
not exempt the wrapped operation from transaction or other independent pins.

## User-defined variables

The optional UDV feature entered mainline in August 2026 through
[PR #6043](https://github.com/sysown/proxysql/pull/6043). The
[history evidence](set-behavior-history-evidence.md) distinguishes that one
integration from its many pre-merge implementation/fix commits.

The core acceptance model is already decided: supported assignments belong to
frontend desired state; they do not require a routable backend. Generic mixed
composition and compatible reuse without mandatory reset are also decided.
The questions below do not reopen those decisions.

| ID | Question | Answers |
| --- | --- | --- |
| U1 | Should UDV tracking remain **opt-in and disabled by default**, with ParserSQL required for admission? | Yes / No |
| U2 | Should the supported local-assignment subset remain restricted to the feature's current direct literal forms, excluding equivalent parenthesized literals, character-set introducers/COLLATE forms, and prepared assignments? | A: retain that initial subset; B: admit additional forms when their value and interpretation can be represented safely |
| U3 | Should the fixed per-session limits remain **128 distinct names and 64 KiB of stored replay target/literal bytes**? | Yes / No |
| U4 | When a supported assignment exceeds those limits, should ProxySQL change that session to backend-bound fallback instead of returning a local resource-limit error? | A: backend-bound fallback; B: local error with previous desired state preserved |
| U5 | After UDV tracking/parser prerequisites are disabled at runtime, how should sessions with already tracked values be handled? | A: continue classification/replay until reset/disconnect, as today; B: synchronize and bind them on their next backend execution so pooled replay can stop |
| U6 | While UDV tracking is active, should unsafe writes/context-change fallback force backend ownership even when query rules explicitly request multiplexing? The feature adds an independent USER_VARIABLE pin. | A: keep that independent pin; B: preserve the applicable explicit variable-multiplex override |
| U7 | Is it intended that UDV tracking **does not support sessions whose procedures, functions, or triggers invisibly change user variables**? Before this feature, an ordinary user-variable SET normally pinned the backend, so hidden changes could remain on that owned connection. | Yes / No |
| U8 | If internal UDV replay has a retryable transport failure on an eligible fresh backend **before client SQL executes**, should the waiting query fail immediately or use configured retry policy? | A: fail and retire the backend, as today; B: allow guarded retry on a replacement backend |

U2 asks about the capability boundary, not local evaluation of arbitrary SQL.
Prepared-protocol support, typed values, and interpretation context still need
their own correct implementation if that boundary expands. U6 requires a
precise decision about each override's scope before any implementation change.
Neither U5 choice silently forgets accepted state. A No for U7 requires a
concrete way to declare, detect, or bind hidden writes. U8 preserves the
transaction, execution-progress, and bounded-retry guards in I-8.

## PostgreSQL: separate decisions

These are conditional on including PostgreSQL SET/session-variable behavior.
Shared startup/default code can affect Stable/libpq even when a change arrived
through the native-backend feature branch. The established transaction,
isolation, and truthful-reset invariants remain requirements under every answer.

| ID | Question | Answers |
| --- | --- | --- |
| G1 | If a client omits `search_path`, whose default should apply? October promoted it into ProxySQL's critical startup defaults, overriding reliance on backend role/database defaults. | A: ProxySQL's configured default; B: backend role/database default |
| G2 | Should supported tracked SET and **single-variable RESET** have frontend-local acceptance through both Simple and Extended Query? Since March the extended path updates frontend state and also forwards the original SQL. | A: local acceptance in both; B: retain backend execution for Extended Query |
| G3 | Should `RESET ALL` remain unsupported for an **unlocked Extended Query session**, including an isolated invocation? Already locked sessions have a separate conditional forwarding path. | A: retain that restriction; B: support the safe isolated form |
| G4 | Should an isolated, transaction-free Extended Query `DISCARD ALL` be supported when the batch has no earlier backend work or queued trailing statements? October added that supported form while retaining unsafe-batch refusal. | Yes / No |
| G5 | If parsing fails for a recognized tracked SET name, should ProxySQL forward it **without requesting a lasting hostgroup lock**? That exception was added in May; unknown names request the configured locking fallback. | A: keep that exception; B: require proof of safe effects before omitting the lock |
| G6 | Should `SET [LOCAL|SESSION] TRANSACTION ...` be forwarded **without itself requesting a session-long hostgroup lock**? October introduced this exception. | Yes / No |
| G7 | If the backend is confirmed idle but the tracker cannot tell whether the transaction committed or rolled back, which setting state should survive? October retains frontend values and invalidates changed backend entries. | A: preserve/replay frontend desired values; B: establish actual post-transaction values before selecting frontend state |
| G8 | During an active Extended Query pipeline, should needing to synchronize a **second differing parameter** be an unsupported condition that terminates the session? This restriction entered in March. | A: retain connection termination; B: support reconciliation of all required parameters |

G7 concerns an unidentified termination cause **after confirmed idle**; it does
not authorize sharing a backend whose active transaction status is uncertain.
G8's alternative requires correct pipeline implementation, not sending internal
SETs arbitrarily into an unfinished client batch.

## Audited changes not presented as open policy questions

These remain part of the historical review, but are either SQL compatibility
corrections, restored behavior, consequences of an already decided contract,
or things that did not change in this window:

* January expanded algorithm 2's timezone names to three components and hyphens.
* April allowed MySQL 9+ to use the MySQL 8+ collation path. Its accidental
  MariaDB regression was restored in May; MariaDB fallback was already present
  at the twelve-month baseline.
* May added `wsrep_trx_fragment_size` and `wsrep_trx_fragment_unit` as ordinary
  tracked variables. Their local acceptance follows the already agreed model;
  the separately broadened error handling is covered by E1/E2.
* MySQL LOCAL assignments became session-scoped tracked assignments in October.
  GLOBAL/PERSIST target validation arrived in the same integration; the
  intermediate unmerged implementation is not a separately shipped behavior.
* MySQL SET TRANSACTION lists progressed from incomplete local processing,
  to whole-statement fallback on October 12, to complete local tracking on
  October 14. Session/LOCAL and next-transaction scopes remain distinct.
  Accepting an invalid suffix or dropping a characteristic is a correctness
  problem, not an alternative behavior to approve.
* The October 12 generic adapter full-input tightening was real, but MySQL's
  session-only adapter call already required a full parse after October 10.
* System-parser map coalescing/order loss, partial frontend mutation, and
  autocommit prefix acceptance predate the window. They remain findings in
  [the current implementation review](set-tracking-review.md), not newly
  attributed 2026 regressions.
* The UDV retry bookkeeping loss and plain SET NAMES context gap entered with
  the August feature interacting with older handlers. Their correction is
  required by the existing ownership/value contracts; there is no question
  asking whether unrepresented state or changed value meaning is acceptable.
* Native PostgreSQL startup/reset corrections were completed before their
  October first-parent integration. Intermediate missing-startup/fake-reset
  states from the unmerged feature branch are not separately integrated
  mainline changes.

## Evidence map

Dates here are mainline integration months; the evidence note gives the
distinction between feature commits and their integration commits. These are
source/history observations, not executed regression results.

| Questions / topic | Primary history and endpoint source |
| --- | --- |
| W1–W4 | [wait_timeout integration](https://github.com/sysown/proxysql/commit/b73160ef5), [clamping](https://github.com/sysown/proxysql/commit/0a9dc9dd2); [session initialization](../../lib/MySQL_Session.cpp#L1199), [client SET](../../lib/MySQL_Session.cpp#L9080), [effective timeout](../../lib/MySQL_Thread.cpp#L4984) |
| E1–E2 | [1231 tolerance](https://github.com/sysown/proxysql/commit/26a6d44a6), [1210 tolerance](https://github.com/sysown/proxysql/commit/d0a1313e5); [error handling](../../lib/MySQL_Session.cpp#L3879), [absence suppression](../../lib/MySQL_Session.cpp#L3121), [flag initialization](../../include/mysql_connection.h#L154), [ordinary reset](../../lib/mysql_connection.cpp#L3462) |
| N1–N6 | [notification integration](https://github.com/sysown/proxysql/commit/795b56a1e); [backend reports](../../lib/MySQL_Session.cpp#L6879), [mode gates](../../lib/MySQL_Session.cpp#L3070), [GTID gate](../../lib/MySQL_Session.cpp#L3018), [capability backoff](../../lib/MySQL_Session.cpp#L11245), [EOF request](../../lib/mysql_connection.cpp#L1040) |
| N7 | [MariaDB last_gtid change](https://github.com/sysown/proxysql/commit/7d41109cd), [integration](https://github.com/sysown/proxysql/commit/69977a509); [tracking-list expression and dispatch](../../lib/MySQL_Session.cpp#L4022) |
| P1–P2 | [ParserSQL integration](https://github.com/sysown/proxysql/commit/6fb2f1ae9), [raw function source](https://github.com/sysown/proxysql/commit/b54aaa5f7), [July production extraction change](https://github.com/sysown/proxysql/commit/e603024dd); [selector precedence](../../lib/MySQL_Session.cpp#L8671), [legacy preprocessing](../../lib/MySQL_Set_Stmt_Parser.cpp#L59), [source extraction](../../lib/Query_Processor_ParserSQL.cpp#L210) |
| P3 | [scope validation](https://github.com/sysown/proxysql/commit/596b84029); [session-only extraction](../../lib/Query_Processor_ParserSQL.cpp#L1185), [fallback policy](../../lib/MySQL_Session.cpp#L10992) |
| P4 | [wrapper passthrough](https://github.com/sysown/proxysql/commit/0c832e5ce), [whitespace extension](https://github.com/sysown/proxysql/commit/960c8bcb7); [dispatch](../../lib/MySQL_Session.cpp#L8655) |
| P5 | [tokenizer parity](https://github.com/sysown/proxysql/commit/aebb0c1e9); [adapter](../../lib/Query_Processor_ParserSQL.cpp#L446) |
| U1–U8 | [single UDV integration](https://github.com/sysown/proxysql/commit/57dc075ec); [defaults](../../lib/MySQL_Thread.cpp#L1451), [admission gate](../../lib/mysql_connection.cpp#L3193), [bounds](../../include/MySQL_User_Variables.h#L100), [latched policy](../../lib/MySQL_Session.cpp#L3146), [independent binding policy](../../lib/Query_Processor_ParserSQL.cpp#L887), [hidden-write exclusion](../mysql-user-variable-tracking.md#reads-unsafe-operations-and-context-changes), [replay failure](../../lib/MySQL_Session.cpp#L3223) |
| G1 | [critical search_path](https://github.com/sysown/proxysql/commit/212a62800), [October integration](https://github.com/sysown/proxysql/commit/2775bb222); [startup defaults](../../lib/PgSQL_Protocol.cpp#L1536), [startup baseline](../../lib/PgSQL_Connection.cpp#L1294) |
| G2–G3 / G8 | [March extended changes](https://github.com/sysown/proxysql/commit/96bc66873), [integration](https://github.com/sysown/proxysql/commit/9d921bdda), [locked-reset exception](https://github.com/sysown/proxysql/commit/abb66cc19); [SET completion](../../lib/PgSQL_Session.cpp#L4829), [RESET ALL refusal](../../lib/PgSQL_Session.cpp#L4884), [locked-session RESET path](../../lib/PgSQL_Session.cpp#L5235), [multi-parameter pipeline restriction](../../lib/PgSQL_Session.cpp#L3435) |
| G4 | [isolated DISCARD ALL](https://github.com/sysown/proxysql/commit/ddd30da59), [transaction-boundary correction](https://github.com/sysown/proxysql/commit/7a7dc7389); [DISCARD handling](../../lib/PgSQL_Session.cpp#L4995) |
| G5 | [tracked-name no-lock fallback](https://github.com/sysown/proxysql/commit/35f84c384), [unknown-name correction](https://github.com/sysown/proxysql/commit/f67714155); [fallback](../../lib/PgSQL_Session.cpp#L4806) |
| G6 | [transaction SET exception](https://github.com/sysown/proxysql/commit/b2e62e0ab), [raw-scope hardening](https://github.com/sysown/proxysql/commit/cfb7124c6); [classifier](../../lib/PgSQL_Variables.cpp#L85) |
| G7 | [unknown-end policy](https://github.com/sysown/proxysql/commit/2a951b51d); [session synchronization](../../lib/PgSQL_Session.cpp#L6739), [transaction manager](../../lib/PgSQL_ExplicitTxnStateMgr.cpp#L366) |

No executable tests were run for this history review. The current implementation
review already records the unavailable local integration infrastructure. This
questionnaire records no new maintainer decisions until answers are supplied.

The three changed review notes passed checks for 181 local references,
171 numeric source anchors, two Markdown heading anchors, 78 cited commit
objects reachable from the pinned endpoint, and unique IDs for all 34 questions.
These are documentation/history checks, not runtime proof of proposed probes.
