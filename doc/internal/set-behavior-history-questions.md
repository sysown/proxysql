# SET/session-variable behavior: twelve-month intent questionnaire

Status: partially answered; maintainer decisions recorded 2026-10-18. Prepared on
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

## Maintainer decisions — 2026-10-18

These decisions describe intended behavior. They do not assert that pending
production changes have been implemented by this documentation PR.

| ID | Answer / status | Intended behavior and follow-up |
| --- | --- | --- |
| E1 | A — confirmed | Tolerate the listed setup errors broadly and classify the variable as absent on that backend. |
| E2 | A — confirmed | The absence classification belongs to the backend connection object, survives ordinary reset, and is not a rejected-value cache. |
| W4 | B — change required | A client with no explicit wait_timeout must follow later global changes. Current initialization-cap behavior still needs an implementation change. |
| P1 | A — confirmed; documented | Explicit SET algorithm 1/2 wins for ordinary system SETs reaching the general parser. See the [parser selection reference](../mysql-set-parser-selection.md). |
| N6 | A — confirmed | Preserve the configuration gate on enabling GTID session tracking. |
| U7 | Clarified; misleading question retired | Hidden writes are not prevented; their use is not recommended. Replaying the frontend's recorded value on another backend is correct. |
| G1 | Open — origin investigated | Explain the origin of tracking separately from the later configurable startup default; see the [history note](pgsql-search-path-history.md). No default policy chosen. |
| G8 | Deferred — issue/RFC | Analyze pipeline reconciliation and protocol ordering in [issue #6504](https://github.com/sysown/proxysql/issues/6504) and the [RFC](pgsql-pipeline-variable-reconciliation-rfc.md) before selecting behavior. |

All other IDs remain unanswered. Their presence here does not imply approval.

## MySQL client wait_timeout

These changes entered mainline in December 2025 through
[PR #4901](https://github.com/sysown/proxysql/pull/4901). Previously the recognized
client SET was ignored; the frontend idle timer used the global policy.

### W1 — Frontend idle timeout — December 2025

**Before:** A recognized client SET wait_timeout was ignored; frontend idle expiry followed the global mysql-wait_timeout.

**After:** The client SET records a per-session frontend timeout. Idle checks use the smaller of the current global policy and that session value. The backend server variable is not changed.

**Observable effect:** A client can now shorten its own frontend connection lifetime without changing backend idle expiry.

**Question:** Should client `SET wait_timeout=N` control the **frontend connection's idle expiry**, without changing the backend server's wait_timeout?

**Answer:** Yes / No

### W2 — Global timeout remains a ceiling — December 2025

**Before:** There was only a global frontend timeout; a client SET did not affect it.

**After:** A client value is now recorded, but it cannot extend expiry beyond the current global timeout. A larger client value can receive OK while the global ceiling still applies.

**Observable effect:** For example, global 60 seconds plus client SET wait_timeout=600 still gives an effective 60-second limit.

**Question:** Should the global `mysql-wait_timeout` remain a hard upper bound, even when the client successfully sets a larger session value?

**Answer:** Yes / No

### W3 — New clamping policy — December 2025

**Before:** Because client wait_timeout was ignored, its zero or out-of-range value did not create a frontend timeout policy.

**After:** A parsed numeric value is clamped to 1–1,728,000 seconds. Zero becomes 1 second, values over 20 days become 20 days, and the client receives local OK.

**Observable effect:** An application sending SET wait_timeout=0 can now cause its frontend to expire after about one idle second, subject to scheduling.

**Question:** Should out-of-range client values receive local OK and be clamped to **1 second through 20 days**, including `0` becoming 1 second?

**Answer:** A: keep clamping; B: reject out-of-range values

### W4 — Existing sessions retain an initialization cap — December 2025

**Before:** Idle enforcement used the current global timeout, including later increases.

**After:** The session copies the global value at initialization. Enforcement subsequently takes min(current_global, saved_session_value), even if that client never sent SET wait_timeout.

**Observable effect:** Open a client with global=10 seconds, then raise global to 60: that existing client remains capped at 10; a newly initialized client gets 60. Lowering global still affects existing clients.

**Question:** For a client that **never sets wait_timeout**, what should happen when an operator raises the global timeout? Current code retains the session-initialization value as a cap.

**Answer:** **B — follow the new global value.**

**Decision:** For clients that have not explicitly set wait_timeout, later global changes must apply. The current saved initialization value is not an intended cap for those clients. Production behavior has not been changed in this PR.


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

### E1 — Additional setup errors classify the variable as absent — May 2026

**Before:** Outside the existing named exceptions, backend error 1231 or 1210 during tracked-variable setup was reported to the waiting client operation and the affected backend was destroyed.

**After:** Those codes now enter the generic tolerated-error path: mark the variable absent on that backend and resume the waiting operation. The change was motivated by wsrep, but the condition is not limited to wsrep variables.

**Observable effect:** The client may already have received local OK for its earlier SET; a later query can now execute although the backend rejected the setting ProxySQL tried to establish.

**Question:** Should setup errors 1231/1210 classify the tracked variable as absent on that backend and let the waiting client query continue? The implementation applies this broadly, beyond the wsrep cases that motivated it.

**Answer:** **A — tolerate these codes broadly for tracked variables.**

**Decision:** The backend variable is classified as absent. This is an intentional availability classification, not a cache declaring one requested value invalid.

### E2 — Backend-variable absence lasts for the connection object — May change

**Before:** The absence flag already persisted for unsupported variables. But an ordinary rejected value caused backend destruction, so that backend object did not survive carrying a newly suppressed variable.

**After:** Errors added by E1 now set the same lifetime absence flag. Later desired values are skipped too. Ordinary MySQL connection reset clears values/hashes but does not clear this flag.

**Observable effect:** Once classified absent, that variable is skipped for this backend connection object regardless of later frontend values, including after ordinary session resets. A new connection object initializes the absence flags again.

**Question:** Should one such rejection suppress **all later values of that variable** for that backend connection object's lifetime, including ordinary session resets?

**Answer:** **A — retain the absence classification for the connection object's lifetime.**

**Decision:** A new requested value does not make an absent backend variable present. Ordinary reset must not be described as clearing this availability classification.


The historical change broadened which setup errors enter an existing absence
classification. The maintainer confirmed both that classification and its
connection-object lifetime. The ordinary MySQL connection reset clears
values/hashes but does not clear `var_absent`; replacing the connection object
initializes that flag again. E1/E2 are no longer open defect/policy questions.

## MySQL backend notifications and tracking modes

[PR #5166](https://github.com/sysown/proxysql/pull/5166), integrated April 2026,
introduced optional backend notifications for system-variable changes, disabled
by default. It can learn changes made inside server-side routines and updates
the frontend and backend maps for recognized variables.

### N1 — Backend reports update frontend desired state — April 2026

**Before:** ProxySQL did not consume this new system-variable notification stream to learn changes made on the backend.

**After:** With the feature enabled, recognized values reported after successful backend work update both frontend desired state and backend metadata. This includes changes originating in stored routines.

**Observable effect:** Later backend reconciliation can reproduce the reported value instead of the older frontend value. The feature defaults to DISABLED.

**Question:** With notifications enabled, should recognized values reported by the backend become the frontend's desired values, including changes made by stored routines?

**Answer:** Yes / No

### N2 — OPTIONAL mode depends on EOF configuration — April 2026

**Before:** There was no OPTIONAL system-variable notification mode.

**After:** The new OPTIONAL mode skips setup when mysql-enable_server_deprecate_eof=false, even if the operator selected OPTIONAL.

**Observable effect:** Selecting OPTIONAL alone does not guarantee notifications are active. This is a newly introduced mode policy, not a change to the previous nonexistent mode.

**Question:** Should OPTIONAL mode do no system-variable notification tracking when `mysql-enable_server_deprecate_eof=false`?

**Answer:** Yes / No

### N3 — ENFORCED mode overrides the EOF preference — April 2026

**Before:** Normal proxied backend connections followed the enable-server-deprecate-EOF setting.

**After:** Selecting the new ENFORCED notification mode requests backend deprecate-EOF even when that setting is false. Fast-forward has a separate negotiated-client-capability path.

**Observable effect:** For ordinary proxied sessions, a previously false EOF preference no longer determines the requested capability when ENFORCED is selected.

**Question:** Should ENFORCED mode override that false setting and request backend deprecate-EOF anyway?

**Answer:** Yes / No

### N4 — Capability enforcement changes server selection — April 2026

**Before:** The new notification feature did not exclude servers for lacking its required capabilities.

**After:** For ordinary proxied sessions in ENFORCED mode, a server missing required capabilities is backed off from selection for 30 seconds.

**Observable effect:** A mixed hostgroup can use its compatible servers; a hostgroup with no eligible server may fail even an ordinary query that does not itself modify session variables. This is not Monitor shunning.

**Question:** For ordinary proxied sessions in ENFORCED mode, should a backend lacking either required capability be excluded from selection for **30 seconds**, so even unrelated queries may fail if no eligible server remains?

**Answer:** Yes / No

### N5 — Notification disable takes effect immediately — April 2026

**Before:** There was no notification-session state or runtime disable lifecycle for this feature.

**After:** Changing the mode to DISABLED immediately stops consuming reports on existing sessions, while values already recorded remain in their frontend/backend maps.

**Observable effect:** Unlike the UDV latch discussed in U5, existing notification sessions do not keep a per-session drain policy. Later hidden backend changes are no longer learned through this stream.

**Question:** When notifications are disabled at runtime, how should already connected sessions behave? Current code immediately stops consuming those notifications but keeps the values already recorded.

**Answer:** A: stop immediately, as today; B: continue tracking existing sessions until reset/disconnect

### N6 — A new configuration gate on existing GTID setup — April 2026

**Before:** The GTID setup verifier checked whether the backend advertised CLIENT_SESSION_TRACKING.

**After:** The verifier additionally requires backend DEPRECATE_EOF and mysql-enable_server_deprecate_eof=true. This extra configuration gate is not conditional on the new notification mode.

**Observable effect:** A false flag can skip GTID setup even when ordinary notifications are DISABLED, or when ENFORCED requested EOF despite that false flag. This skips setup; it does not prove that an already enabled backend stops emitting GTIDs.

**Question:** Should `mysql-enable_server_deprecate_eof=false` prevent ProxySQL from **enabling GTID session tracking**, even when ordinary notification tracking is disabled, or ENFORCED mode requested deprecate-EOF? This extra gate entered with #5166.

**Answer:** **A — preserve the configuration gate.**

**Decision:** A false mysql-enable_server_deprecate_eof setting prevents enabling GTID session tracking through this verifier, including the configuration combinations described above.


N6 is separate from N2/N3: the GTID verifier checks the configuration flag, not
just whether the connection actually negotiated the needed capabilities.

September's MariaDB GTID work added another independent source of backend SETs:
[PR #6275](https://github.com/sysown/proxysql/pull/6275).

### N7 — MariaDB GTID setup modifies a different tracking list — September 2026

**Before:** Earlier September implementations used global-position tracking and auxiliary lookup machinery. There was no retained own-transaction last_gtid setup of the current form.

**After:** The retained implementation adds last_gtid to backend session_track_system_variables when MariaDB GTID collection needs it, preserving existing entries or the wildcard. This path is independent of the ordinary notification mode.

**Observable effect:** Setting mysql-session_track_variables=DISABLED does not prevent this GTID-specific change to the backend tracking list.

**Question:** When MariaDB GTID collection is needed, may ProxySQL add `last_gtid` to backend `session_track_system_variables` even while `mysql-session_track_variables=DISABLED`?

**Answer:** Yes / No


## Parser selection and classification

These questions concern behavior introduced by selecting ParserSQL in May 2026
and subsequent scope/dispatch changes. The default SET algorithm remains 2;
the new query-processor parser setting defaults to 0.

### P1 — Two parser selectors now have precedence — May 2026

**Before:** Ordinary system SETs had algorithms 1/2; query_processor_parser was not available.

**After:** Algorithm 3 and query_processor_parser=1 were added, but the general SET handler checks explicit algorithm 1, then 2, before its algorithm-3-or-QP-parser branch. Special handlers still run earlier.

**Observable effect:** With QP parser=1 and SET algorithm=2, general system SETs still use algorithm 2. This is the contract of a new configuration combination, not a claim that an old QP setting changed meaning.

**Question:** If `query_processor_parser=1` but `set_parser_algorithm=1` or `2`, which should parse ordinary system SETs **reaching the general parser**? The explicit SET setting currently wins.

**Answer:** **A — explicit SET algorithm wins.**

**Decision:** Document this precedence explicitly. It is separate from the UDV admission prerequisite: query_processor_parser=1 can enable that analysis without overriding algorithm 1/2 for general system SETs. See the [operator/developer reference](../mysql-set-parser-selection.md).

### P2 — Parser selection can change literal preprocessing — May/July 2026

**Before:** Legacy SET preprocessing collapsed whitespace without quote awareness. Before ParserSQL integration, there was no algorithm-3 alternative.

**After:** The new ParserSQL path preserves original literal/RHS source text; May and July follow-ups further preserve function and expression spelling. Legacy preprocessing was not changed to match.

**Observable effect:** Changing parser mode can change preserved whitespace inside supported values. Equivalent value meaning is the question; identical SQL formatting is not required.

**Question:** Must supported SET literal values preserve the **same whitespace and quoting meaning across parser algorithms**? ParserSQL preserves source text that legacy preprocessing can collapse.

**Answer:** Yes / No

### P3 — Scope checking changes ParserSQL disposition — October 2026

**Before:** ParserSQL normalization could strip a target scope before session tracking decided whether the assignment belonged to frontend session state. Many standalone GLOBAL statements already took fallback through other paths.

**After:** The session-only ParserSQL call validates scopes before normalization and rejects non-session or malformed targets as a whole. The caller then uses configured fallback/locking policy.

**Observable effect:** Affected statements can move from incorrect local handling to backend execution and possible binding. The question is the binding policy for proven non-session-only operations, not whether scope validation should be removed.

**Question:** For a statement rejected by **ParserSQL's new session-only target-scope check**, should a GLOBAL/PERSIST/PERSIST_ONLY target request the normal hostgroup-locking fallback? Many standalone non-session SETs already used fallback before this change.

**Answer:** A: retain configured conservative binding; B: avoid a lasting pin when the whole statement is proven to have no session-state effects

### P4 — Temporary MariaDB wrappers stop requesting a lasting lock — May 2026

**Before:** An unrecognized SET STATEMENT ... FOR wrapper could enter unknown-SET fallback and request hostgroup locking.

**After:** Recognized wrappers are forwarded unchanged without themselves requesting that lock. A follow-up extends recognition to whitespace such as newlines/tabs.

**Observable effect:** A temporary setting for one wrapped statement no longer automatically makes later routing session-bound. Independent transaction/state pins still apply.

**Question:** Should recognized MariaDB `SET STATEMENT ... FOR ...` execute as one temporary statement wrapper **without itself requesting a lasting hostgroup lock**? This changed from fallback/binding in May.

**Answer:** Yes / No

### P5 — Parser-mode digests return to tokenizer parity — October 2026

**Before:** After ParserSQL introduction, parser mode could produce AST-derived digests differing from legacy tokenization, with fallback handling for incomplete ASTs.

**After:** The retained October implementation uses the same tokenizer/options for digest text, digest hash and first-comment handling. ParserSQL remains responsible for additional classification and SET extraction.

**Observable effect:** For operators already using parser mode, digest-based rule or statistics keys can change back to legacy-compatible forms. The proposed contract is parity for identical SQL and digest settings.

**Question:** Should switching query-processor parser mode preserve digest text, digest hash, and digest-based rule matching for the same SQL and digest settings? October changed parser mode to use tokenizer parity.

**Answer:** Yes / No


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

### U1 — A new opt-in UDV feature — August 2026

**Before:** There was no frontend UDV map, replay mode, or user_variable_tracking setting. Ordinary user-variable handling followed legacy fallback/pinning.

**After:** The new setting defaults to 0. Mode 1 admits tracking only with SET parser 3 or QP parser 1 and the other admission gates.

**Observable effect:** The feature is not enabled by default; applications opting in can acquire replayable user-variable state. The already decided correction is local acceptance of supported SETs.

**Question:** Should UDV tracking remain **opt-in and disabled by default**, with ParserSQL required for admission?

**Answer:** Yes / No

### U2 — Only a strict subset becomes replayable — August 2026

**Before:** There was no locally representable UDV assignment subset for pooled replay.

**After:** The feature admits direct supported literal AST forms in plain text SETs, while equivalent parenthesized forms, introducers/COLLATE and prepared assignments remain outside admission.

**Observable effect:** SET @x=1 can become tracked/replayable while SET @x=(1) takes fallback. These exclusions describe the new feature boundary; unsupported forms did not previously have working pooled replay.

**Question:** Should the supported local-assignment subset remain restricted to the feature's current direct literal forms, excluding equivalent parenthesized literals, character-set introducers/COLLATE forms, and prepared assignments?

**Answer:** A: retain that initial subset; B: admit additional forms when their value and interpretation can be represented safely

### U3 — New per-session replay-map limits — August 2026

**Before:** There was no frontend UDV replay map to impose these limits.

**After:** The new map is bounded to 128 distinct names and 64 KiB of stored replay-target/raw-literal bytes.

**Observable effect:** Applications using many names or large values can reach a tracking bound even when the database would accept the SQL.

**Question:** Should the fixed per-session limits remain **128 distinct names and 64 KiB of stored replay target/literal bytes**?

**Answer:** Yes / No

### U4 — Overflow changes the ownership model — August 2026

**Before:** User-variable SQL normally used legacy backend-bound handling, without a frontend replay-map overflow decision.

**After:** An otherwise supported assignment that would exceed the new map bounds leaves the old map intact and takes backend-bound fallback instead of reporting a local resource-limit error.

**Observable effect:** A session that was replayable can become bound as a consequence of map capacity. This is a new branch in the feature, not a new resource limit on MySQL itself.

**Question:** When a supported assignment exceeds those limits, should ProxySQL change that session to backend-bound fallback instead of returning a local resource-limit error?

**Answer:** A: backend-bound fallback; B: local error with previous desired state preserved

### U5 — Disabling admission does not stop existing replay — August 2026

**Before:** There was no UDV tracking state to drain when configuration changed.

**After:** Disabling mode/parser prerequisites stops new admission, but sessions with committed tracked values keep classification and replay through a latch until reset/change-user/disconnect.

**Observable effect:** Turning the feature off does not immediately eliminate its replay work for existing sessions. Accepted state is retained rather than silently forgotten.

**Question:** After UDV tracking/parser prerequisites are disabled at runtime, how should sessions with already tracked values be handled?

**Answer:** A: continue classification/replay until reset/disconnect, as today; B: synchronize and bind them on their next backend execution so pooled replay can stop

### U6 — The new tracker adds an independent multiplex pin — August 2026

**Before:** Legacy variable handling had its existing exemptions and query-rule overrides, including the applicable multiplex=2 escape path.

**After:** Mode 1 adds successful unsafe/context-fallback USER_VARIABLE ownership independently of that legacy detector, including under explicit multiplex settings.

**Observable effect:** An operator override that avoided a legacy variable pin may no longer prevent the new tracker from binding the backend. The question is which explicitly defined override scope should apply.

**Question:** While UDV tracking is active, should unsafe writes/context-change fallback force backend ownership even when query rules explicitly request multiplexing? The feature adds an independent USER_VARIABLE pin.

**Answer:** A: keep that independent pin; B: preserve the applicable explicit variable-multiplex override

### U7 — Hidden backend writes do not update recorded frontend values — August 2026

**Before:** An ordinary user-variable SET normally pinned the backend. A routine changing that variable later could keep using that owned physical connection.

**After:** Mode 1 makes supported literal state replayable and multiplexable. A hidden UDV write in a procedure, function, or trigger does not update the frontend's recorded assignment map. ProxySQL does not prevent this usage.

**Observable effect:** After an explicit SET @x=1, a routine may change the physical backend's @x to 2 without changing the recorded frontend value. Migration to another backend can replay 1. Replaying that recorded value is correct under the tracking model; the hidden mutation has not become tracked frontend state.

**Clarification:** The earlier wording “excludes this usage” conflated advice with enforcement. Hidden writes are **not recommended and not prevented**. No new detection, introspection, rejection, or ownership policy was selected.

**Answer:** Clarified by the maintainer; the earlier yes/no question is retired.

### U8 — A new replay failure policy — August 2026

**Before:** There was no internal UDV replay command before the client query.

**After:** Any internal UDV replay failure errors the waiting operation and retires the backend; this path does not use the ordinary configured query-retry decision.

**Observable effect:** Even a retryable transport failure before the actual client SQL executes can surface as a client error. The question concerns eligible guarded retries, not retries inside an active/uncertain transaction.

**Question:** If internal UDV replay has a retryable transport failure on an eligible fresh backend **before client SQL executes**, should the waiting query fail immediately or use configured retry policy?

**Answer:** A: fail and retire the backend, as today; B: allow guarded retry on a replacement backend


U2 asks about the capability boundary, not local evaluation of arbitrary SQL.
Prepared-protocol support, typed values, and interpretation context still need
their own correct implementation if that boundary expands. U6 requires a
precise decision about each override's scope before any implementation change.
Neither U5 choice silently forgets accepted state. U7 records the boundary
between recorded frontend assignments and hidden backend mutations; it does not
request new detection or enforcement. U8 preserves the
transaction, execution-progress, and bounded-retry guards in I-8.

## PostgreSQL: separate decisions

These are conditional on including PostgreSQL SET/session-variable behavior.
Shared startup/default code can affect Stable/libpq even when a change arrived
through the native-backend feature branch. The established transaction,
isolation, and truthful-reset invariants remain requirements under every answer.

### G1 — search_path joins configured startup defaults — October 2026

**Before:** search_path was optional dynamic state. When the client did not set it and no other override applied, the backend role/database default could determine it.

**After:** It is now in the critical startup group: ProxySQL fills an omitted value from pgsql-default_search_path, sends it during backend startup, and reports/records it as a startup parameter.

**Observable effect:** A role configured with tenant_schema,public can instead receive ProxySQL's configured default. Unqualified names may therefore resolve differently. This shared code also affects Stable/libpq.

**Question:** If a client omits `search_path`, whose default should apply? October promoted it into ProxySQL's critical startup defaults, overriding reliance on backend role/database defaults.

**Answer:** Open. The maintainer requested the origin and rationale before choosing.

**Follow-up:** The [search_path history note](pgsql-search-path-history.md) separates the original tracking support from the later critical-startup/default-variable change. The available policies remain A: ProxySQL's configured default; B: backend role/database default.

**Why it was added:** Original tracking (October 2025, before this audit window) avoided hostgroup locking for SET search_path. It did not expose this configurable default. The October 2026 startup promotion exposed the knob through existing generic registration. Its stated reasons were a known baseline for omitted clients, SET TO DEFAULT, backend startup materialization, and PostgreSQL 18 ParameterStatus reporting. Establishing that baseline and choosing whose default wins are related but separate decisions. Explicit client startup input still wins over the configured fallback.

### G2 — Extended SET/RESET now also executes the original SQL — March 2026

**Before:** The SET and single-variable RESET handlers could complete locally through the extended path.

**After:** They update frontend state but return to backend execution for Extended Query; Simple Query retains local completion. October additionally repairs ParameterStatus reporting.

**Observable effect:** Supported logical state changes have protocol-dependent backend requirements and work. This is separate from RESET ALL, covered by G3.

**Question:** Should supported tracked SET and **single-variable RESET** have frontend-local acceptance through both Simple and Extended Query? Since March the extended path updates frontend state and also forwards the original SQL.

**Answer:** A: local acceptance in both; B: retain backend execution for Extended Query

### G3 — An explicit Extended Query RESET ALL refusal — March 2026

**Before:** The handler did not have the new blanket extended-mode rejection and followed its local reset handling. This is not proof that every old extended sequence worked correctly.

**After:** An unlocked extended session receives feature-not-supported for RESET ALL, even as an isolated command. Already locked sessions have a separately conditioned forwarding path.

**Observable effect:** The same client reset command can succeed through Simple Query but be rejected through Extended Query.

**Question:** Should `RESET ALL` remain unsupported for an **unlocked Extended Query session**, including an isolated invocation? Already locked sessions have a separate conditional forwarding path.

**Answer:** A: retain that restriction; B: support the safe isolated form

### G4 — A safe Extended Query DISCARD ALL form becomes supported — October 2026

**Before:** The March implementation refused extended DISCARD ALL generally.

**After:** The retained October path allows an isolated transaction-free request with no earlier backend work in the unsynced batch and no queued trailing statements. Unsafe cases remain refused.

**Observable effect:** A safe isolated extended invocation can now succeed instead of receiving the blanket unsupported response.

**Question:** Should an isolated, transaction-free Extended Query `DISCARD ALL` be supported when the batch has no earlier backend work or queued trailing statements? October added that supported form while retaining unsafe-batch refusal.

**Answer:** Yes / No

### G5 — Tracked-name parse failure stops requesting a lock — May 2026

**Before:** A failure to parse a SET used ordinary fallback/locking policy.

**After:** A parse failure for a recognized tracked name is forwarded without requesting that lasting lock. Unknown names use configured fallback; October tightens classification of lookalike names.

**Observable effect:** A rejected malformed statement need not permanently bind a session, but the exception relies on the tracked-name classification. Query-rule and lock-policy conditions still apply.

**Question:** If parsing fails for a recognized tracked SET name, should ProxySQL forward it **without requesting a lasting hostgroup lock**? That exception was added in May; unknown names request the configured locking fallback.

**Answer:** A: keep that exception; B: require proof of safe effects before omitting the lock

### G6 — Transaction SET gets a no-lasting-lock exception — October 2026

**Before:** Transaction-control SETs could reach the general unparsed-SET locking fallback.

**After:** Recognized SET [LOCAL|SESSION] TRANSACTION forms are forwarded without themselves requesting a session-long hostgroup lock; they are not materialized as ordinary tracked GUC assignments.

**Observable effect:** Their classification no longer necessarily pins the session after the transaction ends. The active transaction remains subject to its normal ownership guards.

**Question:** Should `SET [LOCAL|SESSION] TRANSACTION ...` be forwarded **without itself requesting a session-long hostgroup lock**? October introduced this exception.

**Answer:** Yes / No

### G7 — Unknown transaction end preserves desired values — October 2026

**Before:** When the backend became idle without a recognized termination cause, the tracker could discard the transaction snapshot while leaving metadata for changes the server might have reverted.

**After:** Known rollback restores the snapshot and known commit keeps changes. For an unidentified end after confirmed idle, the new path keeps frontend desired values and invalidates changed backend entries for later synchronization.

**Observable effect:** If the actual end rolled back a setting, later reconciliation can reapply the frontend's changed value. This concerns choosing logical state after confirmed idle, not lending an uncertain active transaction.

**Question:** If the backend is confirmed idle but the tracker cannot tell whether the transaction committed or rolled back, which setting state should survive? October retains frontend values and invalidates changed backend entries.

**Answer:** A: preserve/replay frontend desired values; B: establish actual post-transaction values before selecting frontend state

### G8 — An explicit second-parameter pipeline disconnect — March 2026

**Before:** The verification loop used its ordinary variable-sync transition and had no explicit branch terminating the session on a second differing parameter. This does not establish that the older pipeline implementation handled all cases correctly.

**After:** In an active Extended Query pipeline, one required variable can enter the special path; encountering a second differing variable returns a fatal session result.

**Observable effect:** An eligible operation can disconnect because two supported parameters need reconciliation, rather than synchronizing all required state.

**Question:** During an active Extended Query pipeline, should needing to synchronize a **second differing parameter** be an unsupported condition that terminates the session? This restriction entered in March.

**Answer:** Deferred to [issue #6504](https://github.com/sysown/proxysql/issues/6504) and the [RFC](pgsql-pipeline-variable-reconciliation-rfc.md). Neither A (retain termination) nor B (support reconciliation) has been chosen.

**Follow-up:** Establish reachable client sequences, ordering requirements, backend-mode differences, error recovery, and tests before proposing a solution. The current fatal branch alone is not evidence that the previous implementation worked.


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
| U1–U8 | [single UDV integration](https://github.com/sysown/proxysql/commit/57dc075ec); [defaults](../../lib/MySQL_Thread.cpp#L1451), [admission gate](../../lib/mysql_connection.cpp#L3193), [bounds](../../include/MySQL_User_Variables.h#L100), [latched policy](../../lib/MySQL_Session.cpp#L3146), [independent binding policy](../../lib/Query_Processor_ParserSQL.cpp#L887), [hidden-write behavior](../mysql-user-variable-tracking.md#reads-unsafe-operations-and-context-changes), [replay failure](../../lib/MySQL_Session.cpp#L3223) |
| G1 | [critical search_path](https://github.com/sysown/proxysql/commit/212a62800), [October integration](https://github.com/sysown/proxysql/commit/2775bb222); [startup defaults](../../lib/PgSQL_Protocol.cpp#L1536), [startup baseline](../../lib/PgSQL_Connection.cpp#L1294) |
| G2–G3 / G8 | [March extended changes](https://github.com/sysown/proxysql/commit/96bc66873), [integration](https://github.com/sysown/proxysql/commit/9d921bdda), [locked-reset exception](https://github.com/sysown/proxysql/commit/abb66cc19); [SET completion](../../lib/PgSQL_Session.cpp#L4829), [RESET ALL refusal](../../lib/PgSQL_Session.cpp#L4884), [locked-session RESET path](../../lib/PgSQL_Session.cpp#L5235), [multi-parameter pipeline restriction](../../lib/PgSQL_Session.cpp#L3435) |
| G4 | [isolated DISCARD ALL](https://github.com/sysown/proxysql/commit/ddd30da59), [transaction-boundary correction](https://github.com/sysown/proxysql/commit/7a7dc7389); [DISCARD handling](../../lib/PgSQL_Session.cpp#L4995) |
| G5 | [tracked-name no-lock fallback](https://github.com/sysown/proxysql/commit/35f84c384), [unknown-name correction](https://github.com/sysown/proxysql/commit/f67714155); [fallback](../../lib/PgSQL_Session.cpp#L4806) |
| G6 | [transaction SET exception](https://github.com/sysown/proxysql/commit/b2e62e0ab), [raw-scope hardening](https://github.com/sysown/proxysql/commit/cfb7124c6); [classifier](../../lib/PgSQL_Variables.cpp#L85) |
| G7 | [unknown-end policy](https://github.com/sysown/proxysql/commit/2a951b51d); [session synchronization](../../lib/PgSQL_Session.cpp#L6739), [transaction manager](../../lib/PgSQL_ExplicitTxnStateMgr.cpp#L366) |

No executable tests were run for this history review. The current implementation
review already records the unavailable local integration infrastructure. This
questionnaire records the maintainer decisions above; other questions remain open.

Documentation validation for this revision is recorded in the PR description.
Source/history checks do not establish the runtime results of proposed probes.
