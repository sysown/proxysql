# SET/session-variable behavior history: 2025-10-18 through 2026-10-18

The first sections cover MySQL user-defined variables; the closing sections
add the system-variable, parser, and PostgreSQL histories used by the
[intent questionnaire](set-behavior-history-questions.md). Source endpoint is
[`a832cbb22`](https://github.com/sysown/proxysql/commit/a832cbb22be47fffc7a7caf9b82d1f8e76b27171),
on the existing `docs/invariants-expansion` branch/PR #6491. Baseline is
[`702283321`](https://github.com/sysown/proxysql/commit/70228332135431229940279e49b6db186c6e4241),
the last first-parent integration before the period, committed
2025-10-17T16:41:17+07:00.

This audit used `git log BASE..END`, path/diff searches within that range,
first-parent integration history, and actual before/after source. It did not
filter by author date or search `--all`. For a side-branch commit, its integration
date below is the earliest first-parent commit that contains it, determined by
ancestry. The head of closed/unmerged PR #6480,
`d7c6943459e3ca037ab6bf676af59328490d007a`, is **not an ancestor of END** and is
not counted as a shipped behavior change.

All work stayed in `/Users/renecannao/development/orgs/sysown/proxysql`, on the
existing PR branch. The research made no branch/worktree changes or production
edits. These notes are published with the existing documentation PR.
Validation is **source/history only**: no executable tests, daemon, backend,
or build were run. Test assertions cited below are inspected evidence, not
claims that they passed during this audit. Vendored archives were inspected in
memory, without extracting/building them.

The maintainer has already decided frontend-local acceptance of supported
tracked SET, generic composition of supported trackers, and safe reuse without
mandatory reset. Those decisions are not reopened by this note. Existing
backend-OK documentation explains current history; it does not override them.
The earlier [runtime evidence](set-tracking-runtime-evidence.md) supplies the
long call trace; this file attributes changes to the integration history.

## Integration timeline and surviving changes

| First-parent integration / timestamp | Relevant merged change | Behavior that remains at END |
| --- | --- | --- |
| [PR #5736, `6fb2f1ae9`](https://github.com/sysown/proxysql/commit/6fb2f1ae994802cd6a4d8136c26a3b6d20afdcbb), 2026-05-04T16:57:19+07:00 | ParserSQL SET/full-query parser options; [registration `dcfe687a6`](https://github.com/sysown/proxysql/commit/dcfe687a6ea6661e8fe504dd0b1d039164c5f638) | Introduced SET algorithm 3/full-query parser 1 as optional parsing paths, not UDV replay. These later become alternative prerequisites for #6043. Default SET parser remains 2/full-query parser 0. |
| [PR #6043, `57dc075ec`](https://github.com/sysown/proxysql/commit/57dc075ec8df2bb767b5b90548cff80dfe734fa3), 2026-08-14T01:05:38+07:00 | Literal UDV tracking, matching, replay, reads/fallback, lifecycle and diagnostics | The new opt-in tracker, frontend/backend maps, pending-to-backend-OK ownership, resource limits, delta replay, context policy and drain gates remain. |
| [PR #6156, `6eeeff5e2`](https://github.com/sysown/proxysql/commit/6eeeff5e21c402d2669d7faeb96831da4e54fc12), 2026-09-01T13:50:01+07:00 | Query-rule permanent fast-forward; [handoff cleanup `1c2f21dbf`](https://github.com/sysown/proxysql/commit/1c2f21dbfe4801ac51b826ecfdd4de7bd0c402e9) | A new route out of normal tracked execution clears current pending UDV work before entering permanent raw forwarding. No UDV materialization guard was added to this handoff. |
| [PR #6405, `74c88dfc3`](https://github.com/sysown/proxysql/commit/74c88dfc36f98c2073a280c10599d5cf41acd8fa), 2026-10-10T18:36:52+02:00 | ParserSQL 1.1.0, [scope validation `596b84029`](https://github.com/sysown/proxysql/commit/596b84029767991eaf439eba816bae981d0ef7ad), [UDV expectations `08f4d32d3`](https://github.com/sysown/proxysql/commit/08f4d32d3c2c01a0432a7dd1d213eb1c1f1709ad) | Charset-introducer/COLLATE RHS forms become recognized AST expressions but remain unsupported for UDV tracking; whole statement still falls back. Context scope helper rejects conflicting keyword/@@ forms. The ordinary system extractor gains stricter session-scope validation; the pure UDV analyzer is not replaced by that extractor. |
| [PR #6441, `970a978ae`](https://github.com/sysown/proxysql/commit/970a978ae12eca4e4756bd0decd8bf27f2f53972), 2026-10-12T08:59:43+02:00 | [ParserSQL 1.1.1 `887b35b46`](https://github.com/sysown/proxysql/commit/887b35b460f3b83daec0a6f9f24eea5942f6d6da) | Later grammar/transaction fixes; no new literal-UDV acceptance policy. |
| [PR #6461, `c52887003`](https://github.com/sysown/proxysql/commit/c5288700311d324df38b8095953d379861bcf81d), 2026-10-13T13:54:33+02:00 | [Tokenizer digests `aebb0c1e9`](https://github.com/sysown/proxysql/commit/aebb0c1e9fe0c36e459bb8d593dc9cb17abef2e1) | Full-query-parser mode uses legacy tokenizer digests and first-comment behavior. Raw UDV admission/classification remains independent of digest availability. Query-rule matching can change back to legacy digest semantics; this is an indirect routing change, not a change to UDV literal support. |

Evidence of persistence: `git diff 57dc075ec..END` is empty for
`lib/MySQL_User_Variables.cpp`, `include/MySQL_User_Variables.h`,
`doc/mysql-user-variable-tracking.md`, the 1,493-line runtime test and state-unit
test. The literal analyzer and usage-disposition functions are also unchanged
in the adapter; its UDV-related later source edit is the scope-conflict guard.
The vendored `include/sql_parser/user_variable.h` is identical in the 1.0.11 and
1.1.1 archives, and the classifier block from `is_forbidden_user_variable_context`
through `classify_mysql_user_variable_usage` is byte-identical after removing
line-number offsets. Broader grammar can still affect what AST reaches it;
that identity is not a proof of identical parsing for every SQL input.

## Baseline and immediate pre-#6043 behavior

At BASE there is no `mysql-user_variable_tracking` setting, user-variable map,
typed literal analysis or replay status. SET parser defaults to 2 and SET
hostgroup locking to 1; keep-multiplexing exemptions default to
`tx_isolation,transaction_isolation,version`.
[Baseline defaults](https://github.com/sysown/proxysql/blob/70228332135431229940279e49b6db186c6e4241/lib/MySQL_Thread.cpp#L1058),
[exemption default](https://github.com/sysown/proxysql/blob/70228332135431229940279e49b6db186c6e4241/lib/MySQL_Thread.cpp#L1135).

For default policy, user SETs such as `SET @client_tag='web'` go to the ordinary
unknown/user-variable fallback and backend execution; no frontend logical UDV
value can be replayed elsewhere. In the ordinary SET walker, a user target is
explicitly treated as untracked. Mixed groups can mutate recognized system
tracker entries before the loop notices an unknown/user target and falls back.
That partial-tracker-mutation issue already exists at BASE and must not be
attributed to #6043.
[Baseline parser loop](https://github.com/sysown/proxysql/blob/70228332135431229940279e49b6db186c6e4241/lib/MySQL_Session.cpp#L6171),
[baseline user-target fallback](https://github.com/sysown/proxysql/blob/70228332135431229940279e49b6db186c6e4241/lib/MySQL_Session.cpp#L6607).
Immediately before #6043 its first parent still has that user-target fallback
([`811bedbef`, lines 7770 onward](https://github.com/sysown/proxysql/blob/811bedbef0c79a2e1d6ec477380896be537ec871/lib/MySQL_Session.cpp#L7770)).

For reads, the legacy backend flag detector sees at-signs in a non-SET digest
and disables multiplexing unless its configured exemptions or `multiplex=2`
apply. For a SET under lock policy 1 it relies on the frontend having already
locked the hostgroup; under lock policy 0 it performs the older at-sign scan.
`multiplex=1` clears NO_MULTIPLEX, not the independent USER_VARIABLE bit.
[Baseline detector](https://github.com/sysown/proxysql/blob/70228332135431229940279e49b6db186c6e4241/lib/mysql_connection.cpp#L2785),
[baseline status policy](https://github.com/sysown/proxysql/blob/70228332135431229940279e49b6db186c6e4241/lib/mysql_connection.cpp#L2878).
These older flag/override distinctions remain at END, with a new safe-query
bypass and new successful-fallback binding added by #6043.

Thus the statement “UDV SET needs a backend” is **inherited behavior retained
by the new feature**, not a period regression from formerly local UDV SETs.
The new discrepancy is that #6043 adds a frontend logical tracker but still
requires original backend success to populate it. That is a mismatch with the
latest maintainer decision, independently of historical backward compatibility.

## What PR #6043 changed, before versus after

All changes in this section first reach the integration line in `57dc075ec`
at the timestamp above. August 12/13 feature commits were merged together;
they are not separate mainline releases.

| Behavior | Before #6043 | At merge and END | Classification / confidence |
| --- | --- | --- | --- |
| Activation | No literal UDV replay feature | New mode integer 0..1, default 0; mode 1 needs SET parser 3 **or** query parser 1; plain text COM_QUERY only; no new admission if locked/backend-authoritative | New opt-in feature, high |
| Supported SET ownership | Original backend execution/fallback | Preflight frontend copy, save pending assignments, route original SET, commit frontend and selected-backend maps only after backend OK | New ownership rule over inherited backend dependence; latest decision requires changing it, high |
| Repeated identical SET | Original backend work | Still original backend work every time; exact matching only eliminates internal replay, not original SET or acquisition | Inherited work retained; new tracker misses local/no-op opportunity, high |
| Pure supported group | User-variable fallback/pin | Safe tracking on backend success, no UDV-related pin solely for that group; later routing can replay it | New feature, high |
| Mixed system/user group | Ordinary walker may update supported system entries then fallback | With active feature, any non-user target rejects UDV analysis before the system walker; no generic composition | New early all-or-nothing classification; composition requirement already decided, high |
| Read-only use | Legacy at-sign pin unless exempted | Proven read-only references, even uninitialized variables, bypass legacy pin after synchronization; no-at-sign query is immediately safe | New multiplexability, high |
| Unsupported/write/unknown use | Legacy SET fallback or non-SET UDV pin | Synchronize committed desired state, route original, set default hostgroup lock before execution, and on successful unsafe/context query mark backend authority/USER_VARIABLE | New broader classification/binding policy; high |
| Resource bound | No replay-map bound | Per map 128 distinct variables / 64 KiB target+raw-literal bytes; overflow falls back, executes original, then pins on success instead of partially storing group | New feature limit/fallback, high |
| Pool fit | Ordinary tracked system state only | UDV exact matches influence fit; backend-only names require sanitization; matching supported state can reuse directly | New feature, high; no mandatory reset for an already eligible exact fit |
| Replay | None | Canonical-name-order differences, bounded SET batches, per-OK backend metadata; failure errors waiting client query and retires backend | New feature/failure policy, high |
| Disable/reconfigure | No UDV map to drain | New assignments stop immediately; committed sessions keep classification/replay through a latch until reset/change user/disconnect | New drain policy, high |
| Reset/lifetime | Existing session/backend cleanup | Same lifecycle now clears frontend/backend maps and session UDV flags; pooled state can persist truthfully for matching reuse | New state lifecycle, high |

Sources:
[mode introduction `1716d6092`](https://github.com/sysown/proxysql/commit/1716d609273f72aaf71b11be7212138c6237156d),
[post-OK introduction `6781e4b36`](https://github.com/sysown/proxysql/commit/6781e4b36eea4544e5b3e221df4075f87f7f546b),
[read/context policy `e00fa6694`](https://github.com/sysown/proxysql/commit/e00fa6694c065d464b46a4ded8a68490320d6068),
[fallback/drain hardening `2556c2a75`](https://github.com/sysown/proxysql/commit/2556c2a7551301ab3b20c10f835d374ca66a2444),
[map/limits](../../include/MySQL_User_Variables.h#L98),
[runtime admission](../../lib/MySQL_Session.cpp#L8512),
[backend commit](../../lib/MySQL_Session.cpp#L7307),
[gate/drain](../../lib/MySQL_Session.cpp#L3146),
[pool fit](../../lib/mysql_connection.cpp#L784),
[replay](../../lib/MySQL_User_Variables.cpp#L150).

### Names, literals, scope and syntax boundaries

At merge and END the adapter accepts only an OK/full-input single SET whose
every target is a UDV and every RHS is a supported literal AST. It preserves
input assignment order and duplicate targets in its vector; map application
makes the last assignment win. Canonical identity lowercases ASCII while the
replay target keeps exact validated spelling. Names must be nonempty, ASCII
and no more than 64 decoded bytes; single/double/backtick quoted names with
delimiter doubling are supported, but any backslash in a quoted name falls
back. Unary signs apply to RHS literals, not variable names.
[Analyzer](../../lib/Query_Processor_ParserSQL.cpp#L709),
[identity/order test](../../test/tap/tests/unit/parsersql_unit-t.cpp#L504),
[quoted-target rejection](../../test/tap/tests/unit/parsersql_unit-t.cpp#L517).

Supported RHS forms are single/double quoted strings, integers, fixed-point or
exponent decimals, hex `0x...`/`X'...'`, bit `0b...`/`B'...'`, NULL, and direct
unary `+`/`-` on numeric/hex/bit literals. The exact kind/target/raw text is
stored; this is not a value evaluator or a proof that every numeric magnitude
is server-valid.
[Literal classifier](../../lib/Query_Processor_ParserSQL.cpp#L654),
[literal tests](../../test/tap/tests/unit/parsersql_unit-t.cpp#L479),
[backend-invalid exponent test](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1004).

Parentheses, casts, functions, identifiers, other variables, operators,
introducers, COLLATE, placeholders, prepared protocol, multi-statements,
partial input and unsupported shapes are excluded from new tracking. A mixed
group with a supported first assignment is rejected as a whole, not partly
tracked. Ordinary system-only SET continues to its existing tracker.
[All-target gate](../../lib/Query_Processor_ParserSQL.cpp#L740),
[RHS gate](../../lib/Query_Processor_ParserSQL.cpp#L777),
[rejection tests](../../test/tap/tests/unit/parsersql_unit-t.cpp#L545).

The pure UDV path does not treat GLOBAL/SESSION/LOCAL/PERSIST as alternative
namespaces for UDV state. Its `assignment_has_user_target()` requires a
NODE_USER_VARIABLE as the first target child and rejects extra target children.
Vendored SET parsing preserves keyword scopes as identifier children before
the variable, so scoped user-target forms do not become tracked UDVs. The
system-only scope checker added later is a different consumer.
[UDV target check](../../lib/Query_Processor_ParserSQL.cpp#L709),
[extra-child check](../../lib/Query_Processor_ParserSQL.cpp#L760),
[system session-only extraction](../../lib/Query_Processor_ParserSQL.cpp#L1171).
Archive evidence: `ParserSQL-1.1.1/include/sql_parser/set_parser.h:752-769`
adds a scope identifier before its UDV child; the equivalent code is at
`ParserSQL-1.0.11/include/sql_parser/set_parser.h:551-568`.

### Draft evolution that was fixed before integration

These commits explain the final feature but **must not be counted as
temporary shipped regressions**:

- [Initial bounded state `b16004e64`](https://github.com/sysown/proxysql/commit/b16004e64fcc7598ac17e714ef05d1829089b484),
  [pool match `9c7a83486`](https://github.com/sysown/proxysql/commit/9c7a834864f76432170a4d91a0c722ff0dd7c5b7),
  [replay `4b29bc53a`](https://github.com/sysown/proxysql/commit/4b29bc53a768454865cd8d8c2ad2d33ac816a5b5)
  established the new maps and consumers.
- [Replay bound `9f3c975d3`](https://github.com/sysown/proxysql/commit/9f3c975d3fe788f3d8325dc33de790ce2df74211)
  replaced use of a frontend-negotiated packet limit with a conservative
  backend-unknown floor and redacted internal replay command logging.
- [Tracking hardening `07b24298d`](https://github.com/sysown/proxysql/commit/07b24298d8af701fee17c75883b15a9d5b3f6624)
  made supported admission use the routing epilogue and replaced success-side
  map-limit assertions with safe backend authority/pinning fallback.
- [Fallback hardening `2556c2a75`](https://github.com/sysown/proxysql/commit/2556c2a7551301ab3b20c10f835d374ca66a2444)
  moved UDV analysis outside digest-dependent logic, deferred unsafe/context
  backend authority until success, and restored normal routing epilogue for
  fallbacks. Its final policy still has the retry/context holes below.
- [Replay-state hardening `4013773cb`](https://github.com/sysown/proxysql/commit/4013773cbd81375d522740431c0d1af9143e86b3)
  added ASCII-name rejection and checked staged metadata before acknowledging
  successful replay; silently ignored metadata overflow does not survive merge.
- [Signed literals `65e91e543`](https://github.com/sysown/proxysql/commit/65e91e543442d87c760f4bb72337cadba091c933)
  added direct signed hex/bit support and a missing parser reset. Signed
  integer/decimal support already existed in that branch; signed hex/bit never
  shipped as a separately omitted subset of the merged feature.
- [`98d5a1813`](https://github.com/sysown/proxysql/commit/98d5a1813fd5c9f3ab8dafd376d9f79ca03ce203)
  has the title “constrain tracked user variable names” but changes only docs
  and a state helper test. The actual ASCII production gate is in `4013773cb`.
  Titles alone would misattribute the behavior.

## Questionable surviving behavior and origin

Confidence here is about source/diff evidence, not an executed reproduction.
All probes are proposed, **not run**; the detailed control flow is already in
[runtime evidence](set-tracking-runtime-evidence.md).

| ID / origin | Before → surviving behavior; assessment | Concrete behavioral probe |
| --- | --- | --- |
| H1 / #6043, `6781e4b36` + `07b24298d` | User SET already needed a backend; the new frontend map also waits for backend OK. Exact repeats still send original SET. **High confidence; retained backend dependence/new ownership mismatch, already decided to change.** [Admission](../../lib/MySQL_Session.cpp#L8519), [commit](../../lib/MySQL_Session.cpp#L7307). | Mode1 + valid parser + empty default hostgroup: `SET @client_tag='web'` currently attempts checkout and fails; decided behavior is local OK/count1 with no checkout. Repeat with attached backend and observe original commands, not only replay counter. |
| H2 / #6043, `6781e4b36` | New pending/safe fields are cleared before old eligible retry paths. Successful retry resumes execution without re-admission, bypasses map commit; under default lock1 an otherwise clean supported SET has no lock/pin. It can return actual UDV state with empty/old metadata to pool. **High conditional source confidence; new state-lifetime/isolation risk, not an older retry-policy defect.** [Connect clear/retry](../../lib/MySQL_Session.cpp#L4379), [query clear/retry](../../lib/MySQL_Session.cpp#L7420), [legacy lock-dependent flag](../../lib/mysql_connection.cpp#L3128), [release](../../lib/MySQL_Session.cpp#L10891). | Force first-connect and first-query failure with existing retry guard proven eligible, then successful retry. Check count/fingerprint/counter, route owner elsewhere and force exact-ID reuse by fresh frontend; prove no leakage. Preserve transaction/progress guards. |
| H3 / #6043 interaction with inherited fast path | Short plain SET NAMES was already local at BASE; new raw UDV replay missed it. It changes frontend charset without authority/lock, leaves old map+latch active, and later synchronizes charset before replaying old raw literals. **High source confidence; new context-consistency risk, exact mismatch unverified.** [Fast path](../../lib/MySQL_Session.cpp#L1879), [local OK](../../lib/MySQL_Session.cpp#L1956), [latch/gate](../../lib/MySQL_Session.cpp#L3146), [ordering](../../lib/MySQL_Session.cpp#L7230). | UDV string under utf8mb4; plain `SET NAMES latin1`; alternate distinct physical backends, compare HEX/CHARSET/COLLATION/COERCIBILITY against direct MySQL. Disable optional context notifications to isolate it. Existing test uses a comment and misses this prefix path. |
| H4 / #6043 | New QPO context detector compares target/form, not effective value. Nonempty UDV map makes repeated current sql_mode or commented SET NAMES route and bind. Plain short SET NAMES has the different path H3. **High confidence; local/no-op rule already decided.** [Interception](../../lib/MySQL_Session.cpp#L8556), [detector](../../lib/Query_Processor_ParserSQL.cpp#L951). | Repeat same effective sql_mode and both plain/commented SET NAMES; measure original backend commands, authority and lock. Real context changes still need explicit safe representation/fallback. |
| H5 / #6043 | Active feature rejects any mixed system/user group before the old system walker. Before this, mixed fallback could mutate recognized system trackers first. Neither composes all supported trackers. **High confidence; composition already decided.** [Gate](../../lib/Query_Processor_ParserSQL.cpp#L749), [fallback](../../lib/MySQL_Session.cpp#L8539). | Supported user/system cross-product, both orders, duplicates, then invalid/unsupported later member; assert whole-group disposition and later materialization. No two-variable carveout. |
| H6 / #6043, `9f3c975d3` | New maps allow 64 KiB but backend-unknown replay budget is 1019 SQL bytes; oversized individual assignment fails a later operation. Backend option starts 0; only other assignment found is frontend handshake, not backend limit discovery. Original replacement SET first replays old desired state, so shrinking a large value can fail before its small replacement runs. **High source confidence; new feature fit/availability boundary.** [Init](../../lib/mysql_connection.cpp#L476), [frontend handshake](../../lib/MySQL_Protocol.cpp#L2382), [budget](../../lib/MySQL_User_Variables.cpp#L202), [old-map consumer](../../lib/MySQL_Session.cpp#L3179). | Assign a 2 KiB string on large-packet backend, switch fresh backend, read; then try replacing with small literal. Check first operation fails from old-state replay despite desired-map bound. |
| H7 / #6043, `4013773cb` | Per-assignment staging and canonical replay order can transiently overflow although final map fits. A backend-successful replay then fails metadata acknowledgement and is retired. Draft silent metadata overflow was fixed before merge; current retirement prevents inconsistent reuse. **High confidence; new availability/fit limitation, no demonstrated leak.** [Stage](../../lib/MySQL_User_Variables.cpp#L84), [replay](../../lib/MySQL_User_Variables.cpp#L157), [unit fixture](../../test/tap/tests/unit/mysql_user_variables_unit-t.cpp#L178). | Actual near-limit large `@z`; desired `@a=1,@z=0`; real replay with fitting command budget. Check final-fit behavior and exact backend retirement if acknowledgement fails. |
| H8 / #6043 | New replay failure path errors waiting client query and destroys backend; ordinary configured retries are bypassed, desired frontend state survives. **High confidence about current policy; not a claim I-8 requires every replay failure to retry.** [Replay state](../../lib/MySQL_Session.cpp#L7651), [fail/retire](../../lib/MySQL_Session.cpp#L3223). | Fail internal replay on clean first-borrow backend before actual query executes; compare retries 0/>0 and established-transaction case. Only eligible guarded retries could be considered. |
| H9 / #6043, `2556c2a75` | New successful unsafe/context fallback adds USER_VARIABLE/backend authority regardless of multiplex argument, including2; older detector still has multiplex2 escape hatch. Default non-SET unsafe classification can lock before verdict; failed query does not undo lock. **High source confidence; new policy extension; reconcile intended override scope.** [Policy](../../lib/Query_Processor_ParserSQL.cpp#L887), [consumer](../../lib/MySQL_Session.cpp#L7333), [legacy override](../../lib/mysql_connection.cpp#L3111), [lock](../../lib/MySQL_Session.cpp#L8578). | Mode0/1 × multiplex -1/0/1/2 × lock policy 0/1, successful and rejected unsafe query; inspect independent flags/release. Current unit binding matrix covers -1/0/1 only. |
| H10 / #6043 | Newly multiplexable literal state can be mutated invisibly by no-at-sign stored SQL, without updating maps. Before, original user SET normally pinned. Feature explicitly excludes mode1 deployments with hidden UDV writes. **High confidence about absent detection/documented boundary; consequence unverified.** [SAFE shortcut](../../lib/Query_Processor_ParserSQL.cpp#L836), [documented restriction](../mysql-user-variable-tracking.md#reads-unsafe-operations-and-context-changes). | Track value; call procedure/function/trigger-changing SQL with no visible at-sign; alternate backend IDs, then matching desired state on another frontend. Check actual value versus map. Read-only backend routines are already a positive test. |
| H11 / #6156, `1c2f21dbf`, integrated 2026-09-01 | New query-rule permanent fast-forward clears pending UDV assignments and bypasses normal desired-state materialization onto a newly selected backend. **High confidence about missing guard/materializer; runtime unverified.** [Cleanup](../../lib/MySQL_Session.cpp#L5836), [handoff](../../lib/MySQL_Session.cpp#L5896), [raw path](../../lib/MySQL_Session.cpp#L5710). | Track on route A; fast-forward rule sends backend reader to unused route B. Check value/type/ID. Also place transition rule on supported SET itself and inspect pending ownership. Establish state or reject unsafe transition explicitly. |

The compact probes above include numeric sizes/mode numbers intentionally;
they describe observable behavior rather than helper return-value expectations.
H2/H3/H11 require truthful state/ownership handling, not a question about whether
incorrect behavior is acceptable. H1/H4/H5 must follow the already made local,
no-op and composition decisions. No case justifies mandatory reset for an
otherwise eligible backend whose supported state already matches.

## Lifecycle, transaction and error behaviors present in the feature

- Runtime mode/parser disable drains previously committed state using the
  tracking latch. A fresh session during disable uses legacy behavior; a new
  assignment on a draining session takes fallback. Disabling is not an
  instruction to forget existing state. This policy is new in #6043 and
  remains in [gate code](../../lib/MySQL_Session.cpp#L3146) and
  [integration assertions](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1223).
- Frontend reset/change-user/disconnect clear its maps and flags. Backend
  successful CHANGE_USER clears backend metadata after successful protocol
  completion; failed reset/cleanup does not make a backend reusable.
  [Frontend reset](../../lib/MySQL_Session.cpp#L1207),
  [map clear](../../lib/mysql_connection.cpp#L3485),
  [backend success](../../lib/MySQL_Session.cpp#L4648),
  [cleanup guard](../../lib/mysql_data_stream.cpp#L1936).
- A tracked map is not an exemption from active/uncertain-transaction ownership,
  multiplex pins, result-progress guards or release conditions. The new
  admission gate itself has no active-transaction exclusion; supported literals
  currently execute on the routed/transaction-owned backend. Existing runtime
  tests only begin transactions after initial SET, so they do not prove local
  assignment semantics *inside* a transaction.
  [Gate](../../lib/mysql_connection.cpp#L3193),
  [release](../../lib/MySQL_Session.cpp#L10891),
  [existing transaction test](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L823).
- Tracker-map group staging is atomic; this does not prove that every
  backend-rejected SQL group has no partial server effects. The existing
  backend-invalid literal integration case has one target. Valid-prefix plus
  server-invalid later targets need a direct-MySQL behavioral comparison.
  [Two-map staging](../../lib/mysql_connection.cpp#L3207),
  [current single-target error](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1004).

## Existing tests that constrain the wrong ownership model

The #6043 runtime fixture requires an ONLINE backend/direct connection before
running. It checks original supported SET results, backend numeric rejection,
map counts, routing and replay, but does not check successful admission with an
empty default hostgroup, zero original backend SET work, successful-retry map
truthfulness, plain short SET NAMES context preservation, or fast-forward
materialization. These omissions survive END unchanged.
[Backend fixture prerequisite](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L594).

Helper tests explicitly require supported SET to use the routing epilogue and
test post-OK two-map commitment. Those are assertions of the existing policy,
not independent session semantics proof. Some useful map/batch tests can remain
after changing ownership; they must not be used to defend backend borrowing.
[Routing assertion](../../test/tap/tests/unit/parsersql_unit-t.cpp#L691),
[post-OK helper](../../test/tap/tests/unit/parsersql_unit-t.cpp#L709).
Likewise fallback tests require all mixed system/user groups to bind, and the
SET NAMES preservation case is deliberately commented and therefore bypasses
the old local fast path.
[Mixed assertion](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L935),
[commented context case](../../test/tap/tests/mysql-user-variable-tracking-t.cpp#L1111).

## Candidate questions only for intent not already settled

The root can use these six questions if the broader audit has not resolved them.
They do not reopen local acceptance, generic composition, safe matching reuse,
or whether metadata/isolation bugs are allowed.

1. **Activation:** Keep default `mysql-user_variable_tracking=0` and require
   SET parser 3 or full-query parser 1 for new tracking? **Yes / No.** Both choices
   still require a parser that proves the admitted subset safe.
2. **Eligibility:** Keep the current strict text-protocol/literal-only subset,
   including ASCII names, no backslash in quoted names, and rejection of
   parentheses/introducers/COLLATE/prepared SET? **Yes / No.** A “No” means
   explicitly extend locally provable cases, not evaluate arbitrary SQL.
3. **Resource overflow:** **A:** preserve 128-variable/64 KiB bounds and fall back
   to backend-bound execution when exceeded; **B:** return a client error without
   changing desired state; **C:** configurable caps, with client error on
   overflow. Any accepted assignment also needs a clear later replay-fit
   contract; accepting 64 KiB does not guarantee a 1019-byte command can carry it.
4. **Runtime disable:** **A:** preserve latched classification/replay until
   reset/change-user/disconnect while new assignments use fallback; **B:** on
   next backend execution, synchronize then bind existing tracked sessions so
   further pooled replay stops. Neither option silently forgets state.
5. **Unsafe-use rule conflict:** Should mode1 add its independent USER_VARIABLE
   pin after successful unsafe/context-changing SQL even under explicit
   multiplex 1/2 rules? **Yes / No.** If “No,” define the existing operator
   override's precise scope or explicitly reject an unsafe conflict; this does
   not authorize leaking untracked state or clearing unrelated pins.
6. **Hidden writes:** Keep procedures/functions/triggers that invisibly change
   UDVs an explicitly unsupported mode1 deployment condition? **Yes / No.**
   A “No” needs a concrete declaration/detection/ownership policy, because
   raw-query analysis and system-variable notifications cannot see those writes.

Real context preservation, replay budgets, internal replay retry policy and
fast-forward transitions remain technical decisions to document while applying
these answers. Existing I-4 through I-8 still govern private-state isolation,
transaction ownership, cleanup outcomes, truthful reset state and configured
retry/progress guards; none may be weakened to simplify SET tracking.

## Additional system-variable policy evidence

### Client wait_timeout

[PR #4901](https://github.com/sysown/proxysql/pull/4901) first integrated in
[`b73160ef5`](https://github.com/sysown/proxysql/commit/b73160ef5), committed
2025-12-07T02:43:17+07:00. Its original implementation
[`abe16e669`](https://github.com/sysown/proxysql/commit/abe16e669) was authored
in April 2025; filtering by author date would omit a change introduced during
the requested year. At BASE, wait_timeout was
[recognized but ignored](https://github.com/sysown/proxysql/blob/70228332135431229940279e49b6db186c6e4241/lib/MySQL_Variables.cpp#L46).
The integrated feature adds a frontend idle timeout and minimum-of-session/global
enforcement. It also includes
[`0a9dc9dd2`](https://github.com/sysown/proxysql/commit/0a9dc9dd2)'s silent
1-second/20-day clamping. These were one integrated feature, not separately
shipped April and December behaviors.

The original PR requests frontend expiry, rather than backend expiry, capped
by global policy. The clamp interval and snapshot-default consequences are
additional choices. Current source initializes `this->wait_timeout` from global
policy and then enforces `min(current_global, session_value)`:
[initialization](../../lib/MySQL_Session.cpp#L1199),
[client SET](../../lib/MySQL_Session.cpp#L9080),
[maintenance](../../lib/MySQL_Thread.cpp#L4984).
Thus a client opened at a 10-second global timeout that never sends SET remains
capped at 10 seconds after an operator raises the global value to 60 seconds.
The old timer used current global policy alone. This is a source-derived
consequence, not an executed measurement. Existing
[clamp cases](../../test/tap/tests/mysql-set_wait_timeout-t.cpp#L137) do not
establish the intended live-global-increase policy.

### Backend value-error suppression

[PR #5708](https://github.com/sysown/proxysql/pull/5708) integrated May 5 in
[`012fe2821`](https://github.com/sysown/proxysql/commit/012fe2821). In addition
to two wsrep descriptors and a temporary statement wrapper, it includes
[`26a6d44a6`](https://github.com/sysown/proxysql/commit/26a6d44a6) and
[`d0a1313e5`](https://github.com/sysown/proxysql/commit/d0a1313e5): errors 1231
and 1210 become generally tolerated during descriptor-backed variable setup,
beyond earlier named exceptions. Instead of reporting that setup failure and
destroying the backend, the path sets `var_absent[idx]` and resumes the waiting
operation. The wsrep motivation did not limit this code-wide condition to wsrep.
Subsequent verification skips that variable even if its desired value changes:
[error path](../../lib/MySQL_Session.cpp#L3879),
[absence check](../../lib/MySQL_Session.cpp#L3121),
[older named exception](../../lib/MySQL_Variables.cpp#L21).
The flag is initialized in
[the connection member](../../include/mysql_connection.h#L154), but
[ordinary connection reset](../../lib/mysql_connection.cpp#L3462) does not clear
it. Thus value-error suppression survives ordinary session resets and lasts
for that connection object's lifetime; it is not merely a cache of one bad
value until the next reset.
A runtime probe must establish a value the selected backend actually rejects,
then try a demonstrably accepted value on the same physical connection.

### Notifications, capability policy, and GTID coupling

[PR #5166](https://github.com/sysown/proxysql/pull/5166) first integrated April
22 in [`795b56a1e`](https://github.com/sysown/proxysql/commit/795b56a1e).
Older-authored [`4b9c08320`](https://github.com/sysown/proxysql/commit/4b9c08320)
belongs to that integration. Notification mode defaults to DISABLED. When
enabled, recognized backend reports update both frontend desired values and
backend values, including routine-driven changes. The mode is checked directly
rather than latched for existing notification sessions:
[consumer](../../lib/MySQL_Session.cpp#L6879),
[mode check](../../lib/MySQL_Session.cpp#L7349).

OPTIONAL respects a disabled server-deprecate-EOF setting; ENFORCED requests
EOF anyway and backs unsupported servers off for 30 seconds. Permanent
fast-forward has its own client-capability exception:
[setup](../../lib/MySQL_Session.cpp#L3070),
[connect flags](../../lib/mysql_connection.cpp#L1040),
[enforcement](../../lib/MySQL_Session.cpp#L11245).
The same integration adds backend DEPRECATE_EOF and global enable-EOF tests to
the older GTID verifier, which previously checked CLIENT_SESSION_TRACKING alone.
That gate is not conditional on the new notification mode, and it checks the
configuration flag even if ENFORCED requested the capability:
[GTID verifier](../../lib/MySQL_Session.cpp#L3018). This is N6's cross-feature
behavior, distinct from merely enabling the new notification feature.

September's [PR #6275](https://github.com/sysown/proxysql/pull/6275), integrated
in [`69977a509`](https://github.com/sysown/proxysql/commit/69977a509), replaces
the temporary MariaDB global-position lookup design with own-transaction
last_gtid reporting in
[`7d41109cd`](https://github.com/sysown/proxysql/commit/7d41109cd).
The GTID setup path may add last_gtid to the backend tracking list even when
ordinary notifications are DISABLED, preserving the existing list/wildcard:
[expression and dispatch](../../lib/MySQL_Session.cpp#L4022).
The auxiliary lookup is not retained endpoint behavior.

### Variable catalogue and charset compatibility

The full `mysql_tracked_variables[]` BASE/END comparison adds two descriptors:
wsrep_trx_fragment_size and wsrep_trx_fragment_unit, introduced in
[`a5714d56f`](https://github.com/sysown/proxysql/commit/a5714d56f) and integrated
with #5708. No mixed-SET-specific allowlist was added in mainline.

MySQL 9+ high-ID collation compatibility expanded through
[`7c6f42bcd`](https://github.com/sysown/proxysql/commit/7c6f42bcd), integrated
April 16 in [`13ff9d767`](https://github.com/sysown/proxysql/commit/13ff9d767).
Its numeric-major check temporarily bypassed MariaDB's older fallback.
[`d8e51349e`](https://github.com/sysown/proxysql/commit/d8e51349e), integrated
May 24 in [`453c7554b`](https://github.com/sysown/proxysql/commit/453c7554b),
restored MariaDB family handling. The endpoint is
[validate_charset](../../lib/MySQL_Variables.cpp#L348). The net behavior change
is MySQL 9+ handling; MariaDB fallback itself predates BASE.

## Parser and PostgreSQL integration cross-check

Separate read-only passes checked these actual diffs and earliest first-parent
integrations. They support the non-UDV questions without presenting draft
branch stages as separately integrated mainline behavior.

| Mainline integration | Before → retained behavior | Primary evidence |
| --- | --- | --- |
| January 2026, #5280 | Algorithm 2's two-component word-only timezone syntax → additional three-component/hyphenated names; no default parser switch. | [6e9abed58](https://github.com/sysown/proxysql/commit/6e9abed58), [integration ef872c7f4](https://github.com/sysown/proxysql/commit/ef872c7f4) |
| May 4, #5736 | Algorithms 1/2 only → optional SET algorithm 3 and full-query parser 1. Explicit algorithm 1/2 branches still win for general system SETs. | [dcfe687a6](https://github.com/sysown/proxysql/commit/dcfe687a6), [146a977c2](https://github.com/sysown/proxysql/commit/146a977c2), [selector](../../lib/MySQL_Session.cpp#L8671) |
| May 24 and July 9 | ParserSQL-emitted expression text → verbatim function source, then original MySQL RHS extraction. July's test-titled commit changes production code. | [b54aaa5f7](https://github.com/sysown/proxysql/commit/b54aaa5f7), [e603024dd](https://github.com/sysown/proxysql/commit/e603024dd), [July integration](https://github.com/sysown/proxysql/commit/65214405e) |
| May 5/24 | MariaDB temporary wrapper could request unknown-SET binding → recognized wrapper forwards without itself requesting a lock; later whitespace recognition expands. | [0c832e5ce](https://github.com/sysown/proxysql/commit/0c832e5ce), [960c8bcb7](https://github.com/sysown/proxysql/commit/960c8bcb7) |
| October 10, #6405 | LOCAL missed ordinary tracking dispatch; ParserSQL could normalize away target scope → LOCAL session support plus pre-normalization non-session/malformed-scope rejection. | [47670465f](https://github.com/sysown/proxysql/commit/47670465f), [596b84029](https://github.com/sysown/proxysql/commit/596b84029) |
| October 12/14 | SET TRANSACTION could process a prefix → full-input failure forwards whole statement → valid two-characteristic lists tracked in full. | [6a619700d](https://github.com/sysown/proxysql/commit/6a619700d), [0c03db15f](https://github.com/sysown/proxysql/commit/0c03db15f), [2ccb3121e](https://github.com/sysown/proxysql/commit/2ccb3121e) |
| October 13, #6461 | Parser-mode digest strategy could differ → tokenizer parity for digest/hash/first-comment options, with ParserSQL used for classification and SET extraction. | [aebb0c1e9](https://github.com/sysown/proxysql/commit/aebb0c1e9), [integration c52887003](https://github.com/sysown/proxysql/commit/c52887003) |
| March 9, #5444 | PG extended SET/RESET could finish locally; sync loop immediately transitioned → extended SET/single RESET forwards original after frontend update; RESET ALL refusal; second-difference pipeline termination. | [96bc66873](https://github.com/sysown/proxysql/commit/96bc66873), [integration 9d921bdda](https://github.com/sysown/proxysql/commit/9d921bdda), [pipeline restriction](../../lib/PgSQL_Session.cpp#L3435) |
| May 24 | PG tracked-name parse failure requested ordinary lock fallback → forwarded without requesting lock; full-input requirement added and unknown-name classification later hardened. | [35f84c384](https://github.com/sysown/proxysql/commit/35f84c384), [d7976aca1](https://github.com/sysown/proxysql/commit/d7976aca1), [f67714155](https://github.com/sysown/proxysql/commit/f67714155) |
| October 1, #5882 | PG search_path was optional dynamic state → critical ProxySQL startup default, backend startup option, and ParameterStatus baseline. Shared code also affects Stable/libpq. | [212a62800](https://github.com/sysown/proxysql/commit/212a62800), [integration 2775bb222](https://github.com/sysown/proxysql/commit/2775bb222), [startup](../../lib/PgSQL_Connection.cpp#L1294) |
| October 1/12 | Extended DISCARD ALL uniformly refused → safe isolated transaction-free form supported; unsafe batches remain refused; transaction-boundary detection refined. | [ddd30da59](https://github.com/sysown/proxysql/commit/ddd30da59), [7a7dc7389](https://github.com/sysown/proxysql/commit/7a7dc7389), [handler](../../lib/PgSQL_Session.cpp#L4995) |
| October 12 | PG transaction SET could request ordinary fallback lock → classified SET [LOCAL/SESSION] TRANSACTION forwards without itself requesting that lock. Ordinary LOCAL GUC handling did not become equivalent. | [b2e62e0ab](https://github.com/sysown/proxysql/commit/b2e62e0ab), [cfb7124c6](https://github.com/sysown/proxysql/commit/cfb7124c6) |
| October 12 | Tracker could clear snapshots without correcting reverted backend metadata → known rollback restores snapshot; confirmed idle with unknown cause retains desired values and invalidates changed backend entries. | [2a951b51d](https://github.com/sysown/proxysql/commit/2a951b51d), [manager](../../lib/PgSQL_ExplicitTxnStateMgr.cpp#L366) |

Dropped characteristics, invalid-prefix success, lost literal meaning, and
inaccurate reset bookkeeping are correctness concerns, not behaviors to approve.
The questionnaire separately asks about configuration precedence, classification
and binding, protocol support boundaries, defaults, and failure policies.
