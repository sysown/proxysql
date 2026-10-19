# Traffic behavior history and intent questions — twelve-month audit

Status: open intent questions, source/history review on 2026-10-19. Prepared on
`docs/invariants-expansion` for [PR #6491](https://github.com/sysown/proxysql/pull/6491).
No production code changed and no executable/runtime tests ran for this audit.

The pinned mainline window is **2025-10-19 through 2026-10-19**, by first-parent
integration date. BASE is `70228332135431229940279e49b6db186c6e4241`; END is `9516441f7bd6fdb93f255f1881db19ca9ee56778`.
The current documentation checkout is older than END: endpoint statements below
were read with `git show END:path`, without checking out END. Every source link
uses that immutable END, and history entries name actual integrated commits.

This stream covers ordinary MySQL/PostgreSQL protocol execution, policy/rules,
firewall interactions, result caching, prepared/extended operations, fast-forward,
FFTO activation, retries/transaction failure presentation, worker scheduling and
backpressure. Authentication/TLS policy, topology/pool internals, administration,
statistics/log sinks and plugins are separate streams. A cross-stream integration
can appear here with only its traffic portion examined.

The [product invariants](../agents/invariants.md) are requirements, not choices in
this questionnaire. In particular, session isolation, transaction ownership,
rollback-preserving cleanup and guarded retry remain required under every answer.
Crashes, memory corruption, protocol corruption, silently lost accepted state and
retrying an established transaction on a replacement backend are corrections to
make, not alternatives to approve. Feature/spec documents show recorded design
intent; they do not by themselves establish maintainer ratification.

The existing [SET questionnaire](set-behavior-history-questions.md) owns its 34 IDs
and recorded answers. None is duplicated or reopened here. Latest integrated
[PR #6503](https://github.com/sysown/proxysql/pull/6503) is included: its mixed
system/UDV planning, deferred publication/failure cleanup and change-user charset
work update that evidence, and its prepared-result heartbeat refresh is recorded
as a correction below. **#6503 is not closed/unmerged PR #6480.** PostgreSQL pipeline
variable reconciliation remains deferred to #6504/the existing RFC.

Answer by stable ID, for example `RT01=B, RT05=C, RT21=A`. No choice is preselected.
These questions select product policy; they do not authorize an immediate code
change. Each **Before** is the actual immediately preceding integrated state for
the named change (with intermediate integrated reversals called out), rather than
an arbitrary early feature-branch revision. **After** describes what survives END.

## Questions and recorded decisions

RT02 is already explicitly specified in the maintainer-authored [PR #6151](https://github.com/sysown/proxysql/pull/6151) Summary and Configuration sections: the accepted connection keeps its version for its lifetime. Its history is retained below, but no new answer is requested. The other 21 RT IDs remain questions.

### RT01 — Version queries may use a pooled server’s version

**Before:** Immediately before January #5277, December #4889 locally answered the exact COM_QUERY forms `SELECT @@version` and `SELECT VERSION()` with the configured proxy-advertised version. Before that December integration they followed the ordinary backend path.

**After at END:** Default `mysql-select_version_forwarding=3` first peeks at a free connection in the current/default hostgroup and locally returns its server version; absent a usable version it forwards. Mode 0 returns the internal advertised version, 1 always forwards, and 2 uses the pool then the internal version. These are exact-length special-query forms, not every spelling of a version expression.

**Client/operator consequence:** In a hostgroup containing 8.0 and 8.4 servers, a client can receive a free connection’s 8.0 version without a version query executing on the server selected by its SQL routing rules. Pool occupancy can determine whether the special query is answered locally or routed normally.

**Intent question:** Which should be the default for these exact version queries? **A:** current smart pool lookup then backend fallback (3); **B:** always execute the query on a backend (1); **C:** always return the proxy-advertised version (0).

**Version/tier/default activation:** MySQL; all tiers; default 3 from January. Existing persisted configuration can override it.

**Evidence:** [#4889 / 5a314d236](https://github.com/sysown/proxysql/commit/5a314d23648e69bea56f78c47085a30799f17169) (first parent [8cf3e59ea](https://github.com/sysown/proxysql/commit/8cf3e59ead6702942cb8bf19874a29df0b829288)); [#5277 / 591e1bca6](https://github.com/sysown/proxysql/commit/591e1bca6b823d4f669b8aab4ad7fe31006e5906) (first parent [4f675ed13](https://github.com/sysown/proxysql/commit/4f675ed1376c543b7a1056324710292e032d8230)). END: [lib/MySQL_Session.cpp:9694](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L9694), [lib/MySQL_Session.cpp:9881](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L9881), [lib/MySQL_Thread.cpp:1489](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L1489).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT02 — A frontend keeps its listener’s advertised version across reload

**Before:** Before #6151, greetings and locally synthesized version responses used the global `mysql-server_version`; there was no per-listener catalog or frontend version snapshot.

**After at END:** A v3.1+ frontend pins the version resolved for its listener at acceptance. The greeting and internal version-query answers use that pinned string. Reloading the catalog/global fallback affects later connections; already connected clients keep their pinned value. Smart forwarding can still return a backend version as RT01 describes.

**Client/operator consequence:** Connect to listener A advertised as 5.7, then reload A to 8.4: an existing client’s mode-0 version response remains 5.7 while a new client sees 8.4.

**Recorded decision — no answer requested:** Yes. The maintainer-authored [PR #6151](https://github.com/sysown/proxysql/pull/6151) explicitly pins the resolved version for the frontend lifetime. This audit records that declared contract; it does not infer approval from a bot summary or a source comment.

**Version/tier/default activation:** MySQL v3.1/v4.0 only; empty catalog `{}` by default. Pinning also snapshots the global fallback on those tiers. Stable retains the global path.

**Evidence:** [#6151 / be564e8f7](https://github.com/sysown/proxysql/commit/be564e8f75adffc19e20ac4eca1a2d3b9ab5fec3) (first parent [8dad803bd](https://github.com/sysown/proxysql/commit/8dad803bd840e7e7f8a27cdca20d5b9a51b0a108)). END: [lib/MySQL_Thread.cpp:5822](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L5822), [lib/MySQL_Protocol.cpp:1261](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Protocol.cpp#L1261), [lib/MySQL_Session.cpp:9685](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L9685).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT03 — Default first-comment policy follows rewritten SQL

**Before:** Before #5410, first-comment annotations were consumed after rules, but the parser still described the original SQL even when a rule rewrote it. There was no first-comment phase selector.

**After at END:** The new selector is 0=off, 1=before rules, 2=after rules, 3=both; default 2. After rules, rewritten SQL is reparsed and its first comment supplies annotations. A rewrite that removes an original annotation therefore removes its post-rule effect. Modes 1/3 can retain prepare-time `min_gtid` per client statement handle after April #5581.

**Client/operator consequence:** A rule stripping `/* hostgroup=20 */` can now stop that client hint from overriding its destination. Conversely a rewritten first comment containing `hostgroup=20` can override the rule’s output under default mode 2.

**Intent question:** Which comment/rule precedence should be the default? **A:** annotations from final rewritten SQL after rules (2); **B:** original annotations before rules, letting rules override them (1); **C:** annotations disabled (0).

**Version/tier/default activation:** MySQL and PostgreSQL shared rule processor; all tiers; default 2. The MySQL prepared `min_gtid` preservation applies to modes 1/3.

**Evidence:** [#5410 / d683dd7b8](https://github.com/sysown/proxysql/commit/d683dd7b8b4ac1fffd723d30ff811e49952909fd) (first parent [2b710e518](https://github.com/sysown/proxysql/commit/2b710e518f3876f2c2046f26b4ec257d0bb9072b)); [#5581 / 6cab7bd13](https://github.com/sysown/proxysql/commit/6cab7bd13b06bc12bed928bfc9eddab050bb382d) (first parent [f7ee5cd02](https://github.com/sysown/proxysql/commit/f7ee5cd028ff34efea42a41dc19cb24be121b65e)). END: [lib/Query_Processor.cpp:2938](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L2938), [lib/Query_Processor.cpp:3234](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L3234), [lib/MySQL_Thread.cpp:1443](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L1443), [lib/MySQL_Session.cpp:5143](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L5143).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT04 — Operators can disregard min_gtid client annotations

**Before:** Before #5150, a valid `min_gtid` first-comment annotation was parsed whenever the existing comment path ran; there was no separate ignore switch.

**After at END:** `mysql-ignore_min_gtid_annotations=true` suppresses this annotation instead of creating the per-query constraint. It does not turn off rule-based `gtid_from_hostgroup`, nor does it promise every cached or explicitly fresh-connection path enforces causal constraints.

**Client/operator consequence:** A client sending `/* min_gtid=uuid:123 */ SELECT ...` can be routed without that requested minimum when the operator selects this switch; success does not promise the annotated transaction is visible.

**Intent question:** Should the operator’s ignore switch be allowed to discard an otherwise valid client `min_gtid` request without returning an error to that client? **Yes / No.**

**Version/tier/default activation:** MySQL; all tiers; defaults false. Comment phase selection is a separate gate (RT03).

**Evidence:** [#5150 / dfd46fee4](https://github.com/sysown/proxysql/commit/dfd46fee4b6dce6867eeb693c0e2a727d6707a65) (first parent [8be91071e](https://github.com/sysown/proxysql/commit/8be91071ef65b5d4c79899f8599362b0824131ca)). END: [include/MySQL_Query_Processor.h:84](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/include/MySQL_Query_Processor.h#L84), [lib/MySQL_Thread.cpp:1592](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L1592), [lib/MySQL_Session.cpp:10156](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L10156).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT05 — Firewall lookup uses the final rewritten digest

**Before:** Before #5410, a rewrite changed the SQL text but the later firewall lookup still read the original parser digest.

**After at END:** The after-rules parser refresh replaces `qp->digest` with the final rewritten SQL’s digest before the shared whitelist lookup. Intermediate rules’ digest matching still occurs before this final refresh; raw pattern matching can already see rewritten text.

**Client/operator consequence:** If a rule rewrites `SELECT ... FROM public_t` to `SELECT ... FROM private_t`, protecting mode needs the rewritten digest whitelisted. Whitelisting only the client’s original digest no longer authorizes that transformed request.

**Intent question:** What should the firewall whitelist authorize after a rewrite? **A:** final rewritten digest, as now; **B:** original client digest; **C:** require both digests to be authorized.

**Version/tier/default activation:** Both protocols via the shared processor, all tiers; relevant only with an SQL rewrite and firewall whitelist enabled.

**Evidence:** [#5410 / d683dd7b8](https://github.com/sysown/proxysql/commit/d683dd7b8b4ac1fffd723d30ff811e49952909fd) (first parent [2b710e518](https://github.com/sysown/proxysql/commit/2b710e518f3876f2c2046f26b4ec257d0bb9072b)). END: [lib/Query_Processor.cpp:3234](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L3234), [lib/Query_Processor.cpp:3270](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L3270).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT06 — A matching rule converts the entire MySQL session to fast-forward

**Before:** Before #6156, a query-rule attribute could not activate fast-forward. Permanent mode came from account/replication paths; ordinary matching COM_QUERY requests continued through normal processing.

**After at END:** `attributes={"switch_to_fast_forward":true}` on a matching rule causes an eligible normal MySQL COM_QUERY session to enter permanent fast-forward at its resolved hostgroup. Subsequent traffic is relayed on the retained backend rather than re-entering ordinary per-query routing, caching, firewall or rewrite processing. The handoff clears normal query policy state.

**Client/operator consequence:** A routing rule matching the first special request can send all later requests on that connection through that backend, including SQL that would otherwise match a blocking rule.

**Intent question:** Should this rule action permanently switch the frontend for its remaining lifetime? **A:** permanent session switch, as now; **B:** support a bounded request/exchange switch and return to normal policy afterward.

**Version/tier/default activation:** MySQL; all tiers; opt-in Boolean attribute, false when absent; excludes mirror/admin and COM_FIELD_LIST. There is no equivalent PostgreSQL query-rule action.

**Evidence:** [#6156 / 6eeeff5e2](https://github.com/sysown/proxysql/commit/6eeeff5e21c402d2669d7faeb96831da4e54fc12) (first parent [9b7d0e66c](https://github.com/sysown/proxysql/commit/9b7d0e66c04b1eb2761ab569ce538d5e644e8f18)). END: [lib/MySQL_Query_Processor.cpp:823](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Query_Processor.cpp#L823), [lib/MySQL_Session.cpp:6300](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L6300), [lib/MySQL_Session.cpp:5773](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L5773), [lib/MySQL_Session.cpp:5888](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L5888).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT07 — Unsupported query-rule handoffs end the frontend

**Before:** Before the query-rule action existed, matching this new attribute had no handoff effect and a compressed/pipelined ordinary session could continue under its prior command handling. Within #6156 the unsafe transitional implementations were corrected before integration; they are not separate integrated behavior.

**After at END:** A requested handoff on a compressed frontend or with queued client packets generates error 1815/HY000 and returns a fatal session result. The October correction attempts a bounded nonblocking error flush before deletion; it does not promise delivery under backpressure.

**Client/operator consequence:** A client using compression can be disconnected by a newly enabled fast-forward rule even though that SQL could execute in normal mode.

**Intent question:** For a compressed or queued-packet session that cannot safely enter fast-forward, which policy should apply? **A:** error and close, as now; **B:** error this request and preserve normal session operation; **C:** ignore the action for this request and execute normally.

**Version/tier/default activation:** MySQL; all tiers; only with the explicit RT06 attribute. Correct framing/state ownership remain mandatory under every option.

**Evidence:** [#6156 / 6eeeff5e2](https://github.com/sysown/proxysql/commit/6eeeff5e21c402d2669d7faeb96831da4e54fc12) (first parent [9b7d0e66c](https://github.com/sysown/proxysql/commit/9b7d0e66c04b1eb2761ab569ce538d5e644e8f18)); [#6440 / e100071e2](https://github.com/sysown/proxysql/commit/e100071e2b660c51743d9b52fcd0e7bb515632a0) (first parent [5ace3febc](https://github.com/sysown/proxysql/commit/5ace3febc60b29264fe9a331a05a8e793ebe3237)). END: [lib/MySQL_Session.cpp:5903](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L5903), [lib/MySQL_Session.cpp:5942](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L5942).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT08 — Fast-forward backend closure has a bounded output-drain window

**Before:** Before #5203, detecting a closed fast-forward backend could immediately close the session while result bytes were still buffered for its frontend.

**After at END:** Backend closure can defer frontend teardown while buffered output drains, capped by `mysql-fast_forward_grace_close_ms`; default 5000, allowed 0–3600000. Empty buffers permit earlier close. This is a bound on draining after closure, not a query retry or a guarantee all bytes arrive.

**Client/operator consequence:** A slow fast-forward consumer has up to roughly five seconds of additional opportunity to receive already buffered backend output. At the configured deadline the connection can close with bytes still queued.

**Intent question:** Should the default output-drain deadline after a fast-forward backend closes be **A:** five seconds, as now; **B:** wait until output drains subject to the ordinary frontend lifetime controls?

**Version/tier/default activation:** MySQL; all tiers; fast-forward sessions only; default 5000 ms. Crash prevention and avoiding immediate needless data loss are corrections, not questions.

**Evidence:** [#5203 / 29a6b8576](https://github.com/sysown/proxysql/commit/29a6b8576a6c382e8bdafc5802b35ddb5667598f) (first parent [831d5fda8](https://github.com/sysown/proxysql/commit/831d5fda8a26bcdeaa8c56452833fac58b1918cd)). END: [lib/MySQL_Session.cpp:5539](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L5539), [lib/MySQL_Thread.cpp:1473](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L1473), [lib/mysql_data_stream.cpp:1096](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/mysql_data_stream.cpp#L1096).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT09 — FFTO now defaults off on both innovative tiers

**Before:** FFTO first entered #5410, before the tier split. After the March tier split it existed in v3.1/v4.0. April #5553 explicitly defaulted v3.1 off while leaving the then-v4/GenAI build on.

**After at END:** May #5701’s GenAI carve-out removed `PROXYSQLGENAI` from the core default path. At END, both protocols default `ffto_enabled=false` even in v4.0. Source comments explicitly record the default change. Opting in still observes fast-forward traffic, with packet/message-size bypass and protocol framing limits.

**Client/operator consequence:** An operator moving from the earlier v4 build to the current v4 defaults can lose FFTO query/error observations until the setting is explicitly enabled; raw fast-forward traffic can continue.

**Intent question:** Which tier default is intended? **A:** off in both v3.1 and v4.0, as at END; **B:** off in v3.1 and on in v4.0, as April specified.

**Version/tier/default activation:** FFTO compiled only in v3.1/v4.0; both protocols; END default false; Stable has no FFTO. Existing persisted true values still activate it.

**Evidence:** [#5410 / d683dd7b8](https://github.com/sysown/proxysql/commit/d683dd7b8b4ac1fffd723d30ff811e49952909fd) (first parent [2b710e518](https://github.com/sysown/proxysql/commit/2b710e518f3876f2c2046f26b4ec257d0bb9072b)); [#5434 / d3f7d2da4](https://github.com/sysown/proxysql/commit/d3f7d2da4c225cc82ae3f4df83229dfd8cb3843d) (first parent [c60f390b4](https://github.com/sysown/proxysql/commit/c60f390b447b758bb592130872b073cee47c86c7)); [#5553 / 7510d8073](https://github.com/sysown/proxysql/commit/7510d8073a3fb8883be348d4152241f285b699ee) (first parent [ceb969089](https://github.com/sysown/proxysql/commit/ceb9690891558ace0a51efa0888a3872c125e7fd)); [#5701 / 65c522e63](https://github.com/sysown/proxysql/commit/65c522e635606c74884828a1c28db7becfda15fa) (first parent [40ee836fc](https://github.com/sysown/proxysql/commit/40ee836fc0cebdc2dfc2f71dd29922dcf5d259be)). END: [lib/MySQL_Thread.cpp:1475](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L1475), [lib/PgSQL_Thread.cpp:1049](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Thread.cpp#L1049), [lib/MySQLFFTO.cpp:34](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQLFFTO.cpp#L34), [lib/PgSQLFFTO.cpp:39](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQLFFTO.cpp#L39).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT10 — Ordinary MySQL command pipelining becomes supported

**Before:** Immediately before #6470, ordinary commands received while a command was in flight could be unexpected packets causing disconnect. December #5257 already had a special counted/late-OK workaround for unexpected COM_PING; it was not general command queueing.

**After at END:** Authenticated non-fast-forward, non-mirror sessions leave queued commands in input order and drain them when returning to WAITING_CLIENT_DATA. Reading is paused while a busy session has queued packets so TCP backpressure bounds further intake. Busy COM_QUIT retains immediate teardown behavior; the older COM_PING special case still exists.

**Client/operator consequence:** A Connector/J batch can send several commands before reading replies and keep the connection rather than fail simply because the next ordinary command arrived early.

**Intent question:** Should authenticated ordinary MySQL sessions accept and sequentially execute pipelined commands by default? **A:** support this queueing by default, as now; **B:** require a separate operator compatibility opt-in.

**Version/tier/default activation:** MySQL; all tiers; no new enable flag. This does not promise arbitrary fast-forward pipelining or concurrent command execution.

**Evidence:** [#5257 / 0b85700e2](https://github.com/sysown/proxysql/commit/0b85700e22f1a886b8f8843168ce67b5052b0b1f) (first parent [88edaac61](https://github.com/sysown/proxysql/commit/88edaac61be725d05e4bffb5728995ddb73ecf84)); [#6470 / 4d7dea573](https://github.com/sysown/proxysql/commit/4d7dea573f7868d46ec5adf00e0bf93dbe34bab2) (first parent [c52887003](https://github.com/sysown/proxysql/commit/c5288700311d324df38b8095953d379861bcf81d)). END: [lib/MySQL_Session.cpp:6020](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L6020), [lib/MySQL_Session.cpp:7031](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L7031), [lib/MySQL_Session.cpp:7056](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L7056), [lib/mysql_data_stream.cpp:1105](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/mysql_data_stream.cpp#L1105).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT11 — Existing cache_ttl rules begin caching prepared results

**Before:** Before #6194, query-result caching covered the supported simple/text-query path. MySQL binary Execute and PostgreSQL extended Execute had no corresponding result-cache hit/admission path.

**After at END:** On v3.1/v4.0, the same positive query-rule `cache_ttl` now enables eligible prepared-result caching without another activation switch. MySQL excludes cursors, LongData, active transactions, hostgroup locks, causal requirements and conservative FOR/LOCK tokens. PostgreSQL limits this to bounded unnamed Bind/[Describe portal]/Execute/client-Sync frames, with no attached backend, active transaction, untracked startup options or init_connect. Keys include hostgroup, parameter bytes/types and tracked system state; protocol result bytes are retained.

**Client/operator consequence:** An unchanged broad SELECT-cache rule can begin returning a previous prepared execution’s rows after upgrading tiers/versions. An application previously relying on each prepared execution reaching the server now needs the expanded scope considered.

**Intent question:** Should an existing positive cache_ttl rule automatically authorize prepared-result caching? **A:** yes, subject to the eligibility guards; **B:** require a separate explicit prepared-cache opt-in.

**Version/tier/default activation:** MySQL and PostgreSQL; v3.1/v4.0 only; activated by existing cache_ttl>0. Stable prepared executions retain their prior uncached path.

**Evidence:** [#6194 / 594ed7cd3](https://github.com/sysown/proxysql/commit/594ed7cd36109dad1db5f8643678e08a2abefa4a) (first parent [d13b2ae22](https://github.com/sysown/proxysql/commit/d13b2ae2227437f533db8fe49e0a36bce7ba0dc1)). END: [lib/MySQL_Session.cpp:5188](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L5188), [lib/MySQL_Session.cpp:10490](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L10490), [lib/PgSQL_Session.cpp:7761](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L7761), [lib/PgSQL_Session.cpp:5757](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L5757).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT12 — Parameterized PostgreSQL cancellation targets proxy sessions

**Before:** Before #5299, the existing local cancellation handler recognized complete literal SELECT calls through Simple Query; parameterized extended Execute did not use the new Bind PID extraction/local dispatch path.

**After at END:** Complete recognized `pg_cancel_backend($1)`/`pg_terminate_backend($1)` extended calls decode one positive text/int4/int8 PID and dispatch the proxy’s session kill API scoped by frontend username. The local success result is `t` once dispatch is requested; it is not a confirmed report that a database PID was found or cancelled. October narrows classification to complete calls and fixes comment/parser handling.

**Client/operator consequence:** A driver binding PID 123 now asks ProxySQL to cancel its frontend session 123 rather than running the SQL function against the selected database server. An unmatched ID can still receive local `t`.

**Intent question:** For these parameterized calls, should success mean **A:** local proxy-session cancellation was requested, returning t as now; **B:** return t only after confirming an eligible proxy target exists; **C:** forward the function call to the database instead?

**Version/tier/default activation:** PostgreSQL; all tiers; recognized exact function-call shape and enabled digest/classifier path; literal proxy-PID behavior predates this extension.

**Evidence:** [#5299 / 2637d28f3](https://github.com/sysown/proxysql/commit/2637d28f365b1e765875dabfb2a0af4c96a906e5) (first parent [3bcb9e0bd](https://github.com/sysown/proxysql/commit/3bcb9e0bd584cb9cac0257592400605fea49f484)); [#6442 / 5ace3febc](https://github.com/sysown/proxysql/commit/5ace3febc60b29264fe9a331a05a8e793ebe3237) (first parent [970a978ae](https://github.com/sysown/proxysql/commit/970a978ae12eca4e4756bd0decd8bf27f2f53972)). END: [lib/PgSQL_Session.cpp:6236](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L6236), [lib/PgSQL_Session.cpp:6440](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L6440), [lib/PgSQL_Session.cpp:7984](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L7984).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT13 — Native PostgreSQL backend driver is the innovative-tier default

**Before:** The first parent of #5882 had only the libpq backend driver available for normal traffic. The native feature branch’s earlier off-by-default scaffolding and incomplete raw-pass-through implementations were not separately integrated mainline states.

**After at END:** #5882 integrates the native TCP backend driver and defaults `pgsql-use_native_backend_protocol=true` in v3.1/v4.0; Stable does not expose the setting and forces libpq. Unix filesystem/abstract-socket backends deliberately fall back to libpq even when the knob is true.

**Client/operator consequence:** Upgrading a v3.1 installation without setting this variable changes the driver used by newly initialized TCP backend connections, including its wire/result path and added named-portal/LISTEN capabilities.

**Intent question:** Should native TCP backend mode be the default in v3.1/v4.0? **A:** enabled by default, as now; **B:** opt-in, retaining libpq as the default.

**Version/tier/default activation:** PostgreSQL v3.1/v4.0; default true. Stable is libpq-only; Unix backends fall back to libpq.

**Evidence:** [#5882 / 2775bb222](https://github.com/sysown/proxysql/commit/2775bb222ed67e613332fa8bfdff526ae56baa49) (first parent [bae148763](https://github.com/sysown/proxysql/commit/bae14876302c754b941f2c1dccbdcbba6c112dfe)). END: [lib/PgSQL_Thread.cpp:1210](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Thread.cpp#L1210), [lib/PgSQL_Thread.cpp:4400](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Thread.cpp#L4400), [lib/PgSQL_Connection.cpp:371](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Connection.cpp#L371), [lib/PgSQL_Connection.cpp:1353](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Connection.cpp#L1353).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT14 — Reloading native mode does not migrate pooled connections

**Before:** Before native mode existed there was no backend-driver choice to reload; all pooled connections used libpq.

**After at END:** The driver choice is captured when a connection handler is first initialized. Reusing an established connection does not convert it to the current setting. Therefore one pool can contain native and libpq connections after a reload; actual mode checks remain necessary. The Unix fallback can create this mix even without a reload.

**Client/operator consequence:** Enable native mode with an old libpq pool: one request may use libpq while a later new connection uses native. The variable’s runtime value alone does not establish that LISTEN can run on the borrowed connection.

**Intent question:** When this setting changes, which activation contract should apply? **A:** existing connections keep their driver and drain normally, as now; **B:** retire safely idle connections of the previous mode so future borrowing converges before advertising the new capability.

**Version/tier/default activation:** PostgreSQL v3.1/v4.0; relevant on live knob changes and mixed endpoint types. No option permits interrupting an active transaction or unsafe reuse.

**Evidence:** [#5882 / 2775bb222](https://github.com/sysown/proxysql/commit/2775bb222ed67e613332fa8bfdff526ae56baa49) (first parent [bae148763](https://github.com/sysown/proxysql/commit/bae14876302c754b941f2c1dccbdcbba6c112dfe)); [#6387 / 6758c60ce](https://github.com/sysown/proxysql/commit/6758c60ce5b19e463cbd5a9dbf83c1650a678469) (first parent [2e19e2d86](https://github.com/sysown/proxysql/commit/2e19e2d868c5d2c756445bba3b40cef3ee6eb6d2)). END: [lib/PgSQL_Connection.cpp:364](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Connection.cpp#L364), [lib/PgSQL_Connection.cpp:1353](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Connection.cpp#L1353), [lib/PgSQL_Session.cpp:1586](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L1586), [lib/PgSQL_Session.cpp:4525](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L4525).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT15 — Named-portal support has a backend-mode boundary

**Before:** Immediately before #5882, normal extended Bind/Execute rejected named portals and the unnamed execution path did not honor row-limited Execute by retaining a resumable named portal.

**After at END:** The integrated native path adds named portal Bind/Describe/Execute/Close, retains the portal’s backend ownership and supports named Execute max_rows/resume. Turning the native setting off preserves the libpq named-portal refusal. Unnamed Execute still forces max_rows=0 for legacy parity; that inherited limitation is not attributed as a new regression.

**Client/operator consequence:** A client using named cursors can fetch a bounded number of rows and resume in the native path, but selecting libpq compatibility mode removes that newly supported client capability.

**Intent question:** Should named-portal support remain a native-mode capability? **A:** retain this boundary; **B:** provide the same supported named-portal behavior in libpq compatibility mode.

**Version/tier/default activation:** PostgreSQL; native feature available only v3.1/v4.0 and enabled by default. Session admission currently checks the worker setting; pooled actual-mode interactions require their separate validation (RT14).

**Evidence:** [#5882 / 2775bb222](https://github.com/sysown/proxysql/commit/2775bb222ed67e613332fa8bfdff526ae56baa49) (first parent [bae148763](https://github.com/sysown/proxysql/commit/bae14876302c754b941f2c1dccbdcbba6c112dfe)). END: [lib/PgSQL_Session.cpp:7616](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L7616), [lib/PgSQL_Session.cpp:7841](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L7841), [lib/PgSQL_Session.cpp:7869](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L7869), [lib/PgSQL_Session.cpp:7900](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L7900).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT16 — LISTEN on a libpq connection returns unsupported

**Before:** Before #5882, recognized ordinary LISTEN requests were refused rather than supported with delivery of asynchronous notifications. Historical lexical bypasses that silently accepted LISTEN are correctness gaps, not a prior supported notification contract.

**After at END:** Native-mode sessions can retain the subscribed backend and relay asynchronous messages. An actually libpq backend cannot surface NotificationResponse through this implementation; the session returns feature-not-supported, including if native mode is globally enabled but a borrowed connection is still libpq. Detection and transaction/session pins were hardened after integration.

**Client/operator consequence:** After enabling native mode, a LISTEN can still fail because the pool supplied an older libpq connection or the backend address uses the deliberate Unix/libpq fallback.

**Intent question:** For an otherwise safely replaceable libpq connection selected for LISTEN, should ProxySQL **A:** return unsupported, as now; **B:** acquire a capable native connection automatically when the endpoint supports one?

**Version/tier/default activation:** PostgreSQL; native-capable v3.1/v4.0 only; Stable/libpq remain unsupported. Current supported native notifications retain ownership; no option permits losing a subscription through multiplexing.

**Evidence:** [#5882 / 2775bb222](https://github.com/sysown/proxysql/commit/2775bb222ed67e613332fa8bfdff526ae56baa49) (first parent [bae148763](https://github.com/sysown/proxysql/commit/bae14876302c754b941f2c1dccbdcbba6c112dfe)); [#6387 / 6758c60ce](https://github.com/sysown/proxysql/commit/6758c60ce5b19e463cbd5a9dbf83c1650a678469) (first parent [2e19e2d86](https://github.com/sysown/proxysql/commit/2e19e2d868c5d2c756445bba3b40cef3ee6eb6d2)); [#6442 / 5ace3febc](https://github.com/sysown/proxysql/commit/5ace3febc60b29264fe9a331a05a8e793ebe3237) (first parent [970a978ae](https://github.com/sysown/proxysql/commit/970a978ae12eca4e4756bd0decd8bf27f2f53972)). END: [lib/PgSQL_Session.cpp:1586](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L1586), [lib/PgSQL_Session.cpp:4520](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L4520), [lib/PgSQL_Thread.cpp:3860](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Thread.cpp#L3860).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT17 — Regex resource exhaustion skips policy rather than rejecting SQL

**Before:** Before #6470, engine 1 used pcrecpp matching directly: a match-limit failure could be indistinguishable from no-match (therefore a negated rule could apply), and recursive patterns could exhaust a worker stack. A GLOBAL replacement could retain replacements made before a later limit hit.

**After at END:** Engine 1 now has bounded recursion/match work. A match limit hit skips the whole rule, negated or not, then later policy continues. A replacement limit leaves SQL unchanged; other rule outputs are not rolled back. Engine 3 similarly excludes a rule on match errors and leaves failed substitution unchanged. Resource/stack safety is required; the open choice is the client/policy fallback.

**Client/operator consequence:** An error-producing or destination-setting rule with an expensive pattern may be bypassed for a sufficiently difficult query. For example, `(.|\n)*` repeated matches can hit a depth limit on a long subject; a later/default route can then execute it.

**Intent question:** After a rule’s runtime regex limit is reached, should ProxySQL **A:** skip that match/rewrite and continue policy, as now; **B:** reject the client request with an explicit policy-evaluation error?

**Version/tier/default activation:** Both protocols, all tiers for engine 1; engine 3 is v3.1/v4.0 only. Engine defaults: PCRE1 in Stable/v3.1, PCRE2 in v4.0. Limits are automatic; no permission to remove safety bounds is sought.

**Evidence:** [#6470 / 4d7dea573](https://github.com/sysown/proxysql/commit/4d7dea573f7868d46ec5adf00e0bf93dbe34bab2) (first parent [c52887003](https://github.com/sysown/proxysql/commit/c5288700311d324df38b8095953d379861bcf81d)); [#6440 / e100071e2](https://github.com/sysown/proxysql/commit/e100071e2b660c51743d9b52fcd0e7bb515632a0) (first parent [5ace3febc](https://github.com/sysown/proxysql/commit/5ace3febc60b29264fe9a331a05a8e793ebe3237)). END: [lib/Query_Processor.cpp:378](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L378), [lib/Query_Processor.cpp:1200](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L1200), [lib/Query_Processor.cpp:1226](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L1226), [lib/Query_Processor.cpp:3140](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L3140).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT18 — Invalid negated regexes differ across engines/tiers

**Before:** Before the PCRE2 migration, an invalid PCRE/RE2 pattern was a non-match, and negate_match_pattern could turn that into a matching rule. August #6120 initially replaced engine 1 globally; October #6440/#6461 restored legacy engines and introduced opt-in engine 3 instead.

**After at END:** At END, engines 1/2 preserve that legacy invalid-pattern negation behavior. PCRE2 engine 3 skips an invalid rule regardless of negation; it is the v4.0 default, while v3.1/Stable default 1. Compile errors are reported once per load rather than silently proving policy applied.

**Client/operator consequence:** The same invalid negated rule can match all queries on default v3.1 but no queries on default v4.0. This can alter a blocking or routing rule during a tier move without changing its row.

**Intent question:** For v4.0/engine 3, should an invalid negated regex **A:** make the rule inapplicable, as now; **B:** retain the legacy negation result of a failed match? Stable compatibility and safe bounded matching remain required.

**Version/tier/default activation:** Both protocols; engine 3 accepted only v3.1/v4.0, default only v4.0. A v3.1 operator can opt in explicitly.

**Evidence:** [#6120 / e7f1ab368](https://github.com/sysown/proxysql/commit/e7f1ab368be3fef61f1ab6fe61a2bb20b0eec5ba) (first parent [00c40e275](https://github.com/sysown/proxysql/commit/00c40e275e3a40cdf5363c1178e7a84155411dee)); [#6440 / e100071e2](https://github.com/sysown/proxysql/commit/e100071e2b660c51743d9b52fcd0e7bb515632a0) (first parent [5ace3febc](https://github.com/sysown/proxysql/commit/5ace3febc60b29264fe9a331a05a8e793ebe3237)); [#6461 / c52887003](https://github.com/sysown/proxysql/commit/c5288700311d324df38b8095953d379861bcf81d) (first parent [a8aca8b75](https://github.com/sysown/proxysql/commit/a8aca8b753e4086ce4d4bf379afcb748bc026574)). END: [lib/Query_Processor.cpp:1194](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L1194), [lib/Query_Processor.cpp:1248](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L1248), [lib/MySQL_Thread.cpp:1444](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L1444), [lib/PgSQL_Thread.cpp:1144](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Thread.cpp#L1144).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT19 — CIDR addresses normalize host bits into a subnet

**Before:** Before #6223, query-rule client_addr/proxy_addr supported their existing exact/wildcard text forms, not numeric CIDR lists. A value such as 10.0.128.5/20 did not select the corresponding numeric subnet.

**After at END:** A rule can use up to eight numeric CIDR prefixes. Host bits are masked off: 10.0.128.5/20 becomes 10.0.128.0/20. Matching uses existing ordered rule evaluation, not longest-prefix routing. IPv4-mapped IPv6 peers are treated as their embedded IPv4 address after October correction; literal Unix listener paths retain their own path.

**Client/operator consequence:** An operator entering a host-looking address with /20 can route every matching client across that subnet, not just 10.0.128.5. Broader earlier rules still take their normal precedence.

**Intent question:** Should CIDR inputs with nonzero host bits be **A:** normalized to their network, as now; **B:** rejected as invalid input requiring an explicit network address?

**Version/tier/default activation:** MySQL/PostgreSQL shared rule processor, all tiers; opt-in CIDR syntax in rule fields; existing exact/wildcard paths remain. Invalid-list handling is separately documented, not permission for partial unsafe matching.

**Evidence:** [#6223 / b4f68d539](https://github.com/sysown/proxysql/commit/b4f68d539a38df9f812664aa4ed55613c911608b) (first parent [da57c6e46](https://github.com/sysown/proxysql/commit/da57c6e46431312d6a00a27d2fed10f3e7649f7e)); [#6373 / 380cb3eac](https://github.com/sysown/proxysql/commit/380cb3eacdb8fd8b485c80c30f7210d625e17aa9) (first parent [7de4a9703](https://github.com/sysown/proxysql/commit/7de4a9703a61fe69e916e56a8080868bfbdac696)); [#6440 / e100071e2](https://github.com/sysown/proxysql/commit/e100071e2b660c51743d9b52fcd0e7bb515632a0) (first parent [5ace3febc](https://github.com/sysown/proxysql/commit/5ace3febc60b29264fe9a331a05a8e793ebe3237)). END: [lib/gen_utils.cpp:178](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/gen_utils.cpp#L178), [lib/gen_utils.cpp:247](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/gen_utils.cpp#L247), [lib/Query_Processor.cpp:628](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L628), [lib/Query_Processor.cpp:1270](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L1270).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT20 — Worker scheduling trades strict FIFO for bounded fairness work

**Before:** Before #5819, sessions_sort used its older sorting path when enabled. May replaced it with a running/waiting/idle partition gated by pool-acquire failure ratio; #5825 promoted the oldest waiter instead of sorting the entire waiting band each pass.

**After at END:** With sessions_sort enabled, at least 5% NULL pool acquisitions across qualifying ticks (at least four attempts, three disagreeing ticks) toggles partitioning. Stable retains the older single-oldest promotion when the waiting band exceeds four. v3.1/v4.0 add occasional oldest-first ordering of the front 20% at most once per 50 ms, plus bounded off-poll waiter work. This approximates arrival fairness; it is not a strict global FIFO contract.

**Client/operator consequence:** Under pool pressure, an older request can receive preferential worker attention while some younger requests overtake between fairness passes; reducing sorting work trades tail fairness against worker throughput.

**Intent question:** Should the worker promise **A:** best-effort bounded fairness with the current hysteresis/occasional ordering; **B:** a stricter FIFO admission order among otherwise equally eligible waiters, accepting its scheduling cost?

**Version/tier/default activation:** Both protocols; sessions_sort defaults true. May gate/partition applies all tiers; September extra fairness/off-poll paths are PROXYSQL31 gated and inherited by v4.0. Server eligibility/connection ownership still constrain every ordering.

**Evidence:** [#5819 / a1ca6a0ca](https://github.com/sysown/proxysql/commit/a1ca6a0ca39339ea2361fdca816730bf6a23ca77) (first parent [46ab989ad](https://github.com/sysown/proxysql/commit/46ab989adb791a42119f5efc3c91d176b4cc6a64)); [#5825 / 97eab1bbf](https://github.com/sysown/proxysql/commit/97eab1bbf0ce3c7c453e8a8bb96b2bd564e4758f) (first parent [b5b4d8bd1](https://github.com/sysown/proxysql/commit/b5b4d8bd13c3ccf2d4b8e532c94a788530995c37)); [#6195 / 08cf04957](https://github.com/sysown/proxysql/commit/08cf04957728229a5511498f712a5ed5945325f1) (first parent [563e47f1a](https://github.com/sysown/proxysql/commit/563e47f1a819c21e1700136c72b3025ae570ddd0)). END: [lib/Base_Thread.cpp:38](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Base_Thread.cpp#L38), [lib/Base_Thread.cpp:289](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Base_Thread.cpp#L289), [lib/Base_Thread.cpp:351](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Base_Thread.cpp#L351), [lib/MySQL_Thread.cpp:5165](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L5165), [lib/PgSQL_Thread.cpp:4134](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Thread.cpp#L4134).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT21 — A lost PostgreSQL transaction can preserve the frontend by default

**Before:** Before #5654 there was no preserved-but-poisoned recovery path: nonretryable client-library failures returned a fatal session result and closed the frontend. Some broken connections also lost transaction knowledge and could incorrectly become retry eligible. The same integration corrects that separate bug; replaying an interrupted established transaction is already prohibited by I-8.

**After at END:** Default preserve_client_on_broken_backend_in_tx=true allows an explicit-transaction backend death before result transfer to destroy the backend, preserve the frontend in a locally aborted state, and refuse ordinary work until a supported whole-transaction end. Plain ROLLBACK/ABORT or COMMIT/END can recover locally; October adds guarded extended recovery. It does not resume the lost transaction.

**Client/operator consequence:** A driver can keep its socket, receive failed-transaction state, issue ROLLBACK and then execute fresh work, instead of discarding the client connection. Already streamed output and unsupported recovery forms retain their stricter failure handling.

**Intent question:** Should preserving the frontend in this aborted state be **A:** enabled by default, as now; **B:** opt-in, with frontend closure the default?

**Version/tier/default activation:** PostgreSQL all tiers; introduced April; default true. Guards require an explicit transaction, valid frontend and no started result transfer.

**Evidence:** [#5654 / 7ca0d153c](https://github.com/sysown/proxysql/commit/7ca0d153cc1c53df120d8048a8d2c814a3aeecc5) (first parent [9727871a1](https://github.com/sysown/proxysql/commit/9727871a16875f57319b1b782a5054171bafdada)); [#6442 / 5ace3febc](https://github.com/sysown/proxysql/commit/5ace3febc60b29264fe9a331a05a8e793ebe3237) (first parent [970a978ae](https://github.com/sysown/proxysql/commit/970a978ae12eca4e4756bd0decd8bf27f2f53972)). END: [lib/PgSQL_Thread.cpp:1191](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Thread.cpp#L1191), [lib/PgSQL_Session.cpp:2781](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L2781), [lib/PgSQL_Session.cpp:3835](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L3835), [lib/PgSQL_Session.cpp:609](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L609).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

### RT22 — Preserved transaction failures replace the primary SQLSTATE

**Before:** Before preserved poisoned sessions existed, the failing connection path surfaced its ordinary backend/connection error and terminated or finalized through that path; there was no new synthesized failed-transaction error palette.

**After at END:** For the preserved path, the ErrorResponse is SQLSTATE 25P02 at severity ERROR, with ReadyForQuery E. Original backend text is sanitized/capped and sent as a WARNING/01000 notice; the original SQLSTATE is not retained as the primary ErrorResponse code. Later rejection also uses 25P02.

**Client/operator consequence:** An application expecting 57P01 to trigger its backend-death handling instead receives 25P02 and must inspect the notice/log to distinguish this failure from an ordinary failed transaction.

**Intent question:** When preserving the frontend after backend death, should the initial primary error be **A:** synthesized 25P02 with backend text as a notice, as now; **B:** preserve the original error SQLSTATE while still reporting aborted transaction state?

**Version/tier/default activation:** PostgreSQL all tiers, only when RT21’s preserve path is selected; default preservation true. This choice cannot authorize replay or claim a lost commit succeeded.

**Evidence:** [#5654 / 7ca0d153c](https://github.com/sysown/proxysql/commit/7ca0d153cc1c53df120d8048a8d2c814a3aeecc5) (first parent [9727871a1](https://github.com/sysown/proxysql/commit/9727871a16875f57319b1b782a5054171bafdada)). END: [lib/PgSQL_Session.cpp:2781](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L2781), [lib/PgSQL_Session.cpp:2810](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L2810), [lib/PgSQL_Session.cpp:137](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L137).

**Confidence/validation:** High for the described source behavior; source-only, not executed.

## Corrections, restored states and inherited concerns

- **Required transaction/retry corrections:** #5654 preserves transaction knowledge
  after a broken backend so it cannot authorize in-transaction replay; #6387 blocks
  PostgreSQL retry after CommandComplete; #6482 computes/retains MySQL unknown
  transaction state before prepared-result cleanup clears connector errors. These
  implement I-5/I-8. RT21/RT22 concern the separate optional frontend/error policy.
- **PostgreSQL extended abandonment:** #5882’s integrated endpoint destroys a backend
  left mid-batch on a local refusal, and refuses reset that might commit abandoned
  work. The source feature branch’s earlier reset/startup/raw-pass-through defects
  were corrected before first-parent integration; they are not shipped mainline
  stages. Unread ErrorResponse/ReadyForQuery handling and native send-failure teardown
  were hardened further in #6442. I-4 through I-7 decide the correctness obligations.
- **Prepared/protocol corrections:** bounds checks, per-client parameter-type
  ownership, cross-hostgroup binds, missing/stale backend statement IDs, LongData
  parameter types, packet continuation sizing, result-format preservation and
  close/portal cleanup prevent crashes, data corruption or invalid execution.
  PostgreSQL heterogeneous formats were collapsed before July #5878, cleanly
  rejected by #5878, then supported through the patched libpq API in September
  #6259; END retains full per-column formats. No question asks to permit corruption.
- **Restored routing:** #5388 briefly reset PostgreSQL current_hostgroup to the user
  default when no destination rule matched; #5401 explicitly reverted that change.
  The endpoint must not be described as retaining that February default reset.
  Mirror fast-routing suppression (#5385) and resetting a stale nonmatching rule
  pointer (#5778) correct destination selection under existing policy.
- **Restored regex compatibility:** the global PCRE1-to-PCRE2 replacement in #6120
  did enter mainline, then #6440/#6461 restored engine 1 and tier-qualified engine 3.
  Its interim Stable behavior is historical, not END. RE2 CASELESS rewrites now use
  the compiled options (#6373); PCRE legacy rewrite syntax and invalid-pattern
  negation compatibility were restored. RT17/RT18 isolate surviving policy choices.
- **Digests/classification:** December introduced PostgreSQL-specific tokenization;
  subsequent nested/dollar-quote, typecast, comment, grouping and terminator changes
  were reviewed as query-rule/classification correctness. ParserSQL initially had
  an independent digest path, but #6461/#6470 deliberately restore tokenizer digest
  parity independent of parser mode, including empty/comment-only SQL. No open
  question treats truncated/missing digests as permission to match an unrelated rule.
- **Latest endpoint:** #6503 adds atomic planning/publication for supported mixed SET
  assignments, discards failed plans, reconciles context and preserves change-user
  charset behavior. Cross-reference the SET review/recorded UDV questions rather
  than treating this as a separate approved policy. The same integration refreshes
  worker heartbeats during large prepared results at 32 MiB intervals; it corrects
  watchdog starvation, not a new client query-timeout contract.
- **Version peek lifetime concern (source-only):** get_backend_version_for_hostgroup
  returns a connection-owned char pointer after releasing the hostgroup lock. The
  RT01 policy does not ratify that pointer lifetime. A lifetime-safe implementation
  is an independent correctness investigation; no race was executed here.
- **Prepared cache private-state concern (source-only):** MySQL’s new eligibility
  predicate has no general MultiplexDisabled/attached-backend guard and its key
  includes tracked system variables, not arbitrary @variables or temporary-table
  contents. A focused probe should compare two same-user/schema prepared SELECTs
  over private state with the pre-existing text-cache behavior under the operator’s
  explicit cache_ttl rule. This is **not an established I-4 violation** or a request
  to approve private-state leakage: the operator-selected cache policy and inherited
  text-cache scope must first be established. RT11 asks only whether the prepared
  expansion should inherit that existing rule automatically.
- **Inherited limits:** unnamed PostgreSQL Execute max_rows remains forced to zero;
  the earlier pre-native libpq behavior already ignored it. Simple-query cache hits
  already bypassed causal backend-selection constraints before this window. The
  October documentation records that cache/GTID interaction but did not introduce
  it. Neither is falsely attributed as a new October behavior.
- **FFTO scope:** pipelined attribution/framer fixes, row/error accounting and
  over-limit bypass preserve observational correctness. Observation does not make
  raw relay traffic obey ordinary query rules. Beyond RT09, logging/statistics
  retention and sink policies are reviewed in the observability stream.

## Coverage and depth

The queue contains 196 first-parent integrations selected by broad traffic-path
matches; it includes documentation/tests and cross-stream changes. Every entry is
classified below and in the companion traffic-coverage.json. “Question” means its
relevant before/after diff and endpoint consumers were followed for the linked IDs.
“Correction” means the net traffic diff was examined/triaged as a correction,
restoration or an already-owned SET topic; it is not proof that every branch is
correct. Broad bundles were inspected for runtime deltas and selected callers,
**not exhaustively line-by-line across unrelated modules/dependencies**. “Outside”
records the handoff; it is not a claim that this reviewer completed that stream.
Support-only changes were checked for production relevance. No runtime paths were
executed. Tests named in source/history are evidence of intended coverage only.

Queue totals: 86 documented correction/no new intent question, 72 outside stream, 27 question, 11 support-only. There are 22 new RT questions.

| Integration (mainline date) | Disposition | Traffic finding / handoff |
| --- | --- | --- |
| [360646b7d](https://github.com/sysown/proxysql/commit/360646b7d51eb766471ed8f601e04eaf6c7371a6) (2025-10-20) | Outside | Processlist query-length projection and SQLite-size safety; observability stream. |
| [c6cbce34b](https://github.com/sysown/proxysql/commit/c6cbce34b15c85ed388f7df5437e515559265354) (2025-10-20) | Outside | GTID reader reconnect/refactor; backend stream; later reverted by #5175. |
| [5018cb66d](https://github.com/sysown/proxysql/commit/5018cb66d9620518ea949d39ab2b219e21f1d36a) (2025-10-20) | Outside | Debug authentication logging/secret masking and hex helpers; authentication/security stream. |
| [eb10eff1e](https://github.com/sysown/proxysql/commit/eb10eff1e1b6ae8221ebcede1c18254a3da18035) (2025-10-22) | Outside | Explicitly restores preceding GTID reader implementation; backend stream. |
| [4f8c5992c](https://github.com/sysown/proxysql/commit/4f8c5992ca7fc94003249b4f2c8d5b91af27dbd9) (2025-10-24) | Correction | Copies current MySQL query for processlist lifetime safety; no new traffic intent. |
| [9dd4d54e7](https://github.com/sysown/proxysql/commit/9dd4d54e79d168816ecd3db3b75bd9f28b929d0d) (2025-10-24) | Correction | Copies current PostgreSQL query for processlist lifetime safety; no new traffic intent. |
| [a44dee127](https://github.com/sysown/proxysql/commit/a44dee127deabc37a9fc2ea2ede58e11d64a605e) (2025-10-24) | Correction | Removes intermediate extended-query writeout calls; batching optimization, no new SQL policy. |
| [d2cb0183b](https://github.com/sysown/proxysql/commit/d2cb0183b301277a9a83eb740b1076e1f4c7031e) (2025-11-04) | Outside | Full-auth packet sequence ID correction; authentication stream. |
| [c06e15fd7](https://github.com/sysown/proxysql/commit/c06e15fd745a6aafa1fc4b977ed0efb1e4ba104f) (2025-11-04) | Support | DEBUG watchdog simulated-delay hook/test control, not ordinary runtime policy. |
| [8be91071e](https://github.com/sysown/proxysql/commit/8be91071ef65b5d4c79899f8599362b0824131ca) (2025-11-04) | Outside | Default interface variable getter projection; administration/startup stream. |
| [dfd46fee4](https://github.com/sysown/proxysql/commit/dfd46fee4b6dce6867eeb693c0e2a727d6707a65) (2025-11-04) | RT04 | Adds explicit min_gtid annotation ignore switch; fixes allocation terminator too. |
| [4fa3bf6a9](https://github.com/sysown/proxysql/commit/4fa3bf6a91102750979ec7c0886945362c0e9631) (2025-11-05) | Correction | Current-query copy guard prevents processlist use-after-free. |
| [cce161bc7](https://github.com/sysown/proxysql/commit/cce161bc74f7f146bb6a386f31854b49c21551e9) (2025-11-06) | Correction | Malformed binary Execute bounds/length validation; protocol correctness, no permission question. |
| [29a6b8576](https://github.com/sysown/proxysql/commit/29a6b8576a6c382e8bdafc5802b35ddb5667598f) (2025-11-20) | RT08 | Fast-forward backend-close output-drain policy and default deadline. |
| [05ab128c4](https://github.com/sysown/proxysql/commit/05ab128c4ad59558b5ba0e1b037f3de07b2f5b61) (2025-11-25) | Outside | GTID event counting/refactor; backend GTID stream. |
| [3c4e09fec](https://github.com/sysown/proxysql/commit/3c4e09fec0bb4261121f53d07c1bc520189486c7) (2025-12-06) | Correction | Prepared metadata cache/reference ownership/eviction refactor; selected session callers reviewed, not every purge branch. |
| [0f719d3e7](https://github.com/sysown/proxysql/commit/0f719d3e7bdfc53246e2ed6b91d14c3c62dd4ab1) (2025-12-06) | Correction | Replication commands exempted from unrelated deprecate-EOF compatibility check; protocol compatibility correction. |
| [b73160ef5](https://github.com/sysown/proxysql/commit/b73160ef5f7adabe0231902520101736c67bd5c1) (2025-12-07) | Correction | Frontend wait_timeout tracking already owns W1-W4 in SET questionnaire; no duplicate. |
| [87026c049](https://github.com/sysown/proxysql/commit/87026c049d0449e299fa7d90168a851ec3ffa387) (2025-12-10) | Correction | Permanent fast-forward accepts bidirectional queued data instead of fatal check; relay correctness. |
| [8cf3e59ea](https://github.com/sysown/proxysql/commit/8cf3e59ead6702942cb8bf19874a29df0b829288) (2025-12-11) | Outside | Config-file prefix stripping and parameterized SQLite insertion; administration stream. |
| [5a314d236](https://github.com/sysown/proxysql/commit/5a314d23648e69bea56f78c47085a30799f17169) (2025-12-14) | RT01 | Intermediate always-local exact version-query behavior; superseded by January smart default. |
| [6ee087c73](https://github.com/sysown/proxysql/commit/6ee087c73c1105c56235fa4764cc2be36e7bc948) (2025-12-17) | Correction | cache_empty_result=0 now still caches nonempty results in both protocols; restores field meaning. |
| [2667540fc](https://github.com/sysown/proxysql/commit/2667540fcc3bd576c40ed2bc7b04cb903b86602b) (2025-12-19) | Outside | PostgreSQL monitor SSL support/counters; backend/authentication streams. |
| [efd87ae4d](https://github.com/sysown/proxysql/commit/efd87ae4d4cbf14a9818ba846f0b13af26bc10f7) (2025-12-19) | Correction | PostgreSQL-specific digest tokenizer; inspected normalization/classification changes, no independent normalization-policy question selected. |
| [0b85700e2](https://github.com/sysown/proxysql/commit/0b85700e22f1a886b8f8843168ce67b5052b0b1f) (2025-12-20) | RT10 | Historical special unexpected COM_PING path precedes general command queueing; retained at END. |
| [faa64a570](https://github.com/sysown/proxysql/commit/faa64a570d19fe35af43494db0babdee3e3cdc89) (2025-12-20) | Correction | Monitor query comment removes wrong trailing token; support/correctness only. |
| [2d1140581](https://github.com/sysown/proxysql/commit/2d1140581d80eff3158214b2163db31601044089) (2025-12-25) | Support | Unit-test documentation; no ordinary traffic behavior. |
| [4f675ed13](https://github.com/sysown/proxysql/commit/4f675ed1376c543b7a1056324710292e032d8230) (2026-01-08) | Support | TLS keylog documentation, no active policy delta here. |
| [591e1bca6](https://github.com/sysown/proxysql/commit/591e1bca6b823d4f669b8aab4ad7fe31006e5906) (2026-01-08) | RT01 | Introduces version forwarding modes and smart default after December local behavior. |
| [ef872c7f4](https://github.com/sysown/proxysql/commit/ef872c7f4885a21e4578fff9b8d3bdbe4263ba2b) (2026-01-08) | Correction | SET timezone grammar extension already covered by SET questionnaire corrections. |
| [e6cbdcad7](https://github.com/sysown/proxysql/commit/e6cbdcad7f8de61c62afd8606684b6381978d76c) (2026-01-09) | Outside | Fork/exec file-descriptor closing safety; startup/delivery stream. |
| [9c3f6b0aa](https://github.com/sysown/proxysql/commit/9c3f6b0aa57847b712924141c7cd52ebb4671446) (2026-01-09) | Support | Poll call-site documentation only. |
| [c6ed5b96c](https://github.com/sysown/proxysql/commit/c6ed5b96cdf5a63d69f5d87c3488496e569bf9b3) (2026-01-12) | Correction | One Bind format code applies to all values; correct libpq parameter-format expansion. |
| [876d4ad3b](https://github.com/sysown/proxysql/commit/876d4ad3b86d7751e09ec2d984d0fb4b23fc135d) (2026-01-12) | Outside | Installs pgsql_users use_ssl into session; authentication/TLS stream. |
| [3bcb9e0bd](https://github.com/sysown/proxysql/commit/3bcb9e0bd584cb9cac0257592400605fea49f484) (2026-01-16) | Correction | Avoids extended Close-flood threshold deadlock; backpressure progress correction. |
| [2637d28f3](https://github.com/sysown/proxysql/commit/2637d28f365b1e765875dabfb2a0af4c96a906e5) (2026-01-16) | RT12 | Adds parameterized proxy-PID cancellation/termination and synthesized response semantics. |
| [27f13ca18](https://github.com/sysown/proxysql/commit/27f13ca18d8aa0a6dd82a235b6ef274ea444fc00) (2026-02-03) | Correction | Connector teardown avoids unsafe SSL close handling; no new policy selected. |
| [052436332](https://github.com/sysown/proxysql/commit/0524363322d4ebdc2e6473d0a9059a5556cc0e73) (2026-02-05) | Outside | Large GenAI integration: runtime hook/API surfaces triaged; plugin behavior belongs to root plugin stream, not exhaustively reviewed here. |
| [77fe58280](https://github.com/sysown/proxysql/commit/77fe5828019011dc7c78a3bfd6e8dfe3aae14fbf) (2026-02-06) | Outside | DEBUG FLUSH STATS commands; administration/observability stream. |
| [de0a9b9c2](https://github.com/sysown/proxysql/commit/de0a9b9c27b4dbb0cb582b974139b6d5e7c87470) (2026-02-06) | Correction | Refreshes connection pointer after state transition; use-after-free correction. |
| [a360dc22a](https://github.com/sysown/proxysql/commit/a360dc22aed7de67d7349886b936a25d94a3c2a5) (2026-02-06) | Support | Platform headers/build/link guards, no requested traffic-policy change. |
| [e82ff6f8a](https://github.com/sysown/proxysql/commit/e82ff6f8aa8688f1a721117193696fc3fe9c7580) (2026-02-12) | Outside | Adds protocol-scoped Prometheus labels/counters; observability stream. |
| [83209da48](https://github.com/sysown/proxysql/commit/83209da48709e09996c19c5e2303849cf3b05949) (2026-02-15) | Correction | RequestEnd null/lifetime guard; crash correction. |
| [3b578db4b](https://github.com/sysown/proxysql/commit/3b578db4bf767b29ad25b71c500eeaff200749cd) (2026-02-15) | Correction | Broad RAII/initialization/race bundle; traffic constructor/poll/protocol deltas triaged, not exhaustive module re-review. |
| [28b1114cd](https://github.com/sysown/proxysql/commit/28b1114cd986f15ef308bfc1b2b8fd06b325cee5) (2026-02-16) | Correction | PostgreSQL prepared reference lifetime race correction. |
| [5256f3d77](https://github.com/sysown/proxysql/commit/5256f3d77ac07b3d40ce42134e9f8c9620bef01d) (2026-02-18) | Correction | Extended query counts/bytes corrected; no-rule default-hostgroup reset is later explicitly reverted by #5401. |
| [bad7ce40c](https://github.com/sysown/proxysql/commit/bad7ce40c5598b1d229e4fcd37499e04a2d7243a) (2026-02-18) | Outside | PostgreSQL advanced events logging and counters; observability stream. |
| [9e157d2aa](https://github.com/sysown/proxysql/commit/9e157d2aa37868ce96fd2f793e687b41901f6c50) (2026-02-19) | Outside | TSDB service/metrics integration; observability/plugin stream. |
| [b64f2e561](https://github.com/sysown/proxysql/commit/b64f2e56149fbc10a85ff55ca29928b958f44fe5) (2026-02-20) | Outside | Buffered events/audit logger sampling/flush policies; observability stream. |
| [1dbe9fde9](https://github.com/sysown/proxysql/commit/1dbe9fde97589a6ede0d56a3c237582f80f3d862) (2026-02-20) | Correction | Fast routing no longer overrides mirror destination; preserves selected mirror policy. |
| [364767819](https://github.com/sysown/proxysql/commit/36476781931bd00cb549b88b43b059214fd5434d) (2026-02-20) | Correction | Digest grouping options read as integers, not bools; type correctness. |
| [2b710e518](https://github.com/sysown/proxysql/commit/2b710e518f3876f2c2046f26b4ec257d0bb9072b) (2026-02-22) | Correction | Reverts #5388 no-rule hostgroup default reset; END does not retain that transient change. |
| [d683dd7b8](https://github.com/sysown/proxysql/commit/d683dd7b8b4ac1fffd723d30ff811e49952909fd) (2026-02-25) | RT03, RT05, RT09 | Final rewrite reparsing changes annotations and firewall digest; initial FFTO. Unrelated MCP/TopK/test bundle handed off. |
| [5b721a659](https://github.com/sysown/proxysql/commit/5b721a6594f6bfa6e0b513f0ebed83d5fe3fe3bd) (2026-02-27) | Outside | TSDB metric-update correction; observability stream. |
| [c60f390b4](https://github.com/sysown/proxysql/commit/c60f390b447b758bb592130872b073cee47c86c7) (2026-03-06) | Outside | PostgreSQL replication-lag monitor; backend stream. |
| [d3f7d2da4](https://github.com/sysown/proxysql/commit/d3f7d2da4c225cc82ae3f4df83229dfd8cb3843d) (2026-03-07) | RT09 | Release-tier split gates FFTO; defaults tracked through later integrations. |
| [9d921bdda](https://github.com/sysown/proxysql/commit/9d921bdda38a1a1be0ba5dcba5ac59de10444728) (2026-03-09) | Correction | Pipeline txn/protocol validation and late COPY recovery corrections; SET G2/G3/G8 already owned; startup authentication elsewhere. |
| [3803f1107](https://github.com/sysown/proxysql/commit/3803f11077f21510b2b43ea7168abf91b54b739e) (2026-03-10) | Correction | PostgreSQL meta-command/query compatibility extension; fixed response/dispatch surfaces, no material new policy question selected. |
| [40716dcb4](https://github.com/sysown/proxysql/commit/40716dcb4662ae4dc28c24db3177c40622b6d926) (2026-03-19) | Outside | Startup listener conflict validation; administration/delivery stream. |
| [1a0dea6da](https://github.com/sysown/proxysql/commit/1a0dea6da05c29a741978de1012c9313129e6467) (2026-03-20) | Outside | Admin credential logging sanitization; authentication/administration stream. |
| [540fa174b](https://github.com/sysown/proxysql/commit/540fa174b4160a47b53ae734776b65e663d325e3) (2026-03-20) | Correction | Adds zstd negotiated frontend compression with fallback/validation; compatibility support, CPU-preference detail not escalated as separate intent question. |
| [7918e1737](https://github.com/sysown/proxysql/commit/7918e1737d940ad4929b50359be9bddb73fd0702) (2026-03-20) | Support | FreeBSD build portability. |
| [16529445b](https://github.com/sysown/proxysql/commit/16529445bf2c98e7473effd2bad54139c3042cad) (2026-03-22) | Correction | Extracts runtime decision helpers for unit tests; selected routing/transaction/regex callers checked, no independent policy redesign selected. |
| [cb8d0aa73](https://github.com/sysown/proxysql/commit/cb8d0aa737c9e2dff3fb0db8f5873b30b235b3c7) (2026-03-22) | Outside | TLS certificate statistics; auth/observability stream. |
| [e067683f4](https://github.com/sysown/proxysql/commit/e067683f4e022ac96f37716d413c2c97404a5c11) (2026-03-31) | Correction | FFTO error-recording feature extends observer accounting; sink/error-stat policy handed to observability stream. |
| [2fcc5729e](https://github.com/sysown/proxysql/commit/2fcc5729eec032a0e3d95a72fbdc08e7903940cc) (2026-03-31) | Correction | SHOW WARNINGS recognized after comment stripping; compatibility correction. |
| [d0625dc24](https://github.com/sysown/proxysql/commit/d0625dc243296b99c199203982aa508078580447) (2026-03-31) | Correction | Coverage-oriented hooks/refactors including packet/protocol helpers; no separate runtime intent chosen. |
| [63007cfa3](https://github.com/sysown/proxysql/commit/63007cfa3966d43ec45c6574a719ef2f770752a2) (2026-04-01) | Correction | Avoid duplicate metadata refresh/statement ownership errors; safety correction. |
| [7a574a537](https://github.com/sysown/proxysql/commit/7a574a537a3e0596c369e35d7e0c94435deda2c7) (2026-04-05) | Outside | COM_CHANGE_USER field bounds hardening; authentication/security stream. |
| [419cd7608](https://github.com/sysown/proxysql/commit/419cd7608b9e886f95badcdcc1a9555ba3dc2904) (2026-04-05) | Correction | Short COM_STMT_CLOSE safely discarded instead of out-of-bounds read. |
| [49b60b24a](https://github.com/sysown/proxysql/commit/49b60b24a6a83039e8a1136e23c7a021d68b9ef2) (2026-04-05) | Outside | Handshake response string bounds; authentication/security stream. |
| [ceb969089](https://github.com/sysown/proxysql/commit/ceb9690891558ace0a51efa0888a3872c125e7fd) (2026-04-05) | Correction | Short LongData packet validation and 16-bit parameter index; protocol correctness. |
| [7510d8073](https://github.com/sysown/proxysql/commit/7510d8073a3fb8883be348d4152241f285b699ee) (2026-04-05) | RT09 | Explicit April FFTO defaults by tier; v4 default subsequently changes in May. |
| [f713d78e4](https://github.com/sysown/proxysql/commit/f713d78e4136fd36cc85d24ccd1e1c7f1ceb75e9) (2026-04-09) | Outside | Backend DNS resolution-family selector; backend connectivity stream. |
| [1a8e4ed91](https://github.com/sysown/proxysql/commit/1a8e4ed91882c8b0645360c92ca668c7bf3e765b) (2026-04-09) | Outside | PostgreSQL SSL key logging; authentication/TLS stream. |
| [7f14beedc](https://github.com/sysown/proxysql/commit/7f14beedc15d6d48fc510c6d393743b530630f65) (2026-04-09) | Outside | PostgreSQL backend SSL configuration/verification; authentication/TLS stream. |
| [29a95af03](https://github.com/sysown/proxysql/commit/29a95af031b67d8d595688803dcf6c3bdde0d558) (2026-04-09) | Outside | PostgreSQL Cluster synchronization; administration stream. |
| [669ab9149](https://github.com/sysown/proxysql/commit/669ab914948f03b10c1ded21a4361d283cd9652d) (2026-04-10) | Correction | Broad lint/refactor changes triaged for traffic parser/state effects; no distinct new policy selected; unrelated areas outside. |
| [6cab7bd13](https://github.com/sysown/proxysql/commit/6cab7bd13b06bc12bed928bfc9eddab050bb382d) (2026-04-13) | RT03 | Per-client prepared min_gtid preserves selected pre-rule annotations after rewrites. |
| [c75e222ce](https://github.com/sysown/proxysql/commit/c75e222ce5f465840e97665316cfcf75bff2a63a) (2026-04-13) | Outside | GTID range/event state; backend stream. |
| [852468894](https://github.com/sysown/proxysql/commit/85246889459d6e45737732c04d01e2c40909a96b) (2026-04-13) | Correction | COPY matcher accepts inline-comment forms and avoids needless regex work; lexical compatibility correction. |
| [824588d19](https://github.com/sysown/proxysql/commit/824588d1983f850a941496683d82838b216d5c4c) (2026-04-14) | Correction | Compiler/static-analysis cleanup; selected protocol EVP conversion and macros inspected, no separate policy. |
| [13ff9d767](https://github.com/sysown/proxysql/commit/13ff9d767152d0331905478d267dcf1a642bb350) (2026-04-16) | Correction | MySQL9 charset compatibility correction plus test-matrix support; SET corrections already own charset scope. |
| [17a54193c](https://github.com/sysown/proxysql/commit/17a54193cc352ab721e959d8d3326f4373e338ed) (2026-04-17) | Correction | Separates zstd compression-level default from zlib default; no independent intent question selected. |
| [82fadbc1f](https://github.com/sysown/proxysql/commit/82fadbc1f4bd530ec503ea990ac7a129be37a237) (2026-04-17) | Correction | Restores lost greeting upper capability bits; proposed client-session-tracking variable reverted before integration. |
| [dbb40a30b](https://github.com/sysown/proxysql/commit/dbb40a30baec7d23568ebe2d2b228737d31dfcba) (2026-04-19) | Correction | Mostly test/CI/monitor changes plus hexadecimal hash-round parsing correction; auth/backend details outside. |
| [795b56a1e](https://github.com/sysown/proxysql/commit/795b56a1e5ed6811360e24e226a59de657b2cbb9) (2026-04-22) | Correction | System-variable notification modes and tracked GTID gate owned by SET N1-N6; no duplicates. |
| [7ca0d153c](https://github.com/sysown/proxysql/commit/7ca0d153cc1c53df120d8048a8d2c814a3aeecc5) (2026-04-23) | RT21, RT22 | Required transaction-knowledge retry fix plus distinct default frontend-survival and SQLSTATE policies. |
| [5dc586fd6](https://github.com/sysown/proxysql/commit/5dc586fd6bcfc425cb85d4663e538c4736b99616) (2026-04-23) | Outside | GTID range validation; backend stream. |
| [0f2b3e64a](https://github.com/sysown/proxysql/commit/0f2b3e64a5f3cf77d1b32d623a0be99218d1d3d7) (2026-04-24) | Support | Darwin linking and const correctness for interval comparisons. |
| [849fad944](https://github.com/sysown/proxysql/commit/849fad94401588623cc58e9e1ca560a7bfdce2fc) (2026-05-01) | Outside | Plugin chassis interfaces/lifecycle; root plugin stream; traffic hook boundary triaged only. |
| [65c522e63](https://github.com/sysown/proxysql/commit/65c522e635606c74884828a1c28db7becfda15fa) (2026-05-03) | RT09 | GenAI carve-out removes v4 FFTO default-on path; wider plugin relocation outside this stream. |
| [621ddb786](https://github.com/sysown/proxysql/commit/621ddb786e66bbe6ae1e278a20eef2189d2cba9a) (2026-05-03) | Outside | Authentication lock order/atomic replacement; authentication stream. |
| [15c67a9e9](https://github.com/sysown/proxysql/commit/15c67a9e9152c2d5257aec7d98780f74e6697f71) (2026-05-04) | Outside | Length-encoded authentication capability guard; authentication stream. |
| [6fb2f1ae9](https://github.com/sysown/proxysql/commit/6fb2f1ae994802cd6a4d8136c26a3b6d20afdcbb) (2026-05-04) | Correction | ParserSQL integration; SET P1-P3 already owned; independent digest path later restored to tokenizer parity. |
| [012fe2821](https://github.com/sysown/proxysql/commit/012fe2821421669458d71027d7ef1fda7799ba7a) (2026-05-05) | Correction | wsrep tracked variables and tolerated setup errors owned by SET E1/E2; recorded answers retained. |
| [0ceb33680](https://github.com/sysown/proxysql/commit/0ceb3368042947f00e7c1d8372d7c88f3a3214a5) (2026-05-14) | Correction | Fixes stale nonmatching qr pointer bypassing fast routing and PostgreSQL typecast swallowing SQL; restores intended routing/parsing. |
| [453c7554b](https://github.com/sysown/proxysql/commit/453c7554bff14acdea1b4896e98157a6bcf2d19e) (2026-05-24) | Correction | Large SET/DNS/charset/lifetime bundle; SET ownership and backend handoffs recorded; selected protocol deltas checked. |
| [7bd9339c3](https://github.com/sysown/proxysql/commit/7bd9339c318e67d5d0a036d06ae840285141544f) (2026-05-25) | Support | Unit coverage/CI manifest support only for this stream. |
| [141c3e87c](https://github.com/sysown/proxysql/commit/141c3e87c40eb3a4c29f8a30cc023079bb944d61) (2026-05-25) | Correction | Accumulates all untracked PostgreSQL startup options and fixes escaping/trailing-space construction. |
| [7dbe1f702](https://github.com/sysown/proxysql/commit/7dbe1f702985bdaf8808a6389ffbd3a61a9f2bc6) (2026-05-25) | Correction | Bounds first packet recv before allocation/receive; required protocol memory safety. |
| [46ab989ad](https://github.com/sysown/proxysql/commit/46ab989adb791a42119f5efc3c91d176b4cc6a64) (2026-05-25) | Outside | PROXY UNKNOWN must use actual TCP peer; authentication/network identity stream. |
| [a1ca6a0ca](https://github.com/sysown/proxysql/commit/a1ca6a0ca39339ea2361fdca816730bf6a23ca77) (2026-05-26) | RT20 | Pool-pressure partition gating and scheduling policy; local-cache distribution belongs to backend stream. |
| [97eab1bbf](https://github.com/sysown/proxysql/commit/97eab1bbf0ce3c7c453e8a8bb96b2bd564e4758f) (2026-05-26) | RT20 | Promotes longest-waiting session; later innovative-tier partial sort tracked at END. |
| [8e0060f69](https://github.com/sysown/proxysql/commit/8e0060f6915863a577a804edc14ea7559fc9c7ad) (2026-06-13) | Outside | PostgreSQL Unix-socket backend path; backend connectivity stream. |
| [862f5ec35](https://github.com/sysown/proxysql/commit/862f5ec3520ad433e8e33c153099e503774bdb04) (2026-06-16) | Outside | LOAD MYSQL VARIABLES feedback and runtime projection; administration stream. |
| [ee6cdb935](https://github.com/sysown/proxysql/commit/ee6cdb935899e5795c9703a3bc9d2a5072721ef2) (2026-07-07) | Correction | Temporarily rejects heterogeneous result formats instead of corrupting data; full support arrives #6259. |
| [afc1afac9](https://github.com/sysown/proxysql/commit/afc1afac97231490c72a317e32a6b799d3f079b2) (2026-07-08) | Outside | PROXYSQL INTERNAL SESSION diagnostic version field; observability stream. |
| [73ed635d0](https://github.com/sysown/proxysql/commit/73ed635d0c7ab06f88a918e965bc5da84351d464) (2026-07-08) | Correction | Refreshes prepared bind metadata after cross-hostgroup implicit prepare; execution correctness. |
| [65214405e](https://github.com/sysown/proxysql/commit/65214405e86c2072ad64afe71c2326674205b7c6) (2026-07-09) | Correction | ParserSQL adapter tests and production extraction fixes; SET P2/P5 own behavior questions. |
| [e9dfbeb21](https://github.com/sysown/proxysql/commit/e9dfbeb21dd7225d0cc123b57651b489a05258c0) (2026-07-11) | Outside | MySQL passthrough-auth implementation/spec; authentication stream. |
| [0069d4249](https://github.com/sysown/proxysql/commit/0069d42492ec145447ec99af097ec5164540145b) (2026-07-11) | Outside | Hostgroup timeout overrides feed session timeout consumers; backend configuration stream owns policy precedence. |
| [3020ee4e9](https://github.com/sysown/proxysql/commit/3020ee4e95315e7dc6c8b1ace7e07a8562576276) (2026-07-21) | Correction | Protocol-violation diagnostics add attributed context; no new query policy. |
| [20bbe92a0](https://github.com/sysown/proxysql/commit/20bbe92a0258e78293f3f1359ee901b7aae164bb) (2026-07-21) | Outside | Query digest purge/reset age policies; observability stream. |
| [81244e21b](https://github.com/sysown/proxysql/commit/81244e21b5f15650bd5dc9961e4031e6ae745770) (2026-07-23) | Outside | Passthrough authentication tier gate; authentication stream. |
| [fb849fe9d](https://github.com/sysown/proxysql/commit/fb849fe9d41ee02ce9a465e962d141e0ebc442b1) (2026-07-23) | Outside | Frontend COM_PING accounting; observability stream. |
| [893cb9ee2](https://github.com/sysown/proxysql/commit/893cb9ee2bccf1376aa4bd522cc28424a5e9faee) (2026-07-23) | Correction | Connection closure diagnostics; no independent execution policy delta. |
| [c66549e14](https://github.com/sysown/proxysql/commit/c66549e142192932186961f48dca681f0b19cc5d) (2026-07-27) | Correction | Zero parameter-format codes means all-text; correct PostgreSQL Bind default handling. |
| [691309e1e](https://github.com/sysown/proxysql/commit/691309e1ec60da6f4422ebdf0b063d5535e29c76) (2026-07-29) | Outside | Config round-trip for firewall/fast-routing/SSL/hostgroup sections; administration stream. |
| [a8c1cef4d](https://github.com/sysown/proxysql/commit/a8c1cef4d44c4beea7f6aa21b8a09a7cb8c75520) (2026-07-29) | Correction | Validates zlib expanded lengths; compressed-protocol memory safety. |
| [8ca2df54f](https://github.com/sysown/proxysql/commit/8ca2df54f6ecb5b15712a27d4e813162cbb0523e) (2026-07-29) | Outside | Large RDS BGD topology/worker/configuration bundle; backend stream, traffic gates triaged only. |
| [8ca4e32f7](https://github.com/sysown/proxysql/commit/8ca4e32f71412546df4905a799b3889a765a8657) (2026-08-03) | Correction | Preserves compression on raw fast-forward Unix backend links; relay compatibility correction. |
| [62e05922c](https://github.com/sysown/proxysql/commit/62e05922c35115a56e75c29dac8a5cfb28fef006) (2026-08-08) | Outside | Admin credential scope separation and reload behavior; authentication/administration stream. |
| [3849dec4a](https://github.com/sysown/proxysql/commit/3849dec4a9d9d1860f18a79633932131c6e5a9d5) (2026-08-09) | Support | Coverage unit changes; no new ordinary runtime policy. |
| [db0a21115](https://github.com/sysown/proxysql/commit/db0a2111540708de5255732058aab9a7d47956af) (2026-08-09) | Outside | Monitor caching_sha2 option; authentication/backend monitor stream. |
| [2bd3c17ca](https://github.com/sysown/proxysql/commit/2bd3c17ca4487811cf6a7719ce00c7f70f6b7dca) (2026-08-09) | Outside | Authentication response length guards; authentication/security stream. |
| [b4c751414](https://github.com/sysown/proxysql/commit/b4c7514147b92128d627fa9f0462f0ff57772a1c) (2026-08-10) | Correction | Atomic single-flight soft-TTL claimant restores existing one-refresh policy; no new refresh lifecycle selected. |
| [b263edcac](https://github.com/sysown/proxysql/commit/b263edcace11863355bb520527417b09355dee82) (2026-08-10) | Correction | FFTO pipelined ReadyForQuery attribution correction; preserves observer result ownership. |
| [6a6913b7b](https://github.com/sysown/proxysql/commit/6a6913b7b5ad8d7f325a61530c129114bc1cacd7) (2026-08-10) | Outside | caching_sha2 frontend RSA capability; authentication/TLS stream. |
| [0a7a023a2](https://github.com/sysown/proxysql/commit/0a7a023a2a219900daebcd40aababbe1cc232d6f) (2026-08-11) | Outside | Frontend certificate identity policy; authentication/TLS stream. |
| [16b361e46](https://github.com/sysown/proxysql/commit/16b361e46fa17384b714a17a6b8653f5952dbb08) (2026-08-11) | Correction | Broad string/ownership security cleanup; runtime diff triage, not exhaustive unrelated-module analysis. |
| [7b0d92f68](https://github.com/sysown/proxysql/commit/7b0d92f68e27651a345be034b2a7c8468d22de6f) (2026-08-11) | Outside | Configured caching_sha2 RSA public-key path; authentication stream. |
| [96fa1cf99](https://github.com/sysown/proxysql/commit/96fa1cf9923849a7bfbfb78f432545293802202a) (2026-08-12) | Outside | Optional ed25519 authentication; authentication stream. |
| [df292eacc](https://github.com/sysown/proxysql/commit/df292eacc821d56bbed92fcdb68dc98b852e103b) (2026-08-12) | Correction | Bounded formatting/ownership cleanup across runtime; selected session/firewall formatting checked, no policy redesign. |
| [6ebf75fff](https://github.com/sysown/proxysql/commit/6ebf75fff142e843aab701619dc84d2e0e2199e3) (2026-08-13) | Correction | Reusable FFTO framers preserve row/terminator attribution; no traffic routing policy change. |
| [efe591090](https://github.com/sysown/proxysql/commit/efe591090254703fb637e4500e17ae14ca184445) (2026-08-13) | Outside | GTID collection/update from OK packets; backend GTID stream; SET notification overlap already owned. |
| [57dc075ec](https://github.com/sysown/proxysql/commit/57dc075ec8df2bb767b5b90548cff80dfe734fa3) (2026-08-14) | Correction | Literal UDV tracking owned by SET U1-U8, including accepted U7 clarification; no duplicate. |
| [d235caa80](https://github.com/sysown/proxysql/commit/d235caa80129f2e2426331faddc4085c35e77829) (2026-08-15) | Outside | Advertises/stores frontend client attributes in session diagnostics; authentication/observability streams. |
| [d72f48067](https://github.com/sysown/proxysql/commit/d72f480674a04fa4ac583c1c3fba8f27857a1c50) (2026-08-15) | Outside | SQLite/admin CONNECTION_ID local response; administration stream. |
| [3f3ca1c47](https://github.com/sysown/proxysql/commit/3f3ca1c47215b3eb6a3255b3ec447ee462f319c6) (2026-08-16) | Correction | Idle-worker shutdown/handoff lifetime ownership correction; no permission question. |
| [94b3c8260](https://github.com/sysown/proxysql/commit/94b3c82604dab349237f49d9bc7c98019d53a057) (2026-08-17) | Support | ASAN label/CI infrastructure verification support. |
| [99c37c7c1](https://github.com/sysown/proxysql/commit/99c37c7c1b668c46364ecb767ad085838a3cbfef) (2026-08-18) | Correction | Maintainability bundle with RNG failure handling; selected runtime deltas triaged; authentication security owns RNG admission. |
| [749c4710c](https://github.com/sysown/proxysql/commit/749c4710c7dbd84140166c1a22c925588286c896) (2026-08-19) | Outside | GenAI variable seeding/TSDB serialization and processlist formatting; plugin/observability streams. |
| [a3b671b31](https://github.com/sysown/proxysql/commit/a3b671b312bf9aa7edf9c01771516abcc74455a4) (2026-08-26) | Correction | Terminate-packet memory cleanup; PostgreSQL session lifecycle leak correction. |
| [40ea2de1b](https://github.com/sysown/proxysql/commit/40ea2de1bdf6547951df600185d3b3f1820f1dbe) (2026-08-31) | Outside | Hostgroup pool statistics/refcount snapshots; backend/observability streams. |
| [00c40e275](https://github.com/sysown/proxysql/commit/00c40e275e3a40cdf5363c1178e7a84155411dee) (2026-08-31) | Correction | Hot-path fast rejection/guards; active-transaction caching reverted inside integration; no surviving new policy selected. |
| [e7f1ab368](https://github.com/sysown/proxysql/commit/e7f1ab368be3fef61f1ab6fe61a2bb20b0eec5ba) (2026-08-31) | RT18 | Historical global PCRE2 migration; partially restored in October, surviving engine policy qualified. |
| [b52db0781](https://github.com/sysown/proxysql/commit/b52db0781fb7c442a2b08757696c62dfc5604455) (2026-08-31) | Outside | TLS cipher configuration; authentication/TLS stream. |
| [9b7d0e66c](https://github.com/sysown/proxysql/commit/9b7d0e66c04b1eb2761ab569ce538d5e644e8f18) (2026-09-01) | Correction | Drains COM_QUIT correctly over TLS including split records; protocol/lifecycle correction. |
| [6eeeff5e2](https://github.com/sysown/proxysql/commit/6eeeff5e21c402d2669d7faeb96831da4e54fc12) (2026-09-01) | RT06, RT07 | New permanent rule-driven fast-forward action and unsupported handoff teardown policy. |
| [fd001a51b](https://github.com/sysown/proxysql/commit/fd001a51b0cf405141fbdf1b417ad0845bd06b33) (2026-09-01) | Outside | Worker/backend buffer gauges; observability stream. |
| [8dad803bd](https://github.com/sysown/proxysql/commit/8dad803bd840e7e7f8a27cdca20d5b9a51b0a108) (2026-09-01) | Correction | RE2 dependency migration and wrapper diagnostics; rewrite CASELESS correction later #6373; packaging outside. |
| [be564e8f7](https://github.com/sysown/proxysql/commit/be564e8f75adffc19e20ac4eca1a2d3b9ab5fec3) (2026-09-01) | RT02 | Per-interface version catalog/pinning and internal version response use. |
| [c31006d84](https://github.com/sysown/proxysql/commit/c31006d844ec789551fb6cca84317c3dfc254d9d) (2026-09-02) | Outside | Bootstrap authentication defaults; authentication/administration stream. |
| [5940f34ca](https://github.com/sysown/proxysql/commit/5940f34cacca6342fe644b4e5f71e4284bcf0775) (2026-09-03) | Outside | PostgreSQL frontend method/secret negotiation; authentication stream. |
| [53327da99](https://github.com/sysown/proxysql/commit/53327da99fdf699a1956cb03a400d642f107ff13) (2026-09-04) | Outside | Shared digest-stat atomics/lock changes; observability stream; no imagined threadlocal flush behavior. |
| [75f14db81](https://github.com/sysown/proxysql/commit/75f14db81db505941b4b48c9c56f24b7c50bcece) (2026-09-04) | Correction | Preserves backend reply errors/progress instead of misclassification; required PostgreSQL retry/result handling correctness. |
| [80941ae5e](https://github.com/sysown/proxysql/commit/80941ae5e2cb29963c8bb14c46a7a441ae4f08d2) (2026-09-06) | Outside | DuckDB plugin capability/protocol translation; root plugin stream. |
| [563e47f1a](https://github.com/sysown/proxysql/commit/563e47f1a819c21e1700136c72b3025ae570ddd0) (2026-09-08) | Outside | Router plugin publishes direct-route fast-forward attributes; RT06 owns core action, plugin publication policy outside. |
| [08cf04957](https://github.com/sysown/proxysql/commit/08cf04957728229a5511498f712a5ed5945325f1) (2026-09-15) | RT20 | Tier-gated worker starvation scheduling, partial oldest ordering and off-poll work. |
| [d13b2ae22](https://github.com/sysown/proxysql/commit/d13b2ae2227437f533db8fe49e0a36bce7ba0dc1) (2026-09-15) | Correction | COPY fast-forward TLS resource ownership/hand-off correction; no new SQL policy. |
| [594ed7cd3](https://github.com/sysown/proxysql/commit/594ed7cd36109dad1db5f8643678e08a2abefa4a) (2026-09-15) | RT11 | Prepared/extended result cache automatically consumes positive cache_ttl on innovative tiers. |
| [bf44ee9e3](https://github.com/sysown/proxysql/commit/bf44ee9e38109f6096722a5f9fcd3e7977bee4fb) (2026-09-27) | Outside | MariaDB causal GTID collection/routing storage; backend stream owns domain identity. |
| [4330a3510](https://github.com/sysown/proxysql/commit/4330a35102c9c0c1f771264c7e4a6373be13b305) (2026-09-28) | Outside | Connection maximum age policy/teardown; backend stream. |
| [b4f68d539](https://github.com/sysown/proxysql/commit/b4f68d539a38df9f812664aa4ed55613c911608b) (2026-09-28) | RT19 | CIDR rules introduce numeric matching, host-bit normalization and list bounds. |
| [6a4858e69](https://github.com/sysown/proxysql/commit/6a4858e69d7802529e5392ed99b73f17937717c9) (2026-09-30) | Correction | Preserves per-column Bind result formats, clears stale prepared IDs on retry and prevents packet double frees. |
| [c0bb2b2e0](https://github.com/sysown/proxysql/commit/c0bb2b2e0bf3402f58d5e073394fee7d440f32ea) (2026-09-30) | Support | MariaDB GTID wire-contract tests; small production debug support only. |
| [69977a509](https://github.com/sysown/proxysql/commit/69977a509e0d694ee0162bb856a718d6ffa1e3f9) (2026-09-30) | Outside | MariaDB last_gtid collection correction; backend stream plus SET N7. |
| [2775bb222](https://github.com/sysown/proxysql/commit/2775bb222ed67e613332fa8bfdff526ae56baa49) (2026-10-01) | RT13, RT14, RT15, RT16 | Native driver defaults/activation, named portals and LISTEN; guarded reset/retry ownership corrections separated. |
| [7de4a9703](https://github.com/sysown/proxysql/commit/7de4a9703a61fe69e916e56a8080868bfbdac696) (2026-10-02) | Correction | Excludes multi-result/overflowed query-cache admission; preserves cache wire validity. |
| [380cb3eac](https://github.com/sysown/proxysql/commit/380cb3eacdb8fd8b485c80c30f7210d625e17aa9) (2026-10-02) | RT19 | CIDR mapped-address correction supports RT19; protocol recovery/GTID/cache fixes documented; auth/backend areas handed off. |
| [2e19e2d86](https://github.com/sysown/proxysql/commit/2e19e2d868c5d2c756445bba3b40cef3ee6eb6d2) (2026-10-02) | Outside | Plugin listener restart/publication policy; administration/plugin streams. |
| [6758c60ce](https://github.com/sysown/proxysql/commit/6758c60ce5b19e463cbd5a9dbf83c1650a678469) (2026-10-02) | RT14, RT16 | Actual-mode LISTEN checks and stale mode cleanup support RT14/RT16; retry completion/timeouts/cache changes are correctness fixes. |
| [37d627b97](https://github.com/sysown/proxysql/commit/37d627b9743f7d51d6b783b039f994e0b18474f0) (2026-10-03) | Outside | AWS IAM backend authentication/provider lifecycle; authentication/plugin streams. |
| [6f438aa1f](https://github.com/sysown/proxysql/commit/6f438aa1f0e9ed38ecdb107d0bc829d27f9a8408) (2026-10-03) | Correction | Broad security cleanup: runtime net diffs triaged, memory/format validation corrections; external GenAI/scripts outside. |
| [d6211de2e](https://github.com/sysown/proxysql/commit/d6211de2e51150297172bb7ab972a406c54abb6e) (2026-10-10) | Outside | Prepared-statement bounds security diagnostics; root security stream; no optional invalid-read behavior. |
| [30825ffde](https://github.com/sysown/proxysql/commit/30825ffde9b34700806a250f26578248972c490e) (2026-10-10) | Outside | Enforces existing LOAD DATA LOCAL INFILE gate at connector boundary; security stream. |
| [b926fb3a9](https://github.com/sysown/proxysql/commit/b926fb3a97418d3d5789dea3db20a79e67ac9459) (2026-10-10) | Correction | Reassembles compressed inner packet headers across frames; required wire framing/memory safety. |
| [246210e08](https://github.com/sysown/proxysql/commit/246210e088599cfb0414a96843d0e9d27f535388) (2026-10-10) | Correction | Execute parameter/temporal/type bounds and decode availability; required input safety. |
| [b93e58714](https://github.com/sysown/proxysql/commit/b93e58714dc056f7d998e9c21fdded84f2a60577) (2026-10-10) | Outside | Authentication protocol short-packet safety; security/authentication stream. |
| [74c88dfc3](https://github.com/sysown/proxysql/commit/74c88dfc36f98c2073a280c10599d5cf41acd8fa) (2026-10-10) | Correction | ParserSQL1.1 grammar integration; selected adapter parity/scope changes covered by SET review and later tokenizer restoration. |
| [9f58be1d3](https://github.com/sysown/proxysql/commit/9f58be1d3007819e6e8566b5ead98d5327b4fbc4) (2026-10-11) | Correction | Restores LongData effective parameter type when execute omits type block. |
| [7601b3937](https://github.com/sysown/proxysql/commit/7601b39375a5b154b0a235c3db24fea7d3ff72f8) (2026-10-12) | Correction | Binary-result framing/continuation sizes and GTID local-cache eligibility corrected; auth/schema details outside. |
| [58c0e289d](https://github.com/sysown/proxysql/commit/58c0e289d7ec0ad22f3092929579a055d1799d26) (2026-10-12) | Correction | Transaction-status sentinel and ownership/formatting cleanup; no independent new traffic policy. |
| [970a978ae](https://github.com/sysown/proxysql/commit/970a978ae12eca4e4756bd0decd8bf27f2f53972) (2026-10-12) | Correction | ParserSQL comment/classifier/digest fallback and SET scope corrections; final tokenizer parity later retained. |
| [5ace3febc](https://github.com/sysown/proxysql/commit/5ace3febc60b29264fe9a331a05a8e793ebe3237) (2026-10-12) | RT12, RT16, RT21 | Poisoned extended recovery, LISTEN classification and complete cancel calls support linked policies; remaining fixes required correctness. |
| [e100071e2](https://github.com/sysown/proxysql/commit/e100071e2b660c51743d9b52fcd0e7bb515632a0) (2026-10-12) | RT07, RT17, RT18 | Restores PCRE1/tier defaults and separates engine3 semantics; bounded handoff error delivery supports RT07. |
| [f87f56a94](https://github.com/sysown/proxysql/commit/f87f56a947d386ba2142572faf6f114d1b5517ef) (2026-10-12) | Correction | Unsigned output-queue partial sentinel comparison; transport correctness. |
| [c52887003](https://github.com/sysown/proxysql/commit/c5288700311d324df38b8095953d379861bcf81d) (2026-10-13) | RT18 | Completes engine split and final tokenizer digest parity; original backend GTID policy resolved separately. |
| [4d7dea573](https://github.com/sysown/proxysql/commit/4d7dea573f7868d46ec5adf00e0bf93dbe34bab2) (2026-10-14) | RT10, RT17 | Default command queueing and bounded regex policy; SET/memory/digest corrections documented separately. |
| [b0fe50bc3](https://github.com/sysown/proxysql/commit/b0fe50bc3713acd18b270b9330fbcb4a067acc22) (2026-10-17) | Correction | Hot-path optimization and handler double-pass avoidance; tier gates/credential latch corrections, no separate policy selected. |
| [d3fb26bdd](https://github.com/sysown/proxysql/commit/d3fb26bdd341020f3774ff1754a05dcc88934636) (2026-10-17) | Correction | Retains unknown MySQL transaction state after failed prepared Execute; I-5/I-8 require correction. |
| [c92ea07ac](https://github.com/sysown/proxysql/commit/c92ea07acf9e7f3a65df835d739b372aebb6f81f) (2026-10-17) | Outside | AWS managed bootstrap CLI/plugin auto-start change; administration/plugin stream. |
| [5d839a0ab](https://github.com/sysown/proxysql/commit/5d839a0ab3bf785a6381e39b81be3e8ffa6ffd81) (2026-10-17) | Correction | Prepared Execute parameter-type bounds; mandatory protocol memory safety. |
| [48801ccc2](https://github.com/sysown/proxysql/commit/48801ccc231cbacccd43121834a25d34d3792541) (2026-10-18) | Correction | Restores Stable startup/lock/teardown behavior by tier gating; I-2 correction, no permission to change Stable. |
| [9516441f7](https://github.com/sysown/proxysql/commit/9516441f7bd6fdb93f255f1881db19ca9ee56778) (2026-10-19) | Correction | Latest PR6503 mixed SET/context planning already owned by SET review; 32MiB prepared-result heartbeat correction; not PR6480. |
