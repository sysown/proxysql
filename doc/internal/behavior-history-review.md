# Repository-wide twelve-month behavior review

This review covers the original request across the repository. The earlier SET/session questionnaire was only one part of that work; its narrower scope was not an agreed restriction. **123 additional unanswered intent questions** are organized below, with a first batch of 16 and eight detailed evidence reports. Existing SET IDs and answers remain intact.

**Source window:** 2025-10-19 through 2026-10-19, Europe/Madrid, by first-parent integration date. Compare BASE [`702283321`](https://github.com/sysown/proxysql/commit/70228332135431229940279e49b6db186c6e4241) to END [`9516441f7`](https://github.com/sysown/proxysql/commit/9516441f7bd6fdb93f255f1881db19ca9ee56778). This covers **465 first-parent integrations**, containing **5,368 reachable commits** and **2,748 changed paths**. END includes [PR #6503](https://github.com/sysown/proxysql/pull/6503); closed/unmerged #6480 and other unmerged branches are excluded.

The source endpoint is newer than the documentation checkout. Evidence was read with git show/diff against immutable commits, without changing this PR’s branch or worktree. Each detailed entry explains the immediately preceding integrated state, surviving behavior at END, activation/tier/default, observable consequence, question, and source evidence. A feature that did not exist before the window is identified as new behavior rather than a regression in an older implementation.

## How to answer

Use stable IDs, for example `RT11=A, AU03=B, OB01=B, AI-01=No`. Answers can come in batches; leave an ID unanswered when it needs discussion. The first listed choice is not a recommendation. An answer records intended policy, not permission to implement an immediate patch. Existing isolation, transaction, retry, cleanup and LOAD invariants continue to constrain every choice.

## First batch: 16 questions across all eight areas

These prioritize consequential defaults, upgrade effects and ownership boundaries. The linked detailed entries contain the source trace and exact activation conditions. The complete question index follows this batch.

### RT03 — Default first-comment policy follows rewritten SQL

**Before:** Annotations previously used original SQL even after a rule rewrite.

**After / effect:** Default post-rule processing now reads the rewritten SQL’s first comment; removing or inserting a hint can change the final destination.

**Question:** Which comment/rule precedence should be the default? **A:** annotations from final rewritten SQL after rules (2); **B:** original annotations before rules, letting rules override them (1); **C:** annotations disabled (0).

[Source evidence and full scope](behavior-history-traffic.md#rt03--default-first-comment-policy-follows-rewritten-sql).

### RT11 — Existing cache_ttl rules begin caching prepared results

**Before:** Positive cache_ttl rules did not cache MySQL binary prepared results or PostgreSQL extended Execute results.

**After / effect:** On v3.1/v4, the same existing rules also enable eligible prepared-result caching without a second opt-in.

**Question:** Should an existing positive cache_ttl rule automatically authorize prepared-result caching? **A:** yes, subject to the eligibility guards; **B:** require a separate explicit prepared-cache opt-in.

[Source evidence and full scope](behavior-history-traffic.md#rt11--existing-cache_ttl-rules-begin-caching-prepared-results).

### BE01 — What does PostgreSQL replication lag promise?

**Before:** PostgreSQL had no equivalent replication-lag admission check.

**After / effect:** The new check measures receive-to-replay lag on a replica, not evidence that it has received the primary’s latest work; a behind-but-fully-replayed replica may pass.

**Question:** Which promise is intended? A: exclude only observed receive-to-replay lag using this integer-seconds measure. B: also require evidence of primary-to-replica freshness. C: make the measurement/freshness policy configurable.

[Source evidence and full scope](behavior-history-backends.md#be01--what-does-postgresql-replication-lag-promise).

### BE15 — Should Blue/Green cutover terminate existing backend work?

**Before:** There was no automatic Blue/Green cutover controller.

**After / effect:** When this optional controller enters cutover, its endpoint handling can terminate already-borrowed backend work rather than only prevent new borrows.

**Question:** Should cutover A: interrupt all existing work for the endpoint as implemented, B: stop new borrows but let current owners finish, or C: allow a configured drain deadline before forced interruption? Transaction safety, isolation and retry invariants constrain all three choices.

[Source evidence and full scope](behavior-history-backends.md#be15--should-bluegreen-cutover-terminate-existing-backend-work).

### AU01 — Enabling pass-through changes existing empty-password accounts

**Before:** An empty-password mysql_users row used ordinary passwordless authentication.

**After / effect:** Enabling v3.1/v4 pass-through with its default empty-password sub-gate reinterprets eligible existing rows as credential-learning accounts; legacy passwordless/native clients can fail.

**Question:** Should the master pass-through switch reinterpret all existing empty-password rows by default? **Choices:** A: Yes, with empty_password=true as now; B: Require explicit per-account pass-through intent in addition to the master switch.

[Source evidence and full scope](behavior-history-authentication.md#au01--enabling-pass-through-changes-existing-empty-password-accounts).

### AU03 — Learned credentials become a username-wide authentication authority

**Before:** There was no learned pass-through authentication cache.

**After / effect:** A successful backend probe creates username-wide local authentication authority; default TTL=0 permits no age expiry, and ordinary USERS LOAD does not flush it.

**Question:** How long should a successful backend probe authorize later frontend logins? **Choices:** A: Username-wide cached authority until the configured eviction conditions, with zero TTL allowed; B: Require a finite lifetime and revalidation on expiry; C: Revalidate each frontend login against a backend.

[Source evidence and full scope](behavior-history-authentication.md#au03--learned-credentials-become-a-username-wide-authentication-authority).

### AD01 — Conflicting core listener configuration aborts the whole startup

**Before:** Cross-module core listeners were not preflighted by this overlap check.

**After / effect:** A detected overlap aborts the whole startup with exit status 0, which can look successful to a supervisor.

**Question:** For a detected cross-module core listener overlap, should ProxySQL **A: abort the whole startup with exit status 0 as now**, **B: abort with a nonzero exit status**, or **C: continue only the safely bindable modules**?

[Source evidence and full scope](behavior-history-administration.md#ad01--conflicting-core-listener-configuration-aborts-the-whole-startup).

### AD13 — Managed apply failure can follow already visible changes to earlier families

**Before:** This optional managed-deployment publisher did not exist.

**After / effect:** Activation spans multiple families; failure after an earlier publication can leave that earlier family’s changes visible. This is a question about the new cross-family contract, not ordinary single-family LOAD guarantees.

**Question:** Should managed activation promise **A: partial changes may be visible on failure and must be reconciled**, or **B: failure preserves the preceding configuration across all mapped families**?

[Source evidence and full scope](behavior-history-administration.md#ad13--managed-apply-failure-can-follow-already-visible-changes-to-earlier-families).

### OB01 — Per-worker event and audit buffers

**Before:** Accepted entries went directly to the shared file stream; there was no fsync guarantee.

**After / effect:** Enabled event and audit logs now use per-worker application buffers, defaulting to 4KiB/1s flush thresholds; quiet entries can appear later.

**Question:** Should event and audit logs both use these default per-worker buffers? **Choices:** A: buffer both, as implemented; B: buffer event logs but send audit entries directly to the file stream; C: send both directly.

[Source evidence and full scope](behavior-history-observability.md#ob01--per-worker-event-and-audit-buffers).

### OB13 — Ordinary SHOW PROCESSLIST no longer has its short SQL-text view

**Before:** Ordinary SHOW PROCESSLIST exposed a short 100-character preview.

**After / effect:** Ordinary and FULL SHOW now return the available projected query text, subject to the Admin query-length limit (default 2MiB).

**Question:** Should ordinary SHOW return the same available query text as FULL? **Choices:** A: retain the complete projected text; B: restore a short preview for ordinary SHOW and reserve longer text for FULL.

[Source evidence and full scope](behavior-history-observability.md#ob13--ordinary-show-processlist-no-longer-has-its-short-sql-text-view).

### DE01 — RPM upgrades stop forcing a service restart

**Before:** RPM upgrade scriptlets requested a stop/start cycle.

**After / effect:** The replacement specs omit an explicit upgrade-restart hook. Standard systemd macro behavior leaves restart to the operator/distribution; actual package upgrades were not run.

**Question:** Should RPM upgrades leave restart timing under operator/distribution control? **Choices:** A: retain no forced upgrade restart; B: automatically restart the service on upgrade.

[Source evidence and full scope](behavior-history-delivery.md#de01--rpm-upgrades-stop-forcing-a-service-restart).

### DE05 — The drift guard covers backend user policy before a global LOAD

**Before:** There was no bundled PostgreSQL user-sync tool with this drift guard.

**After / effect:** The optional sample checks backend user halves before a global LOAD. Frontend-only staged edits can escape that check and become active too.

**Question:** Which unrelated pending user edits should block the synchronizer before its global LOAD? **Choices:** A: detected backend-half drift only, as implemented; B: all frontend/backend user-policy drift, requiring a broader guard.

[Source evidence and full scope](behavior-history-delivery.md#de05--the-drift-guard-covers-backend-user-policy-before-a-global-load).

### EX13 — Router metadata loss can retain admission and recompute from cached topology/current health

**Before:** There was no Router-metadata plugin selecting this fallback policy.

**After / effect:** On metadata loss, the optional plugin can continue with last validated membership and current health, without an age cutoff.

**Question:** During metadata loss, should Router routing use **A: last validated membership plus available current health without an age cutoff**, **B: the same fallback only up to a configured age**, or **C: closed plugin gates until metadata recovers**?

[Source evidence and full scope](behavior-history-protocol-extensions.md#ex13--router-metadata-loss-can-retain-admission-and-recompute-from-cached-topologycurrent-health).

### EX17 — Router collapses backend Host variants without importing frontend source restrictions

**Before:** There was no Router import of these account variants.

**After / effect:** Compatible backend user@Host rows collapse into one proxy username; their Host restrictions are not translated into frontend source restrictions.

**Question:** Should compatible backend Host variants be **A: collapsed and imported without frontend source restrictions as now**, **B: imported only after explicit operator opt-in for the username**, or **C: imported only with a supported translation of their client-source restrictions**?

[Source evidence and full scope](behavior-history-protocol-extensions.md#ex17--router-collapses-backend-host-variants-without-importing-frontend-source-restrictions).

### AI-01 — Removal of the MySQL GenAI and LLM query syntax

**Before:** MySQL COM_QUERY accepted GENAI:/LLM: prefixes and registered work with the core worker.

**After / effect:** The plugin carve-out removes that public submission path. Remaining worker and embedding code do not establish that this old syntax still works.

**Question:** Should the MySQL `GENAI:` and `LLM:` syntax remain removed? Yes / No.

[Source evidence and full scope](behavior-history-ai-services.md#ai-01--removal-of-the-mysql-genai-and-llm-query-syntax).

### AI-11 — RAG source deletion removes search entries but retains document text

**Before:** The standalone ingester skipped existing document IDs and did not reconcile removed source rows.

**After / effect:** In that manually run utility, confirmed source deletion removes searchable chunks/embeddings but soft-deletes the document while retaining its stored raw text.

**Question:** For a confirmed deleted source row, should ingestion A) retain the document text in a tombstone, or B) erase its stored text and metadata?

[Source evidence and full scope](behavior-history-ai-services.md#ai-11--rag-source-deletion-removes-search-entries-but-retains-document-text).

## Complete unanswered question index

The counts below exclude the original 34 SET IDs, resolved/documented RT02/AU04/AU06, and AU18 (a duplicate of RT02). Stable IDs keep their gaps. These are audit work partitions, not claims about the product’s architectural decomposition.

| Area | Additional unanswered questions | Detailed before/after evidence |
| --- | ---: | --- |
| Traffic, rules and protocol execution | 21 | [Detailed report](behavior-history-traffic.md) |
| Backend selection, pools, topology and monitoring | 20 | [Detailed report](behavior-history-backends.md) |
| Authentication, TLS and client identity | 16 | [Detailed report](behavior-history-authentication.md) |
| Configuration, startup, plugins and peer synchronization | 15 | [Detailed report](behavior-history-administration.md) |
| Statistics, logging and telemetry | 14 | [Detailed report](behavior-history-observability.md) |
| MySQL X, DuckDB and Router services | 18 | [Detailed report](behavior-history-protocol-extensions.md) |
| GenAI, MCP, RAG and anomaly services | 12 | [Detailed report](behavior-history-ai-services.md) |
| Packaging, builds and operator tools | 7 | [Detailed report](behavior-history-delivery.md) |

Each question links directly to its complete before/after explanation. Some new diagnostic fields, bug fixes and support changes have a recorded disposition without an unresolved policy question; the integration inventory includes them.

### Traffic, rules and protocol execution

| ID and behavior | Intent question / choices |
| --- | --- |
| [RT01 — Version queries may use a pooled server’s version](behavior-history-traffic.md#rt01--version-queries-may-use-a-pooled-servers-version) | Which should be the default for these exact version queries? **A:** current smart pool lookup then backend fallback (3); **B:** always execute the query on a backend (1); **C:** always return the proxy-advertised version (0). |
| [RT03 — Default first-comment policy follows rewritten SQL](behavior-history-traffic.md#rt03--default-first-comment-policy-follows-rewritten-sql) | Which comment/rule precedence should be the default? **A:** annotations from final rewritten SQL after rules (2); **B:** original annotations before rules, letting rules override them (1); **C:** annotations disabled (0). |
| [RT04 — Operators can disregard min_gtid client annotations](behavior-history-traffic.md#rt04--operators-can-disregard-min_gtid-client-annotations) | Should the operator’s ignore switch be allowed to discard an otherwise valid client `min_gtid` request without returning an error to that client? **Yes / No.** |
| [RT05 — Firewall lookup uses the final rewritten digest](behavior-history-traffic.md#rt05--firewall-lookup-uses-the-final-rewritten-digest) | What should the firewall whitelist authorize after a rewrite? **A:** final rewritten digest, as now; **B:** original client digest; **C:** require both digests to be authorized. |
| [RT06 — A matching rule converts the entire MySQL session to fast-forward](behavior-history-traffic.md#rt06--a-matching-rule-converts-the-entire-mysql-session-to-fast-forward) | Should this rule action permanently switch the frontend for its remaining lifetime? **A:** permanent session switch, as now; **B:** support a bounded request/exchange switch and return to normal policy afterward. |
| [RT07 — Unsupported query-rule handoffs end the frontend](behavior-history-traffic.md#rt07--unsupported-query-rule-handoffs-end-the-frontend) | For a compressed or queued-packet session that cannot safely enter fast-forward, which policy should apply? **A:** error and close, as now; **B:** error this request and preserve normal session operation; **C:** ignore the action for this request and execute normally. |
| [RT08 — Fast-forward backend closure has a bounded output-drain window](behavior-history-traffic.md#rt08--fast-forward-backend-closure-has-a-bounded-output-drain-window) | Should the default output-drain deadline after a fast-forward backend closes be **A:** five seconds, as now; **B:** wait until output drains subject to the ordinary frontend lifetime controls? |
| [RT09 — FFTO now defaults off on both innovative tiers](behavior-history-traffic.md#rt09--ffto-now-defaults-off-on-both-innovative-tiers) | Which tier default is intended? **A:** off in both v3.1 and v4.0, as at END; **B:** off in v3.1 and on in v4.0, as April specified. |
| [RT10 — Ordinary MySQL command pipelining becomes supported](behavior-history-traffic.md#rt10--ordinary-mysql-command-pipelining-becomes-supported) | Should authenticated ordinary MySQL sessions accept and sequentially execute pipelined commands by default? **A:** support this queueing by default, as now; **B:** require a separate operator compatibility opt-in. |
| [RT11 — Existing cache_ttl rules begin caching prepared results](behavior-history-traffic.md#rt11--existing-cache_ttl-rules-begin-caching-prepared-results) | Should an existing positive cache_ttl rule automatically authorize prepared-result caching? **A:** yes, subject to the eligibility guards; **B:** require a separate explicit prepared-cache opt-in. |
| [RT12 — Parameterized PostgreSQL cancellation targets proxy sessions](behavior-history-traffic.md#rt12--parameterized-postgresql-cancellation-targets-proxy-sessions) | For these parameterized calls, should success mean **A:** local proxy-session cancellation was requested, returning t as now; **B:** return t only after confirming an eligible proxy target exists; **C:** forward the function call to the database instead? |
| [RT13 — Native PostgreSQL backend driver is the innovative-tier default](behavior-history-traffic.md#rt13--native-postgresql-backend-driver-is-the-innovative-tier-default) | Should native TCP backend mode be the default in v3.1/v4.0? **A:** enabled by default, as now; **B:** opt-in, retaining libpq as the default. |
| [RT14 — Reloading native mode does not migrate pooled connections](behavior-history-traffic.md#rt14--reloading-native-mode-does-not-migrate-pooled-connections) | When this setting changes, which activation contract should apply? **A:** existing connections keep their driver and drain normally, as now; **B:** retire safely idle connections of the previous mode so future borrowing converges before advertising the new capability. |
| [RT15 — Named-portal support has a backend-mode boundary](behavior-history-traffic.md#rt15--named-portal-support-has-a-backend-mode-boundary) | Should named-portal support remain a native-mode capability? **A:** retain this boundary; **B:** provide the same supported named-portal behavior in libpq compatibility mode. |
| [RT16 — LISTEN on a libpq connection returns unsupported](behavior-history-traffic.md#rt16--listen-on-a-libpq-connection-returns-unsupported) | For an otherwise safely replaceable libpq connection selected for LISTEN, should ProxySQL **A:** return unsupported, as now; **B:** acquire a capable native connection automatically when the endpoint supports one? |
| [RT17 — Regex resource exhaustion skips policy rather than rejecting SQL](behavior-history-traffic.md#rt17--regex-resource-exhaustion-skips-policy-rather-than-rejecting-sql) | After a rule’s runtime regex limit is reached, should ProxySQL **A:** skip that match/rewrite and continue policy, as now; **B:** reject the client request with an explicit policy-evaluation error? |
| [RT18 — Invalid negated regexes differ across engines/tiers](behavior-history-traffic.md#rt18--invalid-negated-regexes-differ-across-enginestiers) | For v4.0/engine 3, should an invalid negated regex **A:** make the rule inapplicable, as now; **B:** retain the legacy negation result of a failed match? Stable compatibility and safe bounded matching remain required. |
| [RT19 — CIDR addresses normalize host bits into a subnet](behavior-history-traffic.md#rt19--cidr-addresses-normalize-host-bits-into-a-subnet) | Should CIDR inputs with nonzero host bits be **A:** normalized to their network, as now; **B:** rejected as invalid input requiring an explicit network address? |
| [RT20 — Worker scheduling trades strict FIFO for bounded fairness work](behavior-history-traffic.md#rt20--worker-scheduling-trades-strict-fifo-for-bounded-fairness-work) | Should the worker promise **A:** best-effort bounded fairness with the current hysteresis/occasional ordering; **B:** a stricter FIFO admission order among otherwise equally eligible waiters, accepting its scheduling cost? |
| [RT21 — A lost PostgreSQL transaction can preserve the frontend by default](behavior-history-traffic.md#rt21--a-lost-postgresql-transaction-can-preserve-the-frontend-by-default) | Should preserving the frontend in this aborted state be **A:** enabled by default, as now; **B:** opt-in, with frontend closure the default? |
| [RT22 — Preserved transaction failures replace the primary SQLSTATE](behavior-history-traffic.md#rt22--preserved-transaction-failures-replace-the-primary-sqlstate) | When preserving the frontend after backend death, should the initial primary error be **A:** synthesized 25P02 with backend text as a notice, as now; **B:** preserve the original error SQLSTATE while still reporting aborted transaction state? |

### Backend selection, pools, topology and monitoring

| ID and behavior | Intent question / choices |
| --- | --- |
| [BE01 — What does PostgreSQL replication lag promise?](behavior-history-backends.md#be01--what-does-postgresql-replication-lag-promise) | Which promise is intended? A: exclude only observed receive-to-replay lag using this integer-seconds measure. B: also require evidence of primary-to-replica freshness. C: make the measurement/freshness policy configurable. |
| [BE02 — Does a failed PostgreSQL lag check retain admission indefinitely?](behavior-history-backends.md#be02--does-a-failed-postgresql-lag-check-retain-admission-indefinitely) | Choose the failure contract: A: retain the last lag admission state until a successful sample or another health policy changes it. B: exclude after a bounded age or failure count. C: fail open/closed according to an explicit hostgroup policy. |
| [BE03 — Is PostgreSQL lag action scoped to an endpoint or one membership?](behavior-history-backends.md#be03--is-postgresql-lag-action-scoped-to-an-endpoint-or-one-membership) | Should one observation govern A: every membership of the endpoint, B: only the probed membership, or C: only memberships in the configured replication relationship? |
| [BE04 — Should PostgreSQL monitoring require the configured transport?](behavior-history-backends.md#be04--should-postgresql-monitoring-require-the-configured-transport) | Confirm the monitoring contract: A: configured/grouped transport is mandatory and a selected TLS row fully replaces global fields. B: permit transport fallback. C: keep strict transport but inherit unspecified TLS fields. |
| [BE05 — Is the new PostgreSQL DNS TTL a refresh timer or a validity limit?](behavior-history-backends.md#be05--is-the-new-postgresql-dns-ttl-a-refresh-timer-or-a-validity-limit) | Which stale-address policy is intended? A: keep serving the last address through arbitrary DNS failures. B: stop serving at TTL expiry and use resolver/error handling. C: keep a separately bounded stale grace period. |
| [BE06 — Should the attached hostgroup override the global query timeout?](behavior-history-backends.md#be06--should-the-attached-hostgroup-override-the-global-query-timeout) | Ratify A: positive rule timeout, then attached-hostgroup default, then global default; B: rule zero explicitly disables all defaults; or C: a different precedence tied to the originally requested hostgroup rather than the attached membership. |
| [BE07 — When does a primary suppress same-hostgroup backups?](behavior-history-backends.md#be07--when-does-a-primary-suppress-same-hostgroup-backups) | Is this availability definition intended? A: retain all three modes with these distinct failure outcomes. B: backups become usable whenever no primary can satisfy the request. C: preserve status/capacity modes but enumerate which additional exclusions should count as primary absence. |
| [BE08 — Does backup exclusion apply to worker-local reuse?](behavior-history-backends.md#be08--does-backup-exclusion-apply-to-worker-local-reuse) | Should primary/backup policy govern A: global acquisition only, allowing local reuse to retain affinity, B: every new frontend borrower including local reuse, or C: only after a bounded drain/grace period following primary recovery? |
| [BE09 — Is two ping intervals the serious-shun minimum recovery delay?](behavior-history-backends.md#be09--is-two-ping-intervals-the-serious-shun-minimum-recovery-delay) | Which recovery contract is intended? A: the fixed two-interval safety margin. B: recovery only after a confirmed successful probe. C: the configured shun recovery remains authoritative with a separately configurable monitor margin. |
| [BE10 — May Aurora topology absence remove configured memberships?](behavior-history-backends.md#be10--may-aurora-topology-absence-remove-configured-memberships) | Confirm A: successful nonempty topology absence is enough to remove runtime membership after N samples, including across intervening failures. B: only consecutive successful observations count and missing members are shunned. C: removal requires independent confirmation or a different configured policy. |
| [BE11 — Does GTID evidence remain trusted while its reader is disconnected?](behavior-history-backends.md#be11--does-gtid-evidence-remain-trusted-while-its-reader-is-disconnected) | Which trust boundary is intended? A: retain execution knowledge until a successful reconnect replaces it. B: stop trusting reader-derived knowledge as soon as the reader fails. C: retain only independently validated connection/identity-bound evidence, with a bounded lifetime. |
| [BE12 — When should a stale-IP monitor timeout stop counting as backend failure?](behavior-history-backends.md#be12--when-should-a-stale-ip-monitor-timeout-stop-counting-as-backend-failure) | Should the health contract A: ignore a timeout only when positive DNS evidence proves the socket belongs to an obsolete address, B: count any endpoint probe timeout toward normal failure policy, or C: retry the current resolved address before deciding? |
| [BE13 — Does enabling RDS discovery authorize automatic Blue/Green control?](behavior-history-backends.md#be13--does-enabling-rds-discovery-authorize-automatic-bluegreen-control) | Choose the activation boundary: A: existing topology discovery plus the default-enabled BGD auto-discovery switch authorizes the controller. B: BGD control requires explicit operator opt-in distinct from discovery. C: discovery may create an inactive row that an operator must activate. |
| [BE14 — What observation proves Blue/Green completion or rollback?](behavior-history-backends.md#be14--what-observation-proves-bluegreen-completion-or-rollback) | Which completion evidence is acceptable? A: retain the phase-dependent empty/absent-table inference. B: require direct per-reader/target confirmation. C: make the inference configurable with a timeout/manual-resolution policy. Missing or unrecognized metadata shape also needs an explicit retain/rollback/cleanup decision rather than relying on its parser shape. |
| [BE15 — Should Blue/Green cutover terminate existing backend work?](behavior-history-backends.md#be15--should-bluegreen-cutover-terminate-existing-backend-work) | Should cutover A: interrupt all existing work for the endpoint as implemented, B: stop new borrows but let current owners finish, or C: allow a configured drain deadline before forced interruption? Transaction safety, isolation and retry invariants constrain all three choices. |
| [BE16 — Can Blue/Green temporarily override reader placement and retain green rows?](behavior-history-backends.md#be16--can-bluegreen-temporarily-override-reader-placement-and-retain-green-rows) | Ratify A: availability-driven temporary writer fallback plus retained green membership, B: respect writer_is_also_reader=0 even if readers become unavailable and remove monitor-added green rows on cleanup, or C: independently configure those two policies. |
| [BE17 — What recovery guarantee owns Blue/Green side effects?](behavior-history-backends.md#be17--what-recovery-guarantee-owns-bluegreen-side-effects) | Which operational contract is intended? A: best-effort one-shot cleanup, fresh-start recovery and unsupported overlap are accepted limitations. B: retain/reconcile effects until confirmed clean and reject overlapping claims. C: keep limited recovery but expose explicit unresolved-effect state requiring operator action. |
| [BE18 — Does enabling locality intentionally change neutral local-cache selection?](behavior-history-backends.md#be18--does-enabling-locality-intentionally-change-neutral-local-cache-selection) | Is neutral mode A: configured-weight local selection and the uniform zero-weight cache fallback as implemented, B: exact pre-feature local selection when no positive locality evidence exists, or C: weighted local selection but no zero-weight reuse? |
| [BE19 — When does stale locality metadata stop biasing selection?](behavior-history-backends.md#be19--when-does-stale-locality-metadata-stop-biasing-selection) | Ratify A: bounded stale bias with immediate provider-removal neutrality and conservative same-AZ classification, B: neutralize every refresh failure, or C: configure freshness and identity confidence requirements separately. |
| [BE20 — Do health, backup and latency filters always outrank locality?](behavior-history-backends.md#be20--do-health-backup-and-latency-filters-always-outrank-locality) | Should policy order A: remain eligibility/backup/latency, then locality weighting, B: let locality alter backup/latency preference, or C: expose explicit ordering while retaining hard transaction/consistency constraints? |

### Authentication, TLS and client identity

| ID and behavior | Intent question / choices |
| --- | --- |
| [AU01 — Enabling pass-through changes existing empty-password accounts](behavior-history-authentication.md#au01--enabling-pass-through-changes-existing-empty-password-accounts) | Should the master pass-through switch reinterpret all existing empty-password rows by default? **Choices:** A: Yes, with empty_password=true as now; B: Require explicit per-account pass-through intent in addition to the master switch. |
| [AU02 — Unknown-user admission synthesizes account policy](behavior-history-authentication.md#au02--unknown-user-admission-synthesizes-account-policy) | What should authorize unknown-user pass-through admission? **Choices:** A: The two global gates, with an optional username allowlist and synthesized policy; B: Require a nonempty allowlist and an explicit default account-policy template; C: Require a provisioned frontend account for every admitted username. |
| [AU03 — Learned credentials become a username-wide authentication authority](behavior-history-authentication.md#au03--learned-credentials-become-a-username-wide-authentication-authority) | How long should a successful backend probe authorize later frontend logins? **Choices:** A: Username-wide cached authority until the configured eviction conditions, with zero TTL allowed; B: Require a finite lifetime and revalidation on expiry; C: Revalidate each frontend login against a backend. |
| [AU05 — Probe failure classification controls lockout and login availability](behavior-history-authentication.md#au05--probe-failure-classification-controls-lockout-and-login-availability) | Is this the intended pass-through failure contract? **Choices:** A: Fresh fail-fast probe, generic login failure, and lockout only for 1045/1698/1130; B: Retry transient probe failures within a separately configured login budget, retaining credential-only lockout accounting; C: Make failure classification and retry budget operator-configurable. |
| [AU07 — RSA key configuration failures preserve or substitute a serving identity](behavior-history-authentication.md#au07--rsa-key-configuration-failures-preserve-or-substitute-a-serving-identity) | What should happen when the configured RSA key pair is unusable? **Choices:** A: Retain the last accepted pair; on first load try defaults, then continue TLS-only; B: Retain the last accepted pair; on first load disable RSA without substituting defaults; C: Treat an explicitly configured unusable pair as a startup error. |
| [AU08 — PostgreSQL authentication_method becomes a minimum-strength floor](behavior-history-authentication.md#au08--postgresql-authentication_method-becomes-a-minimum-strength-floor) | Should the global method be a minimum floor reconciled with auto-detected secret formats? **Choices:** A: Yes, with the implemented plaintext/md5/SCRAM matrix; B: Keep the configured wire method authoritative and require explicit account-level format/method configuration. |
| [AU09 — Weak PostgreSQL floors retain a challenge-method existence signal](behavior-history-authentication.md#au09--weak-postgresql-floors-retain-a-challenge-method-existence-signal) | What compatibility/security policy should apply to mixed secret types under a weak floor? **Choices:** A: Support the current per-secret challenge selection and explicitly document the existence signal; B: Reject such mixed configurations unless the floor is raised to SCRAM; C: Add an explicit per-account method policy with documented enumeration semantics. |
| [AU10 — Plaintext PostgreSQL SCRAM caching reuses salts across usernames](behavior-history-authentication.md#au10--plaintext-postgresql-scram-caching-reuses-salts-across-usernames) | What should be the scope of the plaintext-to-SCRAM verifier cache? **Choices:** A: Per-worker and password-keyed, with reused salts as implemented; B: Per-account/credential-generation cache so different usernames do not share an ad-hoc salt; C: Keep fresh per-login salts and make verifier caching an explicit opt-in. |
| [AU11 — An in-progress PostgreSQL SCRAM login pins its old account policy](behavior-history-authentication.md#au11--an-in-progress-postgresql-scram-login-pins-its-old-account-policy) | What revocation boundary should apply to account changes during a pending SCRAM login? **Choices:** A: Finish using the original coherent account snapshot if the account still exists; B: Reject/restart pending authentication whenever its credential or account policy changes. |
| [AU12 — Native PostgreSQL TLS uses explicit ProxySQL trust configuration](behavior-history-authentication.md#au12--native-postgresql-tls-uses-explicit-proxysql-trust-configuration) | Should native backend TLS inherit libpq's ambient TLS inputs? **Choices:** A: Use only explicit ProxySQL TLS configuration, as now; B: Preserve libpq environment/default-file resolution for equivalent settings; C: Require explicit TLS material before activating native mode where ambient material was in use. |
| [AU13 — A malformed PostgreSQL protocol-range row can mean use defaults](behavior-history-authentication.md#au13--a-malformed-postgresql-protocol-range-row-can-mean-use-defaults) | How should malformed per-server TLS protocol ranges affect new connections? **Choices:** A: Keep the current distinction: bare dash warns/uses defaults, other invalid ranges fail at connect; B: Fail new connections for every malformed nonempty range; C: Warn and use defaults for every malformed range. |
| [AU14 — MariaDB default trust chooses the first qualifying OS bundle](behavior-history-authentication.md#au14--mariadb-default-trust-chooses-the-first-qualifying-os-bundle) | What should determine default backend trust when explicit CA settings are absent? **Choices:** A: The implemented explicit/environment/first-qualifying-OS-bundle/default precedence, failing the selected invalid bundle; B: Delegate all implicit discovery to OpenSSL defaults/environment; C: Keep OS discovery but continue to later bundles after a load failure. |
| [AU15 — IAM connection validation restricts endpoint and trust inputs](behavior-history-authentication.md#au15--iam-connection-validation-restricts-endpoint-and-trust-inputs) | Are canonical RDS endpoint naming and explicit CA configuration mandatory IAM admission requirements? **Choices:** A: Yes, retain the current endpoint/region/TCP/TLS/explicit-CA restrictions; B: Permit aliases through an explicit canonical signing/TLS-identity mapping, retaining verification; C: Permit system trust as an additional CA source while retaining canonical endpoint validation. |
| [AU16 — IAM adds a fixed token-wait deadline and one credential-refresh retry](behavior-history-authentication.md#au16--iam-adds-a-fixed-token-wait-deadline-and-one-credential-refresh-retry) | What should bound IAM token acquisition and refresh retries? **Choices:** A: The current five-second/overall-connect deadline and single 1045 generation refresh; B: Operator-configurable token deadline and credential-refresh budget, still bounded by overall connection policy; C: Use only the ordinary overall connection deadline and disable automatic credential-refresh retry. |
| [AU17 — The IAM provider owns token freshness before handshake](behavior-history-authentication.md#au17--the-iam-provider-owns-token-freshness-before-handshake) | Who must enforce freshness of a token returned as OK? **Choices:** A: The provider alone; core consumes OK/nonempty and handles backend rejection; B: Core additionally rejects tokens expired or too close to expiry using a documented handshake safety margin. |
| [AU19 — An existing keylog opt-in now includes PostgreSQL backend secrets](behavior-history-authentication.md#au19--an-existing-keylog-opt-in-now-includes-postgresql-backend-secrets) | Should enabling admin-ssl_keylog_file authorize the process-wide TLS keylog scope? **Choices:** A: Yes, one opt-in and one sink for all supported TLS consumers; B: Require protocol/connection-role selection for which secrets are recorded. |

### Configuration, startup, plugins and peer synchronization

| ID and behavior | Intent question / choices |
| --- | --- |
| [AD01 — Conflicting core listener configuration aborts the whole startup](behavior-history-administration.md#ad01--conflicting-core-listener-configuration-aborts-the-whole-startup) | For a detected cross-module core listener overlap, should ProxySQL **A: abort the whole startup with exit status 0 as now**, **B: abort with a nonzero exit status**, or **C: continue only the safely bindable modules**? |
| [AD02 — REST route file grammar and row identity](behavior-history-administration.md#ad02--rest-route-file-grammar-and-row-identity) | Is this grammar the compatibility contract: prefer `restapi_routes`, retain `restapi` as fallback, permit generated IDs, and prefer `interval_ms` if both timeout spellings are present: **yes or no**? |
| [AD03 — PostgreSQL Admin metadata emulation reports synthetic or empty results](behavior-history-administration.md#ad03--postgresql-admin-metadata-emulation-reports-synthetic-or-empty-results) | Should recognized PostgreSQL-only metadata requests that have no SQLite equivalent return **A: shaped empty results** or **B: an explicit unsupported-operation error**? |
| [AD04 — Variable LOAD reports mixed acceptance inside an OK result](behavior-history-administration.md#ad04--variable-load-reports-mixed-acceptance-inside-an-ok-result) | Should these counters be a supported machine-consumable LOAD result contract, with OK retaining its mixed-acceptance meaning: **yes or no**? |
| [AD05 — PostgreSQL peer configuration synchronization is on and persistent by default](behavior-history-administration.md#ad05--postgresql-peer-configuration-synchronization-is-on-and-persistent-by-default) | For an existing peer deployment, should newly supported PostgreSQL families synchronize at threshold 3 and persist by default (**A**), or remain disabled until explicitly enabled (**B**)? |
| [AD06 — A plugin-set mismatch prevents the whole v4.0 peer relationship](behavior-history-administration.md#ad06--a-plugin-set-mismatch-prevents-the-whole-v40-peer-relationship) | Should peer eligibility require **A: exact whole-plugin-set identity as now**, or **B: compatibility determined separately for the configuration family being synchronized**? |
| [AD07 — Plugin selection is a startup file/CLI source outside the SQL three-layer model](behavior-history-administration.md#ad07--plugin-selection-is-a-startup-filecli-source-outside-the-sql-three-layer-model) | Is file-plus-additive-CLI selection, independent of MEMORY/DISK/RUNTIME SQL state, the supported module-selection precedence: **yes or no**? |
| [AD08 — STOP/START recreates the initially selected plugins rather than rescanning the file](behavior-history-administration.md#ad08--stopstart-recreates-the-initially-selected-plugins-rather-than-rescanning-the-file) | Should in-process restart use **A: the initially selected module list**, or **B: a fresh text-file module selection**, while preserving the original CLI overrides? |
| [AD09 — Runtime-ready failure closes plugin gates while core listener startup continues](behavior-history-administration.md#ad09--runtime-ready-failure-closes-plugin-gates-while-core-listener-startup-continues) | Is runtime-ready failure intended to mean **A: core starts with the affected plugin gates closed**, or **B: that selected capability must be ready before traffic admission**? This question concerns traffic admission only; it does not offer approval for blocking core Admin commands (C2). |
| [AD10 — Scoped MySQL plugin publication always makes configuration durable](behavior-history-administration.md#ad10--scoped-mysql-plugin-publication-always-makes-configuration-durable) | Should this service always persist and activate its scoped configuration in one operation (**A**), or expose a separate persistence choice (**B**)? |
| [AD11 — Scoped publication can succeed while skipping colliding users and rules](behavior-history-administration.md#ad11--scoped-publication-can-succeed-while-skipping-colliding-users-and-rules) | For colliding users/rules, should publication **A: succeed with skipped rows and an explicit collision list**, or **B: reject the whole scoped plan**? |
| [AD12 — Managed deployment installation moves into ordinary startup](behavior-history-administration.md#ad12--managed-deployment-installation-moves-into-ordinary-startup) | Is automatic provider installation/recovery as part of the ordinary managed launch the intended product workflow, replacing the core manifest one-shot CLI: **yes or no**? |
| [AD13 — Managed apply failure can follow already visible changes to earlier families](behavior-history-administration.md#ad13--managed-apply-failure-can-follow-already-visible-changes-to-earlier-families) | Should managed activation promise **A: partial changes may be visible on failure and must be reconciled**, or **B: failure preserves the preceding configuration across all mapped families**? |
| [AD14 — Discovery reconciliation preserves observed role and status by default](behavior-history-administration.md#ad14--discovery-reconciliation-preserves-observed-role-and-status-by-default) | For an already present endpoint, should discovery **A: preserve observed placement/status unless the provider explicitly forces topology**, or **B: make every desired-set submission authoritative for placement/status**? |
| [AD15 — Discovery updates may persist only their delegated server slice](behavior-history-administration.md#ad15--discovery-updates-may-persist-only-their-delegated-server-slice) | Should controller submissions be permitted to select **A: runtime only / MEMORY / MEMORY+DISK per delegated slice**, or **B: runtime only with persistence reserved for explicit operator SAVE**? |

### Statistics, logging and telemetry

| ID and behavior | Intent question / choices |
| --- | --- |
| [OB01 — Per-worker event and audit buffers](behavior-history-observability.md#ob01--per-worker-event-and-audit-buffers) | Should event and audit logs both use these default per-worker buffers? **Choices:** A: buffer both, as implemented; B: buffer event logs but send audit entries directly to the file stream; C: send both directly. |
| [OB02 — Sampling also removes events from in-memory history](behavior-history-observability.md#ob02--sampling-also-removes-events-from-in-memory-history) | Should eventslog sampling cover both the file sink and circular history? **Choices:** A: both sinks, as implemented; B: file output only, retaining complete selected circular history. |
| [OB03 — PostgreSQL query-event retention is bounded and truncated](behavior-history-observability.md#ob03--postgresql-query-event-retention-is-bounded-and-truncated) | Should PostgreSQL use this bounded, oldest-first-eviction history with independently truncated SQL text? **Choices:** A: retain these semantics; B: require complete query text for retained events and explicitly report/refuse entries that cannot fit. |
| [OB04 — Live-map and Top-K digest observations may be approximate](behavior-history-observability.md#ob04--live-map-and-top-k-digest-observations-may-be-approximate) | May live-map/Top-K digest observations be individually atomic but approximate across columns? **Choices:** A: retain approximate cross-column observations for these readers; B: require a coherent row snapshot for these readers too. |
| [OB05 — Selective digest purge includes the cutoff timestamp](behavior-history-observability.md#ob05--selective-digest-purge-includes-the-cutoff-timestamp) | Should the age cutoff be inclusive? **Choices:** A: last_seen <= T, as implemented; B: last_seen < T. |
| [OB06 — TSDB automatically records the full metrics registry](behavior-history-observability.md#ob06--tsdb-automatically-records-the-full-metrics-registry) | Should enabling TSDB automatically include every registered metric family and label? **Choices:** A: include the complete registry, as implemented; B: require a configured allowlist/filter. |
| [OB07 — TSDB has separate raw and hourly retention policies](behavior-history-observability.md#ob07--tsdb-has-separate-raw-and-hourly-retention-policies) | Which retention policy should the TSDB expose? **Choices:** A: configurable raw/probe retention plus fixed one-year hourly retention; B: one configured lifetime for all TSDB tables; C: independently configurable lifetimes. |
| [OB08 — Disabling TSDB also pauses retention](behavior-history-observability.md#ob08--disabling-tsdb-also-pauses-retention) | Should disabling TSDB pause cleanup as well as collection? **Choices:** A: pause both, as implemented; B: stop collection but continue retention cleanup. |
| [OB09 — TSDB backend health means TCP reachability, separate from routing health](behavior-history-observability.md#ob09--tsdb-backend-health-means-tcp-reachability-separate-from-routing-health) | Should this TSDB series remain a separate TCP-connect observation? **Choices:** A: retain separate TCP reachability; B: derive database-health observations from the protocol Monitor instead. |
| [OB10 — TSDB read API follows REST availability, not sampler enablement](behavior-history-observability.md#ob10--tsdb-read-api-follows-rest-availability-not-sampler-enablement) | What should gate built-in TSDB reads? **Choices:** A: REST availability alone, as implemented; B: an explicit TSDB read-enable control; C: authenticated management access. |
| [OB11 — MySQL memory gauges follow a bounded sampling interval](behavior-history-observability.md#ob11--mysql-memory-gauges-follow-a-bounded-sampling-interval) | Should these memory gauges share the existing bounded memory sampling interval? **Choices:** A: use that interval, as implemented; B: refresh these gauges on every metrics scrape. |
| [OB12 — Hostgroup wait counters use start and completion events in different windows](behavior-history-observability.md#ob12--hostgroup-wait-counters-use-start-and-completion-events-in-different-windows) | Should reset-window wait counts and durations retain these event-time semantics? **Choices:** A: count starts when they start and full durations when they finish, as implemented; B: require counts and durations to refer to the same wait cohort across reset. |
| [OB13 — Ordinary SHOW PROCESSLIST no longer has its short SQL-text view](behavior-history-observability.md#ob13--ordinary-show-processlist-no-longer-has-its-short-sql-text-view) | Should ordinary SHOW return the same available query text as FULL? **Choices:** A: retain the complete projected text; B: restore a short preview for ordinary SHOW and reserve longer text for FULL. |
| [OB14 — Protocol-labelled Prometheus series replace ambiguous protocol metrics](behavior-history-observability.md#ob14--protocol-labelled-prometheus-series-replace-ambiguous-protocol-metrics) | Should the labelled protocol series be the compatibility boundary for affected metrics? **Choices:** A: require consumers to select/aggregate protocol-labelled series, as implemented; B: also retain a documented legacy MySQL-compatible series during migration. |

### MySQL X, DuckDB and Router services

| ID and behavior | Intent question / choices |
| --- | --- |
| [EX01 — MySQLX opt-in identities, local authentication and lazy backend admission](behavior-history-protocol-extensions.md#ex01--mysqlx-opt-in-identities-local-authentication-and-lazy-backend-admission) | Is the supported terminating-X admission contract local opt-in authentication followed by backend authentication on first use, with reserved backend pass_through rejected: **yes or no**? |
| [EX02 — MySQLX backend encryption follows the frontend by default](behavior-history-protocol-extensions.md#ex02--mysqlx-backend-encryption-follows-the-frontend-by-default) | Should the backend default be **A: as_client, retaining plaintext for a plaintext frontend unless endpoint use_ssl requests TLS**, or **B: required for every backend leg**? |
| [EX03 — MySQLX TLS passthrough changes the identity and inspection boundary](behavior-history-protocol-extensions.md#ex03--mysqlx-tls-passthrough-changes-the-identity-and-inspection-boundary) | For an explicitly upgraded passthrough route, is dedicated opaque forwarding with backend-owned authentication and no local X identity/SQL enforcement the supported contract: **yes or no**? |
| [EX04 — MySQLX compression is negotiated at the proxy and bounded independently of the backend](behavior-history-protocol-extensions.md#ex04--mysqlx-compression-is-negotiated-at-the-proxy-and-bounded-independently-of-the-backend) | Is proxy-terminated frontend compression, with a 16 MiB expansion cap and uncompressed-message fallback, the supported compatibility boundary: **yes or no**? |
| [EX05 — Removing MySQLX variable tables requires manual value migration](behavior-history-protocol-extensions.md#ex05--removing-mysqlx-variable-tables-requires-manual-value-migration) | Should legacy MySQLX variable values be **A: warned about and ignored, requiring manual migration as now**, or **B: automatically migrated to mysqlx-* global-variable rows**? |
| [EX06 — DuckDB reuses application credentials for a shared embedded database](behavior-history-protocol-extensions.md#ex06--duckdb-reuses-application-credentials-for-a-shared-embedded-database) | Should access be **A: inherited from the existing protocol users for the shared engine**, or **B: require a separate DuckDB-specific identity opt-in**? |
| [EX07 — DuckDB local files and extensions use one process-level external-access gate](behavior-history-protocol-extensions.md#ex07--duckdb-local-files-and-extensions-use-one-process-level-external-access-gate) | Is the contract a single operator-controlled external-access capability shared by all authenticated DuckDB clients, disabled by default and independent of read_only: **yes or no**? |
| [EX08 — DuckDB clients lose authority to change engine-wide settings](behavior-history-protocol-extensions.md#ex08--duckdb-clients-lose-authority-to-change-engine-wide-settings) | Is engine-wide DuckDB configuration exclusively Admin-controlled, with clients confined to supported session settings: **yes or no**? |
| [EX09 — DuckDB LOAD rejects lifecycle changes and separates pending/durable values from effective runtime](behavior-history-protocol-extensions.md#ex09--duckdb-load-rejects-lifecycle-changes-and-separates-pendingdurable-values-from-effective-runtime) | Is this feature-owned LOAD/SAVE contract—reject unappliable lifecycle candidates, publish effective runtime, and persist pending Main separately—supported: **yes or no**? |
| [EX10 — DuckDB wire protocols expose a single-statement text-only SQL/result contract](behavior-history-protocol-extensions.md#ex10--duckdb-wire-protocols-expose-a-single-statement-text-only-sqlresult-contract) | Is a text-only, single-statement DuckDB API with complex-type text conversion and possible NULL degradation for unwrappable output an acceptable supported compatibility surface: **yes or no**? |
| [EX11 — DuckDB acknowledges SET autocommit without changing DuckDB transaction mode](behavior-history-protocol-extensions.md#ex11--duckdb-acknowledges-set-autocommit-without-changing-duckdb-transaction-mode) | For SET autocommit=0/1, should the endpoint **A: retain success as a compatibility no-op**, **B: reject it as unsupported**, or **C: implement matching transaction semantics**? |
| [EX12 — Router metadata compatibility is narrow, while routing guidelines are advisory diagnostics](behavior-history-protocol-extensions.md#ex12--router-metadata-compatibility-is-narrow-while-routing-guidelines-are-advisory-diagnostics) | When non-null routing-guideline metadata is present, should the plugin **A: continue with its baseline rules and expose an unsupported diagnostic**, or **B: refuse that topology until the guideline is supported or removed**? |
| [EX13 — Router metadata loss can retain admission and recompute from cached topology/current health](behavior-history-protocol-extensions.md#ex13--router-metadata-loss-can-retain-admission-and-recompute-from-cached-topologycurrent-health) | During metadata loss, should Router routing use **A: last validated membership plus available current health without an age cutoff**, **B: the same fallback only up to a configured age**, or **C: closed plugin gates until metadata recovers**? |
| [EX14 — Router ports are baseline routing rules, not a read-only authorization layer](behavior-history-protocol-extensions.md#ex14--router-ports-are-baseline-routing-rules-not-a-read-only-authorization-layer) | Is the Router RO/split contract endpoint selection by these baseline rules, with SQL write protection supplied by backend policy rather than a proxy authorization check: **yes or no**? |
| [EX15 — Router imports username-level account policy and retains previous unresolved credentials](behavior-history-protocol-extensions.md#ex15--router-imports-username-level-account-policy-and-retains-previous-unresolved-credentials) | When a previously owned username becomes conflicting/unsupported, should synchronization **A: retain its prior row and report unresolved as now**, or **B: disable that imported username until a supported unambiguous policy is available**? |
| [EX16 — Router metadata TLS policy does not set traffic-backend TLS](behavior-history-protocol-extensions.md#ex16--router-metadata-tls-policy-does-not-set-traffic-backend-tls) | Should the Router metadata default be **A: PREFERRED with plaintext fallback**, **B: REQUIRED with its current post-connect check**, or **C: VERIFY_IDENTITY with an operator-supplied trust anchor required before bootstrap**? |
| [EX17 — Router collapses backend Host variants without importing frontend source restrictions](behavior-history-protocol-extensions.md#ex17--router-collapses-backend-host-variants-without-importing-frontend-source-restrictions) | Should compatible backend Host variants be **A: collapsed and imported without frontend source restrictions as now**, **B: imported only after explicit operator opt-in for the username**, or **C: imported only with a supported translation of their client-source restrictions**? |
| [EX18 — Router-generated traffic backends default to unencrypted connections independently of metadata TLS](behavior-history-protocol-extensions.md#ex18--router-generated-traffic-backends-default-to-unencrypted-connections-independently-of-metadata-tls) | How should Router-generated backend traffic TLS be controlled: **A: retain use_ssl=false independently of metadata TLS**, **B: add a distinct mandatory operator choice for traffic TLS**, or **C: derive the traffic TLS requirement from the selected metadata TLS policy**? |

### GenAI, MCP, RAG and anomaly services

| ID and behavior | Intent question / choices |
| --- | --- |
| [AI-01 — Removal of the MySQL GenAI and LLM query syntax](behavior-history-ai-services.md#ai-01--removal-of-the-mysql-genai-and-llm-query-syntax) | Should the MySQL `GENAI:` and `LLM:` syntax remain removed? Yes / No. |
| [AI-02 — Authority conveyed by a configuration endpoint token](behavior-history-ai-services.md#ai-02--authority-conveyed-by-a-configuration-endpoint-token) | Should possession of the configuration endpoint token grant these general Admin-table read and DML permissions? Yes / No. |
| [AI-03 — Bearer credentials in URL parameters](behavior-history-ai-services.md#ai-03--bearer-credentials-in-url-parameters) | Should MCP continue accepting bearer credentials in URL parameters? Yes / No. |
| [AI-04 — Stateless, POST-only MCP transport](behavior-history-ai-services.md#ai-04--stateless-post-only-mcp-transport) | Is this stateless POST-only lifecycle the intended supported MCP contract? Yes / No. |
| [AI-05 — Direct backend targets and an implicit default target](behavior-history-ai-services.md#ai-05--direct-backend-targets-and-an-implicit-default-target) | With multiple executable targets, should an omitted `target_id` A) select an implicit default, or B) return an error requiring a target? |
| [AI-06 — MCP SQL rules may rewrite or acknowledge without executing](behavior-history-ai-services.md#ai-06--mcp-sql-rules-may-rewrite-or-acknowledge-without-executing) | Should these MCP rules retain both SQL replacement and successful acknowledgment without execution? Yes / No. |
| [AI-07 — Statistics pagination has a bounded offset as well as page size](behavior-history-ai-services.md#ai-07--statistics-pagination-has-a-bounded-offset-as-well-as-page-size) | Should statistics browsing A) remain limited to a capped offset, or B) allow all offsets while keeping each returned page bounded? |
| [AI-08 — Historical tools read specific stores rather than merge history](behavior-history-ai-services.md#ai-08--historical-tools-read-specific-stores-rather-than-merge-history) | Should MCP keep requiring an explicit disk source to retrieve persisted query events? Yes / No. |
| [AI-09 — Failure contract for incomplete history and discovery responses](behavior-history-ai-services.md#ai-09--failure-contract-for-incomplete-history-and-discovery-responses) | On incomplete source data should these tools A) fail the whole request, or B) return the available data with explicit per-component errors and an incomplete marker? |
| [AI-10 — RAG token authority includes refetching complete source rows](behavior-history-ai-services.md#ai-10--rag-token-authority-includes-refetching-complete-source-rows) | Should a RAG endpoint token authorize live refetch of every column from every enabled source? Yes / No. |
| [AI-11 — RAG source deletion removes search entries but retains document text](behavior-history-ai-services.md#ai-11--rag-source-deletion-removes-search-entries-but-retains-document-text) | For a confirmed deleted source row, should ingestion A) retain the document text in a tombstone, or B) erase its stored text and metadata? |
| [AI-12 — Enabling anomaly detection also enables blocking by default](behavior-history-ai-services.md#ai-12--enabling-anomaly-detection-also-enables-blocking-by-default) | Once anomaly detection is enabled, should its default be A) blocking matching queries, or B) observation only until blocking is separately enabled? |

### Packaging, builds and operator tools

| ID and behavior | Intent question / choices |
| --- | --- |
| [DE01 — RPM upgrades stop forcing a service restart](behavior-history-delivery.md#de01--rpm-upgrades-stop-forcing-a-service-restart) | Should RPM upgrades leave restart timing under operator/distribution control? **Choices:** A: retain no forced upgrade restart; B: automatically restart the service on upgrade. |
| [DE02 — Ordinary Darwin/FreeBSD builds gain ClickHouse capability](behavior-history-delivery.md#de02--ordinary-darwinfreebsd-builds-gain-clickhouse-capability) | Should normal Darwin/FreeBSD builds include ClickHouse capability by default? **Choices:** Yes / No. |
| [DE03 — The PostgreSQL user synchronizer disables individually missing roles](behavior-history-delivery.md#de03--the-postgresql-user-synchronizer-disables-individually-missing-roles) | Should disable be the default for individually missing managed roles? **Choices:** A: disable, as implemented; B: keep the previous account active unless explicitly configured to disable. |
| [DE04 — The synchronizer persists successful user loads by default](behavior-history-delivery.md#de04--the-synchronizer-persists-successful-user-loads-by-default) | What should the synchronizer default be for disk persistence? **Choices:** A: automatically SAVE after successful LOAD; B: persist only when explicitly opted in. |
| [DE05 — The drift guard covers backend user policy before a global LOAD](behavior-history-delivery.md#de05--the-drift-guard-covers-backend-user-policy-before-a-global-load) | Which unrelated pending user edits should block the synchronizer before its global LOAD? **Choices:** A: detected backend-half drift only, as implemented; B: all frontend/backend user-policy drift, requiring a broader guard. |
| [DE06 — An empty authoritative role snapshot is rejected by default](behavior-history-delivery.md#de06--an-empty-authoritative-role-snapshot-is-rejected-by-default) | Should empty snapshots require explicit permission? **Choices:** A: refuse by default, as implemented; B: accept a successfully fetched empty snapshot as authoritative by default. |
| [DE07 — Importer failures may leave partially edited MEMORY rows](behavior-history-delivery.md#de07--importer-failures-may-leave-partially-edited-memory-rows) | Should failed batches leave owned MEMORY changes for resumable reconciliation? **Choices:** A: retain the explicit partial/repair-on-next-run behavior; B: require restoration of the prior editable state before reporting a failed batch. |

## Previous answers and already documented decisions

The [SET questionnaire](set-behavior-history-questions.md#maintainer-decisions--2026-10-18) preserves the 34 original IDs and its original source endpoint. E1/E2 classify variables as absent for the backend object lifetime, rather than caching invalid values. W4=B still requires a production change. P1=A has its parser-selection reference. N6=A keeps the gate. U7 is clarified and retired; hidden writes are discouraged, not prevented, and replay of recorded frontend values is correct. G1 remains open after origin research; G8 is deferred to [issue #6504](https://github.com/sysown/proxysql/issues/6504) and its RFC. None is silently answered or reopened here.

RT02’s connection-lifetime version pin is explicitly specified in the maintainer-authored [PR #6151](https://github.com/sysown/proxysql/pull/6151). AU04’s miss-only pass-through TLS check and AU06’s additive verified-certificate condition are explicit in the maintainer-authored Behavior section of [PR #6028](https://github.com/sysown/proxysql/pull/6028). Their source histories remain in the detailed reports as recorded decisions. Other explicit decisions, including #5987 management credential namespaces, #6115 OpenSSL shipping and #6415 GTID watermark policy, are recorded by the relevant stream. Bot summaries and implementation/spec prose alone were not accepted as maintainer answers.

## Source concerns requiring investigation, separate from intent questions

The review found source paths that appear not to enforce an existing or exposed contract. Those are not offered as “approve the bug” choices. They require focused reproduction and design analysis before a production fix:

- [AI service concerns](behavior-history-ai-services.md#corrections-limitations-and-superseded-mechanisms): SQL execution drops advertised row/time/permission/TLS controls; RAG controls are not fully consumed; anomaly settings and outcomes are disconnected; the standalone ingester has destructive incremental reconciliation/duplicate-insert paths. An independent review rechecked the highest-impact control and ingestion paths; these are source findings, not reproduced outcomes.
- [Protocol-extension concerns](behavior-history-protocol-extensions.md#source-concerns-separate-from-policy-approval): MySQL X backend ownership/state and exposed transport controls need dedicated verification.
- [Administration concerns](behavior-history-administration.md#existing-contracts-and-surviving-concerns--not-approval-questions): plugin callback blocking, startup dependencies and shared-connection rollback ownership need focused follow-up.
- [Backend concerns](behavior-history-backends.md#corrections-restorations-and-resolved-decisions): lag-counter scope, DNS-disabled failure accounting and tier-dependent recovered-server capacity guards remain source follow-ups.
- [Traffic concerns](behavior-history-traffic.md#corrections-restored-states-and-inherited-concerns): pooled-version pointer lifetime and cache/private-state eligibility need focused checks against existing policy. This audit does not claim a demonstrated cross-session cache leak.

## Coverage and verification limits

The [integration inventory](behavior-history-inventory.md) assigns every one of the 465 integrations a disposition and links its evidence stream. Coverage was reconciled after the initial path-based queues: authentication gained 28 supplemental integrations, observability gained five diagnostic handoffs, and support/no-net-change integrations have explicit entries. Cross-stream handoffs were checked for an owner rather than counted as completed review by themselves.

The detailed reports distinguish scoped source/consumer traces from diff/path screens. They are not a line-by-line audit of all 5,368 commits or every bundled dependency. Changes that restore an existing guarantee, are later reverted, or only affect tests/docs/build support are identified separately; a passing screen is not proof that the entire integration is defect-free. Test/CI changes are inventoried, but execution semantics of external reusable workflow bodies and downstream plugin/provider implementations are outside the pinned repository evidence.

Independent source review corrected two draft overstatements before publication: OB04 now limits approximate cross-column digest observations to live-map/Top-K readers, distinguishing normal detached Admin SQL dumps; DE05 now precisely describes the backend-half drift guard and the frontend gap before a global LOAD. A separate reviewer checked the strongest AI control/ingestion findings. The architecture’s obsolete PostgreSQL heartbeat-query claim was also corrected to the actual WAL-query path.

No builds, tests, live package upgrades, authentication attempts or traffic experiments were executed for this audit. Static verification covers coverage/count consistency, Markdown/local/source links, commit reachability and whitespace. No production code or behavior changed.

Static checks on the 13 new/updated documents verified 2,729 Markdown links, including 406 local references and 667 immutable source URLs across 163 file revisions; all 508 cited source/integration commits are reachable from END. All 465 integration rows have an owning disposition, and the 123 unanswered IDs are unique. Previously recorded SET decisions and question bodies are unchanged.
