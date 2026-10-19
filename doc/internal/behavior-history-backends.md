# Backend behavior history, 2025-10-19 through 2026-10-19

This is a source audit and maintainer-question list, not an implementation proposal or approval. It covers the supplied **92 first-parent integration candidates**, including support matches, from BASE `70228332135431229940279e49b6db186c6e4241` through END `9516441f7bd6fdb93f255f1881db19ca9ee56778`. Integration dates in the queue, not side-branch author dates, define the window. The preceding state for each selected change is its actual first parent. END was inspected with `git show`, without switching the documentation branch.

The research follows `CLAUDE.md`, `doc/agents/invariants.md`, `doc/architecture.md` and the backend-management chapter. I-1 through I-8 remain binding; no option below approves a LOAD veto, Stable-tier regression, unsafe connection sharing, accidental commit or forbidden retry. Existing SET questions are not reopened. Immutable source links point to the actual integration/parent or END. Feature documents describe stated intention; their existence alone does not prove a maintainer decision. The explicit final #6415 highest-GTID decision is treated as resolved.

Depth: **deep** means the relevant changed backend paths were compared with their immediate predecessor, traced to the cited owner/consumer, and checked at END; it does not mean every file of a large mixed PR was reviewed. **screen** means path/hunk/available support evidence was inspected to route or classify it, without a full semantic audit. No builds, installs, runtime probes or tests were run; source-derived examples are predictions, not reproduced outcomes. GitHub issue/PR discussion threads and external AWS deployment traces were not independently retrieved. No production source was edited.

## Questions requiring maintainer intent

These questions distinguish purposeful policy choices from restoration of established behavior. None has a preselected answer.

### BE01 — What does PostgreSQL replication lag promise?

**Integration:** [`c60f390b4`](https://github.com/sysown/proxysql/commit/c60f390b447b758bb592130872b073cee47c86c7). **Activation/tier/defaults:** All tiers, PostgreSQL monitor enabled (default true), a replication-hostgroup membership with max_replication_lag > 0. Default lag interval 10000 ms, timeout 1000 ms, count 1; max_replication_lag=0 leaves lag exclusion disabled.

**Before:** The scheduler created connect, ping and read-only tasks; the existing lag HGM methods were not driven by a PostgreSQL lag probe.

**After at END:** The new probe compares the last received and replayed WAL positions and otherwise measures time since the last replayed transaction. It is not a primary-to-replica network-lag measurement. A successful first-cell result is converted to integer seconds with atoi; the parser has no explicit SQL-NULL/unknown result branch. The Percona-heartbeat query path is disabled.

**Concrete consequence:** A replica whose receive and replay positions match can report zero while disconnected from its primary. A value of 5.9 seconds is acted on as 5, so a configured limit of 5 is not exceeded until the integer value rises.

**Decision:** Which promise is intended? A: exclude only observed receive-to-replay lag using this integer-seconds measure. B: also require evidence of primary-to-replica freshness. C: make the measurement/freshness policy configurable.

**Evidence:** [before task types](https://github.com/sysown/proxysql/blob/d3af6c11bf6682d94bcd6825f26942f631bb9474/lib/PgSQL_Monitor.cpp#L261); [END lag SQL](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Monitor.cpp#L47); [END conversion](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Monitor.cpp#L701); [END defaults](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Thread.cpp#L1084).

### BE02 — Does a failed PostgreSQL lag check retain admission indefinitely?

**Integration:** [`c60f390b4`](https://github.com/sysown/proxysql/commit/c60f390b447b758bb592130872b073cee47c86c7). **Activation/tier/defaults:** Same activation as BE01. The separate ping health policy still applies; this asks about a backend that answers ping but whose lag query repeatedly fails.

**Before:** There was no active PostgreSQL lag-check cycle whose failure needed an admission policy.

**After at END:** Only successful lag checks call replication_lag_action. Query errors and timeouts are logged/counted but do not shun, restore, or reset the membership lag counter. There is no age bound on the last successful lag admission decision in this path.

**Concrete consequence:** After a healthy sample, revoke the monitor role’s ability to execute the lag query while leaving connectivity intact: the member can remain ONLINE despite arbitrarily old lag evidence. Conversely, after a bad sample then errors, the accumulated bad count survives.

**Decision:** Choose the failure contract: A: retain the last lag admission state until a successful sample or another health policy changes it. B: exclude after a bounded age or failure count. C: fail open/closed according to an explicit hostgroup policy.

**Evidence:** [before scheduler](https://github.com/sysown/proxysql/blob/d3af6c11bf6682d94bcd6825f26942f631bb9474/lib/PgSQL_Monitor.cpp#L261); [END success-only action](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Monitor.cpp#L1887); [END lag state/counters](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_HostGroups_Manager.cpp#L3046).

### BE03 — Is PostgreSQL lag action scoped to an endpoint or one membership?

**Integration:** [`c60f390b4`](https://github.com/sysown/proxysql/commit/c60f390b447b758bb592130872b073cee47c86c7). **Activation/tier/defaults:** All tiers; endpoint appears in at least one configured PostgreSQL replication writer/reader group with positive max_replication_lag. The exposed monitor_replication_lag_group_by_host defaults false but this HGM branch hardcodes endpoint-wide action.

**Before:** The dormant HGM lag function selected its branch using the MySQL-named thread variable; no PostgreSQL lag scheduler drove it.

**After at END:** The scheduler creates one probe per hostgroup/endpoint tuple. Every successful result scans every hostgroup membership with the same hostname:port; each membership applies its own max_replication_lag. This includes memberships outside the replication pair that caused the probe.

**Concrete consequence:** The same replica exists in a replication reader group with limit 5 and an independent reporting group with limit 30. A probe admitted by the first configuration can also change the second group’s status. Multiple scheduled memberships also produce multiple counter increments per scheduling round (a separate correctness follow-up below).

**Decision:** Should one observation govern A: every membership of the endpoint, B: only the probed membership, or C: only memberships in the configured replication relationship?

**Evidence:** [before scope selection](https://github.com/sysown/proxysql/blob/d3af6c11bf6682d94bcd6825f26942f631bb9474/lib/PgSQL_HostGroups_Manager.cpp#L2705); [END probe grouping](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Monitor.cpp#L517); [END endpoint-wide branch](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_HostGroups_Manager.cpp#L3110).

### BE04 — Should PostgreSQL monitoring require the configured transport?

**Integration:** [`2667540fc`](https://github.com/sysown/proxysql/commit/2667540fcc3bd576c40ed2bc7b04cb903b86602b). **Activation/tier/defaults:** All tiers, PostgreSQL monitoring. use_ssl defaults 0; grouped probe targets use MAX(use_ssl). Per-server TLS rows added by 7f14beedc select the monitor username first, then the empty-username row, then global settings.

**Before:** Monitor connection strings omitted sslmode and the per-server TLS material, leaving libpq transport negotiation to its defaults/environment.

**After at END:** The monitor explicitly sends sslmode=require for use_ssl=1 and sslmode=disable for use_ssl=0. When any membership enables TLS, the grouped endpoint probe uses TLS. Per-server configuration is a whole-row replacement for the global certificate/CA/CRL/protocol fields, including empty fields.

**Concrete consequence:** An endpoint shared by a plaintext group and a TLS group has one TLS monitor target. A monitor-specific TLS row containing only a client certificate can leave globally configured CA fields empty rather than inherit them.

**Decision:** Confirm the monitoring contract: A: configured/grouped transport is mandatory and a selected TLS row fully replaces global fields. B: permit transport fallback. C: keep strict transport but inherit unspecified TLS fields.

**Evidence:** [before connection options](https://github.com/sysown/proxysql/blob/6ee087c73c1105c56235fa4764cc2be36e7bc948/lib/PgSQL_Monitor.cpp#L873); [END grouped use_ssl](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Monitor.cpp#L505); [END TLS row/global choice](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Monitor.cpp#L452); [END strict modes](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Monitor.cpp#L1095); [END username precedence](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_HostGroups_Manager.cpp#L4504).

### BE05 — Is the new PostgreSQL DNS TTL a refresh timer or a validity limit?

**Integration:** [`453c7554b`](https://github.com/sysown/proxysql/commit/453c7554bff14acdea1b4896e98157a6bcf2d19e). **Activation/tier/defaults:** All tiers, PostgreSQL DNS cache enabled by nonzero TTL/refresh interval; defaults are 300000/60000 ms. Traffic connections consume the cache; native multi-address fallback was subsequently repaired by 5ace3febc.

**Before:** PostgreSQL traffic relied on libpq resolution for new connections; it had no separately owned PostgreSQL DNS cache/resolver cycle.

**After at END:** A successful connection can seed the cache, background resolution refreshes it, and traffic receives cached addresses. Expiration removes the bookkeeping item and starts a lookup, but a failed lookup does not remove the old cache entry. DNS_Cache::lookup has no ordinary-record TTL test. Failed refreshes can therefore continue serving the old address until a later success, explicit removal, or disabling the cache. This follows the existing MySQL strategy but is newly applied to PostgreSQL.

**Concrete consequence:** A hostname is moved to a replacement server and subsequent resolution is unavailable. New PostgreSQL connections may continue dialing the old address beyond five minutes even though the variable is called cache_ttl.

**Decision:** Which stale-address policy is intended? A: keep serving the last address through arbitrary DNS failures. B: stop serving at TTL expiry and use resolver/error handling. C: keep a separately bounded stale grace period.

**Evidence:** [before direct libpq connection](https://github.com/sysown/proxysql/blob/9719d4ae0591d8de905b9456df08c3e95117d220/lib/PgSQL_Connection.cpp#L951); [END refresh expiry](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Monitor.cpp#L3001); [END success-only bookkeeping](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Monitor.cpp#L3075); [END lookup without record TTL](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/DNS_Cache.cpp#L338); [END defaults](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Thread.cpp#L1105).

### BE06 — Should the attached hostgroup override the global query timeout?

**Integration:** [`0069d4249`](https://github.com/sysown/proxysql/commit/0069d42492ec145447ec99af097ec5164540145b). **Activation/tier/defaults:** Both protocols, all tiers. Configure hostgroup_settings.default_query_timeout in [1000,1728000000] ms and LOAD servers. Default hostgroup sentinel is -1, so absent configuration uses existing behavior.

**Before:** SetQueryTimeout chose a positive query-rule timeout and otherwise the protocol global default.

**After at END:** It inserts the attached backend membership’s current hostgroup timeout between the query rule and global default. The backend actually used supplies the setting, and it is read when the query deadline is established. A rule timeout of zero does not establish a deadline, so a positive hostgroup default still applies.

**Concrete consequence:** With global timeout 60000 and hostgroup 10 timeout 2000, a query routed to a backend in 10 receives a two-second deadline despite the global value; a rule timeout 0 does not disable that hostgroup deadline.

**Decision:** Ratify A: positive rule timeout, then attached-hostgroup default, then global default; B: rule zero explicitly disables all defaults; or C: a different precedence tied to the originally requested hostgroup rather than the attached membership.

**Evidence:** [before MySQL deadline](https://github.com/sysown/proxysql/blob/e9dfbeb21dd7225d0cc123b57651b489a05258c0/lib/MySQL_Session.cpp#L5337); [END MySQL precedence](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L6470); [END PostgreSQL precedence](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L2736); [END disabled default](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/BaseHGC.cpp#L81).

### BE07 — When does a primary suppress same-hostgroup backups?

**Integration:** [`da57c6e46`](https://github.com/sysown/proxysql/commit/da57c6e46431312d6a00a27d2fed10f3e7649f7e). **Activation/tier/defaults:** Both protocols, PROXYSQL31 (therefore also PROXYSQL40), positive backup_weight_threshold T in hostgroup_settings. Default T=0 disables the feature; missing backup_availability means selectable.

**Before:** Every eligible positive-weight server participated in the weighted draw; a low weight was a probability rather than a spare designation.

**After at END:** Weights >=T are primaries and 0<weight<T are backups. A primary candidate suppresses backups. Otherwise selectable admits backups; status suppresses backups if any primary is ONLINE even if unusable by capacity/latency/GTID; capacity suppresses if a primary is ONLINE and has used-capacity available even if excluded by another predicate.

**Concrete consequence:** A GTID-ineligible or high-latency primary remains ONLINE. Under status/capacity, a ready backup may be excluded and acquisition can wait/fail, while selectable would admit it. With status, an ONLINE but saturated primary also suppresses the spare.

**Decision:** Is this availability definition intended? A: retain all three modes with these distinct failure outcomes. B: backups become usable whenever no primary can satisfy the request. C: preserve status/capacity modes but enumerate which additional exclusions should count as primary absence.

**Evidence:** [before weighted selection](https://github.com/sysown/proxysql/blob/4330a35102c9c0c1f771264c7e4a6373be13b305/lib/MyHGC.cpp#L14); [END primary presence](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MyHGC.cpp#L23); [END partition/filter](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MyHGC.cpp#L74); [END PostgreSQL counterpart](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_HostGroups_Manager.cpp#L130); [END defaults](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/BaseHGC.cpp#L83).

### BE08 — Does backup exclusion apply to worker-local reuse?

**Integration:** [`da57c6e46`](https://github.com/sysown/proxysql/commit/da57c6e46431312d6a00a27d2fed10f3e7649f7e). **Activation/tier/defaults:** Same feature activation as BE07, and a compatible released backup connection remains in a worker-local cache. The MySQL AWS-locality local path also omits the backup partition.

**Before:** Worker-local cache reuse did not implement a primary/backup distinction because that distinction did not exist.

**After at END:** The new primary/backup partition is applied in global HGM server selection. Neither protocol’s local matching checkout checks backup_weight_threshold or backup_availability; a compatible locally held backup can be borrowed before the global selector runs.

**Concrete consequence:** A backup served during a primary outage. The primary recovers while a backup socket is retained locally. A subsequent compatible request can still borrow that socket although a global checkout would now select only primaries.

**Decision:** Should primary/backup policy govern A: global acquisition only, allowing local reuse to retain affinity, B: every new frontend borrower including local reuse, or C: only after a bounded drain/grace period following primary recovery?

**Evidence:** [before no backup policy](https://github.com/sysown/proxysql/blob/4330a35102c9c0c1f771264c7e4a6373be13b305/lib/MyHGC.cpp#L14); [END global enforcement](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MyHGC.cpp#L298); [END MySQL local consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L7248); [END PostgreSQL local consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Thread.cpp#L6201).

### BE09 — Is two ping intervals the serious-shun minimum recovery delay?

**Integration:** [`185abefec`](https://github.com/sysown/proxysql/commit/185abefec1c0862fd5c14465e84f1ace099a894b). **Activation/tier/defaults:** MySQL all tiers, serious shun_and_killall with monitoring enabled. Applies beyond Aurora. Existing recovery also requires used/free connections to drain and the selector can perform its existing accelerated retry when no normal weight exists.

**Before:** shun_and_killall extended the error timestamp using one monitor_ping_interval when it exceeded shun_recovery_time_sec.

**After at END:** The timestamp extension uses twice monitor_ping_interval to avoid recovery before the next health observation. The ordinary recovery delay can therefore be controlled by monitor cadence even when the operator set a much smaller explicit shun_recovery_time_sec.

**Concrete consequence:** At ping interval 8 seconds and shun recovery 1 second, the ordinary eligibility recovery window is stretched toward 16 seconds (with strict time comparison/granularity), instead of toward 8 seconds. This is source timing arithmetic, not a measured outage bound.

**Decision:** Which recovery contract is intended? A: the fixed two-interval safety margin. B: recovery only after a confirmed successful probe. C: the configured shun recovery remains authoritative with a separately configurable monitor margin.

**Evidence:** [before one interval](https://github.com/sysown/proxysql/blob/0ceb3368042947f00e7c1d8372d7c88f3a3214a5/lib/MySQL_HostGroups_Manager.cpp#L3744); [END doubled margin](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_HostGroups_Manager.cpp#L4414); [END accelerated fallback context](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MyHGC.cpp#L301).

### BE10 — May Aurora topology absence remove configured memberships?

**Integration:** [`185abefec`](https://github.com/sysown/proxysql/commit/185abefec1c0862fd5c14465e84f1ace099a894b). **Activation/tier/defaults:** MySQL Aurora monitor all tiers, active mysql_aws_aurora_hostgroups row with autopurge_missing_checks > 0 (default 0, range 0..100). Successful nonempty REPLICA_HOST_STATUS results drive the counter; query failures/empty results do not.

**Before:** The Aurora monitor discovered/adjusted roles and lag but did not remove absent runtime members through this automatic purge policy.

**After at END:** After the configured number of missing samples, both writer and reader hostgroup memberships are removed through remove_server_in_hg; OFFLINE_HARD is skipped, other statuses participate. Reappearance resets that member counter; failed/empty probes neither advance nor reset it. Runtime topology removal is stronger than shunning and is not an edit to persistent Admin input.

**Concrete consequence:** With threshold 3, three nonempty topology snapshots omitting a reporting member, separated by failed probes, can remove that member. A later Admin LOAD of its saved row can reintroduce it.

**Decision:** Confirm A: successful nonempty topology absence is enough to remove runtime membership after N samples, including across intervening failures. B: only consecutive successful observations count and missing members are shunned. C: removal requires independent confirmation or a different configured policy.

**Evidence:** [before result actions](https://github.com/sysown/proxysql/blob/0ceb3368042947f00e7c1d8372d7c88f3a3214a5/lib/MySQL_Monitor.cpp#L6319); [END activation gate](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L6438); [END absence counters/removal](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L8236); [END removal effect](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_HostGroups_Manager.cpp#L7755).

### BE11 — Does GTID evidence remain trusted while its reader is disconnected?

**Integration:** [`efe591090`](https://github.com/sysown/proxysql/commit/efe591090254703fb637e4500e17ae14ca184445). **Activation/tier/defaults:** MySQL causal-read selection with a configured nonzero gtid_port and populated GTID data. The removal of active gating is unconditional; update_gtid_from_ok defaults false and does not need to be enabled for this behavior.

**Before:** gtid_exists required the endpoint’s GTID_Server_Data::active flag to be true before considering its executed set.

**After at END:** A stored GTID can satisfy eligibility even with the reader inactive. Successful reader reconnection now clears the old executed set before bootstrap (380cb3eac), but the failure/disconnected interval retains it. New OK-packet evidence can also update the existing endpoint entry when explicitly enabled.

**Concrete consequence:** The reader disconnects after reporting uuid:42. The database endpoint stays ONLINE, or its address is reassigned before reader reconnect completes. A causal read requiring 42 can still select it from the remembered set until a successful reader reconnect clears the knowledge.

**Decision:** Which trust boundary is intended? A: retain execution knowledge until a successful reconnect replaces it. B: stop trusting reader-derived knowledge as soon as the reader fails. C: retain only independently validated connection/identity-bound evidence, with a bounded lifetime.

**Evidence:** [before active gate](https://github.com/sysown/proxysql/blob/6ebf75fff142e843aab701619dc84d2e0e2199e3/lib/MySQL_HostGroups_Manager.cpp#L1701); [END ungated lookup](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_HostGroups_Manager.cpp#L2158); [END reconnect reset](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/GTID_Server_Data.cpp#L287); [END failure leaves object](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/GTID_Server_Data.cpp#L80); [END opt-in default](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L1535).

### BE12 — When should a stale-IP monitor timeout stop counting as backend failure?

**Integration:** [`8ca2df54f`](https://github.com/sysown/proxysql/commit/8ca2df54f6ecb5b15712a27d4e813162cbb0523e). **Activation/tier/defaults:** Generic MySQL read-only, Group Replication and Galera timeout paths, all tiers, hostname endpoints with an established monitor socket. No active BGD deployment is required. Literal IPs and port=0 are excluded.

**Before:** A probe timeout followed the normal missed-check/error/role or viability handling.

**After at END:** The new timeout class marks a probe as stale if its connected peer IP is not valid in the current DNS cache; these stale timeouts avoid the normal health actions. This can preserve endpoint availability during a DNS cutover rather than applying an old socket’s failure to the new endpoint.

**Concrete consequence:** During DNS replacement, the old monitor connection hangs. Normal timeout policy could demote/shun a healthy replacement hostname; ignoring the old-address failure instead waits for probing the new destination. Separately, the predicate also treats missing/disabled cache as not-valid; that stronger correctness concern is recorded below.

**Decision:** Should the health contract A: ignore a timeout only when positive DNS evidence proves the socket belongs to an obsolete address, B: count any endpoint probe timeout toward normal failure policy, or C: retry the current resolved address before deciding?

**Evidence:** [before ordinary timeout](https://github.com/sysown/proxysql/blob/a8c1cef4d44c4beea7f6aa21b8a09a7cb8c75520/lib/MySQL_Monitor.cpp#L794); [END stale decision](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L8458); [END GR action consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L9420); [END Galera consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L9909); [END missing/disabled semantics](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/DNS_Cache.cpp#L208).

### BE13 — Does enabling RDS discovery authorize automatic Blue/Green control?

**Integration:** [`8ca2df54f`](https://github.com/sysown/proxysql/commit/8ca2df54f6ecb5b15712a27d4e813162cbb0523e). **Activation/tier/defaults:** MySQL all tiers. Existing monitor_aws_rds_topology_discovery_interval defaults 0 (discovery off); new aws_blue_green_deployment_auto_discovery defaults 1. A positive discovery interval, replication writer/reader mapping, and recognizable role/status metadata can activate it without an explicit BGD configuration row.

**Before:** RDS topology discovery recognized the existing Multi-AZ cluster shape; there was no BGD controller/runtime row creation path.

**After at END:** Recognized BGD metadata can create an active runtime deployment with NULL green hostgroups, writer_is_also_reader=0, check interval 1000 ms and timeout 800 ms. The first matching replication mapping is selected. Subsequent phases can change DNS, hostgroup placement and connection eligibility. Auto-generated rows are runtime-only and skipped on normal SAVE-to-persistent BGD tables.

**Concrete consequence:** An operator previously enabled topology discovery to learn Multi-AZ membership. After upgrade, the same setting plus returned BGD metadata can authorize active switchover control without inserting a BGD row.

**Decision:** Choose the activation boundary: A: existing topology discovery plus the default-enabled BGD auto-discovery switch authorizes the controller. B: BGD control requires explicit operator opt-in distinct from discovery. C: discovery may create an inactive row that an operator must activate.

**Evidence:** [before discovery classifier](https://github.com/sysown/proxysql/blob/a8c1cef4d44c4beea7f6aa21b8a09a7cb8c75520/lib/MySQL_Monitor.cpp#L3452); [END discovery defaults](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L1383); [END classifier/caller](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L3674); [END auto row defaults](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_HostGroups_Manager.cpp#L8346).

### BE14 — What observation proves Blue/Green completion or rollback?

**Integration:** [`8ca2df54f`](https://github.com/sysown/proxysql/commit/8ca2df54f6ecb5b15712a27d4e813162cbb0523e). **Activation/tier/defaults:** Active MySQL BGD monitoring, explicit or automatically discovered, all tiers. The feature document describes this as ProxySQL policy derived partly from one deployment trace; that is stated intention, not independent maintainer ratification.

**Before:** There was no BGD state machine or inferred reader-completion boundary.

**After at END:** Writer SWITCHOVER_COMPLETED enters a separate reader-wait state. An empty, absent or vanished topology table then causes successful cleanup; the same observations before writer completion cause rollback. Generic query failures retain state. A nonempty unclassified topology/missing target/empty status instead changes to NONE without the rollback helper; an unknown nonempty status can take the backward/rollback path.

**Concrete consequence:** A metadata table disappears while waiting for readers: the monitor unshuns readers and drops pins without directly verifying each reader’s DNS propagation. The same absence just before observing writer completion instead restores the blue placement.

**Decision:** Which completion evidence is acceptable? A: retain the phase-dependent empty/absent-table inference. B: require direct per-reader/target confirmation. C: make the inference configurable with a timeout/manual-resolution policy. Missing or unrecognized metadata shape also needs an explicit retain/rollback/cleanup decision rather than relying on its parser shape.

**Evidence:** [before no BGD controller](https://github.com/sysown/proxysql/blob/a8c1cef4d44c4beea7f6aa21b8a09a7cb8c75520/lib/MySQL_Monitor.cpp#L3475); [END phase classifier](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L7571); [END success/rollback decision](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L7991); [stated feature intention](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/doc/AWS_Blue_Green/RDS_BGD_Monitor.md#L209).

### BE15 — Should Blue/Green cutover terminate existing backend work?

**Integration:** [`8ca2df54f`](https://github.com/sysown/proxysql/commit/8ca2df54f6ecb5b15712a27d4e813162cbb0523e). **Activation/tier/defaults:** Active MySQL BGD post-processing with a resolved green pair, all tiers. A drain matches hostname:port across every HGM membership, beyond the deployment’s named hostgroups. The feature does not authorize transaction replay; I-8 remains binding.

**Before:** There was no BGD DNS pin/drain action; ordinary server-status and lifetime policies controlled established sockets.

**After at END:** Post-processing pins blue names to green addresses, drops shared free sockets and marks used sockets healthy=false/reusable=false. Current protocol steps can fail when they next observe unhealthy state; the sockets are destroyed rather than returned. This is active interruption, not merely retiring idle capacity after a graceful transaction boundary. Completion also drains eligible configured green endpoints.

**Concrete consequence:** A long-running transaction or a query using the same endpoint in another hostgroup can lose its backend when the BGD worker pins that endpoint, even before that frontend voluntarily releases the connection.

**Decision:** Should cutover A: interrupt all existing work for the endpoint as implemented, B: stop new borrows but let current owners finish, or C: allow a configured drain deadline before forced interruption? Transaction safety, isolation and retry invariants constrain all three choices.

**Evidence:** [before offline predicate](https://github.com/sysown/proxysql/blob/a8c1cef4d44c4beea7f6aa21b8a09a7cb8c75520/lib/mysql_connection.cpp#L2162); [END pin then drain](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L7759); [END all-membership retirement](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_HostGroups_Manager.cpp#L4649); [END protocol health consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/mysql_connection.cpp#L2427); [stated interruption/retirement contract](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/doc/AWS_Blue_Green/RDS_BGD_Monitor.md#L435).

### BE16 — Can Blue/Green temporarily override reader placement and retain green rows?

**Integration:** [`8ca2df54f`](https://github.com/sysown/proxysql/commit/8ca2df54f6ecb5b15712a27d4e813162cbb0523e). **Activation/tier/defaults:** Active MySQL BGD post-processing. writer_is_also_reader from configuration or automatic mode; explicit green hostgroups permit green-row materialization.

**Before:** Ordinary replication configuration supplied writer/reader membership; there was no BGD policy that temporarily overrode it or retained BGD-added green membership.

**After at END:** Unmapped blue readers become SHUNNED_AWS_BGD. If all readers would be shunned, the writer is temporarily made a reader even when writer_is_also_reader=0. Cleanup restores that configured reader preference and unshuns recorded readers. Added green rows remain runtime configuration after both success and rollback; successful cleanup drains eligible green sockets, rollback deliberately does not.

**Concrete consequence:** An application using its reader hostgroup to isolate load from the writer can send read traffic to the writer during cutover. A green writer added during discovery can remain selectable in its green hostgroup after cancellation until configuration is changed.

**Decision:** Ratify A: availability-driven temporary writer fallback plus retained green membership, B: respect writer_is_also_reader=0 even if readers become unavailable and remove monitor-added green rows on cleanup, or C: independently configure those two policies.

**Evidence:** [before no BGD reader override](https://github.com/sysown/proxysql/blob/a8c1cef4d44c4beea7f6aa21b8a09a7cb8c75520/lib/MySQL_Monitor.cpp#L3475); [END fallback logic](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L7719); [END cleanup split](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L7849); [stated green membership persistence](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/doc/AWS_Blue_Green/RDS_BGD_Monitor.md#L512).

### BE17 — What recovery guarantee owns Blue/Green side effects?

**Integration:** [`8ca2df54f`](https://github.com/sysown/proxysql/commit/8ca2df54f6ecb5b15712a27d4e813162cbb0523e). **Activation/tier/defaults:** All active MySQL BGD deployments, especially configuration reloads during/post cutover, disable/removal, worker exit and process restart. Overlapping endpoint assignments to active deployments are documented as unsupported and unvalidated.

**Before:** No BGD controller owned DNS pins, temporary role changes or BGD shuns.

**After at END:** Effects live in worker-local maps. Cleanup invokes operations once, clears its state, and has no retained per-effect retry ledger. A configuration change at/after post-processing rolls back and restarts from NONE; earlier phases reconstruct mappings. A new worker/process starts with no prior deployment progress; its first completed-phase observation does not reconstruct the former map. An endpoint is required to belong to only one active deployment, by operator discipline.

**Concrete consequence:** A deployment is disabled during post-processing or its worker loses a complete map. The feature promises best-effort cleanup of known effects, not proof of all external postconditions; re-enable/restart does not recover the old ownership record.

**Decision:** Which operational contract is intended? A: best-effort one-shot cleanup, fresh-start recovery and unsupported overlap are accepted limitations. B: retain/reconcile effects until confirmed clean and reject overlapping claims. C: keep limited recovery but expose explicit unresolved-effect state requiring operator action.

**Evidence:** [before no BGD effect owner](https://github.com/sysown/proxysql/blob/a8c1cef4d44c4beea7f6aa21b8a09a7cb8c75520/lib/MySQL_Monitor.cpp#L3475); [END phase-dependent refresh](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L7428); [END one-shot effects/state clearing](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L7849); [stated one-shot limit](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/doc/AWS_Blue_Green/RDS_BGD_Monitor.md#L529); [stated overlap constraint](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/doc/AWS_Blue_Green/RDS_BGD_Monitor.md#L648).

### BE18 — Does enabling locality intentionally change neutral local-cache selection?

**Integration:** [`37d627b97`](https://github.com/sysown/proxysql/commit/37d627b9743f7d51d6b783b039f994e0b18474f0). **Activation/tier/defaults:** MySQL PROXYSQL40, mysql-aws_locality_awareness=true (default false), valid hostgroup aws.locality_awareness policy with both multipliers. No external provider is required for the neutral metadata state to exist.

**Before:** Local checkout returned the first fully compatible cached connection satisfying GTID/lag/backoff checks; it did not draw among parent servers by configured weight.

**After at END:** Enabled locality builds distinct-parent candidates from compatible cached sockets and uses snapshot effective weights, even when all metadata is unknown/provider-unavailable and every multiplier is 1.0. Multiple sockets of one parent do not multiply its selection weight. If total local weight is zero it uses a uniform parent fallback; the global selector still rejects a zero-total-weight hostgroup.

**Concrete consequence:** With identical compatible sockets on parents weighted 1 and 9, merely enabling locality can change local-cache distribution before any metadata provider succeeds. With cached zero-weight parents, local and global zero-weight outcomes differ.

**Decision:** Is neutral mode A: configured-weight local selection and the uniform zero-weight cache fallback as implemented, B: exact pre-feature local selection when no positive locality evidence exists, or C: weighted local selection but no zero-weight reuse?

**Evidence:** [before first-compatible local checkout](https://github.com/sysown/proxysql/blob/04dc9afa05757abb94c76dcc21af8550faa436d2/lib/MySQL_Thread.cpp#L7064); [END locality activation](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L7269); [END neutral/zero-weight local lottery](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L7447); [END global zero-weight contrast](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MyHGC.cpp#L457); [END opt-in default](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L1569).

### BE19 — When does stale locality metadata stop biasing selection?

**Integration:** [`37d627b97`](https://github.com/sysown/proxysql/commit/37d627b9743f7d51d6b783b039f994e0b18474f0). **Activation/tier/defaults:** MySQL PROXYSQL40 with locality enabled and a valid hostgroup policy. Required multipliers 1..10, same-AZ >= same-region. Refresh defaults 300 seconds; stale TTL defaults 1800, configurable up to seven days.

**Before:** There was no asynchronous AWS metadata bias or associated freshness/failure policy.

**After at END:** Fresh and unexpired stale metadata apply the same multiplier. Transient provider errors can retain the prior successful locality until TTL; expiry/missing metadata is neutral. Provider_unavailable is immediately neutral even with a cached previous value. Same-AZ classification additionally requires an instance endpoint, equal region/AZ text and equal nonempty account id; cluster/reader/custom endpoints receive at most region preference.

**Concrete consequence:** An instance moves after the last success and refreshes fail: the old AZ boost can remain for 30 minutes by default. Removing the provider instead neutralizes it immediately. An endpoint resolving to a same-AZ database can still receive only region preference if it is a cluster endpoint or account identity is unavailable.

**Decision:** Ratify A: bounded stale bias with immediate provider-removal neutrality and conservative same-AZ classification, B: neutralize every refresh failure, or C: configure freshness and identity confidence requirements separately.

**Evidence:** [before no locality bias](https://github.com/sysown/proxysql/blob/04dc9afa05757abb94c76dcc21af8550faa436d2/lib/MyHGC.cpp#L105); [END identity/classification](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Aws_Locality_Manager.cpp#L190); [END provider absence](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Aws_Locality_Manager.cpp#L1033); [END freshness policy](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Aws_Locality_Manager.cpp#L1070); [END freshness defaults](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/include/Aws_Locality_Types.h#L77).

### BE20 — Do health, backup and latency filters always outrank locality?

**Integration:** [`37d627b97`](https://github.com/sysown/proxysql/commit/37d627b9743f7d51d6b783b039f994e0b18474f0). **Activation/tier/defaults:** MySQL PROXYSQL40 locality, with any relevant GTID/Aurora lag/session-track limits, backup partition and latency-awareness filters. Ordinary candidate constraints remain binding; locality only scales the remaining configured weights.

**Before:** Global selection applied eligibility and optional latency awareness before the ordinary weighted draw. The new backup feature was already present before locality merged.

**After at END:** Locality executes after the global backup partition and latency-awareness elimination. It does not rescue a nearby candidate already removed by those filters. Remote/unknown endpoints retain multiplier 1 rather than being categorically excluded. Same-AZ and same-region multipliers are alternatives, not multiplied together.

**Concrete consequence:** A nearby backup remains excluded while an eligible remote primary exists. A same-AZ primary removed by latency awareness gets no chance to compete through its AZ boost. A remote surviving primary still receives traffic.

**Decision:** Should policy order A: remain eligibility/backup/latency, then locality weighting, B: let locality alter backup/latency preference, or C: expose explicit ordering while retaining hard transaction/consistency constraints?

**Evidence:** [before backup already active](https://github.com/sysown/proxysql/blob/04dc9afa05757abb94c76dcc21af8550faa436d2/lib/MyHGC.cpp#L283); [END backup stage](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MyHGC.cpp#L298); [END latency elimination](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MyHGC.cpp#L418); [END later locality draw](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MyHGC.cpp#L446); [END noncumulative multiplier](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Aws_Locality_Manager.cpp#L1080).

## Corrections, restorations and resolved decisions

The following changes are not requests to ratify regressions. Their issue numbers identify source comments/test names or integration subjects where available; no runtime outcome is claimed.

- **Connection/pool correctness:** remove the selected expired connection rather than index zero (abddff335); signed server-purge iteration avoids underflow (48f1b3cfe); preserve connection age through local/shared release and HGCU reset instead of rejuvenating/recycling it (4330a3510); a later fix keeps expired busy connections on the necessary termination path (380cb3eac). These preserve lifetime/ownership safety rather than establish new sharing guarantees.
- **Monitor resource/lifetime repairs:** MySQL monitor pool registration/unregistration and batch-task cleanup (461f5d52f, 5de836a4c), SQLite statement RAII (3b578db4b), PostgreSQL queue/connection cleanup and controller re-enable support (04dc9afa0), and the debug tracking-array destructor (546abf5c8). Scheduling decreases are clamped to the new interval (f7ee5cd02), while 64-bit interval conversion removes overflow for accepted long intervals (#6429, 5ace3febc).
- **Transport/version correctness:** avoid manual plaintext COM_QUIT over TLS and subsequently send protocol-correct quit (27f13ca18, 9b7d0e66c); omit invalid PostgreSQL port=0 on Unix socket connections (8e0060f69); use single quotes in the Group Replication member separator under ANSI_QUOTES (040899c71); select Galera status tables by actual server family/version (453c7554b); clear the long-lived Aurora worker’s OpenSSL error queue (58f93d377). The GR worker’s initial cycle obtains fresh evidence rather than letting stale prior ping history suppress every probe (dbb40a30b).
- **GTID restoration/compatibility:** reconnect ownership after the early refactor/revert sequence (05ab128c4); I3/I4 ranges and merged intervals (c75e222ce); bounded/strict wire parsing (5dc586fd6, 16b361e46); stream flavor and execution-set reset on successful reconnect, own `last_gtid` rather than whole-server MariaDB positions, and honest gap-aware display (380cb3eac). Later GTID-set grammar, separators, oversized-token reduction and the untrackable sentinel prevent rejection/retention of an older causal predicate (e100071e2, 4d7dea573). END’s explicit final maintainer decision #6415 routes using the highest transaction id; full-set containment is deliberately excluded and is not an open defect or question.
- **Pool selection preservation:** extracted `evaluate_pool_state` reproduces the former warming/quality/eviction/throttle decisions (16529445b). Replacing rand/fastrand with the thread-safe fast PRNG (3e4e857b4 and earlier PostgreSQL change) retains a weighted lottery. Widening total weights and combining two 32-bit draws prevents unreachable cumulative intervals when totals exceed 32 bits (da57c6e46); no least-connections or round-robin policy was inferred.
- **Dead code versus live behavior:** 8b2b29918 and 5f9806ea5 remove large disabled implementations. Their deleted code is not evidence of a live before/after policy change. Header lint, bounded diagnostic formatting, internal monitor port defaults and delivery/test-only work are explicitly classified in the ledger.

### Concrete correctness follow-ups separated from policy questions

1. **Lag-count multiplication:** BE03’s new PostgreSQL scheduler groups probes by hostgroup/hostname/port but each result increments the endpoint’s memberships across all hostgroups. With the same endpoint in several scheduled groups, `monitor_replication_lag_count` can be reached after fewer distinct sampling rounds. Once membership scope is decided, the counter should count the chosen logical observation boundary; this is not an invitation to accept an accidental duplicate increment as an invariant.
2. **Absence of DNS knowledge treated as proof of stale IP:** BE12’s predicate returns `!is_ip_valid`; that helper returns false for a disabled cache or a missing hostname, and `timeout_validate_ip_change` does not first require a present/enabled record. Thus generic monitor timeout suppression can occur without positive evidence that the endpoint changed. The source condition is concrete; a focused reproduction with cache disabled/missing, hostname socket and forced timeout remains unrun.
3. **Recovered-server capacity check confined to innovative builds:** BE07’s integration adds `mysql_recovered_candidate_eligible` / `pgsql_recovered_candidate_eligible` only under `PROXYSQL31`; the Stable recovery branch retains the pre-existing unchecked candidate admission. For MySQL the helper checks both max-online count and used capacity; PostgreSQL checks used capacity. If these checks are required correctness for recovered backends generally, I-2 requires the fix on Stable as well. Do not resolve this by weakening I-2 or silently assuming the backup feature creates the older capacity problem.

Evidence for the concrete follow-ups: [probe grouping](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Monitor.cpp#L517); [all-membership apply](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_HostGroups_Manager.cpp#L3110); [stale-IP predicate](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Monitor.cpp#L8458); [disabled/missing cache result](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/DNS_Cache.cpp#L208); [tier-gated recovered MySQL guard](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MyHGC.cpp#L238); [tier-gated recovered PostgreSQL guard](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_HostGroups_Manager.cpp#L2374).

### Hostgroup acquisition statistics cross-stream handoff

PR #6150 [`40ea2de1b`](https://github.com/sysown/proxysql/commit/40ea2de1bdf6547951df600185d3b3f1820f1dbe) adds automatic instrumentation in PROXYSQL31/40; there is no runtime enable switch. Acquisition means a socket was attached from local/shared inventory, not that a TCP connection was established or a query is running. The first unsuccessful checkout starts one wait; repeated retries retain it. Acquisition, request end, hostgroup change or session destruction finishes the elapsed wait. SQL resets advance baselines for acquisitions, waits and completed wait time, while the live waiters gauge remains. A wait crossing reset contributes its full duration when it finishes, although its initial waits_total increment belonged to the earlier window. Prometheus uses lifetime snapshots and is unaffected by SQL window reset. These are new measurements, not new pool-capacity admission limits; the observability stream owns whether the window/reset semantics need a separate maintainer question. Evidence: [window reset/live waiters](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/include/HostgroupPoolStats.h#L54); [logical wait/acquisition](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/include/HostgroupPoolStats.h#L108); [MySQL checkout consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L10314); [PostgreSQL checkout consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L5613); [destruction cleanup](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Base_Session.cpp#L79); [lifetime Prometheus counters](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_HostGroups_Manager.cpp#L4016); [SQL snapshot projection](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Base_HostGroups_Manager.cpp#L215).

## Gaps and boundaries

- This is the complete disposition ledger for the **supplied backend queue**, not proof that a path-based queue finds every semantic backend change in the repository. Session-only checkout/waiter/fast-forward/native-protocol work, authentication/IAM credentials, managed/plugin materialization, cluster transport and observability APIs have other stream owners. The ledger names those boundaries rather than claiming their PRs were fully audited.
- The MySQL `resolution_family` feature was screened, including `system` default and resolver-family propagation, but immediate runtime changes with existing cached addresses, literal-IP inputs and GTID-reader connections were not deeply traced. This remains a coverage gap; no family-wide promise is inferred.
- The MySQL ping batching refactor was screened for action/resource flow. Burst scheduling, maximum queue delay, observation ordering across multiple consumers and large topologies were not measured or exhaustively proven.
- No new general Group Replication/Galera election contract is inferred from compile/query fixes. Existing lag/writer policy was followed where modified; combinations of multiple controllers acting on the same endpoint need dedicated investigation beyond BE12 and BGD’s explicit overlap limitation.
- PostgreSQL monitor TLS row matching/transport was traced. Certificate identity enforcement, complete live connection invalidation when TLS rows change, and authentication mechanisms are not fully reviewed here. Native and libpq connection fallback now consume the all-address cache surface after 5ace3febc, but no live multi-address DNS test was run.
- MariaDB causal-read wire/domain support was read through current parsers and reset handling. External database guarantees for domain/sequence prefix completeness and divergent multi-primary histories were not independently verified, so no normative cross-server MariaDB causal guarantee is asserted. Own-session token/fallback routing questions belong to the traffic stream; #6415 is closed.
- AWS BGD’s document includes bounded deployment observations and external attachments. Their factual AWS generality was not verified here. BE13–BE17 ask about ProxySQL policy; a maintainer answer should not turn the trace into an AWS guarantee. DNS recovery after failures, partial cleanup failures and real process restart behavior were not executed.
- Retained AWS provider leases, plugin unload and managed discovery are cross-area integration concerns; this stream follows the locality snapshot consumer/failure policy and leaves provider-lifecycle ratification to the extension stream.

## Complete integration disposition ledger

`deep` and `screen` are scoped as defined above. A correction disposition means no new policy question was selected from the reviewed backend slice; it is not a claim that every file or downstream interaction is correct. IDs link the integration to the questions it informs. The machine-readable companion is `/private/tmp/proxysql-behavior-review-2026-10/backends-coverage.json`.

| Integration (first-parent date) | Disposition | Depth | IDs | Backend-stream evidence / boundary |
| --- | --- | --- | --- | --- |
| [`c6cbce34b`](https://github.com/sysown/proxysql/commit/c6cbce34b15c85ed388f7df5437e515559265354) (2025-10-20) | superseded | screen | — | GTID reconnect refactor and exact revert; later 05ab128c4 restores revised machinery. No independent surviving policy selected here. |
| [`eb10eff1e`](https://github.com/sysown/proxysql/commit/eb10eff1e1b6ae8221ebcede1c18254a3da18035) (2025-10-22) | superseded | screen | — | GTID reconnect refactor and exact revert; later 05ab128c4 restores revised machinery. No independent surviving policy selected here. |
| [`29a6b8576`](https://github.com/sysown/proxysql/commit/29a6b8576a6c382e8bdafc5802b35ddb5667598f) (2025-11-20) | outside-stream | screen | — | Fast-forward frontend/stream graceful-close behavior; traffic stream owns protocol outcome. |
| [`05ab128c4`](https://github.com/sysown/proxysql/commit/05ab128c4ad59558b5ba0e1b037f3de07b2f5b61) (2025-11-25) | correction | deep | BE11 | GTID reconnect ownership/read failure repair and bootstrap interval/event-count preservation; later range/reconnect work tracked under BE11. |
| [`3c4e09fec`](https://github.com/sysown/proxysql/commit/3c4e09fec0bb4261121f53d07c1bc520189486c7) (2025-12-06) | outside-stream | screen | — | Prepared-statement redesign belongs to traffic; backend HGM deltas replace selector PRNG, preserving weighted-selection policy. |
| [`65dbe904f`](https://github.com/sysown/proxysql/commit/65dbe904f06346cd6f2e98c3512f15cd7fabe843) (2025-12-06) | correction | screen | — | MySQL monitor batches ping tasks, result inserts and resource ownership; screened async delivery, no separately proven admission-policy change. Timing/load behavior not deep-reviewed. |
| [`2667540fc`](https://github.com/sysown/proxysql/commit/2667540fcc3bd576c40ed2bc7b04cb903b86602b) (2025-12-19) | question | deep | BE04 | Monitor TLS now follows explicit use_ssl rather than implicit libpq negotiation. |
| [`efd87ae4d`](https://github.com/sysown/proxysql/commit/efd87ae4d4cbf14a9818ba846f0b13af26bc10f7) (2025-12-19) | correction | screen | — | Only backend-stream delta moves DEBUG monitor pointer read inside lock; digest changes outside stream. |
| [`461f5d52f`](https://github.com/sysown/proxysql/commit/461f5d52f2033d707fa38c2da40f6f43dbfaf341) (2025-12-26) | correction | screen | — | MySQL monitor pool ownership/registration lifetime fixes; screened get/put/unregister lifecycle, no new policy question. |
| [`8b2b29918`](https://github.com/sysown/proxysql/commit/8b2b29918a233029448c6237793334bac95616a1) (2026-01-12) | support-only | screen | — | Deletes #if 0 legacy read_only implementations in both HGMs; active read_only_action_v2 remains. |
| [`27f13ca18`](https://github.com/sysown/proxysql/commit/27f13ca18d8aa0a6dd82a235b6ef274ea444fc00) (2026-02-03) | correction | screen | — | Stops plaintext COM_QUIT injection on TLS monitor sockets; later 9b7d0e66c implements protocol-correct quit. |
| [`052436332`](https://github.com/sysown/proxysql/commit/0524363322d4ebdc2e6473d0a9059a5556cc0e73) (2026-02-05) | outside-stream | screen | — | GenAI integration outside backend policy; Pg monitor SQLite helper calls routed through owned proxy symbols. |
| [`abddff335`](https://github.com/sysown/proxysql/commit/abddff3355012cd64cf7393178b74377e1bf263c) (2026-02-06) | correction | deep | — | Age pruning removes matching index i rather than unrelated index 0 in MySQL/PostgreSQL pools. |
| [`48f1b3cfe`](https://github.com/sysown/proxysql/commit/48f1b3cfef8b04ca5decf2f960192c6e16cc6261) (2026-02-06) | correction | deep | — | Signed purge index permits decrement/revisit at first removed server, avoiding unsigned underflow. |
| [`a360dc22a`](https://github.com/sysown/proxysql/commit/a360dc22aed7de67d7349886b936a25d94a3c2a5) (2026-02-06) | support-only | screen | — | Portability include and ULLONG_MAX replacement in Pg monitor; broader macOS work outside stream. |
| [`e82ff6f8a`](https://github.com/sysown/proxysql/commit/e82ff6f8aa8688f1a721117193696fc3fe9c7580) (2026-02-12) | outside-stream | screen | — | Adds protocol labels to pool/client Prometheus metrics; administration/observability stream owns compatibility. |
| [`3b578db4b`](https://github.com/sysown/proxysql/commit/3b578db4bf767b29ad25b71c500eeaff200749cd) (2026-02-15) | correction | screen | — | SQLite prepared-statement RAII/const cleanup and monitor init fixes; backend touched hunks screened, broad mixed PR not deeply audited here. |
| [`5de836a4c`](https://github.com/sysown/proxysql/commit/5de836a4c1423f39f50d86d73f2904a6a4b10169) (2026-02-15) | correction | screen | — | Centralized monitor connection destruction and unprocessed-task cleanup; scoped lifecycle screen, no new eligibility policy selected. |
| [`acd955b9d`](https://github.com/sysown/proxysql/commit/acd955b9d6efc4cb37ca7947d4c31c5da46c013d) (2026-02-16) | outside-stream | screen | — | WebUI metrics collector friendship/access; observability stream owns new access contract. |
| [`c60f390b4`](https://github.com/sysown/proxysql/commit/c60f390b447b758bb592130872b073cee47c86c7) (2026-03-06) | question | deep | BE01, BE02, BE03 | Activates PostgreSQL lag SQL, scheduling and HGM actions; measurement, failure and membership scope questions. |
| [`4d58ce473`](https://github.com/sysown/proxysql/commit/4d58ce473ee1912ce97f41b8c18dafa96d781f52) (2026-03-08) | outside-stream | screen | — | Admin/bootstrap paths and supporting tests; no backend implementation delta. |
| [`161584186`](https://github.com/sysown/proxysql/commit/16158418647dbb872ccd60f8497e71d3d9ae8184) (2026-03-09) | outside-stream | screen | — | Adds protocol labels to pool/client Prometheus metrics; administration/observability stream owns compatibility. |
| [`8a1a942d6`](https://github.com/sysown/proxysql/commit/8a1a942d659ded6b01b8bf375760813faf80a01f) (2026-03-09) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`b0926ac24`](https://github.com/sysown/proxysql/commit/b0926ac246d200cc964f237e55bfc9d55e249f94) (2026-03-09) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`458ef0197`](https://github.com/sysown/proxysql/commit/458ef01970eb30b67b7ff57c4108b9e177a1cf19) (2026-03-19) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`abd1da861`](https://github.com/sysown/proxysql/commit/abd1da861f4c9357fe298ea4013f15d03c689f27) (2026-03-22) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`16529445b`](https://github.com/sysown/proxysql/commit/16529445bf2c98e7473effd2bad54139c3042cad) (2026-03-22) | support-only | deep | — | Extracted pool decision helper compared with former inline warming/eviction/quality/throttle branches; same policy. Monitor decision helper is not assumed to be a production caller. |
| [`7f5bbf0f1`](https://github.com/sysown/proxysql/commit/7f5bbf0f1924d68d825139bc24563d9a86da6b36) (2026-03-22) | correction | screen | — | Missing cstdint include in extracted monitor helper. |
| [`63007cfa3`](https://github.com/sysown/proxysql/commit/63007cfa3966d43ec45c6574a719ef2f770752a2) (2026-04-01) | outside-stream | screen | — | MySQL Session execution behavior belongs to traffic; no HGM/monitor source delta. |
| [`21b3e238e`](https://github.com/sysown/proxysql/commit/21b3e238ee9a1e10d00d505241e1e656a6b3a66d) (2026-04-08) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`bd83f9b35`](https://github.com/sysown/proxysql/commit/bd83f9b3570c07af2f8c50d8e8b279518754dd72) (2026-04-09) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`f713d78e4`](https://github.com/sysown/proxysql/commit/f713d78e4136fd36cc85d24ccd1e1c7f1ceb75e9) (2026-04-09) | feature-screened | screen | — | Adds MySQL resolution_family=system/IPv4/IPv6, applied to resolver requests and normal connection resolver. Existing cached addresses and live-family changes not deeply traced; explicit gap below. |
| [`7f14beedc`](https://github.com/sysown/proxysql/commit/7f14beedc15d6d48fc510c6d393743b530630f65) (2026-04-09) | question | deep | BE04 | Per-server PostgreSQL TLS row and monitor username/global precedence; admin persistence transport belongs to administration/authentication. |
| [`669ab9149`](https://github.com/sysown/proxysql/commit/669ab914948f03b10c1ded21a4361d283cd9652d) (2026-04-10) | support-only | screen | — | Header lint/type/forward declaration cleanup and bounded string handling; screened backend hunks, no new policy selected. |
| [`f7ee5cd02`](https://github.com/sysown/proxysql/commit/f7ee5cd028ff34efea42a41dc19cb24be121b65e) (2026-04-12) | correction | deep | — | Shrinks previously scheduled PostgreSQL probe deadline after runtime interval decrease; retains already-imminent checks on increases. Later lifecycle change makes refresh observable between distant cycles. |
| [`c75e222ce`](https://github.com/sysown/proxysql/commit/c75e222ce5f465840e97665316cfcf75bff2a63a) (2026-04-13) | correction | deep | — | GTID range I3/I4 support and interval merging; malformed-reader handling corrected. No need to ask whether valid ranges should be parsed. |
| [`c05302b95`](https://github.com/sysown/proxysql/commit/c05302b95458d9b58470bf78155f243225a97f01) (2026-04-14) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`824588d19`](https://github.com/sysown/proxysql/commit/824588d1983f850a941496683d82838b216d5c4c) (2026-04-14) | support-only | screen | — | Backend macros/const-cast/thread-name lint cleanup. |
| [`13ff9d767`](https://github.com/sysown/proxysql/commit/13ff9d767152d0331905478d267dcf1a642bb350) (2026-04-16) | outside-stream | screen | — | MySQL variables/protocol support and GR test environment; SET/session-variable stream owns semantic change. |
| [`dbb40a30b`](https://github.com/sysown/proxysql/commit/dbb40a30baec7d23568ebe2d2b228737d31dfcba) (2026-04-19) | correction | deep | — | First GR cycle probes configured hosts rather than trusting stale prior ping log; restores fresh health observation. |
| [`795b56a1e`](https://github.com/sysown/proxysql/commit/795b56a1e5ed6811360e24e226a59de657b2cbb9) (2026-04-22) | outside-stream | screen | — | Session tracking capability enforcement/backoff shared with local/global selection; established SET/session tracking review owns policy, not reopened here. |
| [`5dc586fd6`](https://github.com/sysown/proxysql/commit/5dc586fd6bcfc425cb85d4663e538c4736b99616) (2026-04-23) | correction | deep | — | Strict transaction interval parsing and GTID wire range validation; PgSQL session changes outside stream. |
| [`0f2b3e64a`](https://github.com/sysown/proxysql/commit/0f2b3e64a5f3cf77d1b32d623a0be99218d1d3d7) (2026-04-24) | support-only | screen | — | GTID portable format/type/const signatures; no changed eligibility intent selected. |
| [`621ddb786`](https://github.com/sysown/proxysql/commit/621ddb786e66bbe6ae1e278a20eef2189d2cba9a) (2026-05-03) | outside-stream | screen | — | Authentication lock ordering; authentication/session stream. |
| [`3e4e857b4`](https://github.com/sysown/proxysql/commit/3e4e857b4d2ef38b694cf34dc8f9c934b94a3c9d) (2026-05-04) | correction | deep | — | Thread-safe fast PRNG replaces rand/fastrand for server and free-connection draw; weighted policy retained. |
| [`185abefec`](https://github.com/sysown/proxysql/commit/185abefec1c0862fd5c14465e84f1ace099a894b) (2026-05-14) | question | deep | BE09, BE10 | Optional Aurora runtime autopurge and generic serious-shun delay increase. |
| [`453c7554b`](https://github.com/sysown/proxysql/commit/453c7554bff14acdea1b4896e98157a6bcf2d19e) (2026-05-24) | question | deep | BE05 | Separate PostgreSQL DNS cache newly affects traffic; Galera version/vendor query correction is restoration. |
| [`8e0060f69`](https://github.com/sysown/proxysql/commit/8e0060f6915863a577a804edc14ea7559fc9c7ad) (2026-06-13) | correction | deep | — | Omit invalid port=0 libpq parameter for Unix socket backend/monitor connection. |
| [`5e5b416af`](https://github.com/sysown/proxysql/commit/5e5b416aff7a3145e2aa9bf867b28b9e667daf05) (2026-06-13) | outside-stream | screen | — | MySrvC connect error1862 added to credential-error shun-skip list; authentication stream notified. |
| [`6a33b85ae`](https://github.com/sysown/proxysql/commit/6a33b85ae402bb0e52da7e847b91e41e98a094b1) (2026-06-13) | support-only | screen | — | Deletes unused default ports on internal monitor tables where callers provide port explicitly; no production endpoint fallback removed. |
| [`040899c71`](https://github.com/sysown/proxysql/commit/040899c718f8654a7133df791d84548bb873a3bb) (2026-07-08) | correction | deep | — | GR query uses SQL single-quoted separator, making it independent of ANSI_QUOTES. |
| [`a3718bcfc`](https://github.com/sysown/proxysql/commit/a3718bcfcac53f63e6c89f5b514db98ea83c9349) (2026-07-08) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`0069d4249`](https://github.com/sysown/proxysql/commit/0069d42492ec145447ec99af097ec5164540145b) (2026-07-11) | question | deep | BE06 | Per-hostgroup timeout read by both protocol session deadline consumers. |
| [`8ca2df54f`](https://github.com/sysown/proxysql/commit/8ca2df54f6ecb5b15712a27d4e813162cbb0523e) (2026-07-29) | question | deep | BE12, BE13, BE14, BE15, BE16, BE17 | BGD state machine, automatic activation, DNS pinning, endpoint retirement, reader policy and lifetime; generic stale-IP timeout exception. |
| [`16b361e46`](https://github.com/sysown/proxysql/commit/16b361e46fa17384b714a17a6b8653f5952dbb08) (2026-08-11) | correction | screen | — | GTID fixed-buffer/UUID bounds validation and Pg error stats bounded strings; backend production hunks screened. |
| [`df292eacc`](https://github.com/sysown/proxysql/commit/df292eacc821d56bbed92fcdb68dc98b852e103b) (2026-08-12) | correction | screen | — | Bounded snprintf conversions for backend diagnostics/statistics; no selection policy chosen. |
| [`efe591090`](https://github.com/sysown/proxysql/commit/efe591090254703fb637e4500e17ae14ca184445) (2026-08-13) | question | deep | BE11 | Optional OK-packet GTID accumulation, active-reader gate removed independently of opt-in. |
| [`cd4bd3ab8`](https://github.com/sysown/proxysql/commit/cd4bd3ab86f2c272a3ff62382317dcf829839d90) (2026-08-13) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`b327de622`](https://github.com/sysown/proxysql/commit/b327de62202642f0c32f158e98fd2b1c86c6a386) (2026-08-16) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`94b3c8260`](https://github.com/sysown/proxysql/commit/94b3c82604dab349237f49d9bc7c98019d53a057) (2026-08-17) | outside-stream | screen | — | Admin/ASAN workflow and resultset/session fixes; no backend HGM/monitor source delta. |
| [`99c37c7c1`](https://github.com/sysown/proxysql/commit/99c37c7c1b668c46364ecb767ad085838a3cbfef) (2026-08-18) | support-only | screen | — | Monitor jitter/retirement draw moves to rand_fast and minor includes; policy/probability constants retained. |
| [`c1bdc6384`](https://github.com/sysown/proxysql/commit/c1bdc6384d9279d6ad9912570da9a89cdb0dca3c) (2026-08-30) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`40ea2de1b`](https://github.com/sysown/proxysql/commit/40ea2de1bdf6547951df600185d3b3f1820f1dbe) (2026-08-31) | outside-stream | deep | — | PROXYSQL31 hostgroup acquisition/wait statistics instrument checkout and request-end; no acquisition eligibility behavior found. Administration/observability owns metric reset/API contract. |
| [`9b7d0e66c`](https://github.com/sysown/proxysql/commit/9b7d0e66c04b1eb2761ab569ce538d5e644e8f18) (2026-09-01) | correction | deep | — | Shared protocol-aware COM_QUIT sender replaces manual plaintext monitor quit; TLS orderly close restoration. |
| [`5940f34ca`](https://github.com/sysown/proxysql/commit/5940f34cacca6342fe644b4e5f71e4284bcf0775) (2026-09-03) | outside-stream | screen | — | PostgreSQL auth redesign; HGM kill-args updated to pass userinfo, authentication/traffic owns full protocol changes. |
| [`5f9806ea5`](https://github.com/sysown/proxysql/commit/5f9806ea528af5d9d7fffd3900f2810bc6279d41) (2026-09-03) | support-only | deep | — | Removes large #if 0 BaseHGM block; live template/common HGM code retained, not a runtime rewrite. |
| [`563e47f1a`](https://github.com/sysown/proxysql/commit/563e47f1a819c21e1700136c72b3025ae570ddd0) (2026-09-08) | outside-stream | screen | — | Router/plugin runtime integration; backend deltas add under-lock query/commit plumbing. Core LOAD behavior belongs to administration and binding I-1/I-3. |
| [`08cf04957`](https://github.com/sysown/proxysql/commit/08cf04957728229a5511498f712a5ed5945325f1) (2026-09-15) | outside-stream | screen | — | Innovative waiter/out-of-poll admission and local-pool fairness changes belong to traffic/execution stream; no monitor/HGM production delta. |
| [`58f93d377`](https://github.com/sysown/proxysql/commit/58f93d3776fa2396267dcd995214018cd7953d6c) (2026-09-26) | correction | deep | — | Clears thread-local OpenSSL error queue after Aurora checks so old TLS errors cannot poison subsequent probes. |
| [`bf44ee9e3`](https://github.com/sysown/proxysql/commit/bf44ee9e38109f6096722a5f9fcd3e7977bee4fb) (2026-09-27) | feature-screened | deep | BE11 | MariaDB causal-read domain-ID wire support; END fixes session GTID source/display and reader flavor reset. Eligibility uses domain/sequence; no added policy question without checking external MariaDB guarantees. |
| [`4330a3510`](https://github.com/sysown/proxysql/commit/4330a35102c9c0c1f771264c7e4a6373be13b305) (2026-09-28) | correction | deep | — | Honors max-age on release/local/global/reset queue; aged socket cannot be recycled, busy connection still reaches termination after later fix. |
| [`da57c6e46`](https://github.com/sysown/proxysql/commit/da57c6e46431312d6a00a27d2fed10f3e7649f7e) (2026-09-28) | question | deep | BE07, BE08 | Opt-in primary/backup partition and availability modes; local-cache scope unresolved. Wide weight draw repair and recovery capacity gating reviewed separately. |
| [`1387fc34f`](https://github.com/sysown/proxysql/commit/1387fc34f7b33067ee209867540cfd928c6157b5) (2026-09-28) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`8d4ff4db5`](https://github.com/sysown/proxysql/commit/8d4ff4db58b777ed33e56d5a76edc7ccb2051eae) (2026-09-29) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`9f0099d17`](https://github.com/sysown/proxysql/commit/9f0099d17d5ba97d17dfbf5cd72f13e33d05d3c4) (2026-09-29) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`696781be8`](https://github.com/sysown/proxysql/commit/696781be8e14b7e1de09f9fd088ff2f18551ba75) (2026-09-29) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`f9d251bb4`](https://github.com/sysown/proxysql/commit/f9d251bb4521377bf742abcee9f15485f7492f35) (2026-09-30) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`69977a509`](https://github.com/sysown/proxysql/commit/69977a509e0d694ee0162bb856a718d6ffa1e3f9) (2026-09-30) | correction | deep | — | Prefers MariaDB own last_gtid; later 380cb3eac removes global-position fallback entirely, so intermediate fallback is not an END question. |
| [`f23c70b60`](https://github.com/sysown/proxysql/commit/f23c70b6069764e7b935a4116b79e7d4ce9159ff) (2026-09-30) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`bae148763`](https://github.com/sysown/proxysql/commit/bae14876302c754b941f2c1dccbdcbba6c112dfe) (2026-09-30) | support-only | screen | — | Queue match is backend tests, infrastructure, binlog-reader version/delivery or test orchestration; no backend production code changed in this integration. |
| [`2775bb222`](https://github.com/sysown/proxysql/commit/2775bb222ed67e613332fa8bfdff526ae56baa49) (2026-10-01) | outside-stream | screen | — | Native PostgreSQL backend protocol belongs to traffic/authentication; HGM native PID kill/stats null-safe adaptation inspected. |
| [`380cb3eac`](https://github.com/sysown/proxysql/commit/380cb3eacdb8fd8b485c80c30f7210d625e17aa9) (2026-10-02) | correction | deep | BE11 | Reconnect clears GTID stream/set, own-transaction source only, truthful MariaDB display and aged-busy KILL path. Disconnected trust question remains. |
| [`04dc9afa0`](https://github.com/sysown/proxysql/commit/04dc9afa05757abb94c76dcc21af8550faa436d2) (2026-10-02) | correction | deep | — | PostgreSQL monitor disable/re-enable, queue/connection cleanup, cancellation and global-variable refresh lifetime restoration; worker count applies on next enable. |
| [`37d627b97`](https://github.com/sysown/proxysql/commit/37d627b9743f7d51d6b783b039f994e0b18474f0) (2026-10-03) | question | deep | BE18, BE19, BE20 | PROXYSQL40 AWS locality new weighted policy, stale/failure handling, global and local consumers. IAM/provider secrets and managed/plugin control belong to other streams. |
| [`6f438aa1f`](https://github.com/sysown/proxysql/commit/6f438aa1f0e9ed38ecdb107d0bc829d27f9a8408) (2026-10-03) | correction | screen | — | Large diagnostic bounded-string rewrite in HGM/monitor; no deep audit of every formatting/truncation consequence. |
| [`546abf5c8`](https://github.com/sysown/proxysql/commit/546abf5c885ff985c3e98852630bac28de9223a3) (2026-10-03) | correction | screen | — | Deletes DEBUG monitor tracking array on destruction; Admin LOAD changes are administration/I-1 scope. |
| [`7601b3937`](https://github.com/sysown/proxysql/commit/7601b39375a5b154b0a235c3db24fea7d3ff72f8) (2026-10-12) | outside-stream | screen | — | IAM established-socket policy correction and GTID local route correction; root authentication/traffic owns conclusions, pool source inspected. |
| [`5ace3febc`](https://github.com/sysown/proxysql/commit/5ace3febc60b29264fe9a331a05a8e793ebe3237) (2026-10-12) | correction | deep | — | Pg monitor 64-bit interval conversion, disabled schedule arithmetic, DNS multi-address fallback; transaction/session corrections covered by I-4..I-8 and traffic stream. |
| [`e100071e2`](https://github.com/sysown/proxysql/commit/e100071e2b660c51743d9b52fcd0e7bb515632a0) (2026-10-12) | correction | deep | — | GTID set grammar/OWN_GTID handling, per-HG backup log throttle. Explicit #6415 highest-id routing decision remains closed; other mixed code outside stream. |
| [`c52887003`](https://github.com/sysown/proxysql/commit/c5288700311d324df38b8095953d379861bcf81d) (2026-10-13) | resolved-decision | deep | — | Explicit final #6415 decision rejects full-set containment; source-backed highest-trxid design is not a new question. |
| [`4d7dea573`](https://github.com/sysown/proxysql/commit/4d7dea573f7868d46ec5adf00e0bf93dbe34bab2) (2026-10-14) | correction | deep | — | GTID separator/reduction/untrackable sentinel prevents older predicate retention; HGM plugin/discovery claim rename/checksum plumbing outside backend policy. |
| [`b0fe50bc3`](https://github.com/sysown/proxysql/commit/b0fe50bc3713acd18b270b9330fbcb4a067acc22) (2026-10-17) | correction | screen | — | Hostgroup string snapshots/lifetime synchronization and hot-path amortization; inspected backend hunks, authentication/localpool performance broader than this stream. |

Coverage counts: 2 superseded, 31 correction, 19 outside-stream, 10 question, 27 support-only, 2 feature-screened, 1 resolved-decision; 58 screen, 34 deep. Twenty question IDs are stable within this report; answers and implementation remain separate maintainer work.
