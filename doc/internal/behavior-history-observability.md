# Twelve-month behavior review: statistics, logging and telemetry

Status: awaiting maintainer answers. Reviewed 2026-10-19; source/history only. BASE `70228332135431229940279e49b6db186c6e4241`; END `9516441f7bd6fdb93f255f1881db19ca9ee56778`. Integration window 2025-10-19 through 2026-10-19. The current documentation checkout is not switched to END; source citations below are immutable END permalinks. No runtime probes were executed.

This review distinguishes observation consistency, sink/lifetime policy and new optional surfaces. Existing MySQL circular history is not attributed to this year. Protocol-label changes are dated by their February mainline integration, not their older author dates. A source/spec statement of intent is not automatically a maintainer answer.

## Questions

### OB01 — Per-worker event and audit buffers

**Activation / integration:** February 2026; both protocols, all tiers; logging must already be enabled.

**Before:** MySQL wrote each accepted event/audit entry directly to the shared file stream under the logger lock. This was not an fsync guarantee.

**After:** The logger first serializes into per-thread buffers. Defaults are a 4,096-byte size threshold and a 1,000ms timeout for event/audit buffers; forced flush/rotation drains contexts. A sub-threshold entry can remain in a worker buffer before file-stream I/O.

**Observable effect:** An operator tailing a quiet log may see entries later even though the client operation has completed. The question concerns the additional application buffer, not a claim about power-loss durability.

**Question:** Should event and audit logs both use these default per-worker buffers?

**Answer:** A: buffer both, as implemented; B: buffer event logs but send audit entries directly to the file stream; C: send both directly

**Evidence:** [b64f2e561](https://github.com/sysown/proxysql/commit/b64f2e561); [lib/MySQL_Logger.cpp:1683](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Logger.cpp#L1683); [lib/MySQL_Logger.cpp:1950](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Logger.cpp#L1950); [lib/MySQL_Thread.cpp:1498](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Thread.cpp#L1498).

### OB02 — Sampling also removes events from in-memory history

**Activation / integration:** February 2026; both protocols, all tiers; eventslog_rate_limit defaults to 1.

**Before:** There was no eventslog_rate_limit sampling gate in this path; selected event entries could reach both the file and existing MySQL circular history.

**After:** With rate_limit=N greater than 1, a random approximately 1/N acceptance test returns before construction/copy into either sink. The gate affects event logging, not the separate audit-entry method.

**Observable effect:** Setting N=100 to reduce file output also means in-memory query-event history is sampled. It does not merely reduce disk writes.

**Question:** Should eventslog sampling cover both the file sink and circular history?

**Answer:** A: both sinks, as implemented; B: file output only, retaining complete selected circular history

**Evidence:** [b64f2e561](https://github.com/sysown/proxysql/commit/b64f2e561); [lib/MySQL_Logger.cpp:1558](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Logger.cpp#L1558); [lib/PgSQL_Logger.cpp:1011](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Logger.cpp#L1011); [lib/log_utils.cpp:120](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/log_utils.cpp#L120).

### OB03 — PostgreSQL query-event retention is bounded and truncated

**Activation / integration:** February 2026; PostgreSQL, all tiers; eventslog_buffer_history_size defaults to 0/off.

**Before:** PostgreSQL lacked this circular-buffer-to-SQL query-event history. MySQL already had a bounded mechanism.

**After:** PostgreSQL gains a ring that evicts the oldest entries, a default 10,000-row in-memory SQL cap, and a default 32KiB query-text copy limit. The file event representation is a separate sink.

**Observable effect:** A query longer than 32KiB can be present with truncated SQL in the memory/history export. A full ring replaces old events instead of blocking traffic or retaining an unbounded history.

**Question:** Should PostgreSQL use this bounded, oldest-first-eviction history with independently truncated SQL text?

**Answer:** A: retain these semantics; B: require complete query text for retained events and explicitly report/refuse entries that cannot fit

**Evidence:** [bad7ce40c](https://github.com/sysown/proxysql/commit/bad7ce40c); [lib/PgSQL_Logger.cpp:222](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Logger.cpp#L222); [lib/PgSQL_Logger.cpp:1534](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Logger.cpp#L1534); [lib/PgSQL_Logger.cpp:1671](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Logger.cpp#L1671).

### OB04 — Live-map and Top-K digest observations may be approximate

**Activation / integration:** September 2026 atomic-counter change in the shared digest implementation. The demonstrated production consumer of live-map observations is MCP Top-K in the opt-in v4 GenAI plugin. Ordinary Admin SQL digest refresh uses a detached map instead.

**Before:** Updating an existing digest took the exclusive digest-map lock. A reader holding the read lock excluded those updates while reading a row.

**After:** Existing-entry updates use the read lock and per-field relaxed atomics. A Top-K reader holding that same kind of lock can observe `count_star` after an update and `sum_time` before it. Ranking snapshots ordering keys to avoid changing them mid-sort; this does not make all row fields one transaction. By contrast, ordinary Admin `stats_*_query_digest` refresh calls `get_query_digests_v2()`, which detaches the map under the write lock before reading its entries: those rows are not concurrently updated while dumped.

**Observable effect:** MCP Top-K results can temporarily combine counters from different instants. This is shared-map observation consistency, not delayed thread-local flushing or a claim that normal SQL digest dumps read concurrently changing rows. A legacy live-map API has the same limitation; the located caller is DEBUG-only.

**Question:** May live-map/Top-K digest observations be individually atomic but approximate across columns?

**Answer:** A: retain approximate cross-column observations for these readers; B: require a coherent row snapshot for these readers too

**Evidence:** [53327da99](https://github.com/sysown/proxysql/commit/53327da99); [update caller:3532](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L3532); [atomic update:111](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/QP_query_digest_stats.cpp#L111); [SQL dispatch:1807](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Admin.cpp#L1807); [map detach:2187](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L2187); [detached dump:2241](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L2241); [live Top-K:2512](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L2512); [MCP consumer:1685](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Stats_Tool_Handler.cpp#L1685).

### OB05 — Selective digest purge includes the cutoff timestamp

**Activation / integration:** July 2026; both protocols, all tiers; explicit PURGE ... TO epoch command.

**Before:** The supported purge mechanism removed entire digest collections; there was no age-selective PURGE ... TO command.

**After:** The new Admin command translates an epoch cutoff to monotonic time and removes entries whose last_seen is less than or equal to it. During asynchronous purge, entries created or updated in the detached-map window are merged back. A positive cutoff before the monotonic epoch becomes a successful no-op.

**Observable effect:** PURGE stats_mysql_query_digest TO T removes an entry last seen exactly at T, not only entries strictly older than T. New observations during the purge are preserved.

**Question:** Should the age cutoff be inclusive?

**Answer:** A: last_seen <= T, as implemented; B: last_seen < T

**Evidence:** [20bbe92a0](https://github.com/sysown/proxysql/commit/20bbe92a0); [lib/Admin_Handler.cpp:581](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Admin_Handler.cpp#L581); [lib/Query_Processor.cpp:1942](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Query_Processor.cpp#L1942).

### OB06 — TSDB automatically records the full metrics registry

**Activation / integration:** February 2026; Innovative/v4.0 only; tsdb-enabled defaults to 0.

**Before:** No embedded TSDB sampled the full Prometheus registry into persistent labelled series.

**After:** Enabling TSDB samples all registered metric families and labels, including extensions in the shared registry, every 5 seconds by default. It refreshes module metrics first and writes to the persistent statistics database.

**Observable effect:** Enabling one switch starts history collection for every registered series rather than a selected list. Adding a metric producer can consequently add stored history without another TSDB configuration change.

**Question:** Should enabling TSDB automatically include every registered metric family and label?

**Answer:** A: include the complete registry, as implemented; B: require a configured allowlist/filter

**Evidence:** [9e157d2aa](https://github.com/sysown/proxysql/commit/9e157d2aa); [5b721a659](https://github.com/sysown/proxysql/commit/5b721a659); [lib/ProxySQL_Statistics.cpp:169](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Statistics.cpp#L169); [lib/ProxySQL_Statistics.cpp:1913](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Statistics.cpp#L1913).

### OB07 — TSDB has separate raw and hourly retention policies

**Activation / integration:** February 2026; Innovative/v4.0 only; active when TSDB is enabled.

**Before:** There were no TSDB raw/hourly tables or these retention rules; pre-existing statistics histories had their own policies.

**After:** Raw samples and backend-probe rows follow tsdb-retention_days (default 7), while hourly aggregates have a fixed 365-day lifetime. Hourly data averages/minima/maxima are aggregated by metric and labels.

**Observable effect:** Setting tsdb-retention_days=30 retains raw samples for 30 days but leaves hourly aggregates eligible for a year. The knob is not a common lifetime for all TSDB data.

**Question:** Which retention policy should the TSDB expose?

**Answer:** A: configurable raw/probe retention plus fixed one-year hourly retention; B: one configured lifetime for all TSDB tables; C: independently configurable lifetimes

**Evidence:** [9e157d2aa](https://github.com/sysown/proxysql/commit/9e157d2aa); [lib/ProxySQL_Statistics.cpp:1588](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Statistics.cpp#L1588); [lib/ProxySQL_Statistics.cpp:1641](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Statistics.cpp#L1641).

### OB08 — Disabling TSDB also pauses retention

**Activation / integration:** February 2026; Innovative/v4.0 only; runtime tsdb-enabled=0.

**Before:** There was no TSDB enable/disable lifetime policy.

**After:** Sampling, downsampling and retention timers all return false while TSDB is disabled. Existing persisted samples remain queryable; disabling does not purge them.

**Observable effect:** An operator who disables collection also stops expiry cleanup until it is enabled again. Stored rows do not continue aging out through this timer.

**Question:** Should disabling TSDB pause cleanup as well as collection?

**Answer:** A: pause both, as implemented; B: stop collection but continue retention cleanup

**Evidence:** [9e157d2aa](https://github.com/sysown/proxysql/commit/9e157d2aa); [lib/ProxySQL_Statistics.cpp:1745](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Statistics.cpp#L1745); [lib/ProxySQL_Statistics.cpp:1778](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Statistics.cpp#L1778).

### OB09 — TSDB backend health means TCP reachability, separate from routing health

**Activation / integration:** February 2026; Innovative/v4.0 only; tsdb-monitor_enabled defaults to 0.

**Before:** There was no separate TSDB backend-health probe stream.

**After:** Enabling the TSDB monitor adds nonblocking TCP connection probes to targets obtained from runtime HGM datasets. It records connection reachability/latency in TSDB; this probe does not perform database authentication/query validation or change HGM server availability.

**Observable effect:** A server accepting TCP but rejecting authentication can appear reachable in this series while the protocol Monitor reports a different condition. Enabling this option adds connection attempts; it is not merely exporting existing Monitor measurements.

**Question:** Should this TSDB series remain a separate TCP-connect observation?

**Answer:** A: retain separate TCP reachability; B: derive database-health observations from the protocol Monitor instead

**Evidence:** [9e157d2aa](https://github.com/sysown/proxysql/commit/9e157d2aa); [lib/ProxySQL_Statistics.cpp:1991](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Statistics.cpp#L1991); [lib/ProxySQL_Statistics.cpp:2046](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Statistics.cpp#L2046).

### OB10 — TSDB read API follows REST availability, not sampler enablement

**Activation / integration:** February/May 2026; Innovative/v4.0 with the REST server enabled.

**Before:** The REST server had configured script routes, without these built-in TSDB data routes.

**After:** The server registers built-in /api/tsdb/metrics, /query and /status plus dashboard assets when compiled with TSDB. The GET handlers have no TSDB-enabled test or request-authentication check and add Access-Control-Allow-Origin: *. Thus persisted history remains readable through these routes even when sampling is off.

**Observable effect:** Turning on REST exposes these built-in read surfaces alongside configured routes; turning off TSDB sampling does not revoke that read surface. This describes the handler boundary, not a claim that a deployment exposes the listener outside its network controls.

**Question:** What should gate built-in TSDB reads?

**Answer:** A: REST availability alone, as implemented; B: an explicit TSDB read-enable control; C: authenticated management access

**Evidence:** [9e157d2aa](https://github.com/sysown/proxysql/commit/9e157d2aa); [0ceb33680](https://github.com/sysown/proxysql/commit/0ceb33680); [lib/ProxySQL_RESTAPI_Server.cpp:348](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_RESTAPI_Server.cpp#L348); [lib/ProxySQL_RESTAPI_Server.cpp:529](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_RESTAPI_Server.cpp#L529).

### OB11 — MySQL memory gauges follow a bounded sampling interval

**Activation / integration:** September 2026; all tiers; admin-prometheus_memory_metrics_interval defaults to 61 seconds.

**Before:** The MySQL module metrics update called the buffer/session-memory getters on each metrics refresh. A separate Admin memory interval already throttled other expensive memory collection.

**After:** These MySQL memory scans and gauge updates move into that existing bounded Admin memory collection interval. The same change repairs getters that incorrectly updated counter storage instead of setting gauges.

**Observable effect:** Repeated Prometheus scrapes can see unchanged MySQL buffer/session-memory gauges for the configured interval even as allocations change. The default is 61 seconds, not a fresh worker scan per scrape.

**Question:** Should these memory gauges share the existing bounded memory sampling interval?

**Answer:** A: use that interval, as implemented; B: refresh these gauges on every metrics scrape

**Evidence:** [fd001a51b](https://github.com/sysown/proxysql/commit/fd001a51b); [lib/ProxySQL_Admin_Stats.cpp:142](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Admin_Stats.cpp#L142); [lib/ProxySQL_Admin.cpp:3172](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Admin.cpp#L3172).

### OB12 — Hostgroup wait counters use start and completion events in different windows

**Activation / integration:** August 2026; Innovative/v4.0 automatic instrumentation; explicit SQL reset controls its window.

**Before:** There was no per-hostgroup acquisition/wait statistics family with separate lifetime and reset-window views.

**After:** The new SQL reset advances baselines for acquisitions, wait starts and completed wait duration. The live waiters gauge is not reset. A wait begun before reset and completed after it contributes its entire elapsed duration in the later window. Prometheus lifetime counters do not reset with the SQL window.

**Observable effect:** After a reset, wait_time_us_total can increase for an earlier wait without a new waits_total increment in that window. Consumers must not assume the two fields always describe one completion cohort.

**Question:** Should reset-window wait counts and durations retain these event-time semantics?

**Answer:** A: count starts when they start and full durations when they finish, as implemented; B: require counts and durations to refer to the same wait cohort across reset

**Evidence:** [40ea2de1b](https://github.com/sysown/proxysql/commit/40ea2de1b); [include/HostgroupPoolStats.h:45](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/include/HostgroupPoolStats.h#L45); [lib/Base_HostGroups_Manager.cpp:215](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Base_HostGroups_Manager.cpp#L215); [lib/ProxySQL_Admin_Stats.cpp:1256](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Admin_Stats.cpp#L1256).

### OB13 — Ordinary SHOW PROCESSLIST no longer has its short SQL-text view

**Activation / integration:** October 2025; both protocols, all tiers; ordinary Admin SHOW commands.

**Before:** SHOW PROCESSLIST, SHOW PGSQL PROCESSLIST and SHOW PGSQL ACTIVITY selected a fixed SUBSTR(...,0,100) text preview. FULL variants exposed the longer representation.

**After:** The ordinary forms select the complete info/query field available from the processlist projection. Query text is bounded by the new configuration structure, whose Admin default is 2MiB, rather than the old fixed short SHOW preview.

**Observable effect:** An unchanged ordinary SHOW command can return much more SQL text, increase response size, and expose literals beyond the prior preview. FULL still differs in columns, but no longer supplies a distinct SQL-text truncation boundary.

**Question:** Should ordinary SHOW return the same available query text as FULL?

**Answer:** A: retain the complete projected text; B: restore a short preview for ordinary SHOW and reserve longer text for FULL

**Evidence:** [360646b7d](https://github.com/sysown/proxysql/commit/360646b7d); [lib/Admin_Handler.cpp:5479](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/Admin_Handler.cpp#L5479); [lib/ProxySQL_Admin.cpp:3204](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Admin.cpp#L3204); [include/proxysql_admin.h:24](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/include/proxysql_admin.h#L24).

### OB14 — Protocol-labelled Prometheus series replace ambiguous protocol metrics

**Activation / integration:** February 2026; both protocols, all tiers; normal metrics exposition.

**Before:** Affected MySQL metric series lacked a protocol label. PostgreSQL HGM/thread/query-cache metric refreshes were disabled to avoid collisions with names shared by MySQL.

**After:** Affected series distinguish protocol=mysql and protocol=pgsql, and PostgreSQL refreshes are enabled. Metric names can therefore now yield multiple protocol series where an existing consumer previously saw only MySQL observations.

**Observable effect:** A dashboard or recording rule selecting a shared metric name without a protocol filter may now include both protocols. Label-set-sensitive consumers also see a migration, even when only MySQL traffic is present.

**Question:** Should the labelled protocol series be the compatibility boundary for affected metrics?

**Answer:** A: require consumers to select/aggregate protocol-labelled series, as implemented; B: also retain a documented legacy MySQL-compatible series during migration

**Evidence:** [e82ff6f8a](https://github.com/sysown/proxysql/commit/e82ff6f8a); [lib/MySQL_HostGroups_Manager.cpp:465](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_HostGroups_Manager.cpp#L465); [lib/ProxySQL_Admin.cpp:2970](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Admin.cpp#L2970).

## Screened changes that do not request a new policy decision

* The REST route lookup now binds URI and method rather than constructing SQL from request text (#5270); this is a correctness/security correction, not a proposal to preserve injection behavior.
* Logger flush/rotation ownership, forced cross-thread flushing, PostgreSQL newest-row retention and runtime sizing repairs were completed within the initial logger integrations. Their draft broken variants are not separately integrated behavior.
* TSDB sampling now refreshes module metrics before collection (#5426), and later database serialization/rollover repairs restore intended measurements. They do not independently ratify the collection/retention policies above.
* Bounded timestamp/string formatting and preserving 64-bit statistics timestamps are corrections; this report does not ask whether overflow, truncation or unsafe formatting should be retained.
* Credential namespace changes affecting the web UI and pass-through authentication audit fields are reviewed with authentication, not silently omitted.
* TLS certificate details and stats_proxysql_global were introduced together in March. Their intermediate draft table naming/movement is not a separately shipped compatibility break. New cipher/OpenSSL metadata and service snapshots are additions, with TLS/authentication behavior reviewed separately.

## Integration screening coverage

Each row is an integration screened for this stream. “Related” means a shared integration whose substantive policy is reviewed in another stream; it does not claim every line in that integration received a full code review. Deep source traces underpin the questions above.

| Integration | Date | Disposition |
| --- | --- | --- |
| [360646b7d](https://github.com/sysown/proxysql/commit/360646b7d51eb766471ed8f601e04eaf6c7371a6) | 2025-10-20 | Processlist projection/query text; OB13 |
| [27714335a](https://github.com/sysown/proxysql/commit/27714335ab2686bd2e6bbc88cc8dece036f6148a) | 2025-11-28 | Only adds keepalive-disabled LOAD warnings; setting values/defaults and socket policy are unchanged |
| [3c4e09fec](https://github.com/sysown/proxysql/commit/3c4e09fec0bb4261121f53d07c1bc520189486c7) | 2025-12-06 | Prepared-statement statistics/cache refactor; traffic stream |
| [af2318786](https://github.com/sysown/proxysql/commit/af23187865514ec6bdc3dd98c1264667a5402823) | 2025-12-26 | REST lookup parameterization; no new intent question |
| [052436332](https://github.com/sysown/proxysql/commit/0524363322d4ebdc2e6473d0a9059a5556cc0e73) | 2026-02-05 | Initial GenAI surfaces; extensions stream |
| [a360dc22a](https://github.com/sysown/proxysql/commit/a360dc22aed7de67d7349886b936a25d94a3c2a5) | 2026-02-06 | Darwin processlist/build adaptations; no separate telemetry policy |
| [e82ff6f8a](https://github.com/sysown/proxysql/commit/e82ff6f8aa8688f1a721117193696fc3fe9c7580) | 2026-02-12 | Protocol-labelled metrics and PostgreSQL refresh; OB14 |
| [3b578db4b](https://github.com/sysown/proxysql/commit/3b578db4bf767b29ad25b71c500eeaff200749cd) | 2026-02-15 | Logger/preparatory statistics cleanup; no separate policy |
| [acd955b9d](https://github.com/sysown/proxysql/commit/acd955b9d6efc4cb37ca7947d4c31c5da46c013d) | 2026-02-16 | Adds WebUI MetricsCollector friend declarations; no executable collector is introduced by that integration |
| [10ff1322b](https://github.com/sysown/proxysql/commit/10ff1322ba16401c94a819f355b4a1f35749d9d7) | 2026-02-17 | MCP multi-profile projections; AI services stream |
| [bad7ce40c](https://github.com/sysown/proxysql/commit/bad7ce40c5598b1d229e4fcd37499e04a2d7243a) | 2026-02-18 | PostgreSQL query-event history; OB03 |
| [9e157d2aa](https://github.com/sysown/proxysql/commit/9e157d2aa37868ce96fd2f793e687b41901f6c50) | 2026-02-19 | TSDB policy and built-in reads; OB06, OB07, OB08, OB09, OB10 |
| [b64f2e561](https://github.com/sysown/proxysql/commit/b64f2e56149fbc10a85ff55ca29928b958f44fe5) | 2026-02-20 | Buffered logging and sampling; OB01, OB02 |
| [d683dd7b8](https://github.com/sysown/proxysql/commit/d683dd7b8b4ac1fffd723d30ff811e49952909fd) | 2026-02-25 | Tier/base integration; delivery/extensions streams |
| [5b721a659](https://github.com/sysown/proxysql/commit/5b721a6594f6bfa6e0b513f0ebed83d5fe3fe3bd) | 2026-02-27 | Metric refresh before sampling; OB06 evidence; OB06 |
| [d3f7d2da4](https://github.com/sysown/proxysql/commit/d3f7d2da4c225cc82ae3f4df83229dfd8cb3843d) | 2026-03-07 | Tier guarding of innovative features; delivery stream |
| [161584186](https://github.com/sysown/proxysql/commit/16158418647dbb872ccd60f8497e71d3d9ae8184) | 2026-03-09 | Completes PostgreSQL HGM protocol metric labels after the earlier labels feature; OB14 compatibility boundary applies; OB14 |
| [e336a12aa](https://github.com/sysown/proxysql/commit/e336a12aa513ee52e4e8d1fa9b0b5d39e1fb57c7) | 2026-03-20 | Build, lint or inspected test/support changes in this stream; no distinct telemetry policy |
| [7918e1737](https://github.com/sysown/proxysql/commit/7918e1737d940ad4929b50359be9bddb73fd0702) | 2026-03-20 | Build, lint or inspected test/support changes in this stream; no distinct telemetry policy |
| [cb8d0aa73](https://github.com/sysown/proxysql/commit/cb8d0aa737c9e2dff3fb0db8f5873b30b235b3c7) | 2026-03-22 | TLS certificate/global statistics added; draft naming changes not separately shipped |
| [d0625dc24](https://github.com/sysown/proxysql/commit/d0625dc243296b99c199203982aa508078580447) | 2026-03-31 | Build, lint or inspected test/support changes in this stream; no distinct telemetry policy |
| [669ab9149](https://github.com/sysown/proxysql/commit/669ab914948f03b10c1ded21a4361d283cd9652d) | 2026-04-10 | Build, lint or inspected test/support changes in this stream; no distinct telemetry policy |
| [824588d19](https://github.com/sysown/proxysql/commit/824588d1983f850a941496683d82838b216d5c4c) | 2026-04-14 | Build, lint or inspected test/support changes in this stream; no distinct telemetry policy |
| [65c522e63](https://github.com/sysown/proxysql/commit/65c522e635606c74884828a1c28db7becfda15fa) | 2026-05-03 | GenAI carve-out and stats ownership; extensions stream |
| [05d0268f7](https://github.com/sysown/proxysql/commit/05d0268f78d76be64e429f8d363c5ce3d999e067) | 2026-05-03 | Stats projection plugin ABI; administration/extensions streams |
| [0ceb33680](https://github.com/sysown/proxysql/commit/0ceb3368042947f00e7c1d8372d7c88f3a3214a5) | 2026-05-14 | Same-origin TSDB dashboard and batch fixes; OB10 |
| [185abefec](https://github.com/sysown/proxysql/commit/185abefec1c0862fd5c14465e84f1ace099a894b) | 2026-05-14 | Build, lint or inspected test/support changes in this stream; no distinct telemetry policy |
| [e9dfbeb21](https://github.com/sysown/proxysql/commit/e9dfbeb21dd7225d0cc123b57651b489a05258c0) | 2026-07-11 | Pass-through audit fields; authentication stream |
| [20bbe92a0](https://github.com/sysown/proxysql/commit/20bbe92a0258e78293f3f1359ee901b7aae164bb) | 2026-07-21 | Age-selective digest purge; OB05 |
| [62e05922c](https://github.com/sysown/proxysql/commit/62e05922c35115a56e75c29dac8a5cfb28fef006) | 2026-08-08 | Admin credential scope / web account lookup; authentication stream |
| [4327dbbea](https://github.com/sysown/proxysql/commit/4327dbbea4b77072c095fab4226b8fc8613d7685) | 2026-08-11 | FreeBSD fd count without procfs |
| [16b361e46](https://github.com/sysown/proxysql/commit/16b361e46fa17384b714a17a6b8653f5952dbb08) | 2026-08-11 | Bounded logger/statistics formatting |
| [df292eacc](https://github.com/sysown/proxysql/commit/df292eacc821d56bbed92fcdb68dc98b852e103b) | 2026-08-12 | GenAI handler ownership; extensions stream |
| [99c37c7c1](https://github.com/sysown/proxysql/commit/99c37c7c1b668c46364ecb767ad085838a3cbfef) | 2026-08-18 | Maintainability/bounded formatting; no separate policy |
| [749c4710c](https://github.com/sysown/proxysql/commit/749c4710c7dbd84140166c1a22c925588286c896) | 2026-08-19 | TSDB database/rollover serialization; GenAI defaults reviewed in extensions |
| [e4b5a7657](https://github.com/sysown/proxysql/commit/e4b5a765740eb1cdcaeb4e8724d96e2c8f539298) | 2026-08-31 | Vendored OpenSSL version reporting; explicit maintainer decision #6115 |
| [40ea2de1b](https://github.com/sysown/proxysql/commit/40ea2de1bdf6547951df600185d3b3f1820f1dbe) | 2026-08-31 | Per-hostgroup lifetime/window counters; OB12 |
| [fd001a51b](https://github.com/sysown/proxysql/commit/fd001a51b0cf405141fbdf1b417ad0845bd06b33) | 2026-09-01 | Bounded memory-gauge sampling and gauge-storage correction; OB11 |
| [53327da99](https://github.com/sysown/proxysql/commit/53327da99fdf699a1956cb03a400d642f107ff13) | 2026-09-04 | Digest shared atomic counters and observation consistency; OB04 |
| [2775bb222](https://github.com/sysown/proxysql/commit/2775bb222ed67e613332fa8bfdff526ae56baa49) | 2026-10-01 | Native protocol event shape/Close logging; traffic stream |
| [37d627b97](https://github.com/sysown/proxysql/commit/37d627b9743f7d51d6b783b039f994e0b18474f0) | 2026-10-03 | IAM credential behavior; authentication stream |
| [6f438aa1f](https://github.com/sysown/proxysql/commit/6f438aa1f0e9ed38ecdb107d0bc829d27f9a8408) | 2026-10-03 | Bounded formatting and associated low-risk fixes |
| [58c0e289d](https://github.com/sysown/proxysql/commit/58c0e289d7ec0ad22f3092929579a055d1799d26) | 2026-10-12 | GenAI/script SQL safety; extensions/delivery streams |
| [e100071e2](https://github.com/sysown/proxysql/commit/e100071e2b660c51743d9b52fcd0e7bb515632a0) | 2026-10-12 | Statistics/field-safety batch corrections; source concerns retained separately |
| [4d7dea573](https://github.com/sysown/proxysql/commit/4d7dea573f7868d46ec5adf00e0bf93dbe34bab2) | 2026-10-14 | Admin/stats reentrancy and protocol follow-ups; administration/traffic streams |
| [b0fe50bc3](https://github.com/sysown/proxysql/commit/b0fe50bc3713acd18b270b9330fbcb4a067acc22) | 2026-10-17 | Tier guards and hot-path changes; administration/traffic streams |

## Supplemental cross-stream diagnostics screen

The integration-inventory reconciliation found five additional observation surfaces handed off by other streams. These are recorded behavior additions, screened through their changed source and surviving END definitions/consumers. They are not represented as unanswered policy questions merely because a new field or counter exists. This supplements the 46-row queue above.

| Integration | Before → after / scope | END consumer |
| --- | --- | --- |
| [77fe58280](https://github.com/sysown/proxysql/commit/77fe5828019011dc7c78a3bfd6e8dfe3aae14fbf) | New DEBUG-only PROXYSQL FLUSH [MYSQL|PGSQL] STATS commands call existing digest/error/pool/client-host-cache resets, skipping absent modules. Additive debugging surface; no separate unresolved policy selected. | [lib/ProxySQL_Admin.cpp:1327](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Admin.cpp#L1327) |
| [afc1afac9](https://github.com/sysown/proxysql/commit/afc1afac97231490c72a317e32a6b799d3f079b2) | PROXYSQL INTERNAL SESSION gains actual PROXYSQL_VERSION for both protocols, distinct from advertised database version. Additive diagnostic schema; no intent choice selected. | [lib/MySQL_Session.cpp:1635](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L1635) |
| [fb849fe9d](https://github.com/sysown/proxysql/commit/fb849fe9d41ee02ce9a465e962d141e0ebc442b1) | Counts frontend COM_PING separately in Com_frontend_ping and protocol=mysql Prometheus counter; observed handler still replies locally. Additive counter, no backend ping/routing change. | [lib/MySQL_Session.cpp:8255](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L8255) |
| [d235caa80](https://github.com/sysown/proxysql/commit/d235caa80129f2e2426331faddc4085c35e77829) | Advertises CLIENT_CONNECT_ATTRS; stores validated key/value pairs on frontend stream and projects connect_attrs into internal-session JSON. Duplicate keys collapse in JSON; malformed lengths reject authentication. Source-screened additive diagnostic feature, not an authentication authority. | [lib/mysql_data_stream.cpp:1992](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/mysql_data_stream.cpp#L1992) |
| [b52db0781](https://github.com/sysown/proxysql/commit/b52db0781fb7c442a2b08757696c62dfc5604455) | Adds ssl_ciphers Admin table populated from SSL_CTX_get_ciphers at bootstrap. Observes configured frontend context, does not alter cipher negotiation; no intent choice selected. | [lib/ProxySQL_Admin.cpp:3617](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Admin.cpp#L3617) |
