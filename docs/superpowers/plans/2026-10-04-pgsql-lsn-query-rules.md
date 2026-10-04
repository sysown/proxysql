# PostgreSQL Query-Rule LSN Selection Implementation Plan

> **Execution record:** The user authorized implementation with multiple agents on 2026-10-04. Work was divided by file ownership and integrated on the dedicated feature branch. The original task checklists below describe planned work; the [validation record](../../pgsql-lsn-query-rules-validation.md) records what actually ran and its limits. Related changes are committed together after integration review rather than once per overlapping task.

**Goal:** Add native PostgreSQL LSN-constrained connection selection through `pgsql_query_rules.lsn_from_hostgroup` in ProxySQL v3.1/v4.0, using local last-execution records and shared background sample histories.

**Architecture:** A frontend retains one endpoint/completion timestamp per hostgroup. When an opted-in query reaches backend selection, its session worker resolves that timestamp and supplies a fixed LSN requirement to ordinary selection within its destination hostgroup. Query-cache behavior is unchanged. The PostgreSQL monitor performs server polling and history cleanup; it never updates sessions. History has both progress-based pruning and a configured age limit.

**Tech Stack:** C++17, native PostgreSQL application protocol, existing asynchronous monitor transport, SQLite admin/configuration, cluster runtime snapshots, TAP unit tests and isolated PostgreSQL integration tests.

**Spec:** [Revised design](../specs/2026-10-04-pgsql-lsn-query-rules-design.md). Read it before executing any task. It supersedes all requirements in the 2026-10-03 design and plan.

## Global Constraints

- Work in `/data/rene/proxysql/.worktrees/pgsql-lsn-causal-reads`, branch `feat/pgsql-lsn-causal-reads`; do not change the original `v3.0` checkout.
- All feature code, schema, variables and stats are gated by `PROXYSQL31`; v4.0 inherits the flag. v3.0 behavior and projections remain unchanged.
- Exactly one `{hostname, port, completed_at}` record per frontend/hostgroup. The latest real application completion replaces it, including on a different endpoint. No aggregation of prior source-server dependencies.
- No extra SQL, handshake or identity-validation wait on application connections. No background traversal or mutation of sessions. No completion batches or per-session monitor demand.
- `lsn_from_hostgroup` is nullable, accepts HG0, and occupies the position between `multiplex` and `log`. Rule output initializes to -1.
- `destination_hostgroup` always remains the routing target. No replication-hostgroup activation, writer/reader routing policy, or automatic fallback.
- Monitor settings: `pgsql-monitor_lsn_poll_interval` (proposed 10 ms, range 1–60000), `pgsql-monitor_lsn_poll_timeout` (proposed 100 ms, range 1–600000), and proposed `pgsql-monitor_lsn_history` (60000 ms, range 1000–604800000). Remove rejected `lsn_wait_timeout` and draft polling names without aliases. The history variable is separate from monitor log retention.
- Use fresh local monotonic completion times and sample-send times; choose the first sample with start strictly greater than completion. Arrival time cannot establish ordering.
- Prune by progress where relationships permit and independently by sample age. Retain at most one sample before the history cutoff; unknown relationships or stalled/down servers cannot block age cleanup. Old timestamps may resolve to a newer requirement; never fabricate a sample or relax an unresolved requirement.
- One endpoint record and monitor connection per hostname/port; `stats_pgsql_lsn` has only hostname, port, lsn.
- Cluster choice: no PostgreSQL query-rule sync between the legacy and extended schema tiers. v3.1↔v4.0 may sync. No legacy fallback or silent field loss.
- Keep ordinary transaction, cancellation, connection setup and pool semantics. Opted-in requests use existing acquisition deadlines; the polling timeout never becomes a client deadline.
- Query-cache lookup, insertion and invalidation stay unchanged. Cache hits return without any LSN lookup, monitor wait or backend selection; causal resolution begins only on the backend-selection path.
- Do not rewrite history or perform a blanket reset of the current worktree. Earlier uncommitted code is an interrupted implementation, not a verified baseline.

## Review Focus

1. A delayed poll reply must not cover a completion that occurred after the poll started (Tasks 4, 5, 8).
2. A NULL field, shifted positional column or incompatible cluster projection must not enable a rule accidentally or mutate existing rules on failure (Tasks 2, 3).
3. Enabling rules after a session has already used a backend, or reusing that backend for another frontend, must preserve the correct local record (Tasks 6, 8).
4. Progress/age pruning must retain a valid later sample for old timestamps, remain bounded with stalled or unknown members, and never weaken a resolved requirement (Tasks 4, 5, 8).
5. Cache behavior remains unchanged and cache hits never reach LSN resolution. Backend reuse, named portals, COPY and initialization must apply connection-selection constraints without additional application SQL (Tasks 6, 7, 8).

---

## Starting point and file ownership

At planning time HEAD is `88b42dc8d`; the default branch remains
`546abf5c885ff985c3e98852630bac28de9223a3`. There are uncommitted removals of the
application bootstrap and edits to old docs/tests. Do not treat their build or
tests as evidence for this replacement. Save a local diff for reference before
editing, then replace rejected code with ordinary patches.

| Files | Responsibility |
| --- | --- |
| `include/PgSQL_Query_Processor.h`, `lib/PgSQL_Query_Processor.cpp` | Extended rule/output field, chaining, snapshots and serialization. |
| `include/ProxySQL_Admin_Tables_Definitions.h`, `lib/ProxySQL_Admin_Disk_Upgrade.cpp`, `lib/Admin_Bootstrap.cpp`, `include/proxysql_admin.h` | Versioned table layouts and ordered upgrade. |
| `lib/ProxySQL_Admin.cpp`, `lib/ProxySQL_Config.cpp` | Rule load/save and configuration round trips. |
| `include/ProxySQL_Cluster.hpp`, `lib/ProxySQL_Cluster.cpp`, `lib/Admin_Handler.cpp` | Tier-specific projection, validation, checksums and synchronization. |
| `include/PgSQL_LSN_Manager.h`, `lib/PgSQL_LSN_Manager.cpp` | Endpoint history, timestamp resolution, current progress and pruning; replace batch ownership. |
| `include/PgSQL_LSN_Probe.h`, `lib/PgSQL_LSN_Probe.cpp`, `include/PgSQL_LSN_Monitor.h`, `lib/PgSQL_LSN_Monitor.cpp`, `lib/PgSQL_Monitor.cpp` | Monitor-owned background sampling, publication and periodic pruning, without session demand. |
| `include/PgSQL_Backend.h`, `lib/PgSQL_Backend.cpp`, native connection/protocol/session files | One local last-execution record and real completion hooks. |
| `include/PgSQL_LSN_Routing.h`, HGM/session/thread files, `lib/PgSQL_LSN_Admission.cpp` | Rule-derived monitoring interests and causal-only pool filtering. |
| `lib/ProxySQL_Admin_Stats.cpp`, build files and TAP groups | Tier-gated stats, correct linkage and test registration. |

Delete the rejected feature's `include/PgSQL_LSN_Waiter_List.h` if it has no
remaining caller; preserve the unrelated ordinary pool waiter implementation.
Do not split existing large session/admin files as an unrelated refactor.

## Commit policy

Every task commit must have a descriptive subject and a multi-paragraph body.
Explain the concrete old behavior, the new behavior, the design constraint it
serves, and actual validation with its limits. No subject-only commits and no
generic bodies such as “add LSN dependency and batch manager.” Write the exact
message to a temporary file and use `git commit --file <path>`.

For example, the completed routing commit should explain that only queries
whose effective rules set `lsn_from_hostgroup` resolve a source timestamp; all
pool paths filter candidates in the unchanged destination hostgroup. Its body
must name the tests actually run for pending samples, pool reuse and timeout
behavior, and state which live cases remain untested. Do not claim tests passed
merely because this plan lists them. Stage task paths explicitly.

## Task 1: Remove the rejected integration and establish tier boundaries

**Files:** Modify the existing LSN integration in `include/PgSQL_Connection.h`, `include/PgSQL_Session.h`, `include/PgSQL_Thread.h`, `include/PgSQL_HostGroups_Manager.h`, `include/PgSQL_LSN_Routing.h`, `include/proxysql_structs.h`, their `lib/` implementations, admin/config/cluster files changed by the old replication flag, `lib/Makefile`, `test/tap/tests/unit/Makefile`, and `test/tap/groups/groups.json`.

**Interfaces:** Remove `PgSQL_LSN_Policy`, `Dependency`, `SampleTicket`, completion batching, activation epochs, writer fallback and the application bootstrap contract. No replacement public routing API is introduced in this task.

- [ ] Add baseline tests asserting absence of `lsn_causal_reads` from replication-hostgroup schemas and transport; assert native query execution adds no LSN/identity SQL. For v3.0, assert no LSN settings or stats table and the original query-rule column count/order.
- [ ] Run the new assertions against the rejected implementation and record the failures. Inspect `git diff` against the base to identify feature-only hunks; preserve unrelated native protocol and pool code.
- [ ] Remove rejected runtime hooks and replication schema/config/cluster changes. Remove per-connection LSN stamps and bootstrap state; preserve native application-cycle ownership only where Task 6 will use it. Guard retained standalone LSN code/build targets behind the supported tier.
- [ ] Build and run the existing server-load, configuration, protocol-framer and waiter tests. The four-column replication fixtures must again agree with production schema. Record a tier-specific baseline before adding the new rule field.
- [ ] Commit with a body explaining the discarded architecture and why the default v3.0 path is restored. This is a development checkpoint, not a completed causal-read feature.

## Task 2: Add the ordered, version-gated query-rule field and upgrade

**Files:** Modify `include/ProxySQL_Admin_Tables_Definitions.h`, `include/PgSQL_Query_Processor.h`, `include/proxysql_admin.h`, `lib/PgSQL_Query_Processor.cpp`, `lib/ProxySQL_Admin.cpp`, `lib/ProxySQL_Config.cpp`, `lib/ProxySQL_Admin_Disk_Upgrade.cpp`, `lib/Admin_Bootstrap.cpp`. Create `test/tap/tests/unit/pgsql_lsn_query_rules_unit-t.cpp`; extend `admin_disk_upgrade_unit-t.cpp` and `config_write_unit-t.cpp`; register the new target.

**Interfaces:** Under `PROXYSQL31`, add `int lsn_from_hostgroup = -1` to `PgSQL_Query_Processor_Rule_t` and `PgSQL_Query_Processor_Output`. Add output `init()` following the MySQL reset convention; add `process_query_extended(PgSQL_Query_Processor_Output*, const PgSQL_Query_Processor_Rule_t*)`. Add `void ProxySQL_Admin::disk_upgrade_pgsql_query_rules()` and call it before generic table verification. Extend `new_query_rule(...)` only in the supported tier, placing the parameter after multiplex.

- [ ] Test 34/35 full columns and 33/34 active-projection columns in the two tiers; assert the neighboring values `multiplex=2`, `lsn_from_hostgroup=17`, `log=1`, `apply=1` survive every round trip. Test NULL, HG0, negative rejection, cloning, chained overrides and resetting the next query to -1. Run the new target and record failure.
- [ ] Implement both schema definitions, the gated rule/output field, runtime cloning/rendering, admin positional parsing and config read/write. Validate the full incoming column names/order/count before clearing rules or changing checksums; do not add the field to the shared MySQL/PGSQL base type in v3.0.
- [ ] Test migration of a real legacy SQLite table with non-default rules, high IDs, quoted text and inactive rows. Assert all legacy values survive, the new field is NULL in the correct position, the next generated ID is valid, and a second upgrade is a no-op. Include failure/rollback coverage.
- [ ] Implement transactional table reconstruction with explicit legacy column lists; preserve the existing table until the replacement has been built and copied successfully. Plain `ALTER TABLE ADD COLUMN` is insufficient. Wire the upgrade into bootstrap before disk-to-memory loading.
- [ ] Run `make -C test/tap/tests/unit pgsql_lsn_query_rules_unit-t admin_disk_upgrade_unit-t config_write_unit-t` and those three binaries in the supported build; run the legacy schema assertions against the v3.0 build. Commit with migration and round-trip evidence.

## Task 3: Version the cluster projection and reject incompatible synchronization

**Files:** Modify `include/ProxySQL_Cluster.hpp`, `lib/ProxySQL_Cluster.cpp`, `lib/Admin_Handler.cpp`, `lib/ProxySQL_Admin.cpp`; extend `test/tap/tests/unit/cluster_sync_unit-t.cpp` and `pgsql_lsn_query_rules_unit-t.cpp`.

**Interfaces:** Preserve `CLUSTER_QUERY_PGSQL_QUERY_RULES` as the tier-selected projection: 33 fields in v3.0, 34 in v3.1/v4.0. Use that same ordered projection for the cached runtime resultset and checksum. Keep fast-routing transport unchanged. Declare `static bool ProxySQL_Admin::validate_pgsql_query_rules_projection(const SQLite3_result&, std::string&)` in `include/proxysql_admin.h`, implement it in `lib/ProxySQL_Admin.cpp`, and call it before mutation at the admin/cluster boundary.

- [ ] Add transport fixtures with distinct values around the new position. Test new→new and legacy→legacy round trips, matching checksums, NULL and HG0. Test both incompatible directions, truncated/extra/reordered fields, and malformed source IDs; failures must leave runtime, admin rows, disk rows and checksums unchanged.
- [ ] Run the tests to observe rejection/shape failures before changing transport. Include an actual legacy query string sent to the newer admin handler, rather than only testing a helper.
- [ ] Implement the gated request string and admin interception. Reject the incompatible legacy projection on newer nodes; never serve the newer resultset under an old column list. Validate shape and rule values before applying incoming snapshots; handle loader failure before save-to-memory/disk or success metrics.
- [ ] Verify checksum input is exactly the resultset being transported. No retry without `lsn_from_hostgroup`, no all-NULL compatibility exception, and no change to unrelated cluster modules.
- [ ] Run `make -C test/tap/tests/unit cluster_sync_unit-t pgsql_lsn_query_rules_unit-t` and both binaries in the relevant tiers. Commit with the explicit mixed-version limitation in the body.

## Task 4: Replace the batch manager with timestamp histories

**Files:** Replace the contracts in `include/PgSQL_LSN_Manager.h`, `lib/PgSQL_LSN_Manager.cpp`, and `test/tap/tests/unit/pgsql_lsn_manager_unit-t.cpp`.

**Interfaces:** Keep `Endpoint{address,port}`, numeric `Lsn`/`Micros`, and `History{system_id,timeline}`. Define `LastExecution{Endpoint endpoint; Micros completed_at=0;}`, `Sample{Micros started_at; Lsn lsn;}`, and `RequiredLsn{History history; Lsn lsn;}`. Define `LookupState{Ready,Pending,Unavailable,HistoryChanged}` and `LookupResult{LookupState state; std::optional<RequiredLsn> required;}`. Define `Observation{Endpoint endpoint; History history; int64_t postmaster_start_us; Sample sample; bool valid;}`. Manager methods:

```cpp
void reconcile_endpoints(const std::vector<Endpoint>&);
void publish(const Observation&);
void withdraw(const Endpoint&);
LookupResult lookup_after(const Endpoint&, Micros) const;
std::optional<Observation> latest(const Endpoint&) const;
void retain_predecessor(const Endpoint&, Lsn);
void prune_before(Micros cutoff);
uint64_t revision() const;
std::vector<Observation> latest_all() const;
```

- [ ] Write deterministic tests for strict timestamp ordering, equal timestamps, a delayed response from a poll started before completion, empty/pending histories, gaps between LSNs, duplicate coalescing, fixed resolved targets, withdrawal/recovery and stale/changed history. Test old timestamps cannot cross an observed identity reset. Separately test first discovery after completion: a successful first sample started later resolves the dependency, without a reconnect or activation guard.
- [ ] Test pruning with samples `(100,12330),(200,12339),(300,12345)` and floor 12340: completion 150 resolves to 12339; completion 250 resolves to 12345; completion 350 remains pending. Add no-predecessor and equal-LSN cases. Run the failing target.
- [ ] Test age cutoff 250 with those same samples: retain `(200,12339)` and `(300,12345)`, resolve completion 150 to 12339 and completion 250 to 12345. Cutoff 400 retains only `(300,12345)`; completion 350 remains pending. Cover cutoff equality, no samples, all old samples, duplicate coalescing, shrinking/enlarging the window, and both orders of progress/age pruning. Verify pruning leaves already-resolved request targets unchanged.
- [ ] Implement per-endpoint ordered numeric storage with binary search, append/coalesce and prefix removal. `prune_before` keeps at most the newest sample before the cutoff plus all newer samples for each endpoint, respecting stricter prior progress pruning. Release expired storage or bound reusable capacity. Use narrow endpoint synchronization; ordinary current-progress reads never scan the history. Publication and lookup contain no session pointers, hostgroup IDs, shared completion handles or socket I/O.
- [ ] Keep a validity boundary for an observed identity/reset change separate from the pruning anchor. Ignore stale publications. A missing endpoint or old history cannot turn an existing source record into “no dependency.”
- [ ] Run `make -C test/tap/tests/unit pgsql_lsn_manager_unit-t` and the binary; run this pure component with ASan/UBSan. Commit with the ordering proof and pruning examples in the body.

## Task 5: Derive interests from rules and poll physical servers

**Files:** Modify `include/PgSQL_LSN_Routing.h`, HGM headers/implementation, `lib/ProxySQL_Admin.cpp`, `include/PgSQL_LSN_Probe.h`, `lib/PgSQL_LSN_Probe.cpp`, `include/PgSQL_LSN_Monitor.h`, `lib/PgSQL_LSN_Monitor.cpp`, `lib/PgSQL_Monitor.cpp`, variable definitions in the thread/header files, and monitor/probe/config unit tests.

**Interfaces:** Replace routing policy with `PgSQL_LSN_Interest{uint32_t source_hostgroup; std::vector<uint32_t> destination_hostgroups; bool any_destination;}`. Declare `std::vector<PgSQL_LSN_Interest> collect_pgsql_lsn_interests(const SQLite3_result& rules, const SQLite3_result& fast_routes)` in `include/PgSQL_LSN_Routing.h` and implement it beside runtime rule loading in `lib/ProxySQL_Admin.cpp`. Add `void PgSQL_HostGroups_Manager::replace_lsn_interests(const std::vector<PgSQL_LSN_Interest>&)`. The HGM expands current endpoint membership for monitoring and pruning; it never stores duplicate physical samples. `PgSQL_Monitor` schedules `PgSQL_LSN_Monitor` polling and housekeeping using all three `pgsql-monitor_lsn_*` settings. The monitor calls Task 4 publication/pruning methods; session workers perform only timestamp lookups and candidate checks on the backend-selection path.

- [ ] Add tests for direct 10→20 rules, shared endpoints, 10→20 plus 10→30, chained flag/source/destination rules, fast routing, unspecified default destinations, disabled rules and server reload. In uncertain rule paths, assert conservative destination coverage rather than dropped interests. Run the failing tests.
- [ ] Implement interest derivation outside the per-query path. Use reachable rule chains while ignoring match predicates conservatively; unresolved/default destinations set `any_destination`, including configured hostgroups. Publish interests with the same runtime-rule change. Server reload recomputes membership without consulting replication hostgroups.
- [ ] Add monitor tests for one connection per endpoint, start-time capture at sample send, one outstanding probe, cadence, bounded poll timeout, delayed final response, stale reconnect results, monitor disable and DNS-cache-disabled hostnames. Assert no session access or completion-count-driven sampling.
- [ ] Add retention tests with one replica stuck for ten minutes while other replicas advance, unknown rule relationships, failed/down probes, unchanged LSNs and a changed history window. Advance a fake monotonic clock and prove age cleanup continues without successful probes or a usable progress floor. Test all three setting names, ranges, runtime reload and absence in v3.0.
- [ ] Replace batch tickets/demand with periodic polling of relevant endpoints. Retain background-only identity validation and reuse existing monitor credentials/TLS. Use insertion or replay position according to server recovery state, without assigning routing roles. Add the new supported-tier variables with the exact defaults/ranges in the spec.
- [ ] On publications/config changes, compute each source endpoint's progress-pruning floor over the union of its source/destination memberships. Unknown or incompatible progress prevents advancing that floor only. Independently run `prune_before(max(0, now - history_ms * 1000))` during monitor housekeeping, including failed-probe ticks. Keep one physical history across duplicate memberships. Retention does not change server health/status; normal candidate LSN comparison excludes replicas below the required position.
- [ ] Run `make -C test/tap/tests/unit pgsql_lsn_probe_unit-t pgsql_lsn_monitor_unit-t pgsql_lsn_config_unit-t pgsql_lsn_manager_unit-t` and those binaries. Include the existing monitor lifecycle regression tests. Commit with cadence, timeout and retention behavior explained.

## Task 6: Record the last actual native execution locally

**Files:** Modify `include/PgSQL_Backend.h`, `lib/PgSQL_Backend.cpp`, `include/PgSQL_Connection.h`, `lib/PgSQL_Connection.cpp`, `include/PgSQL_Session.h`, `lib/PgSQL_Session.cpp`, `lib/PgSQL_Protocol.cpp`, and `test/tap/tests/unit/pgsql_lsn_completion_unit-t.cpp`.

**Interfaces:** Add `LastExecution last_execution` to `PgSQL_Backend` under `PROXYSQL31`. Add `void PgSQL_Session::record_lsn_completion(const PgSQL_Connection&, Micros completed_at)`; the native response boundary supplies a fresh monotonic time. Retain only the minimal application-cycle/owner marker needed to distinguish real application responses from internal/synthetic responses. No connection certificate or manager lookup is required.

- [ ] Rewrite completion tests to assert exactly one overwritten tuple per HG, no manager enrollment, correct actual endpoint, separate HG records, and persistence across pool detach/reuse. Explicitly test A@200 followed by B@150 in the same HG: the source record becomes B, as agreed; there is no retained A dependency.
- [ ] Test native simple and extended completion, suppressed ReadyForQuery, explicit commit, COMMIT AND CHAIN, rollback, multi-statement errors and COPY. Internal setup/reset, cached results, synthetic errors and intermediate protocol acknowledgements do not update the record. Run the failing target.
- [ ] Implement local bookkeeping before frontend completion publication. Update endpoint text only when the endpoint changes. Preserve the record through backend reset/detach but clear it when the frontend is destroyed; audit `PgSQL_Backend::reset()` accordingly.
- [ ] Use a socketpair test to assert completion bookkeeping and later timestamp resolution emit zero additional application bytes and leave DSS, pending buffers, deadlines and `init_connect` state unchanged. Test enabling query rules after the session already has a completion record.
- [ ] Run completion, command-complete, response-framer, transaction-state and named-portal tests. Verify the 3.0 type layout/path does not include this bookkeeping. Commit with the precise completion boundary and last-server replacement semantics.

## Task 7: Apply the requirement only to opted-in connection selection

**Files:** Modify `include/PgSQL_Session.h`, `lib/PgSQL_LSN_Admission.cpp`, `lib/PgSQL_Session.cpp`, HGM and thread pool-selection code, and `test/tap/tests/unit/pgsql_lsn_admission_unit-t.cpp`; update worker waiter regression tests as necessary. Preserve existing query-cache implementation and policy.

**Interfaces:** Request-local `PgSQL_LSN_Request` contains the effective source HG, a copy of `LastExecution`, and an optional fixed `RequiredLsn`. Add `enum class PgSQL_LSN_PrepareResult { Disabled, Ready, Pending, Error };` and `PgSQL_LSN_PrepareResult PgSQL_Session::lsn_prepare_request()`. Preserve `bool lsn_server_allowed(const PgSQL_SrvC&) const` and `bool lsn_backend_allowed(const PgSQL_Connection&) const` as cached eligibility predicates; remove bootstrap/allow-unstamped meanings. Pool APIs already receiving the session use its requirement without repurposing GTID strings.

- [ ] Test that an unset field or absent source record performs no history lookup and has ordinary routing/cache behavior. Test set HG0, pending sample, a fixed resolved target, different source/destination HGs, actual source endpoint selection after membership change, and the deliberate last-server replacement behavior.
- [ ] Test a cache hit with an effective `lsn_from_hostgroup` and an existing source record while monitor data is missing: it returns without LSN lookup, waiting or backend selection, and leaves the source record unchanged. A cache miss reaches constrained backend selection; insertion retains existing rules/TTL behavior.
- [ ] Test lagging candidates are excluded before weighting in local/shared pools, attached reuse and explicit new-connection requests. With no candidate, assert the destination never changes. Changing background poll timeout must not change the client deadline. Run the failing tests.
- [ ] Resolve when backend selection is reached, after ordinary query-cache handling and before the backend operation acquires a snapshot. Capture the source once; store the resolved requirement once. Use only latest in-memory candidate observations to filter connections. No internal SQL or backend certification calls remain.
- [ ] Reuse ordinary non-vanilla backend acquisition/retry scheduling, as MySQL's GTID path does. Start and retain the ordinary acquisition deadline even while the source sample is pending. Preserve query cancellation, disconnect and shutdown; do not build a dedicated LSN wait-timeout/fallback subsystem or a monitor-to-session notification list.
- [ ] Recheck the connection-selection predicate before backend dispatch, including Bind/portal creation and COPY. Respect existing transaction/portal affinity; if an opted-in request cannot meet the requirement on its pinned backend, fail without moving or leaving an inconsistent transaction state. Do not alter affinity for ordinary queries or add LSN behavior to query-cache paths.
- [ ] Run admission, query-cache allocation, worker-waiter, named-portal and transaction-state tests. Include refusal with `mybe` pointing at a different HG from the actual active backend, the defect found in the earlier review. Commit with no-fallback and ordinary-timeout evidence.

## Task 8: Validate the supported tiers and end-to-end behavior

**Files:** Replace the rejected scenarios in `test/tap/tests/pgsql_lsn_endpoint_smoke.py`; create `test/tap/tests/pgsql_lsn_cluster_schema_smoke.py`; update TAP groups, unit Makefile, `lib/ProxySQL_Admin_Stats.cpp`, and create `docs/pgsql-lsn-query-rules.md`.

**Interfaces:** Live scripts take explicit proxy binary paths and an artifact directory, create unique containers/listeners, and clean up only resources they created. Cluster smoke takes `--proxy30`, `--proxy31`, `--proxy40`, `--artifacts`. Stats consumes `latest_all()` from Task 4 and formats LSNs without exposing historical rows.

- [ ] Add native live cases with one source and two physical replicas: ordinary reads remain unrestricted; an opted-in read waits for its source sample and eligible destination; paused destination replay causes ordinary acquisition timeout without switching HG; source completion is acknowledged without waiting for a poll. Compare application PostgreSQL statement logs with feature disabled/enabled to prove zero added application SQL.
- [ ] Test fresh and pre-existing pooled connections with different timezone/search-path settings and configured initialization SQL. Test source rules enabled after completion, explicit transactions, extended Bind/Execute/Sync, COPY, cancellation, pool exhaustion and an unknown sampled endpoint. Keep artifacts proving sample-start ordering and fixed targets.
- [ ] Test the minimum/predecessor example, duplicate memberships, one source feeding two destinations, rule reload and a newly added lagging server. Verify `stats_pgsql_lsn` has exactly three columns and one row per physical endpoint.
- [ ] Verify bounded history with one replica stuck beyond `pgsql-monitor_lsn_history`, unknown relationships and a down server. Resolve an old completion to the retained later anchor, select an eligible recent replica and exclude the lagging one. Also test no eligible replica: retain ordinary acquisition timeout. Verify cache hits with configured LSN rules use the existing cache behavior and perform no backend selection or history lookup.
- [ ] Build v3.0, v3.1 and v4.0 from the same completed feature commit in separate disposable worktrees/build directories. Do not trust the unit Makefile's auto-detection to prove a v3.0 build; inspect the actual binary and schema. Commands for the respective build roots are `make -j4 debug`, `make -j4 PROXYSQL31=1 debug`, and `make -j4 PROXYSQL40=1 debug`.
- [ ] In each applicable build, compile/run `pgsql_lsn_query_rules_unit-t`, `cluster_sync_unit-t`, `admin_disk_upgrade_unit-t`, `config_write_unit-t` and the relevant server-runtime fixtures. In supported builds also run manager, probe, monitor, completion, admission, waiter, query-cache, transaction and framer targets. Include `WITHGCOV=1` for standalone LSN test linkage and ASan/UBSan for the pure history manager. Run `python3 -m unittest discover -s test/tap/groups -p test_makefile_dependencies.py -v`.
- [ ] Run `python3 test/tap/tests/pgsql_lsn_endpoint_smoke.py --proxy <v31-binary> --artifacts <owned-dir>` and the v4.0 equivalent. Run cluster smoke for 3.0↔3.0, 3.1↔3.1, 3.1↔4.0 and both incompatible 3.0/new directions, proving rejection is non-mutating. Verify online upgrade preserves a populated legacy config DB.
- [ ] Measure non-causal throughput/latency against the same base build, with polling inactive and active; report the local timestamp cost rather than claiming zero CPU overhead. Measure history memory versus window/poll interval, allocated capacity after pruning, monitor housekeeping cost and causal lookup cost. Hold a replica indefinitely and verify memory stabilizes; at fixed cadence expect roughly `ceil(history_ms / poll_interval_ms) + 2` retained samples per endpoint before coalescing.
- [ ] Write operator documentation with one `lsn_from_hostgroup` rule example, the three monitor settings, old-timestamp lookup after pruning, unchanged cache behavior, the last-server contract, native/tier scope, cluster incompatibility and no application SQL. Obtain a whole-change review before describing the feature as complete. Commit with actual results, unrun cases and remaining risks; do not claim the previous design's tests validated this one.

## Self-review and execution handoff

The plan covers the agreed single-record overwrite behavior, the polling-only
timeout, explicit monitor ownership, physical endpoint tracking, timestamp/send
ordering, retained anchors with an age limit, unchanged caching, per-rule opt-in,
unchanged destination, native-only execution and the four
schema/version/upgrade/cluster requirements. Each Review Focus item maps to
specific tests above.

Implementation and integration review are complete. Final debug builds passed
for all three tiers; the 3.1 affected suites passed 1,095 assertions, live
native tests passed 27 checks each on 3.1 and 4.0, and the live cluster/upgrade
matrix passed 104 checks. See the validation record for legacy/4.0 linked
tests, sanitizer/coverage results and the planned experiments that were not
run. The original `v3.0` checkout remains untouched; the feature branch and
worktree are retained for review.
