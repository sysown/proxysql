# PostgreSQL LSN Causal Reads Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide session read-your-writes consistency on PostgreSQL physical replicas using shared background LSN sampling and bounded asynchronous waits.

**Architecture:** A hostgroup-owned manager batches observed writer completions and publishes immutable dependency and server-progress snapshots. Dedicated monitor connections certify WAL identity and progress; session and pool admission check those snapshots before acquiring a read snapshot. The frontend owns its dependencies across multiplexing.

**Tech Stack:** C++17, existing PostgreSQL native and libpq backend paths, asynchronous monitor and worker infrastructure, SQLite admin configuration, TAP unit/integration tests, isolated PostgreSQL 17 containers.

**Spec:** [PostgreSQL LSN Causal Reads Design](../specs/2026-10-03-pgsql-lsn-causal-reads-design.md). Read both documents before execution.

## Global Constraints

- Work only in `/data/rene/proxysql/.worktrees/pgsql-lsn-causal-reads`, branch `feat/pgsql-lsn-causal-reads`. Never build or edit through the original checkout.
- `pgsql-lsn_poll_interval`: default 10 ms, accepted range 1 through 60000 ms.
- `pgsql-lsn_wait_timeout`: default 100 ms, accepted range 0 through 600000 ms; zero means one eligibility check followed by valid-writer fallback.
- `lsn_causal_reads INT NOT NULL DEFAULT 0 CHECK(lsn_causal_reads IN (0,1))` enables a writer/reader hostgroup pair. No additional tuning variables.
- One authoritative writer, physical replication, matching current timeline, direct stable endpoints, externally fenced failover. No additional commit-durability guarantee.
- No PostgreSQL extension, application changes, replication slot, WAL stream, or per-commit SQL query. Identity probes use `replication=database` and require replication permission and WAL sender capacity.
- Seal before sending the writer sample; sample insertion LSN on writers and replay LSN on readers. Every completed application cycle returning to idle on a protected writer is covered.
- No worker-blocking waits; one causal deadline per request; no stale-read fallback. Invalid history uses SQLSTATE `55000`; ordinary cancellation retains existing semantics.
- Dependencies, batches, and waiters remain process-local. Writer incarnation changes invalidate old dependencies in v1. Do not add failover ancestry inference.
- Tests must cover both supported backend protocols. Preserve existing unsupported-protocol errors rather than silently skipping causal admission.

## Review Focus

1. A completion arriving after sealing but before the sample reply must join the next batch (Task 1).
2. A numerically higher LSN from the wrong history, or old certification after reconnect, must never qualify a replica (Tasks 1, 3, 4).
3. An error following an earlier commit, or a suppressed native ReadyForQuery packet, must still preserve the dependency before returning control to the frontend (Task 4).
4. Cached connections, cached results, and Bind-created snapshots must obey the same admission gate as ordinary queries (Task 5).
5. Activation on an old frontend, cancellation during waiter registration, and mixed-version cluster sync must fail or wake safely without erasing dependencies (Tasks 2, 5, 7).

---

## Workspace and baseline

The design commit `dac3d99fa19e8a277f2abb4dfc30f0634dc1c74d` is preserved on the feature branch. Local default branch `v3.0` was restored to `546abf5c885ff985c3e98852630bac28de9223a3`, matching `origin/v3.0` at planning time. User untracked files in the original checkout were left in place.

Checks already run in the feature worktree:

```bash
python3 -m unittest discover -s test/tap/groups -p test_makefile_dependencies.py -v
make -C test/tap/tests/unit pgsql_waiter_list_unit-t
./test/tap/tests/unit/pgsql_waiter_list_unit-t
```

Results: 5 Python tests and 39 TAP assertions passed. No feature implementation, full build, live replication test, or benchmark has run yet.

## File responsibilities

| Files | Responsibility |
| --- | --- |
| New `include/PgSQL_LSN_Manager.h`, `lib/PgSQL_LSN_Manager.cpp` | Validated positions, identities, batches, generations, immutable views, demand and eligibility. No sockets or session pointers. |
| New `include/PgSQL_LSN_Probe.h`, `lib/PgSQL_LSN_Probe.cpp` | Identity/sample/identity probe state and strict result validation. |
| `include/PgSQL_Monitor.hpp`, `lib/PgSQL_Monitor.cpp` | Dedicated asynchronous connections, cadence, deadlines, publication and worker notification. |
| PostgreSQL connection, protocol and session files | Backend identity bootstrap, real completion boundaries, frontend dependency ownership and request admission. |
| PostgreSQL hostgroup and thread files; new `include/PgSQL_LSN_Waiter_List.h` | Common pool eligibility, manager lifetime, separate worker-owned LSN wait queues. |
| Admin/configuration/cluster files in Task 2 | Activation and variable lifecycle, migration, compatibility checks. |
| Stats files and new `docs/pgsql-lsn-causal-reads.md` | Current-state diagnostics, bounded counters and operator instructions. |
| New isolated infrastructure and tests in Task 7 | Three-server acceptance suite without modifying existing replication test semantics. |

## Task 1: Establish the dependency, batch and eligibility contract

**Files:** Create `include/PgSQL_LSN_Manager.h`, `lib/PgSQL_LSN_Manager.cpp`, `test/tap/tests/unit/pgsql_lsn_manager_unit-t.cpp`; modify `lib/Makefile`, `test/tap/tests/unit/Makefile`.

**Interfaces:** Define the value types in namespace `pgsql_lsn`; keep `PgSQL_LSN_Manager` consistent with existing top-level class names.

```cpp
using Lsn = uint64_t;
using GroupId = uint32_t;       // writer hostgroup
using Generation = uint64_t;
using Micros = uint64_t;        // monotonic time only
struct Endpoint { std::string address; uint16_t port; };
struct History { uint64_t system_id; uint32_t timeline; };
struct Incarnation { History history; int64_t postmaster_start_us; };
enum class Role { Writer, Replica };
struct ServerToken {
    GroupId group; Generation generation; Endpoint endpoint;
    Incarnation incarnation; Role role;
};
enum class Reason {
    None, HistoryChanged, TrackingNotInitialized, NoSafeBackend
};
enum class DependencyState { Clean, Pending, Ready, Invalid };
struct DependencyView {
    DependencyState state; std::optional<ServerToken> source;
    std::optional<Lsn> required_lsn; uint64_t revision; Reason reason;
};
struct GroupConfig {
    GroupId writer_hostgroup; uint32_t reader_hostgroup; bool enabled;
    std::vector<Endpoint> writers, readers;
};
struct Progress {
    ServerToken server; uint64_t connection_generation;
    std::optional<Lsn> insert_lsn, replay_lsn; bool valid;
    Micros sampled_at_us, duration_us; std::string error;
};
std::optional<Lsn> parse_lsn(std::string_view text);
std::string format_lsn(Lsn value);
bool replica_satisfies(const DependencyView&, const Progress&,
                      const ServerToken& backend);
```

`Dependency` is a copyable shared handle with RAII demand accounting; an empty handle is clean. Its internals retain source token, resolved floor and latest batch reference, never a session pointer. `SampleTicket` is an opaque group/batch/generation/attempt token. `GroupSnapshot` contains configuration, revision, current generation, optional validated writer token, endpoint progress, and demand. Manager methods (all nonblocking apart from short internal locks):

```cpp
void reconcile_groups(const std::vector<pgsql_lsn::GroupConfig>&);
pgsql_lsn::Dependency observe_completion(const pgsql_lsn::ServerToken&,
                                        const pgsql_lsn::Dependency& previous);
pgsql_lsn::DependencyView resolve(const pgsql_lsn::Dependency&) const;
std::optional<pgsql_lsn::SampleTicket> seal_writer_batch(pgsql_lsn::GroupId);
bool complete_writer_sample(const pgsql_lsn::SampleTicket&,
                            const pgsql_lsn::Progress&);
void publish_progress(const pgsql_lsn::Progress&);
void invalidate_endpoint(const pgsql_lsn::Endpoint&, pgsql_lsn::Reason);
pgsql_lsn::GroupSnapshot snapshot(pgsql_lsn::GroupId) const;
```

- [x] **Write deterministic TAP cases** using actual manager methods, explicit synthetic tokens and barriers. No wall-clock sleeps. Assert these outcomes using `ok(...)`:

  ```cpp
  ok(!parse_lsn("0/100000000"), "reject over-wide low half");
  ok(!parse_lsn("0/1junk"), "reject trailing garbage");
  ok(parse_lsn("FFFFFFFF/FFFFFFFF") == UINT64_MAX, "full uint64 range");
  ok(manager.resolve(before).required_lsn == 0x100, "sealed batch resolved");
  ok(manager.resolve(after).state == DependencyState::Pending,
     "late completion cannot use earlier sample");
  ok(!replica_satisfies(required, wrong_history, backend), "history first");
  ```

  Also test null/empty/overflow positions, legitimate zero, failed probe retry, late retry result rejection, fixed resolved targets, many completions sharing one batch, generation invalidation, replica-only restart, mismatching backend stamps, unchanged-weight reload, and reference release. Establish fixture variables directly through the public API. Verify two unresolved batch objects maximum and no chain of prior dependencies after repeated writes.
- [x] **Run the new standalone target and observe failure:** `make -C test/tap/tests/unit pgsql_lsn_manager_unit-t`. The first failure is the missing manager contract; after compiling, the assertions must expose missing behavior.
- [x] **Implement the contract.** Use short per-group locking to serialize enrollment and rotation. Never acquire a hostgroup, monitor or worker lock while holding it. Publish snapshots and notify after releasing it. Latest pending batches can supersede earlier dependencies only through the ordered single-writer sampling sequence; retain the resolved floor. Reject ambiguous mappings atomically. Zero/multiple current writers disable certification. Different replicas have different postmaster start times: compare their WAL history with the writer, and compare their individual incarnation with the selected backend. `invalidate_endpoint(..., NoSafeBackend)` withdraws certification on a transient probe/connect failure; it does not declare the writer history changed. An observed writer incarnation change invalidates the group; an observed replica change invalidates only that endpoint.
- [x] **Add build registration and run the target:** follow the standalone waiter-list Makefile rule, linking the new manager source, TAP and pthread directly. Expected: every assertion passes without a running proxy or PostgreSQL. Run a sanitizer build of this target for reference lifetime and concurrent enrollment/publication.
- [x] **Commit only these paths:** `feat(pgsql): add LSN dependency and batch manager`.

## Task 2: Wire configuration and manager ownership

**Files:** Modify `include/ProxySQL_Admin_Tables_Definitions.h`, `include/PgSQL_HostGroups_Manager.h`, `include/PgSQL_Thread.h`, `include/proxysql.h`, `include/ProxySQL_Cluster.hpp`; `lib/PgSQL_HostGroups_Manager.cpp`, `lib/PgSQL_Thread.cpp`, `lib/ProxySQL_Admin.cpp`, `lib/ProxySQL_Admin_Disk_Upgrade.cpp`, `lib/ProxySQL_Config.cpp`, `lib/ProxySQL_Cluster.cpp`, `lib/ProxySQL_ManagedRuntime.cpp`, `lib/Admin_Handler.cpp`, `lib/Admin_Bootstrap.cpp`; create `test/tap/tests/unit/pgsql_lsn_config_unit-t.cpp`; modify its Makefile.

**Interfaces:** Consume `PgSQL_LSN_Manager::reconcile_groups(...)`. Add `PgSQL_LSN_Manager& PgSQL_HostGroups_Manager::lsn_manager()` backed by one owned manager; no process-global session registry. Configuration snapshots expose pair membership and an activation epoch so sessions can detect enabling after connection creation. Define `bool validate_lsn_groups(const std::vector<pgsql_lsn::GroupConfig>&, std::string& error)` in the manager interface for consistent admin/runtime validation.

- [x] **Write configuration tests** using the real SQLite schemas, migration and variable setter/load paths. Assert default flag zero; defaults 10/100; interval 0 and 60001 rejected; timeout 0 accepted and 600001 rejected; nonnumeric/overflow rejected; overlaps rejected; separate pairs accepted. Migration must preserve every existing column and row. Use exact value assertions, for example `ok(poll_interval == 10 && wait_timeout == 100, "LSN defaults")`. Add new config fields to existing managed-runtime test fixtures that enumerate columns.
- [x] **Build and run `pgsql_lsn_config_unit-t`; record expected failures** for missing columns/setters before wiring them. Full object dependencies can be built with `PROXYSQL31=1 make debug`; do not reuse main-checkout build artifacts.
- [x] **Implement both variables throughout registration, defaults, validation, thread refresh and exported names.** Reuse existing variable persistence; add thread-local declarations/definitions where PostgreSQL settings live. Snapshot timeout into each request later in Task 5; live updates cannot restart existing deadlines.
- [x] **Version the replication-hostgroup schema and preserve old definitions for migration.** Include the column in disk/runtime/internal tables, every explicit SELECT/INSERT, import/export, managed runtime, LOAD/SAVE and checksum/cluster transfer queries. Validate before swapping runtime mappings. Treat disabled mappings as ordinary legacy routing. Destroy the manager only after monitor publications and worker/session handles are quiescent.
- [x] **Implement mixed-version rejection.** Detect the peer's support using the actual replication-hostgroup column projection before applying a sync. If the projection fails or the field is missing, reject synchronization of this configuration; retain the prior runtime state and report the peer incompatibility. Never retry by silently dropping `lsn_causal_reads`. Cover supported and legacy-shaped responses in unit tests; end-to-end sync is Task 7.
- [x] **Run the config target and existing build-system tests.** Expected: all assertions pass, generated configuration with protection off retains old routing behavior. This intermediate commit is development-only: the opt-in feature is not ready until Tasks 3–7 complete.
- [x] **Commit the task paths:** `feat(pgsql): configure LSN causal hostgroup pairs`.

## Task 3: Certify server identity and progress asynchronously

**Files:** Create `include/PgSQL_LSN_Probe.h`, `lib/PgSQL_LSN_Probe.cpp`, `test/tap/tests/unit/pgsql_lsn_probe_unit-t.cpp`; modify `include/PgSQL_Monitor.hpp`, `lib/PgSQL_Monitor.cpp`, `lib/Makefile`, `test/tap/tests/unit/Makefile`.

**Interfaces:** Consume manager snapshots, sample tickets and publication methods from Task 1. `PgSQL_LSN_Probe` owns no socket; the monitor adapter drives it using libpq simple queries. Define `ProbeRows` as `std::vector<std::vector<std::optional<std::string>>>` and methods `std::optional<std::string> next_command()`, `bool consume_result(const ProbeRows&, std::string& error)`, `std::optional<pgsql_lsn::Progress> finish() const`. Construction takes group ID/generation, endpoint, expected role, optional expected incarnation, connection generation and monotonic start time. Initial discovery has no expected incarnation; it publishes identity only after completing the full handshake, never by inventing a zero-valued identity. Errors clear publishable output. The adapter checks result status, field count, complete result draining, socket continuity and deadline before calling `finish()`.

- [x] **Write probe-state tests:** initial `IDENTIFY_SYSTEM`, SQL, final `IDENTIFY_SYSTEM`; no publication before the last result; changed system ID/timeline/role/postmaster/connection generation rejected; NULL replay position rejected; permissions and unexpected row counts rejected; reconnect cannot retain a previous identity. Assert `ok(!probe.finish(), "partial probe cannot certify progress")` at every incomplete stage. Verify writer query uses insertion position and replica query uses replay position; numeric position from `IDENTIFY_SYSTEM` never supplies replay progress.
- [x] **Run `make -C test/tap/tests/unit pgsql_lsn_probe_unit-t` and the resulting binary.** Record missing-state/validation failures before implementation.
- [x] **Implement probe parsing and role-specific SQL.** Normalize postmaster start using `(EXTRACT(EPOCH FROM pg_catalog.pg_postmaster_start_time()) * 1000000)::bigint`, avoiding DateStyle/timezone ambiguity. Establish the expected history from the initial identity response. On subsequent probes use the previous successful identity as the first check, then SQL and final identity. A mismatch invokes endpoint/group invalidation and requires a fresh handshake.
- [x] **Add a separate monitor task and dedicated connection pool with `replication=database`.** Reuse credentials, TLS, DNS and existing connection/query timeout settings. Seal writer batches before dispatching their position query. One outstanding probe per endpoint; SQL plus final identity share one query deadline. Keep the initial identity handshake bounded as well. A failed writer sample retains its sealed batch for retry; stale attempt replies cannot complete it.
- [x] **Schedule from enabled pair membership and live dependency demand.** Do not use the replication-lag task's `max_replication_lag > 0` filter. Poll even before a session's next read, stop when demand is satisfied/released, coalesce missed ticks, and invalidate certification on monitoring disable or reconnect. Publish a changed revision and coalesced worker wakeup after locks are released. Test a fake monotonic clock for cadence, no backlog, interval updates, failure retry and idle backoff.
- [x] **Run manager and probe targets.** Expected: all pass; no networking on the worker path; monitor error states leave unavailable certification. Live credentials/restart and permission cases run in Task 7.
- [x] **Commit the task paths:** `feat(pgsql): monitor certified WAL positions`.

## Task 4: Track real application completions on validated backends

**Files:** Modify `include/PgSQL_Connection.h`, `include/PgSQL_Session.h`, `lib/PgSQL_Connection.cpp`, `lib/PgSQL_Protocol.cpp`, `lib/PgSQL_Session.cpp`; create `test/tap/tests/unit/pgsql_lsn_completion_unit-t.cpp`; modify `test/tap/tests/unit/Makefile`.

**Interfaces:** Add an optional `pgsql_lsn::ServerToken` stamp to each backend connection. Add `int PgSQL_Connection::async_validate_lsn_incarnation(short revents)` using existing asynchronous return conventions. Add `void PgSQL_Session::lsn_on_idle_boundary(const PgSQL_Connection&)`; consume `observe_completion(source, previous)` and maintain `std::unordered_map<pgsql_lsn::GroupId, pgsql_lsn::Dependency>` on the frontend. Track application-cycle serial and origin separately from raw ReadyForQuery status.

- [x] **Write completion tests feeding real response handlers.** Assert one enrollment before idle completion becomes client-visible for libpq and native paths, including suppressed native `Z`. Assert no enrollment for internal setup/probes, duplicate status updates, active/failed transactions, Execute or Flush before Sync. Assert retained dependencies on rollback, `DISCARD ALL`, backend release/reuse and error recovery. Include a multi-statement cycle with an earlier commit and a later error. Test hidden bootstrap messages never enter client output.
- [x] **Run the new completion target and observe the missing enrollment/ordering failures.** Reuse packet builders and connection fixtures from `pgsql_command_complete_unit-t.cpp` and response-framer tests, not a parallel model of the new code.
- [x] **Implement one-time asynchronous backend bootstrap before protected use.** Match endpoint postmaster start and recovery role to the monitor's validated incarnation; require an uninterrupted connection and current group generation. Store the stamp only after successful verification. Reconnect/reset of the physical socket clears it; an ordinary SQL pool reset cannot clear frontend dependencies. A bootstrap mismatch withholds eligibility and triggers endpoint revalidation.
- [x] **Normalize actual idle boundaries in both result paths before output release.** Hook libpq completion before `add_ready_status()` can expose idle; hook native ReadyForQuery before copying/flushing it to client buffers, including paths suppressing that packet. Conservatively enroll every application cycle returning to idle on the writer. Keep COPY, procedures with transaction control, COMMIT PREPARED and Sync error recovery covered by the same cycle boundary. Unknown commit outcome preserves existing error behavior, invalidates the affected dependency if the frontend survives, and never authorizes a write retry.
- [x] **Run completion and existing command-complete, response-framer and named-portal teardown unit targets.** Expected: new enrollment assertions and existing protocol lifecycle assertions pass. Tests verify the boundary hook order, not just final dependency state.
- [x] **Commit the task paths:** `feat(pgsql): capture writer completion dependencies`.

## Task 5: Gate snapshots and pool selection with cancellable LSN waits

**Files:** Create `include/PgSQL_LSN_Waiter_List.h`, `test/tap/tests/unit/pgsql_lsn_admission_unit-t.cpp`; modify `include/PgSQL_Session.h`, `include/PgSQL_Thread.h`, `include/PgSQL_HostGroups_Manager.h`, `lib/PgSQL_Session.cpp`, `lib/PgSQL_Thread.cpp`, `lib/PgSQL_HostGroups_Manager.cpp`, `test/tap/tests/unit/worker_waiter_unit-t.cpp`, `test/tap/tests/unit/Makefile`.

**Interfaces:** Define `enum class LsnAdmission { Proceed, Wait, UseWriter, Error }` and session methods `LsnAdmission lsn_admit(uint32_t destination_hostgroup, pgsql_lsn::Micros now_us)` and `bool lsn_backend_allowed(const PgSQL_Connection&) const`. A request stores selected group/policy, fixed deadline, fallback-issued flag, cached immutable `DependencyView`, and worker-owned wait node. Worker methods `void lsn_waiter_enter(PgSQL_Session*)`, `void lsn_waiter_leave(PgSQL_Session*)`, `void process_lsn_waiters(pgsql_lsn::Micros now_us)` own registration and lifecycle. Hostgroup/local-pool selection receives the same immutable eligibility context, including backend identity, instead of using the dormant PostgreSQL GTID-shaped arguments.

- [ ] **Write admission and worker lifecycle tests.** Assert waiting through unresolved batches; fixed resolved target; all pool paths reject a lagging or mismatched replica; timeout zero immediately chooses a valid writer; elapsed retries never renew the deadline; one fallback maximum. Use an injected monotonic clock, for example `ok(deadline_after_retry == deadline_at_entry, "single causal deadline")`. Exercise notification-before-register, notification-after-register, cancel, disconnect, group removal and shutdown. Verify `ok(waiter_count == 0, "teardown unlinks waiter")` and bounded handle counts. An unready LSN waiter must not block ready requests or ordinary pool waiters.
- [ ] **Run admission and worker-waiter targets; record expected missing-gate/lifecycle failures.** Add direct tests of actual local and shared pool checkout, attached backend reuse and new-connection paths, not only the pure predicate.
- [ ] **Move effective-group resolution before cache lookup and gate before snapshot acquisition.** Apply to simple and extended paths, including Parse/Bind as necessary before any snapshot-taking operation, not merely Execute. Carry the immutable eligibility context through primary/backup server weighting, connection creation and local/shared checkout. Recheck current generation and backend stamp immediately before dispatch. Bootstrap unvalidated connections asynchronously using Task 4.
- [ ] **Implement per-request waits and deadline behavior.** Use a separate intrusive LSN waiter list, preserving vanilla pool waiter order. Register then recheck revision to prevent lost wakeups. Worker poll timers honor the earlier existing request deadline; notifications are coalesced. Cancellation unlinks only that request. After the causal deadline, route once to the validated originating writer subject to ordinary routing/health/connection rules and normal query timeouts. Unknown history or no safe route gives `55000` with `LSN_HISTORY_CHANGED`, `LSN_TRACKING_NOT_INITIALIZED`, or `LSN_NO_SAFE_BACKEND` as applicable.
- [ ] **Preserve transaction and session semantics.** Pin an active transaction, unsynchronized extended cycle, COMMIT AND CHAIN and live portal to its backend even when ordinary transaction persistence is disabled. Do not move an existing snapshot. Reject incompatible session affinity. Compare session creation/activation epochs before using a newly enabled pair; conservative reconnect-required error is acceptable for all pre-existing sessions. Disabling applies to new requests, while in-flight waiters retain their captured policy. Reject fast-forward routing to readers in enabled pairs and keep writer fast-forward affinity.
- [ ] **Bypass both query-cache lookup and insertion for any pending/resolved dependency.** Include simple and extended cache paths; clean sessions retain existing behavior. Test stale preseeded entries, multiplexed clients with different dependencies, old attached connections, activation and disable-during-wait.
- [ ] **Run the new tests plus waiter-list, worker-waiter and query-cache allocation regressions.** Expected: all pass with no blocked worker, restarted deadline, stale session pointer or cache admission bypass.
- [ ] **Commit the task paths:** `feat(pgsql): enforce causal LSN admission and waits`.

## Task 6: Expose diagnostics and document operations

**Files:** Modify `include/ProxySQL_Admin_Tables_Definitions.h`, `include/proxysql_admin.h`, `lib/ProxySQL_Admin.cpp`, `lib/ProxySQL_Admin_Stats.cpp`, `lib/PgSQL_HostGroups_Manager.cpp`, `lib/PgSQL_Thread.cpp`, `lib/PgSQL_Session.cpp`; create `docs/pgsql-lsn-causal-reads.md`; extend `test/tap/tests/unit/pgsql_lsn_config_unit-t.cpp`.

**Interfaces:** Consume manager snapshots and worker/session state; add the admin table `stats_pgsql_lsn` and fields to existing session diagnostics. Publish one row per group/endpoint with writer/reader hostgroups, hostname/port, role, generation, system identifier, timeline, postmaster start, insert/replay LSN, validity, sample age, duration and error. Store unsigned identifiers and LSNs as lossless text at the SQLite boundary; absent progress is SQL NULL.

- [ ] **Write export assertions** for unknown vs zero LSN, `UINT64_MAX`, invalidation, age/duration and error clearing. Assert diagnostics contain required LSN, pending batch ID, generation and wait state. Counters must distinguish covered completions, writer batches, successful/failed probes, replica reads, writer fallback, wait timeout, cancellation and history errors; expose waiter count and cumulative wait time.
- [ ] **Run the config target to observe missing-schema/export failures.** Include the actual stats materialization path in the fixture.
- [ ] **Implement current-state export and counters.** Snapshot under short locks, materialize SQLite rows outside manager locks, and avoid an SQLite write for every successful probe. Bound error/history storage using existing policy. Do not make LSNs, session identifiers or batch IDs Prometheus labels.
- [ ] **Write the operator document.** Include exact activation/knob SQL, monitor permissions and WAL sender capacity, one-writer/direct-endpoint requirements, zero-timeout behavior, cache bypass, existing-session activation error, timeline/restart behavior and mixed-version sync refusal. At 10 ms, explain the ceiling of 100 probes/~200 commands per continuously polled server per proxy; demand/backpressure can lower it. State that this is per-frontend read-your-writes, and reconnect does not certify lost writes survived failover.
- [ ] **Run config/export tests and `git diff --check`; commit:** `feat(pgsql): expose LSN routing diagnostics`.

## Task 7: Prove the guarantee with isolated live replication tests

**Files:** Create `test/infra/infra-pgsql17-lsn/` using the existing `infra-pgsql17-repl` structure: `docker-compose.yml`, `docker-compose-init.bash`, `docker-compose-destroy.bash`, `bin/docker-wait-pgsql.bash`, `bin/docker-pgsql-post.bash`, `bin/docker-proxy-post.bash`, `conf/proxysql/infra-config.sql`, `conf/pgsql/pgsql1/postgresql.conf`, `conf/pgsql/pgsql1/pg_hba.conf`, `conf/pgsql/pgsql1/init-replication.sh`, and `postgresql.conf`/`pg_hba.conf` for `pgsql2` and `pgsql3`. Reuse existing test TLS material explicitly or generate it inside the isolated fixture; do not add production secrets. Create `test/tap/groups/pgsql-lsn/{env.sh,infras.lst,pre-proxysql.bash}`, `test/tap/tests/pgsql-lsn_causal_reads-t.cpp`, `test/tap/tests/pgsql-lsn_lifecycle-t.cpp`, `test/tap/tests/pgsql-lsn_admin-t.cpp`; modify `test/tap/groups/groups.json` and test Makefiles where explicit registration is needed.

**Interfaces:** Tests use libpq, `CommandLine`, existing TAP/admin helpers and SQL-visible stats. The fixture exports three distinct stable endpoints with one writer and two physical replicas, suitable replication and deliberately restricted monitor roles, and `max_prepared_transactions` enabled. The admin test launches a supporting peer from the feature binary with its own datadir and dynamically allocated listeners; a legacy-shaped peer is exercised through a local admin-protocol test server returning the old projection/unknown-column error. Neither is the replication cluster simulator. Lifecycle tests run on a fresh fixture after ordinary causal/admin tests; no destructive failover shares state with another test process.

- [ ] **Write the live TAP assertions and fixture first.** Use unique rows plus backend address/port to identify the actual server. Pause replay while confirming WAL reception advances and replay does not. Assertions include `ok(returned_value == committed_value, "read follows acknowledged write")` and `ok(selected_port != paused_replica_port, "unreplayed replica excluded")`. Test alternate eligible replica, catch-up wakeup, timeout/zero-timeout writer fallback, fixed target under continuous unrelated writes and pool exhaustion.
- [ ] **Add protocol and application cases:** async commit, writing SELECT function, earlier commit followed by error, rollback/savepoint, COPY, transaction-control procedure, COMMIT AND CHAIN, PREPARE/COMMIT PREPARED, repeatable read, named portals, pipeline Flush/Sync/error recovery. Run supported cases with native mode both off and on, recycling pools after each toggle because the mode is latched on connection creation. Verify preseeded stale cache and local-pool paths cannot return stale rows; independent frontends do not share dependencies.
- [ ] **Add lifecycle/configuration cases:** cancellation/disconnect, monitor pause/retry, missing REPLICATION permission, backend bootstrap mismatch, replica restart on the same endpoint, writer restart/promotion with higher numeric wrong-history LSN, stale generation replies via the unit seam, weight-only reload, ambiguous mapping, activation on old sessions, disable during waits, flag/variables LOAD/SAVE/import/export, old database migration and cluster sync to both a supporting peer and a legacy-shaped peer. Preserve prior config on incompatible sync. Finish destructive topology cases last and recreate the fixture before another protocol variant.
- [ ] **Run tests first against the pre-feature binary to establish failure.** Use a separately built baseline binary and the isolated fixture; no builds in the original checkout. It must reject the new config/stats or fail the intended assertions, never accidentally report success by skipping them.
- [ ] **Run the feature build and suite:**

  ```bash
  PROXYSQL31=1 make debug
  WORKSPACE="$PWD" RUN_ID="pgsql-lsn-validation" TAP_GROUPS="pgsql-lsn-g1" ./test/infra/control/run-multi-group.bash
  ```

  Register `pgsql-lsn-g1` consistently with the runner's base-directory/shard convention. Use the existing orchestrator for per-run networks, proxy datadirs and cleanup; no shared fixed host ports. Every pause/reconfiguration has scoped cleanup, including failures. Use bounded condition polling rather than sleeps as evidence. Expected: all new assertions pass on both supported backend paths and cleanup leaves no waiters/references or paused shared servers.
- [ ] **Fix production failures in the owning component and rerun affected tests.** Do not weaken identity checks, skip a failed scenario, or replace replay with receive/flush position to make tests pass.
- [ ] **Commit infrastructure and tests plus fixes:** `test(pgsql): validate causal LSN routing end to end`.

## Task 8: Validate resource bounds and prepare the branch for review

**Files:** Create `test/tap/tests/pgsql-lsn_benchmark.cpp` as an explicitly invoked benchmark, and `docs/pgsql-lsn-causal-reads-validation.md`; modify `test/tap/tests/Makefile` only to add its explicit build target. Keep the benchmark out of default TAP groups.

**Interfaces:** Use public SQL/admin diagnostics and the isolated Task 7 fixture. Benchmark inputs are poll interval (1/10/100 ms), client count and duration; output CSV includes commit and first-read latency percentiles, probe command rate, completions/batch, worker CPU, waiter count/memory and idle probe rate. Record machine/build configuration and actual commands with results.

- [ ] **Run all new unit targets and the affected existing PostgreSQL protocol/cache/waiter targets.** Repeat the original 5 build-system checks. Build without `PROXYSQL31` in a separate disposable build worktree if necessary to verify compile guards; never reuse incompatible object files. Run ASan/UBSan on cancellation, connection loss, portal teardown and monitor shutdown paths, and a supported thread-sanitized pure-manager stress test for enrollment/publication races.
- [ ] **Run live acceptance tests with release and debug builds.** Record exact command, backend mode, TAP counts and exit status. Any unavailable environment or unsupported sanitizer must be reported explicitly, not counted as passing. A missing required correctness run blocks a claim that the feature is validated.
- [ ] **Measure disabled baseline and enabled 1/10/100 ms cases.** Keep data, concurrency and workload constant, include sustained unrelated writes and a paused replica, then disconnect clients to measure idle backoff. Assert no more than one active probe/endpoint, no accumulated overdue probes, two unresolved batches/group maximum, and no growing waiter/reference count after teardown. With identical sustained demand, more completions must increase batching rather than add a per-commit query. Report commit latency separately from first-read wait; defaults remain 10/100 unless measured evidence justifies a separately reviewed design change.
- [ ] **Write measured results and limitations in the validation document.** No invented throughput targets; correctness and bounds above are mandatory, while latency/CPU observations inform future tuning. Distinguish actual test evidence from expected behavior.
- [ ] **Run `git diff --check`, inspect the complete branch diff, and obtain the selected execution workflow's final code review.** Resolve material review findings and rerun affected checks before marking implementation complete.
- [ ] **Commit validation artifacts:** `docs(pgsql): record LSN causal read validation`. Verify `git branch --contains dac3d99fa` and the final feature commit still exclude `v3.0`; leave the worktree/branch available for review. Do not merge or publish without the user's instruction.

## Plan coverage and handoff

Tasks 1–3 establish ordered dependencies, configuration and certification; Task 4 makes completion capture precede client acknowledgement; Task 5 enforces the guarantee across snapshots, caches and all pool paths; Tasks 6–8 supply observability, adversarial system tests and measured bounds. The spec's eleven acceptance categories are covered by Task 1 ordering tests, Tasks 3–5 component tests and the Task 7/8 live matrix.

Implementation is in progress on the dedicated feature branch; checked steps have execution evidence in the task ledger. The interfaces are tightly coupled across monitor, protocol and routing; native execution in this session with a final independent branch review is the suggested approach. Subagent-per-task implementation and review is the alternative if that review cadence is preferred.
