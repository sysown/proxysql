# Execution, lifecycle, and extension architecture: source evidence

Investigation date: 2026-10-18. Scope: the checked-out `docs/invariants-expansion`
branch. These are verified implementation findings and candidate architectural
interpretations, not newly ratified product contracts. Line references describe this
revision; inspect the named function when lines move. No runtime behavior was tested.

## Execution boundaries that matter

ProxySQL's four logical areas do not correspond to four processes. The serving
process hosts protocol workers, shared services, administrative execution, monitoring,
and peer configuration synchronization. Supervision is a separate process concern.

| Execution context | Verified responsibility and boundary | Evidence |
| --- | --- | --- |
| Optional angel process | In daemon mode with restart-on-error enabled, forks and waits for the serving child; restarts after nonzero exit or signal termination, with a budget/backoff for rapid crashes. A successful child exit terminates the angel. It does not route queries or synchronize configuration. | `src/main.cpp:2250` (`ProxySQL_daemonize_phase3`), `:2669` (`handleProcessRestart`), `:3417` (daemon/foreground selection) |
| Serving main thread | Constructs runtime, starts services, then runs the watchdog checking worker heartbeats; conducts shutdown and optional in-process reload. Watchdog and angel are different mechanisms in different execution contexts. | `src/main.cpp:2834` (`watchdog_main_loop`), `:3457` (restart label through shutdown/reload) |
| MySQL and PostgreSQL workers | Each entry point allocates its own protocol thread object, initializes it, waits on the common startup counter, then enters the event loop. Sessions are processed by these worker loops, rather than a dedicated OS thread per traffic client. | `src/main.cpp:554` and `:631`; `lib/MySQL_Thread.cpp:4250`, `:4361`, `:4496`; `lib/PgSQL_Thread.cpp:3311`, `:3461`, `:3636` |
| Optional idle workers | Protocol-specific idle workers are separate execution contexts, conditional on build/runtime configuration. They access peer worker objects, making destruction a group lifetime problem. | `src/main.cpp:593` and `:670` |
| Admin listener and Admin clients | The Admin accept loop also performs scheduler/statistics work. Accepted Admin connections spawn threads. Shutdown joins the listener and waits for the count of active client threads to reach zero before deleting database handles. Admin execution is not serialized merely by being in a single Admin thread. | `lib/ProxySQL_Admin.cpp:2675`, `:2737`, `:3417`, `:3445` |
| Shared hostgroup manager background tasks | MySQL HGM starts its own connection-update worker and GTID syncer; those have lifetimes separate from traffic workers. | `lib/MySQL_HostGroups_Manager.cpp:952` (`init`), `:964` (`shutdown`) |
| Monitoring and cache maintenance | Monitor objects exist even when their schedulers are not enabled; monitor threads are enabled separately. Both protocol query caches share one purge thread. | `src/main.cpp:1143` (cache construction), `:1150` (purge-thread creation), `:1828` (monitor construction), `:1951` and `:1959` (monitor enable gates) |
| Optional plugin activity | Plugins can launch threads/accept loops in their lifecycle; their resources must be drained while the core services they use still exist. | `include/ProxySQL_Plugin.h:581`, `:600`; `src/main.cpp:2018` |

**A correction to existing introductory guidance:** traffic workers are event-driven,
but the inspected ordinary worker paths call `poll()`, with conditional `epoll` paths
for idle handling. Describing all traffic execution as “using libev” is inaccurate.
Other services, including the MySQL GTID syncer, do use libev. The architecture should
specify event-driven execution without prescribing one event library for all contexts.

## Shared managers and worker-local views are separate

The runtime is neither a set of independent workers nor one globally locked state
machine. Protocol thread handlers and HGMs are shared services; worker objects and
session processing are local execution machinery. Workers periodically detect a global
variable-version change and refresh their local variables. The MySQL loop separately
tracks the HGM servers-table version. This establishes **component-specific propagation**,
not an all-components-at-once reconfiguration boundary.

Evidence: `lib/MySQL_Thread.cpp:4397`, `:4438`, `:5382`;
`lib/PgSQL_Thread.cpp:3548`, `:4354`. A separate investigation must map each kind of
configuration publication; these observations do not prove a universal snapshot model.

Architectural implication to review with the maintainer: shared configuration owners
publish changes through the relevant component's existing mechanism. A consumer's
need to observe a change does not itself justify directly sharing every producer's
mutable object or taking an unrelated global lock.

## Lifecycle is several readiness boundaries, not one initialized flag

The actual startup is orchestration in `src/main.cpp`. Construction, configuration
application, callback availability, acceptance of Admin work, and acceptance of traffic
occur at different points. Existence of a non-null global object is not proof all its
services are ready.

| Observed transition | What is established | What it does not establish |
| --- | --- | --- |
| Phase 2 constructs main modules | HGMs and thread-handler objects exist; loggers and statement managers exist. | Workers and all service methods are not necessarily ready. |
| Admin bootstrap | Core and declared plugin schemas materialized; Admin execution infrastructure exists. Auth is constructed afterward in the observed sequence. | Traffic listeners are not serving; plugin lifecycle may still be pending. |
| Phase 3 initializes runtime services | Server configuration applied; query processors, protocol thread handlers/workers and query caches initialized. Workers pass their construction barrier. | Public listener startup has not yet happened. |
| Plugin lifecycle finishes (v4.0) | Full-service plugin initialization/start and runtime-ready callbacks complete; local plugin-set hash published; startup gate opens. | Core traffic listeners are started separately afterward. |
| Protocol listener startup | MySQL then PostgreSQL listeners are started. | Later optional services and HTTP startup still follow. |
| Remaining services startup | Monitoring and optional servers started; HTTP/REST initialized; Admin's `all_modules_started` marked true and remaining HTTP config loaded. | This flag must not be conflated with every other readiness boundary. |

Sources: `src/main.cpp:1003`, `:1048`, `:1678`, `:1749`, `:1807`,
`:1866`, `:1925`, `:1949`, `:1999`.

This table records actual order. It does **not** prove that every adjacent pair is a
necessary dependency, nor ratify the entire sequence as intended architecture.

### Dependencies with explicit justification

1. **Plugin schema declarations precede Admin schema materialization.** Persistent
   plugin tables must be known when Admin restores/builds its schema. Database handles
   are unavailable during schema declaration; full-service initialization is later.
   (`include/ProxySQL_Plugin.h:598`, `:626`; `src/main.cpp:1699`.)
2. **Full-service plugin callbacks follow initialization of the services they borrow.**
   Early actions can use the completed runtime services but exit before traffic is
   served; plugin publication does not open/close listeners.
   (`src/main.cpp:1880`.)
3. **Admin commands and peer configuration synchronization must not overlap v4.0
   plugin lifecycle mutation.** Lifecycle callbacks hold plugin-manager exclusivity
   and may call Admin/HGM; ordinary Admin and peer paths can acquire those locks in
   the opposite order. The startup gate handles this explicit concurrency dependency.
   It has distinct prestart-open, closed, and open states: `--no-start` intentionally
   permits Admin configuration while peer runtime activity waits.
   (`include/ProxySQL_StartupGate.h:4`; `src/main.cpp:1713`, `:1921`.)
4. **Traffic workers register before their startup gate releases.** Shutdown needs a
   complete participant count. All worker/idle run loops leave before any of their
   shared-accessed thread objects are destroyed.
   (`src/main.cpp:569`, `:581`, `:646`, `:658`.)
5. **Stop admission and drain users before destroying borrowed services.** Phase 4
   drains Admin clients, unloads plugins while dependencies exist, then joins runtime
   background activity and destroys modules. MySQL HGM's connection-update thread
   must stop before the thread-handler object it reads is freed. Passthrough-auth
   cache must outlive workers that can be executing an authentication probe.
   (`src/main.cpp:2018`, `:1365`, `:1387`; `lib/ProxySQL_Admin.cpp:3417`.)

### Plugin retirement is not equivalent to stopping traffic workers

Phase 4 unloads plugins **before** joining traffic workers. The manager retirement
path first disables public readiness/query-hook flags, then takes the active-manager
exclusive lock and unpublishes its pointer, then stops plugins in reverse order and
resets the manager. Borrowers using `ScopedActiveManagerPin` hold the corresponding
shared lock across their call. This is an explicit admission/draining mechanism, not
proof that all workers have already stopped. It also does not prove that every other
provider's borrowed lifetime uses that same pin: provider leases must be traced through
their own owners. (`lib/ProxySQL_PluginManager.cpp:104`, `:1152`, `:2441`.)

`runtime_ready` failure is currently logged as degraded readiness and listener startup
continues (`src/main.cpp:1647`). A callback named “ready” therefore must not be treated
as a universal successful-readiness guarantee. If plugin/web draining fails, core
teardown is abandoned via `_Exit` rather than destroying potentially borrowed services
(`src/main.cpp:1662`). These are verified failure policies, not newly recommended ones.

### Lifecycle failure paths are part of the model

A startup failure can occur after worker creation but before listener startup.
Workers' listener-bootstrap wait does not itself inspect shutdown. Phase 4 therefore
clears bootstrap waits before joining, without opening listeners (`src/main.cpp:2026`;
`lib/MySQL_Thread.cpp:4181`). The important architectural issue is **cancellation of
partially established lifecycle stages**, not merely one more init-order patch.

Likewise, startup conflicts intentionally exit successfully before plugin startup so
the angel does not endlessly restart an invalid listener configuration
(`src/main.cpp:1756`). Exit status is therefore part of the supervision contract.

`PROXYSQL RESTART` and STOP/START also reuse the process: shutdown tears down modules,
then `glovars.reload` returns to phase 2 (`src/main.cpp:3497`). Any startup-only registry,
service pointer, or borrowed provider must therefore be classified as process-lifetime
or runtime-generation-lifetime. A first-boot-only assumption is insufficient.

## Extensions and tiers: evidence rather than imagined hooks

The plugin chassis is compiled under `PROXYSQL40`; v3.0/v3.1 startup does not contain
that loader lifecycle (`src/main.cpp:1699`). Feature flags define which architecture
exists in a binary; “optional” does not necessarily mean present but disabled.

The current descriptor exposes schema declaration, early actions, initialization,
start, runtime-ready, and stop, in addition to CLI registration. Its header calls this
a six-phase lifecycle while older comments in `main.cpp` still say four-phase. Use the
actual named transitions instead of a phase count in the architecture.

The crucial teardown rule is explicit: **stop pairs with successful init, not successful
start**. A plugin that initialized successfully receives one stop even when start or a
later startup stage fails; an unsuccessful init does not receive stop
(`include/ProxySQL_Plugin.h:581`). This is a useful lifecycle contract independent of
implementation order.

Real examples of supported consumers:

- mysqlx registers Admin/config/runtime tables and commands
  (`plugins/mysqlx/src/mysqlx_admin_schema.cpp:395`, `:472`).
- mysql_router registers its own configuration tables and commands and has a
  runtime-ready callback (`plugins/mysql_router/src/admin_schema.cpp:180`, `:213`;
  `plugins/mysql_router/src/plugin.cpp:121`, `:237`).
- genai registers query hooks for both protocols and declares its own schemas
  (`plugins/genai/src/plugin_main.cpp:295`, `:367`).

These plugin-owned tables are distinct from the removed **server-module table**
mechanism. Do not infer that “no plugin registered server-module tables” means plugins
register no tables of any kind.

## Recent history that explains architectural boundaries

- `4e957ac3f` (2026-10-14), **remove the unused server-module machinery**: removed
  server-module registry, hostgroup claims, Cluster endpoints, snapshots, checksum
  folding and Admin failure paths because no shipped plugin used that facility.
  An ABI slot remains as a rejecting compatibility stub. Its presence is not evidence
  of a supported extension mechanism. This removes 1,495 lines across 22 files.
- `d304468f5`, **rediscover plugins on reload**: runtime teardown destroys the manager;
  reload must reconstruct discovery rather than rely on first-boot objects.
- `b56cf3996`, **release worker bootstrap waits before joining on every tier**:
  establishes the partial-start failure-path issue described above.
- `a06b5c2fa` (2026-10-12), **exit with code 0 on listener conflict before plugin init**:
  ties validation timing and exit semantics to supervision behavior (#6414).

## Architecture decisions still requiring maintainer intent

Verified order alone cannot answer whether plugin startup should require the current
wide shared-service surface, whether all execution contexts have intentionally chosen
readiness gates, or which currently reachable cross-module global accesses are accepted
coupling versus debt. Those should be explicit review questions, with the evidence above,
rather than silently converted into new architecture rules. No new global barrier,
universal lock, or service registry is proposed by this investigation.
