# Native TCP proxy plugin

Date: 2026-11-11. Status: implementation authorized by the user after the detailed design. The user selected the native approach and requested subagents with most implementation, test, and benchmark work delegated to OpenCode using DeepSeek v4.1 Flash. No additional design-approval pause is required. No commits, pushes, or deployment are requested.

## Intent and approaches

Provide opaque TCP forwarding selected by listening address/port, configurable entirely through ProxySQL Admin. Users can add/remove backends, change balancing and network routing policies, inspect health/statistics, and persist configuration without another control plane.

The user selected a native C++ plugin over a plugin supervising HAProxy. Native forwarding gives one process, direct runtime ownership, and the usual Admin configuration model, at the cost of building and validating the relay. Embedding HAProxy was rejected because adapting its process/thread/lifecycle assumptions creates a much larger coupling. The adjacent HAProxy checkout is reference material and an optional benchmark comparator, not a linked dependency.

## Scope and constraints

* Build only with `PROXYSQL40=1`; use the same C++ toolchain/build tier as core. Linux is the initial supported data-plane platform; unsupported platforms receive an explicit build/runtime diagnostic, never a silent fallback.
* Plugin name `tcp_proxy`; artifact `plugins/tcp_proxy/proxysql_tcp_proxy.so`; entry point `proxysql_plugin_descriptor_v1`.
* IPv4 and IPv6 TCP, byte-transparent TLS passthrough, one backend connection per client connection. Numeric IPv4/IPv6 listener and backend addresses only in this first version. The conventional `hostname` column stores an address. DNS support is deferred until a cancellable bounded resolver is designed; libc getaddrinfo on an Admin callback would violate bounded shutdown.
* Weighted round-robin and weighted least-connections; primary/backup servers; network routing rules; active TCP-connect health checking; dynamic listener/backend changes; draining and immediate administrative disconnect; bounded resources; Admin/runtime/statistics views and existing Prometheus endpoint.
* Exclude UDP, TLS termination, payload/SNI/SQL routing, PROXY protocol, transparent source spoofing, protocol authentication, application health scripts, backend pooling, queued excess connections, automatic Cluster replication, DNS backend names, and zero-copy optimizations in this version. Backend peers see ProxySQL's source address. These are explicit version boundaries, not stub APIs.
* No network I/O, SQL, DNS, logging callbacks, or worker joins while holding a data-plane global lock. No SQL or DNS on connection workers. Admin callbacks must release Admin's global mutex before waiting for control-plane work and reacquire before returning.
* Preserve unrelated files and existing work; workers must not commit, push, create branches, install dependencies globally, read credentials, or operate production endpoints.

## Configuration contract

Five editable tables have identical persistent `config_db` twins registered in `register_schemas()`. Runtime tables prefix the editable name with `runtime_`. Values below are authoritative; bounds are checked both by schema and compiler when practical. All IDs are nonnegative signed 32-bit integers; ports are 1..65535. All tables except settings include `comment TEXT NOT NULL DEFAULT ''`.

`tcp_settings` has exactly one default row, `id=1`:

| Column | Default | Bounds/meaning |
|---|---:|---|
| `id` | 1 | PRIMARY KEY, CHECK(id=1) |
| `worker_threads` | 2 | 1..64; startup-only after workers run |
| `max_connections` | 10000 | 1..1000000; all listeners, including pending connects |
| `buffer_size` | 16384 | 1024..1048576 bytes per direction; startup-only |
| `shutdown_timeout_ms` | 5000 | 0..60000; stop draining deadline |
| `half_close_timeout_ms` | 30000 | 1..3600000; completion after first EOF |

`tcp_hostgroups`:

| Column | Default | Meaning |
|---|---|---|
| `hostgroup_id` | required | PRIMARY KEY, independent of MySQL/PgSQL hostgroups |
| `balance` | `roundrobin` | `roundrobin` or `leastconn` |
| `health_check_interval_ms` | 1000 | 0 disables checks; otherwise 100..3600000 |
| `health_check_timeout_ms` | 500 | 1..60000 |
| `health_check_rise` | 2 | 1..100 consecutive successful checks |
| `health_check_fall` | 3 | 1..100 consecutive failed checks |

`tcp_servers`:

| Column | Default | Meaning |
|---|---|---|
| `server_id` | required | PRIMARY KEY; stable administrative identity |
| `hostgroup_id` | required | Must reference a configured hostgroup |
| `hostname` | required | Numeric IPv4/IPv6 address only, no embedded NUL |
| `port` | required | Backend TCP port |
| `status` | `ONLINE` | `ONLINE`, `OFFLINE_SOFT`, `OFFLINE_HARD` |
| `weight` | 1 | 1..1000 |
| `max_connections` | 1000 | 1..1000000, across all workers |
| `backup` | 0 | 0 or 1 |

`tcp_listeners`:

| Column | Default | Meaning |
|---|---|---|
| `listener_id` | required | PRIMARY KEY; stable capacity/statistics identity |
| `active` | 1 | 0 or 1 |
| `bind_address` | `0.0.0.0` | Numeric IPv4/IPv6; IPv6 sockets explicitly IPV6_V6ONLY |
| `bind_port` | required | Listening TCP port |
| `default_hostgroup` | required | Must reference a configured hostgroup |
| `max_connections` | 10000 | 1..1000000 |
| `connect_timeout_ms` | 2000 | 1..60000; total connection-establishment budget |
| `idle_timeout_ms` | 60000 | 0 disables; otherwise 1..86400000 |
| `max_connect_attempts` | 3 | 1..16; failed connects only |

`tcp_routing_rules`:

| Column | Default | Meaning |
|---|---|---|
| `rule_id` | required | PRIMARY KEY; ascending order, first match wins |
| `active` | 1 | 0 or 1 |
| `listener_id` | NULL | NULL matches every listener; otherwise valid listener reference |
| `source_cidr` | NULL | NULL matches every source; otherwise canonical IPv4/IPv6 CIDR |
| `action` | `ROUTE` | `ROUTE` or `REJECT` |
| `destination_hostgroup` | NULL | Required for ROUTE; NULL for REJECT |

Rule matching uses the actual socket peer address, never untrusted application metadata. No matching rule means the listener's default hostgroup. A matching REJECT closes without protocol-specific reply. A healthy empty hostgroup is legal: it rejects new connections rather than falling back elsewhere. Reject dangling references even in inactive rows so activation is deterministic. Reject overlapping active listeners, including duplicates inside this plugin. Reject IPv4-mapped IPv6 bind/CIDR spellings unless normalized consistently; simplest initial implementation rejects those spellings with a clear error.

## Admin commands and persistence

Canonical exact commands:

* `LOAD TCP CONFIG TO RUNTIME`: all five tables, one activation.
* `SAVE TCP CONFIG FROM RUNTIME`: replace all five editable tables with the effective runtime configuration; no health/counter persistence.
* `LOAD TCP CONFIG FROM DISK`: replace all five editable tables transactionally; no implicit activation.
* `SAVE TCP CONFIG TO DISK`: persist all five editable tables transactionally; no implicit activation.

Register conventional aliases `LOAD TCP CONFIG FROM MEMORY`, `SAVE TCP CONFIG TO MEMORY`, `LOAD TCP CONFIG TO MEMORY`, and `SAVE TCP CONFIG FROM MEMORY` for the corresponding canonical operation. Do not expose per-table LOAD commands that could create mixed policy/server generations. SQL DML affects editable memory only. Saving to disk may intentionally persist a configuration not yet active; startup validates it before serving.

Default startup with no TCP configuration succeeds with zero listeners. Settings defaults are inserted only if absent. Invalid persisted configuration fails the plugin startup without opening its listeners; do not overwrite persisted rows. Core's existing configured-plugin failure policy remains authoritative. No-start exposes registered schema but does not create relay workers/listeners; plugin command availability follows existing chassis behavior. STOP/START and RESTART must leave no plugin threads/fds behind and restore disk configuration in the normal chassis sequence.

Runtime projections have the editable columns plus a `generation` column; SAVE uses explicit column lists. `runtime_tcp_status` provides state, generation, last activation error, and active/retired connections. Statistics tables in stats DB: `stats_tcp_listeners`, `stats_tcp_servers`, `stats_tcp_rules`; include IDs, active connections, accepted/selected totals, rejects, connect errors, byte counters, administrative/health status as appropriate. Keep useful rows for retired identities while their sessions drain; snapshots clearly identify retired rows. Runtime tables represent the actual configuration, never unactivated SQL edits.

## Runtime interfaces and ownership

Plugin-independent engine code lives under `plugins/tcp_proxy/include` and `src`, with no ProxySQL globals, SQLite, JSON library, or Prometheus dependency. This makes the real relay independently testable. Public engine API in `tcp_proxy.h` uses namespace `tcp_proxy`:

* Value types `Settings`, `Hostgroup`, `Server`, `Listener`, `Rule`, `Config` represent the tables with the exact column names above. Optional rule values use `std::optional`. `Config` owns settings and vectors `hostgroups`, `servers`, `listeners`, `rules`.
* `bool validate_config(const Config&, std::string& error)` performs pure structural/range/address/CIDR/reference validation; no binds/DNS. `std::string listener_interfaces(const Config&)` formats active endpoints for core collision validation.
* `class Engine` with PIMPL; constructor/destructor; `bool start(const Config&, std::string&)`; `bool apply(const Config&, std::string&)`; `void stop()`; `Snapshot snapshot() const`; `Config config() const`; `bool running() const`. No throws across these public mutation boundaries. `start` starts resources and applies generation 1, even for empty configuration. `apply` serializes via try-lock and reports busy instead of blocking another Admin load. Startup-only setting changes reject atomically. `stop` is idempotent and bounded by shutdown_timeout_ms plus short thread cleanup overhead.
* `Snapshot` contains `generation`, `running`, `last_error`, global totals, and typed listener/server/rule rows. Header defines exact snapshot member names before Admin implementation begins; the root coordinator freezes that header between implementation stages. Statistics are copied without network or SQL and without holding a lock over worker joins.

Private files separate config validation/route compilation, selection/capacity state, relay/accept lifecycle, and health monitoring. A test harness may drive Engine directly; the production plugin must use that same engine, not a second simplified relay.

## Activation and concurrency

The Admin callback first acquires a plugin-owned LOAD mutex with try_lock while holding the Admin mutex, before copying any editable row. A competing LOAD returns busy immediately without waiting while holding Admin. The successful callback retains the LOAD guard until after reacquiring Admin and completing its response, preventing stale snapshots or out-of-order publication. It copies all editable rows while it holds the Admin mutex. It releases that mutex using the paired command-context callbacks, validates/prepares and applies through Engine, then reacquires using RAII on every exit. If callbacks are unavailable in isolated tests, direct invocation may run synchronously because no Admin client owns that test connection. Workers never request the Admin mutex, avoiding an inverse wait. Two overlapping runtime loads return a descriptive busy error for one; do not let an older delayed snapshot overwrite a later successful activation. Snapshot/save operations briefly hold the engine configuration mutex only.

Prepare the complete immutable candidate, convert numeric backend addresses into owned sockaddr values, validate core reservations, prepare newly required listener sockets, allocate changed runtime state, and stage worker control messages before publication. Bind with SO_REUSEADDR but never SO_REUSEPORT. All socket/thread setup errors roll back temporary resources and preserve generation and old listeners. No getaddrinfo or other resolver is used on this path; inet_pton validates both families. This keeps configuration work cancellable/bounded and avoids delaying shutdown on an active Admin resolver callback.

An acceptor thread owns the current listener set and hands accepted sockets to a fixed pool of epoll workers through bounded queues and eventfd wakeups. A different fixed-pool design is acceptable only if it preserves single-worker ownership for each flow and the same atomic activation semantics. Short acceptance/publication locking establishes one linearization point: every accepted flow pins one complete generation. Reuse unchanged endpoint sockets even if listener ID or policies change. New binds become visible together; removed endpoints cease accepting before activation returns. An endpoint replacement requiring closing an overlapping active socket before binding the replacement is rejected atomically with instructions to remove/apply/add/apply; do not claim transactional rollback across an irreversible close/rebind gap.

Stable shared capacity state for listener/server IDs counts pending and established connections across workers and pinned generations. Acquire global, listener, and server slots before dispatch/connect; release every acquired slot exactly once on every failure/close path. Use CAS or equivalent race-safe reservations; no unchecked fetch-add admission. Lowering a capacity does not kill existing sessions, but prevents admission until below the new limit. Endpoint edits retain established old flows; health resets for changed endpoints. Removed rows cease receiving new assignments and retain runtime state until draining completes. All queued accepted sockets count toward limits. Dispatch queues are bounded; full queues reject and count a reason.

Administrative `OFFLINE_HARD` publishes a disconnect instruction for that server_id to every worker, affecting connections pinned to older generations too. Acknowledge processing before LOAD returns. There is no later fail-able preparation after irreversible hard disconnect begins. All other configuration edits, including OFFLINE_SOFT and removal, preserve established flows. Worker commands must not retain raw pointers to reclaimed generations or close a reused file descriptor from stale epoll events; use stable per-flow tokens/tombstones or deferred destruction across an event batch.

## Forwarding, balancing, and health

Flow states: accepted, selecting, connecting, relaying, half-closed, closed. Nonblocking connect completion checks SO_ERROR. Support server-first protocols by initiating connect immediately on acceptance. Retry only failed connection attempts, within total deadline and max_connect_attempts, avoiding already attempted server/address candidates when alternatives exist. Never retry after a backend connection has succeeded, after sending any application byte, or after receiving an application byte from that backend; never replay application traffic. Do not read client application bytes until backend establishment, or retain them without forwarding during retries. An accepted old-generation flow with a reserved in-flight connect may complete that connect after a soft removal or endpoint edit. If it must retry, only currently ONLINE, healthy, capacity-eligible servers with unchanged endpoint identity in its pinned hostgroup may be chosen; removed/offline/replaced endpoints cannot receive new retry attempts. A hard-offline instruction closes queued, pending and established flows for the server ID. Test these pending-connect boundaries explicitly.

Each direction uses at most buffer_size payload bytes. Enable read interest only with buffer space; enable write interest only with queued bytes. Handle EINTR, EAGAIN, short reads/writes, SO_ERROR, HUP combined with readable data, and MSG_NOSIGNAL. Flush bytes read before EOF before calling shutdown(peer, SHUT_WR). Continue the reverse stream until its EOF/error/deadline. The first EOF starts half_close_timeout_ms; normal idle deadline is based on successful I/O progress using monotonic time. No one-thread-per-connection implementation.

Eligible backends are ONLINE, healthy (or checks disabled), below their capacity, and in the selected hostgroup. Select primaries first; backups become eligible only when no primary is eligible, including primary saturation. Round-robin honors weights across workers through shared scheduler state; smooth weighted round-robin is acceptable. Leastconn minimizes reserved_connections/weight with rotating ties. Capacity reservation and selection must be coordinated so contending workers cannot exceed max_connections or overcommit the selected server. Checks never consume application capacity or user byte counters.

A dedicated bounded nonblocking health loop probes endpoints using connect + SO_ERROR, monotonic deadlines and rise/fall hysteresis, never one thread per server. Limit simultaneous probes (default 64) and jitter schedules. New checked endpoints start UNKNOWN/ineligible until rise successes. Disabled checks treat ONLINE servers as eligible immediately. Health DOWN prevents new connections and preserves established ones. Keep administrative and health status separate. Do not convert a single user connect error into a persistent administrative status change. Probes for removed/stale endpoint identities cannot overwrite the health of replacements. Expose selected numeric endpoint and health. Each server row identifies exactly one endpoint.

## Core listener-validation service

Append one service callback and bump chassis layout/max to ABI 17 while keeping all existing compatible prefixes and the existing rejection of reserved/incompatible layouts:

`bool (*validate_listener_interfaces)(const char* owner, const char* interfaces, std::string& error);`

Before plugin init, `ProxySQL_Main_exit_on_listener_conflicts()` copies the enabled core listener modules it already collected into an owned process-local reservation snapshot. Add a small generic listener-reservation helper (new header/source is preferred) and seed it from that function before its borrowed variable strings are freed. The service compares a plugin's numeric candidate interfaces against this snapshot using the existing listener validator. It performs no SQL and accepts no mutation of core interfaces. Phase B returns a clear unavailable error; normal init/start and Admin LOAD can call it. Clear/reseed reservations on internal reload. Plugin-to-plugin conflicts are additionally prevented by exclusive kernel binds; no plugin-specific table names enter core.

Initial start and every LOAD validate active TCP endpoints through this service before Engine activation; a missing service rejects listener activation explicitly. Check enabled core listeners only, allowing a TCP-only process to reuse a disabled MySQL/PgSQL port. Bind failure remains authoritative for unrelated external processes and other plugin listeners. Explicit V6ONLY sockets avoid cross-family kernel surprises; conservative rejection from core's existing validator is acceptable if clearly diagnosed. Update tests that currently label ABI 17 as unsupported to use ABI 18, and add compatible ABI 16 prefix coverage. Test debug-tier compatibility too.

## Metrics and lifecycle

Lifecycle review ruling: plugin Context storage must remain alive until the core manager's stop callback, including release SIGTERM's std::exit/atexit path. An automatically destroyed function-static Context is unsafe because its destructor runs before the earlier-created global plugin manager. Use explicit module-owned storage with destruction only after chassis stop during DSO finalization; release all resources on init failure/stop and free storage on unload, with no per-reload heap leak. Do not change generic core signal semantics to mask plugin ownership. Verify real SIGTERM fast exit and ordinary STOP/START.

Read API ruling: only mutation boundaries promise no exceptions. A failed config()/snapshot() copy must propagate a failure, never return a valid-looking empty configuration that Admin SAVE could persist. Read-only consumers fail safely; metric sampler contains exceptions at its thread boundary. If a coherent configuration/generation cannot be obtained after bounded retries, Admin returns an error and leaves editable tables untouched.

Prometheus metrics use `proxysql_tcp_` prefix and bounded labels: listener/server/rule IDs, never client addresses. Include connection totals/active, directional bytes, rejects/connect failures, health and active generation. The core Registry owns the twelve stable metric families for process lifetime; the plugin owns only its samples. Retain families across plugin unload, remove only plugin-owned samples after joining the sampler, and rebind empty families on restart. This avoids deleting merged preexisting families in the default Merge registry. A fixed component=tcp_proxy constant label names the module, and the tcp_proxy metric namespace and sample labels have one serialized lifecycle/sampler writer. Reject visible conflicting names and existing sample labels; never adopt/delete a foreign sample. Core-library constructors/vtables own Family, Counter and Gauge objects, so no plugin-defined Collectable callback remains after unload. Empty retained families do not appear in scrapes, twelve names bound family storage, and all dynamic samples must be pruned. Handle initialization failure cleanup. Counters may reset across STOP/START and process restarts; document this.

`register_schemas`: declare persistent pairs, runtime/stats tables, commands, aliases and refresh callbacks without accessing DB handles. `init`: obtain services, read restored config and prepare metrics/context; all init failures clean their own resources because the chassis does not call stop on failed init. `start`: validate listener reservations and start Engine; no protocol worker objects are required. `runtime_ready` can report running/unconfigured state but is not the safety gate for owned sockets. `stop`: close accepts, allow bounded connection drain, force close remaining sockets, stop health loop, wake/join workers, remove owned metric samples and release all module-owned resources. Tolerate start failure and repeated local stop calls.

## Verification and acceptance

Engine tests must exercise actual loopback sockets and assert bytes and close behavior. Minimum cases: configuration bounds/references/CIDRs/duplicate wildcards; IPv4 and supported IPv6; arbitrary binary payload > several buffers; server-first greeting; bidirectional half-close with response after client SHUT_WR; simultaneous flows and capacity enforcement; weighted distribution and leastconn; source rule/reject/default; primary/backup; unavailable backend and bounded connect retry; idle and half-close timeouts; health fall/rise and stale endpoint results; backend/listener edits preserving existing sessions; OFFLINE_HARD closing old-generation sessions; failed bind and invalid config leaving generation/listener behavior unchanged; startup-only settings rejection; bounded stop and repeated restart; fd/thread leak checks; concurrent apply/admission.

Admin/DSO tests must cover exported descriptor/name/ABI, exact schema pairs and seeded settings, every command and alias, malformed rows, SQL quoting, runtime-vs-memory distinction, all-table disk roundtrip, startup restore, SAVE excluding health, mutex release/reacquire on failure, runtime/statistics projections, metrics cleanup, and listener reservation service. Add real daemon/Admin tests when a v4 daemon can be built; otherwise report that gap explicitly and do not present an engine harness as full daemon verification.

Provide reproducible benchmark tooling with a direct backend baseline and the same Engine implementation. Measure small-message roundtrip latency p50/p95/p99, connections/s, sustained bytes/s, CPU/RSS and idle connection footprint with fixed workload parameters. Compare HAProxy only if available/built; record binary versions, worker counts, concurrency, payload, durations, host details and raw results. Benchmarks are local measurements, not performance claims without data. Default runs are short (seconds), bind loopback, start only task-owned children and clean them up reliably. No broad pkill or load against external services.

Implementation is complete only when scoped tests pass, integration seams are reviewed, benchmark evidence exists, user documentation/SQL examples are included, and all unverified platform/daemon/performance limitations are explicitly recorded.

Metrics ownership review ruling: default Registry::Merge cannot identify newly-created empty families through its public API. Do not mutate global insertion policy, access private library layout, or change dependency ABI. Retain core-owned stable families, own samples only, stage ownership bookkeeping before Add, and remove newly-created samples on tracking failure. The sampler never acquires Admin's SQL mutex, because fast SHUTDOWN/KILL may call exit while holding it and teardown must join the sampler. Core v4 defers STOP/RESTART counter reset until after plugin and worker teardown. The plugin manager holds shared ownership of the registry through stop and DSO unload, including fast process exit; no plugin atexit workaround or dependency ABI change is needed.
