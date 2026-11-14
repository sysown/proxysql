# Native TCP Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Deliver a native opaque TCP plugin with transactional Admin configuration, safe hot changes, health monitoring, tests and measured benchmark evidence.

**Architecture:** A core-independent C++ engine owns the TCP data plane and immutable generations. A thin plugin translates Admin tables/commands and projects runtime/metrics. A generic additive chassis service validates candidate listeners against enabled core reservations.

**Tech Stack:** C++17-compatible standard/POSIX APIs, Linux epoll/eventfd, SQLite3DB and existing plugin/Prometheus services; Python3 loopback test/benchmark tooling.

**Spec:** `docs/superpowers/specs/2026-11-11-native-tcp-proxy-design.md`

## Global Constraints

- Build only with `PROXYSQL40=1`; use the same C++ toolchain/build tier as core.
- Plugin name `tcp_proxy`; artifact `plugins/tcp_proxy/proxysql_tcp_proxy.so`; entry point `proxysql_plugin_descriptor_v1`.
- No one-thread-per-connection implementation. No SQL or DNS on connection workers. No application replay.
- Failed configuration preparation preserves active generation/listeners. Irreversible hard disconnect begins only after all fail-able preparation.
- OpenCode implementation workers use `opencode/deepseek-v4.1-flash`; root/subagents coordinate and independently review/verify. No commits, pushes, or production operations.
- Concurrent OpenCode workers use distinct managed worktrees. Integrate only reviewed scoped files back to the user's original checkout; do not change unrelated work.
- The user explicitly authorized implementation after the design; proceed through the plan without another approval pause.

## Review Focus

- Reload during partial send/EOF must preserve buffered bytes and never act on stale/reused fds.
- Concurrent LOAD and SAVE must not deadlock Admin or publish an older slow candidate after a newer one.
- Capacity counts must include queued/pending/old-generation sessions and release every reservation on failure.
- Startup collision checking must account for enabled core listeners before they bind, and permit ports of disabled components.
- STOP/START must leave no plugin threads, fds or metric samples. Twelve core-owned empty families may remain across unload.

---

### Task 1: Core-independent TCP engine

**Files:** Create `plugins/tcp_proxy/include/tcp_proxy.h`, private engine headers as needed, `plugins/tcp_proxy/src/config.cpp`, `engine.cpp`, `health.cpp` (or similarly focused units), `plugins/tcp_proxy/tests/engine_unit.cpp`, and a standalone `plugins/tcp_proxy/tests/Makefile`.

**Interfaces:** Consumes the exact configuration/default/semantic contract in the spec. Produces `tcp_proxy::Config`, `Settings`, `Hostgroup`, `Server`, `Listener`, `Rule`, `Snapshot`, `validate_config`, `listener_interfaces`, and the PIMPL `Engine` public API specified there. Snapshot row field names must be documented and frozen in the header before Task 3 starts; notify coordinator when ready. Header includes no ProxySQL/SQLite/Prometheus types.

- [x] Write actual failing tests for config defaults/bounds/dangling references/CIDR and a real socket forward + client-half-close response. Run them and record failure.
- [x] Define the public API and implement pure validation and route selection; exact column names/defaults come from the spec. Reject embedded NULs and unsupported mapped IPv6 values explicitly.
- [x] Implement fixed-worker nonblocking forwarding, bounded buffers/queues/capacity, backend connection budget/retries, correct server-first and half-close behavior, and monotonic deadlines. Per-flow event tokens prevent stale epoll-event fd reuse.
- [x] Implement prepare/publish/reuse/remove listener activation, cross-generation stable state, busy rejection, atomic startup-setting rejection, acknowledged hard disconnect, and bounded/idempotent stop. Test failed bind leaves generation/listeners intact and old-generation sessions survive soft changes but close on hard changes.
- [x] Implement bounded nonblocking health loop, rise/fall hysteresis, primary/backup eligibility, shared weighted scheduling and leastconn reservations. Test health transitions and stale endpoint state protection.
- [x] Run standalone tests with normal compiler warnings and ASan/UBSan where supported. Assert loopback binary payloads larger than buffers, capacity under parallel clients, concurrent apply, idle/half-close deadline, restart, and fd/thread counts. Write exact commands and results to the worker report.

### Task 2: Generic core listener reservation service

**Files:** Create `include/ProxySQL_PluginListenerReservations.h`, `lib/ProxySQL_PluginListenerReservations.cpp`, `test/tap/tests/unit/plugin_listener_reservations_unit-t.cpp`; modify `include/ProxySQL_Plugin.h`, `lib/ProxySQL_PluginManager.cpp`, `src/main.cpp`, `test/tap/tests/unit/Makefile`, and incompatible ABI expectation tests only as needed. Inspect lib Makefile source discovery before adding explicit objects.

**Interfaces:** Produces ABI-17 service tail `bool (*validate_listener_interfaces)(const char* owner, const char* interfaces, std::string& error)`; no earlier service/descriptor offsets change. Generic reservation helper accepts an owned vector of module-name/interface strings copied from existing startup modules. API names may be chosen by worker and recorded in report. Consumes existing `proxysql_listen_validator` overlap logic.

- [x] Add failing standalone TAP tests for exact and wildcard IPv4/IPv6 collisions, disabled/empty reservations, no conflicts on distinct ports, replacing reservation snapshots during reload, and borrowed-input lifetime independence. Run red.
- [x] Implement thread-safe owned reservation snapshot and pure candidate validation. Strictly reject malformed candidate strings rather than silently accepting validator parse failures. Core existing parser behavior outside this service remains unchanged.
- [x] Seed enabled core reservations in `ProxySQL_Main_exit_on_listener_conflicts()` before freeing variable strings; wire live and phase-B rejecting callbacks; bump layout/max to 17 and update ABI-version comments. Leave compatible prefixes and reserved ABI rejection unchanged.
- [x] Update future-ABI fixtures from 17 to 18, explicitly verify ABI 16 remains compatible, and ensure DEBUG tagging still works. Add standalone target to unit Makefile.
- [x] Run reservation TAP directly with standard library + TAP; run relevant existing standalone listener/gate tests. Compile affected core paths when dependencies are available and report any gap accurately.

### Task 3: Admin plugin, metrics and build integration

**Files:** Create `plugins/tcp_proxy/{Makefile,exports.map,README.md}`, `include/tcp_proxy_plugin.h`, `src/plugin.cpp`, `src/admin.cpp`, `src/metrics.cpp`, private headers as needed, `tests/admin_unit.cpp`; modify top-level `Makefile` build/debug/clean/install/uninstall entries only. Create `doc/tcp-proxy-plugin.md` or make README the canonical user reference with link from doc. Add any necessary focused TAP target/integration test without broad test-suite changes.

**Interfaces:** Consumes Task 1's frozen header and Task 2's ABI-17 callback. Produces the descriptor, five persistent table pairs with identical DDL, runtime/stats projections, exact canonical commands and aliases, and Prometheus metrics with lifecycle cleanup. Production plugin uses Task 1 Engine.

- [x] Write failing registration/command/schema tests with fake services and real isolated SQLite3DB where feasible. Assert defaults, aliases, no DB access in phase B, and all configured columns.
- [x] Implement strict SQL-to-Config parsing without silent numeric truncation, invalid enum fallback, dangling references, or embedded-NUL acceptance; every column/default is fixed by the spec.
- [x] Implement transactional disk/memory and runtime/memory copying with explicit column lists and SQL quoting, plus LOAD try-lock before snapshot -> Admin mutex handoff -> listener validation -> Engine apply -> reacquire on all exits. Reject concurrent applies promptly and preserve runtime on validation/apply failure. Test two LOADs and SAVE while first LOAD is unlocked.
- [x] Implement runtime/config/retired-state statistics snapshots and bounded-label Prometheus families. Remove only owned samples after sampler/worker shutdown; retain core-owned families and pin registry lifetime through DSO unload. Verify repeated init/start/stop and failure cleanup.
- [x] Implement startup/stop/descriptor, lowercase artifact/exports, Linux guard, standard toolchain/feature-tier flags, stage-runtime if used, and top-level build/debug/clean/install/uninstall wiring. No changes to v3 build behavior.
- [x] Run admin/DSO tests and build release + debug plugin. Inspect `nm -D` export surface. Run real isolated daemon Admin smoke if a matching v4 core is available; test SQL configure, LOAD, forwarding, failed LOAD rollback, SAVE disk/restore and lifecycle. Record limitations explicitly.

### Task 4: Independent adversarial testing, benchmarks and documentation

**Files:** Create `plugins/tcp_proxy/tests/engine_harness.cpp`, Python test/benchmark tools under `plugins/tcp_proxy/tests/`, documented test/benchmark targets, and a dated results artifact under `docs/benchmarks/` containing reproducible workload/host details and measurements. Update user reference and spec/plan status with actual shipped limitations. Worker uses its own worktree until integrated.

**Interfaces:** Consumes frozen Engine header/implementation; harness starts the same Engine and offers a minimal test control interface for reload/snapshot/stop. No alternate TCP engine. Tests can use standard Python socket/threading/subprocess and loopback backend children. DSO/Admin integration uses actual production plugin.

- [x] Build a controllable harness and write failing adversarial tests around actual sockets: random binary/backpressure, server-first, SHUT_WR response, capacities, source policies, backups, timeouts, bind rollback, concurrent reload, hard-offline old generations, listener/backend soft removal, and repeated restart/leak counts.
- [x] Run the suite and send concrete defects to coordinator rather than quietly relaxing assertions or changing design. Keep edits limited to test/documentation paths; implementation fixes return to responsible worker.
- [x] Implement reproducible short direct/backend and native-engine benchmarks for latency p50/p95/p99, connections/s, throughput, process CPU/RSS and idle connections. Include cleanup, raw JSON, host/compiler/worker/concurrency/payload/duration metadata and sample counts. Build/run adjacent HAProxy as optional comparison if feasible, with identical workloads and worker counts.
- [x] Run actual benchmarks and write results with scope/measurement caveats; no fabricated comparisons or hard performance claims from tiny samples. Confirm direct baseline measures the same backend protocol and payload.
- [x] Document working SQL examples for listener/hostgroup/backend/rule configuration, soft/hard removal and persistence; explain numeric-address-only backend support, TCP-only/TLS passthrough/source identity, no-start/lifecycle behavior, v4 build and existing Admin interface.

### Task 5: Final integration and independent review

**Files:** Only scoped changes from Tasks 1–4, progress/evidence artifacts; root original checkout receives reviewed changes with no commits.

**Interfaces:** All task deliverables and exact tests above.

- [x] Review every complete diff for scope, design compliance, and concurrency/resource lifetime defects; root integrates files explicitly, preserving unrelated changes. No concurrent workers mutate one worktree.
- [x] Run root-owned meaningful verification: standalone engine/admin/reservations + adversarial suite, release/debug compile, focused chassis regression tests, and daemon smoke when provisioned dependencies permit. Do not duplicate unchanged passing suites without a new change or concern.
- [x] Request an independent whole-change review of design compliance, Admin lock ordering, event/flow lifetimes, failure rollback, and build/ABI compatibility; repair concrete findings through delegated workers and recheck affected paths.
- [x] Confirm benchmark raw evidence and user docs match actual behavior. Update plan/ledger with completed tasks and any external build/platform gaps. Report exact tested scope and remaining limitations, plus design/documentation links.

## Final integration evidence

All five tasks completed in the original checkout. Subagents coordinated
OpenCode implementation/testing with `opencode-go/deepseek-v4.1-flash` (the
requested DeepSeek model through the available provider). Root independently
reviewed/integrated the changes and verified the final composed build.

- Engine: 69 cases / 1,138 checks; ASan/UBSan/leak checks also passed.
- Admin: 240 assertions with real SQLite3DB and deterministic Engine tests.
- Independent real sockets: 44 scenarios, including binary streams, backpressure,
  half-close, TLS passthrough, health, retries, reload and retirement.
- Core: reservations 52 checks (release/debug), lifecycle 98, ABI 67, managed
  configuration 12 and Prometheus 12. Existing gate/validator checks also passed.
- Final release/debug DSO builds passed; layout 17, correct DEBUG tagging, only
  `proxysql_plugin_descriptor_v1` exported.
- Final matching release daemon: basic forwarding, reload/rollback, five-table
  disk persistence, lifecycle and enabled/disabled core collisions all passed.
  Lifecycle includes no-start/START, STOP/START, SLOW shutdown, SIGTERM, fast SQL
  SHUTDOWN and KILL with bounded successful exit.
- Final independent Engine and integration reviews found no remaining blockers.
  Final metrics ownership and registry lifetime findings have regression tests.

The final v4-only core integration pins the shared registry through plugin stop
and unload, and defers STOP/RESTART counter reset until after plugin and worker
teardown. The sampler acquires no Admin SQL mutex. V3 reset timing is preserved.

Release plugin SHA256:
`bee084a3d23075b6868c712a0e28f0e5527c75c9c9a9d2db216de28e12d03d0d`.
Matching release host SHA256:
`0a192231469657639a3173a8c61f7ae673b8e8e2ee8719000df3b7bcfdff61be`.

The matching core was compiled in the isolated core worktree using existing
read-only donor dependency builds; the original checkout's dependency tree was
not rebuilt. Release and debug plugin builds used the same dependency headers.
Full debug-daemon integration was not run. Linux is the shipped platform;
backend addresses must be numeric IPv4/IPv6. TLS is passed through unchanged.
The benchmark compares the standalone production Engine harness with direct
connections and HAProxy; its resource figures exclude the full ProxySQL daemon.

See [user guide](../../../doc/tcp-proxy-plugin.md) and
[benchmark results](../../benchmarks/2026-11-11-native-tcp-proxy.md).
No commits, pushes or production deployments were performed.
