# Plugin Chassis (PR #5651) — Reviewer's Guide

This guide exists because PR #5651 is unusually large (105 files, +48,749 / −32 lines, ~150 commits over three weeks) and was built incrementally by merging several feature branches. Reading it commit-by-commit is not productive. Reading it file-by-file without context is also not productive. This doc gives you a structured walk-through so you can validate each layer independently.

**Companion documents:**
- [`ABI.md`](./ABI.md) — the plugin ABI contract: what's stable, what's tail-extensible, how versioning works.
- [`FILE_CHANGES.md`](./FILE_CHANGES.md) — file-by-file inventory (~140 files described, grouped by area).

**For plugin authors who just want to write a plugin**, see [`doc/PLUGIN_API.md`](../PLUGIN_API.md). This document is for someone reviewing the plumbing.

---

## 1. What this PR does (in one paragraph)

It introduces a **plugin chassis** — a generic ABI plus a `dlopen`-based loader inside `libproxysql.a` — and uses that chassis to ship the **first plugin**: a MySQL X Protocol terminator that builds as a separate `.so`. The chassis lives behind `#ifdef PROXYSQL40` (a new feature tier; `PROXYSQLGENAI` now implies it). Under any v3.x build (`make` with no flags, `make PROXYSQL31=1`) the chassis is **fully invisible** — no symbols, no headers, no behaviour change. The mysqlx plugin is the prototype consumer of the chassis; it auths clients, routes queries to a backend MySQL via X Protocol, optionally terminates client TLS / requires backend TLS, pools backend connections, and negotiates zstd / lz4 X Protocol compression.

```
   ┌─────────────────────────────────────────────┐
   │  proxysql binary                            │
   │  ┌──────────────────────────────────────┐   │
   │  │  libproxysql.a                       │   │
   │  │  ┌────────────────────────────────┐  │   │
   │  │  │  ProxySQL_PluginManager        │  │   │
   │  │  │  (the chassis)                 │  │   │
   │  │  │  - dlopen + RTLD_LOCAL         │  │   │
   │  │  │  - ordered lifecycle           │  │   │
   │  │  │  - services injection          │  │   │
   │  │  │  - admin-command dispatch      │  │   │
   │  │  │  - query-hook dispatch         │  │   │
   │  │  └────────────────────────────────┘  │   │
   │  └──────────────────────────────────────┘   │
   └─────────────────────────────────────────────┘
                        │ dlopen
                        ▼
   ┌─────────────────────────────────────────────┐
   │  ProxySQL_MySQLX_Plugin.so                  │
   │  - X Protocol auth + routing + compression  │
   │  - ~5,600 LOC handwritten                   │
   │  - protobuf 3.x (statically vendored zstd,  │
   │    lz4)                                     │
   └─────────────────────────────────────────────┘
```

The chassis is designed so the same pattern can host other plugins later (PgBouncer-protocol bridge, custom auth plugins, telemetry plugins, etc.) without reopening this PR.

---

## 2. Reading orders

Pick one based on your time budget. Each is cumulative — the 2-hour pass continues from where the 30-minute one ends.

### 30-minute pass: "is this load-bearing?"

Goal: convince yourself the chassis ABI and lifecycle are sane and the v3.x invisibility is real. Don't read mysqlx; trust that it's a consumer.

1. Read **§3 (ABI surface)** below. Cross-check against [`ABI.md`](./ABI.md).
2. Skim `include/ProxySQL_Plugin.h` — note `PROXYSQL_PLUGIN_ABI_VERSION = 8`, the descriptor's ABI-gated tail, and the matching service-table tail.
3. Read **§4 (Ordered plugin lifecycle)** below.
4. Skim `lib/ProxySQL_PluginManager.cpp` lines **324–461** (load + register_schemas + abi_version gating) and **548–576** (stop_all pairs with init).
5. Check the v3.x invisibility claim:
   - `grep -L PROXYSQL40 include/ProxySQL_Plugin.h include/ProxySQL_PluginManager.h lib/ProxySQL_PluginManager.cpp` should be **empty** (every chassis file is wrapped).
   - The chassis-related deltas in `lib/Admin_Bootstrap.cpp` (line ~944) and `lib/ProxySQL_Admin.cpp` (line ~342) are inside `#ifdef PROXYSQL40` blocks.
6. Skim **§7 (Seams where consistency could break)** below — this is the list of things the incremental development pattern could have left contradictions in. Each item has a one-line check.

### 2-hour pass: "is this really designed?"

Goal: walk one full request path through the chassis and through mysqlx. Convince yourself the design is coherent end-to-end.

7. Read **§5 (Mysqlx as worked example)** below.
8. Trace one client connection through the code:
   - `Mysqlx_Thread::accept_new_connection()` (`plugins/mysqlx/src/mysqlx_thread.cpp:200`)
   - `MysqlxSession::handler()` switch (`plugins/mysqlx/src/mysqlx_session.cpp:187`)
   - `handler_capabilities_get()` → `handler_capabilities_set()` (compression + tls negotiation)
   - `handler_auth_start()` → `handle_auth_mysql41()` → `resolve_backend_target()` → `send_auth_ok()`
   - `handler_connecting_server()` (`mysqlx_session.cpp:1028`) — the backend auth handshake
   - `handler_waiting_client_msg()` / `handler_waiting_server_msg()` — the steady-state pump
9. Read **§6 (Build & CI)** below.
10. Verify a v3.0 build still works locally: `make clean && make` (with no flags). Should produce `src/proxysql` with no chassis symbols (`nm src/proxysql | grep -i plugin_manager` should be empty).

### Full day: "I'm going to vouch for this on `v3.0`."

Goal: validate the entire test corpus, run the unit tests, and exercise the e2e against a real MySQL.

11. Read [`FILE_CHANGES.md`](./FILE_CHANGES.md) end-to-end.
12. Run the test suite per the verification checklist at the end of this doc.
13. Build with `PROXYSQLGENAI=1` and run a local mysqlx connection through ProxySQL against a Docker MySQL 8.4. The CI workflow `.github/workflows/CI-mysqlx.yml` documents the commands.

---

## 3. The chassis ABI surface

The chassis is defined by **two headers** plus the loader implementation. The contract a plugin author sees is everything declared in `include/ProxySQL_Plugin.h`. The contract the proxysql core sees is everything declared in `include/ProxySQL_PluginManager.h`.

**Key types (in `include/ProxySQL_Plugin.h`):**

- `PROXYSQL_PLUGIN_ABI_VERSION` (currently `9`) — what newly-built plugins target. ABI 1 supplied the original six-field descriptor; later ABIs only append fields or extend compatible service contracts.
- `ProxySQL_PluginDescriptor` — the struct returned via `extern "C" proxysql_plugin_descriptor_v1()`. Its current tail contains schema, CLI, early-action, and runtime-ready callbacks. The single mandatory entry point a plugin must export is unchanged.
- `ProxySQL_PluginServices` — the injected service table: registration APIs, log helper, three DB getters, live snapshots, Prometheus registry, runtime views, encrypted secrets, listener gates, and scoped MySQL configuration publication. Tail-append discipline preserves compatibility with plugins built against shorter layouts.

**The contract of the descriptor is:**
- `name` is a non-null, non-empty C string. The loader rejects anything else.
- `abi_version ∈ [1, PROXYSQL_PLUGIN_ABI_VERSION_MAX]`. The loader rejects anything else.
- `init`, `start`, `stop`: function pointers. NULL is permitted (a plugin can opt out of a phase).
- `register_schemas`: only read when `abi_version >= 2`. ABI-1 plugins skip Phase B.

**See [`ABI.md`](./ABI.md) for the full contract**, including the tail-append rule, the Phase-B-vs-Phase-D services availability matrix, the C++-ABI coupling note (`std::string` and `prometheus-cpp` are part of the contract — plugin and core must share toolchain), and the empty-source-sync invariant.

### ABI 6–9 availability matrix

| ABI | Descriptor tail | Service tail |
|---:|---|---|
| 6 | `register_cli_options`, `early_action` | parsed options through action context |
| 7 | unchanged | encrypted secret callbacks |
| 8 | `runtime_ready` | listener gate, scoped MySQL config publisher, live snapshots |
| 9 | unchanged | V2 scoped MySQL publisher with a separate rule-ID attributes array |

The callback order is fixed: discover all configured modules, register their CLI options, perform the one definitive core parse, call `register_schemas`, materialize Admin databases, call `early_action`, then `init`, `start`, and `runtime_ready`, and finally call `stop` during teardown. An early action may request a successful or failed process exit; otherwise startup continues. `runtime_ready` runs after core runtime dependencies exist and immediately before listener validation/start. A plugin whose `init` succeeded receives exactly one `stop`, even if `start` or runtime readiness later fails.

`--no-plugins` is unconditional: it suppresses named and explicit module discovery and therefore every plugin CLI, schema, action, init, start, runtime-ready, and stop callback. With no configured plugins, each lifecycle wrapper is a successful no-op and the core follows its pre-plugin startup path.

Ownership is explicit at every boundary. The early-action option context, Admin command DB handles, and scoped MySQL publication plan are borrowed only for their callback or call. Registered table, listener-gate, and publication data are copied by core. Each live snapshot callback returns a new caller-owned `SQLite3_result`; the caller must `delete` it. Publication results own their message and collision data.

The scoped MySQL publisher replaces only objects recorded for that owner, keeps unrelated operator rows intact, and records one active generation in both memory and disk. ABI 9 keeps the ABI-8 base plan unchanged and supplies query-rule attributes separately by rule ID; validation and publication remain all-or-nothing across main, disk, and live runtime. A listener gate remains owner-scoped until replaced or removed. On a closed-gate accept, core closes the accepted fd before creating a session or starting a protocol handshake, increments the copied gate's rejection counter, and rate-limits warnings to one per 30 seconds. Admin port 6032 and the default MySQL port 6033 cannot be gated.

---

## 4. The ordered plugin lifecycle

This is the single most important thing to validate. The lifecycle is implemented in `lib/ProxySQL_PluginManager.cpp` and driven from `src/main.cpp`'s startup sequence.

```
startup                                                                                 shutdown
┌─────┐  discover/CLI   parse   schemas   Admin   action   init   start   ready   ┌─────────┐
│main │ ──────────────► once ─► register ─► DBs ─► early ─► full ─► run ─► gates ─►│ workers │
└─────┘                                                                          └────┬────┘
                                                                                      │
                                                                                 stop/unload
```

| Phase | Driver | What runs | What's available to the plugin |
|---|---|---|---|
| A | discovery and CLI registration | `dlopen(RTLD_NOW \| RTLD_LOCAL)`, resolve and validate the descriptor, register plugin options, then run the definitive parse | CLI registry only during option registration |
| B | `proxysql_load_configured_plugins()` invokes `invoke_register_schemas_phase()` | Plugin's `register_schemas` callback runs. Plugins declare admin-schema tables and admin commands. | Phase-B services struct: `register_table`, `register_command`, `register_command_alias`, `log_message`. **DB getters return nullptr** (admin not initialized yet). Query-hook registration refuses with a warning. |
| C | `ProxySQL_Main_init_Admin_module()` calls `Admin::init()` | Admin module merges plugin-declared tables into `tables_defs_{admin,config,stats}` and runs `check_and_build_standard_tables` (single canonical DDL pass for both core + plugin tables) | Plugin code does not run; admin is materializing the schema the plugin asked for in Phase B |
| D | `proxysql_run_configured_plugin_early_actions()` | Plugin's optional one-shot action runs after Admin is live | Parsed plugin options and full services, including encrypted secrets |
| E | `proxysql_init_configured_plugins()` | Plugin's `init` callback runs | Full services struct: live DB handles, `register_query_hook` works, `get_prometheus_registry` works |
| F | `proxysql_start_configured_plugins()` | Plugin's `start` callback runs | Full services. This is where the plugin spawns threads / opens listeners. |
| ready | `proxysql_runtime_ready_configured_plugins()` | ABI-8 `runtime_ready` runs after core dependencies and before listeners accept normal traffic | Full services; a failure force-closes that plugin owner's gates |
| (run) | worker threads | Steady-state. Plugins respond to `dispatch_admin_command` and `dispatch_query_hook` calls from the core. | Full services |
| stop | `proxysql_stop_configured_plugins()` | Plugin's `stop` callback runs | Full services |
| unload | manager destructor | `dlclose` after every plugin's `stop` returned | Nothing |

**Invariants worth verifying:**

1. **stop pairs with init**, **not** with start. If init succeeds but start fails, stop still runs. (See `lib/ProxySQL_PluginManager.cpp:548–576`. Test: `plugin_manager_unit-t.cpp:test_multi_plugin_start_failure_stops_started`.)
2. **Phase E writes commands_/hooks_; workers read them lock-free.** Phase E MUST complete before any worker thread reads via `proxysql_has_configured_plugin_query_hook`. If a future change moves listener startup before Phase E finishes, plain writes race plain reads. (Comment block at `lib/ProxySQL_PluginManager.cpp:929–949`.)
3. **The manager pointer is published BEFORE Admin::init**. `Admin::init` reads tables via `proxysql_get_plugin_manager()`. If the publish was deferred to after Phase D, the merge would see no plugin tables. (Comment block at the top of `proxysql_load_configured_plugins`.)
4. **`register_schemas` is only dereferenced when `abi_version >= 2`.** A v1 plugin's struct ends after `status_json`; reading past would be an out-of-bounds access. (Check at `lib/ProxySQL_PluginManager.cpp:407`.)
5. **The descriptor and services structs are tail-extensible.** A plugin compiled against an older supported ABI still loads in an ABI-9 core (the core reads only the fields that version defines). The reverse — an ABI-9 plugin against an older core — is rejected by the version check.

---

## 5. The mysqlx plugin as worked example

The mysqlx plugin lives entirely under `plugins/mysqlx/`. It builds as `ProxySQL_MySQLX_Plugin.so` and is loaded by the chassis at startup.

**The state machine is in `MysqlxSession`** (`plugins/mysqlx/src/mysqlx_session.cpp`, ~1,600 LOC). The 21-state `enum Status` drives a switch in `handler()` (line 187). For each Status value there's one `handler_*()` function. The state-to-handler mapping is in [`FILE_CHANGES.md`](./FILE_CHANGES.md) area H.

**A typical client flow:**

```
client                                              ProxySQL                                         backend
  │                                                    │                                              │
  ├─── TCP connect ───────────────────────────────────►│                                              │
  │                                                    ├─ accept_new_connection                       │
  │                                                    │  → MysqlxSession in CONNECTING_CLIENT        │
  ├─── CapabilitiesGet ──────────────────────────────► ├─ handler_connecting_client                   │
  │ ◄────────────────── caps reply ────────────────────┤  → X_CAPABILITIES_GET → handler_capabilities_get
  ├─── CapabilitiesSet (tls=true,                  ──► ├─ handler_capabilities_set:                   │
  │     compression=zstd_stream)                       │    parse caps, validate compression algo     │
  │ ◄──────────────────── Ok ─────────────────────────┤                                              │
  │ ◄═══ TLS handshake ═══════════════════════════════►│   X_TLS_ACCEPT_INIT / _CONT / _DONE          │
  ├─── AuthenticateStart (mysql41) ─────────────────► ├─ handler_auth_start                           │
  │ ◄────────────── AuthenticateContinue ─────────────┤    (challenge sent)                           │
  ├─── AuthenticateContinue (scramble) ──────────────►├─ handler_auth_challenge_response:             │
  │                                                    │     verify scramble (CRYPTO_memcmp)           │
  │                                                    │     resolve_backend_target() ─── route ──────┤
  │ ◄────────────────── AuthenticateOk ───────────────┤                                              │
  │                                                    │   WAITING_CLIENT_XMSG                        │
  ├─── StmtExecute ─────────────────────────────────► ├─ handler_waiting_client_msg                   │
  │                                                    │     → CONNECTING_SERVER if no backend yet    │
  │                                                    │     → handler_connecting_server: connect +   │
  │                                                    │       backend auth state machine ────────────►├─── X auth handshake
  │                                                    │     → forward_to_backend  ───────────────────►├─── StmtExecute
  │                                                    │                                              │ ◄── Resultset rows
  │                                                    │   handler_waiting_server_msg                 │
  │                                                    │     → forward_frame_to_client                │
  │                                                    │     → send_to_client_compressed              │
  │ ◄────────────── (zstd-compressed) Resultset ──────┤                                              │
  │                                                    │   WAITING_CLIENT_XMSG                        │
  │                                                    │  (loop)                                      │
```

The mysqlx plugin demonstrates every chassis affordance:

- **Phase B** — `mysqlx_register_schemas` declares 8 admin-schema tables (`mysqlx_users`, `mysqlx_routes`, `mysqlx_backend_endpoints`, `mysqlx_variables`, plus their `runtime_*` admin-side projections and `stats_mysqlx_*` tables), 16 admin commands (`LOAD MYSQLX USERS TO RUNTIME` and the 7 cousins, plus `SAVE` variants and aliases like `FROM MEMORY` / `FROM MEM` / `TO RUN`), and four runtime-view refresh callbacks via `services.register_runtime_view` (one per `runtime_mysqlx_<X>` table).
- **Phase E** — `mysqlx_init` performs disk-to-memory sync of the mysqlx tables on first boot, then loads the in-memory `MysqlxConfigStore` directly from the editable admin tables via four `install_<X>_from_admin` calls.
- **Phase F** — `mysqlx_start` clamps the thread-pool size, drives the listener reconciler from `MysqlxConfigStore::snapshot_active_routes()`, and spawns N worker threads.
- **Admin command dispatch** — `LOAD MYSQLX <X> TO RUNTIME` lands on a callback that invokes `MysqlxConfigStore::install_<X>_from_admin`; `SAVE MYSQLX <X> [FROM RUNTIME] TO MEMORY` invokes `MysqlxConfigStore::save_<X>_to_admin_table`. The disk-tier variants (LOAD/SAVE FROM/TO DISK) remain a plain BEGIN/DELETE/INSERT/COMMIT between configdb and admindb.
- **Runtime-view projections** — when admin runs `SELECT * FROM runtime_mysqlx_users` (or one of the four cousins), the chassis fires the registered refresh callback, which calls `MysqlxConfigStore::project_<X>_to_runtime_view(admindb)` to wipe and refill the admin table from current module state.
- **Identity callbacks** — each `MysqlxSession` is given an `identity_lookup_` closure that calls back into `MysqlxConfigStore::resolve_identity()` for the username the client sends.

If you can convince yourself the chassis can host the mysqlx plugin coherently, the chassis is in good shape.

---

## 6. Build & CI tier-flag wiring

`PROXYSQL40=1` must propagate consistently through five Makefile layers. **A mismatch silently changes the descriptor / services struct layouts** between core and plugin — the link succeeds, the first dispatch corrupts memory.

```
top-level Makefile
   │  PSQL40 := -DPROXYSQL40 (when PROXYSQL40=1)
   │
   ├─► lib/Makefile     (compiles ProxySQL_PluginManager.cpp into libproxysql.a)
   ├─► src/Makefile     (links libproxysql.a)
   ├─► plugins/mysqlx/Makefile   (compiles ProxySQL_MySQLX_Plugin.so)
   └─► test/tap/tests/unit/Makefile  (compiles plugin_*_unit-t / mysqlx_*_unit-t)
                                      adds -DMYSQLX_TEST_BUILD on top
```

**Verifications:**

- `nm src/proxysql | grep -i ProxySQL_PluginManager` is **empty** when built without `PROXYSQL40=1`.
- `nm src/proxysql | grep -i ProxySQL_PluginManager` is **non-empty** when built with `PROXYSQLGENAI=1` (which implies `PROXYSQL40=1`).
- The mysqlx plugin Makefile fails fast if libprotobuf is **not** 3.x (see `plugins/mysqlx/Makefile:38–51`). Already saw this fire on CI in commit `9f5ed235b` — the `cleanbuild` path triggered the check on a v3.0 box without libprotobuf-dev. Fixed by skipping the check on `clean`/`cleanall`.
- CI workflow `.github/workflows/CI-mysqlx.yml` invokes `make` inside `plugins/mysqlx` with **all five tier flags** explicitly: `PROXYSQL40=1 PROXYSQL31=1 PROXYSQLFFTO=1 PROXYSQLTSDB=1 PROXYSQLGENAI=1`. This was added in commit `df7e335e2` after the tests/CI agent caught that the workflow was building the plugin with a different set of tier flags than the cached `src/proxysql` had been built with — exactly the silent struct-layout-mismatch hazard.

---

## 7. Seams where consistency could break

These are the places where the incremental development pattern could have left contradictions — a comment that says one thing while the code does another, two paths that claim to do the same job, an `#ifdef` that forgot to flip somewhere. Each item has a one-line verification.

| # | Concern | Verification |
|---|---|---|
| 1 | The five Makefile layers all see the same tier flags | `make clean && PROXYSQLGENAI=1 make` succeeds; `nm src/proxysql` and `nm plugins/mysqlx/ProxySQL_MySQLX_Plugin.so` both contain `ProxySQL_PluginManager` symbols. |
| 2 | `PROXYSQL40` macro gates every chassis source | `git grep -l 'class ProxySQL_PluginManager\|register_schemas\|invoke_register_schemas_phase' include lib src` — every hit should be inside an `#ifdef PROXYSQL40` block (or in a header that is itself wrapped). |
| 3 | The chassis is invisible to v3.x | `make clean && make` (no flags) — no chassis-related symbols in the binary. |
| 4 | The ordered startup in main.cpp matches the lifecycle invariant | Discovery/CLI → definitive parse → schemas → Admin DBs → early actions → init → start → runtime-ready. No reordering. |
| 5 | The descriptor `register_schemas` is gated by `abi_version >= 2` | `lib/ProxySQL_PluginManager.cpp:407` — the read is inside `if (descriptor->abi_version >= 2u)`. |
| 6 | `materialize_plugin_tables()` is gone (was a no-op disguised as load-bearing) | `git grep materialize_plugin_tables` returns only the explanatory comment in `Admin_Bootstrap.cpp:~1351`. |
| 7 | Plugin getters in `ProxySQL_Admin.cpp` are gated | `proxysql_plugin_get_admindb/configdb/statsdb` definitions are inside `#ifdef PROXYSQL40` (line ~342). |
| 8 | Test-only forgery setters do not leak into production | `nm plugins/mysqlx/ProxySQL_MySQLX_Plugin.so | grep inject_identity_for_test` is **empty**. (The test build defines `MYSQLX_TEST_BUILD`; the production build does not.) |
| 9 | `MysqlxConnection::reset()` scrubs backend buffers between pool reuses | `plugins/mysqlx/src/mysqlx_connection.cpp:39–52`: calls `backend_ds_.clear_io_buffers()` (added in commit `4bd4b462b`). |
| 10 | `Mysqlx_Thread::run()` drains sessions on shutdown | `plugins/mysqlx/src/mysqlx_thread.cpp:run()` post-loop walks `sessions_` and calls `shutdown_notify_client()`. |
| 11 | `inet_pton` failure is fatal in `start_connect()` | `plugins/mysqlx/src/mysqlx_connection.cpp:53–67`: returns `-1` with `state_=ERROR_STATE` on parse failure. |
| 12 | `groups.json` lint passes locally | `python3 test/tap/groups/check_groups.py` returns OK (no missing-from-groups, no built-but-unregistered). |
| 13 | All 32 plugin/mysqlx tests carry `@proxysql_min_version:4.0` | `grep -E '^\s*"(mysqlx_\|plugin_\|test_mysqlx_)' test/tap/groups/groups.json \| wc -l` should be 32. (The total tag count `grep -c '@proxysql_min_version:4.0'` includes pre-existing GenAI/AI/MCP tests and is much higher — that's expected, not a bug.) |
| 14 | TLS_PASSTHROUGH (dead code) is gone | `git grep TLS_PASSTHROUGH plugins/` returns nothing. |
| 15 | The dead `#else /* !PROXYSQL40 */` branches in PluginManager are gone | `git grep '!PROXYSQL40' include lib` — no inner `#else` branches inside whole-file PROXYSQL40 wraps. |
| 16 | The orphaned `infras.lst` and `docker-compose-mysqlx.yml` are gone | `ls test/tap/groups/mysqlx-e2e/infras.lst test/infra/docker-compose-mysqlx.yml` returns "No such file or directory" for both. |
| 17 | `g_active_plugin_manager_mutex` is a `std::shared_mutex` (not `std::mutex`) | `grep 'std::shared_mutex g_active_plugin_manager_mutex' lib/ProxySQL_PluginManager.cpp`. |

If all 17 of these check, the consistency concern is largely answered — the pieces line up.

---

## 8. Commit topology

The PR has ~150 commits, but they group naturally into five intent-bands. You don't need to review individually; you need to know which commits drove which design.

### Band 1 — chassis foundation (early April)
The original design + initial implementation. These set the ABI shape.

- `7e1a12b8f` feat: add generic plugin ABI and loader
- `da7e18271` fix: align plugin loader ABI and tests
- `f13463d33` feat(plugin-abi): Step 2.2 — four-phase plugin lifecycle
- `cd15afdd1e` feat: support plugin-owned admin tables and commands
- `2430516600` fix: reject conflicting plugin registrations

If you only read 5 commits, read these.

### Band 2 — mysqlx baseline (early-to-mid April)
The X Protocol plugin built on top of the chassis. ~80 commits, mostly within `plugins/mysqlx/`. These are the "feature work" commits and are best reviewed by reading the result, not the patches — see [`FILE_CHANGES.md`](./FILE_CHANGES.md) area A–L.

### Band 3 — mysqlx hardening (mid-to-late April)
Bug fixes from running the plugin against a real MySQL 8.4. These are the small surgical commits — the kind you'd cherry-pick if you needed to backport a fix.

- `7e2f7828a` fix(mysqlx): make sync transactions atomic on execute() failure
- `c78d7b859` fix(mysqlx): reconcile bind-address changes
- `dd131b0aa` fix(mysqlx): reconcile listeners at startup and on LOAD ROUTES TO RUNTIME
- `3e8c3da9d` fix(mysqlx): preserve backend TLS state past auth handshake
- `82fe27f4b` fix(mysqlx): sync empty source tables to overwrite stale rows
- `e09908179` fix(mysqlx): record stats on unreachable guard
- `76aafdac6` fix(mysqlx): harden check_connect() poll and getsockopt handling
- `bbe812251` fix(mysqlx): reject auth without credential_lookup and release pooled fd

### Band 4 — chassis hardening + invisibility audit (April 19–22)
After the original design landed, an audit found symbols leaking into v3.x and dead code paths. These commits clean that up.

- `3ba92815f` fix(plugin-chassis): make chassis fully invisible in v3.x builds
- `ab9d5a103` fix(plugin-chassis): address deep-review findings
- `6edde821c` fix(glovars): forward-declare debug_level for direct header consumers
- `e20876a45` fix(tests): repair pre-existing mysqlx test build breakage
- `f10411692` fix(plugin-mgr): serialize lifecycle and always reset manager on stop

### Band 5 — review-driven cleanup (this week, April 27)
The independent review of PR #5651 produced 19 findings. These commits address them.

- `9f5ed235b` fix(build,test groups): unblock CI on plugin-chassis (B3 + #6 + lint)
- `4bd4b462b` fix(mysqlx): three blocking protocol/pool correctness bugs (B1 + B2 + parse)
- `04bccec51` chore(plugin-chassis): tighten gating, drop dead paths, gate forgery setters (#9 + #10 + #12 + #13)
- `df7e335e2` fix(ci,infra): pass PROXYSQL40 to plugin build, remove orphaned infra files (#5 + #4 + #18)
- `55e90d1a7` fix(plugin-chassis,mysqlx): chassis read-path scaling, graceful shutdown, hardening (#7 + #8 + #11 + #15 + #16 + #17)

For a complete walk through each finding and how it was addressed, see `git log --grep="PR #5651" --since=2026-04-26`.

---

## 9. Verification checklist

A reviewer who can tick each box has done a fair-quality review of this PR.

### Build
- [ ] `make clean && make` (no flags) succeeds on a v3.0-grade box. `nm src/proxysql | grep ProxySQL_PluginManager` is empty.
- [ ] `make clean && PROXYSQLGENAI=1 make` succeeds. `nm src/proxysql | grep ProxySQL_PluginManager` is non-empty.
- [ ] `cd plugins/mysqlx && PROXYSQL40=1 PROXYSQL31=1 PROXYSQLFFTO=1 PROXYSQLTSDB=1 PROXYSQLGENAI=1 make` produces `ProxySQL_MySQLX_Plugin.so`.
- [ ] `nm plugins/mysqlx/ProxySQL_MySQLX_Plugin.so | grep -i 'visibility\|hidden'` shows hidden visibility default; only `proxysql_plugin_descriptor_v1` exported.

### ABI hygiene
- [ ] 32 plugin/mysqlx test entries carry `@proxysql_min_version:4.0`; verify with the grep in §7 row 13.
- [ ] `python3 test/tap/groups/lint_groups_json.py` returns OK.
- [ ] `python3 test/tap/groups/check_groups.py` returns OK.

### Tests
- [ ] `make build_tap_tests` succeeds with `PROXYSQLGENAI=1`.
- [ ] At least one of the larger unit tests passes: `cd test/tap/tests/unit && ./mysqlx_robustness_unit-t` should report 74/74.
- [ ] `./plugin_lifecycle_unit-t`, `./plugin_dispatch_unit-t`, `./plugin_query_hook_unit-t` all green.

### Sanity (manual)
- [ ] Start ProxySQL with `PROXYSQLGENAI=1` build, `plugins=("/path/to/ProxySQL_MySQLX_Plugin.so")` in proxysql.cnf, and the mysqlx_users / mysqlx_routes tables populated.
- [ ] Connect with `mysqlsh --mysqlx --uri user@host:6033` (or X-Protocol port from your config). A handshake completes; a `SELECT 1` round-trips.
- [ ] `SELECT * FROM stats_mysqlx_routes` shows non-zero counters.
- [ ] `SHUTDOWN` — the client sees a clean disconnect, not a TCP RST. (This validates `shutdown_notify_client()` from §7 row 10.)

### Consistency seams (§7)
- [ ] All 17 rows from §7 verified.

If a reviewer ticks all of the above, this PR has been substantively reviewed.

---

## Appendix: how this PR was assembled

For full transparency, the mysqlx plugin started as PR #5593 (`ProtocolX` branch) targeting `v3.0` directly. The chassis started as PR #5651 (`plugin-chassis` branch) also targeting `v3.0`. PR #5593 was retargeted onto `plugin-chassis` and merged there, so the chassis PR (#5651) now carries both. This is why the commit history includes a mix of "chassis foundation" commits and "mysqlx feature/fix" commits — they were two PRs unified into one for review purposes, since the mysqlx plugin doesn't make sense without the chassis underneath it.

The independent review described in Band 5 above produced this guide as a deliverable.
