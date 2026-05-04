# Plugin Chassis (PR #5651) — File-by-File Inventory

This document catalogues every file added or modified by PR #5651 (branch `plugin-chassis` at HEAD `55e90d1a7` vs base `origin/v3.0` at `6ef036a00`). It's the appendix to [`REVIEW_GUIDE.md`](./REVIEW_GUIDE.md) — use this when you've identified a file in a diff and want to know what it does without reading the full file.

**Scope:** 105 files changed (91 NEW + 14 MODIFIED), +48,749 / −32 lines. Of those:
- ~23,000 lines are mechanically generated protobuf C++ under `plugins/mysqlx/proto/` — described once in §M, not file-by-file.
- ~5,600 lines of handwritten C++ in `plugins/mysqlx/src/` (the X Protocol plugin proper).
- ~2,200 lines of handwritten C++ in `lib/` and `include/` (the chassis core).
- ~12,000 lines of test code under `test/tap/tests/unit/` and `test/tap/tests/`.

Sections **A–G** cover the **chassis core**. Sections **H–O** cover the **mysqlx plugin**. Sections **P–T** cover **tests, CI, infra, docs, and build glue**. Each file row carries: path, status, line-count delta, purpose, key contents, what to spot-check.

---

## A. Chassis: public ABI headers (the contract)

### `include/ProxySQL_Plugin.h` — NEW, 324 lines

- **Purpose:** the C++ ABI a plugin compiles against; all types are file-wide guarded by `#ifdef PROXYSQL40` so v3.x TUs see nothing.
- **Key contents:**
  - `PROXYSQL_PLUGIN_ABI_VERSION` (currently `3`) and `_MAX` (also 3). ABI 1 = original 6-field descriptor; ABI 2 appends `register_schemas` for the four-phase lifecycle; ABI 3 keeps the descriptor layout unchanged from ABI 2 and adds a single `register_runtime_view` callback at the **tail of `ProxySQL_PluginServices`** so plugins can declare admin-side projections of module state. ABI-2 plugins still load on an ABI-3 core (loader range is `[1, 3]`; the trailing services field is invisible to the older compile).
  - `ProxySQL_PluginDescriptor` — 7-field struct `{name, abi_version, init, start, stop, status_json, register_schemas}` returned via `extern "C" proxysql_plugin_descriptor_v1()`.
  - `ProxySQL_PluginServices` — services injected into the plugin: `register_table`, `register_command`, `register_command_alias`, three snapshot stubs (always nullptr today), `log_message`, three `get_*db` getters, `register_query_hook`, `get_prometheus_registry`, `register_runtime_view` (ABI 3, tail-appended). Tail-append discipline.
  - Per-phase availability matrix is documented inline above the struct (Phase B: `register_table` live, DB getters return nullptr; Phase D: full services).
  - Query-hook ABI — `ProxySQL_PluginQueryHookPayload/Result/Action`; one hook per protocol per plugin.
  - Runtime-view ABI — `ProxySQL_PluginRuntimeView{table_name, refresh, opaque}` plus `proxysql_plugin_register_runtime_view_cb`. The refresh callback gets a borrowed `SQLite3DB*` and re-projects module state into the named admin-db table on demand.
  - Header explicitly calls out the `std::string` / `prometheus-cpp` C++-ABI coupling: plugins MUST share toolchain with core.
  - Footer comment block encodes the **separation-of-duties contract**: LOAD reads the editable admin table and hands rows to the module's typed install API (never touches `runtime_<X>`); SAVE dumps module state back to the editable table; `runtime_<X>` is an admin-side projection refreshed by the registered view callback. Disk-tier copies are still plain BEGIN/DELETE/INSERT/COMMIT and still subject to the empty-source-must-clear-destination rule (PR #5643).
- **Spot-check:**
  - Verify `register_schemas` is only dereferenced when `abi_version >= 2`.
  - Verify `register_runtime_view` lives at the END of `ProxySQL_PluginServices`; older plugins compiled against the ABI-2 layout never see the field.
  - Verify the loader rejects `abi_version > PROXYSQL_PLUGIN_ABI_VERSION_MAX` rather than reading past its struct.

### `include/ProxySQL_PluginManager.h` — NEW, 172 lines

- **Purpose:** declares the in-process loader/dispatcher (`ProxySQL_PluginManager`) plus the free-standing helpers main.cpp/Admin call.
- **Key contents:**
  - Class is move-only-ish (copy ctor/assign deleted).
  - Public lifecycle: `load`, `invoke_register_schemas_phase`, `init_all`, `start_all`, `stop_all`; plus `tables(kind)`, `dispatch_admin_command`, `register_command_alias`, `resolve_alias_to_canonical`, `register_query_hook`, `has_query_hook`, `dispatch_query_hook`, `register_runtime_view`, `refresh_runtime_views_for_query`.
  - Free-standing API: `proxysql_get_plugin_manager` (atomic load), `proxysql_load_configured_plugins` (Phase A+B, **publishes** the manager), `proxysql_init_configured_plugins` (Phase D), `proxysql_start_configured_plugins`, `proxysql_stop_configured_plugins`, plus three dispatch helpers (`dispatch_configured_plugin_admin_command`, `dispatch_configured_plugin_query_hook`, lock-free `has_configured_plugin_query_hook`), `resolve_configured_plugin_admin_alias`, and `proxysql_refresh_configured_plugin_runtime_views` (admin pre-SELECT hook).
  - Internal `plugin_handle_t` carries dlopen handle + `schemas_registered/initialized/started/stopped` state flags. `runtime_views_` vector holds `registered_runtime_view_t{table_name, refresh, opaque}` entries.
  - Two services structs: `services_` (Phase D, full services) and `services_phase_b_` (Phase B, with stubbed DB getters and stubbed `register_query_hook`). **`register_runtime_view` is wired in BOTH structs** — plugins typically declare runtime views alongside their tables in `register_schemas`, so the callback is live in Phase B as well as Phase D.
- **Spot-check:**
  - Lifecycle invariant: `proxysql_init_configured_plugins` must run BEFORE any worker thread takes the lock-free read path.
  - `resolve_alias_to_canonical` returns `std::string` by value (not borrowed `c_str()`) so a concurrent reload between resolve and dispatch can't dangle a pointer.

---

## B. Chassis: loader implementation

### `lib/ProxySQL_PluginManager.cpp` — NEW, 1,038 lines, file-wide gated under `PROXYSQL40`

- **Purpose:** dlopen orchestration, services trampolines, lifecycle state machine, dispatch.
- **Key contents:**
  - **Concurrency model:** `g_active_plugin_manager` is a `std::atomic<ProxySQL_PluginManager*>`; reads/writes coordinated via `g_active_plugin_manager_mutex` (`std::shared_mutex` — readers from dispatch/resolve paths share, publishers/unpublishers take unique). A separate `std::mutex g_plugin_lifecycle_mutex` serializes load/start/stop transitions. The shared-mutex change exists explicitly to keep query-hook dispatch from collapsing per-worker thread parallelism.
  - **Service trampolines** (file-static): `register_table_service`, `register_command_service`, `register_command_alias_service`, `register_query_hook_service`, `register_runtime_view_service`, `get_admindb/configdb/statsdb_service`, `log_message_service`, `get_prometheus_registry_service`. Each writes to `g_registry_target` set by a `ScopedRegistryTarget` RAII guard around plugin callbacks; `note_registration_failure` records the first failure.
  - **`sql_references_table_ci()`** is the matcher used by `refresh_runtime_views_for_query`: case-insensitive whole-identifier substring match treating `[A-Za-z0-9_]` as identifier characters. So `runtime_mysqlx_users` matches in `` SELECT * FROM `runtime_mysqlx_users` `` but NOT in `runtime_mysqlx_users_extra` or `stats_runtime_mysqlx_users`.
  - **`load()`** (lines 324–383): rejects duplicate paths; `dlopen(RTLD_NOW|RTLD_LOCAL)`; resolves `proxysql_plugin_descriptor_v1`; rejects null/empty `name` and `abi_version` outside `[1, PROXYSQL_PLUGIN_ABI_VERSION_MAX]`.
  - **`invoke_register_schemas_phase()`** (lines 386–461): Phase B; only reads `descriptor->register_schemas` when `abi_version >= 2`; snapshots `tables_*`/`commands_`/storage sizes and rolls back on failure to keep retries idempotent.
  - **`init_all()`** has the same snapshot/rollback contract.
  - **`stop_all()`** (lines 548–576): pairs `stop()` with `init()`, NOT with `start()` — every plugin whose init succeeded gets stop, even if its own start failed (teardown symmetry to avoid leaks). Plugins are marked `stopped=true` even on failure; idempotent across destructor.
  - **`canonicalize_plugin_command()`**: trims, strips trailing `;`, collapses internal whitespace.
  - **Alias collision rules** in `register_command_alias` (lines 765–809): rejects shadowing another command's canonical or alias; idempotent for duplicates.
  - **Publish ordering** in `proxysql_load_configured_plugins` (lines 896–963): manager is installed as active **before** Phase D so `ProxySQL_Admin::init` can read tables via `proxysql_get_plugin_manager`. Comments call out the unsafe-reordering hazard.
  - **`stop_configured_plugins`** clears the active pointer before calling `stop_all`, then `manager.reset()` always runs (so the `.so` is unmapped even if a plugin's stop returned false).
- **Spot-check:**
  - Confirm the `descriptor->register_schemas` access is gated behind the `abi_version >= 2u` check.
  - Verify the `RTLD_LOCAL` flag — no plugin should pollute the global symbol table.
  - Confirm `proxysql_dispatch_configured_plugin_query_hook` calls `g_active_plugin_manager.load()` AFTER taking the shared lock; the lock-free `proxysql_has_configured_plugin_query_hook` is documented to allow false positives.

---

## C. Chassis: admin integration

### `lib/Admin_Bootstrap.cpp` — MODIFIED, +57 lines

- **Purpose:** merges plugin-declared schemas into `tables_defs_{admin,config,stats}` so the existing `check_and_build_standard_tables` DDL pass materializes them.
- **Key contents:**
  - `ProxySQL_Admin::init()` consults `proxysql_get_plugin_manager()`, walks each `ProxySQL_PluginDBKind`, dedup-checks against existing tables, and appends via `insert_into_tables_defs`. On a name conflict it logs and returns false — the caller (now wired to exit) treats this as fatal.
  - Trailing comment block (lines ~1346) explains why `materialize_plugin_tables()` was deleted: it was a post-init no-op since the merge already happens here.
- **Spot-check:**
  - Verify `init()` returns false on the conflict path AND that `src/main.cpp` actually checks the return value.
  - Note the indentation churn around `#ifdef PROXYSQLGENAI` — review for accidental scope changes.

### `lib/Admin_Handler.cpp` — MODIFIED, +43 lines

- **Purpose:** generic dispatch path replacing the previous hard-coded MYSQLX alias ladder.
- **Key contents:**
  - `admin_session_handler()` calls `proxysql_resolve_configured_plugin_admin_alias(query_str)` early; if a canonical comes back, the handler invokes `SPA->dispatch_plugin_admin_command(sess, plugin_canonical.c_str())` and short-circuits.
  - On the rare race where resolve found a command but dispatch returned false (plugin uninstalled between calls), responds with "Plugin failed to handle registered command".
- **Spot-check:**
  - Confirm `plugin_canonical` is held by value (`std::string`), not as a raw pointer.
  - Verify the new branch sits BEFORE the generic LOAD/SAVE handler.

### `lib/ProxySQL_Admin.cpp` — MODIFIED, +42 lines

- **Purpose:** exposes admin/config/stats DB handles to the loader, adds the templated dispatcher, and wires the pre-SELECT runtime-view dispatch.
- **Key contents:**
  - Three free functions `proxysql_plugin_get_admindb/configdb/statsdb()` return `GloAdmin->{admindb,configdb,statsdb}` if `GloAdmin` is non-null. Gated by `PROXYSQL40` so v3.x exports no plugin-aware symbols at all.
  - `ProxySQL_Admin::dispatch_plugin_admin_command<S>(sess, sql)` builds a `ProxySQL_PluginCommandContext{admindb,configdb,statsdb}`, calls `proxysql_dispatch_configured_plugin_admin_command`, and translates `result` into `send_ok_msg_to_client` / `send_error_msg_to_client`.
  - Explicit template instantiations for `MySQL_Session` and `PgSQL_Session`.
  - **Pre-SELECT runtime-view dispatch in `GenericRefreshStatistics`** (around line 1654): `proxysql_refresh_configured_plugin_runtime_views(query_no_space, admindb)` is called for **every admin-port query**, gated only on `if (admin)` and placed **outside** the existing `if (refresh==true)` block. The chassis itself decides whether any plugin's refresh callback fires, by case-insensitive whole-identifier substring match against the query (matching the wording used in section B for the `sql_references_table_ci` matcher) — a query that touches no registered view is a cheap no-op (one shared lock + N substring scans). The `refresh` flag is left untouched; it gates a separate set of core-only refreshes (stats_mysql_processlist, runtime_mysql_users, etc.).

### `include/proxysql_admin.h` — MODIFIED, +8 lines

Declares the templated dispatcher and pulls `ProxySQL_Plugin.h`. Gating matches the cpp instantiation gate.

---

## D. Chassis: startup wiring

### `src/main.cpp` — MODIFIED, +73 lines

- **Purpose:** owns the `GloPluginManager` unique_ptr and threads it through `ProxySQL_Main_init_phase2`.
- **Key contents:**
  - `static std::unique_ptr<ProxySQL_PluginManager> GloPluginManager;` (file scope).
  - Four wrapper functions: `LoadConfiguredPlugins`, `InitConfiguredPlugins`, `StartConfiguredPlugins`, `StopConfiguredPlugins`. Each `exit(EXIT_FAILURE)` on error during startup; shutdown only logs.
  - `UnloadPlugins()` now calls `StopConfiguredPlugins` first, before tearing down the legacy plugin .sos.
  - Ordering in `ProxySQL_Main_init_phase2___not_started`: `LoadConfiguredPlugins` → `ProxySQL_Main_init_Admin_module` → `InitConfiguredPlugins` → `StartConfiguredPlugins`.
  - `ProxySQL_Main_init_Admin_module` now checks `GloAdmin->init()` return and exits on failure.
  - Config parsing: `proxysql_load_plugin_modules_from_config(root, GloVars.plugin_modules)` from the libconfig `Setting&`.
- **Spot-check:**
  - Phase-D-before-workers ordering: confirm `Init/StartConfiguredPlugins` complete before the worker-thread spawning later in `ProxySQL_Main_init_phase3___start_all`.
  - Verify `GloPluginManager` is at file scope, not function-local — destructor needs to run during process teardown.

### `include/proxysql_glovars.hpp` and `lib/ProxySQL_GloVars.cpp` — MODIFIED, +25 / +26 lines

- **Purpose:** add the `plugin_modules` `std::vector<std::string>` to GloVars and the libconfig parser helper.
- **Key contents:**
  - Header gains a forward decl of `_debug_level` (works around a circular include when plugin unit tests pull in `proxysql_glovars.hpp` directly without `proxysql_structs.h`).
  - Free function `proxysql_load_plugin_modules_from_config(const Setting& root, std::vector<std::string>& plugin_modules)`: clears, reads `plugins` setting, pushes each string entry. Silently skips non-string entries.
  - Constructor and destructor explicitly clear `plugin_modules`.

---

## E. Chassis: build system

### `Makefile` (top-level) — MODIFIED, +41 / −14 lines

- **Purpose:** introduces `PROXYSQL40` tier, propagates the macro and runs the mysqlx plugin sub-build.
- **Key contents:**
  - Tier hierarchy: `PROXYSQLGENAI` ⇒ `PROXYSQL40` ⇒ `PROXYSQL31`.
  - `PROXYSQL40=1` triggers a major-version bump (3.0.x → 4.0.x) via the same awk recipe.
  - Each `build_src_*` target conditionally `cd plugins/mysqlx && $(MAKE)` (skipped if `PROXYSQL40` unset).
  - `clean*` targets descend into `plugins/mysqlx`. Top-level `cleanbuild` recurses unconditionally; the plugin Makefile gates its protobuf check to avoid breaking on `clean` (commit `9f5ed235b`).
  - `install`/`uninstall` add `/usr/lib/proxysql/plugins/ProxySQL_MySQLX_Plugin.so`.

### `lib/Makefile` and `src/Makefile` — MODIFIED, +8 / +7 lines

Wire `PSQL40` into compile flags; add `ProxySQL_PluginManager.oo` to `_OBJ_CXX`.

---

## F. Chassis: documentation

### `doc/PLUGIN_API.md` — NEW, 470 lines

Reference for plugin authors; covers loading, four-phase startup, descriptor contract, services, ABI versioning, the empty-source-sync invariant. **For PR-reviewer documentation, see [`REVIEW_GUIDE.md`](./REVIEW_GUIDE.md) and [`ABI.md`](./ABI.md).**

---

## G. Chassis: test scaffolding

### `test/tap/test_helpers/fake_plugin.cpp` — NEW, 280 lines

The harness plugin source; one .cpp builds two .sos (`fake_plugin` and `fake_plugin2`) via `-DFAKE_PLUGIN_NAME=` / `-DFAKE_PLUGIN_ENV_PREFIX=`.

- Three descriptors exposed: `fake_descriptor` (ABI 1, 6 fields), `fake_descriptor_with_phase_b` (ABI 2), `fake_descriptor_bogus_abi` (version 99 — exercises rejection).
- Behaviour toggles via env vars (`PROXYSQL_FAKE_PLUGIN_*`): `INIT_FAIL`, `START_FAIL`, `STOP_FAIL`, `FORCE_BOGUS_ABI`, `ENABLE_PHASE_B`, `_PHASE_B_FAIL`, `_PHASE_B_REGISTER_TABLE`, `_PHASE_B_TOUCH_HANDLES`, `_PHASE_B_PARTIAL_THEN_FAIL`, `HOOK_DENY`. Each emits a log line so tests can assert lifecycle ordering.
- `fake_query_hook` echoes `payload.query_text` back; deny vs allow controlled by env.

---

## H. Mysqlx plugin: entry point

### `plugins/mysqlx/include/mysqlx_plugin.h` — NEW, 74 lines

- Public surface of the plugin — declares `MysqlxPluginContext` and the listener-reconcile entry points.
- `MysqlxPluginContext` holds `services` pointer (chassis ABI), `unique_ptr<MysqlxConfigStore>`, `vector<unique_ptr<Mysqlx_Thread>>`, `route_to_thread` map + mutex + `next_rr_index` for RR thread assignment.
- `mysqlx_reconcile_listeners()` is `__attribute__((weak))` so unit tests linking just admin_schema.cpp resolve cleanly; production .so always has the strong def.
- `mysqlx_reconcile_listeners_impl()` is the pure variant for tests.

### `plugins/mysqlx/src/mysqlx_plugin.cpp` — NEW, 270 lines

- Implements the `ProxySQL_PluginDescriptor` entry exported via `proxysql_plugin_descriptor_v1()`.
- Four-phase lifecycle: `mysqlx_register_schemas` (Phase B, services without DB), `mysqlx_init` (Phase D, DB live), `mysqlx_start`, `mysqlx_stop`.
- `replace_table_atomically()` — every `admindb.execute()` return is checked; defensive ROLLBACK on any failure including post-COMMIT, addresses the v3.0 silent-wipe bug.
- `mysqlx_start()` does `sync_disk_to_memory()` (configdb → editable mysqlx_* tables) then four `install_<X>_from_admin` calls to populate the in-memory `MysqlxConfigStore` directly from the editable admin tables — no `runtime_mysqlx_*` write happens here, since runtime tables are now admin-side projections, not a tier the plugin maintains. Then clamps pool size 1..64 and drives `mysqlx_reconcile_listeners()` on the same path used by `LOAD MYSQLX ROUTES TO RUNTIME`.
- `parse_bind_addr()` handles both `host:port` and `[ipv6]:port`; default port 33060.
- Descriptor is constexpr-ish and pinned to `PROXYSQL_PLUGIN_ABI_VERSION`.

---

## I. Mysqlx plugin: admin schema integration

### `plugins/mysqlx/include/mysqlx_admin_schema.h` — NEW, 8 lines
Single-symbol header declaring `mysqlx_register_admin_schema()`.

### `plugins/mysqlx/src/mysqlx_admin_schema.cpp` — NEW

- Registers DDL for all `mysqlx_*` tables and the `LOAD/SAVE` admin commands.
- Four config-table pairs (memory + runtime): `mysqlx_users`, `mysqlx_routes`, `mysqlx_backend_endpoints`, `mysqlx_variables`, all with `JSON_VALID(attributes)` CHECK constraints.
- Two stats-only tables: `stats_mysqlx_routes`, `stats_mysqlx_processlist`.
- 8 LOAD/SAVE TO RUNTIME commands plus 8 disk variants; each has alias group (`FROM MEMORY`, `FROM MEM`, `TO RUN`, etc.) registered via `register_command_alias`.
- LOAD/SAVE callbacks no longer copy between admin tables. Each `load_<X>_to_runtime` callback invokes `MysqlxConfigStore::install_<X>_from_admin(admindb, err)` (read editable mysqlx_<X>, swap into the module's in-memory state under its own lock). Each `save_<X>_from_runtime` callback invokes `MysqlxConfigStore::save_<X>_to_admin_table(admindb)` (dump module state into the editable mysqlx_<X> table). Disk-tier copies (LOAD/SAVE FROM/TO DISK) remain plain BEGIN/DELETE/INSERT/COMMIT between configdb and admindb.
- Four free functions `refresh_users_runtime_view` / `refresh_routes_runtime_view` / `refresh_endpoints_runtime_view` / `refresh_variables_runtime_view` are registered at schema-registration time via `services.register_runtime_view({"runtime_mysqlx_<X>", &refresh_<X>_runtime_view, nullptr})`. Each calls `MysqlxConfigStore::project_<X>_to_runtime_view(admindb)` to wipe the destination admin-db table and refill it from the module's in-memory state. The chassis fires the relevant callback before any admin SELECT against the projected table.
- `load_routes_to_runtime` calls `mysqlx_reconcile_listeners` weak-pointer if non-null.

---

## J. Mysqlx plugin: configuration runtime

### `plugins/mysqlx/include/mysqlx_config_store.h` — NEW
### `plugins/mysqlx/src/mysqlx_config_store.cpp` — NEW

- **Authoritative in-memory source of truth** for X-protocol routing/identity state. Sessions/threads consume it directly; the `runtime_mysqlx_*` tables in admin_db are admin-side projections of this store, refilled on demand by the plugin's runtime-view refresh callbacks (see §I).
- `MysqlxResolvedIdentity` (was `MysqlxCredentials` — renamed in `84bbdfdca`); now carries a `comment` field.
- `MysqlxRoute` also carries a `comment` field.
- `MysqlxBackendAuthMode` enum: `mapped` / `service_account` / `pass_through`.
- Public struct `MysqlxBackendEndpointOverride{hostname, mysql_port, mysqlx_port, use_ssl, attributes, comment}` — promoted from a file-local `MysqlxEndpointOverride` so SAVE / projection can round-trip the per-(hostname, mysql_port) overrides.
- API: per-entity install / save / project triplets — `install_users_from_admin(db, err)` / `save_users_to_admin_table(db)` / `project_users_to_runtime_view(db)`, same shape for routes / endpoints / variables; convenience `install_all_from_admin(db, err)` (test-only fixture helper); `snapshot_active_routes()` returning `vector<pair<name, bind>>` for the listener reconciler; plus the read-side `resolve_identity`, `pick_endpoint`, `route_hostgroup`, `route_exists`.
- `mutable std::shared_mutex mutex_` — readers (resolve_identity, pick_endpoint, route_exists, snapshot_active_routes, project_*_to_runtime_view) take shared locks; install_*_from_admin takes exclusive. Each install is independent: LOAD MYSQLX USERS does not touch routes/endpoints/variables.
- `install_users_from_admin()` reads the editable `mysqlx_users` plus cross-module `runtime_mysql_users` (canonical password/hostgroup); `install_endpoints_from_admin()` reads the editable `mysqlx_backend_endpoints` and cross-module `runtime_mysql_servers WHERE status='ONLINE'`. None of the install paths touch any `runtime_mysqlx_*` table — those are projections, not inputs.
- `endpoint_overrides_` (the public-struct overrides) is preserved across install_endpoints calls so SAVE can round-trip and the runtime-view projection faithfully reflects what was loaded.
- `pick_from_hostgroup()` supports `first_available` and `round_robin[_with_fallback]`; round-robin uses a separate `rr_mutex_` so RR state doesn't interfere with config swaps.
- Test-only `install_for_test` is unconditionally available — note it bypasses `install_*_from_admin`.

---

## K. Mysqlx plugin: listener reconciliation

### `plugins/mysqlx/src/mysqlx_listener_reconcile.cpp` — NEW

- Desired-state reconciler from the `MysqlxConfigStore` (the authoritative in-memory state) to per-thread listener fds. Signature is `mysqlx_reconcile_listeners_impl(const MysqlxConfigStore& store, ...)` — no DB handle.
- 3-step algorithm: snapshot desired set → remove stale/mis-bound listeners → add missing listeners (RR over thread pool).
- Bind-change detection compares `threads[tidx]->get_listener_addr_for_route()` to `host:port` string; mismatch is treated as remove+add.
- Single-admin-thread assumption is documented inline; the desired set comes from `store.snapshot_active_routes()` (taken under the store's shared lock, dropped before listener fd manipulation) rather than a SELECT against `runtime_mysqlx_routes`. An inline comment calls out why we deliberately do NOT read `runtime_mysqlx_routes` here: that table is an on-demand admin-side projection of the store, only populated when admin runs a SELECT against it; reading it from the LOAD path would see empty/stale data on every startup and every `LOAD MYSQLX ROUTES TO RUNTIME` call.
- RR cursor `next_rr_index` is wrapped via `((next_rr_index % pool) + pool) % pool` — defensive against negative.
- **Note:** if `add_listener` fails (port in use), the route is silently not added to `route_to_thread`; operator gets no error feedback beyond the chassis-level log. Future enhancement opportunity.

---

## L. Mysqlx plugin: protocol layer

### `plugins/mysqlx/include/mysqlx_protocol.h` — NEW, 65 lines
### `plugins/mysqlx/src/mysqlx_protocol.cpp` — NEW, 298 lines

- Frame-level helpers — `MysqlxFrameHeader` (4-byte LE size + 1-byte type), 16 MB cap, encode/decode, blocking `read_exact` / `write_all`, `send_error`/`send_ok` over a raw fd, hex helpers, MYSQL41 SHA1 scramble/verify routines.
- SHA1 via OpenSSL EVP API (3.0+ clean).
- MYSQL41 implementation: `stage1=SHA1(pw)`, `stage2=SHA1(stage1)`, `scramble=stage1 XOR SHA1(challenge||stage2)`. Verifier uses `CRYPTO_memcmp` (constant-time).
- `mysqlx_mysql41_verify_hash()` works against a stored stage2 hash (server-side compute) — important since plugin only stores hash, not plaintext.
- `mysqlx_build_frame()` rejects payloads >= `MYSQLX_MAX_PAYLOAD_SIZE` so the +1 cannot wrap.
- `mysqlx_send_error/ok` use Mysqlx::Error / Mysqlx::Ok protobufs; these are the sync (blocking) helpers used outside the data-plane (init paths, fatal frames).

---

## M. Mysqlx plugin: data stream

### `plugins/mysqlx/include/mysqlx_data_stream.h` — NEW, 138 lines
### `plugins/mysqlx/src/mysqlx_data_stream.cpp` — NEW, 373 lines

- Buffered I/O with optional in-memory BIO-wrapped SSL: `read_buf_/write_buf_`, deque of complete `MysqlxFrame`s, `ssl_write_buf_` for outbound encrypted bytes, `parse_error_` flag, `poll_fds_idx`, status enum.
- `init()` sets non-blocking; `close_and_reset()` tears SSL + clears everything; `clear_io_buffers()` (added in commit `4bd4b462b`) scrubs only buffers and parse-error, preserving SSL/BIO/encrypted state — used by `MysqlxConnection::reset()` between pool reuses.
- `try_parse_frame()` validates `1 <= payload_size <= 16 MB`, sets `parse_error_=true` on out-of-range, slides read window after >4 KiB consumed.
- SSL path uses memory BIOs: `read_from_net()` pumps `recv → BIO_write(rbio_ssl_)`, then `SSL_read` into `feed_bytes`. `write_to_net()` `SSL_write`s app data, then `queue_encrypted_output()` via `BIO_read(wbio_ssl_)` and `flush_ssl_write_buf()`.
- `do_ssl_handshake()` post-handshake drain: **64 KiB `static thread_local` scratch** (commit `55e90d1a7`) — avoids the worker stack on ASan / large-pool builds.
- SSL_read returning 0 surfaced as connection close (close_notify) rather than WANT_IO.

---

## N. Mysqlx plugin: backend connection

### `plugins/mysqlx/include/mysqlx_connection.h` — NEW, 135 lines
### `plugins/mysqlx/src/mysqlx_connection.cpp` — NEW, 318 lines

- Pooled outbound connection holding fd, hostgroup, user/schema, transaction/prepared-stmt flags, the backend `MysqlxDataStream`, optional `SSL_CTX*`, and a 10-state `BackendAuthState` enum.
- `start_connect()` uses `inet_pton(AF_INET, host, ...)` and **rejects non-IPv4-literal hostnames** (commit `55e90d1a7` — previously the return was discarded and a hostname silently became 0.0.0.0).
- `check_connect()` polls with timeout vs `connect_timeout_ms_`, checks `SO_ERROR`.
- Backend auth state machine: capabilities GET → CapabilitiesSet (advertise MYSQL41 + optional `tls=true`) → optional TLS handshake → AuthenticateStart → AuthenticateContinue (compute scramble) → AuthenticateOk.
- `read_auth_frame()` filters out leading NOTICE frames (backends emit session-state-change notices); previously caused the auth state machine to spin to handshake timeout.
- `step_auth_authenticate_start_sent()`: **`ParseFromArray` return is now checked** (commit `4bd4b462b`); previously a malformed AuthenticateContinue produced an undefined-input scramble.
- `reset()` calls `backend_ds_.clear_io_buffers()` to scrub straggler frames between pool checkouts while preserving the SSL session.

---

## O. Mysqlx plugin: session state machine — the core

### `plugins/mysqlx/include/mysqlx_session.h` — NEW, 301 lines

- Per-client session state. The big enum is `MysqlxSession::Status` (21 values).
- `Status` enum drives `handler()`. Compression negotiation state: `MysqlxCompressionAlgo` (NONE / ZSTD_STREAM / LZ4_MESSAGE), combine-mixed flag, max-combine count.
- Lazy zstd contexts (`ZSTD_DCtx*`, `ZSTD_CCtx*`) opaquely forward-declared; only the .cpp pulls `<zstd.h>`.
- Test-only forgery setters (`inject_identity_for_test`, `resolve_backend_target_for_test`) are gated behind `MYSQLX_TEST_BUILD` (commit `04bccec51`); read-only `target_*_for_test` getters remain unconditional.
- `MysqlxTlsMode`: only `TLS_OFF` / `TLS_TERMINATE` remain — the dead `TLS_PASSTHROUGH` was removed in `55e90d1a7` (it never set up a real opaque pipe).

### `plugins/mysqlx/src/mysqlx_session.cpp` — NEW, 1,604 lines (the biggest file)

State → handler mapping (from `handler()` switch at line 187):

| State | Handler | Role |
|---|---|---|
| `CONNECTING_CLIENT` | `handler_connecting_client()` (L230) | initial frame intake; routes to capabilities or auth |
| `X_CAPABILITIES_GET` | `handler_capabilities_get()` (L265) | emits supported caps incl. tls + compression list |
| `X_CAPABILITIES_SET` | `handler_capabilities_set()` (L352) | parses CapabilitiesSet; **5051/5052 errors on malformed body** (commit `4bd4b462b`); two-pass for compression vs tls |
| `X_AUTH_START` | `handler_auth_start()` (L520) | dispatches PLAIN vs MYSQL41 |
| `X_AUTH_CHALLENGE_SENT` | `handler_auth_challenge_response()` (L561) | verifies MYSQL41 scramble, then `resolve_backend_target()` before send_auth_ok |
| `WAITING_CLIENT_XMSG` | `handler_waiting_client_msg()` (L724) | data-plane client → backend pump; calls `dispatch_client_message()` (L653) which intercepts Compression frames |
| `CONNECTING_SERVER` | `handler_connecting_server()` (L1028) | drives backend connect + auth state machine |
| `WAITING_SERVER_XMSG` | `handler_waiting_server_msg()` (L801) | backend → client pump; routes through `send_to_client_compressed()` |
| `X_TLS_ACCEPT_INIT` | `handler_tls_accept_init()` (L918) | drives client-side `do_ssl_handshake()` |
| `X_SESSION_RESET_WAITING` | `handler_session_reset_waiting()` (L856) | observes terminal frame for SessionReset |
| `X_SESSION_CLOSING` | `handler_session_closing()` (L912) | drains and marks unhealthy |

States `X_AUTH_OK_SENT`, `X_AUTH_FAILED`, `X_TLS_ACCEPT_CONT/DONE`, `X_TLS_CONNECT_*`, `X_SESSION_CLOSED`, `PROCESSING_X_QUERY` are reachable as transient or sentinel values but have no dedicated handler in the dispatch.

Other notable members:
- `resolve_backend_target()` (L956) — error codes 4000 (empty default_route), 4001 (unknown route), 4002 (no endpoints); records `mysqlx_stats().record_conn_err()`.
- `shutdown_notify_client()` (L1143) — commit `55e90d1a7`: enqueues 1053 fatal Error, single-pass `write_to_net()`, `SSL_set_quiet_shutdown(1)+SSL_shutdown`, then `status=X_SESSION_CLOSING`. Idempotent and skipped if fd<0 or already closing.
- Compression Phase 1: negotiation in `handler_capabilities_set`; Phase 2: `handle_compression_message()` (L1292); Phase 3: `send_to_client_compressed()` (L1576), `emit_single_compressed()`, `emit_batched_compressed()`, `flush_compression_batch()`.

---

## P. Mysqlx plugin: worker thread

### `plugins/mysqlx/include/mysqlx_thread.h` — NEW, 123 lines
### `plugins/mysqlx/src/mysqlx_thread.cpp` — NEW, 419 lines

- Owns listener fds, accept loop, poll set, sessions, per-thread connection cache.
- Parallel listener vectors (`listener_fds_`, `listener_addrs_`, `listener_ports_`, `listener_route_names_`) protected by `listener_mutex_`. Invariant: same length, same index = same listener.
- `signal_pipe_` for cross-thread wakeup (used by `stop()`).
- `run()` loop: 200 ms poll timeout, `rebuild_poll_set()`, `process_ready_fds()`, `process_all_sessions()`. **After loop exit, walks sessions and calls `shutdown_notify_client()` under `sessions_mutex_`** (commit `55e90d1a7`).
- `process_all_sessions()` only invokes `handler()` when there's actual work (revents set, buffered frames, or `to_process` flag) — perf fix from commit `a2e99eed5`.
- Two timeouts: `HANDSHAKE_TIMEOUT_MS = 10s` for pre-auth, `IDLE_TIMEOUT_MS = 28800000` (8h) for established.
- `accept_new_connection()` enforces `max_sessions_`, sets TCP_NODELAY, attaches a closure that resolves identity via the `MysqlxConfigStore`.
- Connection cache LRU: scan from rbegin, match (hostgroup, user, schema, reusable); evict oldest at front when over `max_cached_`.
- `add_listener()` uses SO_REUSEADDR, accepts dotted-quad bind or "" → INADDR_ANY.
- `remove_listener_for_route()` does **NOT** disturb in-flight sessions — documented inline. Route-name lookup only happens at backend-target resolution (auth time), so an authenticated session continues regardless.
- `get_ssl_ctx()` returns `GloVars.get_SSL_ctx()` — leverages the chassis-owned cert.

---

## Q. Mysqlx plugin: stats

### `plugins/mysqlx/include/mysqlx_stats.h` — NEW, 59 lines
### `plugins/mysqlx/src/mysqlx_stats.cpp` — NEW, 113 lines

- Per-route atomic counters with periodic SQLite flush.
- `MysqlxRouteStats` uses `std::atomic<uint64_t>` for conn_ok/err/used and bytes counters.
- `record_conn_*` take `mutex_` (not just atomic) so the `last_conn_err_` test sentinel is consistent with the increment.
- `flush_to_sqlite()` builds INSERT via `std::string` (not snprintf into 1024 buf — fix for the silent-truncate bug on long route names) and `sqlite_escape()` doubles single quotes.
- Singleton `mysqlx_stats()`.

---

## R. Mysqlx plugin: build system

### `plugins/mysqlx/Makefile` — NEW, 150 lines

- Builds `ProxySQL_MySQLX_Plugin.so` standalone, sourcing repo-root includes.
- Auto-detects repo root by walking up for `src/proxysql_global.cpp` (12-hop limit + clear error).
- **Protobuf 3.x ABI guard:** `pkg-config --modversion protobuf`, fails fast unless major == 3 (the .pb.cc was generated with 3.21.12; protobuf 4.x changed SONAME). **Guard skipped on `clean`/`cleanall`** (commit `9f5ed235b`).
- `-fvisibility=hidden -fvisibility-inlines-hidden`: only `proxysql_plugin_descriptor_v1` is exported (it's `extern "C"`); avoids ODR collisions with proxysql core under `dlopen`.
- Hardening: `_FORTIFY_SOURCE=2` (skipped under ASan or `-O0`), `-fstack-protector-strong`, `-fPIC`.
- Propagates feature flags `PROXYSQL40/31/FFTO/TSDB/GENAI` from the top-level build.
- Static-links `deps/zstd/zstd/lib/libzstd.a` and `deps/lz4/lz4/lib/liblz4.a` since RTLD_LOCAL means transitive symbols from the proxysql binary are not visible.
- Dynamic links: `-lprotobuf -lssl -lcrypto`.

---

## S. Mysqlx plugin: generated protobuf

### `plugins/mysqlx/proto/` — 8 `.pb.cc` + 8 `.pb.h` (~23k LOC total)

- **Files:** `mysqlx`, `mysqlx_connection`, `mysqlx_session`, `mysqlx_datatypes`, `mysqlx_notice`, `mysqlx_sql`, `mysqlx_resultset`, `mysqlx_expect`.
- **Status:** Mechanically generated. **Do not review line-by-line.**
- **Source:** `test/deps/mysql-connector-c-8.4.0/.../plugin/x/protocol/protobuf/*.proto` via protoc 3.21.12.
- **Regen recipe** (from Makefile lines 22-27):
  ```
  PROTO_SRC=test/deps/mysql-connector-c-8.4.0/mysql-8.4.0/plugin/x/protocol/protobuf
  protoc --proto_path=$PROTO_SRC --cpp_out=plugins/mysqlx/proto \
    mysqlx.proto mysqlx_connection.proto mysqlx_session.proto \
    mysqlx_datatypes.proto mysqlx_notice.proto mysqlx_sql.proto \
    mysqlx_resultset.proto mysqlx_expect.proto
  ```
- Compile flags: built with `-w` (warnings off) — generator does not promise warning-free output across compilers.

---

## T. Tests, CI, infra

### T.1 New unit tests under `test/tap/tests/unit/`

All 28 are **NEW** and **gated under `PROXYSQL40=1`**. All are pure in-process — no Docker, no MySQL backend; they link against `libproxysql.a` plus selected `plugins/mysqlx/src/*.cpp` source files compiled directly into the test binary with `-DMYSQLX_TEST_BUILD`. Several use a socketpair for fake I/O.

**Total: 985 `plan(...)` assertions** across the 28 unit tests (640 mysqlx-side + 345 plugin-chassis-side).

| File | LOC | `plan()` | Scope |
|---|---|---|---|
| `plugin_config_unit-t.cpp` | 364 | 48 | manager config-load + per-plugin variable round-trip |
| `plugin_dispatch_unit-t.cpp` | 389 | 52 | global `proxysql_dispatch_configured_plugin_admin_command` |
| `plugin_lifecycle_unit-t.cpp` | 294 | 26 | four-phase plugin lifecycle (Phase B then Phase D, ordering, partial rollback) |
| `plugin_manager_unit-t.cpp` | 464 | 96 | end-to-end manager driver (load/init/start/stop/unload, multi-plugin) |
| `plugin_prometheus_unit-t.cpp` | 110 | 10 | `get_prometheus_registry` returns `GloVars.prometheus_registry` |
| `plugin_query_hook_unit-t.cpp` | 283 | 46 | pre-execution query hook (`deny|allow`); manager-level register |
| `plugin_registry_unit-t.cpp` | 334 | 68 | in-process descriptor registry; admin-command alias dispatch |
| `mysqlx_admin_commands_unit-t.cpp` | 181 | 27 | `LOAD/SAVE MYSQLX TO/FROM RUNTIME\|MEMORY\|DISK` admin commands |
| `mysqlx_admin_disk_commands_unit-t.cpp` | 205 | 32 | `LOAD/SAVE MYSQLX TO/FROM DISK` against on-disk SQLite |
| `mysqlx_admin_schema_unit-t.cpp` | 141 | 25 | `mysqlx_users` and route table DDL string contents |
| `mysqlx_backend_auth_unit-t.cpp` | 302 | 42 | backend auth state machine; uses `inject_identity_for_test` (gated to `MYSQLX_TEST_BUILD`) |
| `mysqlx_compression_unit-t.cpp` | 991 | 64 | X-Protocol compression Phases 1–3 (zstd_stream + lz4_message) |
| `mysqlx_concurrent_unit-t.cpp` | 143 | 6 | N-session listener-on-real-port stress |
| `mysqlx_config_store_concurrent_unit-t.cpp` | 455 | 15 | multi-thread reader/writer race on `MysqlxConfigStore` |
| `mysqlx_config_store_pure_unit-t.cpp` | 365 | 25 | pure-API CRUD on `MysqlxConfigStore` |
| `mysqlx_config_store_unit-t.cpp` | 136 | 16 | smoke version of the above |
| `mysqlx_connection_unit-t.cpp` | 41 | 10 | `MysqlxConnection` state machine transitions |
| `mysqlx_credential_verify_unit-t.cpp` | 144 | 24 | credential-bytes verification (MYSQL41 / SHA256_MEMORY) |
| `mysqlx_data_stream_unit-t.cpp` | 89 | 18 | X-Protocol frame header parser (length+type, partial frames) |
| `mysqlx_message_dispatch_unit-t.cpp` | 661 | 49 | end-to-end message-type → handler dispatch via socketpair-backed session |
| `mysqlx_protocol_socket_unit-t.cpp` | 373 | 20 | socket roundtrip (`read_one_message`, `send_message`) |
| `mysqlx_protocol_unit-t.cpp` | 315 | 42 | frame encode/decode + auth helper unit-isolation |
| `mysqlx_robustness_unit-t.cpp` | 1,509 | 74 | error/edge robustness: malformed frames, partial reads, listener reconcile, identity injection |
| `mysqlx_route_store_unit-t.cpp` | 440 | 26 | route selection strategies |
| `mysqlx_session_unit-t.cpp` | 637 | 62 | `MysqlxSession` lifecycle, `resolve_backend_target`, identity round-trip |
| `mysqlx_stats_unit-t.cpp` | 330 | 22 | `MysqlxStatsStore` and `stats_mysqlx_routes` flush |
| `mysqlx_thread_unit-t.cpp` | 147 | 22 | `MysqlxThread` listener/event-loop unit |
| `mysqlx_tls_unit-t.cpp` | 257 | 18 | TLS state on the data stream |

### T.2 New integration / e2e tests under `test/tap/tests/`

| File | LOC | `plan()` | Notes |
|---|---|---|---|
| `test_mysqlx_plugin_load-t.cpp` | 72 | 6 | dlopens the real `.so` and verifies registered tables. Pure in-process. |
| `test_mysqlx_admin_tables-t.cpp` | 364 | 43 | walks the registered table set after `init_all` and asserts DDL substrings. Pure in-process. |
| `test_mysqlx_e2e_handshake-t.cpp` | 427 | 10 (or skip_all) | MYSQL41 auth against real MySQL X port (33060). Requires running MySQL 8.x; reads `MYSQLX_E2E_HOST/PORT/USER/PASS`. |
| `test_mysqlx_e2e_routing-t.cpp` | 388 | 10 (or skip_all) | Same setup but pointed at ProxySQL (`MYSQLX_E2E_PROXYSQL_PORT`, default 16603). Requires both ProxySQL with mysqlx plugin AND a backend MySQL. |

E2e tests skip with `plan(skip_all => ...)` when target is unreachable, exit 0 — this is the correct behaviour, but means CI can pass spuriously if the target was never wired. CI-mysqlx.yml fails fast if `test_mysqlx_*-t` glob is empty.

### T.3 Test build glue

#### `test/tap/tests/unit/Makefile` — MODIFIED, +321 / −4 lines

- Autodetects `PROXYSQL40` from `libproxysql.a` symbols (lines 199–203). Same trick for FFTO / TSDB / GenAI / DEBUG.
- Adds `-DMYSQLX_TEST_BUILD` to `OPT` (line 243) so test-only methods on plugin classes compile in.
- New `FAKE_PLUGIN_SO` and `FAKE_PLUGIN2_SO` targets (lines 282–299).
- New `mysqlx_plugin_build` target shells into `plugins/mysqlx` to produce the .so.
- 28 explicit per-test rules listing the exact plugin sources to drag in.
- `UNIT_TESTS` augmented inside `ifeq ($(PROXYSQL40),1) ... endif` block (lines 372–404) — none of these binaries exist on v3.0/v3.1 builds.

#### `test/tap/tests/Makefile` — MODIFIED, +47 / −7 lines

- Adds `PROXYSQL40_DETECTED` autodetect; under `!PROXYSQL40` filters `test_mysqlx_*` out of the wildcard glob.
- Symlinks `test_mysqlx_plugin_load-t` and `test_mysqlx_admin_tables-t` from `unit/`.
- Adds protobuf object compilation + explicit rules for e2e tests.
- Comment notes `test_mysqlx_listener_smoke-t` is retired (commit `df7e335e2`); coverage moved to `mysqlx_thread_unit-t` and `mysqlx_robustness_unit-t`.

### T.4 TAP groups manifest

#### `test/tap/groups/groups.json` — MODIFIED, +37 / −7 lines

- 32 new entries — all carry `@proxysql_min_version:4.0`:
  - 7 `plugin_*_unit-t` → `unit-tests-g1`
  - 21 `mysqlx_*_unit-t` → `unit-tests-g1`
  - 2 `test_mysqlx_admin_tables-t`, `test_mysqlx_plugin_load-t` → `unit-tests-g1`
  - 2 `test_mysqlx_e2e_{handshake,routing}-t` → `mysqlx-e2e-g1`

Verified: `python3 test/tap/groups/check_groups.py` returns OK; `python3 test/tap/groups/lint_groups_json.py` returns OK.

#### `test/tap/groups/mysqlx-e2e/env.sh` — NEW, 19 lines

Sets `SKIP_PROXYSQL=1` (so `ensure-infras.bash` short-circuits before docker-compose), `MYSQLX_E2E_HOST/PORT/USER/PASS`, plus `MYSQLX_E2E_PROXYSQL_PORT=16603`. Header explicitly notes there is no `infras.lst` and no `infra-mysqlx/` — those would be misleading. The dbdeployer-based local scripts in this dir are *not* in the CI critical path.

#### `test/tap/groups/mysqlx-e2e/setup-infras.bash` — NEW, 86 lines

Local-developer-only. Pulls dbdeployer, fetches MySQL 8.4 newest minimal, deploys single sandbox, creates `mysqlx_test` user, polls 33060.

#### `test/tap/groups/mysqlx-e2e/pre-cleanup.bash` — NEW, 18 lines

Stops and deletes the dbdeployer 8.4 sandbox.

### T.5 CI workflow

#### `.github/workflows/CI-mysqlx.yml` — NEW, 178 lines

Sole CI change in this PR. Triggers: `workflow_run` from `CI-trigger`, plus `workflow_dispatch`.

- **Job `unit-tests`** (ubuntu-22.04): sparse checkout, restore build cache, build the mysqlx plugin with all five tier flags (`PROXYSQL40=1 PROXYSQL31=1 PROXYSQLFFTO=1 PROXYSQLTSDB=1 PROXYSQLGENAI=1`), run `mysqlx_*_unit-t` and `plugin_*_unit-t`. `SKIP_PROXYSQL=1`. Loop fails fast on first non-zero exit.
- **Job `e2e-tests`** (depends on unit-tests): same checkout/cache/plugin-build dance, then dbdeployer setup of MySQL 8.4, create `mysqlx_test` user, poll 33060, source `env.sh`, run every `test_mysqlx_*-t` binary. `if: always()` cleanup of the sandbox.

### T.6 Test infrastructure

**No `test/infra/` changes on this HEAD.** The orphaned `test/infra/docker-compose-mysqlx.yml` and `test/tap/groups/mysqlx-e2e/infras.lst` were removed in commit `df7e335e2` and are absent. The mysqlx-e2e group does not use the docker-compose flow — env.sh sets `SKIP_PROXYSQL=1` and CI uses dbdeployer inline.

---

## Inconsistencies / loose ends

The following were identified during review but are **not** correctness bugs — they're places to verify or low-priority follow-ups:

1. **`mysqlx-e2e/setup-infras.bash` port assumption**: deploys the sandbox with `--port=13306` (classic protocol port) but `env.sh` advertises `MYSQLX_E2E_PORT=33060`. dbdeployer's default X protocol port for `single` is `classic_port + 20000`, so a 13306 deploy would expose X on **33306**, not 33060. CI-mysqlx.yml does NOT pass `--port=13306` so it gets the default (3306 / 33060). Local `setup-infras.bash` and CI therefore reach different ports. NOTE-level only — the script is "ad-hoc local use, not in the CI critical path".

2. **e2e tests live in `tests/` but registered in `unit/` UNIT_TESTS list**: `test_mysqlx_plugin_load-t` and `test_mysqlx_admin_tables-t` live under `tests/` but are listed in `unit/Makefile`'s `UNIT_TESTS` and re-exposed via `ln -fs` from `tests/Makefile`. Intentional (they share libproxysql.a + plugin .so glue) but unusual.

3. **`groups.json` cosmetic churn**: unrelated reordering of group keys on six `test_mysql_*-t` lines (legacy-g3 row ordering). No semantic effect.

4. **Listener-removal does not disturb in-flight sessions**: documented in `mysqlx_thread.cpp:remove_listener_for_route()` as expected behaviour. If a future use case requires active disconnection, the path would walk `sessions_` on `identity_->default_route` match and call `shutdown_notify_client()`.

5. **TLS_PASSTHROUGH was removed but `mysqlx_variables.tls_mode` config column still accepts arbitrary strings**: future work should validate the column at runtime to reject unknown values, OR plumb through a real PASSTHROUGH implementation.

No registered-but-missing-source or built-but-unregistered tests. Lint passes.
