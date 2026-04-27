# Plugin Chassis ABI Contract

This document is the canonical reference for what the chassis ABI promises to plugin authors and to the proxysql core. **Read this before reasoning about plugin-vs-core compatibility.** If anything here drifts from `include/ProxySQL_Plugin.h`, the header wins and this document is wrong — file an issue.

For the reviewer's guide that situates this in the larger PR, see [`REVIEW_GUIDE.md`](./REVIEW_GUIDE.md). For the API a plugin author writes against, see [`../PLUGIN_API.md`](../PLUGIN_API.md).

---

## 1. The two surfaces

The chassis exposes two ABI surfaces:

1. **Descriptor surface** — what a plugin's `.so` exports. Defined in `include/ProxySQL_Plugin.h`. Stable across feature tiers. Tail-extensible.
2. **Services surface** — what the chassis injects into the plugin (function pointers the plugin calls back through). Also defined in `include/ProxySQL_Plugin.h`. Also tail-extensible.

A plugin compiled against ABI version N is loadable by a chassis that supports `PROXYSQL_PLUGIN_ABI_VERSION_MAX >= N`. The reverse — a future plugin against an older chassis — is rejected at load time.

---

## 2. The descriptor surface

The plugin must export exactly one symbol:

```c
extern "C" const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1();
```

The function's return value is a pointer to a static `ProxySQL_PluginDescriptor` whose lifetime is tied to the `.so`'s lifetime. The chassis dereferences this pointer immediately after `dlopen`.

### `ProxySQL_PluginDescriptor` fields, in order

| Field | Type | Required? | Read by chassis when |
|---|---|---|---|
| `name` | `const char*` (non-null, non-empty) | yes | always |
| `abi_version` | `uint32_t` (must be in `[1, PROXYSQL_PLUGIN_ABI_VERSION_MAX]`) | yes | always |
| `init` | function pointer | NULL allowed | Phase D |
| `start` | function pointer | NULL allowed | Phase E |
| `stop` | function pointer | NULL allowed | shutdown |
| `status_json` | function pointer | NULL allowed | when `SHOW PLUGIN STATUS` is implemented (not yet) |
| `register_schemas` | function pointer | NULL allowed | Phase B, **only when `abi_version >= 2`** |

**Rules:**

- The fields must appear in the order above. Reordering breaks ABI.
- Fields can only be **appended** in future ABI versions, never inserted in the middle.
- A NULL function pointer means "the plugin opts out of this phase". For example, a plugin with `start = nullptr` still loads and inits, but never spawns its own threads.
- The chassis MUST NOT read past the last field defined for `abi_version`. ABI-1 plugins do not have `register_schemas`; reading it would be an out-of-bounds access.

### Validation at load time

The chassis (`lib/ProxySQL_PluginManager.cpp:324–383`) enforces:

- `dlsym` resolves `proxysql_plugin_descriptor_v1`. Else: load fails.
- The function returns non-null. Else: load fails.
- `descriptor->name` is non-null and non-empty. Else: load fails.
- `descriptor->abi_version >= 1 && <= PROXYSQL_PLUGIN_ABI_VERSION_MAX`. Else: load fails with "unsupported plugin ABI version".
- `descriptor->register_schemas`, if read at all, is read with the predicate `descriptor->abi_version >= 2u`.

### Current ABI version

```c
#define PROXYSQL_PLUGIN_ABI_VERSION       2
#define PROXYSQL_PLUGIN_ABI_VERSION_MAX   2
```

ABI 1 and ABI 2 differ in **one field**: ABI 2 appends `register_schemas`. ABI-1 plugins skip Phase B entirely.

Future ABI versions append fields. The chassis bumps `PROXYSQL_PLUGIN_ABI_VERSION_MAX` and gates each new field's read on `abi_version >= N`.

---

## 3. The services surface

When the chassis calls into the plugin (Phase B `register_schemas`, Phase D `init`, Phase E `start`, shutdown `stop`), it passes a `const ProxySQL_PluginServices*`. The plugin uses this to call back into the core: registering tables/commands, registering query hooks, getting DB handles, logging.

### Phase-availability matrix

The services struct is the **same shape** in every phase, but some function pointers behave differently depending on which phase the plugin is in. This is the single most surprising thing about the chassis; get it wrong and you get a phantom-success that breaks at runtime.

| Service field | Phase B (`register_schemas`) | Phase D (`init`) | Phase E (`start`) | Steady state |
|---|---|---|---|---|
| `register_table` | live | live | n/a | n/a |
| `register_command` | live | live | n/a | n/a |
| `register_command_alias` | live | live | n/a | n/a |
| `log_message` | live | live | live | live |
| `get_admindb` | **returns nullptr** | live | live | live |
| `get_configdb` | **returns nullptr** | live | live | live |
| `get_statsdb` | **returns nullptr** | live | live | live |
| `register_query_hook` | **returns false (warn)** | live | n/a | n/a |
| `get_prometheus_registry` | live | live | live | live |

Reasons:

- **DB handles in Phase B** — the admin module hasn't initialized yet, so the SQLite handles don't exist. Returning a nullptr from a stub is safer than not installing the function pointer (a misbehaving plugin sees a nullptr return instead of crashing on a null function pointer call).
- **`register_query_hook` in Phase B** — query hooks are registered in `commands_` / `mysql_query_hook_` / `pgsql_query_hook_`, which Phase D writes and workers read lock-free. Phase B is too early; the plugin is told "no" and warned.
- **Registration after Phase D** — the chassis does not currently support live registration. Once Phase D returns, `register_table` / `register_command` are not called by anyone. This is by design — see §6 for the worker-thread visibility argument.

### Field stability

The services struct is **tail-extensible**. The chassis fills the struct in declaration order and the plugin reads what it knows about. A plugin compiled against ABI 2 that runs on a future ABI-3 chassis will simply not see the new fields; that's fine.

The reverse — a future plugin trying to call a field that doesn't exist on the current chassis — would crash. The chassis prevents this by rejecting plugins whose `abi_version > PROXYSQL_PLUGIN_ABI_VERSION_MAX`.

---

## 4. C++ ABI coupling — read this carefully

The chassis ABI is **not pure C**. It uses `std::string` and `prometheus::Registry*` in callback signatures (specifically `ProxySQL_PluginQueryHookPayload`, `ProxySQL_PluginCommandResult`, `get_prometheus_registry`). This means:

> **Plugins MUST be compiled with the same C++ standard library and the same prometheus-cpp version as the proxysql core.**

In practice, this means a plugin .so should be:
- Compiled with the same `-std=c++17` flag.
- Linked against the same libstdc++ ABI.
- Compiled with the same prometheus-cpp headers (the chassis vendors prometheus-cpp under `deps/prometheus-cpp`; plugins should source from the same).
- Compiled with **matching feature-tier flags** (`-DPROXYSQL40 -DPROXYSQL31 -DPROXYSQLFFTO -DPROXYSQLTSDB -DPROXYSQLGENAI`). Mismatched tier flags silently change struct layouts in `ProxySQL_PluginDescriptor` / `ProxySQL_PluginServices` because some inline `#ifdef` blocks add fields. The mysqlx plugin Makefile pulls these from the environment and propagates them; the top-level Makefile sets them from the build flag.

The mysqlx plugin Makefile (`plugins/mysqlx/Makefile:56–61`) carries an explicit comment about this. The CI workflow `.github/workflows/CI-mysqlx.yml` passes the flags explicitly to the sub-make.

### Hidden-visibility hardening

The mysqlx plugin is built with `-fvisibility=hidden -fvisibility-inlines-hidden`. Only `proxysql_plugin_descriptor_v1` is exported (it's `extern "C"`). This:

- Prevents ODR collisions with the proxysql core.
- Avoids leaking template instantiations across the dlopen boundary.
- Makes RTLD_LOCAL meaningful — without hidden visibility, the plugin's symbols are still in the .so's dynsym table even if dlopen says they're local.

Plugin authors should follow the same pattern.

### `dlopen` mode

The chassis loads with `RTLD_NOW | RTLD_LOCAL`. This means:

- `RTLD_NOW`: all symbols are resolved at load time. A plugin with unresolved symbols fails to load (rather than crashing on first use).
- `RTLD_LOCAL`: the plugin's symbols are not added to the global namespace. Two plugins that happen to define the same symbol name don't collide. But: this also means the plugin cannot rely on transitive dependencies of the proxysql binary being visible — if the plugin needs `libzstd`, it must link `libzstd` itself (statically is recommended; the mysqlx plugin does this).

---

## 5. The empty-source-sync invariant

This is a behavioural invariant baked into how the chassis-driven LOAD/SAVE commands work. It's documented at the bottom of `include/ProxySQL_Plugin.h` and at length in `doc/PLUGIN_API.md`. Briefly:

When a plugin's `LOAD ... TO RUNTIME` command runs, it copies rows from a "source" table (e.g. `mysqlx_users`) to a "runtime" table (e.g. `runtime_mysqlx_users`). The convention is that this is a full replace: existing runtime rows are deleted, then the source rows are inserted. **Including when the source table is empty.** An empty source means "no users / no routes / nothing", not "leave the runtime alone".

This is the convention the core's own LOAD/SAVE commands follow. Plugins must do the same. PR #5643 fixed an early mysqlx implementation that did NOT delete first; it caused stale-row bugs after `DELETE FROM mysqlx_users; LOAD MYSQLX USERS TO RUNTIME;` left the runtime table populated with the previous values.

The reference implementation is `plugins/mysqlx/src/mysqlx_admin_schema.cpp:copy_table()` — it does `BEGIN; DELETE FROM <runtime>; INSERT INTO <runtime> SELECT * FROM <source>; COMMIT;` with checked rollback on any failure.

---

## 6. Concurrency model and lifecycle invariants

The chassis is single-threaded during startup and shutdown but multi-threaded during steady-state. The boundary is:

- Phase A → B → C → D → E run **on the main thread**, in order, with no concurrent access to `commands_`, `mysql_query_hook_`, `pgsql_query_hook_`, or `tables_` on the manager.
- After Phase E returns, **the main thread is done**. Worker threads (created by `start`) take over.
- Workers read `commands_` and `*_query_hook_` via `proxysql_dispatch_configured_plugin_*` and `proxysql_has_configured_plugin_query_hook`. The first goes through `g_active_plugin_manager_mutex` (a `std::shared_mutex` — readers share, writers take unique). The second is plain atomic load and is documented to allow false positives.

**The single load-bearing invariant:** Phase D must finish before any worker thread takes the lock-free read path. If it didn't — if `start` returned and workers began running before Phase D's writes to `commands_` settled — workers' plain reads would race the manager's plain writes from Phase D. The chassis enforces this by not calling `start_all` until `init_all` has returned.

`stop` runs on the main thread again, after worker threads have been signaled to exit. Plugins must ensure their `stop` callback waits for any threads it spawned in `start`.

### Lifecycle pairing

Critical: **`stop` pairs with `init`, not with `start`.** Concretely:

- If a plugin's `init` succeeds and `start` then fails, `stop` STILL runs.
- If a plugin's `init` fails, `stop` does NOT run.
- If a plugin's `init` fails for plugin B in a multi-plugin load, plugin A's `stop` still runs (because A's init succeeded).

This is the only correct teardown discipline — `start` failures must release whatever `init` acquired.

Verified by `test/tap/tests/unit/plugin_manager_unit-t.cpp:test_multi_plugin_start_failure_stops_started`.

---

## 7. ABI versioning rules

The chassis follows these rules for ABI evolution:

1. **Increment `PROXYSQL_PLUGIN_ABI_VERSION` for any descriptor or services change.**
2. **Append, never insert.** New fields go at the end of the relevant struct.
3. **Gate every new field's read.** When the chassis dereferences a field that's only valid for `abi_version >= N`, the read must be inside `if (descriptor->abi_version >= Nu)`.
4. **Plugins set their own `abi_version` to whatever their compile-time header had.** This is the contract for "what fields I have". The chassis's `PROXYSQL_PLUGIN_ABI_VERSION_MAX` is the contract for "what fields I know how to read".
5. **A future ABI 3 must not change the layout of fields that exist at ABI 2.** Otherwise an ABI-2 plugin stops being loadable.

The current public API surface (`ProxySQL_PluginDescriptor` + `ProxySQL_PluginServices` + the query-hook payload/result/action types) is **not yet versioned individually**. A future change might (e.g.) add a `ProxySQL_PluginServices_v3` for the second wave of services. The chassis is structured so this addition is a tail-append on the descriptor (`new_services` field) rather than a new struct.

### What can the chassis do, but plugins should not?

The chassis can:
- Pass `nullptr` as a service pointer to indicate "this service is unavailable in this phase". Plugin code must null-check.
- Reject a plugin whose `abi_version` is unrecognised. Plugins must accept this and exit cleanly.
- Tear down a plugin (`stop` + `dlclose`) at any time after `init` succeeded.

Plugins must NOT:
- Cache `services` pointers across phases. The struct may differ between phases (Phase B vs Phase D services are two distinct objects in the chassis; they happen to be ABI-compatible but the function pointers differ).
- Hold references to `SQLite3DB*` past `stop`. After `stop` returns, the admin module may tear down the DB.
- Spawn threads outside `start`. The chassis only signals workers via the worker-shutdown path triggered by `stop`; threads created elsewhere have no clean shutdown.
- Modify their own descriptor at runtime. The chassis caches the pointer.

---

## 8. Reference: minimal plugin skeleton

```cpp
#include "ProxySQL_Plugin.h"
#include <atomic>

static std::atomic<bool> g_running{false};

static bool my_init(const ProxySQL_PluginServices* services) {
    services->log_message(0, "my_plugin: init");
    // ... acquire resources, register query hooks, etc.
    return true;
}

static bool my_register_schemas(const ProxySQL_PluginServices* services) {
    static const char* my_table_ddl =
        "CREATE TABLE IF NOT EXISTS my_plugin_config ("
        "  name TEXT PRIMARY KEY, value TEXT)";
    ProxySQL_PluginTableDef def{"my_plugin_config", my_table_ddl, ProxySQL_PluginDBKind::admin_db};
    services->register_table(def);
    return true;
}

static bool my_start(const ProxySQL_PluginServices* services) {
    g_running.store(true);
    // spawn whatever threads/listeners the plugin needs
    return true;
}

static bool my_stop(const ProxySQL_PluginServices* services) {
    g_running.store(false);
    // join threads, close listeners
    return true;
}

static const ProxySQL_PluginDescriptor descriptor = {
    "my_plugin",                          // name
    PROXYSQL_PLUGIN_ABI_VERSION,          // abi_version (= 2)
    my_init,                              // init   (Phase D)
    my_start,                             // start  (Phase E)
    my_stop,                              // stop
    nullptr,                              // status_json (not yet implemented)
    my_register_schemas                   // register_schemas (Phase B)
};

extern "C" const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
    return &descriptor;
}
```

That's the minimum a chassis-aware plugin needs. The mysqlx plugin is the reference for how this scales up — see [`REVIEW_GUIDE.md`](./REVIEW_GUIDE.md) §5 and [`FILE_CHANGES.md`](./FILE_CHANGES.md) areas A–L.

---

## 9. Versioning discipline going forward

Anyone extending the chassis ABI in the future must:

1. Bump `PROXYSQL_PLUGIN_ABI_VERSION` and `PROXYSQL_PLUGIN_ABI_VERSION_MAX` in `include/ProxySQL_Plugin.h`.
2. Append the new field at the END of the relevant struct.
3. Gate every read of the new field on `abi_version >= NEW_VERSION`.
4. Update [`PLUGIN_API.md`](../PLUGIN_API.md) with the new field's contract.
5. Update this document's §2 (descriptor) or §3 (services) to add a row for the new field.
6. Add a unit test in `test/tap/tests/unit/plugin_lifecycle_unit-t.cpp` (or wherever appropriate) that exercises (a) a plugin compiled at the previous ABI version still loads and runs, and (b) the new field is reachable when set.

If a future change ever needs to break ABI compatibility — i.e., it cannot be expressed as a tail-append — that's a hard rebuild for every shipped plugin and should be deferred until a major version bump.
