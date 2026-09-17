# ProxySQL GenAI Plugin — Reference

## 1. Overview

The **genai plugin** is a dynamically loaded plugin that adds GenAI,
MCP (Model Context Protocol), RAG (Retrieval-Augmented Generation),
and SQL anomaly-detection capabilities to ProxySQL. It hosts the MCP
HTTP listener, the LLM bridge (OpenAI / Anthropic / generic / local
llama.cpp), the FTS- and vector-backed schema discovery cache, and a
pre-execution query hook that feeds the anomaly detector.

This is a v4.0+ plugin: it requires the chassis (`PROXYSQL40=1`) and
is built only when the operator explicitly opts in. Without the flag,
none of this code ships in `proxysql` — the binary stays a plain
MySQL/PgSQL proxy.

### What the plugin owns

| Subsystem | Class | Header |
|---|---|---|
| MCP listener + lifecycle | `MCP_Threads_Handler` | `MCP_Thread.h` |
| MCP HTTP server | `ProxySQL_MCP_Server` | `ProxySQL_MCP_Server.hpp` |
| GenAI worker pool | `GenAI_Threads_Handler` | `GenAI_Thread.h` |
| AI features manager | `AI_Features_Manager` | `AI_Features_Manager.h` |
| Anomaly detection | `Anomaly_Detector` | `Anomaly_Detector.h` |
| Schema discovery | `Discovery_Schema` | `Discovery_Schema.h` |
| Vector storage | `AI_Vector_Storage` | `AI_Vector_Storage.h` |
| MySQL / PgSQL static harvesters | `Static_Harvester`, `PgSQL_Static_Harvester` | `*Static_Harvester.h` |
| LLM provider bridge | `LLM_Bridge`, `LLM_Clients` | `LLM_Bridge.h` |
| FTS index over MySQL catalogs | `MySQL_FTS`, `MySQL_Catalog` | `MySQL_FTS.h` / `MySQL_Catalog.h` |
| Tool handlers (per MCP endpoint) | `Admin_Tool_Handler`, `Cache_Tool_Handler`, `Config_Tool_Handler`, `MCP_Tool_Handler`, `MySQL_Tool_Handler`, `Observe_Tool_Handler`, `Query_Tool_Handler`, `RAG_Tool_Handler`, `Stats_Tool_Handler` | `tool_handlers/*.h` |
| Backend connection helper | `backend_client` | `backend_client.h` |

For deeper architecture see `doc/MCP/Architecture.md` and
`doc/LLM_Bridge/ARCHITECTURE.md` in the repo root; this document
covers only the **plugin lifecycle, configuration, and operational
contract**.

## 2. Building

```bash
PROXYSQL40=1 make            # builds proxysql + the .so
PROXYSQL40=1 make install    # installs both
```

`PROXYSQL40=1` cascades to `PROXYSQL31=1` → `PROXYSQLFFTO=1` +
`PROXYSQLTSDB=1`. The plugin .so lands at
`/usr/lib/proxysql/ProxySQL_GenAI_Plugin.so`.

The build also pulls `sqlite-vec` from `deps/` and links `vec.o` into
`libproxysql.a` so the plugin's `AI_Vector_Storage` can register the
extension via `proxy_sqlite3_vec_init`. v3.0 builds (no
`PROXYSQL40`) skip both.

## 3. Loading

Add the plugin path to the `plugins` array in `proxysql.cnf`:

```
plugins = (
    "/usr/lib/proxysql/ProxySQL_GenAI_Plugin.so"
)
```

The `plugins=` line must be present **before** ProxySQL starts;
plugins cannot be loaded after startup. Removing the line and
restarting unloads the plugin cleanly.

## 4. Lifecycle

The chassis runs the plugin through five phases:

| Phase | Callback | What the genai plugin does |
|---|---|---|
| A. load | (chassis dlopen) | reads the descriptor (`abi_version=3`) |
| B. register_schemas | `genai_register_schemas` | calls `genai_register_admin_tables` to publish the MCP table set + the three `runtime_mcp_*` projections via `services->register_runtime_view` |
| C. admin bootstrap | (chassis) | materialises the registered SQLite schemas |
| D. init | `genai_init` | Prometheus counters, query hook, constructs `MCP_Threads_Handler` / `GenAI_Threads_Handler` / `AI_Features_Manager` / `Anomaly_Detector`, registers admin SQL verbs |
| E. start | `genai_start` | reads `mcp-*` and `genai-*` from `main.global_variables`, installs profiles, starts the MCP listener if `mcp-enabled=true`, kicks off `genai_refresh_runtime_components` |

Teardown (`genai_stop`) is the reverse, in dependency order:
listener → tool handlers → AI features → GenAI workers → atomic clear
of the embed-fn hook → anomaly detector. Counters stay registered
against the shared Prometheus registry (prometheus-cpp has no
unregister API).

## 5. Admin SQL surface

Registered with the chassis command registry; chassis admin
dispatcher routes by canonical name + alias.

| Command | Effect |
|---|---|
| `LOAD MCP VARIABLES TO RUNTIME` | push `mcp-*` from `main.global_variables` into `MCP_Threads_Handler` |
| `LOAD MCP VARIABLES FROM DISK` / `TO MEMORY` | sync `disk.global_variables` → `main.global_variables` (mcp-* slice); runtime remains unchanged until `TO RUNTIME` |
| `LOAD MCP VARIABLES FROM CONFIG` | re-read the `mcp` block from `proxysql.cnf`, apply it, and reevaluate the listener |
| `SAVE MCP VARIABLES TO MEMORY` / `... TO DISK` | reverse direction |
| `LOAD MCP PROFILES TO RUNTIME` | atomic install of `main.mcp_auth_profiles` + `main.mcp_target_profiles` into the in-memory snapshot, rebuilds joined `target_auth_map`; within the profile-command family, this is the only verb that applies profiles or may start the listener |
| `LOAD MCP PROFILES FROM DISK` / `TO MEMORY` | `disk.` → `main.` only; the runtime is untouched until `TO RUNTIME` |
| `SAVE MCP PROFILES TO MEMORY` | atomic dump of in-memory snapshot back to both editable tables in one transaction |
| `LOAD MCP QUERY RULES TO RUNTIME` | install `main.mcp_query_rules` snapshot, attach to `Discovery_Schema` if listener up |
| `SAVE MCP QUERY RULES TO MEMORY` | dump in-memory snapshot back to `main.mcp_query_rules` |
| `LOAD GENAI VARIABLES TO RUNTIME` / `FROM CONFIG` | reload `genai-*` and reinit the GenAI/AI runtime stack |
| `SAVE GENAI VARIABLES TO MEMORY` | dump runtime `genai-*` back to `main.global_variables` |
| `LOAD/SAVE *PROFILES* / *QUERY RULES* TO/FROM DISK` | sync `disk.*` ↔ `main.*` |

ABI 3 contract: `runtime_mcp_*` tables are **chassis-projected
views** of module state. The plugin's
`project_*_to_runtime_view` callbacks are the only writers; LOAD
commands install snapshots into the module without touching
`runtime_<X>`, and a SELECT against `runtime_mcp_<X>` triggers a
fresh projection from the snapshot before returning rows.

### Effective vs. projected targets

`runtime_mcp_target_profiles` projects the **raw** target snapshot, while the
query endpoint consumes the **joined** `target_auth_map`. A target profile is
excluded from that map -- and therefore from `list_targets` and every query
tool -- when it is `active=0`, or when its `auth_profile_id` has no row in
`mcp_auth_profiles` (there is no FK constraint, so the INSERT is accepted).

So that the two surfaces cannot silently disagree, the runtime view carries two
derived, read-only columns:

| Column | Meaning |
|---|---|
| `effective` | `1` if the row is in `target_auth_map` and reachable by the query endpoint; `0` if it was excluded |
| `skip_reason` | empty when `effective=1`; otherwise `inactive` or `auth_profile_id not found` |

Every excluded row is also logged at install time, and `LOAD MCP PROFILES TO
RUNTIME` reports the counts in its reply:

```
admin> LOAD MCP PROFILES TO RUNTIME;
MCP profiles loaded to runtime: 1 auth profile(s), 1 of 3 target(s) effective
(1 inactive, 1 with unresolved auth_profile_id; see
runtime_mcp_target_profiles.skip_reason and the error log)
```

`effective=1` does **not** mean the target is executable -- backend
reachability is resolved per request. `Query_Tool_Handler::format_target_
unavailable_error` diagnoses that second class of failure (empty
`db_username`, no ONLINE backend in the hostgroup).

### Startup persistence

The chassis copies every plugin-registered `config_db` table from `disk.` into
`main.` during Admin bootstrap, before the plugin's `start()` callback runs, so
`SAVE MCP PROFILES TO DISK` / `SAVE MCP QUERY RULES TO DISK` survive a restart
with no post-restart `LOAD ... FROM DISK` needed. `genai_start()` then installs
profiles before listener construction, then installs query rules into the new
`Discovery_Schema` before the listener starts accepting requests.

## 6. Configuration

All `mcp-*` and `genai-*` keys live in `main.global_variables`.
Canonical reference (with defaults and runtime semantics) is in
`doc/MCP/VARIABLES.md`. The plugin re-reads on every
`LOAD ... TO RUNTIME` command.

Tables owned by the plugin (registered in Phase B):

| DB | Table | Purpose |
|---|---|---|
| admin | `mcp_query_rules` | editable query rules |
| admin | `mcp_auth_profiles` | editable backend auth profiles |
| admin | `mcp_target_profiles` | editable MCP target → hostgroup mapping |
| admin | `runtime_mcp_query_rules` / `runtime_mcp_auth_profiles` / `runtime_mcp_target_profiles` | chassis-projected views (no persistent rows; refreshed per SELECT from module snapshot) |
| config | persistent copies of the three editable tables above | for `LOAD ... FROM DISK`, and restored into `main.` automatically at startup |
| stats | `stats_mcp_query_digest` / `stats_mcp_query_digest_reset` | MCP tool call digest statistics (periodic + reset variants) |
| stats | `stats_mcp_query_tools_counters` / `stats_mcp_query_tools_counters_reset` | per-endpoint tool invocation counters |
| stats | `stats_mcp_query_rules` | rule hit counts |
| stats | `stats_genai_global` | aggregated GenAI/MCP/AI status variables (21 counters) |

## 7. Observability

### Prometheus counters

Registered against the shared `services->get_prometheus_registry()`:

| Counter | Increments when |
|---|---|
| `proxysql_genai_detected_anomalies_total` | the anomaly detector flags a query (any risk) |
| `proxysql_genai_blocked_queries_total` | the detector blocks a query (DENY returned to client) |

### SQL status variables

`SELECT * FROM stats_genai_global ORDER BY Variable_name;`

Returns 21 counters aggregated from three handler classes:

| Variable_name prefix | Source | Count |
|---|---|---|
| `genai_*` | GenAI_Threads_Handler | 4 |
| `mcp_*` | MCP_Threads_Handler | 3 |
| `llm_*` | AI_Features_Manager | 10 |
| `anomaly_*` | AI_Features_Manager | 3 |
| `daily_cloud_spend_usd` | AI_Features_Manager | 1 |

### MCP query digest

`SELECT * FROM stats_mcp_query_digest;` — MCP tool call digest
statistics with tool_name, run_id, fingerprint, count_star, timing
(min/max/sum). Stats are persisted to SQLite and survive restarts.
`stats_mcp_query_digest_reset` variant clears stats on read.

Plugin log lines route through `services->log_message` (see
`genai_log()` in `plugin_main.cpp`). Severity follows syslog levels;
the chassis writes to `proxysql.log`.

## 8. Concurrency notes

- **`genai_anomaly_embed_fn`** is `std::atomic` with acquire/release
  semantics; the embedding back-end pointer's lifetime is paired with
  the `GloGATH` global it dereferences (see the long comment in
  `Anomaly_Detector.cpp`).
- **`MCP_Threads_Handler` variable accessors** (`get_variable`,
  `set_variable`, `has_variable`, `get_variables_list`) all serialize
  on the handler's `pthread_rwlock`.
- **`genai_refresh_runtime_components`** takes an exclusive lifecycle lock
  while replacing the GenAI resources its AI/RAG handlers borrow, then rebinds
  the persistent handlers before admitting another request. Admin command
  callbacks yield the Admin global mutex before waiting for this lock, avoiding
  a lock inversion with MCP config/stats requests. Other readers, especially
  the anomaly-detector query hook, are not yet covered by the same lifecycle
  lock; see the detailed contract comment in `genai_plugin.h`.
- **Profile triplet**: `install_profiles_from_admin` and
  `save_profiles_to_admin_table` are *atomic across both tables*: one
  wrlock for both swaps + one BEGIN/COMMIT for both writes, FK-aware
  delete order. Per-table install/save methods exist but only rebuild
  one half of the joined `target_auth_map`; prefer the combined
  variants from new code.

## 9. Testing

| Suite | Path | Coverage |
|---|---|---|
| Plugin lifecycle | `test/tap/tests/unit/genai_plugin_load_unit-t.cpp` | load → Phase B → init → start → LOAD MCP PROFILES → runtime view projection → SAVE round-trip → stop |
| Anomaly detector | `genai_plugin_anomaly_unit-t.cpp` | normalize_query, check_sql_injection (private-via-friend) |
| Backend client | `genai_plugin_backend_client_unit-t.cpp` | parse + dial guards |
| FTS string utils | `genai_fts_string_unit-t.cpp` | sanitize_name / escape_* |
| MCP variable accessors | `genai_mcp_thread_unit-t.cpp` | get_variable / set_variable round-trip + concurrency |
| Discovery schema | `genai_discovery_schema_unit-t.cpp` | catalog cache shape |
| LLM clients | `genai_llm_clients_unit-t.cpp` | HTTP client wiring |
| Chassis runtime-view dispatch | `plugin_runtime_views_unit-t.cpp` | end-to-end via real plugin .so |

Integration tests live in the `ai-g1` TAP group (run via
`test/infra/control/run-tests-isolated.bash TAP_GROUP=ai-g1`); they
spin up real MySQL 8.4 + PgSQL 16 backends and exercise the MCP
endpoints + LLM surface end-to-end.

### Known unit-test gaps

`Admin_Tool_Handler`, `Cache_Tool_Handler`, `Config_Tool_Handler`,
`Observe_Tool_Handler`, and `RAG_Tool_Handler` have no dedicated
unit test — coverage relies on `ai-g1` integration tests. RAG is
the most worth closing given vector-storage complexity.

## 10. Known gaps

- **Non-MCP `genai_refresh_runtime_components` race**: see Concurrency notes
  above; needs a proper rwlock around the remaining `GloGATH`/`GloAI`
  consumers.
- **Tool-handler unit tests**: see Testing section.

## 11. History

The plugin is the result of an 8-step carve-out (Steps 1–8b on this
branch) that moved ~28K LOC out of ProxySQL core. The original
design and per-step plans live in
`docs/superpowers/specs/2026-04-16-genai-plugin-carveout-design.md`
and adjacent files; the consolidated PR is #5701.
