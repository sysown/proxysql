# Step 4 — Move MCP subsystem into the GenAI plugin — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the MCP subsystem (`MCP_Thread`, `MCP_Endpoint`, `MCP_Tool_Handler`, `ProxySQL_MCP_Server`, and the eight non-AI/non-RAG tool handlers) and their admin-table/admin-command surface out of `lib/` and into `plugins/genai/`. Delete the global `GloMCPH`. Replace the two `Admin_Handler.cpp` MCP call sites (`has_variable` for `mcp-` variables; `load_target_auth_map` in the `LOAD MCP PROFILES …` handler) with admin-SQL dispatch via `register_command`. Introduce `plugins/genai/src/backend_client.cpp` consolidating the MySQL+PgSQL client boilerplate currently scattered across `Query_Tool_Handler` and `MySQL_Tool_Handler`, and rewire those handlers to issue queries through `127.0.0.1:6033` / pgsql-port instead of connecting directly to backend hosts.

**Architecture:** Bottom-up move performed in seven sub-steps (4.A done; 4.B–4.G remaining). Each sub-step is one reviewable commit that leaves the tree buildable in both `make` (no plugin) and `make` + `plugins = (genai)` configurations. The unmoved-yet pieces stay behind their existing `#ifdef PROXYSQLGENAI` guard until their owning sub-step lands; once moved, the guard is dropped from those files and the corresponding core call sites are deleted in the same commit. The `PROXYSQLGENAI` macro itself is **not** removed in this step — that is Step 7.

**Spec reference:** `docs/superpowers/specs/2026-04-16-genai-plugin-carveout-design.md`, section "Migration sequence → Step 4".

**Tech Stack:** C++17, GNU Make, MariaDB client library, `libpq`, SQLite3 (via core handles), prometheus-cpp (via shared registry), TAP test framework.

**Branch:** `v3.0-genai-plugin` (worktree at `.worktrees/v3.0-genai-plugin`, base `origin/v3.0`). Last commit on branch: `5b936459a` (Step 4.A).

---

## Resolved design questions

The carve-out spec leaves two questions open for the writing-plans phase. This plan resolves them:

### Q-svcuser: how does the plugin authenticate to local ProxySQL?

**Resolution:** **Manual admin bootstrap via `mcp_auth_profiles`.** Reuse the existing table — the `db_username`/`db_password` columns are already present per profile. The plugin connects to `127.0.0.1:6033` (or the pgsql port) using the per-target credentials looked up from `runtime_mcp_target_profiles` joined with `runtime_mcp_auth_profiles`. The operator is responsible for ensuring the `db_username` is provisioned in `mysql_users` / `pgsql_users` (and routed by `mysql_query_rules` to the desired hostgroup).

Why this option, not the alternatives:
- **Auto-generated random password at init:** introduces a new bootstrap mechanism (write to admin table + read back at next start) for no incremental safety win — the plugin is in-process and trusted regardless.
- **Unix-socket loopback bypass:** would need a new admin auth bypass path; out of scope for a carve-out.

The "service user" terminology in the spec (`design.md` lines 144–153) collapses to "the user named in the existing `mcp_auth_profiles` row." No schema changes.

### Q-localhost-port: how does the plugin discover the local proxy port?

**Resolution:** Read `mysql-interfaces` / `pgsql-interfaces` from `global_variables` via `services->get_admindb()` at backend-pool-init time. Extract the first IPv4/127.0.0.1 listener; fall back to a Unix socket if the variable lists one. Cache the result for the lifetime of the plugin; re-read on `LOAD MCP PROFILES TO RUNTIME` (since that already reinitializes the connection pool today). No new config knob.

---

## Sub-step breakdown

| Sub-step | Description | Status |
|---|---|---|
| 4.A | Remove `GENAI:` / `LLM:` query-prefix escape hatches from `MySQL_Session` | **done** (rebased: `a79a27a9e`) |
| 4.B | Add `backend_client.cpp` to plugin (no callers yet); add unit test | **done** (`16a4340eb`) |
| 4.C | **(revised — see "4.C/4.D/4.E merge" below)** Move all MCP code into the plugin as one atomic commit: 8 tool handlers + `MCP_Tool_Handler` base + `MCP_Endpoint` + `MCP_Thread` + `ProxySQL_MCP_Server`, rewire `Query`/`MySQL` handlers via `backend_client::dial_*_local`, take `MCP_Threads_Handler` ownership in `genai_init/start/stop`, delete `GloMCPH`. | pending |
| ~~4.D~~ | ~~Move `MCP_Tool_Handler` (base) + `Query_Tool_Handler` + `MySQL_Tool_Handler`; rewire to `backend_client` going through `127.0.0.1:6033`~~ | merged into 4.C |
| ~~4.E~~ | ~~Move `MCP_Endpoint`, `MCP_Thread`, `ProxySQL_MCP_Server`; replace `GloMCPH` with a plugin-internal singleton owned by `genai_init/start/stop`~~ | merged into 4.C |
| 4.F | Replace `Admin_Handler.cpp` `has_variable("mcp-…")` and `load_target_auth_map` sites with `register_command` dispatch | pending |
| 4.G | Move MCP admin tables (`mcp_*`, `runtime_mcp_*`, `stats_mcp_*`) registration from `ProxySQL_Admin.cpp` / `Admin_Bootstrap.cpp` to `plugin_tables.cpp` via `register_table` | pending |

### 4.C / 4.D / 4.E merge (revision)

**Why the original split doesn't work.** The original plan assumed the 5
"stateless" tool handlers (Admin, Cache, Config, Observe, Stats) could
move first because they don't dial backends.  In practice all five
**except Observe** are constructed directly in
`lib/ProxySQL_MCP_Server.cpp` (`new Admin_Tool_Handler(handler)` etc.,
lines 84-131).  Moving any of those `.cpp` files out of `lib/` while
leaving `ProxySQL_MCP_Server.cpp` in `lib/` makes
`lib/libproxysql.a` reference symbols it no longer publishes — the
`src/proxysql` link breaks.

The transitional-shim escape hatch the original plan proposed
(forwarding header in `include/`, leave `.cpp` in `lib/`) doesn't help
either: the *symbols* still need to live in `lib/libproxysql.a` while
core's MCP listener exists, and that's a `.cpp`-level question, not a
header-level one.  `Observe_Tool_Handler` is the only one that's free
to move on its own — but it's also orphan code (zero call sites; only
self-referenced), so moving it standalone provides no architectural
forward progress.

**What does work.** Move the entire MCP construction surface together
in one commit: the 8 tool handlers (Admin, Cache, Config, MCP_Tool,
MySQL, Observe, Query, Stats — minus AI/RAG which stay for Steps 5/6),
plus `MCP_Tool_Handler` base, plus `MCP_Endpoint` / `MCP_Thread` /
`ProxySQL_MCP_Server`.  The plugin's `genai_init` / `genai_start` /
`genai_stop` take ownership of the `MCP_Threads_Handler` object that
used to be `GloMCPH` in core.  The Query and MySQL tool handlers'
backend dialing is rewritten to call `backend_client::dial_*_local` (the
helper added in 4.B) so this commit also delivers what 4.D promised.

`AI_Tool_Handler` and `RAG_Tool_Handler` stay in `lib/` for Steps 5/6;
the plugin's `ProxySQL_MCP_Server.cpp` keeps its existing
`#ifdef PROXYSQLGENAI` guards around their construction.  Plugin-side
references to those still-in-core types resolve at `dlopen` time via
the host symbol table (the proxysql binary already exports them under
`-Wl,--export-dynamic`).

`Admin_Handler.cpp`'s two MCP call sites (`has_variable("mcp-…")` at
~L1191 and `load_target_auth_map` at ~L2695) get FIXME stubs in this
commit — the admin SQL surface for `mcp-*` variables and
`LOAD MCP PROFILES …` is **temporarily non-functional between this
commit and 4.F**.  This is called out explicitly in the commit message
so reviewers know the gap is intentional and bounded.

`lib/ProxySQL_Admin.cpp` keeps its 31 `GloMCPH` references for now;
those are admin-table glue that 4.G replaces with `register_table`
dispatch.  We delete only the **runtime** GloMCPH references in this
commit (`src/main.cpp` lifecycle calls + `lib/ProxySQL_Admin.cpp`
L3628-3744 listener-management block) — the table-registration glue
stays until 4.G removes it.  The forward declaration of
`MCP_Threads_Handler*` in `include/proxysql.h` is replaced by an
opaque-pointer alias so the surviving `lib/ProxySQL_Admin.cpp` glue
still compiles.

**Commit size.** ~10K LOC moved, ~200 LOC of surgical changes in core.
Big, but reviewable as "everything that was MCP in lib/ is now in
plugins/genai/" — the diff per file is mostly path changes plus
relocated `#include`s.  The handful of substantive edits
(`backend_client::dial_*_local` rewires, FIXME stubs in
`Admin_Handler.cpp`, lifecycle hooks in `genai_init`) are what
reviewers spend their attention on.

Net carve-out at end of Step 4 (estimate, before Step 5): **~13 K LOC** of `lib/` removed; **~8 K LOC** of `plugins/genai/src/` added (handler bodies move 1:1, plus `backend_client.cpp` and a per-step set of `plugin_*.cpp` adapter additions).

---

## Sub-step 4.B — `backend_client.cpp` (plugin-side helper)

**Why first.** Lets the subsequent file-move commits land as `git mv` + minimal edits (swap raw `mysql_real_connect` calls for `backend_client::connect_mysql(target)`), keeping the diff in 4.D reviewable. The helper has no callers yet at the end of 4.B — it's exercised only by a unit test — so this commit is functionally a no-op.

**Files added:**

| Path | Role |
|---|---|
| `plugins/genai/include/backend_client.h` | Header: `MySQLBackendConn`, `PgSQLBackendConn`, `connect_mysql(BackendTarget)`, `connect_pgsql(BackendTarget)`, RAII `close()` helpers |
| `plugins/genai/src/backend_client.cpp` | Impl: `mysql_init`+`mysql_options`+`mysql_real_connect` (or `PQconnectdb`), bound to `127.0.0.1` + the discovered local proxy port. `BackendTarget` carries `{user, password, schema, hostgroup_id}` — the host/port come from the local-proxy lookup, not from the target row |
| `plugins/genai/src/local_proxy_endpoint.cpp` | One-time admindb lookup of `mysql-interfaces` / `pgsql-interfaces`; cached `std::pair<std::string,int>` per protocol |
| `plugins/genai/test/unit/backend_client_unit-t.cpp` | Unit: connect to a mock `mysql-interfaces`-style listener fixture; assert connect/auth/cleanup. No real proxysql process required (use `MYSQL_FAKE_LISTENER` fixture pattern from anomaly unit tests) |

**Files modified:**

| Path | What changes |
|---|---|
| `plugins/genai/Makefile` | Compile + link the two new `.cpp` |
| `plugins/genai/include/genai_plugin.h` | Add `BackendClient` accessor on `GenAIPluginContext` (still null at end of 4.B) |
| `plugins/genai/test/unit/Makefile` | Build `backend_client_unit-t` |

**Steps:**

- [ ] **4.B.1** Create `backend_client.h` with the `MySQLBackendConn` / `PgSQLBackendConn` types and free-function `connect_*` declarations. Use `std::unique_ptr` with custom deleters for the underlying handles — RAII matches the existing `Anomaly_Detector` style.
- [ ] **4.B.2** Implement `local_proxy_endpoint.cpp`. Lookup is `SELECT variable_value FROM global_variables WHERE variable_name='mysql-interfaces'` (resp. `pgsql-interfaces`), pick the first `127.0.0.1:NNNN` listener (or `0.0.0.0:NNNN` → use `127.0.0.1`). On failure: log via `services->log_message`, return `{}` — caller treats empty as "skip this protocol."
- [ ] **4.B.3** Implement `backend_client.cpp`. The MySQL path mirrors `Query_Tool_Handler.cpp:430-456` verbatim except host/port come from `local_proxy_endpoint`, not from the target. PgSQL similar via the existing `PQconnectdb` conninfo construction.
- [ ] **4.B.4** Write `backend_client_unit-t.cpp`. Spin up a TCP listener on `127.0.0.1:0` that speaks just enough MySQL handshake for `mysql_real_connect` to succeed (or use the existing `test/tap/test_helpers/fake_*` if one fits). Assert `connect_mysql({user="x", password="y", …})` returns a usable handle.
- [ ] **4.B.5** Local build + run the unit test:
  ```
  cd plugins/genai && make
  cd plugins/genai/test/unit && make && ./backend_client_unit-t
  ```
- [ ] **4.B.6** Run a clean `make` at the top to confirm the core build is unchanged.
- [ ] **4.B.7** Commit: `feat(plugins/genai): Step 4.B — add backend_client helper for local-proxy connections`.

---

## Sub-step 4.C — Move stateless tool handlers

The five handlers below have no direct backend client calls (verified via `grep -l "mysql_real_connect\|PQconnectdb" lib/*Tool_Handler.cpp` → only `Query_Tool_Handler.cpp` and `MySQL_Tool_Handler.cpp` match). They read core state via globals (`GloMyHGM`, `GloAdmin`, etc.) which all become services-layer reads inside the plugin.

**Files moved (`git mv` to preserve history):**

| From | To |
|---|---|
| `include/Admin_Tool_Handler.h` | `plugins/genai/include/Admin_Tool_Handler.h` |
| `include/Cache_Tool_Handler.h` | `plugins/genai/include/Cache_Tool_Handler.h` |
| `include/Config_Tool_Handler.h` | `plugins/genai/include/Config_Tool_Handler.h` |
| `include/Observe_Tool_Handler.h` | `plugins/genai/include/Observe_Tool_Handler.h` |
| `include/Stats_Tool_Handler.h` | `plugins/genai/include/Stats_Tool_Handler.h` |
| `lib/Admin_Tool_Handler.cpp` | `plugins/genai/src/tool_handlers/Admin_Tool_Handler.cpp` |
| `lib/Cache_Tool_Handler.cpp` | `plugins/genai/src/tool_handlers/Cache_Tool_Handler.cpp` |
| `lib/Config_Tool_Handler.cpp` | `plugins/genai/src/tool_handlers/Config_Tool_Handler.cpp` |
| `lib/Observe_Tool_Handler.cpp` | `plugins/genai/src/tool_handlers/Observe_Tool_Handler.cpp` |
| `lib/Stats_Tool_Handler.cpp` | `plugins/genai/src/tool_handlers/Stats_Tool_Handler.cpp` |

**Steps:**

- [ ] **4.C.1** `git mv` the ten files. Drop the `#ifdef PROXYSQLGENAI` guards from each (gating is now by location).
- [ ] **4.C.2** For each handler, replace direct global accesses (`GloMyHGM`, `GloAdmin`, `GloVars`, etc.) with calls through `ctx.services->…`. Tabulate the global → service-call mapping in this sub-step's commit message — there will be a small number of repeated patterns. **If a handler reaches for a core global that has no services equivalent today, do not invent one in this step**; instead, mark the call site `// TODO(step4-followup):` and continue. We'll resolve in 4.E (which already touches the services struct for `GloMCPH` removal). Document the count in the commit message.
- [ ] **4.C.3** Update `lib/Makefile` to drop the moved `.cpp` files; update `plugins/genai/Makefile` to compile them.
- [ ] **4.C.4** Update any `lib/*.cpp` that `#include`d the moved headers — these are self-contained handlers, so the only includer is `lib/MCP_Tool_Handler.cpp` (the dispatcher), which still lives in core at end of 4.C. Add a `#include "Admin_Tool_Handler.h"` etc. via the relative path `../../plugins/genai/include/…` from core? **No** — instead, leave a thin forwarding header in `include/` for the duration of 4.C+4.D (deleted in 4.E when `MCP_Tool_Handler.cpp` itself moves). Document this transitional shim in the commit message.
- [ ] **4.C.5** Build both flavors:
  ```
  make clean && make 2>&1 | tail -20                  # core only — should succeed
  cd plugins/genai && make 2>&1 | tail -20            # plugin builds
  ```
- [ ] **4.C.6** Run any tool-handler unit tests already in `plugins/genai/test/unit/` (probably none touch these yet — that's fine).
- [ ] **4.C.7** Commit: `feat(plugins/genai): Step 4.C — move 5 stateless MCP tool handlers into the plugin`.

---

## Sub-step 4.D — Move `MCP_Tool_Handler` (base) + `Query_Tool_Handler` + `MySQL_Tool_Handler`; rewire to `backend_client`

This is the largest sub-step (~5K LOC moved + non-trivial backend rewire). The two handlers being rewired currently dial backends directly using `target.host:target.port`; after this sub-step they dial `127.0.0.1:6033` (or the pgsql equivalent) using `backend_client::connect_*`.

**Files moved (`git mv`):**

| From | To |
|---|---|
| `include/MCP_Tool_Handler.h` | `plugins/genai/include/MCP_Tool_Handler.h` |
| `include/Query_Tool_Handler.h` | `plugins/genai/include/Query_Tool_Handler.h` |
| `include/MySQL_Tool_Handler.h` | `plugins/genai/include/MySQL_Tool_Handler.h` |
| `lib/MCP_Tool_Handler.cpp` | `plugins/genai/src/tool_handlers/MCP_Tool_Handler.cpp` |
| `lib/Query_Tool_Handler.cpp` | `plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp` |
| `lib/MySQL_Tool_Handler.cpp` | `plugins/genai/src/tool_handlers/MySQL_Tool_Handler.cpp` |

**Steps:**

- [ ] **4.D.1** `git mv` the six files. Drop `#ifdef PROXYSQLGENAI`.
- [ ] **4.D.2** In `Query_Tool_Handler.cpp` (init pool, ~L420-515), replace:
  - `MYSQL* mysql = mysql_init(NULL); mysql_options(...); mysql_real_connect(mysql, target.host.c_str(), target.db_username.c_str(), target.db_password.c_str(), …)` → `auto conn = backend_client::connect_mysql({target.db_username, target.db_password, target.default_schema, target.hostgroup_id});`
  - `PQconnectdb("host=… port=… user=… password=…")` → `auto conn = backend_client::connect_pgsql({…});`

  The host/port go to `127.0.0.1` + the local proxy port discovered by `local_proxy_endpoint` (4.B). The `target.host`/`target.port` columns become **informational only** in this step — kept for log messages and future direct-to-backend opt-in (Q8 capability) — but no longer used for the dial.
- [ ] **4.D.3** Same rewire pass on `MySQL_Tool_Handler.cpp`.
- [ ] **4.D.4** Delete the transitional shim headers added in 4.C.4 (those handlers now live next to their callers).
- [ ] **4.D.5** Update `lib/Makefile` and `plugins/genai/Makefile`. Add `-lmariadbclient -lpq` to the plugin link line if not already present.
- [ ] **4.D.6** Build core + plugin. Run existing TAP MCP tests under the new flow. **Expected behavior change:** queries appear in `stats_mysql_query_digest` (because they now go through proxysql) where they previously didn't. Document this in the commit message — it is a deliberate side-effect of the carve-out, not a regression.
- [ ] **4.D.7** Manual smoke: start proxysql with `plugins = (genai)`, configure an `mcp_auth_profile` whose `db_username` is provisioned in `mysql_users`, configure an `mcp_target_profile` pointing at a hostgroup with at least one backend, then run an MCP `query` tool call against the local MCP port. Confirm it returns a result and that `stats_mysql_query_digest` records the query.
- [ ] **4.D.8** Commit: `feat(plugins/genai): Step 4.D — move MCP_Tool_Handler/Query/MySQL handlers, route through 127.0.0.1:6033`.

---

## Sub-step 4.E — Move `MCP_Endpoint`, `MCP_Thread`, `ProxySQL_MCP_Server`; eliminate `GloMCPH`

**Files moved (`git mv`):**

| From | To |
|---|---|
| `include/MCP_Thread.h` | `plugins/genai/include/MCP_Thread.h` |
| `include/MCP_Endpoint.h` | `plugins/genai/include/MCP_Endpoint.h` |
| `include/ProxySQL_MCP_Server.hpp` | `plugins/genai/include/ProxySQL_MCP_Server.hpp` |
| `lib/MCP_Thread.cpp` | `plugins/genai/src/MCP_Thread.cpp` |
| `lib/MCP_Endpoint.cpp` | `plugins/genai/src/MCP_Endpoint.cpp` |
| `lib/ProxySQL_MCP_Server.cpp` | `plugins/genai/src/ProxySQL_MCP_Server.cpp` |

**Files modified in core:**

| Path | What changes |
|---|---|
| `src/main.cpp` | Delete `extern MCP_Threads_Handler* GloMCPH;`, the `new`/`init`/`delete`/null-checks at L498/927/974/1311-1316/1756. Plugin lifecycle (`LoadConfiguredPlugins` → `genai_init/start/stop`) replaces all of these |
| `lib/ProxySQL_Admin.cpp` | Delete the 31 `GloMCPH` references and the MCP server-lifecycle block at L3628-3744. The MCP listener now belongs to `genai_start` / `genai_stop` |
| `lib/Admin_Handler.cpp` | Delete `extern MCP_Threads_Handler* GloMCPH` (the `has_variable` and `load_target_auth_map` callers move to 4.F, but **the `extern` is dropped here** because the symbol no longer exists in core after this commit. The two callers temporarily lose their conditional clauses; they get re-added as `register_command` dispatch in 4.F) |
| `include/proxysql.h` (and others that forward-declare `MCP_Threads_Handler`) | Drop the forward decl |

**Plugin-side additions:**

| Path | What changes |
|---|---|
| `plugins/genai/include/genai_plugin.h` | Add `MCP_Threads_Handler* mcp = nullptr;` to `GenAIPluginContext` |
| `plugins/genai/src/plugin_main.cpp` | `genai_init` constructs `ctx.mcp = new MCP_Threads_Handler(); ctx.mcp->init();`. `genai_start` calls `ctx.mcp->start()` (which spawns the listener thread). `genai_stop` calls `ctx.mcp->shutdown(); delete ctx.mcp;` |

**Steps:**

- [ ] **4.E.1** `git mv` the six files; drop `#ifdef PROXYSQLGENAI`. Update `#include` paths inside the moved files (e.g., `#include "MCP_Tool_Handler.h"` already resolves because both live in the plugin tree).
- [ ] **4.E.2** Delete the four core call sites in `src/main.cpp`. Verify no other core file references `GloMCPH` after this.
- [ ] **4.E.3** Delete the 31 references in `lib/ProxySQL_Admin.cpp`. Some of these are inside admin-table merge logic; that surface moves to 4.G — for now leave the table definitions in place and only delete the **runtime** references to `GloMCPH`.
- [ ] **4.E.4** In `Admin_Handler.cpp`, drop the `extern MCP_Threads_Handler* GloMCPH;` and temporarily `#ifdef 0` (or remove) the two call sites at `L1191` and `L2695-2696`. They will be reintroduced by 4.F as `register_command` dispatch. Add a `// FIXME(step4f):` comment so the gap is obvious if anyone audits between 4.E and 4.F.
- [ ] **4.E.5** Plugin: extend `GenAIPluginContext` with the `mcp` pointer, wire the lifecycle calls into `genai_init/start/stop` (mirror the pattern of `anomaly_detector` from Step 3).
- [ ] **4.E.6** Build:
  ```
  make clean && make 2>&1 | tail -20
  cd plugins/genai && make 2>&1 | tail -20
  ```
  Both should succeed. The "MCP variables / MCP profiles" admin SQL surfaces will be **temporarily broken** between 4.E and 4.F — that is the whole reason 4.F is the next sub-step. Make this explicit in the commit message: "Tree builds, admin SQL surface for `mcp-*` variables and `LOAD MCP PROFILES …` is non-functional until 4.F."
- [ ] **4.E.7** Run the existing TAP plugin lifecycle tests (`test_mysqlx_plugin_load-t`, `plugin_manager_unit-t`) — these don't touch MCP and must still pass.
- [ ] **4.E.8** Commit: `feat(plugins/genai): Step 4.E — move MCP server/endpoint/thread into plugin, delete GloMCPH`.

---

## Sub-step 4.F — `register_command` dispatch for `mcp-*` variables and `LOAD MCP PROFILES …`

Restores the admin SQL surface that 4.E temporarily broke, but routed through the plugin ABI rather than through `GloMCPH`.

**Files modified:**

| Path | What changes |
|---|---|
| `lib/Admin_Handler.cpp` | Replace the FIXME comments left in 4.E with: a single fall-through clause at the end of the `has_variable` chain that asks the plugin registry for any registered command matching `SET mcp_variable …`; the `LOAD MCP PROFILES` block becomes a passthrough to whatever the plugin registered for those verbs |
| `plugins/genai/src/plugin_commands.cpp` (new) | Calls `services->register_command("LOAD MCP PROFILES FROM DISK", &load_profiles_from_disk_cb)` (and the four other variants), `register_command("SET mcp-* …", &mcp_set_variable_cb)`, etc. The callback handlers wrap the methods that used to live on `MCP_Threads_Handler::has_variable` / `load_target_auth_map` (now plugin-internal calls into `ctx.mcp->…`) |
| `plugins/genai/include/genai_plugin.h` | Forward-declare the command callbacks |

**Steps:**

- [ ] **4.F.1** Decide on the exact set of admin-SQL verbs to register. Inventory: `LOAD MCP PROFILES {FROM DISK, FROM CONFIG, TO MEMORY, TO RUNTIME, FROM RUNTIME}`, `SAVE MCP PROFILES {…}`, plus the SET clause for any `mcp-*` variable. List them in the commit body.
- [ ] **4.F.2** Implement `plugin_commands.cpp`. Each callback returns `ProxySQL_PluginCommandResult{error_code, rows_affected, message}`.
- [ ] **4.F.3** In `Admin_Handler.cpp`, the dispatcher already exists from Step 0 (`ProtocolX` cherry-pick added it). Confirm it covers the verbs we register; if not, extend the prefix-match logic to dispatch on `"SET mcp-"` and the `LOAD MCP PROFILES` / `SAVE MCP PROFILES` prefixes before falling through to the unknown-verb path.
- [ ] **4.F.4** Reintroduce the variable-lookup behavior in `has_variable`: instead of a hardcoded `GloMCPH->has_variable`, walk the plugin command registry for a registered `mcp_get_variable` command (or, if the registry doesn't naturally support a query/lookup operation, register a synthesized `INTERNAL: HAS MCP VARIABLE …` callback used only by `has_variable`). Pick whichever pattern matches what the existing dispatcher supports — read `lib/ProxySQL_PluginManager.cpp` (cherry-picked in Step 0) to see the registered surface before designing this.
- [ ] **4.F.5** Build core + plugin. Manual smoke: `SET mcp-port=6090; LOAD MCP PROFILES FROM DISK;` via the admin port — both should round-trip through the plugin and update `ctx.mcp` state.
- [ ] **4.F.6** Run the TAP MCP integration tests (`test/tap/tests/test_mcp_*` if any exist; otherwise the existing manual smoke is the gate).
- [ ] **4.F.7** Commit: `feat(plugins/genai): Step 4.F — re-route mcp-* admin SQL through plugin command registry`.

---

## Sub-step 4.G — Move MCP admin tables to `register_table`

**Files modified:**

| Path | What changes |
|---|---|
| `lib/Admin_Bootstrap.cpp` | Delete the `mcp_*` and `runtime_mcp_*` table-creation blocks (8-12 tables) |
| `lib/ProxySQL_Admin.cpp` | Delete remaining MCP-specific bootstrap/merge code (the residual after 4.E removed the `GloMCPH` runtime references) |
| `plugins/genai/src/plugin_tables.cpp` (new) | Calls `services->register_table({…})` for each MCP table. Same SQL DDL strings — copy-paste verbatim from the deleted `Admin_Bootstrap.cpp` blocks |
| `plugins/genai/include/genai_plugin.h` | Forward-declare the table-registration entry point called from `genai_init` |

**Steps:**

- [ ] **4.G.1** Inventory the MCP tables in `Admin_Bootstrap.cpp` (grep for `mcp_` and `runtime_mcp_` and `stats_mcp_`). List exact table names and DB kind (admin/config/stats) in the commit body.
- [ ] **4.G.2** Create `plugin_tables.cpp` with one `register_table` call per inventoried table. Call from `genai_init` (early — before anything that reads from those tables).
- [ ] **4.G.3** Delete the original creation blocks from `Admin_Bootstrap.cpp` and `ProxySQL_Admin.cpp`.
- [ ] **4.G.4** Build core + plugin. Start proxysql with `plugins = (genai)`. Verify in the admin SQL:
  ```
  SHOW TABLES;             -- mcp_* tables present
  SHOW TABLES FROM stats;  -- stats_mcp_* present
  ```
- [ ] **4.G.5** Run the existing TAP admin-table-listing tests (those that snapshot `SHOW TABLES`) — they will need their golden files updated since the tables are now plugin-registered (same SQL, same names, but the test-expectation files might be regenerated). Document which files were regenerated.
- [ ] **4.G.6** Commit: `feat(plugins/genai): Step 4.G — register MCP admin tables through the plugin ABI`.

---

## Cross-cutting concerns

### What stays behind `#ifdef PROXYSQLGENAI` after Step 4

After 4.G, the only `lib/`-side `PROXYSQLGENAI` references should be those guarding **GenAI/LLM/AI** code (still in core, moves in Step 5) and **RAG/Vector/discovery** code (Step 6). Verify with:
```
grep -rn 'PROXYSQLGENAI' lib/ include/ src/main.cpp | grep -v -E '(GenAI|LLM|AI_|Catalog|FTS|RAG|Vector|Discovery|Harvester)'
```
The output should be empty after 4.G.

### Test gating

Step 2 added two ABI smoke tests; Step 3 added a plugin anomaly unit test. Step 4 should add at minimum:

- `plugins/genai/test/unit/backend_client_unit-t.cpp` (4.B)
- `plugins/genai/test/unit/genai_plugin_mcp_lifecycle_unit-t.cpp` (4.E) — asserts `genai_init/start/stop` brings the MCP listener up and down without crashing
- `plugins/genai/test/unit/genai_plugin_mcp_command_unit-t.cpp` (4.F) — registers a fake `services->register_command` recorder, calls `genai_init`, asserts the expected verbs are registered

The existing TAP tests under `test/tap/tests/test_mcp_*` (if any) become integration coverage and must continue to pass after 4.D/4.E/4.F. Inventory them at the start of execution and track which ones gate which sub-step.

### Rollback story

Each sub-step is one commit. `git revert <sha>` should restore the previous working state, **except** that:

- Reverting 4.E without also reverting 4.F leaves `Admin_Handler.cpp` references to a deleted `GloMCPH` symbol. Always revert 4.E and 4.F together.
- Reverting 4.G without reverting 4.E leaves the plugin trying to construct `MCP_Threads_Handler` against missing tables. Revert as a stack (4.G → 4.F → 4.E → 4.D → 4.C → 4.B).

### ProtocolX coordination

This sub-step relies on the plugin command registry from Step 0's cherry-pick. If `origin/ProtocolX` evolves the registry surface before this step lands, re-read `lib/ProxySQL_PluginManager.cpp` and `include/ProxySQL_Plugin.h` and adjust 4.F's dispatch design accordingly. No other ProtocolX coordination concerns for Step 4.

### Out of scope

- Direct-to-backend opt-in (the Q8 "per-target capability"). Tracked as a follow-up; the `target.host`/`target.port` columns stay in the schema for it.
- Async / timeout enforcement on tool-handler queries. Same as today.
- Splitting `genai.so` into `mcp.so` + others. Step 4 keeps everything in one plugin.
- Removing `PROXYSQLGENAI` the macro. That is Step 7.

---

## Closing checklist (run after 4.G)

- [ ] `make clean && make` (no plugin) — succeeds, binary doesn't reference any MCP symbols (`nm src/proxysql | grep -iE 'MCP_|GloMCPH'` → empty)
- [ ] `make clean && make && cd plugins/genai && make` — succeeds, `genai.so` exports the descriptor and contains the moved symbols
- [ ] Start `proxysql` with `plugins = (genai)`; admin port responds; MCP listener responds; one end-to-end MCP `query` tool call succeeds against a real backend hostgroup
- [ ] All `plugins/genai/test/unit/*-t` pass
- [ ] All previously-passing TAP tests pass
- [ ] Carve-out scoreboard updated in the closing commit message:
  ```
  Step 0-2 :    0
  Step 3   : ~1100
  Step 4   : ~13000  (MCP server, endpoint, thread, 8 tool handlers, backend_client)
  ```
