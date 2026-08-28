# GenAI plugin carve-out — design

**Status:** Design approved; implementation plan pending
**Branch:** `v3.0-genai-plugin` (worktree at `.worktrees/v3.0-genai-plugin`)
**Base:** `v3.0` at 13ff9d767
**Date:** 2026-04-16

## Background & motivation

All PROXYSQLGENAI-guarded code currently lives inside the core ProxySQL tree:
63 files touched by `#ifdef PROXYSQLGENAI`, including GenAI/MCP/LLM subsystems,
9 tool handlers, the anomaly detector, schema discovery, and vector storage.
Core call sites reference the globals `GloMCPH`, `GloGATH`, `GloAI` (init/shutdown
in `src/main.cpp`, admin glue in `ProxySQL_Admin.cpp` and `Admin_Handler.cpp`,
a pre-execution hook and a `GENAI:` query-prefix shortcut in `MySQL_Session.cpp`).

The `origin/ProtocolX` branch introduces a plugin loader and ABI
(`proxysql_plugin_descriptor_v1`, `register_table`, `register_command`,
`log_message`, `get_*db`, users/servers snapshots). The reference plugin on
that branch is `mysqlx`. Plugins own their own listener threads; the ABI has no
session-level hooks today.

This effort extracts all PROXYSQLGENAI code into an in-tree plugin at
`plugins/genai/`, using the ProtocolX ABI cherry-picked into this branch and
extended with two additive services (a pre-execution query hook and a
shared Prometheus registry handle). Motivations:

1. Separate core proxy from GenAI/MCP/LLM features so core can ship and be
   reviewed independently of AI features.
2. Isolate and improve testing. The current test tree mixes GenAI tests with
   core tests, obscuring which failures belong to which subsystem. The
   carve-out lets plugin unit tests live with the plugin, while integration
   tests exercise the proxy+plugin combo separately.
3. Stress-test the plugin ABI with a substantially larger exercise than
   `mysqlx`, surfacing boundary problems early.

## Decisions summary

| # | Decision | Choice |
|---|---|---|
| Q1 | Scope | One plugin now (`genai.so`); decompose later if warranted |
| Q2 | `GENAI:` query-prefix hook | Removed; users reach GenAI via MCP, admin SQL, or REST |
| Q3 | Plugin location | In-tree at `plugins/genai/`, alongside `mysqlx` |
| Q4 | ProtocolX dependency ordering | Cherry-pick loader + ABI into this branch |
| Q5 | Admin schema ownership | All GenAI tables/commands via plugin ABI |
| Q6 | Migration strategy | Incremental; module at a time |
| Q7 | Anomaly-detector session hook | Extend ABI with a pre-execution query hook |
| Q8 | Tool-handler backend access | Via `127.0.0.1:6033` / pgsql-port; direct-to-backend as per-target capability |
| Q9 | `PROXYSQLGENAI` build flag | Deleted entirely |
| Q10 | Testing strategy | Hybrid: unit tests in plugin, integration in-tree |

## Goals

1. All `PROXYSQLGENAI`-guarded code leaves `lib/`, `include/`, and
   `src/main.cpp`, moving to `plugins/genai/` as a dynamically-loaded `.so`.
2. Core ProxySQL builds and runs without any knowledge that GenAI exists.
   `PROXYSQLGENAI` the macro is deleted.
3. The plugin communicates with core exclusively through a documented ABI
   (the ProtocolX loader's, with two additive extensions: query hook +
   shared Prometheus registry handle).
4. Test isolation improves: plugin unit tests live with the plugin;
   integration tests live in-tree under a dedicated test group that loads
   the plugin.
5. Feature parity for user-visible behavior, with one explicit exception:
   the `GENAI:`-prefixed MySQL-protocol query shortcut is removed.

## Non-goals

- Decomposing GenAI into sub-plugins (MCP / RAG / Anomaly Detector split).
- Moving the plugin to a separate repo.
- Touching `PROXYSQL31`, `PROXYSQLFFTO`, `PROXYSQLTSDB` feature gates.
- Introducing a generalized `PLUGINS=` make variable.
- Backward compatibility for the `GENAI:` query prefix.
- Hot-reload, per-plugin resource quotas, or plugin sandboxing.

## Architecture

### Process layout

One `proxysql` binary. Zero or more plugin `.so`s loaded at startup based on
`plugins = (...)` in `proxysql.cnf`. `plugins/genai/genai.so` is one of them.
The plugin runs in-process, in its own threads (MCP listener, GenAI worker,
anomaly-detector worker) — the same thread topology as today, just inside
the plugin.

### ABI inherited from ProtocolX

Cherry-picked into this branch as a prerequisite step:

- `proxysql_plugin_descriptor_v1` — exported entry point with
  `init / start / stop / status_json` function pointers.
- `register_table(db, schema, populator, [loader])` — registers tables in
  the admin/config/stats SQLite DBs.
- `register_command(verb, handler)` — registers admin SQL verbs.
- `log_message(level, fmt, ...)` — unified logging.
- `get_admindb() / get_configdb() / get_statsdb()` — raw `sqlite3*` handles.
- `users_snapshot() / servers_snapshot()` — copy-in-time views of
  users/servers.

### ABI extensions added by this work

Both extensions are additive fields inside `ProxySQL_PluginServices`
(new function pointers that are `NULL` in older plugins) — no v2 bump.

1. **Pre-execution query hook.**
   `register_query_hook(proto, callback)` where `proto ∈ {MYSQL, PGSQL}`.
   Callback receives `{user, client_ip, schema, query_text, query_len}` and
   returns `ALLOW | DENY(msg)`. Called from the hot path in `MySQL_Session`
   and `PgSQL_Session` just before the query dispatches to a backend.
   Consumed by the anomaly detector. First real-time extension point.

2. **Prometheus registry access.**
   `get_prometheus_registry()` returns the `prometheus::Registry*` core
   already uses (via `prometheus-cpp`, in `deps/`). Plugins register
   their own counters / gauges / histograms against the shared registry,
   so plugin-owned metrics show up alongside core metrics in the same
   `/metrics` endpoint a scraper already polls. Same C++ ABI coupling
   caveat as the existing `std::string` field: plugins must be built in
   the ProxySQL build tree (or against a matching `prometheus-cpp`).

   For plugin state that is naturally tabular (and queryable via admin
   SQL), use the existing `register_table(stats_db, …)` path, not
   Prometheus. GenAI's existing `stats_mcp_query_tools_counters`,
   `stats_mcp_query_digest`, `stats_mcp_query_rules`, and their
   `_reset` siblings — currently registered in `Admin_Bootstrap.cpp` —
   move to the plugin via that path during Step 4.

   *(`SHOW MYSQL STATUS` is intentionally NOT a target: it's a
   MySQL-protocol-specific response that core owns; mixing plugin
   metrics into it would couple plugins to wire-protocol details.)*

### What the plugin does NOT get

- No session-object access beyond the hook payload above.
- No thread-pool introspection.
- No query-processor internals.
- No direct access to hostgroup manager structures (snapshots only).

### Runtime data flows — plugin to core

- Config reads: admin SQL over localhost, or `get_configdb()` for bulk/rare
  reads.
- Stats reads: `get_statsdb()` directly (read-only use).
- Backend queries issued by tool handlers: a MySQL/PGSQL client connection
  to `127.0.0.1:6033` / pgsql-port as a service user — routing, pooling,
  and ACLs handled by ProxySQL itself. Direct-to-backend (bypassing core)
  is a per-target capability available because MariaDB client + libpq are
  linked into the plugin anyway. Per-target selection lives in the
  `mcp_targets` admin table. **Open for writing-plans:** how the service
  user is provisioned (manual admin bootstrap vs. auto-generated at plugin
  init with a random password written to an admin table vs. Unix-socket
  loopback bypass). This design accepts any of those; the implementation
  plan picks one.

### Runtime data flows — core to plugin

- Lifecycle: `init / start / stop` via the descriptor.
- Admin SQL to plugin-registered tables/commands: routed by the admin
  dispatcher via the ABI.
- Query hook: per-query callback (MySQL + PgSQL).
- Nothing else.

### Globals fate

`GloMCPH`, `GloGATH`, `GloAI` disappear from `src/main.cpp`. Core call sites
become:

- `src/main.cpp:922-924, 961-971` (init/shutdown) → plugin lifecycle via the
  descriptor.
- `Admin_Handler.cpp:1155-1158` (`has_variable`) → `register_command` dispatch.
- `Admin_Handler.cpp:2659-2660` (`load_target_auth_map`) → `register_command`
  dispatch with a joined resultset passed in as command argument.
- `MySQL_Session.cpp:3706` (anomaly analyze) → `register_query_hook` consumer.
- `MySQL_Session.cpp:3795` (`GENAI:` prefix dispatch) → deleted outright.

No weak-linkage pointers in core.

## Module layout

```
plugins/genai/
├── Makefile                       # builds genai.so; links MariaDB client, libpq, curl, etc.
├── plugin.cnf.sample              # documents plugin config knobs
├── include/
│   ├── genai_plugin.h             # descriptor export + plugin-wide globals
│   ├── Anomaly_Detector.h
│   ├── GenAI_Thread.h
│   ├── MCP_Thread.h, MCP_Endpoint.h, MCP_Tool_Handler.h
│   ├── ProxySQL_MCP_Server.hpp
│   ├── LLM_Bridge.h
│   ├── AI_Features_Manager.h, AI_Tool_Handler.h, AI_Vector_Storage.h
│   ├── MySQL_Catalog.h, MySQL_FTS.h, Discovery_Schema.h
│   └── Static_Harvester.h, PgSQL_Static_Harvester.h
├── src/
│   ├── plugin_main.cpp            # proxysql_plugin_descriptor_v1() + init/start/stop
│   ├── plugin_tables.cpp          # all register_table(...) calls (was ProxySQL_Admin glue)
│   ├── plugin_commands.cpp        # all register_command(...) calls (was Admin_Handler glue)
│   ├── plugin_hooks.cpp           # register_query_hook(...) → anomaly_detector
│   ├── plugin_metrics.cpp         # Prometheus counters/gauges via get_prometheus_registry()
│   ├── backend_client.cpp         # shared MySQL+PGSQL client helper used by tool handlers
│   ├── <one .cpp per module>      # existing lib/*.cpp files moved 1:1
│   └── tool_handlers/             # the 9 *_Tool_Handler.cpp files
└── test/
    ├── unit/                      # plugin-internal unit tests
    └── (integration tests live at top-level test/tap/tests/ — see Testing)
```

### Key structural decisions

- **Plugin adapters (`plugin_*.cpp`) are new files** that own the ABI
  boundary. They are the only files that include `<proxysql_plugin_abi.h>`.
  Every other file in the plugin stays "domain code" that doesn't know it's
  in a plugin — which makes modules trivially testable in `test/unit/`.
- **Tool handlers get their own subdir.** There are 9, they share a base
  class, and grouping them physically matches how they're reasoned about.
- **`backend_client.cpp` consolidates** MySQL and PgSQL client usage that's
  currently scattered across `Query_Tool_Handler`, `MCP_Tool_Handler`, etc.
  This is the one targeted cleanup included — it's the main entry point for
  the "connect to local ProxySQL" pattern.
- **`plugin.cnf.sample`** documents plugin-specific admin tables and default
  rows. Actual config lives in admin tables (registered via `register_table`),
  not in cnf sections.
- **No header rewrites.** Existing headers move verbatim; the Makefile sets
  `-I` appropriately.

### What stays in core

- `include/proxysql_plugin_abi.h` — public contract, part of the ProtocolX
  cherry-pick.
- Nothing else GenAI-related. The 14 references in `ProxySQL_Admin.cpp` and
  5 in `Admin_Handler.cpp` are deleted; the corresponding admin tables and
  commands move to `plugin_tables.cpp` / `plugin_commands.cpp`.

## Migration sequence

Each step is a reviewable PR that leaves the tree buildable both with and
without the plugin loaded. Steps target `v3.0` (or an integration branch off
it), not each other, to keep review scope bounded.

**Step 0 — ProtocolX cherry-pick (prerequisite).**
Cherry-pick from `origin/ProtocolX`: the plugin loader
(`ProxySQL_PluginManager`), the ABI header (`proxysql_plugin_abi.h`), the
`plugins = (...)` cnf parser, and — if useful as a reference test — the
`mysqlx` plugin. Purely additive to core; no core behavior changes unless a
plugin is listed in the cnf.

**Step 1 — Plugin skeleton.**
Create `plugins/genai/` with `Makefile`, `plugin_main.cpp` exporting a
descriptor whose `init/start/stop` do nothing, and a trivial unit test that
loads/unloads the `.so`. Wire into top-level `Makefile` as an optional
artifact. After this PR, `plugins = (genai)` loads an empty plugin
successfully.

**Step 2 — ABI extensions land.**
Add `register_query_hook` (MySQL + PgSQL hot-path call site, no-op when no
hook registered) and `get_prometheus_registry` (returns the same
`prometheus::Registry*` core uses). Tests: a synthetic test plugin that
registers a hook counting queries and asserts the count; another that
registers a Prometheus counter and asserts it appears at `/metrics`.
Does not yet touch anomaly detection. Isolates the hot-path change as its
own PR for review scrutiny.

**Step 3 — Move Anomaly Detector.**
Move `Anomaly_Detector.{h,cpp}` and the `st_var_ai_*` counters into the
plugin. Replace `MySQL_Session.cpp:3706` call site with the new
`register_query_hook` consumer inside the plugin. Delete the old call site
from core. CI: add a `genai-anomaly` test group.

**Step 4 — Move MCP subsystem.**
Move `MCP_Thread`, `MCP_Endpoint`, `MCP_Tool_Handler`, `ProxySQL_MCP_Server`,
and the 9 tool handlers. Introduce `backend_client.cpp` consolidating
MySQL+PgSQL client usage. Rewire tool handlers' backend access to go through
`127.0.0.1:6033` / pgsql-port. Delete `GloMCPH`; replace Admin_Handler
`has_variable` / `load_target_auth_map` sites with admin-SQL dispatch via
`register_command`. Delete the `GENAI:` query-prefix detection and dispatch
in `MySQL_Session` (line numbers approximate: prefix detection near 3737,
`GloGATH->process_json_query` dispatch near 3795 as of base 13ff9d767).

**Step 5 — Move GenAI/LLM and AI Features.**
Move `GenAI_Thread`, `LLM_Bridge`, `LLM_Clients`, `AI_Features_Manager`,
`AI_Tool_Handler`. Delete `GloGATH` and `GloAI`; migrate the remaining
`Admin_Handler.cpp:1155-1158` references to `register_command` handlers.

**Step 6 — Move RAG/Vector and schema discovery.**
Move `AI_Vector_Storage`, `RAG_Tool_Handler`, `MySQL_Catalog`, `MySQL_FTS`,
`Discovery_Schema`, `Static_Harvester`, `PgSQL_Static_Harvester`. Mostly
leaf modules that don't touch core — a file-move exercise.

**Step 7 — Delete `PROXYSQLGENAI`.**
Remove the macro from all build files and any surviving conditional
compilation. Audit that nothing in core still references GenAI symbols.
Delete `test/tap/tests_with_deps/genai-*` files that got moved. Update
docs. This is the point of no return — reverting after this means
cherry-picking all the deletions back.

### Rollback story

Steps 1–6 are individually revertable (plugin doesn't load, or a module
isn't in the plugin yet). Step 7 is not.

### ProtocolX coordination

Step 2 extends the ABI before ProtocolX is upstream. When ProtocolX merges
to `v3.0`, either (a) it absorbs the hook + Prometheus-registry extensions,
or (b) this branch rebases onto the merged ProtocolX and moves its
additions. The writing-plans phase will decide who owns this reconciliation.

## Error handling and failure modes

- **Plugin load failure** (missing `.so`, missing descriptor symbol, ABI
  version mismatch, `init` returns error): core logs and aborts startup.
  A plugin listed in `plugins = (...)` is a required dependency; no silent
  degradation.
- **ABI version mismatch**: descriptor includes a version field; core
  refuses mismatches at load. Additive extensions stay inside v1 as new
  fields that are NULL in older plugins. A breaking ABI change would
  introduce a v2 descriptor coexisting with v1.
- **Query hook returns DENY**: core sends an error to the client
  (`ERROR 1045`-style for MySQL, equivalent for PgSQL) with the
  plugin-supplied message. Query does not dispatch to backend.
- **Query hook crashes**: same as any in-process segfault — process dies.
  No sandboxing in v1; trust model matches loadable modules in other
  proxies.
- **Slow query hook**: no timeout enforcement in v1. Hook runs synchronously
  on the session thread; slow hook slows the proxy. Documented as
  plugin-author responsibility. Async/timeout is a future extension.
- **Prometheus metric name collision**: registering a metric whose name is
  already taken in the shared registry surfaces as a `prometheus-cpp`
  exception inside the plugin's init; plugin aborts its init and core
  refuses startup. Plugins should namespace their metric names
  (e.g. `proxysql_genai_*`).
- **Admin SQL dispatch failures** (plugin command handler throws): caught
  at the ABI boundary, returned to the admin client as a SQL error, logged.
  Does not crash core.
- **Backend-client failures inside the plugin**: standard MySQL/PGSQL
  client error handling; surfaces to the MCP client invoking the tool.
- **Partial migration states** (Steps 1–6): if someone builds with the
  PROXYSQLGENAI flag during this window but doesn't list `genai` in
  `plugins = (...)`, GenAI features are simply absent — same UX as
  building `PROXYSQLGENAI=0` today.

## Testing

### Unit tests — `plugins/genai/test/unit/`

- Anomaly detector rule engine: synthetic `(user, ip, schema, query)`
  tuples, assert allow/deny.
- Tool-handler logic: mock `backend_client`; assert each tool produces
  correct MCP JSON for correct/malformed inputs.
- LLM_Bridge / LLM_Clients: mock HTTP transport; assert per-provider
  request shape and error/timeout handling.
- MySQL_Catalog / MySQL_FTS / Discovery_Schema: feed in-memory sqlite3
  handles with fixture data; assert query results.

Built via `make -C plugins/genai test`. Runs in CI as a fast job — no
Docker, no backends. Follows the existing core unit-test harness pattern
(`test_globals.h` / `test_init.h`).

### Integration tests — `test/tap/tests/`

- New group `genai-g1` starts proxysql with `plugins = (genai)` and
  exercises real end-to-end flows. If GenAI behavior diverges across MySQL
  server versions (the current test matrix covers `mysql57`, `mysql84`,
  `mysql90`, `mysql95`), a version-specific sibling (`genai-mysql84-g1`,
  etc.) is added only for the versions where coverage is needed — not
  blanket-replicated.: MCP client → tool handler → `127.0.0.1:6033` →
  backend; anomaly detector blocking a real query; admin SQL round-trips
  hitting plugin-registered tables.
- Docker infra in `test/infra/` grows the configs this group needs.
  LLM calls use mocks/offline stubs; no real OpenAI calls in CI.
- Runs in CI as a slower job, gated on unit tests passing.

### ABI smoke tests — `test/tap/tests/`

- `test_plugin_loader-t.cpp`: loads a dummy `.so` built for tests, asserts
  init/start/stop lifecycle, asserts `plugins = ()` leaves core untouched,
  asserts malformed descriptor fails cleanly. Not GenAI-specific —
  benefits `mysqlx` too.
- `test_plugin_query_hook-t.cpp`: dummy plugin registers a counting hook;
  test asserts every query increments and that DENY returns the error to
  the client.
- `test_plugin_prometheus-t.cpp`: dummy plugin registers a Prometheus
  counter against the shared registry; test scrapes `/metrics` and
  asserts the metric (and its incremented value) is present.

### Test group wiring

- `test/tap/groups/genai-g1/pre-proxysql.bash` generates a proxysql.cnf
  with `plugins = (genai)`.
- `test/tap/groups/genai-g1/infras.lst` lists Docker compose targets.
- `.github/workflows/` grows a `CI-genai.yml` caller job following the
  two-branch caller/reusable split documented in
  `doc/GH-Actions/README.md`.

### Migration-step test gating

Each step from the migration sequence lands with its corresponding tests.
Step 2 blocks on the two ABI smoke tests. Step 3 blocks on anomaly-detector
unit tests. Etc. No step merges without tests that prove that step's delta.

## Dependencies and packaging

### Plugin's link-time deps

- MariaDB client library (in `deps/`) — linked into the plugin.
- `libpq` (in `deps/postgresql/`) — same.
- `curl`, `lz4`, `zstd` (in `deps/`) — linked for LLM HTTP calls and any
  compressed protocol.
- `sqlite3` — NOT linked into the plugin; uses `sqlite3*` handles from
  core via `get_admindb()` etc. One `sqlite3` symbol set in the process.
- `jemalloc` — NOT linked into the plugin; inherits core's allocator via
  normal dynamic linking.
- `re2` / `pcre` — linked if a moved module needs them (e.g., anomaly
  detector rule matching). Decided per module.

### Binary impact

`genai.so` on the order of tens of MB (client libs + LLM/MCP code). Core
`proxysql` binary shrinks by whatever `PROXYSQLGENAI` adds today. Net
process-RSS roughly neutral.

### Packaging

- New subpackage `proxysql-genai` drops `genai.so` under
  `/usr/lib/proxysql/plugins/` and `plugin.cnf.sample` under
  `/usr/share/proxysql/`. Depends on the matching `proxysql` version.
- `make packages` grows a target for the subpackage.
- AI-tier Docker images include the subpackage; core images don't.
- The "AI tier" becomes `proxysql` + `proxysql-genai` installed together,
  replacing the old `PROXYSQLGENAI=1` build variant.

### Config file

Users enable the plugin by adding `plugins = (genai)` to `proxysql.cnf`.
Plugin-specific config lives in admin tables registered via
`register_table`. `plugin.cnf.sample` documents those tables and default
rows. No new top-level cnf sections for GenAI.

### Docs to update (Step 7)

- `CLAUDE.md`: remove GenAI from "Core Components" and "Conditional
  Components"; add a "Plugins" section pointing to
  `plugins/genai/README.md`. Update the feature-tier table — "AI/MCP" tier
  becomes "install `proxysql-genai` subpackage and enable in cnf" rather
  than `PROXYSQLGENAI=1`.
- `doc/GH-Actions/README.md`: document the new `CI-genai.yml` caller and
  its reusable counterpart.
- `doc/agents/project-conventions.md`: add plugin-authoring conventions
  (ABI header, where plugins live, no core globals).
- New `plugins/genai/README.md`: user-facing docs for the plugin — what
  it provides, how to enable, admin tables it adds, config knobs.
- `.github/workflows/`: remove `PROXYSQLGENAI=1` from build matrices;
  add the plugin-artifact build.

### What doesn't change

- Other feature flags (`PROXYSQL31`, `PROXYSQLFFTO`, `PROXYSQLTSDB`)
  stay. Feature tiers retain meaning for non-AI features.
- Licensing: plugin stays GPL, same as core.
