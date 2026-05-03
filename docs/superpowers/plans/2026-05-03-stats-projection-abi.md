# Stats Projection ABI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the plugin ABI so plugins can project stats tables into `statsdb` (not just `admin_db`), then move the 5 `stats_mcp_*` tables from core to the genai plugin and clean up mysqlx's back-channel workaround.

**Architecture:** Add a `db_kind` field to `ProxySQL_PluginRuntimeView` (ABI v3→v4). The chassis dispatches the correct DB handle (`admindb`/`configdb`/`statsdb`) based on `db_kind`. Genai registers 5 stats tables + refresh callbacks. Mysqlx drops its back-channel in favor of the chassis-supplied handle.

**Tech Stack:** C++17, SQLite3, plugin chassis ABI, pthread rwlocks.

**Design doc:** `docs/superpowers/specs/2026-05-03-stats-projection-abi-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `include/ProxySQL_Plugin.h` | Modify | ABI struct: add `db_kind` to `ProxySQL_PluginRuntimeView`, bump version v4 |
| `include/ProxySQL_PluginManager.h` | Modify | Internal: add `db_kind` to `registered_runtime_view_t`, extend dispatch signature |
| `lib/ProxySQL_PluginManager.cpp` | Modify | Dispatch: store `db_kind` on registration, select DB by `db_kind` in refresh |
| `lib/ProxySQL_Admin.cpp` | Modify | Call site: pass all 3 DB handles to refresh function |
| `include/ProxySQL_Admin_Tables_Definitions.h` | Modify | Remove 5 `STATS_SQLITE_TABLE_MCP_*` macros |
| `lib/ProxySQL_Admin_Stats.cpp` | Modify | Remove MCP design comments (lines 2604-2651) |
| `plugins/mysqlx/src/mysqlx_admin_schema.cpp` | Modify | Set `db_kind` on 6 registrations, simplify 2 stats callbacks |
| `plugins/genai/src/plugin_tables.cpp` | Modify | Add 5 DDL constants, 5 refresh callbacks, 5 table + 5 view registrations |
| `test/tap/tests/unit/plugin_runtime_views_unit-t.cpp` | Modify | Update aggregate init to include `db_kind`, add `db_kind` dispatch test |
| `doc/plugin-chassis/ABI.md` | Modify | Document ABI v4 change |

---

### Task 1: Extend `ProxySQL_PluginRuntimeView` with `db_kind` and bump ABI

**Files:**
- Modify: `include/ProxySQL_Plugin.h:32-33,217-224`

- [ ] **Step 1: Update ABI version constants**

In `include/ProxySQL_Plugin.h`, change lines 32-33:

```cpp
#define PROXYSQL_PLUGIN_ABI_VERSION 4u
#define PROXYSQL_PLUGIN_ABI_VERSION_MAX 4u
```

And add `db_kind` to the struct at lines 217-221:

```cpp
struct ProxySQL_PluginRuntimeView {
	const char *table_name;
	void (*refresh)(SQLite3DB *db, void *opaque);
	void *opaque;
	ProxySQL_PluginDBKind db_kind;
};
```

Update the comment block at lines 26-31 to document ABI v4:

```cpp
//   ABI 1: original 6-field descriptor (name, abi_version, init, start,
//          stop, status_json). Pre-chassis build.
//   ABI 2: appends `register_schemas` (four-phase lifecycle, PROXYSQL40).
//   ABI 3: same descriptor layout as ABI 2; ProxySQL_PluginServices grows
//          a `register_runtime_view` field at the end so plugins can
//          declare admin-side projections of module state. Plugins that
//          stay on ABI 2 keep working — they simply don't see the new
//          field in their compiled-against struct, and core never
//          dereferences past the ABI-2 layout for them.
//   ABI 4: ProxySQL_PluginRuntimeView gains a `db_kind` field at the
//          start of the struct. The chassis passes the matching DB handle
//          (admindb/configdb/statsdb) to the refresh callback instead of
//          always passing admindb. Plugins must set db_kind explicitly.
```

Also update the comment at lines 184-212 to mention `db_kind`. Change the paragraph starting at line 200:

```cpp
// The refresh callback receives a borrowed DB handle matching the
// registered db_kind (admin_db → admindb, config_db → configdb,
// stats_db → statsdb) and is expected to do (typically) `BEGIN;
// DELETE FROM <table>; INSERT/REPLACE INTO <table> ...; COMMIT;`
// from the module's in-memory state.
```

- [ ] **Step 2: Commit**

```bash
git add include/ProxySQL_Plugin.h
git commit -m "feat(abi): add db_kind to ProxySQL_PluginRuntimeView, bump ABI v4 (issue #5729)"
```

---

### Task 2: Update `ProxySQL_PluginManager` internal struct and dispatch

**Files:**
- Modify: `include/ProxySQL_PluginManager.h:72,81,138-143`
- Modify: `lib/ProxySQL_PluginManager.cpp:164-170,764-821,975-987`

- [ ] **Step 1: Update `registered_runtime_view_t` in `include/ProxySQL_PluginManager.h`**

Add `db_kind` to the struct at line 138:

```cpp
struct registered_runtime_view_t {
	ProxySQL_PluginDBKind db_kind { ProxySQL_PluginDBKind::admin_db };
	std::string table_name {};
	void (*refresh)(SQLite3DB*, void*) { nullptr };
	void* opaque { nullptr };
};
```

Update the `refresh_runtime_views_for_query` declaration at line 81:

```cpp
void refresh_runtime_views_for_query(const std::string& sql,
	SQLite3DB* admindb, SQLite3DB* configdb, SQLite3DB* statsdb) const;
```

- [ ] **Step 2: Update `register_runtime_view` implementation in `lib/ProxySQL_PluginManager.cpp`**

At line 764, add `db_kind` storage:

```cpp
bool ProxySQL_PluginManager::register_runtime_view(const ProxySQL_PluginRuntimeView& view) {
	if (view.table_name == nullptr || *view.table_name == '\0' || view.refresh == nullptr) {
		return false;
	}
	for (const auto& existing : runtime_views_) {
		if (strcasecmp(existing.table_name.c_str(), view.table_name) == 0) {
			return false;
		}
	}
	registered_runtime_view_t entry;
	entry.db_kind = view.db_kind;
	entry.table_name = view.table_name;
	entry.refresh = view.refresh;
	entry.opaque = view.opaque;
	runtime_views_.push_back(std::move(entry));
	return true;
}
```

- [ ] **Step 3: Update `refresh_runtime_views_for_query` dispatch**

Replace the method at line 815:

```cpp
void ProxySQL_PluginManager::refresh_runtime_views_for_query(const std::string& sql,
	SQLite3DB* admindb, SQLite3DB* configdb, SQLite3DB* statsdb) const
{
	for (const auto& view : runtime_views_) {
		if (view.refresh == nullptr) continue;
		if (!sql_references_table_ci(sql, view.table_name)) continue;
		SQLite3DB* db = nullptr;
		switch (view.db_kind) {
		case ProxySQL_PluginDBKind::admin_db:  db = admindb; break;
		case ProxySQL_PluginDBKind::config_db: db = configdb; break;
		case ProxySQL_PluginDBKind::stats_db:  db = statsdb;  break;
		}
		if (db == nullptr) continue;
		view.refresh(db, view.opaque);
	}
}
```

- [ ] **Step 4: Update `proxysql_refresh_configured_plugin_runtime_views` free function**

Replace the function at line 975:

```cpp
void proxysql_refresh_configured_plugin_runtime_views(const std::string& sql,
	SQLite3DB* admindb, SQLite3DB* configdb, SQLite3DB* statsdb)
{
	std::shared_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
	ProxySQL_PluginManager* mgr = g_active_plugin_manager.load();
	if (mgr == nullptr) {
		return;
	}
	mgr->refresh_runtime_views_for_query(sql, admindb, configdb, statsdb);
}
```

Update the declaration in `include/ProxySQL_PluginManager.h` at line 177:

```cpp
void proxysql_refresh_configured_plugin_runtime_views(const std::string& sql,
	SQLite3DB* admindb, SQLite3DB* configdb, SQLite3DB* statsdb);
```

Update the comment at lines 171-176 to mention the new parameters:

```cpp
// Admin-side helper: invoke every plugin runtime-view refresh callback
// whose registered table is referenced by `sql`. Used by Admin's
// pre-SELECT path, mirroring the way runtime_mysql_users is refreshed
// before its SELECTs. No-op if no plugin manager is active or no views
// match. Caller supplies all three DB handles; the chassis dispatches
// the correct one based on each view's registered db_kind.
```

- [ ] **Step 5: Commit**

```bash
git add include/ProxySQL_PluginManager.h lib/ProxySQL_PluginManager.cpp
git commit -m "feat(chassis): dispatch correct DB handle by db_kind in runtime view refresh (issue #5729)"
```

---

### Task 3: Update the call site in `ProxySQL_Admin::GenericRefreshStatistics`

**Files:**
- Modify: `lib/ProxySQL_Admin.cpp:1622-1624`

- [ ] **Step 1: Pass all 3 DB handles**

At line 1622-1624, change:

```cpp
	if (admin) {
		proxysql_refresh_configured_plugin_runtime_views(query_no_space, admindb, configdb, statsdb);
	}
```

`admindb`, `configdb`, and `statsdb` are member variables of `ProxySQL_Admin` (declared at lines 606-608 of `proxysql_admin.h`).

- [ ] **Step 2: Commit**

```bash
git add lib/ProxySQL_Admin.cpp
git commit -m "feat(admin): pass all 3 DB handles to plugin runtime view refresh (issue #5729)"
```

---

### Task 4: Update mysqlx plugin registrations

**Files:**
- Modify: `plugins/mysqlx/src/mysqlx_admin_schema.cpp:269-290,502-508`

- [ ] **Step 1: Simplify stats refresh callbacks**

Replace `refresh_stats_routes_view` at line 269:

```cpp
void refresh_stats_routes_view(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	mysqlx_stats().flush_to_sqlite(*db);
}
```

Replace `refresh_stats_processlist_view` at line 283:

```cpp
void refresh_stats_processlist_view(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	if (&mysqlx_populate_stats_processlist == nullptr) return;
	mysqlx_populate_stats_processlist(*db);
}
```

- [ ] **Step 2: Add `db_kind` to all runtime view registrations**

At lines 502-508, change:

```cpp
	if (services.register_runtime_view != nullptr) {
		services.register_runtime_view({ProxySQL_PluginDBKind::admin_db, kRuntimeMysqlxUsersTable,             &refresh_users_runtime_view,     nullptr});
		services.register_runtime_view({ProxySQL_PluginDBKind::admin_db, kRuntimeMysqlxRoutesTable,            &refresh_routes_runtime_view,    nullptr});
		services.register_runtime_view({ProxySQL_PluginDBKind::admin_db, kRuntimeMysqlxBackendEndpointsTable,  &refresh_endpoints_runtime_view, nullptr});
		services.register_runtime_view({ProxySQL_PluginDBKind::admin_db, kRuntimeMysqlxVariablesTable,         &refresh_variables_runtime_view, nullptr});
		services.register_runtime_view({ProxySQL_PluginDBKind::stats_db, kStatsMysqlxRoutesTable,              &refresh_stats_routes_view,      nullptr});
		services.register_runtime_view({ProxySQL_PluginDBKind::stats_db, kStatsMysqlxProcesslistTable,         &refresh_stats_processlist_view, nullptr});
	}
```

- [ ] **Step 3: Commit**

```bash
git add plugins/mysqlx/src/mysqlx_admin_schema.cpp
git commit -m "feat(mysqlx): set db_kind on runtime views, drop statsdb back-channel (issue #5729)"
```

---

### Task 5: Update genai plugin — existing registrations + stats tables

**Files:**
- Modify: `plugins/genai/src/plugin_tables.cpp`
- Modify: `include/ProxySQL_Admin_Tables_Definitions.h` (remove 5 macros)
- Modify: `lib/ProxySQL_Admin_Stats.cpp` (remove MCP comments)

- [ ] **Step 1: Add stats DDL constants and helper to `plugin_tables.cpp`**

Add these locally in the anonymous namespace (after the existing `register_config` helper at line 40):

```cpp
void register_stats(ProxySQL_PluginServices* services, const char* name, const char* def) {
	ProxySQL_PluginTableDef td { ProxySQL_PluginDBKind::stats_db, name, def };
	services->register_table(td);
}

static constexpr const char* kStatsMCPQueryToolsCounters =
	"CREATE TABLE stats_mcp_query_tools_counters ("
	"  endpoint VARCHAR NOT NULL ,"
	"  tool VARCHAR NOT NULL ,"
	"  schema VARCHAR NOT NULL ,"
	"  count INT NOT NULL ,"
	"  first_seen INTEGER NOT NULL ,"
	"  last_seen INTEGER NOT NULL ,"
	"  sum_time INTEGER NOT NULL ,"
	"  min_time INTEGER NOT NULL ,"
	"  max_time INTEGER NOT NULL ,"
	"  PRIMARY KEY (endpoint, tool, schema))";

static constexpr const char* kStatsMCPQueryToolsCountersReset =
	"CREATE TABLE stats_mcp_query_tools_counters_reset ("
	"  endpoint VARCHAR NOT NULL ,"
	"  tool VARCHAR NOT NULL ,"
	"  schema VARCHAR NOT NULL ,"
	"  count INT NOT NULL ,"
	"  first_seen INTEGER NOT NULL ,"
	"  last_seen INTEGER NOT NULL ,"
	"  sum_time INTEGER NOT NULL ,"
	"  min_time INTEGER NOT NULL ,"
	"  max_time INTEGER NOT NULL ,"
	"  PRIMARY KEY (endpoint, tool, schema))";

static constexpr const char* kStatsMCPQueryDigest =
	"CREATE TABLE stats_mcp_query_digest ("
	"  tool_name VARCHAR NOT NULL ,"
	"  run_id INT ,"
	"  digest VARCHAR NOT NULL ,"
	"  digest_text VARCHAR NOT NULL ,"
	"  count_star INTEGER NOT NULL ,"
	"  first_seen INTEGER NOT NULL ,"
	"  last_seen INTEGER NOT NULL ,"
	"  sum_time INTEGER NOT NULL ,"
	"  min_time INTEGER NOT NULL ,"
	"  max_time INTEGER NOT NULL ,"
	"  PRIMARY KEY(tool_name, run_id, digest))";

static constexpr const char* kStatsMCPQueryDigestReset =
	"CREATE TABLE stats_mcp_query_digest_reset ("
	"  tool_name VARCHAR NOT NULL ,"
	"  run_id INT ,"
	"  digest VARCHAR NOT NULL ,"
	"  digest_text VARCHAR NOT NULL ,"
	"  count_star INTEGER NOT NULL ,"
	"  first_seen INTEGER NOT NULL ,"
	"  last_seen INTEGER NOT NULL ,"
	"  sum_time INTEGER NOT NULL ,"
	"  min_time INTEGER NOT NULL ,"
	"  max_time INTEGER NOT NULL ,"
	"  PRIMARY KEY(tool_name, run_id, digest))";

static constexpr const char* kStatsMCPQueryRules =
	"CREATE TABLE stats_mcp_query_rules ("
	"  rule_id INTEGER PRIMARY KEY NOT NULL ,"
	"  username VARCHAR ,"
	"  target_id VARCHAR ,"
	"  hits INTEGER NOT NULL)";
```

- [ ] **Step 2: Add stats refresh callbacks**

Add these in the anonymous namespace (after the existing runtime refresh callbacks):

```cpp
void refresh_stats_mcp_query_digest(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;
	Query_Tool_Handler* qth = mcp->query_tool_handler;
	if (qth == nullptr) return;
	Discovery_Schema* catalog = qth->get_catalog();
	if (catalog == nullptr) return;
	SQLite3_result* result = catalog->get_mcp_query_digest(false);
	if (result == nullptr) return;
	if (!db->execute("BEGIN")) { delete result; return; }
	db->execute("DELETE FROM stats_mcp_query_digest");
	char** row;
	while ((row = result->next_row()) != nullptr) {
		char* q = sqlite3_mprintf(
			"INSERT INTO stats_mcp_query_digest"
			" (tool_name, run_id, digest, digest_text, count_star,"
			"  first_seen, last_seen, sum_time, min_time, max_time)"
			" VALUES('%q','%q','%q','%q','%q','%q','%q','%q','%q','%q')",
			row[0], row[1], row[2], row[3], row[4],
			row[5], row[6], row[7], row[8], row[9]);
		db->execute(q);
		sqlite3_free(q);
	}
	db->execute("COMMIT");
	delete result;
}

void refresh_stats_mcp_query_digest_reset(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;
	Query_Tool_Handler* qth = mcp->query_tool_handler;
	if (qth == nullptr) return;
	Discovery_Schema* catalog = qth->get_catalog();
	if (catalog == nullptr) return;
	SQLite3_result* result = catalog->get_mcp_query_digest(true);
	if (result == nullptr) return;
	if (!db->execute("BEGIN")) { delete result; return; }
	db->execute("DELETE FROM stats_mcp_query_digest_reset");
	char** row;
	while ((row = result->next_row()) != nullptr) {
		char* q = sqlite3_mprintf(
			"INSERT INTO stats_mcp_query_digest_reset"
			" (tool_name, run_id, digest, digest_text, count_star,"
			"  first_seen, last_seen, sum_time, min_time, max_time)"
			" VALUES('%q','%q','%q','%q','%q','%q','%q','%q','%q','%q')",
			row[0], row[1], row[2], row[3], row[4],
			row[5], row[6], row[7], row[8], row[9]);
		db->execute(q);
		sqlite3_free(q);
	}
	db->execute("COMMIT");
	delete result;
}

void refresh_stats_mcp_query_rules(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;
	Query_Tool_Handler* qth = mcp->query_tool_handler;
	if (qth == nullptr) return;
	Discovery_Schema* catalog = qth->get_catalog();
	if (catalog == nullptr) return;
	SQLite3_result* result = catalog->get_stats_mcp_query_rules();
	if (result == nullptr) return;
	if (!db->execute("BEGIN")) { delete result; return; }
	db->execute("DELETE FROM stats_mcp_query_rules");
	char** row;
	while ((row = result->next_row()) != nullptr) {
		char* q = sqlite3_mprintf(
			"INSERT INTO stats_mcp_query_rules"
			" (rule_id, username, target_id, hits)"
			" VALUES('%q','%q','%q','%q')",
			row[0], row[1], row[2], row[3]);
		db->execute(q);
		sqlite3_free(q);
	}
	db->execute("COMMIT");
	delete result;
}

void refresh_stats_mcp_query_tools_counters(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;
	Query_Tool_Handler* qth = mcp->query_tool_handler;
	if (qth == nullptr) return;
	SQLite3_result* result = qth->get_tool_usage_stats_resultset(false);
	if (result == nullptr) return;
	if (!db->execute("BEGIN")) { delete result; return; }
	db->execute("DELETE FROM stats_mcp_query_tools_counters");
	char** row;
	while ((row = result->next_row()) != nullptr) {
		char* q = sqlite3_mprintf(
			"INSERT INTO stats_mcp_query_tools_counters"
			" (endpoint, tool, schema, count, first_seen,"
			"  last_seen, sum_time, min_time, max_time)"
			" VALUES('%q','%q','%q','%q','%q','%q','%q','%q','%q')",
			row[0], row[1], row[2], row[3], row[4],
			row[5], row[6], row[7], row[8]);
		db->execute(q);
		sqlite3_free(q);
	}
	db->execute("COMMIT");
	delete result;
}

void refresh_stats_mcp_query_tools_counters_reset(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;
	Query_Tool_Handler* qth = mcp->query_tool_handler;
	if (qth == nullptr) return;
	SQLite3_result* result = qth->get_tool_usage_stats_resultset(true);
	if (result == nullptr) return;
	if (!db->execute("BEGIN")) { delete result; return; }
	db->execute("DELETE FROM stats_mcp_query_tools_counters_reset");
	char** row;
	while ((row = result->next_row()) != nullptr) {
		char* q = sqlite3_mprintf(
			"INSERT INTO stats_mcp_query_tools_counters_reset"
			" (endpoint, tool, schema, count, first_seen,"
			"  last_seen, sum_time, min_time, max_time)"
			" VALUES('%q','%q','%q','%q','%q','%q','%q','%q','%q')",
			row[0], row[1], row[2], row[3], row[4],
			row[5], row[6], row[7], row[8]);
		db->execute(q);
		sqlite3_free(q);
	}
	db->execute("COMMIT");
	delete result;
}
```

Add the needed include at the top of the file (after the existing includes):

```cpp
#include "Query_Tool_Handler.h"
#include "Discovery_Schema.h"
```

- [ ] **Step 3: Update `register_runtime_view_or_warn` to accept `db_kind`**

Replace the helper at lines 67-76:

```cpp
void register_runtime_view_or_warn(
	ProxySQL_PluginServices* services,
	ProxySQL_PluginDBKind db_kind,
	const char* name,
	void (*cb)(SQLite3DB*, void*)
) {
	ProxySQL_PluginRuntimeView v { db_kind, name, cb, nullptr };
	if (!services->register_runtime_view(v)) {
		genai_log(6, "genai plugin: register_runtime_view(%s) failed\n", name);
	}
}
```

- [ ] **Step 4: Update existing runtime view registrations to include `db_kind = admin_db`**

In `genai_register_admin_tables`, change lines 126-132:

```cpp
	if (services->register_runtime_view != nullptr) {
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::admin_db,
		                              "runtime_mcp_auth_profiles",
		                              &refresh_runtime_mcp_auth_profiles);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::admin_db,
		                              "runtime_mcp_target_profiles",
		                              &refresh_runtime_mcp_target_profiles);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::admin_db,
		                              "runtime_mcp_query_rules",
		                              &refresh_runtime_mcp_query_rules);
	}
```

- [ ] **Step 5: Add stats table and runtime view registrations**

Add after the existing runtime view registrations (before the closing `}` of `genai_register_admin_tables`):

```cpp
	// Stats tables (stats_db). These are projected on demand from the
	// plugin's in-memory counters by the refresh callbacks registered
	// below.
	register_stats(services, "stats_mcp_query_tools_counters",
	               kStatsMCPQueryToolsCounters);
	register_stats(services, "stats_mcp_query_tools_counters_reset",
	               kStatsMCPQueryToolsCountersReset);
	register_stats(services, "stats_mcp_query_digest",
	               kStatsMCPQueryDigest);
	register_stats(services, "stats_mcp_query_digest_reset",
	               kStatsMCPQueryDigestReset);
	register_stats(services, "stats_mcp_query_rules",
	               kStatsMCPQueryRules);

	if (services->register_runtime_view != nullptr) {
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::stats_db,
		                              "stats_mcp_query_digest",
		                              &refresh_stats_mcp_query_digest);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::stats_db,
		                              "stats_mcp_query_digest_reset",
		                              &refresh_stats_mcp_query_digest_reset);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::stats_db,
		                              "stats_mcp_query_rules",
		                              &refresh_stats_mcp_query_rules);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::stats_db,
		                              "stats_mcp_query_tools_counters",
		                              &refresh_stats_mcp_query_tools_counters);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::stats_db,
		                              "stats_mcp_query_tools_counters_reset",
		                              &refresh_stats_mcp_query_tools_counters_reset);
	}
```

- [ ] **Step 6: Remove `#include "ProxySQL_Admin_Tables_Definitions.h"` from plugin_tables.cpp**

Remove the include at line 26 — the genai plugin no longer needs it for the stats DDLs (the admin/config table DDL macros are still there, but those are also referenced from this file). Actually, check: the existing admin table registrations use `ADMIN_SQLITE_TABLE_MCP_QUERY_RULES` etc. Those macros are still defined in `ProxySQL_Admin_Tables_Definitions.h`. So the include must stay.

Keep the include. Only the `STATS_SQLITE_TABLE_MCP_*` macros are being moved to local constants.

- [ ] **Step 7: Commit**

```bash
git add plugins/genai/src/plugin_tables.cpp
git commit -m "feat(genai): register stats_mcp_* tables with db_kind=stats_db and refresh callbacks (issue #5729)"
```

---

### Task 6: Remove MCP stats macros and comments from core

**Files:**
- Modify: `include/ProxySQL_Admin_Tables_Definitions.h:350-351,455-494`
- Modify: `lib/ProxySQL_Admin_Stats.cpp:2604-2651`

- [ ] **Step 1: Remove 5 `STATS_SQLITE_TABLE_MCP_*` macros from `ProxySQL_Admin_Tables_Definitions.h`**

Remove lines 350-351 (`STATS_SQLITE_TABLE_MCP_QUERY_TOOLS_COUNTERS` and `_RESET`).

Remove lines 455-494 (the `STATS_SQLITE_TABLE_MCP_QUERY_DIGEST`, `_RESET`, and `STATS_SQLITE_TABLE_MCP_QUERY_RULES` macros, plus their comment blocks).

- [ ] **Step 2: Remove MCP design comments from `ProxySQL_Admin_Stats.cpp`**

Remove lines 2604-2651 (the MCP QUERY DIGEST STATS and MCP query rules statistics comment blocks that describe the intended but never-implemented populators).

- [ ] **Step 3: Commit**

```bash
git add include/ProxySQL_Admin_Tables_Definitions.h lib/ProxySQL_Admin_Stats.cpp
git commit -m "refactor: remove MCP stats DDL macros and design comments from core (issue #5729)"
```

---

### Task 7: Update unit tests

**Files:**
- Modify: `test/tap/tests/unit/plugin_runtime_views_unit-t.cpp`

- [ ] **Step 1: Update aggregate initialization to include `db_kind`**

Every `register_runtime_view` call in the test uses aggregate init `{name, cb, opaque}`. Append `db_kind` at the tail:

```cpp
{nullptr, &noop_cb, nullptr, ProxySQL_PluginDBKind::admin_db}
```

Specifically, update these lines:

Line 53:
```cpp
ok(mgr.register_runtime_view({nullptr, &noop_cb, nullptr, ProxySQL_PluginDBKind::admin_db}) == false,
```

Line 55:
```cpp
ok(mgr.register_runtime_view({"", &noop_cb, nullptr, ProxySQL_PluginDBKind::admin_db}) == false,
```

Line 57:
```cpp
ok(mgr.register_runtime_view({"runtime_x", nullptr, nullptr, ProxySQL_PluginDBKind::admin_db}) == false,
```

Line 60:
```cpp
ok(mgr.register_runtime_view({"runtime_x", &noop_cb, nullptr, ProxySQL_PluginDBKind::admin_db}) == true,
```

Line 62:
```cpp
ok(mgr.register_runtime_view({"runtime_x", &noop_cb, nullptr, ProxySQL_PluginDBKind::admin_db}) == false,
```

Line 64:
```cpp
ok(mgr.register_runtime_view({ProxySQL_PluginDBKind::admin_db, "RUNTIME_X", &noop_cb, nullptr}) == false,
```

Lines 79-81:
```cpp
ok(mgr.register_runtime_view({ProxySQL_PluginDBKind::admin_db, "runtime_mysqlx_users",  &probe_refresh_cb, &users_probe})  == true,
ok(mgr.register_runtime_view({ProxySQL_PluginDBKind::admin_db, "runtime_mysqlx_routes", &probe_refresh_cb, &routes_probe}) == true,
```

Line 129:
```cpp
ok(mgr.register_runtime_view({ProxySQL_PluginDBKind::admin_db, "runtime_mysqlx_users", &probe_refresh_cb, &probe}) == true,
```

- [ ] **Step 2: Update `probe_refresh_cb` signature to match new `refresh` type**

The callback signature doesn't change (still `void (*)(SQLite3DB*, void*)`), so no change needed to `probe_refresh_cb` or `noop_cb`.

- [ ] **Step 3: Update `refresh_runtime_views_for_query` calls to pass 3 DB handles**

All calls like:
```cpp
mgr.refresh_runtime_views_for_query("...", nullptr);
```
become:
```cpp
mgr.refresh_runtime_views_for_query("...", nullptr, nullptr, nullptr);
```

This applies to lines 85-86, 92-93, 100-101, 107-108, 114-115, 133-134, 139-140, 145-146, 151-152, 157-158, 163-164.

- [ ] **Step 4: Add test for `db_kind` dispatch**

Add a new test block before `return exit_status()`:

```cpp
	// ---- db_kind dispatch: correct DB handle passed ----
	{
		diag(">>> refresh_runtime_views_for_query dispatches correct DB by db_kind");

		SQLite3DB* admin_ptr = reinterpret_cast<SQLite3DB*>(0x1);
		SQLite3DB* config_ptr = reinterpret_cast<SQLite3DB*>(0x2);
		SQLite3DB* stats_ptr = reinterpret_cast<SQLite3DB*>(0x3);

		SQLite3DB* received_db = nullptr;

		auto db_probe_cb = [](SQLite3DB* db, void* opaque) {
			*static_cast<SQLite3DB**>(opaque) = db;
		};

		ProxySQL_PluginManager mgr;
		ok(mgr.register_runtime_view({ProxySQL_PluginDBKind::stats_db, "stats_mcp_test", db_probe_cb, &received_db}) == true,
		   "registered stats_mcp_test with db_kind=stats_db");

		mgr.refresh_runtime_views_for_query("SELECT * FROM stats_mcp_test", admin_ptr, config_ptr, stats_ptr);
		ok(received_db == stats_ptr,
		   "stats_db view receives statsdb handle (got %p, expected %p)", received_db, stats_ptr);

		received_db = nullptr;
		SQLite3DB* admin_received = nullptr;
		ok(mgr.register_runtime_view({ProxySQL_PluginDBKind::admin_db, "runtime_mcp_test", db_probe_cb, &admin_received}) == true,
		   "registered runtime_mcp_test with db_kind=admin_db");

		mgr.refresh_runtime_views_for_query("SELECT * FROM runtime_mcp_test", admin_ptr, config_ptr, stats_ptr);
		ok(admin_received == admin_ptr,
		   "admin_db view receives admindb handle (got %p, expected %p)", admin_received, admin_ptr);
	}
```

Update `plan(20)` to `plan(24)` (4 new assertions).

- [ ] **Step 5: Commit**

```bash
git add test/tap/tests/unit/plugin_runtime_views_unit-t.cpp
git commit -m "test: update runtime view unit tests for db_kind dispatch (issue #5729)"
```

---

### Task 8: Update other unit tests that use `refresh_runtime_views_for_query`

**Files:**
- Modify: `test/tap/tests/unit/genai_plugin_load_unit-t.cpp`

- [ ] **Step 1: Update `refresh_runtime_views_for_query` calls to pass 3 DB handles**

In `genai_plugin_load_unit-t.cpp`, any calls to `mgr.refresh_runtime_views_for_query(sql, admindb)` need to become `mgr.refresh_runtime_views_for_query(sql, admindb, nullptr, nullptr)`.

Search for all occurrences and update them.

- [ ] **Step 2: Commit**

```bash
git add test/tap/tests/unit/genai_plugin_load_unit-t.cpp
git commit -m "test: update genai plugin load unit test for 3-handle refresh (issue #5729)"
```

---

### Task 9: Build and verify compilation

- [ ] **Step 1: Build the core library**

```bash
make clean && make
```

Expected: clean build with no errors.

- [ ] **Step 2: Build the unit tests**

```bash
make build_tap_tests
```

Expected: all test binaries compile without errors.

- [ ] **Step 3: Run the runtime views unit test**

```bash
test/tap/tests/unit/plugin_runtime_views_unit-t
```

Expected: all 24 tests pass.

- [ ] **Step 4: Commit any compilation fixes if needed**

---

### Task 10: Update ABI documentation

**Files:**
- Modify: `doc/plugin-chassis/ABI.md`

- [ ] **Step 1: Document ABI v4 change**

Add an entry to the ABI version history table documenting that ABI v4 adds `db_kind` to `ProxySQL_PluginRuntimeView` and the chassis now dispatches the correct DB handle based on it. Note that mysqlx's stats-view back-channel is no longer needed.

- [ ] **Step 2: Commit**

```bash
git add doc/plugin-chassis/ABI.md
git commit -m "docs: document ABI v4 db_kind extension in ABI.md (issue #5729)"
```
