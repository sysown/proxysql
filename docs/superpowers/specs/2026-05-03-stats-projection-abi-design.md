# Stats Projection ABI for GenAI Plugin

**Date:** 2026-05-03
**Issue:** #5729
**Branch:** issue-5729-stats-projection-abi

## Problem

The genai plugin carve-out (Step 4) left `stats_mcp_*` tables as a known gap. The DDL macros exist in `ProxySQL_Admin_Tables_Definitions.h`, the in-memory data structures and snapshot methods exist in the plugin, but there is no bridge to populate the tables from admin SELECT queries. Additionally, `ProxySQL_PluginRuntimeView` only carries an `admindb` handle — plugins that need to write to `statsdb` (like mysqlx's stats views) must reach through a back-channel, violating the separation-of-duties principle.

## Design Decision: Option 2 — Extend `ProxySQL_PluginRuntimeView`

Add a `db_kind` field to the existing `ProxySQL_PluginRuntimeView` struct. The chassis dispatches the correct DB handle based on `db_kind`. Single hook, no duplication, fixes the architectural leak.

Alternatives considered and rejected:
- **Option 1** (parallel `register_stats_view`): Works but cements two near-identical hooks.
- **Option 3** (context struct): More flexible but bigger ABI surface for no current need.

## ABI Change (v3 → v4)

### `ProxySQL_PluginRuntimeView` struct (`include/ProxySQL_Plugin.h`)

```cpp
struct ProxySQL_PluginRuntimeView {
    const char *table_name;
    void (*refresh)(SQLite3DB *db, void *opaque);
    void *opaque;
    ProxySQL_PluginDBKind db_kind;   // NEW (ABI 4): tail-appended for backward compat
};
```

`PROXYSQL_PLUGIN_ABI_VERSION` bumps from 3 to 4.

The `db_kind` field uses the existing `ProxySQL_PluginDBKind` enum (`admin_db`, `config_db`, `stats_db`). The field is tail-appended so that existing `{table_name, refresh, opaque}` aggregate initializers in ABI-3 plugins continue to compile and zero-initialize the trailing field (which defaults to `admin_db` = 0). The chassis passes the matching handle to `refresh()`.

### `registered_runtime_view_t` (`include/ProxySQL_PluginManager.h`)

```cpp
struct registered_runtime_view_t {
    ProxySQL_PluginDBKind db_kind { ProxySQL_PluginDBKind::admin_db };
    std::string table_name {};
    void (*refresh)(SQLite3DB*, void*) { nullptr };
    void* opaque { nullptr };
};
```

### Dispatch change (`lib/ProxySQL_PluginManager.cpp`)

`refresh_runtime_views_for_query()` gains `configdb` and `statsdb` parameters:

```cpp
void refresh_runtime_views_for_query(const std::string& sql,
    SQLite3DB* admindb, SQLite3DB* configdb, SQLite3DB* statsdb) const;
```

For each registered view, selects the DB handle matching `view.db_kind`:
- `admin_db` → `admindb`
- `config_db` → `configdb`
- `stats_db` → `statsdb`

The free function `proxysql_refresh_configured_plugin_runtime_views()` mirrors the new signature. The call site in `ProxySQL_Admin::GenericRefreshStatistics()` (line 1623 of `ProxySQL_Admin.cpp`) passes `this->admindb`, `this->configdb`, `this->statsdb`.

## Genai Stats Tables

### Tables (5 total)

Move DDL definitions from `ProxySQL_Admin_Tables_Definitions.h` to `plugins/genai/src/plugin_tables.cpp` as local constants.

| Table | `db_kind` | Data Source | Reset |
|-------|-----------|-------------|-------|
| `stats_mcp_query_digest` | `stats_db` | `Discovery_Schema::get_mcp_query_digest(false)` | No |
| `stats_mcp_query_digest_reset` | `stats_db` | `Discovery_Schema::get_mcp_query_digest(true)` | Yes |
| `stats_mcp_query_rules` | `stats_db` | `Discovery_Schema::get_stats_mcp_query_rules()` | No |
| `stats_mcp_query_tools_counters` | `stats_db` | `Query_Tool_Handler::get_tool_usage_stats_resultset(false)` | No |
| `stats_mcp_query_tools_counters_reset` | `stats_db` | `Query_Tool_Handler::get_tool_usage_stats_resultset(true)` | Yes |

`stats_mcp_query_rules` has no `_reset` variant because `get_stats_mcp_query_rules()` does not support reset semantics.

### Refresh callback pattern

Each callback:
1. Receives `SQLite3DB* db` (will be `statsdb` because `db_kind = stats_db`)
2. Executes `DELETE FROM <table>`
3. Calls the data source method to get `SQLite3_result*`
4. Iterates rows and inserts into the table

### Registration

In `genai_register_admin_tables()`:
- Register each table DDL via `register_table({ProxySQL_PluginDBKind::stats_db, name, def})`
- Register each runtime view via `register_runtime_view({ProxySQL_PluginDBKind::stats_db, name, callback, nullptr})`

### Existing genai views

Update the 3 existing `runtime_mcp_*` registrations to include `db_kind = admin_db` (no behavior change):
- `runtime_mcp_auth_profiles`
- `runtime_mcp_target_profiles`
- `runtime_mcp_query_rules`

## Mysqlx Migration

Set explicit `db_kind` on all 3 mysqlx runtime view registrations:

| View | `db_kind` | Callback Change |
|------|-----------|-----------------|
| `runtime_mysqlx_users` | `admin_db` | None |
| `stats_mysqlx_routes` | `stats_db` | Drop back-channel, use passed `db` directly |
| `stats_mysqlx_processlist` | `stats_db` | Drop back-channel, use passed `db` directly |

The two stats callbacks simplify to:

```cpp
void refresh_stats_routes_view(SQLite3DB* db, void*) {
    mysqlx_stats().flush_to_sqlite(*db);
}
void refresh_stats_processlist_view(SQLite3DB* db, void*) {
    mysqlx_processlist().flush_to_sqlite(*db);
}
```

## Files Changed

| File | Change |
|------|--------|
| `include/ProxySQL_Plugin.h` | Add `db_kind` to struct, bump ABI v4 |
| `include/ProxySQL_PluginManager.h` | Add `db_kind` to internal struct, extend dispatch signature |
| `lib/ProxySQL_PluginManager.cpp` | Dispatch correct DB by `db_kind`, pass all 3 handles |
| `lib/ProxySQL_Admin.cpp` | Pass `admindb`, `configdb`, `statsdb` to refresh function |
| `include/ProxySQL_Admin_Tables_Definitions.h` | Remove 5 `STATS_SQLITE_TABLE_MCP_*` macros |
| `lib/ProxySQL_Admin_Stats.cpp` | Remove MCP design comments (lines 2604-2651) |
| `plugins/mysqlx/src/mysqlx_admin_schema.cpp` | Set `db_kind` on 3 registrations, simplify 2 stats callbacks |
| `plugins/genai/src/plugin_tables.cpp` | Add 5 DDLs, 5 table registrations, 5 refresh callbacks, update 3 existing registrations |
| `doc/plugin-chassis/ABI.md` | Document ABI v4 change |

## Acceptance Criteria

- [ ] `stats_mcp_*` table DDLs no longer in `include/ProxySQL_Admin_Tables_Definitions.h`
- [ ] `lib/ProxySQL_Admin_Stats.cpp` has no MCP references
- [ ] `ProxySQL_PluginRuntimeView` has `db_kind` field, ABI v4
- [ ] Chassis dispatches correct DB handle based on `db_kind`
- [ ] SELECT against `stats_mcp_query_digest` from admin returns data from plugin's in-memory state
- [ ] `_reset` semantics preserved for digest and tools counters
- [ ] Mysqlx stats views use passed `db` directly (no back-channel)
- [ ] Unit test for the projection refresh callback
