# MySQLX Canonical Admin Commands

Date: 2026-04-09
Branch: `ProtocolX`
Supersedes: `PLUGIN MYSQLX LOAD ...` syntax from the initial mysqlx-plugin-impl

## Motivation

The initial mysqlx plugin implementation introduced commands with a `PLUGIN MYSQLX` prefix
(e.g. `PLUGIN MYSQLX LOAD USERS TO RUNTIME`). This breaks the established ProxySQL admin
syntax convention and exposes internal plugin namespace isolation to end users.

MySQL X Protocol is a separate protocol from MySQL classic, so MYSQLX commands should have
their own first-class `MYSQLX` namespace — completely independent from `MYSQL` commands —
matching the existing `MYSQL`/`PGSQL` pattern.

## Command Set

### LOAD commands (config → runtime)

| Primary | Aliases |
|---------|---------|
| `LOAD MYSQLX USERS TO RUNTIME` | `LOAD MYSQLX USERS TO RUN`, `LOAD MYSQLX USERS FROM MEMORY`, `LOAD MYSQLX USERS FROM MEM` |
| `LOAD MYSQLX ROUTES TO RUNTIME` | `LOAD MYSQLX ROUTES TO RUN`, `LOAD MYSQLX ROUTES FROM MEMORY`, `LOAD MYSQLX ROUTES FROM MEM` |
| `LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME` | `LOAD MYSQLX BACKEND ENDPOINTS TO RUN`, `LOAD MYSQLX BACKEND ENDPOINTS FROM MEMORY`, `LOAD MYSQLX BACKEND ENDPOINTS FROM MEM` |

### SAVE commands (runtime → config)

| Primary | Aliases |
|---------|---------|
| `SAVE MYSQLX USERS TO MEMORY` | `SAVE MYSQLX USERS TO MEM`, `SAVE MYSQLX USERS FROM RUNTIME`, `SAVE MYSQLX USERS FROM RUN` |
| `SAVE MYSQLX ROUTES TO MEMORY` | `SAVE MYSQLX ROUTES TO MEM`, `SAVE MYSQLX ROUTES FROM RUNTIME`, `SAVE MYSQLX ROUTES FROM RUN` |
| `SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY` | `SAVE MYSQLX BACKEND ENDPOINTS TO MEM`, `SAVE MYSQLX BACKEND ENDPOINTS FROM RUNTIME`, `SAVE MYSQLX BACKEND ENDPOINTS FROM RUN` |

## Architecture Changes

### 1. Remove `PLUGIN` prefix gate from ProxySQL_PluginManager

Drop from `lib/ProxySQL_PluginManager.cpp`:

- `kPluginCommandPrefix[]` constant
- `has_plugin_command_prefix()` function
- Prefix validation check in `register_command()`
- Prefix check in `dispatch_admin_command()`

The command registration API (`proxysql_plugin_register_command_cb`) remains unchanged.
Plugins register the full canonical command string (e.g. `LOAD MYSQLX USERS TO RUNTIME`).
The manager stores and dispatches by case-insensitive match against the canonical form
only — no prefix filtering.

### 2. First-class dispatch in Admin_Handler.cpp

Add command alias vectors alongside existing `LOAD_MYSQL_USERS_FROM_MEMORY` etc.:

```
LOAD_MYSQLX_USERS_FROM_MEMORY      = { "LOAD MYSQLX USERS TO RUNTIME", "LOAD MYSQLX USERS TO RUN", ... }
SAVE_MYSQLX_USERS_TO_MEMORY        = { "SAVE MYSQLX USERS TO MEMORY", "SAVE MYSQLX USERS TO MEM", ... }
LOAD_MYSQLX_ROUTES_FROM_MEMORY     = { ... }
SAVE_MYSQLX_ROUTES_TO_MEMORY       = { ... }
LOAD_MYSQLX_BACKEND_ENDPOINTS_FROM_MEMORY = { ... }
SAVE_MYSQLX_BACKEND_ENDPOINTS_TO_MEMORY  = { ... }
```

In the admin command dispatch (`admin_handler_query_process__cmd_and_run_query`), add
new `is_admin_command_or_alias()` blocks for each MYSQLX command group. Each block calls
through `SPA->dispatch_plugin_admin_command()` — the existing bridge between
`ProxySQL_Admin` and `ProxySQL_PluginManager`.

This replaces the current fallback dispatch at line ~5299, which only fires after all
known commands fail. MYSQLX commands become first-class, dispatched at the same level as
MYSQL and PGSQL commands.

### 3. Add SAVE command handlers in mysqlx_admin_schema.cpp

Current implementation only has LOAD (copy from config table to runtime table).
Add SAVE handlers that copy in the reverse direction (runtime → config), following the
same `copy_table` pattern.

Register all six commands (3 LOAD + 3 SAVE) during `mysqlx_register_admin_schema()`.

### 4. Update plugin command registration

In `mysqlx_admin_schema.cpp`, replace:

```cpp
services.register_command("PLUGIN MYSQLX LOAD USERS TO RUNTIME", &load_users_to_runtime);
```

with:

```cpp
services.register_command("LOAD MYSQLX USERS TO RUNTIME", &load_users_to_runtime);
```

Same for routes and endpoints. Add SAVE registrations for all three tables.

## What Stays Unchanged

- `ProxySQL_PluginServices` API — same `register_command` callback signature
- `ProxySQL_PluginCommandContext` — same db handle passing
- `ProxySQL_PluginCommandResult` — same result structure
- Plugin `.so` loading, lifecycle (`init`/`start`/`stop`), table registration
- Config/runtime table DDL schemas
- `dispatch_plugin_admin_command()` template in `ProxySQL_Admin`
- Cluster sync — remains a Phase 2 concern; MYSQLX tables are not wired into
  `mysql_users`/`mysql_servers` cluster checksum propagation

## Files Changed

| File | Change |
|------|--------|
| `lib/ProxySQL_PluginManager.cpp` | Remove `PLUGIN` prefix gate from `register_command` and `dispatch_admin_command` |
| `lib/Admin_Handler.cpp` | Add MYSQLX alias vectors and dispatch blocks for all 6 commands |
| `plugins/mysqlx/src/mysqlx_admin_schema.cpp` | Register canonical command names, add SAVE handlers |
| `test/tap/tests/unit/plugin_registry_unit-t.cpp` | Update test expectations to use canonical syntax |
| `test/tap/tests/test_mysqlx_admin_tables-t.cpp` | Update test expectations to use canonical syntax |
| `docs/superpowers/status/2026-04-07-mysqlx-plugin-wrapup.md` | Update command listing |
