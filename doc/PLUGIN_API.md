# ProxySQL Plugin API

ProxySQL supports dynamically loaded plugins via `.so` shared libraries. A plugin
can extend ProxySQL with new protocols, admin tables, admin commands, or any
other functionality by registering itself through a well-defined C++ ABI.

## Overview

- Plugins are loaded at startup from paths specified in `proxysql.cnf`.
- Each plugin is a shared library (`.so`) that exports a single C entry point.
- ProxySQL calls the plugin's lifecycle hooks (`init`, `start`, `stop`) in order.
- During `init`, the plugin receives a services struct with callbacks it can use
  to register tables, commands, access databases, and log messages.
- ProxySQL does not know or care what a plugin does — the plugin self-registers
  everything it needs.

## Loading a Plugin

Add the plugin path to `proxysql.cnf`:

```
plugins = (
    "/path/to/my_plugin.so"
)
```

Multiple plugins can be listed:

```
plugins = (
    "/path/to/protocol_a.so",
    "/path/to/protocol_b.so"
)
```

The `plugins` directive is read from the configuration **file** only. It is not
persisted to the ProxySQL admin database. If the database exists when ProxySQL
starts, other settings are loaded from the database instead of the config file,
but the `plugins` list is always read from the config file (parsed in an early
startup phase before the database takes precedence).

### Startup Sequence

ProxySQL uses a **four-phase** plugin lifecycle.  Every phase but Phase B
is mandatory; Phase B is optional via the `register_schemas` descriptor
field and only enabled when the plugin declares ABI version 2.

1. **Phase A — load.**  ProxySQL parses `proxysql.cnf` and populates the
   `plugins` list.  For each plugin path, ProxySQL calls `dlopen()`,
   resolves the `proxysql_plugin_descriptor_v1` symbol, and validates
   the descriptor (`abi_version`, `name`, callback pointers).
2. **Phase B — register_schemas (optional, ABI 2 only).**  If the
   descriptor wires `register_schemas`, the loader invokes it with a
   `ProxySQL_PluginServices` whose `register_table` /
   `register_command` / `register_command_alias` entries are LIVE but
   whose DB-handle getters (`get_admindb`, `get_configdb`,
   `get_statsdb`) are non-null stubs that return `nullptr`.  The plugin
   declares the tables it owns and (optionally) its admin commands; it
   MUST NOT touch DB handles here.  Plugins that leave
   `register_schemas` null (or that declare ABI 1) skip this phase
   entirely and do all their setup in Phase D.
3. **Phase C — admin materialization.**  The admin module initializes
   and materializes the SQLite schemas collected during Phase B
   (`merge_plugin_tables` + `CREATE TABLE`).  On DDL failure ProxySQL
   aborts startup.
4. **Phase D — init.**  The plugin's `init()` callback is called,
   receiving a fully live `ProxySQL_PluginServices` (DB handles now
   valid).  Plugins that opted out of Phase B register their tables
   AND commands here; plugins that used Phase B only finish their
   context setup.
5. **Phase E — start.**  The plugin's `start()` callback is called.
   The plugin should start its threads, open listener sockets, and
   load runtime configuration.  After this returns, ProxySQL is ready
   and the plugin is live.

### Shutdown Sequence

1. The plugin's `stop()` callback is called.
2. The plugin should stop its threads, close sockets, and release resources.
3. ProxySQL unloads the `.so`.

## The Plugin Contract

A plugin must:

1. Be compiled as a shared library (`.so`) with the same C++17 toolchain as the
   ProxySQL core.
2. Export a single `extern "C"` function named `proxysql_plugin_descriptor_v1`.
3. Return a pointer to a static `ProxySQL_PluginDescriptor` struct.

### ABI Header

All types are defined in `include/ProxySQL_Plugin.h`:

```cpp
#include "ProxySQL_Plugin.h"
```

### The Descriptor

```cpp
struct ProxySQL_PluginDescriptor {
    const char *name;                         // Human-readable plugin name
    uint32_t abi_version;                     // PROXYSQL_PLUGIN_ABI_VERSION (1 or 2)
    proxysql_plugin_init_cb init;             // bool (*)(ProxySQL_PluginServices *)
    proxysql_plugin_start_cb start;           // bool (*)()
    proxysql_plugin_stop_cb stop;             // bool (*)()
    proxysql_plugin_status_json_cb status_json;  // const char *(*)()
    proxysql_plugin_register_schemas_cb register_schemas; // ABI 2 only, optional
};
```

| Field              | Type          | Description                                               |
|--------------------|---------------|-----------------------------------------------------------|
| `name`             | `const char*` | Plugin identifier, used in logging.                        |
| `abi_version`      | `uint32_t`    | Set from `PROXYSQL_PLUGIN_ABI_VERSION`.  Value `1` = pre-chassis descriptor (six fields).  Value `2` = PROXYSQL40 descriptor (adds `register_schemas`).  A v3/v3.1 ProxySQL core rejects `abi_version > 1`. |
| `init`             | callback      | Phase D — called with live services; register tables and commands here (or finish context setup if `register_schemas` already did it). |
| `start`            | callback      | Phase E — start threads, open sockets, load config.        |
| `stop`             | callback      | Called on shutdown.  Pairs with `init`, not `start`: if `init` returned true and `start` later failed, `stop` is still called so the plugin can release resources it allocated in `init`. |
| `status_json`      | callback      | Return a static JSON string describing plugin status.      |
| `register_schemas` | callback      | Phase B (ABI 2 only).  Optional; leave null to skip Phase B entirely.  Services passed here have `register_table` / `register_command` / `register_command_alias` LIVE but DB-handle getters returning `nullptr`. |

All callbacks return `bool` (except `status_json` which returns `const char*`).
Return `true` on success, `false` on failure. A `false` return from
`register_schemas`, `init`, or `start` causes ProxySQL to exit.

#### ABI version

`include/ProxySQL_Plugin.h` exposes `PROXYSQL_PLUGIN_ABI_VERSION` (2 under
PROXYSQL40, undefined in pre-chassis builds — the descriptor is then a
legacy six-field struct with `abi_version = 1`).  Plugins MUST assign
`abi_version` from this macro rather than hard-coding a literal; the
core's loader uses it to detect layout skew and reject plugins built
for an unsupported ABI.  See `ProxySQL_Plugin.h` for the exact rules.

### The Entry Point

```cpp
extern "C" const ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
    return &my_descriptor;
}
```

## Services Available to Plugins

During `init()`, the plugin receives a `ProxySQL_PluginServices` struct
containing function pointers the plugin can call:

```cpp
struct ProxySQL_PluginServices {
    proxysql_plugin_register_table_cb register_table;
    proxysql_plugin_register_command_cb register_command;
    proxysql_plugin_snapshot_cb get_mysql_users_snapshot;
    proxysql_plugin_snapshot_cb get_mysql_servers_snapshot;
    proxysql_plugin_snapshot_cb get_mysql_group_replication_hostgroups_snapshot;
    proxysql_plugin_log_message_cb log_message;
    proxysql_plugin_db_handle_cb get_admindb;
    proxysql_plugin_db_handle_cb get_configdb;
    proxysql_plugin_db_handle_cb get_statsdb;
};
```

### Service Callbacks

#### `register_table`

```cpp
void register_table(const ProxySQL_PluginTableDef &def);
```

Register a SQLite table in one of ProxySQL's databases. Tables are created
automatically before `start()` is called.

```cpp
struct ProxySQL_PluginTableDef {
    ProxySQL_PluginDBKind db_kind;   // Which database: admin_db, config_db, or stats_db
    const char *table_name;          // Table name (e.g., "my_plugin_config")
    const char *table_def;           // CREATE TABLE statement
};
```

`ProxySQL_PluginDBKind` values:

| Value       | Database   | Purpose                                              |
|-------------|------------|------------------------------------------------------|
| `admin_db`  | In-memory  | Runtime/admin tables, queryable via admin interface  |
| `config_db` | On-disk    | Persistent configuration (survives restarts)         |
| `stats_db`  | In-memory  | Statistics/metrics tables                            |

**Convention**: For configuration tables that support the standard
memory↔runtime↔disk tier model, register the table in **both** `admin_db` and
`config_db`. Create a separate `runtime_`-prefixed table in `admin_db` only.
This is the pattern used by ProxySQL's built-in modules (e.g., `mysql_users` +
`runtime_mysql_users`).

#### `register_command`

```cpp
void register_command(const char *sql, proxysql_plugin_admin_command_cb cb);
```

Register an admin command handler. When a user issues the given SQL command
through the admin interface, ProxySQL calls the registered callback.

```cpp
ProxySQL_PluginCommandResult my_command(
    const ProxySQL_PluginCommandContext &ctx,
    const char *sql
);
```

**Important**: Command matching is case-insensitive with whitespace normalization.
Only register the canonical form (e.g., `"LOAD MYPLUGIN USERS TO RUNTIME"`).
Alias resolution (e.g., `"TO RUN"` → `"TO RUNTIME"`) must be handled in
`Admin_Handler.cpp` in the ProxySQL core — plugins only see the canonical form.

#### `log_message`

```cpp
void log_message(int level, const char *message);
```

Log a message through ProxySQL's logging system. The numeric levels match
ProxySQL's internal `proxy_*` severity scheme — anything other than 3 or 4 is
emitted as info:

| Level | Meaning |
|-------|---------|
| 3     | Error   |
| 4     | Warning |
| any other value | Info |

#### `get_admindb`, `get_configdb`, `get_statsdb`

```cpp
SQLite3DB *get_admindb();
SQLite3DB *get_configdb();
SQLite3DB *get_statsdb();
```

Return a pointer to the respective SQLite database. Use these to query and
modify plugin tables at runtime. These are valid only during `start()` and later
(not during `init()`).

#### `get_mysql_users_snapshot`, `get_mysql_servers_snapshot`, `get_mysql_group_replication_hostgroups_snapshot`

```cpp
SQLite3_result *get_mysql_users_snapshot();
SQLite3_result *get_mysql_servers_snapshot();
SQLite3_result *get_mysql_group_replication_hostgroups_snapshot();
```

Return a snapshot of ProxySQL's internal MySQL topology state. These allow a
plugin to access the current user list, server list, or group replication
hostgroups without directly coupling to internal data structures.

## Admin Command Context and Result

### Context

```cpp
struct ProxySQL_PluginCommandContext {
    SQLite3DB *admindb;
    SQLite3DB *configdb;
    SQLite3DB *statsdb;
};
```

Passed to every command callback. Provides direct access to the three databases.

### Result

```cpp
struct ProxySQL_PluginCommandResult {
    int error_code;       // 0 = success, non-zero = error
    uint64_t rows_affected;
    std::string message;  // Optional message (empty = no message)
};
```

Return a result from your command callback:
- `error_code == 0`: ProxySQL sends an OK packet to the client.
- `error_code != 0`: ProxySQL sends an error packet with the message.

## Minimal Plugin Example

This is a complete, minimal plugin that registers one table and one command:

```cpp
// my_plugin.cpp
#include "ProxySQL_Plugin.h"
#include <cstdio>

namespace {

ProxySQL_PluginServices* g_services = nullptr;

ProxySQL_PluginCommandResult handle_ping(const ProxySQL_PluginCommandContext&, const char*) {
    return {0, 0, "pong"};
}

bool my_init(ProxySQL_PluginServices *services) {
    g_services = services;

    // Register a configuration table
    ProxySQL_PluginTableDef table {
        ProxySQL_PluginDBKind::admin_db,
        "my_plugin_config",
        "CREATE TABLE my_plugin_config ("
        "  key VARCHAR NOT NULL PRIMARY KEY,"
        "  value VARCHAR NOT NULL DEFAULT ''"
        ")"
    };
    services->register_table(table);

    // Register an admin command
    services->register_command("MYPLUGIN PING", &handle_ping);

    return true;
}

bool my_start() {
    // Start threads, open sockets, etc.
    return true;
}

bool my_stop() {
    // Stop threads, close sockets, etc.
    return true;
}

const char* my_status_json() {
    return "{\"name\":\"my_plugin\",\"state\":\"running\"}";
}

const ProxySQL_PluginDescriptor my_descriptor = {
    "my_plugin",        // name
    1,                  // abi_version
    &my_init,           // init
    &my_start,          // start
    &my_stop,           // stop
    &my_status_json     // status_json
};

} // namespace

extern "C" const ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
    return &my_descriptor;
}
```

## Build Requirements

### Compiler Compatibility

Plugins **must** be compiled with the same C++ compiler and standard library as
the ProxySQL core. This is because `ProxySQL_PluginCommandResult` contains
`std::string`, which has an ABI that varies between compilers and standard
library versions. The safest approach is to build plugins within the ProxySQL
build tree.

### Example Makefile

```makefile
CXX      = g++
CXXFLAGS = -std=c++17 -shared -fPIC -O2
INCLUDES = -I$(PROXYSQL_SRC)/include

my_plugin.so: my_plugin.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $<

clean:
	rm -f my_plugin.so
```

Build:

```bash
make PROXYSQL_SRC=/path/to/proxysql
```

### Linking

Plugins are loaded with `RTLD_NOW | RTLD_LOCAL`. They should not link against
`libproxysql.a` or any ProxySQL internal libraries. The plugin communicates
with ProxySQL exclusively through the callbacks in `ProxySQL_PluginServices`.

If a plugin needs SQLite3DB functionality (querying tables), it accesses it
through the `get_admindb()` / `get_configdb()` / `get_statsdb()` service
callbacks, not by linking against ProxySQL's SQLite wrapper.

## Admin Integration Patterns

### The Three-Tier Configuration Model

ProxySQL uses a three-tier configuration model:

```
DISK (on-disk SQLite)  ↔  MEMORY (in-memory admin tables)  ↔  RUNTIME (live state)
```

Plugins that manage configuration should follow this pattern:

1. Register tables in both `config_db` (for disk persistence) and `admin_db`
   (for in-memory configuration).
2. Register `runtime_`-prefixed tables in `admin_db` for the live runtime state.
3. Register admin commands for each tier transition:
   - `LOAD MYPLUGIN <OBJECT> TO RUNTIME` — copy from memory to runtime tables
   - `SAVE MYPLUGIN <OBJECT> TO MEMORY` — copy from runtime to memory tables

### Registering Admin Commands

Commands are registered with the canonical form. Alias support (e.g., `TO RUN`
for `TO RUNTIME`, `FROM MEM` for `FROM MEMORY`) is handled in ProxySQL's
`Admin_Handler.cpp`, not in the plugin. If you need new aliases, you must modify
the ProxySQL core to add the alias vectors and dispatch mapping.

### Table Registration Patterns

```cpp
// Configuration table: visible in both admin and config databases
void register_config_table(ProxySQL_PluginServices& services,
                           const char* name, const char* def) {
    services.register_table({ProxySQL_PluginDBKind::admin_db, name, def});
    services.register_table({ProxySQL_PluginDBKind::config_db, name, def});
}

// Runtime table: admin database only
void register_runtime_table(ProxySQL_PluginServices& services,
                            const char* name, const char* def) {
    services.register_table({ProxySQL_PluginDBKind::admin_db, name, def});
}

// Stats table: stats database only
void register_stats_table(ProxySQL_PluginServices& services,
                          const char* name, const char* def) {
    services.register_table({ProxySQL_PluginDBKind::stats_db, name, def});
}
```

## Limitations

- **No hot-loading**: Plugins can only be loaded at startup. There is no
  `LOAD PLUGIN` command to load a plugin at runtime. ProxySQL must be restarted
  to add or remove plugins.
- **No dependency resolution**: Plugins are loaded in the order listed in
  `proxysql.cnf`. If one plugin depends on another, the dependency must be
  listed first.
- **Single ABI version**: Only ABI version 1 is supported.
- **Compiler coupling**: Plugins must match the ProxySQL core's C++ compiler
  and standard library due to `std::string` in `ProxySQL_PluginCommandResult`.

## Reference Implementation

The MySQL X Protocol plugin (`plugins/mysqlx/`) is the reference implementation
of a full ProxySQL plugin. It demonstrates:

- Multi-file plugin structure with separate headers/sources
- Custom `Makefile` within the ProxySQL build tree
- Admin table registration (config + runtime + stats tables)
- Admin command handlers with the three-tier model
- Plugin-owned threads with listener sockets
- TLS integration via ProxySQL's global SSL context
- Connection pooling for backend connections
- A standalone test suite using a custom test harness

Key files:
- `plugins/mysqlx/src/mysqlx_plugin.cpp` — Plugin entry point and lifecycle
- `plugins/mysqlx/src/mysqlx_admin_schema.cpp` — Table and command registration
- `plugins/mysqlx/Makefile` — Build configuration
