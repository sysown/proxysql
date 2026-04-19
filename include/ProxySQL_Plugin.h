#ifndef PROXYSQL_PLUGIN_H
#define PROXYSQL_PLUGIN_H

#include <cstdint>
#include <string>

class SQLite3DB;
class SQLite3_result;
namespace prometheus { class Registry; }

enum class ProxySQL_PluginDBKind : uint8_t {
	admin_db = 0,
	config_db = 1,
	stats_db = 2
};

// The manager deep-copies table_name and table_def; the plugin need not keep
// the pointed-to strings alive after register_table returns.
struct ProxySQL_PluginTableDef {
	ProxySQL_PluginDBKind db_kind;
	const char *table_name;
	const char *table_def;
};

// Borrowed DB handles valid for the duration of the admin command callback.
// Must not be stored beyond the callback invocation.
struct ProxySQL_PluginCommandContext {
	SQLite3DB *admindb;
	SQLite3DB *configdb;
	SQLite3DB *statsdb;
};

// NOTE: ProxySQL_PluginCommandResult contains std::string. Plugins MUST
// be compiled with the same C++ standard library (same compiler, same
// -std= flag, same libstdc++/libc++ version) as the ProxySQL core.
// This is guaranteed when plugins are built within the ProxySQL build
// tree. Third-party plugins must match the core's build environment.
struct ProxySQL_PluginCommandResult {
	int error_code;
	uint64_t rows_affected;
	std::string message;
};

using proxysql_plugin_admin_command_cb =
	ProxySQL_PluginCommandResult (*)(const ProxySQL_PluginCommandContext &, const char *);

using proxysql_plugin_register_table_cb =
	void (*)(const ProxySQL_PluginTableDef &);

using proxysql_plugin_register_command_cb =
	void (*)(const char *, proxysql_plugin_admin_command_cb);

// Register an alternative spelling (alias) of an already-registered command.
// The `canonical` argument MUST match the exact SQL passed to a prior
// `register_command()` call (after whitespace normalization). Plugins use
// this to publish user-friendly spellings — "LOAD MYSQLX USERS FROM MEMORY"
// vs "LOAD MYSQLX USERS TO RUNTIME" — without replicating the canonical
// callback. Core's admin dispatcher consults the alias table to resolve
// incoming SQL to the canonical form before invoking the registered
// callback.
//
// No-op if `canonical` isn't registered yet (plugins should register the
// command BEFORE its aliases). Silently skips duplicate aliases.
using proxysql_plugin_register_command_alias_cb =
	void (*)(const char *canonical, const char *alias);

using proxysql_plugin_snapshot_cb =
	SQLite3_result *(*)();

using proxysql_plugin_db_handle_cb =
	SQLite3DB *(*)();

using proxysql_plugin_log_message_cb =
	void (*)(int, const char *);

// Pre-execution query hook (Step 2 ABI extension).
//
// Wire protocol the hook is being invoked for.  A plugin can register
// independently for each protocol; one hook per protocol per plugin.
enum class ProxySQL_PluginProtocol : uint8_t {
	mysql = 0,
	pgsql = 1
};

// Payload handed to a query-hook callback.  All pointers are owned by
// core and remain valid only for the duration of the callback.  The
// callback must not retain them or mutate the underlying buffers.
//
// query_text is the SQL the client sent, NOT NUL-terminated; query_len
// is its length in bytes.  user / client_ip / schema are NUL-terminated
// C strings and may be empty (never NULL).
struct ProxySQL_PluginQueryHookPayload {
	const char *user;
	const char *client_ip;
	const char *schema;
	const char *query_text;
	uint32_t    query_len;
};

// Outcome of a query hook.  ALLOW lets the query proceed to the
// backend.  DENY returns an error to the client and the query never
// dispatches; the message is copied by core, the plugin need not keep
// it alive after the callback returns.
//
// NOTE: same std::string ABI coupling caveat as
// ProxySQL_PluginCommandResult applies.
enum class ProxySQL_PluginQueryHookAction : uint8_t {
	allow = 0,
	deny  = 1
};

struct ProxySQL_PluginQueryHookResult {
	ProxySQL_PluginQueryHookAction action;
	std::string message;
};

using proxysql_plugin_query_hook_cb =
	ProxySQL_PluginQueryHookResult (*)(const ProxySQL_PluginQueryHookPayload &);

// register_query_hook(proto, cb).  Returns true on success, false if a
// hook for that protocol is already registered.  Valid only during the
// init callback (same lifetime rule as register_table / register_command).
using proxysql_plugin_register_query_hook_cb =
	bool (*)(ProxySQL_PluginProtocol, proxysql_plugin_query_hook_cb);

// Returns the prometheus::Registry* that core uses for its own metrics.
// Plugins register their counters / gauges / histograms against this
// shared registry using prometheus-cpp directly; their metrics then
// surface at the same /metrics endpoint scrapers already poll.
//
// NOTE: prometheus-cpp is a C++ library with C++ ABI surface.  Same
// build-environment caveat applies as to std::string in this header:
// plugins must be compiled in the ProxySQL build tree (or at least
// against a matching prometheus-cpp version + matching libstdc++).
//
// Lifetime: GloVars and its prometheus registry are constructed
// before any plugin is loaded, so the returned pointer is non-null
// for every callback (init, start, admin command callback, query
// hook).  Plugins may register metrics in init() if they want them
// scraped immediately.
using proxysql_plugin_get_prometheus_registry_cb =
	prometheus::Registry* (*)();

// Services provided to plugins across the four-phase lifecycle.
//
// Availability by phase:
//   * register_schemas (Phase B, optional, run between load() and init()):
//       - register_table:            LIVE (writes to pending-tables list)
//       - register_command:          LIVE (orthogonal to schema, OK here)
//       - log_message:               LIVE
//       - get_prometheus_registry:   LIVE (registry is constructed at startup)
//       - get_admindb/get_configdb/get_statsdb: RETURN nullptr (admin module
//         has not yet materialized the schema).  Plugins using this callback
//         MUST NOT touch DB handles here; save that work for init().
//       - register_query_hook:       RETURNS false (not yet wired).
//       - snapshots:                 RETURN nullptr.
//   * init (Phase D): every field LIVE.  register_table/register_command
//     remain valid during init as well (they append to the same registry).
//   * start (Phase E) and beyond: get_*db, log_message, snapshots,
//     get_prometheus_registry remain valid; register_* are no-ops (ignored
//     with a warning — schemas must be declared before start).
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
	// Step 2 ABI extensions.  Both fields are additive at the end of
	// the struct -- older plugins that were built against the previous
	// layout don't read past the previous member; new plugins must
	// check non-null before calling.
	proxysql_plugin_register_query_hook_cb register_query_hook;
	proxysql_plugin_get_prometheus_registry_cb get_prometheus_registry;
	// Step 2.5 extension: register a user-friendly alias for a command
	// already registered via register_command.  Admin's dispatcher
	// resolves aliases to canonical before invoking the callback, so
	// plugins avoid the MYSQLX-specific hardcoded alias ladder that
	// previously lived in lib/Admin_Handler.cpp.
	proxysql_plugin_register_command_alias_cb register_command_alias;
};

using proxysql_plugin_init_cb =
	bool (*)(ProxySQL_PluginServices *);

using proxysql_plugin_start_cb =
	bool (*)();

using proxysql_plugin_stop_cb =
	bool (*)();

// Returned pointer must have static storage duration (string literal or static
// buffer). The caller does not free it.
using proxysql_plugin_status_json_cb =
	const char *(*)();

// Phase B entry point: "declare your schema before admin bootstrap."
//
// Four-phase plugin lifecycle:
//   Phase A: load()             -- dlopen the .so, read the descriptor
//   Phase B: register_schemas() -- NEW, optional; plugin returns its table defs
//   Phase C: admin module init  -- core materializes SQLite schema from the
//                                  plugin-registered defs (merge_plugin_tables
//                                  code path -- first-boot == reload)
//   Phase D: init()             -- plugin runs startup logic with full services
//   Phase E: start()            -- plugin launches its threads / accept loops
//
// This callback is optional (may be nullptr).  Plugins that leave it null
// keep the pre-existing two-phase behavior: Phase B is skipped and the
// plugin's init() is responsible for both schema registration and startup
// work (the mysqlx plugin does this today).
using proxysql_plugin_register_schemas_cb =
	bool (*)(ProxySQL_PluginServices *);

struct ProxySQL_PluginDescriptor {
	const char *name;
	uint32_t abi_version;
	proxysql_plugin_init_cb init;
	proxysql_plugin_start_cb start;
	proxysql_plugin_stop_cb stop;
	proxysql_plugin_status_json_cb status_json;
	/* Optional: called between load() and init().
	 * `services` will have register_table available but DB handle getters
	 * (get_admindb/get_configdb/get_statsdb) will return nullptr. Plugins
	 * that use this callback MUST NOT touch DB handles here; they can in
	 * init() after admin module bootstrap materializes schema. Plugins that
	 * leave this field null keep the pre-existing two-phase behavior. */
	proxysql_plugin_register_schemas_cb register_schemas;
};

using proxysql_plugin_descriptor_v1_t = const ProxySQL_PluginDescriptor *(*)();

#endif /* PROXYSQL_PLUGIN_H */
