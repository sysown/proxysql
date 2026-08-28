#ifndef PROXYSQL_PLUGIN_H
#define PROXYSQL_PLUGIN_H

// Plugin chassis is a v4.0 feature.  Including this header from a v3.x
// (no PROXYSQL40) translation unit yields no declarations -- v3.0/v3.1
// have no plugin concept whatsoever.  Plugins built for PROXYSQL40 set
// abi_version to PROXYSQL_PLUGIN_ABI_VERSION; the loader rejects
// abi_version values it doesn't understand.
#ifdef PROXYSQL40

#include <cstdint>
#include <string>

class SQLite3DB;
class SQLite3_result;
namespace prometheus { class Registry; }

// Descriptor ABI version the plugin was compiled for.  Plugins set
// `abi_version` on their ProxySQL_PluginDescriptor literal to this macro
// so the core loader can detect layout skew between plugin and loader
// builds.
//
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
//          end of the struct. The chassis passes the matching DB handle
//          (admindb/configdb/statsdb) to the refresh callback instead of
//          always passing admindb. ABI-3 plugins that initialize the
//          struct with {table_name, refresh, opaque} automatically get
//          db_kind = admin_db (value 0) via zero-initialization of the
//          trailing field — matching the pre-ABI-4 behaviour.
//   ABI 5: ProxySQL_PluginCommandContext appends optional Admin global-mutex
//          handoff callbacks. Plugins use them only around work that can wait
//          for another Admin consumer; older plugins continue to use the
//          unchanged three DB-handle prefix.
constexpr unsigned int PROXYSQL_PLUGIN_ABI_VERSION = 5u;
constexpr unsigned int PROXYSQL_PLUGIN_ABI_VERSION_MAX = 5u;

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

	// Optional handoff for commands that must wait for work which can itself
	// enter the Admin interface.  Admin_Handler holds its global query mutex
	// while dispatching plugin commands; a callback that drains worker threads
	// while retaining that mutex can deadlock with a worker already waiting for
	// Admin.  Such callbacks may release the mutex for the blocking portion and
	// must reacquire it before returning.  Direct/unit-test dispatchers leave
	// these null, in which case the callback must not attempt a handoff.
	void *admin_mutex_context { nullptr };
	void (*release_admin_mutex)(void *) { nullptr };
	void (*acquire_admin_mutex)(void *) { nullptr };
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

#ifdef PROXYSQL40
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
#endif /* PROXYSQL40 */

using proxysql_plugin_snapshot_cb =
	SQLite3_result *(*)();

using proxysql_plugin_db_handle_cb =
	SQLite3DB *(*)();

using proxysql_plugin_log_message_cb =
	void (*)(int, const char *);

#ifdef PROXYSQL40
// Pre-execution query hook (Step 2 ABI extension).
//
// STATUS (chassis ABI 2 — initial baseline): the registration and
// dispatch path are wired through ProxySQL_PluginManager and the
// chassis fast-path probe (proxysql_has_configured_plugin_query_hook),
// and unit tests exercise the dispatch surface end-to-end. However,
// the production data plane (MySQL_Session::handler___status_WAITING_
// CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo and the matching
// PgSQL_Session COM_QUERY entry) does NOT yet call the dispatch
// helper. Plugins that register a query hook today will see the
// callback invoked from unit tests but not from real client traffic.
// Wiring the production fast-path is a deliberate follow-up — search
// for "TODO(plugin-query-hook)" in lib/MySQL_Session.cpp and
// lib/PgSQL_Session.cpp for the precise injection points.
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

// Runtime-view projection (ABI 3 extension).
//
// Mirrors the canonical mysql_users / runtime_mysql_users pattern: Admin
// owns the editable table (e.g. mysqlx_users), the plugin module owns
// the runtime state (e.g. MysqlxConfigStore::identities_), and the
// runtime_<table> in admin_db is an Admin-side *view* projected on
// demand from the module. The view holds no persistent rows — it is
// wiped and refilled by the plugin's refresh callback before any admin
// SELECT touches it.
//
// Plugins call register_runtime_view(view) during register_schemas or
// init. Each registration ties an admin-db table name (e.g.
// "runtime_mysqlx_users") to a refresh callback. Admin's pre-SELECT
// hook walks every registered view and invokes the callback for any
// that the SQL references.
//
// The refresh callback receives a borrowed DB handle matching the
// registered db_kind (admin_db → admindb, config_db → configdb,
// stats_db → statsdb) and is expected to do (typically) `BEGIN;
// DELETE FROM <table>; INSERT/REPLACE INTO <table> ...; COMMIT;`
// from the module's in-memory state.
//
// Lifetime: the chassis deep-copies `table_name`, so the plugin need
// not keep the pointed-to string alive. The callback pointer itself
// must point at a function with static lifetime (typically a free
// function in the plugin .so). `opaque` is plugin-owned; it is passed
// back unchanged on each invocation. Plugins that don't need it should
// pass nullptr.
//
// Returns true on successful registration, false if `table_name` is
// already registered (by this or another plugin) or if `refresh` is
// nullptr.
struct ProxySQL_PluginRuntimeView {
	const char *table_name;
	void (*refresh)(SQLite3DB *db, void *opaque);
	void *opaque;
	ProxySQL_PluginDBKind db_kind;  // ABI 4: at tail, defaults to admin_db (0)
};

using proxysql_plugin_register_runtime_view_cb =
	bool (*)(const ProxySQL_PluginRuntimeView &);
#endif /* PROXYSQL40 */

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
//       - snapshots:                 RETURN nullptr (see below).
//   * init (Phase D): register_*, log_message, get_*db and
//     get_prometheus_registry are LIVE.  Snapshot getters remain stubs —
//     see the note below.
//   * start (Phase E) and beyond: get_*db, log_message,
//     get_prometheus_registry remain valid; register_* are no-ops (ignored
//     with a warning — schemas must be declared before start).
//
// NOTE ON SNAPSHOT GETTERS (`get_mysql_users_snapshot`, etc.):
// These are currently wired to a stub that returns nullptr in every phase.
// The plan is to surface read-only SQLite3_result snapshots of the core's
// runtime config tables, but the backing plumbing (snapshot acquisition,
// lifetime, invalidation on reload) isn't implemented yet.  Plugins MUST
// treat a nullptr return as "snapshot not available"; do not assume
// non-null just because you're in Phase D.  When the feature lands, only
// the nullptr contract will change — the field signatures won't.
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
#ifdef PROXYSQL40
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

	// ABI-3 extension: declare an admin-side view of module state
	// (canonical pattern, mirrors Admin's own runtime_mysql_users /
	// save_mysql_users_runtime_to_database flow).  See the contract
	// next to ProxySQL_PluginRuntimeView above.  May be nullptr in
	// services_phase_b_ — register_runtime_view is live both during
	// register_schemas() and init(); plugins typically register views
	// at the same point they register their tables, so the callback
	// is wired in both phases.
	proxysql_plugin_register_runtime_view_cb register_runtime_view;
#endif /* PROXYSQL40 */
};

using proxysql_plugin_init_cb =
	bool (*)(ProxySQL_PluginServices *);

using proxysql_plugin_start_cb =
	bool (*)();

// stop() pairs with init() for teardown, not with start().  The loader
// guarantees that every plugin whose init() returned true will get stop()
// called exactly once -- even if its own start() returned false, and even
// if a later plugin's start() caused shutdown mid-startup.  Plugins must
// therefore be able to tear down resources they allocated in init (config
// stores, caches, worker pools not yet spawned, ...) without having seen
// a matching start().  A plugin whose init() returned false never sees
// stop().
using proxysql_plugin_stop_cb =
	bool (*)();

// Returned pointer must have static storage duration (string literal or static
// buffer). The caller does not free it.
using proxysql_plugin_status_json_cb =
	const char *(*)();

#ifdef PROXYSQL40
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
#endif /* PROXYSQL40 */

struct ProxySQL_PluginDescriptor {
	const char *name;
	uint32_t abi_version;
	proxysql_plugin_init_cb init;
	proxysql_plugin_start_cb start;
	proxysql_plugin_stop_cb stop;
	proxysql_plugin_status_json_cb status_json;
#ifdef PROXYSQL40
	/* Optional: called between load() and init().
	 * `services` will have register_table available but DB handle getters
	 * (get_admindb/get_configdb/get_statsdb) will return nullptr. Plugins
	 * that use this callback MUST NOT touch DB handles here; they can in
	 * init() after admin module bootstrap materializes schema. Plugins that
	 * leave this field null keep the pre-existing two-phase behavior. */
	proxysql_plugin_register_schemas_cb register_schemas;
#endif /* PROXYSQL40 */
};

using proxysql_plugin_descriptor_v1_t = const ProxySQL_PluginDescriptor *(*)();

// ---------------------------------------------------------------------------
// ABI guidance: separation of duties between Admin and the plugin module.
//
// Admin owns the editable, persistent configuration tables (e.g.
// mysqlx_users, mysqlx_routes). The plugin module owns the runtime
// state — typically an in-memory snapshot kept under its own mutex.
// The runtime_<table> in admin_db is NOT module storage; it is an
// Admin-side *view* of module state, projected on demand.
//
// LOAD <X> TO RUNTIME callbacks should:
//   - read the editable admin table directly,
//   - hand the rows to the module via a typed install API that swaps
//     state under the module's own lock,
//   - NOT touch runtime_<X> at all.
//
// SAVE <X> [FROM RUNTIME] TO MEMORY callbacks should:
//   - dump the module's in-memory state,
//   - REPLACE INTO the editable admin table,
//   - NOT read runtime_<X>.
//
// The runtime_<X> view is repopulated by a refresh callback registered
// via services.register_runtime_view(...). Admin invokes the callback
// before any SELECT against the registered table; the callback wipes
// the table and re-projects from the module's in-memory state. This
// matches the canonical MySQL_Authentication / runtime_mysql_users
// pattern in core (lib/ProxySQL_Admin.cpp::save_mysql_users_runtime_to_
// database). It does duplicate the data briefly (in module + in the
// projected admin table during a query), and that is the point: the
// module is isolated from Admin's persistence, and operators see a
// faithful snapshot whenever they query.
//
// Disk-tier copies (LOAD X FROM DISK, SAVE X TO DISK) DO copy between
// configdb and admindb persistent tables and remain a plain
// BEGIN/DELETE/INSERT/COMMIT — there is no module involvement and no
// view projection on that path. For those copies, the empty-source-
// must-still-clear-destination rule still applies (see PR #5643): run
// the DELETE+INSERT unconditionally inside a single transaction and
// check each execute() return.
// ---------------------------------------------------------------------------

#endif /* PROXYSQL40 (file-wide) */
#endif /* PROXYSQL_PLUGIN_H */
