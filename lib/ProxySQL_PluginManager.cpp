// Plugin chassis is a v4.0 feature.  Under v3.0/v3.1 this whole
// translation unit compiles to nothing; the linker doesn't see a
// ProxySQL_PluginManager symbol, and any caller that referenced it is
// expected to gate its own code on PROXYSQL40 too.
#ifdef PROXYSQL40

#include "ProxySQL_PluginManager.h"

#include <atomic>
#include <cassert>
#include <cctype>
#include <cstring>
#include <dlfcn.h>
#include <mutex>
#include <shared_mutex>
#include <strings.h>

#include "proxysql.h"
#include "proxysql_glovars.hpp"
#include "sqlite3db.h"
#include "prometheus/registry.h"

extern ProxySQL_GlobalVariables GloVars;

SQLite3DB* proxysql_plugin_get_admindb();
SQLite3DB* proxysql_plugin_get_configdb();
SQLite3DB* proxysql_plugin_get_statsdb();

namespace {

std::atomic<ProxySQL_PluginManager*> g_active_plugin_manager { nullptr };
ProxySQL_PluginManager* g_registry_target = nullptr;
// Guards swaps of g_active_plugin_manager. Readers (dispatch_admin_command,
// dispatch_query_hook, resolve_alias_to_canonical) take a shared lock, so
// many worker threads can be running through plugin callbacks at the same
// time without serializing on a single std::mutex. Writers — load/init/stop
// paths that publish or unpublish the manager pointer — take the unique
// lock. This change is what keeps query-hook dispatch from collapsing the
// per-worker MySQL_Thread / PgSQL_Thread parallelism onto one mutex once a
// plugin actually wires a hook into the hot path.
std::shared_mutex g_active_plugin_manager_mutex {};
// Serializes load/init/stop operations. Held for the duration of a plugin
// lifecycle transition so two reload paths cannot race on g_registry_target /
// g_registry_registration_*. Distinct from g_active_plugin_manager_mutex,
// which only guards pointer reads from the dispatch path.
std::mutex g_plugin_lifecycle_mutex {};
bool g_registry_registration_failed = false;
std::string g_registry_registration_error {};

// RAII guard that sets g_registry_target to `mgr` on construction and
// clears it on destruction.  Also resets the registration-failure sticky
// bits. Used to bracket each plugin callback invocation during Phase B
// (register_schemas) and Phase D (init) so an exception thrown from the
// plugin can't leave the registry globals dirty and break the next
// phase's `assert(g_registry_target == nullptr)`.
struct ScopedRegistryTarget {
	explicit ScopedRegistryTarget(ProxySQL_PluginManager* mgr) {
		g_registry_target = mgr;
		g_registry_registration_failed = false;
		g_registry_registration_error.clear();
	}
	~ScopedRegistryTarget() {
		g_registry_target = nullptr;
		g_registry_registration_failed = false;
		g_registry_registration_error.clear();
	}
	ScopedRegistryTarget(const ScopedRegistryTarget&) = delete;
	ScopedRegistryTarget& operator=(const ScopedRegistryTarget&) = delete;
};

ProxySQL_PluginCommandResult ignored_test_command(const ProxySQL_PluginCommandContext&, const char*) {
	return {0, 0, ""};
}

std::string format_dl_error(const char *prefix) {
	const char *dl_err = dlerror();
	if (dl_err == nullptr) {
		return prefix;
	}
	return std::string(prefix) + dl_err;
}

std::string plugin_name(const ProxySQL_PluginDescriptor *descriptor) {
	if (descriptor == nullptr || descriptor->name == nullptr) {
		return "unknown";
	}
	return descriptor->name;
}

void note_registration_failure(const char* kind, const char* name) {
	g_registry_registration_failed = true;
	if (!g_registry_registration_error.empty()) {
		return;
	}

	g_registry_registration_error = kind;
	g_registry_registration_error += " registration failed";
	if (name != nullptr && *name != '\0') {
		g_registry_registration_error += ": ";
		g_registry_registration_error += name;
	}
}

void register_table_service(const ProxySQL_PluginTableDef& def) {
	if (g_registry_target == nullptr) {
		proxy_warning("Plugin table registration attempted outside init phase for %s\n",
			      def.table_name != nullptr ? def.table_name : "(null)");
		return;
	}

	if (!g_registry_target->register_table(def)) {
		note_registration_failure("plugin table", def.table_name);
		proxy_warning("Plugin table registration failed for %s\n",
			      def.table_name != nullptr ? def.table_name : "(null)");
	}
}

void register_command_service(const char* sql, proxysql_plugin_admin_command_cb cb) {
	if (g_registry_target == nullptr) {
		proxy_warning("Plugin command registration attempted outside init phase for %s\n",
			      sql != nullptr ? sql : "(null)");
		return;
	}

	if (!g_registry_target->register_command(sql, cb)) {
		note_registration_failure("plugin command", sql);
		proxy_warning("Plugin command registration failed for %s\n",
			      sql != nullptr ? sql : "(null)");
	}
}

#ifdef PROXYSQL40
void register_command_alias_service(const char* canonical, const char* alias) {
	if (g_registry_target == nullptr) {
		proxy_warning("Plugin command-alias registration attempted outside init phase "
			      "for %s -> %s\n",
			      alias     != nullptr ? alias     : "(null)",
			      canonical != nullptr ? canonical : "(null)");
		return;
	}

	if (!g_registry_target->register_command_alias(canonical, alias)) {
		note_registration_failure("plugin command alias", alias);
		proxy_warning("Plugin command-alias registration failed: %s -> %s\n",
			      alias     != nullptr ? alias     : "(null)",
			      canonical != nullptr ? canonical : "(null)");
	}
}

bool register_query_hook_service(ProxySQL_PluginProtocol proto,
                                 proxysql_plugin_query_hook_cb cb) {
	if (g_registry_target == nullptr) {
		proxy_warning("Plugin query hook registration attempted outside init phase\n");
		return false;
	}
	if (!g_registry_target->register_query_hook(proto, cb)) {
		note_registration_failure("plugin query hook",
			proto == ProxySQL_PluginProtocol::mysql ? "mysql" : "pgsql");
		proxy_warning("Plugin query hook registration failed for %s\n",
			proto == ProxySQL_PluginProtocol::mysql ? "mysql" : "pgsql");
		return false;
	}
	return true;
}

bool register_runtime_view_service(const ProxySQL_PluginRuntimeView& view) {
	if (g_registry_target == nullptr) {
		proxy_warning("Plugin runtime-view registration attempted outside init/register_schemas phase\n");
		return false;
	}
	if (!g_registry_target->register_runtime_view(view)) {
		note_registration_failure("plugin runtime view",
			view.table_name != nullptr ? view.table_name : "(null)");
		proxy_warning("Plugin runtime-view registration failed for %s\n",
			view.table_name != nullptr ? view.table_name : "(null)");
		return false;
	}
	return true;
}
#endif /* PROXYSQL40 */

SQLite3DB* get_admindb_service() {
	return proxysql_plugin_get_admindb();
}

SQLite3DB* get_configdb_service() {
	return proxysql_plugin_get_configdb();
}

SQLite3DB* get_statsdb_service() {
	return proxysql_plugin_get_statsdb();
}

#ifdef PROXYSQL40
// Phase-B stubs: during register_schemas the admin module has not yet
// materialized the SQLite schema, so DB handles are deliberately nullptr.
// Plugins are documented to never call these during Phase B, but returning
// nullptr gracefully (vs. not installing them) lets misbehaving plugins
// handle it without dereferencing a null function pointer.
SQLite3DB* get_admindb_phase_b_stub()  { return nullptr; }
SQLite3DB* get_configdb_phase_b_stub() { return nullptr; }
SQLite3DB* get_statsdb_phase_b_stub()  { return nullptr; }

// Query hooks are not available in Phase B -- the hook registry is also
// phase-gated on g_registry_target like tables/commands, but we do not
// publish a dispatch path for hooks during schema registration.  Returning
// false lets plugins detect "too early" without crashing.
bool register_query_hook_phase_b_stub(ProxySQL_PluginProtocol,
                                      proxysql_plugin_query_hook_cb) {
	proxy_warning("Plugin query hook registration attempted during register_schemas phase -- do this in init() instead\n");
	return false;
}

prometheus::Registry* get_prometheus_registry_service() {
	return GloVars.prometheus_registry.get();
}
#endif /* PROXYSQL40 */

void log_message_service(int level, const char* message) {
	if (message == nullptr) {
		return;
	}

	switch (level) {
	case 3:
		proxy_error("%s\n", message);
		break;
	case 4:
		proxy_warning("%s\n", message);
		break;
	default:
		proxy_info("%s\n", message);
		break;
	}
}

bool sql_equals_ci(const std::string& lhs, const std::string& rhs) {
	return strcasecmp(lhs.c_str(), rhs.c_str()) == 0;
}

// Normalize a plugin command for alias lookup: strip leading/trailing
// whitespace, strip a trailing ';', collapse internal whitespace runs to
// a single space.
//
// Intentional behavior delta from the pre-chassis v3 path
// (Admin_Handler::resolve_admin_alias_to_canonical), which requires an
// exact length match against the alias string via strncasecmp.  Under the
// chassis, users can type "LOAD  MYSQLX USERS TO RUN" (extra inner
// spaces) or "LOAD MYSQLX USERS TO RUN;" and have it resolve correctly;
// under the !PROXYSQL40 build only the exact spelling matches.  Admin
// commands are low-volume and unambiguous; the looser matching is a
// strict UX improvement.
std::string canonicalize_plugin_command(const std::string& sql) {
	size_t start = 0;
	size_t end = sql.size();
	while (start < end && std::isspace(static_cast<unsigned char>(sql[start]))) {
		++start;
	}
	while (end > start &&
	       (std::isspace(static_cast<unsigned char>(sql[end - 1])) || sql[end - 1] == ';')) {
		--end;
	}

	std::string normalized {};
	normalized.reserve(end - start);
	bool pending_space = false;
	for (size_t i = start; i < end; ++i) {
		const unsigned char ch = static_cast<unsigned char>(sql[i]);
		if (std::isspace(ch)) {
			pending_space = !normalized.empty();
			continue;
		}
		if (pending_space) {
			normalized.push_back(' ');
			pending_space = false;
		}
		normalized.push_back(static_cast<char>(ch));
	}

	return normalized;
}

} // namespace

// Snapshot callbacks return nullptr until implemented.  This is safe to call
// and allows plugins to check the return value rather than crashing on a
// null function pointer.
static SQLite3_result* snapshot_stub() { return nullptr; }

ProxySQL_PluginManager::ProxySQL_PluginManager() {
	std::memset(&services_, 0, sizeof(services_));
	services_.register_table = &register_table_service;
	services_.register_command = &register_command_service;
	services_.get_mysql_users_snapshot = &snapshot_stub;
	services_.get_mysql_servers_snapshot = &snapshot_stub;
	services_.get_mysql_group_replication_hostgroups_snapshot = &snapshot_stub;
	services_.get_admindb = &get_admindb_service;
	services_.get_configdb = &get_configdb_service;
	services_.get_statsdb = &get_statsdb_service;
	services_.log_message = &log_message_service;
#ifdef PROXYSQL40
	services_.register_query_hook = &register_query_hook_service;
	services_.get_prometheus_registry = &get_prometheus_registry_service;
	services_.register_command_alias = &register_command_alias_service;
	services_.register_runtime_view = &register_runtime_view_service;

	// Phase-B (register_schemas) services: same layout as init(), but DB
	// handle getters and the query-hook registrar are stubbed -- see the
	// ProxySQL_PluginServices comment in ProxySQL_Plugin.h for the contract.
	std::memset(&services_phase_b_, 0, sizeof(services_phase_b_));
	services_phase_b_.register_table = &register_table_service;
	services_phase_b_.register_command = &register_command_service;
	services_phase_b_.get_mysql_users_snapshot = &snapshot_stub;
	services_phase_b_.get_mysql_servers_snapshot = &snapshot_stub;
	services_phase_b_.get_mysql_group_replication_hostgroups_snapshot = &snapshot_stub;
	services_phase_b_.get_admindb = &get_admindb_phase_b_stub;
	services_phase_b_.get_configdb = &get_configdb_phase_b_stub;
	services_phase_b_.get_statsdb = &get_statsdb_phase_b_stub;
	services_phase_b_.log_message = &log_message_service;
	services_phase_b_.register_query_hook = &register_query_hook_phase_b_stub;
	services_phase_b_.get_prometheus_registry = &get_prometheus_registry_service;
	// Alias registration is tied to a canonical command; plugins must
	// register_command() first, then register aliases. Since register_command
	// is also available during Phase B, so is register_command_alias.
	services_phase_b_.register_command_alias = &register_command_alias_service;
	// Runtime-view registration is live during register_schemas: views are
	// declared alongside tables, well before init() runs. The actual
	// refresh callback won't fire until Admin handles a SELECT, by which
	// point admin module bootstrap has long since completed.
	services_phase_b_.register_runtime_view = &register_runtime_view_service;
#endif /* PROXYSQL40 */
}

ProxySQL_PluginManager::~ProxySQL_PluginManager() {
	stop_all();
	// Note: g_active_plugin_manager is cleared by callers under the mutex
	// before reset() triggers this destructor.  No unsynchronized access here.
	for (auto it = plugins_.rbegin(); it != plugins_.rend(); ++it) {
		if (it->handle != nullptr) {
			dlclose(it->handle);
			it->handle = nullptr;
		}
	}
}

bool ProxySQL_PluginManager::load(const std::string &path, std::string &err) {
	err.clear();

	// Reject duplicate plugin paths
	for (const auto& existing : plugins_) {
		if (existing.path == path) {
			err = "plugin already loaded: " + path;
			return false;
		}
	}

	void *handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
	if (handle == nullptr) {
		err = format_dl_error("dlopen failed: ");
		return false;
	}

	dlerror();
	auto descriptor_fn = reinterpret_cast<proxysql_plugin_descriptor_v1_t>(
		dlsym(handle, "proxysql_plugin_descriptor_v1"));
	const char *dlsym_err = dlerror();
	if (dlsym_err != nullptr || descriptor_fn == nullptr) {
		err = dlsym_err != nullptr ? dlsym_err : "missing proxysql_plugin_descriptor_v1";
		dlclose(handle);
		return false;
	}

	const ProxySQL_PluginDescriptor *descriptor = descriptor_fn();
	if (descriptor == nullptr) {
		err = "proxysql_plugin_descriptor_v1 returned null";
		dlclose(handle);
		return false;
	}

	if (descriptor->name == nullptr || descriptor->name[0] == '\0') {
		err = "plugin descriptor has null or empty name";
		dlclose(handle);
		return false;
	}

	// Reject plugins built for a newer ABI than this core understands: the
	// plugin's descriptor struct would have more fields than ours, and
	// dereferencing those fields would read past the end of our struct
	// definition.  The reverse direction (older ABI plugin, newer core) is
	// safe via the tail-append pattern -- fields the plugin didn't define
	// are never dereferenced (see handling of register_schemas below).
	if (descriptor->abi_version < 1u ||
	    descriptor->abi_version > PROXYSQL_PLUGIN_ABI_VERSION_MAX) {
		err = "unsupported plugin ABI version";
		dlclose(handle);
		return false;
	}

	plugin_handle_t plugin;
	plugin.handle = handle;
	plugin.descriptor = descriptor;
	plugin.path = path;
	plugins_.push_back(plugin);
	return true;
}

#ifdef PROXYSQL40
bool ProxySQL_PluginManager::invoke_register_schemas_phase(std::string &err) {
	// Phase B of the four-phase lifecycle.  Called after all plugins have
	// been dlopen'd but before admin module bootstrap, so plugins can
	// declare schema for merge_plugin_tables to materialize.
	//
	// Like init_all, we use g_registry_target as the single-threaded seam
	// so the free-standing service trampolines route writes to the right
	// manager.  This path is only taken during startup / reload, never
	// concurrently with the steady-state request path.
	assert(g_registry_target == nullptr);
	err.clear();

	for (auto &plugin : plugins_) {
		if (plugin.schemas_registered || plugin.stopped) {
			continue;
		}
		// register_schemas only exists on ABI v2 descriptors.  Reading it
		// from a v1 plugin's static descriptor would be an out-of-bounds
		// read -- v1 plugins allocate only the first 6 fields.  Treat v1
		// plugins as if they opted out of Phase B.
		proxysql_plugin_register_schemas_cb register_schemas_cb = nullptr;
		if (plugin.descriptor != nullptr && plugin.descriptor->abi_version >= 2u) {
			register_schemas_cb = plugin.descriptor->register_schemas;
		}
		if (register_schemas_cb == nullptr) {
			// Plugin opted out of Phase B -- the pre-existing two-phase
			// path (init-only) still works: mark it as having completed
			// Phase B so init_all doesn't get confused later.
			plugin.schemas_registered = true;
			continue;
		}
		// Snapshot the registration state before invoking the plugin so
		// that a partial success followed by a failure (callback registers
		// three tables, then returns false) doesn't leak registrations a
		// retry would then reject as duplicates.
		const size_t snap_tables_admin  = tables_admin_.size();
		const size_t snap_tables_config = tables_config_.size();
		const size_t snap_tables_stats  = tables_stats_.size();
		const size_t snap_commands      = commands_.size();
		const size_t snap_table_storage = table_storage_.size();
		bool phase_b_ok;
		bool registration_failed;
		std::string registration_error;
		{
			ScopedRegistryTarget target_guard(this);
			phase_b_ok = register_schemas_cb(&services_phase_b_);
			registration_failed = g_registry_registration_failed;
			registration_error = g_registry_registration_error;
		}
		auto rollback = [&]() {
			tables_admin_.resize(snap_tables_admin);
			tables_config_.resize(snap_tables_config);
			tables_stats_.resize(snap_tables_stats);
			commands_.resize(snap_commands);
			while (table_storage_.size() > snap_table_storage) {
				table_storage_.pop_back();
			}
		};
		if (!phase_b_ok) {
			rollback();
			err = "plugin register_schemas failed: " + plugin_name(plugin.descriptor);
			return false;
		}
		if (registration_failed) {
			rollback();
			err = "plugin register_schemas failed: " + plugin_name(plugin.descriptor);
			if (!registration_error.empty()) {
				err += ": " + registration_error;
			}
			return false;
		}
		plugin.schemas_registered = true;
	}

	return true;
}
#endif /* PROXYSQL40 */

bool ProxySQL_PluginManager::init_all(std::string &err) {
	// Only called during single-threaded startup; g_registry_target and
	// g_registry_registration_* globals have no mutex protection by design.
	assert(g_registry_target == nullptr);
	err.clear();

	for (auto &plugin : plugins_) {
		if (plugin.initialized || plugin.stopped) {
			continue;
		}
		if (plugin.descriptor == nullptr || plugin.descriptor->init == nullptr) {
			plugin.initialized = true;
			continue;
		}
		// Same rollback contract as invoke_register_schemas_phase: on
		// failure, trim any registrations this plugin performed so a
		// retry doesn't duplicate-fail.
		const size_t snap_tables_admin  = tables_admin_.size();
		const size_t snap_tables_config = tables_config_.size();
		const size_t snap_tables_stats  = tables_stats_.size();
		const size_t snap_commands      = commands_.size();
		const size_t snap_table_storage = table_storage_.size();
		bool init_ok;
		bool registration_failed;
		std::string registration_error;
		{
			ScopedRegistryTarget target_guard(this);
			init_ok = plugin.descriptor->init(&services_);
			registration_failed = g_registry_registration_failed;
			registration_error = g_registry_registration_error;
		}
		auto rollback = [&]() {
			tables_admin_.resize(snap_tables_admin);
			tables_config_.resize(snap_tables_config);
			tables_stats_.resize(snap_tables_stats);
			commands_.resize(snap_commands);
			while (table_storage_.size() > snap_table_storage) {
				table_storage_.pop_back();
			}
		};
		if (!init_ok) {
			rollback();
			err = "plugin init failed: " + plugin_name(plugin.descriptor);
			return false;
		}
		if (registration_failed) {
			rollback();
			err = "plugin init failed: " + plugin_name(plugin.descriptor);
			if (!registration_error.empty()) {
				err += ": " + registration_error;
			}
			return false;
		}
		plugin.initialized = true;
	}

	return true;
}

bool ProxySQL_PluginManager::start_all(std::string &err) {
	err.clear();

	for (auto &plugin : plugins_) {
		if (plugin.started || plugin.stopped) {
			continue;
		}
		if (!plugin.initialized) {
			err = "plugin not initialized: " + plugin_name(plugin.descriptor);
			return false;
		}
		if (plugin.descriptor == nullptr || plugin.descriptor->start == nullptr) {
			plugin.started = true;
			continue;
		}
		if (!plugin.descriptor->start()) {
			err = "plugin start failed: " + plugin_name(plugin.descriptor);
			return false;
		}
		plugin.started = true;
	}

	return true;
}

bool ProxySQL_PluginManager::stop_all() {
	bool ok = true;

	for (auto it = plugins_.rbegin(); it != plugins_.rend(); ++it) {
		// stop() pairs with init() for teardown symmetry: any plugin
		// that succeeded init() gets stop() called, even if start()
		// later failed.  Otherwise resources the plugin allocated in
		// init (config stores, worker threads, metric gauges, ...)
		// leak on the init-success/start-fail path.  Plugins that
		// never reached init are skipped.
		if (!it->initialized) {
			continue;
		}
		if (it->stopped) {
			continue;
		}
		if (it->descriptor != nullptr && it->descriptor->stop != nullptr) {
			if (!it->descriptor->stop()) {
				proxy_warning("Plugin stop failed: %s\n", plugin_name(it->descriptor).c_str());
				ok = false;
			}
		}
		// Mark stopped even on failure — never retry stop() on the same plugin.
		// The destructor's stop_all() call must be idempotent across failure paths.
		it->stopped = true;
	}

	return ok;
}

size_t ProxySQL_PluginManager::size() const {
	return plugins_.size();
}

const std::vector<ProxySQL_PluginTableDef>& ProxySQL_PluginManager::tables(ProxySQL_PluginDBKind kind) const {
	static const std::vector<ProxySQL_PluginTableDef> empty_tables {};

	switch (kind) {
	case ProxySQL_PluginDBKind::admin_db:
		return tables_admin_;
	case ProxySQL_PluginDBKind::config_db:
		return tables_config_;
	case ProxySQL_PluginDBKind::stats_db:
		return tables_stats_;
	default:
		proxy_warning("Invalid plugin table registry kind requested: %d\n", static_cast<int>(kind));
		return empty_tables;
	}
}

bool ProxySQL_PluginManager::dispatch_admin_command(const ProxySQL_PluginCommandContext& ctx, const std::string& sql, ProxySQL_PluginCommandResult& result) const {
	const std::string normalized_sql = canonicalize_plugin_command(sql);

	for (const auto& command : commands_) {
		bool matches = sql_equals_ci(command.sql, normalized_sql);
#ifdef PROXYSQL40
		if (!matches) {
			for (const auto& alias : command.aliases) {
				if (sql_equals_ci(alias, normalized_sql)) {
					matches = true;
					break;
				}
			}
		}
#endif /* PROXYSQL40 */
		if (!matches) {
			continue;
		}
		if (command.cb == nullptr) {
			return false;
		}
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Dispatching plugin command: %s (via %s)\n",
			    command.sql.c_str(), normalized_sql.c_str());
		// Pass the CANONICAL form to the callback so plugins can ignore
		// which alias the user typed — they match on their own canonical
		// strings only.
		result = command.cb(ctx, command.sql.c_str());
		return true;
	}

	return false;
}

void ProxySQL_PluginManager::register_table_for_test(const ProxySQL_PluginTableDef& def) {
	register_table(def);
}

bool ProxySQL_PluginManager::register_command_for_test(const std::string& sql) {
	return register_command(sql.c_str(), &ignored_test_command);
}

bool ProxySQL_PluginManager::has_command_for_test(const std::string& sql) const {
	const std::string canonical_sql = canonicalize_plugin_command(sql);
	for (const auto& command : commands_) {
		if (sql_equals_ci(command.sql, canonical_sql)) {
			return true;
		}
	}
	return false;
}

bool ProxySQL_PluginManager::register_table(const ProxySQL_PluginTableDef& def) {
	if (def.table_name == nullptr || *def.table_name == '\0' ||
	    def.table_def == nullptr || *def.table_def == '\0') {
		return false;
	}

	const std::vector<ProxySQL_PluginTableDef>* existing_tables = nullptr;
	switch (def.db_kind) {
	case ProxySQL_PluginDBKind::admin_db:
		existing_tables = &tables_admin_;
		break;
	case ProxySQL_PluginDBKind::config_db:
		existing_tables = &tables_config_;
		break;
	case ProxySQL_PluginDBKind::stats_db:
		existing_tables = &tables_stats_;
		break;
	default:
		return false;
	}

	for (const auto& existing : *existing_tables) {
		if (strcasecmp(existing.table_name, def.table_name) == 0) {
			return false;
		}
	}

	table_storage_.push_back({def.table_name, def.table_def});
	const registered_table_storage_t& stored = table_storage_.back();
	const ProxySQL_PluginTableDef owned_def {
		def.db_kind,
		stored.table_name.c_str(),
		stored.table_def.c_str()
	};

	switch (def.db_kind) {
	case ProxySQL_PluginDBKind::admin_db:
		tables_admin_.push_back(owned_def);
		break;
	case ProxySQL_PluginDBKind::config_db:
		tables_config_.push_back(owned_def);
		break;
	case ProxySQL_PluginDBKind::stats_db:
		tables_stats_.push_back(owned_def);
		break;
	default:
		return false;
	}

	return true;
}

#ifdef PROXYSQL40
bool ProxySQL_PluginManager::register_query_hook(ProxySQL_PluginProtocol proto,
                                                 proxysql_plugin_query_hook_cb cb) {
	if (cb == nullptr) {
		return false;
	}
	switch (proto) {
	case ProxySQL_PluginProtocol::mysql:
		if (mysql_query_hook_ != nullptr) return false;
		mysql_query_hook_ = cb;
		return true;
	case ProxySQL_PluginProtocol::pgsql:
		if (pgsql_query_hook_ != nullptr) return false;
		pgsql_query_hook_ = cb;
		return true;
	}
	return false;
}

bool ProxySQL_PluginManager::has_query_hook(ProxySQL_PluginProtocol proto) const {
	switch (proto) {
	case ProxySQL_PluginProtocol::mysql: return mysql_query_hook_ != nullptr;
	case ProxySQL_PluginProtocol::pgsql: return pgsql_query_hook_ != nullptr;
	}
	return false;
}

bool ProxySQL_PluginManager::dispatch_query_hook(ProxySQL_PluginProtocol proto,
                                                 const ProxySQL_PluginQueryHookPayload& payload,
                                                 ProxySQL_PluginQueryHookResult& result) const {
	proxysql_plugin_query_hook_cb cb = nullptr;
	switch (proto) {
	case ProxySQL_PluginProtocol::mysql: cb = mysql_query_hook_; break;
	case ProxySQL_PluginProtocol::pgsql: cb = pgsql_query_hook_; break;
	}
	if (cb == nullptr) {
		return false;
	}
	result = cb(payload);
	return true;
}

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

namespace {

// Case-insensitive substring check matching whole identifier-like
// occurrences. We don't want a SELECT against `runtime_mysqlx_users`
// to also fire the refresh for `runtime_mysqlx_users_extra` if
// someone ever registers both. The match treats `[A-Za-z0-9_]` as
// identifier characters and requires the surrounding chars (if any)
// to be non-identifier — same convention as the sql_equals_ci
// canonicaliser used elsewhere in this file.
bool is_ident_char(unsigned char c) {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') || c == '_';
}

bool sql_references_table_ci(const std::string& sql, const std::string& table_name) {
	if (table_name.empty() || table_name.size() > sql.size()) {
		return false;
	}
	for (size_t i = 0; i + table_name.size() <= sql.size(); i++) {
		if (strncasecmp(sql.data() + i, table_name.data(), table_name.size()) != 0) {
			continue;
		}
		const bool left_ok  = (i == 0) || !is_ident_char(static_cast<unsigned char>(sql[i - 1]));
		const size_t after  = i + table_name.size();
		const bool right_ok = (after == sql.size()) || !is_ident_char(static_cast<unsigned char>(sql[after]));
		if (left_ok && right_ok) {
			return true;
		}
	}
	return false;
}

} // namespace

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
		default:
			proxy_warning("Unknown db_kind %d for runtime view '%s', skipping\n",
				static_cast<uint8_t>(view.db_kind), view.table_name.c_str());
			break;
		}
		if (db == nullptr) continue;
		view.refresh(db, view.opaque);
	}
}
#endif /* PROXYSQL40 */

bool ProxySQL_PluginManager::register_command(const char* sql, proxysql_plugin_admin_command_cb cb) {
	if (sql == nullptr || *sql == '\0' || cb == nullptr) {
		return false;
	}

	const std::string canonical_sql = canonicalize_plugin_command(sql);
	if (canonical_sql.empty()) {
		return false;
	}

	for (const auto& command : commands_) {
		if (sql_equals_ci(command.sql, canonical_sql)) {
			return false;
		}
	}

	commands_.push_back({canonical_sql, cb});
	return true;
}

#ifdef PROXYSQL40
bool ProxySQL_PluginManager::register_command_alias(const char* canonical_sql, const char* alias_sql) {
	if (canonical_sql == nullptr || *canonical_sql == '\0' ||
	    alias_sql == nullptr || *alias_sql == '\0') {
		return false;
	}

	const std::string canonical = canonicalize_plugin_command(canonical_sql);
	const std::string alias = canonicalize_plugin_command(alias_sql);
	if (canonical.empty() || alias.empty()) {
		return false;
	}

	// Reject a request that would shadow another command's canonical
	// spelling. Idempotent for duplicate (canonical, alias) pairs under
	// the same entry.
	for (auto& command : commands_) {
		if (sql_equals_ci(command.sql, alias) && !sql_equals_ci(command.sql, canonical)) {
			return false;
		}
		for (const auto& other_alias : command.aliases) {
			if (sql_equals_ci(other_alias, alias) && !sql_equals_ci(command.sql, canonical)) {
				return false;
			}
		}
	}

	for (auto& command : commands_) {
		if (!sql_equals_ci(command.sql, canonical)) {
			continue;
		}
		// Idempotent: skip if alias (or canonical itself) is already recorded.
		if (sql_equals_ci(command.sql, alias)) {
			return true;
		}
		for (const auto& existing : command.aliases) {
			if (sql_equals_ci(existing, alias)) {
				return true;
			}
		}
		command.aliases.push_back(alias);
		return true;
	}

	return false;
}

std::string ProxySQL_PluginManager::resolve_alias_to_canonical(const std::string& sql) const {
	const std::string canonical_sql = canonicalize_plugin_command(sql);
	if (canonical_sql.empty()) {
		return {};
	}
	for (const auto& command : commands_) {
		if (sql_equals_ci(command.sql, canonical_sql)) {
			return command.sql;
		}
		for (const auto& alias : command.aliases) {
			if (sql_equals_ci(alias, canonical_sql)) {
				return command.sql;
			}
		}
	}
	return {};
}
#endif /* PROXYSQL40 */

ProxySQL_PluginManager* proxysql_get_plugin_manager() {
	return g_active_plugin_manager.load(std::memory_order_acquire);
}

bool proxysql_dispatch_configured_plugin_admin_command(
	const ProxySQL_PluginCommandContext& ctx,
	const std::string& sql,
	ProxySQL_PluginCommandResult& result
) {
	// Reader: shared lock so concurrent admin sessions can dispatch
	// plugin commands in parallel. The unique-lock writers (publish /
	// unpublish in load_/stop_configured_plugins) still serialize swaps.
	std::shared_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
	if (g_active_plugin_manager.load() == nullptr) {
		return false;
	}

	return g_active_plugin_manager.load()->dispatch_admin_command(ctx, sql, result);
}

#ifdef PROXYSQL40
std::string proxysql_resolve_configured_plugin_admin_alias(const std::string& sql) {
	// Return-by-value (not const char*) intentional: the alias table lives
	// in the manager, and the caller typically releases the lock before
	// dispatching. A borrowed c_str() would dangle if the manager is swapped
	// out on reload between resolve and dispatch. Copy out under the lock.
	std::shared_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
	ProxySQL_PluginManager* mgr = g_active_plugin_manager.load();
	if (mgr == nullptr) {
		return {};
	}
	return mgr->resolve_alias_to_canonical(sql);
}

bool proxysql_dispatch_configured_plugin_query_hook(
	ProxySQL_PluginProtocol proto,
	const ProxySQL_PluginQueryHookPayload& payload,
	ProxySQL_PluginQueryHookResult& result
) {
	// Reader: shared lock so query-hook dispatch on the data-plane hot
	// path scales across MySQL_Thread / PgSQL_Thread workers instead of
	// serializing on a single std::mutex. This is the change that lets a
	// plugin wire a query hook without collapsing per-worker parallelism.
	std::shared_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
	ProxySQL_PluginManager* mgr = g_active_plugin_manager.load();
	if (mgr == nullptr) {
		return false;
	}
	return mgr->dispatch_query_hook(proto, payload, result);
}

bool proxysql_has_configured_plugin_query_hook(ProxySQL_PluginProtocol proto) {
	// Hot path: lock-free.  Reads the atomic pointer; if non-null, calls
	// has_query_hook() which only reads two pointer-sized fields.  A
	// concurrent unload can null the pointer between this check and a
	// subsequent dispatch call -- the dispatch helper handles that case
	// by re-checking under the lock.  Callers must tolerate spurious
	// "yes" returns.
	ProxySQL_PluginManager* mgr = g_active_plugin_manager.load(std::memory_order_acquire);
	if (mgr == nullptr) {
		return false;
	}
	return mgr->has_query_hook(proto);
}

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

void proxysql_restore_plugin_config_tables_from_disk(SQLite3DB* admindb,
	const std::vector<ProxySQL_PluginTableDef>& config_tables)
{
	if (admindb == nullptr) {
		return;
	}
	for (const auto& def : config_tables) {
		if (def.table_name == nullptr || *def.table_name == '\0') {
			continue;
		}
		// Every table registered for config_db is also registered for
		// admin_db with the same definition -- that pairing is what makes it
		// a persisted table rather than a runtime projection -- so SELECT *
		// is column-compatible by construction. A plugin that registers a
		// config_db table with no admin_db twin is a registration bug;
		// execute() logs the SQLite error and returns false, and startup
		// continues with that one table unrestored rather than aborting.
		std::string q = "INSERT OR REPLACE INTO main.";
		q += def.table_name;
		q += " SELECT * FROM disk.";
		q += def.table_name;
		admindb->execute(q.c_str());
	}
}

void proxysql_restore_configured_plugin_config_tables(SQLite3DB* admindb) {
	std::shared_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
	ProxySQL_PluginManager* mgr = g_active_plugin_manager.load();
	if (mgr == nullptr) {
		return;
	}
	proxysql_restore_plugin_config_tables_from_disk(
		admindb, mgr->tables(ProxySQL_PluginDBKind::config_db));
}
#endif /* PROXYSQL40 */

bool proxysql_load_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	const std::vector<std::string>& plugin_modules,
	std::string& err
) {
	// Phase A + Phase B of the four-phase lifecycle. Executed BEFORE
	// ProxySQL_Main_init_Admin_module so that plugin-declared schemas are
	// available when Admin::init() merges them into tables_defs_* and
	// runs the DDL via check_and_build_standard_tables.
	//
	// On return, `manager` is populated and installed as the active
	// manager — Admin::init() reads it via proxysql_get_plugin_manager()
	// to find the tables to merge. Phase D (init) runs later, via
	// proxysql_init_configured_plugins, once admin is up.
	std::lock_guard<std::mutex> lifecycle_lock(g_plugin_lifecycle_mutex);
	err.clear();
	{
		std::unique_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
		g_active_plugin_manager.store(nullptr, std::memory_order_release);
	}
	manager.reset();

	if (plugin_modules.empty()) {
		return true;
	}

	auto next_manager = std::make_unique<ProxySQL_PluginManager>();
	for (const auto& path : plugin_modules) {
		if (!next_manager->load(path, err)) {
			err = path + ": " + err;
			return false;
		}
	}

	// Phase B: register_schemas runs here. Plugins declare their
	// admin-schema tables into the manager's pending-tables list.
	// ProxySQL_Admin::init() (called next, via
	// ProxySQL_Main_init_Admin_module in src/main.cpp) drains that list
	// by merging into tables_defs_{admin,config,stats} and then running
	// the DDL via check_and_build_standard_tables — same code path as
	// the core tables. Plugins that left register_schemas null are
	// no-ops here.
	if (!next_manager->invoke_register_schemas_phase(err)) {
		return false;
	}

	// Install as active manager BEFORE admin init, so that
	// proxysql_get_plugin_manager() — used by ProxySQL_Admin::init() to
	// merge plugin-declared schemas into tables_defs_* — can find the
	// registered tables.
	//
	// INVARIANT (publish-before-Phase-D): after this point Phase D
	// (init_all via proxysql_init_configured_plugins) WILL still write
	// to commands_ / mysql_query_hook_ / pgsql_query_hook_ on the
	// published manager.  This is only safe because Phase D runs during
	// single-threaded startup — before ProxySQL_Main_init_phase3___
	// start_all spawns the threads that take the lock-free read path
	// (proxysql_has_configured_plugin_query_hook, Admin_Handler alias
	// resolution).  Any reordering that moves listener startup before
	// proxysql_init_configured_plugins() returns will race plain writes
	// against plain reads.
	{
		std::unique_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
		manager = std::move(next_manager);
		g_active_plugin_manager.store(manager.get(), std::memory_order_release);
	}
	return true;
}

#ifdef PROXYSQL40
bool proxysql_init_configured_plugins(
	ProxySQL_PluginManager* manager,
	std::string& err
) {
	// Phase D of the four-phase lifecycle. Runs after
	// ProxySQL_Main_init_Admin_module has materialized plugin-owned
	// tables, so each plugin's init() sees live DB handles against a
	// schema that already contains its own tables.
	//
	// ORDERING INVARIANT: caller MUST invoke this BEFORE any thread
	// that takes the lock-free read path on the manager
	// (MySQL_Thread / PgSQL_Thread dispatch_query_hook, Admin_Handler
	// alias resolution) comes up.  See src/main.cpp:
	//   ProxySQL_Main_init_phase2___not_started  — runs Phase D
	//   ProxySQL_Main_init_phase3___start_all    — spawns workers
	// Phase 3 must run strictly after Phase 2 returns.
	//
	// FAILURE MODE: if this function returns false, the caller in
	// src/main.cpp calls exit(EXIT_FAILURE) — Phase D failure is a
	// fatal startup error.  The published manager is left in place;
	// plugins that succeeded init() will have stop_all() called during
	// process teardown (see stop_all's "initialized -> stop()"
	// contract).  Runtime reload of plugin_modules is NOT supported by
	// this code path: it is callable from the startup codepath only.
	err.clear();
	if (manager == nullptr) {
		return true;
	}
	return manager->init_all(err);
}
#endif /* PROXYSQL40 */

bool proxysql_start_configured_plugins(
	ProxySQL_PluginManager* manager,
	std::string& err
) {
	std::lock_guard<std::mutex> lifecycle_lock(g_plugin_lifecycle_mutex);
	err.clear();
	if (manager == nullptr) {
		return true;
	}

	return manager->start_all(err);
}

bool proxysql_stop_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	std::string& err
) {
	std::lock_guard<std::mutex> lifecycle_lock(g_plugin_lifecycle_mutex);
	err.clear();
	{
		std::unique_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
		g_active_plugin_manager.store(nullptr, std::memory_order_release);
	}
	if (!manager) {
		return true;
	}

	const bool stop_ok = manager->stop_all();
	// Always tear down the manager so the .so is unmapped and no stale function
	// pointers remain reachable. stop_all() is idempotent across failure (each
	// plugin is marked stopped after one attempt) so the destructor's stop_all()
	// will be a no-op.
	manager.reset();
	if (!stop_ok) {
		err = "plugin stop failed";
		return false;
	}
	return true;
}

#endif /* PROXYSQL40 */
