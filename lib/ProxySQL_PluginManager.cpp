#include "ProxySQL_PluginManager.h"

#include <atomic>
#include <cassert>
#include <cctype>
#include <cstring>
#include <dlfcn.h>
#include <mutex>
#include <strings.h>

#include "proxysql.h"
#include "proxysql_glovars.hpp"
#include "prometheus/registry.h"

extern ProxySQL_GlobalVariables GloVars;

SQLite3DB* proxysql_plugin_get_admindb();
SQLite3DB* proxysql_plugin_get_configdb();
SQLite3DB* proxysql_plugin_get_statsdb();

namespace {

std::atomic<ProxySQL_PluginManager*> g_active_plugin_manager { nullptr };
ProxySQL_PluginManager* g_registry_target = nullptr;
std::mutex g_active_plugin_manager_mutex {};
bool g_registry_registration_failed = false;
std::string g_registry_registration_error {};

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

SQLite3DB* get_admindb_service() {
	return proxysql_plugin_get_admindb();
}

SQLite3DB* get_configdb_service() {
	return proxysql_plugin_get_configdb();
}

SQLite3DB* get_statsdb_service() {
	return proxysql_plugin_get_statsdb();
}

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
	services_.register_query_hook = &register_query_hook_service;
	services_.get_prometheus_registry = &get_prometheus_registry_service;

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

	if (descriptor->abi_version != 1) {
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
		if (plugin.descriptor == nullptr ||
		    plugin.descriptor->register_schemas == nullptr) {
			// Plugin opted out of Phase B -- the pre-existing two-phase
			// path (init-only) still works: mark it as having completed
			// Phase B so init_all doesn't get confused later.
			plugin.schemas_registered = true;
			continue;
		}
		g_registry_target = this;
		g_registry_registration_failed = false;
		g_registry_registration_error.clear();
		const bool phase_b_ok = plugin.descriptor->register_schemas(&services_phase_b_);
		const bool registration_failed = g_registry_registration_failed;
		const std::string registration_error = g_registry_registration_error;
		g_registry_registration_failed = false;
		g_registry_registration_error.clear();
		g_registry_target = nullptr;
		if (!phase_b_ok) {
			err = "plugin register_schemas failed: " + plugin_name(plugin.descriptor);
			return false;
		}
		if (registration_failed) {
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
		g_registry_target = this;
		g_registry_registration_failed = false;
		g_registry_registration_error.clear();
		const bool init_ok = plugin.descriptor->init(&services_);
		const bool registration_failed = g_registry_registration_failed;
		const std::string registration_error = g_registry_registration_error;
		g_registry_registration_failed = false;
		g_registry_registration_error.clear();
		g_registry_target = nullptr;
		if (!init_ok) {
			err = "plugin init failed: " + plugin_name(plugin.descriptor);
			return false;
		}
		if (registration_failed) {
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
		if (!it->started) {
			continue; // Only stop plugins that were actually started.
		}
		if (it->stopped) {
			continue;
		}
		if (it->descriptor != nullptr && it->descriptor->stop != nullptr) {
			if (!it->descriptor->stop()) {
				proxy_warning("Plugin stop failed: %s\n", plugin_name(it->descriptor).c_str());
				ok = false;
				continue;
			}
		}
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
	const std::string canonical_sql = canonicalize_plugin_command(sql);

	for (const auto& command : commands_) {
		if (!sql_equals_ci(command.sql, canonical_sql)) {
			continue;
		}
		if (command.cb == nullptr) {
			return false;
		}
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Dispatching plugin command: %s\n",
			    command.sql.c_str());
		result = command.cb(ctx, canonical_sql.c_str());
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

ProxySQL_PluginManager* proxysql_get_plugin_manager() {
	return g_active_plugin_manager.load(std::memory_order_acquire);
}

bool proxysql_dispatch_configured_plugin_admin_command(
	const ProxySQL_PluginCommandContext& ctx,
	const std::string& sql,
	ProxySQL_PluginCommandResult& result
) {
	std::lock_guard<std::mutex> lock(g_active_plugin_manager_mutex);
	if (g_active_plugin_manager.load() == nullptr) {
		return false;
	}

	return g_active_plugin_manager.load()->dispatch_admin_command(ctx, sql, result);
}

bool proxysql_dispatch_configured_plugin_query_hook(
	ProxySQL_PluginProtocol proto,
	const ProxySQL_PluginQueryHookPayload& payload,
	ProxySQL_PluginQueryHookResult& result
) {
	std::lock_guard<std::mutex> lock(g_active_plugin_manager_mutex);
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

bool proxysql_load_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	const std::vector<std::string>& plugin_modules,
	std::string& err
) {
	// Phase A + Phase B of the four-phase lifecycle. Executed BEFORE
	// ProxySQL_Main_init_Admin_module so that plugin-declared schemas are
	// available when merge_plugin_tables materializes the SQLite schema.
	//
	// On return, `manager` is populated and installed as the active
	// manager — GloAdmin->materialize_plugin_tables() can then query it
	// for the tables to CREATE. Phase D (init) runs later, via
	// proxysql_init_configured_plugins, once admin is up.
	err.clear();
	{
		std::lock_guard<std::mutex> lock(g_active_plugin_manager_mutex);
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
	// GloAdmin->materialize_plugin_tables() (called after
	// ProxySQL_Main_init_Admin_module in src/main.cpp) drains that list
	// into SQLite via the merge_plugin_tables code path. Plugins that
	// left register_schemas null are no-ops here.
	if (!next_manager->invoke_register_schemas_phase(err)) {
		return false;
	}

	// Install as active manager BEFORE admin init, so that
	// proxysql_get_plugin_manager() — used by
	// ProxySQL_Admin::materialize_plugin_tables — can find the
	// registered tables.
	{
		std::lock_guard<std::mutex> lock(g_active_plugin_manager_mutex);
		manager = std::move(next_manager);
		g_active_plugin_manager.store(manager.get(), std::memory_order_release);
	}
	return true;
}

bool proxysql_init_configured_plugins(
	ProxySQL_PluginManager* manager,
	std::string& err
) {
	// Phase D of the four-phase lifecycle. Runs after
	// ProxySQL_Main_init_Admin_module has materialized plugin-owned
	// tables, so each plugin's init() sees live DB handles against a
	// schema that already contains its own tables.
	err.clear();
	if (manager == nullptr) {
		return true;
	}
	return manager->init_all(err);
}

bool proxysql_start_configured_plugins(
	ProxySQL_PluginManager* manager,
	std::string& err
) {
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
	err.clear();
	{
		std::lock_guard<std::mutex> lock(g_active_plugin_manager_mutex);
		g_active_plugin_manager.store(nullptr, std::memory_order_release);
	}
	if (!manager) {
		return true;
	}

	if (!manager->stop_all()) {
		err = "plugin stop failed";
		return false;
	}

	manager.reset();
	return true;
}
