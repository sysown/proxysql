#include "ProxySQL_PluginManager.h"

#include <cstring>
#include <dlfcn.h>
#include <strings.h>

#include "proxysql.h"

SQLite3DB* proxysql_plugin_get_admindb();
SQLite3DB* proxysql_plugin_get_configdb();
SQLite3DB* proxysql_plugin_get_statsdb();

namespace {

ProxySQL_PluginManager* g_active_plugin_manager = nullptr;
ProxySQL_PluginManager* g_registry_target = nullptr;

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

void register_table_service(const ProxySQL_PluginTableDef& def) {
	if (g_registry_target != nullptr) {
		g_registry_target->register_table(def);
	}
}

void register_command_service(const char* sql, proxysql_plugin_admin_command_cb cb) {
	if (g_registry_target != nullptr) {
		g_registry_target->register_command(sql, cb);
	}
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

} // namespace

ProxySQL_PluginManager::ProxySQL_PluginManager() {
	std::memset(&services_, 0, sizeof(services_));
	services_.register_table = &register_table_service;
	services_.register_command = &register_command_service;
	services_.get_admindb = &get_admindb_service;
	services_.get_configdb = &get_configdb_service;
	services_.get_statsdb = &get_statsdb_service;
	services_.log_message = &log_message_service;
}

ProxySQL_PluginManager::~ProxySQL_PluginManager() {
	stop_all();
	if (g_active_plugin_manager == this) {
		g_active_plugin_manager = nullptr;
	}
	for (auto it = plugins_.rbegin(); it != plugins_.rend(); ++it) {
		if (it->handle != nullptr) {
			dlclose(it->handle);
			it->handle = nullptr;
		}
	}
}

bool ProxySQL_PluginManager::load(const std::string &path, std::string &err) {
	err.clear();

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

	if (descriptor->abi_version != 1) {
		err = "unsupported plugin ABI version";
		dlclose(handle);
		return false;
	}

	plugin_handle_t plugin;
	plugin.handle = handle;
	plugin.descriptor = descriptor;
	plugins_.push_back(plugin);
	return true;
}

bool ProxySQL_PluginManager::init_all(std::string &err) {
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
		if (!plugin.descriptor->init(&services_)) {
			g_registry_target = nullptr;
			err = "plugin init failed: " + plugin_name(plugin.descriptor);
			return false;
		}
		g_registry_target = nullptr;
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
		if (!it->initialized && !it->started) {
			continue;
		}
		if (it->stopped) {
			continue;
		}
		if (it->descriptor != nullptr && it->descriptor->stop != nullptr) {
			ok = it->descriptor->stop() && ok;
		}
		it->stopped = true;
	}

	return ok;
}

size_t ProxySQL_PluginManager::size() const {
	return plugins_.size();
}

const std::vector<ProxySQL_PluginTableDef>& ProxySQL_PluginManager::tables(ProxySQL_PluginDBKind kind) const {
	switch (kind) {
	case ProxySQL_PluginDBKind::admin_db:
		return tables_admin_;
	case ProxySQL_PluginDBKind::config_db:
		return tables_config_;
	case ProxySQL_PluginDBKind::stats_db:
	default:
		return tables_stats_;
	}
}

bool ProxySQL_PluginManager::dispatch_admin_command(const ProxySQL_PluginCommandContext& ctx, const std::string& sql, ProxySQL_PluginCommandResult& result) const {
	for (const auto& command : commands_) {
		if (!sql_equals_ci(command.sql, sql)) {
			continue;
		}
		if (command.cb == nullptr) {
			return false;
		}
		result = command.cb(ctx, sql.c_str());
		return true;
	}

	return false;
}

void ProxySQL_PluginManager::register_table_for_test(const ProxySQL_PluginTableDef& def) {
	register_table(def);
}

bool ProxySQL_PluginManager::register_command_for_test(const std::string& sql) {
	return register_command(sql.c_str(), nullptr);
}

bool ProxySQL_PluginManager::has_command_for_test(const std::string& sql) const {
	for (const auto& command : commands_) {
		if (sql_equals_ci(command.sql, sql)) {
			return true;
		}
	}
	return false;
}

void ProxySQL_PluginManager::register_table(const ProxySQL_PluginTableDef& def) {
	switch (def.db_kind) {
	case ProxySQL_PluginDBKind::admin_db:
		tables_admin_.push_back(def);
		break;
	case ProxySQL_PluginDBKind::config_db:
		tables_config_.push_back(def);
		break;
	case ProxySQL_PluginDBKind::stats_db:
		tables_stats_.push_back(def);
		break;
	}
}

bool ProxySQL_PluginManager::register_command(const char* sql, proxysql_plugin_admin_command_cb cb) {
	if (sql == nullptr || *sql == '\0') {
		return false;
	}

	for (const auto& command : commands_) {
		if (strcasecmp(command.sql.c_str(), sql) == 0) {
			return false;
		}
	}

	commands_.push_back({sql, cb});
	return true;
}

ProxySQL_PluginManager* proxysql_get_plugin_manager() {
	return g_active_plugin_manager;
}

bool proxysql_load_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	const std::vector<std::string>& plugin_modules,
	std::string& err
) {
	err.clear();
	manager.reset();
	g_active_plugin_manager = nullptr;

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

	if (!next_manager->init_all(err)) {
		return false;
	}

	manager = std::move(next_manager);
	g_active_plugin_manager = manager.get();
	return true;
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
	if (!manager) {
		g_active_plugin_manager = nullptr;
		return true;
	}

	if (!manager->stop_all()) {
		err = "plugin stop failed";
		return false;
	}

	manager.reset();
	g_active_plugin_manager = nullptr;
	return true;
}
