#include "ProxySQL_PluginManager.h"

#include <cstring>
#include <dlfcn.h>

namespace {

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

} // namespace

ProxySQL_PluginManager::ProxySQL_PluginManager() {
	std::memset(&services_, 0, sizeof(services_));
}

ProxySQL_PluginManager::~ProxySQL_PluginManager() {
	stop_all();
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
		if (!plugin.descriptor->init(&services_)) {
			err = "plugin init failed: " + plugin_name(plugin.descriptor);
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

bool proxysql_load_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	const std::vector<std::string>& plugin_modules,
	std::string& err
) {
	err.clear();
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

	if (!next_manager->init_all(err)) {
		return false;
	}

	manager = std::move(next_manager);
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
		return true;
	}

	if (!manager->stop_all()) {
		err = "plugin stop failed";
		return false;
	}

	manager.reset();
	return true;
}
