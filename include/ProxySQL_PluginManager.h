#ifndef PROXYSQL_PLUGIN_MANAGER_H
#define PROXYSQL_PLUGIN_MANAGER_H

#include "ProxySQL_Plugin.h"

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

class ProxySQL_PluginManager {
public:
	ProxySQL_PluginManager();
	~ProxySQL_PluginManager();

	ProxySQL_PluginManager(const ProxySQL_PluginManager &) = delete;
	ProxySQL_PluginManager &operator=(const ProxySQL_PluginManager &) = delete;

	bool load(const std::string &path, std::string &err);
	bool init_all(std::string &err);
	bool start_all(std::string &err);
	bool stop_all();

	size_t size() const;

private:
	struct plugin_handle_t {
		void *handle{nullptr};
		const ProxySQL_PluginDescriptor *descriptor{nullptr};
		bool initialized{false};
		bool started{false};
		bool stopped{false};
	};

	std::vector<plugin_handle_t> plugins_;
	ProxySQL_PluginServices services_;
};

bool proxysql_load_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	const std::vector<std::string>& plugin_modules,
	std::string& err
);
bool proxysql_start_configured_plugins(
	ProxySQL_PluginManager* manager,
	std::string& err
);
bool proxysql_stop_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	std::string& err
);

#endif /* PROXYSQL_PLUGIN_MANAGER_H */
