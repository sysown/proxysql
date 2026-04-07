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
	const std::vector<ProxySQL_PluginTableDef>& tables(ProxySQL_PluginDBKind kind) const;
	bool dispatch_admin_command(const ProxySQL_PluginCommandContext& ctx, const std::string& sql, ProxySQL_PluginCommandResult& result) const;

	void register_table_for_test(const ProxySQL_PluginTableDef& def);
	bool register_command_for_test(const std::string& sql);
	bool has_command_for_test(const std::string& sql) const;
	void register_table(const ProxySQL_PluginTableDef& def);
	bool register_command(const char* sql, proxysql_plugin_admin_command_cb cb);

	size_t size() const;

private:
	struct plugin_handle_t {
		void *handle{nullptr};
		const ProxySQL_PluginDescriptor *descriptor{nullptr};
		bool initialized{false};
		bool started{false};
		bool stopped{false};
	};

	struct registered_command_t {
		std::string sql {};
		proxysql_plugin_admin_command_cb cb { nullptr };
	};

	std::vector<plugin_handle_t> plugins_;
	ProxySQL_PluginServices services_;
	std::vector<ProxySQL_PluginTableDef> tables_admin_;
	std::vector<ProxySQL_PluginTableDef> tables_config_;
	std::vector<ProxySQL_PluginTableDef> tables_stats_;
	std::vector<registered_command_t> commands_;
};

ProxySQL_PluginManager* proxysql_get_plugin_manager();
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
