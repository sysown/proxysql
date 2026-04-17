#ifndef PROXYSQL_PLUGIN_MANAGER_H
#define PROXYSQL_PLUGIN_MANAGER_H

#include "ProxySQL_Plugin.h"

#include <cstddef>
#include <deque>
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
	bool register_table(const ProxySQL_PluginTableDef& def);
	bool register_command(const char* sql, proxysql_plugin_admin_command_cb cb);
	bool register_query_hook(ProxySQL_PluginProtocol proto, proxysql_plugin_query_hook_cb cb);
	bool has_query_hook(ProxySQL_PluginProtocol proto) const;
	bool dispatch_query_hook(ProxySQL_PluginProtocol proto,
	                         const ProxySQL_PluginQueryHookPayload& payload,
	                         ProxySQL_PluginQueryHookResult& result) const;

	size_t size() const;

private:
	struct plugin_handle_t {
		void *handle{nullptr};
		const ProxySQL_PluginDescriptor *descriptor{nullptr};
		std::string path {};
		bool initialized{false};
		bool started{false};
		bool stopped{false};
	};

	struct registered_command_t {
		std::string sql {};
		proxysql_plugin_admin_command_cb cb { nullptr };
	};

	struct registered_table_storage_t {
		std::string table_name {};
		std::string table_def {};
	};

	std::vector<plugin_handle_t> plugins_;
	ProxySQL_PluginServices services_;
	std::vector<ProxySQL_PluginTableDef> tables_admin_;
	std::vector<ProxySQL_PluginTableDef> tables_config_;
	std::vector<ProxySQL_PluginTableDef> tables_stats_;
	std::deque<registered_table_storage_t> table_storage_;
	std::vector<registered_command_t> commands_;
	// At most one hook per protocol; nullptr means "no hook".
	proxysql_plugin_query_hook_cb mysql_query_hook_ { nullptr };
	proxysql_plugin_query_hook_cb pgsql_query_hook_ { nullptr };
};

ProxySQL_PluginManager* proxysql_get_plugin_manager();
bool proxysql_dispatch_configured_plugin_admin_command(
	const ProxySQL_PluginCommandContext& ctx,
	const std::string& sql,
	ProxySQL_PluginCommandResult& result
);
bool proxysql_dispatch_configured_plugin_query_hook(
	ProxySQL_PluginProtocol proto,
	const ProxySQL_PluginQueryHookPayload& payload,
	ProxySQL_PluginQueryHookResult& result
);
// Fast path for hot code: returns true when the active manager has a hook
// registered for the given protocol.  No locks taken.  Callers should still
// invoke proxysql_dispatch_configured_plugin_query_hook to actually run the
// hook (which takes the manager lock).  Use this to elide the dispatch call
// entirely on the no-plugin path.
bool proxysql_has_configured_plugin_query_hook(ProxySQL_PluginProtocol proto);
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
