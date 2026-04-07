#ifndef PROXYSQL_PLUGIN_H
#define PROXYSQL_PLUGIN_H

#include <cstdint>
#include <string>
#include <vector>

enum ProxySQL_PluginDBKind {
	admin_db,
	config_db,
	stats_db,
};

struct ProxySQL_PluginTableDef {
	ProxySQL_PluginDBKind db_kind{admin_db};
	const char *schema_name{nullptr};
	const char *table_name{nullptr};
	const char *create_statement{nullptr};
};

struct ProxySQL_PluginCommandContext {
	const char *command_name{nullptr};
	std::vector<std::string> arguments;
};

struct ProxySQL_PluginCommandResult {
	bool success{true};
	std::string message;
	std::vector<std::vector<std::string>> rows;
};

class ProxySQL_PluginServices;

using proxysql_plugin_admin_command_cb =
	bool (*)(const ProxySQL_PluginCommandContext &, ProxySQL_PluginCommandResult &, void *);

using proxysql_plugin_register_table_cb =
	bool (*)(void *, const ProxySQL_PluginTableDef &);

using proxysql_plugin_register_command_cb =
	bool (*)(void *, const char *, proxysql_plugin_admin_command_cb, void *);

using proxysql_plugin_snapshot_cb =
	bool (*)(void *, std::vector<std::vector<std::string>> &);

using proxysql_plugin_log_message_cb =
	void (*)(void *, int, const char *);

struct ProxySQL_PluginServices {
	proxysql_plugin_register_table_cb register_table{nullptr};
	proxysql_plugin_register_command_cb register_command{nullptr};
	proxysql_plugin_snapshot_cb get_mysql_users_snapshot{nullptr};
	proxysql_plugin_snapshot_cb get_mysql_servers_snapshot{nullptr};
	proxysql_plugin_snapshot_cb get_mysql_group_replication_hostgroups_snapshot{nullptr};
	proxysql_plugin_log_message_cb log_message{nullptr};
	void *context{nullptr};
};

using proxysql_plugin_init_cb =
	bool (*)(ProxySQL_PluginServices *, std::string &);

using proxysql_plugin_start_cb =
	bool (*)(std::string &);

using proxysql_plugin_stop_cb =
	bool (*)();

using proxysql_plugin_status_cb =
	bool (*)(std::string &);

struct ProxySQL_PluginDescriptor {
	uint32_t abi_version{0};
	const char *name{nullptr};
	proxysql_plugin_init_cb init{nullptr};
	proxysql_plugin_start_cb start{nullptr};
	proxysql_plugin_stop_cb stop{nullptr};
	proxysql_plugin_status_cb status{nullptr};
};

using proxysql_plugin_descriptor_v1_t = const ProxySQL_PluginDescriptor *(*)();

#endif /* PROXYSQL_PLUGIN_H */
