#ifndef PROXYSQL_PLUGIN_H
#define PROXYSQL_PLUGIN_H

#include <cstdint>
#include <string>

class SQLite3DB;
class SQLite3_result;

enum class ProxySQL_PluginDBKind : uint8_t {
	admin_db = 0,
	config_db = 1,
	stats_db = 2
};

struct ProxySQL_PluginTableDef {
	ProxySQL_PluginDBKind db_kind;
	const char *table_name;
	const char *table_def;
};

struct ProxySQL_PluginCommandContext {
	SQLite3DB *admindb;
	SQLite3DB *configdb;
	SQLite3DB *statsdb;
};

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

using proxysql_plugin_snapshot_cb =
	SQLite3_result *(*)();

using proxysql_plugin_log_message_cb =
	void (*)(int, const char *);

struct ProxySQL_PluginServices {
	proxysql_plugin_register_table_cb register_table;
	proxysql_plugin_register_command_cb register_command;
	proxysql_plugin_snapshot_cb get_mysql_users_snapshot;
	proxysql_plugin_snapshot_cb get_mysql_servers_snapshot;
	proxysql_plugin_snapshot_cb get_mysql_group_replication_hostgroups_snapshot;
	proxysql_plugin_log_message_cb log_message;
};

using proxysql_plugin_init_cb =
	bool (*)(ProxySQL_PluginServices *);

using proxysql_plugin_start_cb =
	bool (*)();

using proxysql_plugin_stop_cb =
	bool (*)();

using proxysql_plugin_status_json_cb =
	const char *(*)();

struct ProxySQL_PluginDescriptor {
	const char *name;
	uint32_t abi_version;
	proxysql_plugin_init_cb init;
	proxysql_plugin_start_cb start;
	proxysql_plugin_stop_cb stop;
	proxysql_plugin_status_json_cb status_json;
};

using proxysql_plugin_descriptor_v1_t = const ProxySQL_PluginDescriptor *(*)();

#endif /* PROXYSQL_PLUGIN_H */
