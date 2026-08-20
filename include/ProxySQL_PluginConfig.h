#ifndef PROXYSQL_PLUGIN_CONFIG_H
#define PROXYSQL_PLUGIN_CONFIG_H

#ifdef PROXYSQL40

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class SQLite3DB;
class SQLite3_result;

struct ProxySQL_PluginMysqlServerRow {
	int hostgroup_id;
	const char* hostname;
	uint16_t port;
	uint16_t gtid_port;
	int status;
	int weight;
	int compression;
	int max_connections;
	int max_replication_lag;
	bool use_ssl;
	unsigned int max_latency_ms;
	const char* comment;
};

struct ProxySQL_PluginMysqlUserRow {
	const char* username;
	const char* password;
	bool active;
	bool use_ssl;
	int default_hostgroup;
	const char* default_schema;
	bool schema_locked;
	bool transaction_persistent;
	bool fast_forward;
	bool frontend;
	bool backend;
	int max_connections;
	const char* attributes;
	const char* comment;
};

struct ProxySQL_PluginMysqlRuleRow {
	int rule_id;
	bool active;
	int proxy_port;
	const char* match_digest;
	const char* match_pattern;
	bool negate_match_pattern;
	const char* re_modifiers;
	int destination_hostgroup;
	bool apply;
	const char* comment;
};

struct ProxySQL_PluginMysqlReplicationHostgroupRow {
	int writer_hostgroup;
	int reader_hostgroup;
	const char* check_type;
	const char* comment;
};

struct ProxySQL_PluginMysqlGroupReplicationHostgroupRow {
	int writer_hostgroup;
	int backup_writer_hostgroup;
	int reader_hostgroup;
	int offline_hostgroup;
	bool active;
	int max_writers;
	int writer_is_also_reader;
	int max_transactions_behind;
	const char* comment;
};

struct ProxySQL_PluginMysqlHostgroupAttributesRow {
	int hostgroup_id;
	int max_num_online_servers;
	int autocommit;
	int free_connections_pct;
	const char* init_connect;
	bool multiplex;
	bool connection_warming;
	int throttle_connections_per_sec;
	const char* ignore_session_variables;
	const char* hostgroup_settings;
	const char* servers_defaults;
	const char* comment;
};

struct ProxySQL_PluginMysqlConfigPlan {
	const char* owner;
	uint64_t generation;
	const int* owned_hostgroups;
	size_t owned_hostgroup_count;
	const ProxySQL_PluginMysqlServerRow* servers;
	size_t server_count;
	const ProxySQL_PluginMysqlReplicationHostgroupRow* replication_hostgroups;
	size_t replication_hostgroup_count;
	const ProxySQL_PluginMysqlGroupReplicationHostgroupRow* group_replication_hostgroups;
	size_t group_replication_hostgroup_count;
	const ProxySQL_PluginMysqlHostgroupAttributesRow* hostgroup_attributes;
	size_t hostgroup_attribute_count;
	const ProxySQL_PluginMysqlUserRow* users;
	size_t user_count;
	const ProxySQL_PluginMysqlRuleRow* rules;
	size_t rule_count;
	const char* const* interfaces;
	size_t interface_count;
};

struct ProxySQL_PluginMysqlConfigResult {
	bool applied {false};
	uint64_t generation {0};
	std::string message;
	std::vector<std::string> collisions;
};

enum class ProxySQL_PluginConfigLock : uint8_t {
	admin = 1,
	hostgroups = 2,
	auth = 3,
	query_processor = 4,
	mysql_threads = 5,
};

enum class ProxySQL_PluginConfigStage : uint8_t {
	none = 0,
	admin_staging = 1,
	servers = 2,
	users = 3,
	rules = 4,
	interfaces = 5,
	commit = 6,
};

// Runtime snapshots are owned by the caller. Each non-null result is deleted
// by this object's destructor. The result sets contain complete module state,
// captured while the corresponding runtime locks are held.
struct ProxySQL_PluginMysqlRuntimeSnapshot {
	SQLite3_result* servers {nullptr};
	SQLite3_result* replication_hostgroups {nullptr};
	SQLite3_result* group_replication_hostgroups {nullptr};
	SQLite3_result* hostgroup_attributes {nullptr};
	SQLite3_result* users {nullptr};
	SQLite3_result* rules {nullptr};
	SQLite3_result* fast_routing_rules {nullptr};
	std::string interfaces;

	ProxySQL_PluginMysqlRuntimeSnapshot() = default;
	~ProxySQL_PluginMysqlRuntimeSnapshot();
	ProxySQL_PluginMysqlRuntimeSnapshot(const ProxySQL_PluginMysqlRuntimeSnapshot&) = delete;
	ProxySQL_PluginMysqlRuntimeSnapshot& operator=(const ProxySQL_PluginMysqlRuntimeSnapshot&) = delete;
};

// Core-private publication seam. ProxySQL_Admin supplies live callbacks;
// tests supply deterministic callbacks with failure injection. The publisher
// itself owns lock ordering, transaction ordering, and reverse restoration.
struct ProxySQL_PluginConfigRuntimeHooks {
	void* opaque {nullptr};
	bool (*lock)(void*, ProxySQL_PluginConfigLock, std::string&) {nullptr};
	void (*unlock)(void*, ProxySQL_PluginConfigLock) {nullptr};
	bool (*capture)(void*, ProxySQL_PluginMysqlRuntimeSnapshot&, std::string&) {nullptr};
	bool (*publish)(void*, ProxySQL_PluginConfigStage, SQLite3DB&, uint64_t, std::string&) {nullptr};
	void (*restore)(void*, ProxySQL_PluginConfigStage, const ProxySQL_PluginMysqlRuntimeSnapshot&) {nullptr};
	bool (*checkpoint)(void*, ProxySQL_PluginConfigStage, std::string&) {nullptr};
};

constexpr const char* PROXYSQL_PLUGIN_OWNED_OBJECTS_DDL =
	"CREATE TABLE IF NOT EXISTS proxysql_plugin_owned_objects ("
	"owner TEXT NOT NULL, object_type TEXT NOT NULL CHECK(object_type IN "
	"('hostgroup','mysql_user','mysql_query_rule','mysql_interface')), "
	"object_key TEXT NOT NULL, generation INTEGER NOT NULL, "
	"PRIMARY KEY(owner, object_type, object_key))";

constexpr const char* PROXYSQL_PLUGIN_CONFIG_GENERATIONS_DDL =
	"CREATE TABLE IF NOT EXISTS proxysql_plugin_config_generations ("
	"owner TEXT NOT NULL PRIMARY KEY, generation INTEGER NOT NULL)";

bool proxysql_ensure_plugin_mysql_config_schema(SQLite3DB& db, const char* schema = "main");
ProxySQL_PluginMysqlConfigResult proxysql_apply_plugin_mysql_config(
	SQLite3DB& admindb,
	const ProxySQL_PluginMysqlConfigPlan& plan,
	const ProxySQL_PluginConfigRuntimeHooks& runtime);

#endif /* PROXYSQL40 */
#endif /* PROXYSQL_PLUGIN_CONFIG_H */
