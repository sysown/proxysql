#include "mysql_router_admin.h"
#include "mysql_router_plugin.h"

#include "sqlite3db.h"

#include <string>
#include <string_view>

namespace {

struct TableDefinition {
	const char* name;
	const char* ddl;
};

std::string sqlite_quote(std::string_view value) {
	std::string result("'");
	for (char character : value) {
		if (character == '\'') result.push_back('\'');
		result.push_back(character);
	}
	result.push_back('\'');
	return result;
}

const TableDefinition kPersistentTables[] {
	{"mysql_router_config", "CREATE TABLE mysql_router_config (config_key TEXT PRIMARY KEY,config_value TEXT NOT NULL)"},
	{"mysql_router_instance", "CREATE TABLE mysql_router_instance (singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),topology_type TEXT NOT NULL,topology_uuid TEXT NOT NULL,cluster_id TEXT,clusterset_id TEXT,router_id INTEGER NOT NULL,router_name TEXT NOT NULL,router_address TEXT NOT NULL,metadata_user TEXT NOT NULL,metadata_host TEXT NOT NULL,metadata_port INTEGER NOT NULL,metadata_schema TEXT NOT NULL,advertised_version TEXT NOT NULL,topology_generation INTEGER NOT NULL DEFAULT 0,user_generation INTEGER NOT NULL DEFAULT 0)"},
	{"mysql_router_hostgroups", "CREATE TABLE mysql_router_hostgroups (role TEXT NOT NULL,scope_uuid TEXT NOT NULL,hostgroup_id INTEGER NOT NULL UNIQUE,PRIMARY KEY(role,scope_uuid))"},
	{"mysql_router_users", "CREATE TABLE mysql_router_users (username TEXT PRIMARY KEY,source_fingerprint TEXT NOT NULL,auth_plugin TEXT NOT NULL,state TEXT NOT NULL,last_error TEXT NOT NULL DEFAULT '',generation INTEGER NOT NULL)"},
	{"mysql_router_topology_cache", "CREATE TABLE mysql_router_topology_cache (instance_uuid TEXT PRIMARY KEY,topology_uuid TEXT NOT NULL,topology_name TEXT NOT NULL,group_name TEXT NOT NULL,metadata_major INTEGER NOT NULL,metadata_minor INTEGER NOT NULL,metadata_patch INTEGER NOT NULL,label TEXT NOT NULL,endpoint_host TEXT NOT NULL,endpoint_port INTEGER NOT NULL,instance_kind INTEGER NOT NULL,attributes TEXT NOT NULL,read_only_targets INTEGER NOT NULL,quorum_traffic INTEGER NOT NULL,stats_updates_frequency INTEGER,routing_guideline_unsupported INTEGER NOT NULL)"},
	{"mysql_router_bootstrap_journal", "CREATE TABLE mysql_router_bootstrap_journal (topology_uuid TEXT PRIMARY KEY,router_name TEXT NOT NULL,phase TEXT NOT NULL,router_id INTEGER,metadata_user TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL,last_error TEXT NOT NULL DEFAULT '')"},
};

const TableDefinition kRuntimeTables[] {
	{"runtime_mysql_router_status", "CREATE TABLE runtime_mysql_router_status (status_key TEXT PRIMARY KEY,status_value TEXT NOT NULL)"},
	{"runtime_mysql_router_topology", "CREATE TABLE runtime_mysql_router_topology (topology_generation INTEGER NOT NULL,cluster_uuid TEXT NOT NULL,instance_uuid TEXT NOT NULL,endpoint TEXT NOT NULL,instance_kind TEXT NOT NULL,desired_role TEXT NOT NULL,observed_state TEXT NOT NULL,effective_role TEXT NOT NULL,last_observed_at INTEGER NOT NULL,PRIMARY KEY(instance_uuid,endpoint))"},
	{"runtime_mysql_router_hostgroups", "CREATE TABLE runtime_mysql_router_hostgroups (role TEXT NOT NULL,scope_uuid TEXT NOT NULL,hostgroup_id INTEGER NOT NULL,server_count INTEGER NOT NULL,generation INTEGER NOT NULL,PRIMARY KEY(role,scope_uuid))"},
	{"runtime_mysql_router_users", "CREATE TABLE runtime_mysql_router_users (username TEXT PRIMARY KEY,state TEXT NOT NULL,auth_plugin TEXT NOT NULL,last_error TEXT NOT NULL,generation INTEGER NOT NULL)"},
};

const TableDefinition kStatsTables[] {
	{"stats_mysql_router_refresh", "CREATE TABLE stats_mysql_router_refresh (refresh_id INTEGER PRIMARY KEY,started_at INTEGER NOT NULL,completed_at INTEGER NOT NULL,kind TEXT NOT NULL,result TEXT NOT NULL,from_generation INTEGER NOT NULL,to_generation INTEGER NOT NULL,error_code TEXT NOT NULL,error_message TEXT NOT NULL)"},
	{"stats_mysql_router_errors", "CREATE TABLE stats_mysql_router_errors (error_id INTEGER PRIMARY KEY,kind TEXT NOT NULL,code TEXT NOT NULL,message TEXT NOT NULL,occurrence_count INTEGER NOT NULL,first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL)"},
	{"stats_mysql_router_import", "CREATE TABLE stats_mysql_router_import (import_id INTEGER PRIMARY KEY,run_id TEXT NOT NULL,recorded_at INTEGER NOT NULL,source_path TEXT NOT NULL,section_name TEXT NOT NULL,item_name TEXT NOT NULL,outcome TEXT NOT NULL CHECK(outcome IN ('imported','translated','unresolved')),detail TEXT NOT NULL)"},
};

bool replace_empty_projection(SQLite3DB* db, const char* table) {
	if (db == nullptr || table == nullptr) return false;
	const std::string deletion = std::string("DELETE FROM ") + table;
	if (!db->execute("BEGIN")) return false;
	if (!db->execute(deletion.c_str())) {
		db->execute("ROLLBACK");
		return false;
	}
	if (!db->execute("COMMIT")) {
		db->execute("ROLLBACK");
		return false;
	}
	return true;
}

void refresh_status(SQLite3DB* db, void*) {
	if (db == nullptr || !db->execute("BEGIN")) return;
	if (!db->execute("DELETE FROM runtime_mysql_router_status")) {
		db->execute("ROLLBACK");
		return;
	}
	MysqlRouterContext& context = mysql_router_context();
	MysqlRouterStatus status;
	{
		std::lock_guard<std::mutex> guard(context.status_mutex);
		status = context.status;
	}
	const std::string insertion = "INSERT INTO runtime_mysql_router_status(status_key,status_value) VALUES"
		"('plugin','mysql_router'),('runtime_state'," + sqlite_quote(status.state) + "),"
		"('topology_type'," + sqlite_quote(status.topology_type) + "),"
		"('topology_uuid'," + sqlite_quote(status.topology_uuid) + "),"
		"('metadata_version'," + sqlite_quote(status.metadata_version) + "),"
		"('advertised_contract'," + sqlite_quote(status.advertised_contract) + "),"
		"('router_id','" + std::to_string(status.router_id) + "'),"
		"('router_label'," + sqlite_quote(status.router_label) + "),"
		"('metadata_available','" + std::to_string(status.metadata_available ? 1 : 0) + "'),"
		"('registration_exists','" + std::to_string(status.registration_exists ? 1 : 0) + "'),"
		"('gates_ready','" + std::to_string(status.gates_ready ? 1 : 0) + "'),"
		"('unsupported_router_options','" +
			std::to_string(status.unsupported_router_options ? 1 : 0) + "'),"
		"('topology_generation','" + std::to_string(status.topology_generation) + "'),"
		"('user_generation','" + std::to_string(status.user_generation) + "'),"
		"('topology_last_success','" + std::to_string(status.topology_last_success) + "'),"
		"('user_last_success','" + std::to_string(status.user_last_success) + "'),"
		"('metadata_last_success','" + std::to_string(status.metadata_last_success) + "'),"
		"('stale_seconds','" + std::to_string(status.stale_seconds) + "'),"
		"('user_collisions','" + std::to_string(status.user_collisions) + "'),"
		"('unsupported_auth_plugins','" +
			std::to_string(status.unsupported_auth_plugins) + "'),"
		"('last_error'," + sqlite_quote(status.last_error) + ")";
	bool ok = db->execute(insertion.c_str());
	for (const auto& hostgroup : status.managed_hostgroups) {
		const std::string row = "INSERT INTO runtime_mysql_router_status(status_key,status_value) VALUES(" +
			sqlite_quote("hostgroup." + hostgroup.first) + "," +
			sqlite_quote(std::to_string(hostgroup.second)) + ")";
		ok = ok && db->execute(row.c_str());
	}
	if (!ok || !db->execute("COMMIT")) {
		db->execute("ROLLBACK");
	}
}

void refresh_topology(SQLite3DB* db, void*) {
	if (db == nullptr || !db->execute("BEGIN")) return;
	MysqlRouterContext& context = mysql_router_context();
	uint64_t generation = 0;
	std::vector<MysqlRouterRuntimeTopologyRow> rows;
	{
		std::lock_guard<std::mutex> guard(context.status_mutex);
		generation = context.status.topology_generation;
		rows = context.runtime_topology;
	}
	bool ok = db->execute("DELETE FROM runtime_mysql_router_topology");
	for (const auto& value : rows) {
		const std::string insertion = "INSERT INTO runtime_mysql_router_topology"
			"(topology_generation,cluster_uuid,instance_uuid,endpoint,instance_kind,desired_role,"
			"observed_state,effective_role,last_observed_at) VALUES(" +
			std::to_string(generation) + "," + sqlite_quote(value.cluster_uuid) + "," +
			sqlite_quote(value.instance_uuid) + "," + sqlite_quote(value.endpoint) + "," +
			sqlite_quote(value.instance_kind) + "," + sqlite_quote(value.desired_role) + "," +
			sqlite_quote(value.observed_state) + "," + sqlite_quote(value.effective_role) + "," +
			std::to_string(value.last_observed_at) + ")";
		ok = ok && db->execute(insertion.c_str());
	}
	if (!ok || !db->execute("COMMIT")) db->execute("ROLLBACK");
}

void refresh_hostgroups(SQLite3DB* db, void*) {
	if (db == nullptr || !db->execute("BEGIN")) return;
	MysqlRouterContext& context = mysql_router_context();
	uint64_t generation = 0;
	{
		std::lock_guard<std::mutex> guard(context.status_mutex);
		generation = context.status.topology_generation;
	}
	const std::string insertion = "INSERT INTO runtime_mysql_router_hostgroups"
		"(role,scope_uuid,hostgroup_id,server_count,generation) "
		"SELECT role,scope_uuid,hostgroup_id,(SELECT COUNT(*) FROM mysql_servers s "
		"WHERE s.hostgroup_id=h.hostgroup_id)," + std::to_string(generation) +
		" FROM mysql_router_hostgroups h";
	if (!db->execute("DELETE FROM runtime_mysql_router_hostgroups") ||
		!db->execute(insertion.c_str()) || !db->execute("COMMIT")) db->execute("ROLLBACK");
}

void refresh_users(SQLite3DB* db, void*) {
	if (db == nullptr || !db->execute("BEGIN")) return;
	if (!db->execute("DELETE FROM runtime_mysql_router_users") ||
		!db->execute("INSERT INTO runtime_mysql_router_users(username,state,auth_plugin,last_error,generation) "
			"SELECT username,state,auth_plugin,last_error,generation FROM mysql_router_users") ||
		!db->execute("COMMIT")) db->execute("ROLLBACK");
}

ProxySQL_PluginCommandResult load_config(
		const ProxySQL_PluginCommandContext&, const char*) {
	return {0, 0, "mysql_router configuration loaded to runtime"};
}

ProxySQL_PluginCommandResult save_config(
		const ProxySQL_PluginCommandContext&, const char*) {
	return {0, 0, "mysql_router runtime configuration saved to memory"};
}

ProxySQL_PluginCommandResult reconcile(
		const ProxySQL_PluginCommandContext& context, const char* command) {
	return mysql_router_reconcile_command(context, command);
}

void register_table_pair(ProxySQL_PluginServices& services,
		const TableDefinition& table) {
	services.register_table({ProxySQL_PluginDBKind::admin_db, table.name, table.ddl});
	services.register_table({ProxySQL_PluginDBKind::config_db, table.name, table.ddl});
}

} // namespace

bool mysql_router_register_admin_schema(ProxySQL_PluginServices& services) {
	if (services.register_table == nullptr || services.register_command == nullptr ||
		services.register_runtime_view == nullptr) {
		return false;
	}

	for (const auto& table : kPersistentTables) register_table_pair(services, table);
	for (const auto& table : kRuntimeTables) {
		services.register_table({ProxySQL_PluginDBKind::admin_db, table.name, table.ddl});
	}
	for (const auto& table : kStatsTables) {
		services.register_table({ProxySQL_PluginDBKind::stats_db, table.name, table.ddl});
	}

	if (!services.register_runtime_view({"runtime_mysql_router_status", &refresh_status,
			nullptr, ProxySQL_PluginDBKind::admin_db}) ||
		!services.register_runtime_view({"runtime_mysql_router_topology", &refresh_topology,
			nullptr, ProxySQL_PluginDBKind::admin_db}) ||
		!services.register_runtime_view({"runtime_mysql_router_hostgroups", &refresh_hostgroups,
			nullptr, ProxySQL_PluginDBKind::admin_db}) ||
		!services.register_runtime_view({"runtime_mysql_router_users", &refresh_users,
			nullptr, ProxySQL_PluginDBKind::admin_db})) {
		return false;
	}

	services.register_command("LOAD MYSQL ROUTER CONFIG TO RUNTIME", &load_config);
	services.register_command("SAVE MYSQL ROUTER CONFIG FROM RUNTIME", &save_config);
	services.register_command("MYSQL ROUTER RECONCILE", &reconcile);
	return true;
}
