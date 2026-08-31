#include "mysql_router_admin.h"
#include "mysql_router_plugin.h"

#include "sqlite3db.h"

#include <string>

namespace {

struct TableDefinition {
	const char* name;
	const char* ddl;
};

const TableDefinition kPersistentTables[] {
	{"mysql_router_config", "CREATE TABLE mysql_router_config (config_key TEXT PRIMARY KEY,config_value TEXT NOT NULL)"},
	{"mysql_router_instance", "CREATE TABLE mysql_router_instance (singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),topology_type TEXT NOT NULL,topology_uuid TEXT NOT NULL,cluster_id TEXT,clusterset_id TEXT,router_id INTEGER NOT NULL,router_name TEXT NOT NULL,router_address TEXT NOT NULL,metadata_user TEXT NOT NULL,metadata_schema TEXT NOT NULL,advertised_version TEXT NOT NULL,topology_generation INTEGER NOT NULL DEFAULT 0,user_generation INTEGER NOT NULL DEFAULT 0)"},
	{"mysql_router_hostgroups", "CREATE TABLE mysql_router_hostgroups (role TEXT NOT NULL,scope_uuid TEXT NOT NULL,hostgroup_id INTEGER NOT NULL UNIQUE,PRIMARY KEY(role,scope_uuid))"},
	{"mysql_router_users", "CREATE TABLE mysql_router_users (username TEXT PRIMARY KEY,source_fingerprint TEXT NOT NULL,auth_plugin TEXT NOT NULL,state TEXT NOT NULL,last_error TEXT NOT NULL DEFAULT '',generation INTEGER NOT NULL)"},
	{"mysql_router_bootstrap_journal", "CREATE TABLE mysql_router_bootstrap_journal (topology_uuid TEXT PRIMARY KEY,router_name TEXT NOT NULL,phase TEXT NOT NULL,router_id INTEGER,updated_at INTEGER NOT NULL,last_error TEXT NOT NULL DEFAULT '')"},
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
	const char* ready = context.runtime_ready.load() ? "ready" : "not_ready";
	const std::string insertion =
		"INSERT INTO runtime_mysql_router_status(status_key,status_value) VALUES"
		"('plugin','mysql_router'),('runtime_state','" + std::string(ready) + "')";
	if (!db->execute(insertion.c_str()) || !db->execute("COMMIT")) {
		db->execute("ROLLBACK");
	}
}

void refresh_topology(SQLite3DB* db, void*) {
	replace_empty_projection(db, "runtime_mysql_router_topology");
}

void refresh_hostgroups(SQLite3DB* db, void*) {
	replace_empty_projection(db, "runtime_mysql_router_hostgroups");
}

void refresh_users(SQLite3DB* db, void*) {
	replace_empty_projection(db, "runtime_mysql_router_users");
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
		const ProxySQL_PluginCommandContext&, const char*) {
	return {1, 0, "mysql_router is not bootstrapped"};
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
