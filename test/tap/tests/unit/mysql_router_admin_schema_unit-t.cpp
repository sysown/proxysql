#include "tap.h"

#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"

#include <cstring>
#include <map>
#include <string>

#ifndef PROXYSQL_MYSQL_ROUTER_PLUGIN_PATH
#error "PROXYSQL_MYSQL_ROUTER_PLUGIN_PATH must be defined"
#endif

namespace {

using TableMap = std::map<std::string, std::string>;

const TableMap kPersistentTables {
	{"mysql_router_config", "CREATE TABLE mysql_router_config (config_key TEXT PRIMARY KEY,config_value TEXT NOT NULL)"},
	{"mysql_router_instance", "CREATE TABLE mysql_router_instance (singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),topology_type TEXT NOT NULL,topology_uuid TEXT NOT NULL,cluster_id TEXT,clusterset_id TEXT,router_id INTEGER NOT NULL,router_name TEXT NOT NULL,router_address TEXT NOT NULL,metadata_user TEXT NOT NULL,metadata_host TEXT NOT NULL,metadata_port INTEGER NOT NULL,metadata_schema TEXT NOT NULL,advertised_version TEXT NOT NULL,topology_generation INTEGER NOT NULL DEFAULT 0,user_generation INTEGER NOT NULL DEFAULT 0)"},
	{"mysql_router_hostgroups", "CREATE TABLE mysql_router_hostgroups (role TEXT NOT NULL,scope_uuid TEXT NOT NULL,hostgroup_id INTEGER NOT NULL UNIQUE,PRIMARY KEY(role,scope_uuid))"},
	{"mysql_router_users", "CREATE TABLE mysql_router_users (username TEXT PRIMARY KEY,source_fingerprint TEXT NOT NULL,auth_plugin TEXT NOT NULL,state TEXT NOT NULL,last_error TEXT NOT NULL DEFAULT '',generation INTEGER NOT NULL)"},
	{"mysql_router_topology_cache", "CREATE TABLE mysql_router_topology_cache (instance_uuid TEXT PRIMARY KEY,topology_uuid TEXT NOT NULL,topology_name TEXT NOT NULL,group_name TEXT NOT NULL,metadata_major INTEGER NOT NULL,metadata_minor INTEGER NOT NULL,metadata_patch INTEGER NOT NULL,label TEXT NOT NULL,endpoint_host TEXT NOT NULL,endpoint_port INTEGER NOT NULL,instance_kind INTEGER NOT NULL,attributes TEXT NOT NULL,read_only_targets INTEGER NOT NULL,quorum_traffic INTEGER NOT NULL,stats_updates_frequency INTEGER,routing_guideline_unsupported INTEGER NOT NULL)"},
	{"mysql_router_bootstrap_journal", "CREATE TABLE mysql_router_bootstrap_journal (topology_uuid TEXT PRIMARY KEY,router_name TEXT NOT NULL,phase TEXT NOT NULL,router_id INTEGER,metadata_user TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL,last_error TEXT NOT NULL DEFAULT '')"},
};

const TableMap kRuntimeTables {
	{"runtime_mysql_router_status", "CREATE TABLE runtime_mysql_router_status (status_key TEXT PRIMARY KEY,status_value TEXT NOT NULL)"},
	{"runtime_mysql_router_topology", "CREATE TABLE runtime_mysql_router_topology (topology_generation INTEGER NOT NULL,cluster_uuid TEXT NOT NULL,instance_uuid TEXT NOT NULL,endpoint TEXT NOT NULL,instance_kind TEXT NOT NULL,desired_role TEXT NOT NULL,observed_state TEXT NOT NULL,effective_role TEXT NOT NULL,last_observed_at INTEGER NOT NULL,PRIMARY KEY(instance_uuid,endpoint))"},
	{"runtime_mysql_router_hostgroups", "CREATE TABLE runtime_mysql_router_hostgroups (role TEXT NOT NULL,scope_uuid TEXT NOT NULL,hostgroup_id INTEGER NOT NULL,server_count INTEGER NOT NULL,generation INTEGER NOT NULL,PRIMARY KEY(role,scope_uuid))"},
	{"runtime_mysql_router_users", "CREATE TABLE runtime_mysql_router_users (username TEXT PRIMARY KEY,state TEXT NOT NULL,auth_plugin TEXT NOT NULL,last_error TEXT NOT NULL,generation INTEGER NOT NULL)"},
};

const TableMap kStatsTables {
	{"stats_mysql_router_refresh", "CREATE TABLE stats_mysql_router_refresh (refresh_id INTEGER PRIMARY KEY,started_at INTEGER NOT NULL,completed_at INTEGER NOT NULL,kind TEXT NOT NULL,result TEXT NOT NULL,from_generation INTEGER NOT NULL,to_generation INTEGER NOT NULL,error_code TEXT NOT NULL,error_message TEXT NOT NULL)"},
	{"stats_mysql_router_errors", "CREATE TABLE stats_mysql_router_errors (error_id INTEGER PRIMARY KEY,kind TEXT NOT NULL,code TEXT NOT NULL,message TEXT NOT NULL,occurrence_count INTEGER NOT NULL,first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL)"},
	{"stats_mysql_router_import", "CREATE TABLE stats_mysql_router_import (import_id INTEGER PRIMARY KEY,run_id TEXT NOT NULL,recorded_at INTEGER NOT NULL,source_path TEXT NOT NULL,section_name TEXT NOT NULL,item_name TEXT NOT NULL,outcome TEXT NOT NULL CHECK(outcome IN ('imported','translated','unresolved')),detail TEXT NOT NULL)"},
};

bool has_exact_tables(const std::vector<ProxySQL_PluginTableDef>& actual,
		const TableMap& expected) {
	if (actual.size() != expected.size()) return false;
	for (const auto& table : actual) {
		auto it = expected.find(table.table_name ? table.table_name : "");
		if (it == expected.end() || table.table_def == nullptr || it->second != table.table_def) {
			return false;
		}
	}
	return true;
}

} // namespace

int main() {
	plan(16);

	ProxySQL_PluginManager manager;
	std::string error;
	ok(manager.load(PROXYSQL_MYSQL_ROUTER_PLUGIN_PATH, error),
	   "the schema test loads the real Router plugin: %s", error.c_str());
	ok(manager.invoke_register_schemas_phase(error),
	   "the real Router plugin declares its schemas: %s", error.c_str());

	TableMap expected_admin = kPersistentTables;
	expected_admin.insert(kRuntimeTables.begin(), kRuntimeTables.end());
	ok(has_exact_tables(manager.tables(ProxySQL_PluginDBKind::admin_db), expected_admin),
	   "Admin DB contains the six exact persistent and four exact runtime tables");
	ok(has_exact_tables(manager.tables(ProxySQL_PluginDBKind::config_db), kPersistentTables),
	   "config DB contains the six exact persistent Router tables");
	ok(has_exact_tables(manager.tables(ProxySQL_PluginDBKind::stats_db), kStatsTables),
	   "stats DB contains the three exact Router history tables");

	ok(manager.resolve_alias_to_canonical("LOAD MYSQL ROUTER CONFIG TO RUNTIME") ==
	   "LOAD MYSQL ROUTER CONFIG TO RUNTIME",
	   "LOAD MYSQL ROUTER CONFIG TO RUNTIME is registered exactly");
	ok(manager.resolve_alias_to_canonical("SAVE MYSQL ROUTER CONFIG FROM RUNTIME") ==
	   "SAVE MYSQL ROUTER CONFIG FROM RUNTIME",
	   "SAVE MYSQL ROUTER CONFIG FROM RUNTIME is registered exactly");
	ok(manager.resolve_alias_to_canonical("MYSQL ROUTER RECONCILE") ==
	   "MYSQL ROUTER RECONCILE",
	   "MYSQL ROUTER RECONCILE is registered exactly");
	ok(manager.resolve_alias_to_canonical("SELECT 1").empty(),
	   "unrelated Admin SQL remains unclaimed");
	ProxySQL_PluginCommandResult load_result {};
	ProxySQL_PluginCommandContext command_context {};
	ok(manager.dispatch_admin_command(command_context,
	   "LOAD MYSQL ROUTER CONFIG TO RUNTIME", load_result) &&
	   load_result.error_code != 0 && load_result.message.find("not implemented") !=
	   std::string::npos,
	   "the scaffold LOAD command reports an explicit error instead of false success");
	ProxySQL_PluginCommandResult save_result {};
	ok(manager.dispatch_admin_command(command_context,
	   "SAVE MYSQL ROUTER CONFIG FROM RUNTIME", save_result) &&
	   save_result.error_code != 0 && save_result.message.find("not implemented") !=
	   std::string::npos,
	   "the scaffold SAVE command reports an explicit error instead of false success");

	SQLite3DB admindb;
	admindb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	bool materialized = true;
	for (const auto& table : manager.tables(ProxySQL_PluginDBKind::admin_db)) {
		materialized = materialized && admindb.execute(table.table_def);
	}
	ok(materialized, "the declared Router Admin schema materializes in SQLite");
	manager.refresh_runtime_views_for_query(
		"SELECT * FROM runtime_mysql_router_status", &admindb, nullptr, nullptr);
	ok(admindb.return_one_int("SELECT COUNT(*) FROM runtime_mysql_router_status") >= 20 &&
	   admindb.return_one_int("SELECT COUNT(*) FROM runtime_mysql_router_status "
		   "WHERE status_key='advertised_contract' AND status_value='8.4.0'") == 1,
	   "the status projection publishes the complete Router observability contract");
	manager.refresh_runtime_views_for_query(
		"SELECT * FROM runtime_mysql_router_topology", &admindb, nullptr, nullptr);
	ok(admindb.return_one_int("SELECT COUNT(*) FROM runtime_mysql_router_topology") == 0,
	   "the topology projection does not invent unknown cached health rows");
	admindb.execute("INSERT INTO mysql_router_users(username,source_fingerprint,auth_plugin,state,last_error,generation) "
		"VALUES('app','fingerprint','caching_sha2_password','active','',7)");
	manager.refresh_runtime_views_for_query(
		"SELECT * FROM runtime_mysql_router_users", &admindb, nullptr, nullptr);
	ok(admindb.return_one_int("SELECT COUNT(*) FROM runtime_mysql_router_users "
		"WHERE username='app' AND generation=7") == 1,
	   "the managed-user runtime projection carries exact persisted state");
	ok(manager.stop_all(), "schema-only manager teardown is clean");

	return exit_status();
}
