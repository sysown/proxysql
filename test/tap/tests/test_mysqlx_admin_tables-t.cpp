#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"
#include "tap.h"
#include "test_init.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#ifndef PROXYSQL_MYSQLX_PLUGIN_PATH
#error "PROXYSQL_MYSQLX_PLUGIN_PATH must be defined"
#endif

namespace {

SQLite3DB* g_admin_db = nullptr;
SQLite3DB* g_config_db = nullptr;
SQLite3DB* g_stats_db = nullptr;

const ProxySQL_PluginTableDef* find_table(
	const std::vector<ProxySQL_PluginTableDef>& tables,
	const char* name
) {
	for (const auto& table : tables) {
		if (table.table_name != nullptr &&
		    name != nullptr &&
		    std::strcmp(table.table_name, name) == 0) {
			return &table;
		}
	}
	return nullptr;
}

bool build_registered_tables(SQLite3DB& db, const std::vector<ProxySQL_PluginTableDef>& tables) {
	for (const auto& table : tables) {
		if (table.table_name == nullptr || table.table_def == nullptr) {
			return false;
		}
		if (!db.check_and_build_table(const_cast<char*>(table.table_name),
		                              const_cast<char*>(table.table_def))) {
			return false;
		}
	}
	return true;
}

std::string select_string(SQLite3DB& db, const char* sql) {
	char* error = nullptr;
	std::unique_ptr<SQLite3_result> result { db.execute_statement(sql, &error) };
	std::string value {};
	if (error == nullptr &&
	    result != nullptr &&
	    result->rows_count > 0 &&
	    !result->rows.empty() &&
	    result->rows[0] != nullptr &&
	    result->rows[0]->fields[0] != nullptr) {
		value = result->rows[0]->fields[0];
	}
	if (error != nullptr) {
		free(error);
	}
	return value;
}

} // namespace

SQLite3DB* proxysql_plugin_get_admindb() {
	return g_admin_db;
}

SQLite3DB* proxysql_plugin_get_configdb() {
	return g_config_db;
}

SQLite3DB* proxysql_plugin_get_statsdb() {
	return g_stats_db;
}

int main() {
	plan(42);

	ok(test_init_minimal() == 0, "minimal test globals initialize");

	SQLite3DB admin_db {};
	SQLite3DB config_db {};
	SQLite3DB stats_db {};
	ok(admin_db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX) == 0,
	   "admin sqlite opens");
	ok(config_db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX) == 0,
	   "config sqlite opens");
	ok(stats_db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX) == 0,
	   "stats sqlite opens");

	g_admin_db = &admin_db;
	g_config_db = &config_db;
	g_stats_db = &stats_db;

	ProxySQL_PluginManager mgr;
	std::string err {};

	const bool loaded = mgr.load(PROXYSQL_MYSQLX_PLUGIN_PATH, err);
	ok(loaded, "mysqlx plugin loads for admin table test");
	if (!loaded) {
		diag("load error: %s", err.c_str());
		BAIL_OUT("mysqlx plugin must load before admin table assertions");
	}

	ok(mgr.init_all(err), "mysqlx plugin init registers schema and commands");
	if (!err.empty()) {
		diag("init error: %s", err.c_str());
	}

	const auto& admin_tables = mgr.tables(ProxySQL_PluginDBKind::admin_db);
	const auto& config_tables = mgr.tables(ProxySQL_PluginDBKind::config_db);
	const ProxySQL_PluginTableDef* mysqlx_users = find_table(admin_tables, "mysqlx_users");
	const ProxySQL_PluginTableDef* runtime_mysqlx_users = find_table(admin_tables, "runtime_mysqlx_users");
	const ProxySQL_PluginTableDef* mysqlx_routes = find_table(admin_tables, "mysqlx_routes");
	const ProxySQL_PluginTableDef* runtime_mysqlx_routes = find_table(admin_tables, "runtime_mysqlx_routes");
	const ProxySQL_PluginTableDef* mysqlx_backend_endpoints = find_table(admin_tables, "mysqlx_backend_endpoints");
	const ProxySQL_PluginTableDef* runtime_mysqlx_backend_endpoints = find_table(admin_tables, "runtime_mysqlx_backend_endpoints");

	ok(mysqlx_users != nullptr, "mysqlx_users is registered in admin_db");
	ok(runtime_mysqlx_users != nullptr, "runtime_mysqlx_users is registered in admin_db");
	ok(mysqlx_routes != nullptr, "mysqlx_routes is registered in admin_db");
	ok(runtime_mysqlx_routes != nullptr, "runtime_mysqlx_routes is registered in admin_db");
	ok(mysqlx_backend_endpoints != nullptr, "mysqlx_backend_endpoints is registered in admin_db");
	ok(runtime_mysqlx_backend_endpoints != nullptr, "runtime_mysqlx_backend_endpoints is registered in admin_db");

	if (runtime_mysqlx_users == nullptr ||
	    runtime_mysqlx_routes == nullptr ||
	    runtime_mysqlx_backend_endpoints == nullptr) {
		BAIL_OUT("mysqlx runtime tables must exist before load-to-runtime behavior can be verified");
	}

	ok(build_registered_tables(admin_db, admin_tables), "registered admin tables materialize in sqlite");
	ok(build_registered_tables(config_db, config_tables), "registered config tables materialize in sqlite");

	ok(admin_db.execute("INSERT INTO mysqlx_users (username, active, allowed_auth_methods, default_route, backend_auth_mode, attributes, comment) "
	                    "VALUES ('alice', 1, 'PLAIN', 'rw', 'pass_through', '', 'frontend user')"),
	   "seed mysqlx_users row");
	ok(admin_db.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active, comment) "
	                    "VALUES ('rw', '127.0.0.1:6603', 42, 43, 'first_available', 1, 'route row')"),
	   "seed mysqlx_routes row");
	ok(admin_db.execute("INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port, comment) "
	                    "VALUES ('db1.internal', 3306, 33060, 'endpoint row')"),
	   "seed mysqlx_backend_endpoints row");

	ProxySQL_PluginCommandContext ctx { &admin_db, &config_db, &stats_db };
	ProxySQL_PluginCommandResult result { 1, 0, "" };

	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_users") == 1 &&
	   select_string(admin_db, "SELECT backend_auth_mode FROM runtime_mysqlx_users WHERE username='alice'") == "pass_through",
	   "LOAD MYSQLX USERS TO RUNTIME copies mysqlx user rows");
	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX ROUTES TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_routes") == 1 &&
	   admin_db.return_one_int("SELECT destination_hostgroup FROM runtime_mysqlx_routes WHERE name='rw'") == 42,
	   "LOAD MYSQLX ROUTES TO RUNTIME copies route rows");
	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_backend_endpoints") == 1 &&
	   admin_db.return_one_int("SELECT mysqlx_port FROM runtime_mysqlx_backend_endpoints WHERE hostname='db1.internal' AND mysql_port=3306") == 33060,
	   "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME copies endpoint rows");

	ok(mgr.dispatch_admin_command(ctx, "SAVE MYSQLX USERS TO MEMORY", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_users") == 1,
	   "SAVE MYSQLX USERS TO MEMORY copies runtime rows back to config");
	ok(mgr.dispatch_admin_command(ctx, "SAVE MYSQLX ROUTES TO MEMORY", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_routes") == 1,
	   "SAVE MYSQLX ROUTES TO MEMORY copies runtime rows back to config");
	ok(mgr.dispatch_admin_command(ctx, "SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_backend_endpoints") == 1,
	   "SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY copies runtime rows back to config");

	// ---- LOAD edge cases (7) ----

	{
		SQLite3DB fresh_admin {};
		SQLite3DB fresh_config {};
		SQLite3DB fresh_stats {};
		fresh_admin.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		fresh_config.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		fresh_stats.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		build_registered_tables(fresh_admin, admin_tables);
		build_registered_tables(fresh_config, config_tables);
		ProxySQL_PluginCommandContext fresh_ctx { &fresh_admin, &fresh_config, &fresh_stats };
		ProxySQL_PluginCommandResult fresh_result { 1, 0, "" };
		ok(mgr.dispatch_admin_command(fresh_ctx, "LOAD MYSQLX USERS TO RUNTIME", fresh_result) &&
		   fresh_result.error_code == 0 &&
		   fresh_admin.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_users") == 0,
		   "LOAD MYSQLX USERS TO RUNTIME with empty config table — runtime has 0 rows, error_code==0");
		ok(mgr.dispatch_admin_command(fresh_ctx, "LOAD MYSQLX ROUTES TO RUNTIME", fresh_result) &&
		   fresh_result.error_code == 0 &&
		   fresh_admin.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_routes") == 0,
		   "LOAD MYSQLX ROUTES TO RUNTIME with empty config table — runtime has 0 rows, error_code==0");
		ok(mgr.dispatch_admin_command(fresh_ctx, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", fresh_result) &&
		   fresh_result.error_code == 0 &&
		   fresh_admin.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_backend_endpoints") == 0,
		   "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME with empty config table — runtime has 0 rows, error_code==0");
	}

	admin_db.execute("INSERT INTO mysqlx_users (username, active, allowed_auth_methods, default_route, backend_auth_mode, attributes, comment) "
	                 "VALUES ('bob', 1, 'MYSQL41', 'ro', 'mapped', '', 'second user')");
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result);
	ok(result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_users") == 2,
	   "LOAD twice — second LOAD replaces runtime data (count is 2 not 1+2=3)");

	admin_db.execute("UPDATE mysqlx_users SET backend_auth_mode='native' WHERE username='alice'");
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result);
	ok(result.error_code == 0 &&
	   select_string(admin_db, "SELECT backend_auth_mode FROM runtime_mysqlx_users WHERE username='alice'") == "native",
	   "LOAD after modifying config — runtime reflects new value");

	{
		ProxySQL_PluginCommandContext null_ctx { nullptr, &config_db, &stats_db };
		ProxySQL_PluginCommandResult null_result { 0, 0, "" };
		mgr.dispatch_admin_command(null_ctx, "LOAD MYSQLX USERS TO RUNTIME", null_result);
		ok(null_result.error_code != 0,
		   "LOAD with null admindb in context — returns error_code != 0");
	}

	{
		SQLite3DB multi_admin {};
		SQLite3DB multi_config {};
		SQLite3DB multi_stats {};
		multi_admin.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		multi_config.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		multi_stats.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		build_registered_tables(multi_admin, admin_tables);
		build_registered_tables(multi_config, config_tables);
		multi_admin.execute("INSERT INTO mysqlx_users (username, active, allowed_auth_methods, backend_auth_mode, attributes, comment) "
		                    "VALUES ('u1', 1, 'PLAIN', 'mapped', '', '')");
		multi_admin.execute("INSERT INTO mysqlx_users (username, active, allowed_auth_methods, backend_auth_mode, attributes, comment) "
		                    "VALUES ('u2', 1, 'MYSQL41', 'mapped', '', '')");
		multi_admin.execute("INSERT INTO mysqlx_users (username, active, allowed_auth_methods, backend_auth_mode, attributes, comment) "
		                    "VALUES ('u3', 1, 'PLAIN', 'native', '', '')");
		ProxySQL_PluginCommandContext multi_ctx { &multi_admin, &multi_config, &multi_stats };
		ProxySQL_PluginCommandResult multi_result { 1, 0, "" };
		ok(mgr.dispatch_admin_command(multi_ctx, "LOAD MYSQLX USERS TO RUNTIME", multi_result) &&
		   multi_result.error_code == 0 &&
		   multi_admin.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_users") == 3,
		   "LOAD with multiple rows — seed 3 rows, LOAD, verify runtime count == 3");
	}

	// ---- SAVE data integrity (4) ----

	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result);
	admin_db.execute("UPDATE runtime_mysqlx_users SET backend_auth_mode='sha256' WHERE username='alice'");
	mgr.dispatch_admin_command(ctx, "SAVE MYSQLX USERS TO MEMORY", result);
	ok(result.error_code == 0 &&
	   select_string(admin_db, "SELECT backend_auth_mode FROM mysqlx_users WHERE username='alice'") == "sha256",
	   "SAVE after modifying runtime row — config table reflects modified value");

	admin_db.execute("DELETE FROM mysqlx_routes");
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX ROUTES TO RUNTIME", result);
	admin_db.execute("INSERT INTO runtime_mysqlx_routes (name, bind, destination_hostgroup, strategy, active, comment) "
	                 "VALUES ('ro', '127.0.0.1:6604', 44, 'round_robin', 1, 'new route')");
	mgr.dispatch_admin_command(ctx, "SAVE MYSQLX ROUTES TO MEMORY", result);
	ok(result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_routes") >= 1 &&
	   select_string(admin_db, "SELECT name FROM mysqlx_routes WHERE name='ro'") == "ro",
	   "SAVE after INSERT into runtime — config table has the new row");

	{
		SQLite3DB empty_admin {};
		SQLite3DB empty_config {};
		SQLite3DB empty_stats {};
		empty_admin.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		empty_config.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		empty_stats.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		build_registered_tables(empty_admin, admin_tables);
		build_registered_tables(empty_config, config_tables);
		empty_admin.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active, comment) "
		                    "VALUES ('x', '0.0.0.0:1', 1, 'first_available', 1, 'temp')");
		ProxySQL_PluginCommandContext empty_ctx { &empty_admin, &empty_config, &empty_stats };
		ProxySQL_PluginCommandResult empty_result { 1, 0, "" };
		mgr.dispatch_admin_command(empty_ctx, "LOAD MYSQLX ROUTES TO RUNTIME", empty_result);
		empty_admin.execute("DELETE FROM runtime_mysqlx_routes");
		mgr.dispatch_admin_command(empty_ctx, "SAVE MYSQLX ROUTES TO MEMORY", empty_result);
		ok(empty_result.error_code == 0 &&
		   empty_admin.return_one_int("SELECT COUNT(*) FROM mysqlx_routes") == 0,
		   "SAVE with empty runtime table — config table becomes empty (count=0)");
	}

	{
		SQLite3DB rt_admin {};
		SQLite3DB rt_config {};
		SQLite3DB rt_stats {};
		rt_admin.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		rt_config.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		rt_stats.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		build_registered_tables(rt_admin, admin_tables);
		build_registered_tables(rt_config, config_tables);
		rt_admin.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active, comment) "
		                 "VALUES ('rt1', '0.0.0.0:3307', 10, 'first_available', 1, 'rt test')");
		ProxySQL_PluginCommandContext rt_ctx { &rt_admin, &rt_config, &rt_stats };
		ProxySQL_PluginCommandResult rt_result { 1, 0, "" };
		mgr.dispatch_admin_command(rt_ctx, "LOAD MYSQLX ROUTES TO RUNTIME", rt_result);
		mgr.dispatch_admin_command(rt_ctx, "SAVE MYSQLX ROUTES TO MEMORY", rt_result);
		rt_admin.execute("DELETE FROM mysqlx_routes");
		rt_admin.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active, comment) "
		                 "VALUES ('rt2', '0.0.0.0:3308', 20, 'round_robin', 0, 'changed')");
		mgr.dispatch_admin_command(rt_ctx, "LOAD MYSQLX ROUTES TO RUNTIME", rt_result);
		ok(rt_result.error_code == 0 &&
		   rt_admin.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_routes") == 1 &&
		   select_string(rt_admin, "SELECT name FROM runtime_mysqlx_routes") == "rt2",
		   "SAVE then LOAD roundtrip — SAVE, change config, LOAD, runtime matches re-loaded data");
	}

	// ---- Alias dispatch (8) ----

	ok(mgr.dispatch_admin_command(ctx, "load mysqlx users to runtime", result) &&
	   result.error_code == 0,
	   "lowercase 'load mysqlx users to runtime' dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "LOAD  MYSQLX  USERS  TO  RUNTIME", result) &&
	   result.error_code == 0,
	   "extra whitespace 'LOAD  MYSQLX  USERS  TO  RUNTIME' dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, " load mysqlx users to runtime ", result) &&
	   result.error_code == 0,
	   "leading/trailing whitespace dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "save mysqlx users to memory", result) &&
	   result.error_code == 0,
	   "lowercase 'save mysqlx users to memory' dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX ROUTES TO RUNTIME", result) &&
	   result.error_code == 0,
	   "LOAD MYSQLX ROUTES TO RUNTIME dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "load mysqlx routes to runtime", result) &&
	   result.error_code == 0,
	   "lowercase 'load mysqlx routes to runtime' dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", result) &&
	   result.error_code == 0,
	   "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "save  mysqlx  backend  endpoints  to  memory", result) &&
	   result.error_code == 0,
	   "whitespace-normalized 'save mysqlx backend endpoints to memory' dispatches correctly");

	g_admin_db = nullptr;
	g_config_db = nullptr;
	g_stats_db = nullptr;
	test_cleanup_minimal();
	return exit_status();
}
