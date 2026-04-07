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
	plan(20);

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

	ok(mgr.dispatch_admin_command(ctx, "PLUGIN MYSQLX LOAD USERS TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_users") == 1 &&
	   select_string(admin_db, "SELECT backend_auth_mode FROM runtime_mysqlx_users WHERE username='alice'") == "pass_through",
	   "PLUGIN MYSQLX LOAD USERS TO RUNTIME copies mysqlx user rows");
	ok(mgr.dispatch_admin_command(ctx, "PLUGIN MYSQLX LOAD ROUTES TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_routes") == 1 &&
	   admin_db.return_one_int("SELECT destination_hostgroup FROM runtime_mysqlx_routes WHERE name='rw'") == 42,
	   "PLUGIN MYSQLX LOAD ROUTES TO RUNTIME copies route rows");
	ok(mgr.dispatch_admin_command(ctx, "PLUGIN MYSQLX LOAD BACKEND ENDPOINTS TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_backend_endpoints") == 1 &&
	   admin_db.return_one_int("SELECT mysqlx_port FROM runtime_mysqlx_backend_endpoints WHERE hostname='db1.internal' AND mysql_port=3306") == 33060,
	   "PLUGIN MYSQLX LOAD BACKEND ENDPOINTS TO RUNTIME copies endpoint rows");

	g_admin_db = nullptr;
	g_config_db = nullptr;
	g_stats_db = nullptr;
	test_cleanup_minimal();
	return exit_status();
}
