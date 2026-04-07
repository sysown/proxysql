#include "ProxySQL_PluginManager.h"
#include "tap.h"

#include <cstring>
#include <string>
#include <vector>

#ifndef PROXYSQL_MYSQLX_PLUGIN_PATH
#define PROXYSQL_MYSQLX_PLUGIN_PATH "../../../plugins/mysqlx/ProxySQL_MySQLX_Plugin.so"
#endif

namespace {

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

} // namespace

int main() {
	plan(6);

	ProxySQL_PluginManager mgr;
	std::string err {};
	const char* plugin_path = PROXYSQL_MYSQLX_PLUGIN_PATH;

	const bool loaded = mgr.load(plugin_path, err);
	ok(loaded, "load mysqlx plugin succeeds");
	if (!loaded) {
		diag("load error: %s", err.c_str());
		BAIL_OUT("mysqlx plugin must load before schema assertions");
	}

	ok(mgr.init_all(err), "init_all registers mysqlx schema");
	if (!err.empty()) {
		diag("init error: %s", err.c_str());
	}

	const ProxySQL_PluginTableDef* admin_table = find_table(
		mgr.tables(ProxySQL_PluginDBKind::admin_db),
		"mysqlx_users"
	);
	const ProxySQL_PluginTableDef* config_table = find_table(
		mgr.tables(ProxySQL_PluginDBKind::config_db),
		"mysqlx_users"
	);

	ok(admin_table != nullptr,
	   "mysqlx_users registered in admin_db");
	ok(config_table != nullptr,
	   "mysqlx_users registered in config_db");
	ok(admin_table != nullptr &&
	   admin_table->table_def != nullptr &&
	   std::strstr(admin_table->table_def, "allowed_auth_methods") != nullptr,
	   "mysqlx_users admin schema includes allowed_auth_methods");
	ok(config_table != nullptr &&
	   config_table->table_def != nullptr &&
	   std::strstr(config_table->table_def, "backend_auth_mode") != nullptr,
	   "mysqlx_users config schema includes backend_auth_mode");

	return exit_status();
}
