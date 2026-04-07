#include "ProxySQL_PluginManager.h"
#include "tap.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

bool has_table(const std::vector<ProxySQL_PluginTableDef>& tables, const char* name) {
	for (const auto& table : tables) {
		if (table.table_name != nullptr &&
		    name != nullptr &&
		    std::strcmp(table.table_name, name) == 0) {
			return true;
		}
	}
	return false;
}

} // namespace

int main() {
	plan(4);

	ProxySQL_PluginManager mgr;
	std::string err {};
	const char* plugin_path = "../../../plugins/mysqlx/ProxySQL_MySQLX_Plugin.so";

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

	ok(has_table(mgr.tables(ProxySQL_PluginDBKind::admin_db), "mysqlx_users"),
	   "mysqlx_users registered in admin_db");
	ok(has_table(mgr.tables(ProxySQL_PluginDBKind::config_db), "mysqlx_users"),
	   "mysqlx_users registered in config_db");

	return exit_status();
}
