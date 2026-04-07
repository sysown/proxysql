#include "ProxySQL_PluginManager.h"
#include "ProxySQL_Plugin.h"
#include "tap.h"

int main() {
	plan(4);

	ProxySQL_PluginManager mgr;
	ProxySQL_PluginTableDef def {
		ProxySQL_PluginDBKind::admin_db,
		"mysqlx_users",
		"CREATE TABLE mysqlx_users (username VARCHAR NOT NULL PRIMARY KEY)"
	};

	mgr.register_table_for_test(def);
	ok(mgr.tables(ProxySQL_PluginDBKind::admin_db).size() == static_cast<size_t>(1), "plugin admin table is stored");
	ok(mgr.tables(ProxySQL_PluginDBKind::config_db).size() == static_cast<size_t>(0), "config tables start empty");
	ok(mgr.register_command_for_test("LOAD MYSQLX USERS TO RUNTIME"), "command registration succeeds");
	ok(mgr.has_command_for_test("LOAD MYSQLX USERS TO RUNTIME"), "registered command is discoverable");

	return exit_status();
}
