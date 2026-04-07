#include "ProxySQL_PluginManager.h"
#include "ProxySQL_Plugin.h"
#include "tap.h"

#include <cstring>

namespace {

ProxySQL_PluginCommandResult fake_plugin_command(const ProxySQL_PluginCommandContext&, const char*) {
	return {0, 7, "mysqlx users loaded"};
}

} // namespace

int main() {
	plan(10);

	ProxySQL_PluginManager mgr;
	char table_name[] = "mysqlx_users";
	char table_def[] = "CREATE TABLE mysqlx_users (username VARCHAR NOT NULL PRIMARY KEY)";
	char duplicate_table_name[] = "mysqlx_users";
	char duplicate_table_def[] = "CREATE TABLE mysqlx_users (username VARCHAR NOT NULL PRIMARY KEY)";
	ProxySQL_PluginTableDef def {
		ProxySQL_PluginDBKind::admin_db,
		table_name,
		table_def
	};
	ProxySQL_PluginTableDef duplicate_def {
		ProxySQL_PluginDBKind::admin_db,
		duplicate_table_name,
		duplicate_table_def
	};

	mgr.register_table_for_test(def);
	table_name[0] = 'X';
	table_def[0] = 'X';

	ok(mgr.tables(ProxySQL_PluginDBKind::admin_db).size() == static_cast<size_t>(1), "plugin admin table is stored");
	ok(std::strcmp(mgr.tables(ProxySQL_PluginDBKind::admin_db).front().table_name, "mysqlx_users") == 0, "plugin admin table name is copied");
	ok(std::strcmp(mgr.tables(ProxySQL_PluginDBKind::admin_db).front().table_def, "CREATE TABLE mysqlx_users (username VARCHAR NOT NULL PRIMARY KEY)") == 0, "plugin admin table definition is copied");
	mgr.register_table_for_test(duplicate_def);
	ok(mgr.tables(ProxySQL_PluginDBKind::admin_db).size() == static_cast<size_t>(1), "duplicate table registration is rejected");
	ok(mgr.tables(ProxySQL_PluginDBKind::config_db).size() == static_cast<size_t>(0), "config tables start empty");
	ok(!mgr.register_command_for_test("SELECT 1"), "unnamespaced admin SQL is rejected");
	ok(mgr.register_command("PLUGIN MYSQLX LOAD USERS TO RUNTIME", &fake_plugin_command), "namespaced command registration succeeds");
	ok(!mgr.register_command("PLUGIN MYSQLX LOAD USERS TO RUNTIME", &fake_plugin_command), "duplicate namespaced command is rejected");
	ok(mgr.has_command_for_test("PLUGIN MYSQLX LOAD USERS TO RUNTIME"), "registered command is discoverable");

	ProxySQL_PluginCommandResult result { 1, 0, "" };
	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };
	ok(mgr.dispatch_admin_command(ctx, "PLUGIN MYSQLX LOAD USERS TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   result.rows_affected == 7 &&
	   result.message == "mysqlx users loaded",
	   "registered command dispatches callback result");

	return exit_status();
}
