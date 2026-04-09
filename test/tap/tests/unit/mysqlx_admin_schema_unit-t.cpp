#include "ProxySQL_Plugin.h"
#include "mysqlx_admin_schema.h"
#include "tap.h"
#include "test_init.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace {

std::vector<ProxySQL_PluginTableDef> registered_tables;
std::vector<std::pair<std::string, proxysql_plugin_admin_command_cb>> registered_commands;

void mock_register_table(const ProxySQL_PluginTableDef& def) {
	registered_tables.push_back(def);
}

void mock_register_command(const char* sql, proxysql_plugin_admin_command_cb cb) {
	registered_commands.push_back({sql, cb});
}

bool has_table(const char* name) {
	for (const auto& t : registered_tables) {
		if (t.table_name != nullptr && name != nullptr &&
		    std::strcmp(t.table_name, name) == 0) {
			return true;
		}
	}
	return false;
}

bool has_command_starting_with(const char* prefix) {
	for (const auto& c : registered_commands) {
		if (c.first.compare(0, std::strlen(prefix), prefix) == 0) {
			return true;
		}
	}
	return false;
}

void reset_mocks() {
	registered_tables.clear();
	registered_commands.clear();
}

} // namespace

int main() {
	plan(15);

	reset_mocks();

	{
		ProxySQL_PluginServices null_table_svc {};
		null_table_svc.register_table = nullptr;
		null_table_svc.register_command = &mock_register_command;
		ok(!mysqlx_register_admin_schema(null_table_svc),
		   "mysqlx_register_admin_schema with null register_table returns false");
	}

	{
		ProxySQL_PluginServices null_cmd_svc {};
		null_cmd_svc.register_table = &mock_register_table;
		null_cmd_svc.register_command = nullptr;
		ok(!mysqlx_register_admin_schema(null_cmd_svc),
		   "mysqlx_register_admin_schema with null register_command returns false");
	}

	{
		ProxySQL_PluginServices services {};
		services.register_table = &mock_register_table;
		services.register_command = &mock_register_command;
		ok(mysqlx_register_admin_schema(services),
		   "mysqlx_register_admin_schema with both valid returns true");
	}

	ok(has_table("mysqlx_users"),
	   "registered_tables contains mysqlx_users");
	ok(has_table("runtime_mysqlx_users"),
	   "registered_tables contains runtime_mysqlx_users");
	ok(has_table("mysqlx_routes"),
	   "registered_tables contains mysqlx_routes");
	ok(has_table("runtime_mysqlx_routes"),
	   "registered_tables contains runtime_mysqlx_routes");
	ok(has_table("mysqlx_backend_endpoints"),
	   "registered_tables contains mysqlx_backend_endpoints");
	ok(has_table("runtime_mysqlx_backend_endpoints"),
	   "registered_tables contains runtime_mysqlx_backend_endpoints");
	ok(has_table("stats_mysqlx_routes"),
	   "registered_tables contains stats_mysqlx_routes");
	ok(has_table("stats_mysqlx_processlist"),
	   "registered_tables contains stats_mysqlx_processlist");

	ok(registered_commands.size() == 6,
	   "registered_commands has exactly 6 entries");
	ok(has_command_starting_with("LOAD MYSQLX USERS"),
	   "registered_commands contains command starting with LOAD MYSQLX USERS");
	ok(has_command_starting_with("SAVE MYSQLX USERS"),
	   "registered_commands contains command starting with SAVE MYSQLX USERS");
	ok(has_command_starting_with("LOAD MYSQLX ROUTES"),
	   "registered_commands contains command starting with LOAD MYSQLX ROUTES");

	return exit_status();
}
