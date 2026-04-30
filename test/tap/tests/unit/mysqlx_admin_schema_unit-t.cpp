#include "ProxySQL_Plugin.h"
#include "mysqlx_admin_schema.h"
#include "mysqlx_config_store.h"
#include "tap.h"
#include "test_init.h"

#include <algorithm>
#include <cstring>
#include <memory>
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

struct MysqlxPluginContext {
	ProxySQL_PluginServices* services { nullptr };
	std::unique_ptr<MysqlxConfigStore> config_store {};
	bool started { false };
};

MysqlxPluginContext& mysqlx_context() {
	static MysqlxPluginContext ctx {};
	return ctx;
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(25);
	diag("=== mysqlx_admin_schema_unit-t starting ===");

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
	ok(has_table("mysqlx_variables"),
	   "registered_tables contains mysqlx_variables");
	ok(has_table("runtime_mysqlx_variables"),
	   "registered_tables contains runtime_mysqlx_variables");
	ok(has_table("stats_mysqlx_routes"),
	   "registered_tables contains stats_mysqlx_routes");
	ok(has_table("stats_mysqlx_processlist"),
	   "registered_tables contains stats_mysqlx_processlist");

	ok(registered_commands.size() == 16,
	   "registered_commands has exactly 16 entries (8 runtime + 8 disk)");

	ok(has_command_starting_with("LOAD MYSQLX USERS TO RUNTIME"),
	   "registered_commands contains LOAD MYSQLX USERS TO RUNTIME");
	ok(has_command_starting_with("SAVE MYSQLX USERS TO MEMORY"),
	   "registered_commands contains SAVE MYSQLX USERS TO MEMORY");
	ok(has_command_starting_with("LOAD MYSQLX ROUTES TO RUNTIME"),
	   "registered_commands contains LOAD MYSQLX ROUTES TO RUNTIME");
	ok(has_command_starting_with("SAVE MYSQLX ROUTES TO MEMORY"),
	   "registered_commands contains SAVE MYSQLX ROUTES TO MEMORY");
	ok(has_command_starting_with("LOAD MYSQLX USERS FROM DISK"),
	   "registered_commands contains LOAD MYSQLX USERS FROM DISK");
	ok(has_command_starting_with("SAVE MYSQLX USERS TO DISK"),
	   "registered_commands contains SAVE MYSQLX USERS TO DISK");
	ok(has_command_starting_with("LOAD MYSQLX ROUTES FROM DISK"),
	   "registered_commands contains LOAD MYSQLX ROUTES FROM DISK");
	ok(has_command_starting_with("SAVE MYSQLX ROUTES TO DISK"),
	   "registered_commands contains SAVE MYSQLX ROUTES TO DISK");
	ok(has_command_starting_with("LOAD MYSQLX BACKEND ENDPOINTS FROM DISK"),
	   "registered_commands contains LOAD MYSQLX BACKEND ENDPOINTS FROM DISK");
	ok(has_command_starting_with("LOAD MYSQLX VARIABLES FROM DISK"),
	   "registered_commands contains LOAD MYSQLX VARIABLES FROM DISK");
	ok(has_command_starting_with("SAVE MYSQLX VARIABLES TO DISK"),
	   "registered_commands contains SAVE MYSQLX VARIABLES TO DISK");

	return exit_status();
}
