#include "ProxySQL_Plugin.h"
#include "mysqlx_admin_schema.h"
#include "mysqlx_config_store.h"
#include "tap.h"
#include "test_init.h"
#include "sqlite3db.h"

#include <cstring>
#include <memory>
#include <string>
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

proxysql_plugin_admin_command_cb find_command(const char* name) {
	for (const auto& c : registered_commands) {
		if (c.first == name) return c.second;
	}
	return nullptr;
}

void reset_mocks() {
	registered_tables.clear();
	registered_commands.clear();
}

}

struct MysqlxPluginContext {
	ProxySQL_PluginServices* services { nullptr };
	std::unique_ptr<MysqlxConfigStore> config_store {};
	bool started { false };
};

MysqlxPluginContext& mysqlx_context() {
	static MysqlxPluginContext ctx {};
	return ctx;
}

static void create_all_tables(SQLite3DB& db) {
	for (const auto& t : registered_tables) {
		if (t.db_kind == ProxySQL_PluginDBKind::admin_db ||
		    t.db_kind == ProxySQL_PluginDBKind::config_db) {
			db.execute(t.table_def);
		}
	}
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(32);
	diag("=== mysqlx_admin_disk_commands_unit-t starting ===");

	test_init_minimal();
	mysqlx_context().config_store = std::make_unique<MysqlxConfigStore>();

	reset_mocks();
	ProxySQL_PluginServices services {};
	services.register_table = &mock_register_table;
	services.register_command = &mock_register_command;
	ok(mysqlx_register_admin_schema(services), "mysqlx_register_admin_schema succeeds");

	SQLite3DB admindb;
	admindb.open(const_cast<char*>("file:mem_admindb?mode=memory&cache=shared"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI);  // NOSONAR
	create_all_tables(admindb);

	SQLite3DB configdb;
	configdb.open(const_cast<char*>("file:mem_configdb?mode=memory&cache=shared"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI);  // NOSONAR
	create_all_tables(configdb);

	admindb.execute("ATTACH DATABASE 'file:mem_configdb?mode=memory&cache=shared' AS disk");

	ProxySQL_PluginCommandContext ctx;
	ctx.admindb = &admindb;
	ctx.configdb = &configdb;
	ctx.statsdb = nullptr;

	{
		admindb.execute("INSERT INTO mysqlx_users (username, active) VALUES ('diskuser1', 1)");
		admindb.execute("INSERT INTO mysqlx_users (username, active) VALUES ('diskuser2', 0)");

		auto* cmd = find_command("SAVE MYSQLX USERS TO DISK");
		ok(cmd != nullptr, "SAVE MYSQLX USERS TO DISK command registered");
		ProxySQL_PluginCommandResult res = cmd(ctx, nullptr);
		ok(res.error_code == 0, "SAVE MYSQLX USERS TO DISK succeeds");
		ok(res.message.find("saved to disk") != std::string::npos, "message contains 'saved to disk'");

		int disk_cnt = admindb.return_one_int("SELECT COUNT(*) FROM disk.mysqlx_users");
		ok(disk_cnt == 2, "disk.mysqlx_users has 2 rows after save");
	}

	{
		admindb.execute("DELETE FROM mysqlx_users");
		int mem_cnt = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_users");
		ok(mem_cnt == 0, "mysqlx_users is empty after delete");

		auto* cmd = find_command("LOAD MYSQLX USERS FROM DISK");
		ok(cmd != nullptr, "LOAD MYSQLX USERS FROM DISK command registered");
		ProxySQL_PluginCommandResult res = cmd(ctx, nullptr);
		ok(res.error_code == 0, "LOAD MYSQLX USERS FROM DISK succeeds");
		ok(res.message.find("loaded from disk") != std::string::npos, "message contains 'loaded from disk'");

		int mem_cnt2 = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_users");
		ok(mem_cnt2 == 2, "mysqlx_users has 2 rows after load from disk");

		int alice = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_users WHERE username='diskuser1' AND active=1");
		ok(alice == 1, "diskuser1 restored with correct values");
	}

	{
		admindb.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup) VALUES ('route_d', '0.0.0.0:33060', 5)");

		auto* save_cmd = find_command("SAVE MYSQLX ROUTES TO DISK");
		ok(save_cmd != nullptr, "SAVE MYSQLX ROUTES TO DISK registered");
		ProxySQL_PluginCommandResult save_res = save_cmd(ctx, nullptr);
		ok(save_res.error_code == 0, "SAVE MYSQLX ROUTES TO DISK succeeds");

		admindb.execute("DELETE FROM mysqlx_routes");

		auto* load_cmd = find_command("LOAD MYSQLX ROUTES FROM DISK");
		ok(load_cmd != nullptr, "LOAD MYSQLX ROUTES FROM DISK registered");
		ProxySQL_PluginCommandResult load_res = load_cmd(ctx, nullptr);
		ok(load_res.error_code == 0, "LOAD MYSQLX ROUTES FROM DISK succeeds");

		int cnt = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_routes WHERE name='route_d'");
		ok(cnt == 1, "route_d restored from disk");

		int hg = admindb.return_one_int("SELECT destination_hostgroup FROM mysqlx_routes WHERE name='route_d'");
		ok(hg == 5, "route_d destination_hostgroup preserved");
	}

	{
		admindb.execute("INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port) VALUES ('10.0.0.1', 3306, 33060)");

		auto* save_cmd = find_command("SAVE MYSQLX BACKEND ENDPOINTS TO DISK");
		ok(save_cmd != nullptr, "SAVE MYSQLX BACKEND ENDPOINTS TO DISK registered");
		ProxySQL_PluginCommandResult save_res = save_cmd(ctx, nullptr);
		ok(save_res.error_code == 0, "SAVE MYSQLX BACKEND ENDPOINTS TO DISK succeeds");

		admindb.execute("DELETE FROM mysqlx_backend_endpoints");

		auto* load_cmd = find_command("LOAD MYSQLX BACKEND ENDPOINTS FROM DISK");
		ok(load_cmd != nullptr, "LOAD MYSQLX BACKEND ENDPOINTS FROM DISK registered");
		ProxySQL_PluginCommandResult load_res = load_cmd(ctx, nullptr);
		ok(load_res.error_code == 0, "LOAD MYSQLX BACKEND ENDPOINTS FROM DISK succeeds");

		int cnt = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_backend_endpoints WHERE hostname='10.0.0.1'");
		ok(cnt == 1, "backend endpoint restored from disk");

		int xport = admindb.return_one_int("SELECT mysqlx_port FROM mysqlx_backend_endpoints WHERE hostname='10.0.0.1'");
		ok(xport == 33060, "backend endpoint mysqlx_port preserved");
	}

	{
		admindb.execute("INSERT INTO mysqlx_variables (variable_name, variable_value) VALUES ('thread_pool_size', '8')");
		admindb.execute("INSERT INTO mysqlx_variables (variable_name, variable_value) VALUES ('max_cached_connections', '100')");

		auto* save_cmd = find_command("SAVE MYSQLX VARIABLES TO DISK");
		ok(save_cmd != nullptr, "SAVE MYSQLX VARIABLES TO DISK registered");
		ProxySQL_PluginCommandResult save_res = save_cmd(ctx, nullptr);
		ok(save_res.error_code == 0, "SAVE MYSQLX VARIABLES TO DISK succeeds");

		admindb.execute("DELETE FROM mysqlx_variables");

		auto* load_cmd = find_command("LOAD MYSQLX VARIABLES FROM DISK");
		ok(load_cmd != nullptr, "LOAD MYSQLX VARIABLES FROM DISK registered");
		ProxySQL_PluginCommandResult load_res = load_cmd(ctx, nullptr);
		ok(load_res.error_code == 0, "LOAD MYSQLX VARIABLES FROM DISK succeeds");

		int cnt = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_variables");
		ok(cnt == 2, "both variables restored from disk");

		int v1 = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_variables WHERE variable_name='thread_pool_size' AND variable_value='8'");
		ok(v1 == 1, "thread_pool_size variable value preserved");

		int v2 = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_variables WHERE variable_name='max_cached_connections' AND variable_value='100'");
		ok(v2 == 1, "max_cached_connections variable value preserved");
	}

	{
		ProxySQL_PluginCommandContext null_ctx {};
		null_ctx.admindb = nullptr;
		null_ctx.configdb = nullptr;
		null_ctx.statsdb = nullptr;
		auto* cmd = find_command("SAVE MYSQLX USERS TO DISK");
		ProxySQL_PluginCommandResult res = cmd(null_ctx, nullptr);
		ok(res.error_code != 0, "disk command with null admindb returns error");

		auto* cmd2 = find_command("LOAD MYSQLX USERS FROM DISK");
		ProxySQL_PluginCommandResult res2 = cmd2(null_ctx, nullptr);
		ok(res2.error_code != 0, "disk load with null admindb returns error");
	}

	test_cleanup_minimal();
	return exit_status();
}
