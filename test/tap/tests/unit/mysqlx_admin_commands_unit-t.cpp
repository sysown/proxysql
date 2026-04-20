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

int main() {
	plan(27);

	test_init_minimal();

	mysqlx_context().config_store = std::make_unique<MysqlxConfigStore>();

	reset_mocks();
	ProxySQL_PluginServices services {};
	services.register_table = &mock_register_table;
	services.register_command = &mock_register_command;
	ok(mysqlx_register_admin_schema(services),
	   "mysqlx_register_admin_schema succeeds");

	SQLite3DB admindb;
	admindb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
	for (const auto& t : registered_tables) {
		if (t.db_kind == ProxySQL_PluginDBKind::admin_db) {
			admindb.execute(t.table_def);
		}
	}

	ProxySQL_PluginCommandContext ctx;
	ctx.admindb = &admindb;
	ctx.configdb = nullptr;
	ctx.statsdb = nullptr;

	{
		auto* cmd = find_command("LOAD MYSQLX USERS TO RUNTIME");
		ok(cmd != nullptr, "LOAD MYSQLX USERS TO RUNTIME command registered");
		admindb.execute("INSERT INTO mysqlx_users (username, active) VALUES ('alice', 1)");
		admindb.execute("INSERT INTO mysqlx_users (username, active) VALUES ('bob', 0)");
		ProxySQL_PluginCommandResult res = cmd(ctx, nullptr);
		ok(res.error_code == 0, "LOAD MYSQLX USERS TO RUNTIME succeeds");
		ok(res.rows_affected == 2, "LOAD MYSQLX USERS TO RUNTIME reports 2 rows");
		int cnt = admindb.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_users");
		ok(cnt == 2, "runtime_mysqlx_users has 2 rows after load");
	}

	{
		auto* cmd = find_command("SAVE MYSQLX USERS TO MEMORY");
		ok(cmd != nullptr, "SAVE MYSQLX USERS TO MEMORY command registered");
		admindb.execute("DELETE FROM mysqlx_users");
		ProxySQL_PluginCommandResult res = cmd(ctx, nullptr);
		ok(res.error_code == 0, "SAVE MYSQLX USERS TO MEMORY succeeds");
		int cnt = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_users");
		ok(cnt == 2, "mysqlx_users has 2 rows after save from runtime");
	}

	{
		auto* cmd = find_command("LOAD MYSQLX ROUTES TO RUNTIME");
		ok(cmd != nullptr, "LOAD MYSQLX ROUTES TO RUNTIME command registered");
		admindb.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup) VALUES ('r1', '0.0.0.0:33060', 0)");
		ProxySQL_PluginCommandResult res = cmd(ctx, nullptr);
		ok(res.error_code == 0, "LOAD MYSQLX ROUTES TO RUNTIME succeeds");
		ok(res.rows_affected == 1, "LOAD MYSQLX ROUTES TO RUNTIME reports 1 row");
	}

	{
		auto* cmd = find_command("SAVE MYSQLX ROUTES TO MEMORY");
		ok(cmd != nullptr, "SAVE MYSQLX ROUTES TO MEMORY command registered");
		admindb.execute("DELETE FROM mysqlx_routes");
		ProxySQL_PluginCommandResult res = cmd(ctx, nullptr);
		ok(res.error_code == 0, "SAVE MYSQLX ROUTES TO MEMORY succeeds");
		int cnt = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_routes");
		ok(cnt == 1, "mysqlx_routes has 1 row after save from runtime");
	}

	{
		auto* cmd = find_command("LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME");
		ok(cmd != nullptr, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME command registered");
		admindb.execute("INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port) VALUES ('127.0.0.1', 3306, 33060)");
		ProxySQL_PluginCommandResult res = cmd(ctx, nullptr);
		ok(res.error_code == 0, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME succeeds");
	}

	{
		auto* cmd = find_command("SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY");
		ok(cmd != nullptr, "SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY command registered");
		admindb.execute("DELETE FROM mysqlx_backend_endpoints");
		ProxySQL_PluginCommandResult res = cmd(ctx, nullptr);
		ok(res.error_code == 0, "SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY succeeds");
		int cnt = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_backend_endpoints");
		ok(cnt == 1, "mysqlx_backend_endpoints has 1 row after save");
	}

	{
		auto* cmd = find_command("LOAD MYSQLX VARIABLES TO RUNTIME");
		ok(cmd != nullptr, "LOAD MYSQLX VARIABLES TO RUNTIME command registered");
		admindb.execute("INSERT INTO mysqlx_variables (variable_name, variable_value) VALUES ('thread_pool_size', '4')");
		ProxySQL_PluginCommandResult res = cmd(ctx, nullptr);
		ok(res.error_code == 0, "LOAD MYSQLX VARIABLES TO RUNTIME succeeds");
	}

	{
		auto* cmd = find_command("SAVE MYSQLX VARIABLES TO MEMORY");
		ok(cmd != nullptr, "SAVE MYSQLX VARIABLES TO MEMORY command registered");
		admindb.execute("DELETE FROM mysqlx_variables");
		ProxySQL_PluginCommandResult res = cmd(ctx, nullptr);
		ok(res.error_code == 0, "SAVE MYSQLX VARIABLES TO MEMORY succeeds");
		int cnt = admindb.return_one_int("SELECT COUNT(*) FROM mysqlx_variables");
		ok(cnt == 1, "mysqlx_variables has 1 row after save");
	}

	{
		auto* cmd = find_command("LOAD MYSQLX USERS TO RUNTIME");
		admindb.execute("DELETE FROM mysqlx_users");
		admindb.execute("INSERT INTO mysqlx_users (username, active) VALUES ('charlie', 1)");
		ProxySQL_PluginCommandResult res = cmd(ctx, nullptr);
		int cnt = admindb.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_users");
		ok(cnt == 1, "re-loading users replaces runtime data (not appends)");
		std::unique_ptr<SQLite3_result, void(*)(SQLite3_result*)> r(
			admindb.execute_statement("SELECT username FROM runtime_mysqlx_users WHERE username='charlie'", nullptr),
			[](SQLite3_result* p) { if (p) { /* leaked intentionally for test scope */ } }
		);
		ok(r && r->rows.size() == 1, "runtime contains charlie after reload");
	}

	{
		ProxySQL_PluginCommandContext null_ctx {};
		null_ctx.admindb = nullptr;
		null_ctx.configdb = nullptr;
		null_ctx.statsdb = nullptr;
		auto* cmd = find_command("LOAD MYSQLX USERS TO RUNTIME");
		ProxySQL_PluginCommandResult res = cmd(null_ctx, nullptr);
		ok(res.error_code != 0, "command with null admindb returns error");
	}

	test_cleanup_minimal();
	return exit_status();
}
