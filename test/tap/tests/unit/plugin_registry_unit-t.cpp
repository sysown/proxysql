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
	plan(25);

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
	ProxySQL_PluginTableDef invalid_def {
		static_cast<ProxySQL_PluginDBKind>(255),
		"invalid_table",
		"CREATE TABLE invalid_table (id INTEGER)"
	};
	ProxySQL_PluginTableDef stats_def {
		ProxySQL_PluginDBKind::stats_db,
		"mysqlx_stats",
		"CREATE TABLE mysqlx_stats (id INTEGER)"
	};
	mgr.register_table_for_test(invalid_def);
	ok(mgr.tables(ProxySQL_PluginDBKind::admin_db).size() == static_cast<size_t>(1), "invalid db kind is rejected");
	mgr.register_table_for_test(stats_def);
	ok(mgr.tables(ProxySQL_PluginDBKind::stats_db).size() == static_cast<size_t>(1), "plugin stats table is stored");
	ok(mgr.tables(static_cast<ProxySQL_PluginDBKind>(255)).empty(), "invalid table accessor returns empty");
	ok(mgr.tables(ProxySQL_PluginDBKind::config_db).size() == static_cast<size_t>(0), "config tables start empty");
	ok(mgr.register_command_for_test("SELECT 1"), "any SQL is accepted for command registration");
	ok(mgr.register_command("LOAD MYSQLX USERS TO RUNTIME", &fake_plugin_command), "canonical command registration succeeds");
	ok(!mgr.register_command("LOAD MYSQLX USERS TO RUNTIME", &fake_plugin_command), "duplicate command is rejected");
	ok(!mgr.register_command("LOAD   MYSQLX   USERS TO RUNTIME ;", &fake_plugin_command), "canonical duplicate command is rejected");
	ok(mgr.has_command_for_test("LOAD MYSQLX USERS TO RUNTIME"), "registered command is discoverable");

	ProxySQL_PluginCommandResult result { 1, 0, "" };
	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };
	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   result.rows_affected == 7 &&
	   result.message == "mysqlx users loaded",
	   "registered command dispatches callback result");
	ok(mgr.dispatch_admin_command(ctx, "LOAD   MYSQLX   USERS TO RUNTIME ;", result) &&
	   result.error_code == 0 &&
	   result.rows_affected == 7 &&
	   result.message == "mysqlx users loaded",
	   "dispatch canonicalizes whitespace and trailing semicolons");

	ok(!mgr.register_command("", &fake_plugin_command),
	   "register_command with empty string returns false");
	ok(!mgr.register_command("test", nullptr),
	   "register_command with null callback returns false");
	ok(!mgr.register_command_for_test("   "),
	   "register_command_for_test with whitespace-only string returns false");

	{
		ProxySQL_PluginCommandResult empty_result { 1, 0, "" };
		ok(!mgr.dispatch_admin_command(ctx, "", empty_result),
		   "dispatch_admin_command with empty SQL returns false");
	}

	{
		ProxySQL_PluginCommandResult unreg_result { 1, 0, "" };
		ok(!mgr.dispatch_admin_command(ctx, "NOT A REAL COMMAND", unreg_result),
		   "dispatch_admin_command with unregistered command returns false");
	}

	{
		ProxySQL_PluginTableDef null_name_def {
			ProxySQL_PluginDBKind::admin_db,
			nullptr,
			"CREATE TABLE test (id INTEGER)"
		};
		ok(!mgr.register_table(null_name_def),
		   "register_table with null table_name returns false");
	}

	{
		char some_name[] = "some_table";
		char empty_table_def[] = "";
		ProxySQL_PluginTableDef empty_def {
			ProxySQL_PluginDBKind::admin_db,
			some_name,
			empty_table_def
		};
		ok(!mgr.register_table(empty_def),
		   "register_table with empty table_def returns false");
	}

	{
		char cross_name1[] = "test_table";
		char cross_def1[] = "CREATE TABLE test_table (id INTEGER)";
		ProxySQL_PluginTableDef admin_tbl {
			ProxySQL_PluginDBKind::admin_db,
			cross_name1,
			cross_def1
		};
		char cross_name2[] = "test_table";
		char cross_def2[] = "CREATE TABLE test_table (id INTEGER)";
		ProxySQL_PluginTableDef stats_tbl {
			ProxySQL_PluginDBKind::stats_db,
			cross_name2,
			cross_def2
		};
		ok(mgr.register_table(admin_tbl) && mgr.register_table(stats_tbl),
		   "same table name in different db kinds both succeed");
	}

	{
		ProxySQL_PluginCommandResult space_result { 1, 0, "" };
		ok(mgr.dispatch_admin_command(ctx, "  LOAD MYSQLX USERS TO RUNTIME  ", space_result) &&
		   space_result.error_code == 0 &&
		   space_result.rows_affected == 7,
		   "dispatch with leading/trailing spaces matches registered command");
	}

	{
		ProxySQL_PluginCommandResult dbl_result { 1, 0, "" };
		ok(mgr.dispatch_admin_command(ctx, "LOAD  MYSQLX  USERS  TO  RUNTIME;", dbl_result) &&
		   dbl_result.error_code == 0 &&
		   dbl_result.rows_affected == 7,
		   "dispatch with double spaces and semicolon canonicalizes correctly");
	}

	return exit_status();
}
