#include "ProxySQL_PluginManager.h"
#include "proxysql_glovars.hpp"
#include "tap.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <unistd.h>

extern ProxySQL_GlobalVariables GloVars;

namespace {

char g_fake_admin_db = '\0';
char g_fake_config_db = '\0';
char g_fake_stats_db = '\0';

} // namespace

SQLite3DB* proxysql_plugin_get_admindb() {
	return reinterpret_cast<SQLite3DB*>(&g_fake_admin_db);
}

SQLite3DB* proxysql_plugin_get_configdb() {
	return reinterpret_cast<SQLite3DB*>(&g_fake_config_db);
}

SQLite3DB* proxysql_plugin_get_statsdb() {
	return reinterpret_cast<SQLite3DB*>(&g_fake_stats_db);
}

int main() {
	plan(20);

	Config cfg;
	cfg.readString("plugins=(\"" PROXYSQL_FAKE_PLUGIN_PATH "\");");
	proxysql_load_plugin_modules_from_config(cfg.getRoot(), GloVars.plugin_modules);

	ok(GloVars.plugin_modules.size() == static_cast<size_t>(1),
	   "config parsing stores configured plugin entries");
	ok(GloVars.plugin_modules.front() == PROXYSQL_FAKE_PLUGIN_PATH,
	   "config parsing preserves plugin path values");

	ProxySQL_PluginManager mgr;
	std::string err {};
	ok(!mgr.load("/definitely/missing/plugin.so", err),
	   "missing plugin fails with a useful error");
	ok(!err.empty(), "missing plugin failure returns an error string");

	GloVars.plugin_modules.emplace_back("/tmp/stale.so");
	Config empty_cfg;
	empty_cfg.readString("datadir=\"/tmp\";");
	proxysql_load_plugin_modules_from_config(empty_cfg.getRoot(), GloVars.plugin_modules);
	ok(GloVars.plugin_modules.empty(),
	   "config parsing clears stale plugin entries when plugins is absent");

	char log_template[] = "/tmp/proxysql_fake_plugin.XXXXXX";
	int log_fd = mkstemp(log_template);
	close(log_fd);
	setenv("PROXYSQL_FAKE_PLUGIN_LOG", log_template, 1);

	std::unique_ptr<ProxySQL_PluginManager> configured_manager;
	GloVars.plugin_modules.emplace_back(PROXYSQL_FAKE_PLUGIN_PATH);
	ok(proxysql_load_configured_plugins(configured_manager, GloVars.plugin_modules, err) &&
	   proxysql_start_configured_plugins(configured_manager.get(), err) &&
	   proxysql_stop_configured_plugins(configured_manager, err),
	   "configured plugin lifecycle succeeds");

	std::ifstream log_stream(log_template);
	std::string log_contents((std::istreambuf_iterator<char>(log_stream)),
				 std::istreambuf_iterator<char>());
	ok(log_contents == "init\nstart\nstop\n",
	   "configured plugin lifecycle runs init, start, stop in order");

	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_INVALID_TABLE", "1", 1);
	GloVars.plugin_modules.clear();
	GloVars.plugin_modules.emplace_back(PROXYSQL_FAKE_PLUGIN_PATH);
	ok(!proxysql_load_configured_plugins(configured_manager, GloVars.plugin_modules, err),
	   "configured plugin load fails when plugin service registration fails during init");
	ok(!err.empty(),
	   "plugin init registration failure returns an error string");
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_INVALID_TABLE");

	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND", "1", 1);
	err.clear();
	GloVars.plugin_modules.clear();
	GloVars.plugin_modules.emplace_back(PROXYSQL_FAKE_PLUGIN_PATH);
	ok(proxysql_load_configured_plugins(configured_manager, GloVars.plugin_modules, err),
	   "configured plugin load succeeds when fake plugin registers an admin command");
	ProxySQL_PluginCommandContext ctx { proxysql_plugin_get_admindb(), proxysql_plugin_get_configdb(), proxysql_plugin_get_statsdb() };
	ProxySQL_PluginCommandResult result { 1, 0, "" };
	ok(proxysql_dispatch_configured_plugin_admin_command(ctx, "PLUGIN FAKE NOOP", result) &&
	   result.error_code == 0 &&
	   result.rows_affected == 1 &&
	   result.message == "fake command executed",
	   "configured plugin admin commands dispatch through the active plugin manager");
	ok(proxysql_stop_configured_plugins(configured_manager, err) &&
	   !proxysql_dispatch_configured_plugin_admin_command(ctx, "PLUGIN FAKE NOOP", result),
	   "plugin admin dispatch is disabled once configured plugins are stopped");
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND");

	unsetenv("PROXYSQL_FAKE_PLUGIN_LOG");
	std::remove(log_template);

	// New assertions (13-20)

	GloVars.plugin_modules.clear();
	Config empty_plugins_cfg;
	empty_plugins_cfg.readString("plugins=();");
	proxysql_load_plugin_modules_from_config(empty_plugins_cfg.getRoot(), GloVars.plugin_modules);
	ok(GloVars.plugin_modules.empty(),
	   "config with empty plugins list produces empty plugin_modules");

	GloVars.plugin_modules.clear();
	Config two_cfg;
	two_cfg.readString("plugins=(\"path/a.so\",\"path/b.so\");");
	proxysql_load_plugin_modules_from_config(two_cfg.getRoot(), GloVars.plugin_modules);
	ok(GloVars.plugin_modules.size() == static_cast<size_t>(2) &&
	   GloVars.plugin_modules[0] == "path/a.so" &&
	   GloVars.plugin_modules[1] == "path/b.so",
	   "config parsing stores two plugin entries");

	GloVars.plugin_modules.clear();
	Config no_plugins_cfg;
	no_plugins_cfg.readString("datadir=\"/tmp\";");
	proxysql_load_plugin_modules_from_config(no_plugins_cfg.getRoot(), GloVars.plugin_modules);
	ok(GloVars.plugin_modules.empty(),
	   "config with no plugins key leaves plugin_modules empty with no crash");

	{
		GloVars.plugin_modules.clear();
		Config first_cfg;
		first_cfg.readString("plugins=(\"path/first.so\");");
		proxysql_load_plugin_modules_from_config(first_cfg.getRoot(), GloVars.plugin_modules);

		Config second_cfg;
		second_cfg.readString("plugins=(\"path/a.so\",\"path/b.so\");");
		proxysql_load_plugin_modules_from_config(second_cfg.getRoot(), GloVars.plugin_modules);
		ok(GloVars.plugin_modules.size() == static_cast<size_t>(2) &&
		   GloVars.plugin_modules[0] == "path/a.so" &&
		   GloVars.plugin_modules[1] == "path/b.so",
		   "second config parsing call replaces first plugin list");
	}

	{
		std::unique_ptr<ProxySQL_PluginManager> null_mgr;
		std::string stop_err;
		ok(proxysql_stop_configured_plugins(null_mgr, stop_err),
		   "proxysql_stop_configured_plugins with null manager returns true");
	}

	{
		std::string start_err;
		ok(proxysql_start_configured_plugins(nullptr, start_err),
		   "proxysql_start_configured_plugins with null manager returns true");
	}

	{
		std::unique_ptr<ProxySQL_PluginManager> empty_mgr;
		std::vector<std::string> empty_list;
		std::string load_err;
		ok(proxysql_load_configured_plugins(empty_mgr, empty_list, load_err),
		   "proxysql_load_configured_plugins with empty plugin list returns true");
	}

	{
		ProxySQL_PluginCommandResult after_stop_result { 1, 0, "" };
		ok(!proxysql_dispatch_configured_plugin_admin_command(ctx, "PLUGIN FAKE NOOP", after_stop_result),
		   "dispatch returns false after configured plugins are stopped");
	}

	return exit_status();
}
