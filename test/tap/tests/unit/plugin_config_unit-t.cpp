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
	plan(7);

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

	unsetenv("PROXYSQL_FAKE_PLUGIN_LOG");
	std::remove(log_template);
	return exit_status();
}
