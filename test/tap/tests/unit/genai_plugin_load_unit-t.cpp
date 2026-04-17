// Step 1 acceptance test for the genai plugin scaffold.
//
// Drives the actual genai .so through load → init → start → stop → unload,
// the same way proxysql will at startup.  Any future Step 2+ extension
// (admin tables, query hook, status vars) gets its own assertion here as
// it lands.

#include "ProxySQL_PluginManager.h"
#include "tap.h"

#include <string>

#ifndef PROXYSQL_GENAI_PLUGIN_PATH
#error "PROXYSQL_GENAI_PLUGIN_PATH must be defined"
#endif

namespace {

char g_fake_admin_db = '\0';
char g_fake_config_db = '\0';
char g_fake_stats_db = '\0';

} // namespace

SQLite3DB* proxysql_plugin_get_admindb()  { return reinterpret_cast<SQLite3DB*>(&g_fake_admin_db); }
SQLite3DB* proxysql_plugin_get_configdb() { return reinterpret_cast<SQLite3DB*>(&g_fake_config_db); }
SQLite3DB* proxysql_plugin_get_statsdb()  { return reinterpret_cast<SQLite3DB*>(&g_fake_stats_db); }

int main() {
	plan(8);

	ProxySQL_PluginManager mgr;
	std::string err {};

	const bool loaded = mgr.load(PROXYSQL_GENAI_PLUGIN_PATH, err);
	ok(loaded, "load genai plugin succeeds");
	if (!loaded) {
		diag("load error: %s", err.c_str());
		BAIL_OUT("genai plugin must load before lifecycle assertions");
	}
	ok(mgr.size() == 1, "exactly one plugin handle after load");

	ok(mgr.init_all(err),  "init_all succeeds");
	if (!err.empty()) diag("init error: %s", err.c_str());

	ok(mgr.start_all(err), "start_all succeeds");
	if (!err.empty()) diag("start error: %s", err.c_str());

	ok(mgr.stop_all(),     "stop_all succeeds");

	// Skeleton plugin currently registers no tables and no commands.
	// These assertions tighten as Step 3+ start migrating GenAI surface.
	ok(mgr.tables(ProxySQL_PluginDBKind::admin_db).empty(),
	   "skeleton genai plugin registers no admin tables (yet)");
	ok(mgr.tables(ProxySQL_PluginDBKind::config_db).empty(),
	   "skeleton genai plugin registers no config tables (yet)");
	ok(mgr.tables(ProxySQL_PluginDBKind::stats_db).empty(),
	   "skeleton genai plugin registers no stats tables (yet)");

	return exit_status();
}
