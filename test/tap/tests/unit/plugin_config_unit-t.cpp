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

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif
#ifndef PROXYSQL_FAKE_PLUGIN2_PATH
#error "PROXYSQL_FAKE_PLUGIN2_PATH must be defined"
#endif

namespace {

char g_fake_admin_db = '\0';
char g_fake_config_db = '\0';
char g_fake_stats_db = '\0';

std::string g_log_path {};

void make_log_path() {
	char tpl[] = "/tmp/proxysql_plugin_cfg_log.XXXXXX";
	int fd = mkstemp(tpl);
	if (fd >= 0) close(fd);
	g_log_path = tpl;
	setenv("PROXYSQL_FAKE_PLUGIN_LOG", g_log_path.c_str(), 1);
	setenv("PROXYSQL_FAKE_PLUGIN2_LOG", g_log_path.c_str(), 1);
}

void clear_log() {
	if (g_log_path.empty()) return;
	// See plugin_manager_unit-t.cpp for the SonarCloud rationale.
	std::ofstream truncate_handle(g_log_path, std::ios::trunc);
	(void)truncate_handle;
}

std::string read_log() {
	if (g_log_path.empty()) return "";
	std::ifstream s(g_log_path);
	return std::string((std::istreambuf_iterator<char>(s)), std::istreambuf_iterator<char>());
}

void cleanup_log() {
	if (g_log_path.empty()) return;
	std::remove(g_log_path.c_str());
	unsetenv("PROXYSQL_FAKE_PLUGIN_LOG");
	unsetenv("PROXYSQL_FAKE_PLUGIN2_LOG");
}

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

// PROXYSQL40 splits load+init; without the flag they run as one call.
// This helper keeps test call sites uniform across both builds.
#ifdef PROXYSQL40
static inline bool proxysql_init_configured_plugins_compat(ProxySQL_PluginManager* m, std::string& err) {
	return proxysql_init_configured_plugins(m, err);
}
#else
static inline bool proxysql_init_configured_plugins_compat(ProxySQL_PluginManager*, std::string&) {
	return true;
}
#endif

static void test_config_parse_single() {
	GloVars.plugin_modules.clear();
	Config cfg;
	cfg.readString("plugins=(\"" PROXYSQL_FAKE_PLUGIN_PATH "\");");
	proxysql_load_plugin_modules_from_config(cfg.getRoot(), GloVars.plugin_modules);
	ok(GloVars.plugin_modules.size() == static_cast<size_t>(1),
	   "single plugin entry parsed");
	ok(GloVars.plugin_modules.front() == PROXYSQL_FAKE_PLUGIN_PATH,
	   "plugin path preserved verbatim");
}

static void test_config_parse_multiple() {
	GloVars.plugin_modules.clear();
	Config cfg;
	cfg.readString("plugins=(\"" PROXYSQL_FAKE_PLUGIN_PATH "\","
	               "\"" PROXYSQL_FAKE_PLUGIN2_PATH "\");");
	proxysql_load_plugin_modules_from_config(cfg.getRoot(), GloVars.plugin_modules);
	ok(GloVars.plugin_modules.size() == static_cast<size_t>(2),
	   "two plugin entries parsed");
	ok(GloVars.plugin_modules[0] == PROXYSQL_FAKE_PLUGIN_PATH,
	   "first entry preserved");
	ok(GloVars.plugin_modules[1] == PROXYSQL_FAKE_PLUGIN2_PATH,
	   "second entry preserved");
}

static void test_config_parse_empty_array() {
	GloVars.plugin_modules.clear();
	GloVars.plugin_modules.emplace_back("/tmp/stale.so");
	Config cfg;
	cfg.readString("plugins=();");
	proxysql_load_plugin_modules_from_config(cfg.getRoot(), GloVars.plugin_modules);
	ok(GloVars.plugin_modules.empty(),
	   "empty plugins=() clears the modules vector");
}

static void test_config_no_plugins_directive() {
	GloVars.plugin_modules.clear();
	GloVars.plugin_modules.emplace_back("/tmp/stale.so");
	Config cfg;
	cfg.readString("datadir=\"/tmp\";");
	proxysql_load_plugin_modules_from_config(cfg.getRoot(), GloVars.plugin_modules);
	ok(GloVars.plugin_modules.empty(),
	   "absence of plugins=() clears stale entries");
}

static void test_config_parse_skips_non_strings() {
	GloVars.plugin_modules.clear();
	Config cfg;
	cfg.readString("plugins=(\"" PROXYSQL_FAKE_PLUGIN_PATH "\", 42, true,"
	               "\"" PROXYSQL_FAKE_PLUGIN2_PATH "\");");
	proxysql_load_plugin_modules_from_config(cfg.getRoot(), GloVars.plugin_modules);
	ok(GloVars.plugin_modules.size() == static_cast<size_t>(2),
	   "non-string entries (int, bool) silently skipped");
	ok(GloVars.plugin_modules[0] == PROXYSQL_FAKE_PLUGIN_PATH,
	   "first valid entry preserved");
	ok(GloVars.plugin_modules[1] == PROXYSQL_FAKE_PLUGIN2_PATH,
	   "second valid entry preserved across the gap");
}

static void test_load_missing_path_via_helper() {
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { "/definitely/missing/plugin.so" };
	std::string err;
	ok(!proxysql_load_configured_plugins(mgr, paths, err),
	   "load helper fails when a configured path doesn't exist");
	ok(!err.empty(), "load helper reports a non-empty error");
	ok(err.find("/definitely/missing/plugin.so") != std::string::npos,
	   "load helper error names the failing path");
	ok(proxysql_get_plugin_manager() == nullptr,
	   "global manager remains null after a failed load");
}

static void test_lifecycle_logs_in_order() {
	clear_log();
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins_compat(mgr.get(), err) &&
	   proxysql_start_configured_plugins(mgr.get(), err) &&
	   proxysql_stop_configured_plugins(mgr, err),
	   "single-plugin lifecycle helpers all succeed");
	{
		std::string actual = read_log();
		ok(actual == "fake_plugin:init\nfake_plugin:start\nfake_plugin:stop\n",
		   "init/start/stop logged in order (got: '%s')", actual.c_str());
	}
}

static void test_multi_lifecycle_logs_in_order() {
	clear_log();
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths {
		PROXYSQL_FAKE_PLUGIN_PATH,
		PROXYSQL_FAKE_PLUGIN2_PATH
	};
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins_compat(mgr.get(), err) &&
	   proxysql_start_configured_plugins(mgr.get(), err) &&
	   proxysql_stop_configured_plugins(mgr, err),
	   "two-plugin lifecycle helpers all succeed");
	{
		std::string actual = read_log();
		const std::string expected =
			"fake_plugin:init\nfake_plugin2:init\n"
			"fake_plugin:start\nfake_plugin2:start\n"
			"fake_plugin2:stop\nfake_plugin:stop\n";
		ok(actual == expected,
		   "two plugins: init/start in order, stop reversed (got: '%s')", actual.c_str());
	}
}

static void test_active_manager_visibility() {
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_get_plugin_manager() == nullptr,
	   "no active manager before load");
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins_compat(mgr.get(), err),
	   "load succeeds");
	ok(proxysql_get_plugin_manager() == mgr.get(),
	   "after load, the active pointer matches the unique_ptr");
	ok(proxysql_stop_configured_plugins(mgr, err),
	   "stop helper cleans up");
	ok(proxysql_get_plugin_manager() == nullptr,
	   "after stop, the active pointer is cleared");
}

static void test_reload_replaces_previous_manager() {
	clear_log();
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> first { PROXYSQL_FAKE_PLUGIN_PATH };
	std::vector<std::string> second { PROXYSQL_FAKE_PLUGIN2_PATH };
	std::string err;

	ok(proxysql_load_configured_plugins(mgr, first, err) && proxysql_init_configured_plugins_compat(mgr.get(), err), "first load");
	ok(proxysql_start_configured_plugins(mgr.get(), err), "first start");

	// Reload with a different set; the helper must tear down the previous
	// manager (calling its destructor → no leaked plugin).
	ok(proxysql_load_configured_plugins(mgr, second, err) && proxysql_init_configured_plugins_compat(mgr.get(), err),
	   "reload with a different plugin set succeeds");
	ok(proxysql_start_configured_plugins(mgr.get(), err), "second start");
	ok(proxysql_stop_configured_plugins(mgr, err), "stop helper");

	std::string contents = read_log();
	ok(contents.find("fake_plugin:init\n") != std::string::npos &&
	   contents.find("fake_plugin:start\n") != std::string::npos &&
	   contents.find("fake_plugin:stop\n") != std::string::npos,
	   "first plugin saw a complete init/start/stop cycle (stop fired during reload)");
	ok(contents.find("fake_plugin2:init\n") != std::string::npos &&
	   contents.find("fake_plugin2:start\n") != std::string::npos &&
	   contents.find("fake_plugin2:stop\n") != std::string::npos,
	   "second plugin saw a complete init/start/stop cycle");
}

static void test_reload_to_empty() {
	clear_log();
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> first { PROXYSQL_FAKE_PLUGIN_PATH };
	std::vector<std::string> empty {};
	std::string err;

	ok(proxysql_load_configured_plugins(mgr, first, err) && proxysql_init_configured_plugins_compat(mgr.get(), err), "initial load");
	ok(proxysql_start_configured_plugins(mgr.get(), err), "initial start");
	ok(proxysql_load_configured_plugins(mgr, empty, err) && proxysql_init_configured_plugins_compat(mgr.get(), err),
	   "reload with empty plugin list succeeds");
	ok(mgr.get() == nullptr,
	   "empty reload nulls out the unique_ptr");
	ok(proxysql_get_plugin_manager() == nullptr,
	   "empty reload clears the active pointer too");

	std::string contents = read_log();
	ok(contents.find("fake_plugin:stop\n") != std::string::npos,
	   "previous plugin's stop ran during reload-to-empty");
}

static void test_load_partial_failure() {
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths {
		PROXYSQL_FAKE_PLUGIN_PATH,
		"/definitely/missing/plugin.so",
		PROXYSQL_FAKE_PLUGIN2_PATH
	};
	std::string err;
	ok(!proxysql_load_configured_plugins(mgr, paths, err),
	   "load fails because the second path is missing");
	ok(err.find("/definitely/missing/plugin.so") != std::string::npos,
	   "error names the missing path");
	ok(proxysql_get_plugin_manager() == nullptr,
	   "no active manager left behind after partial-load failure");
}

static void test_init_registration_failure_aborts_load() {
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_INVALID_TABLE", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
#ifdef PROXYSQL40
	// The fake plugin registers an invalid table from its init() callback
	// (Phase D), not register_schemas (Phase B). After the four-phase split,
	// load (Phase A+B) succeeds and the failure surfaces at init time.
	ok(proxysql_load_configured_plugins(mgr, paths, err),
	   "Phase A+B succeeds; the registration failure is in init, not register_schemas");
	ok(!proxysql_init_configured_plugins_compat(mgr.get(), err),
	   "init fails when plugin's init triggers a service-registration failure");
	ok(!err.empty(), "init helper reports a non-empty error");
#else
	// Pre-chassis: init runs inside proxysql_load_configured_plugins, so
	// the registration failure surfaces from the load helper directly.
	ok(!proxysql_load_configured_plugins(mgr, paths, err),
	   "load fails when plugin's init triggers a service-registration failure");
	ok(!err.empty(), "load helper reports a non-empty error");
#endif
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_INVALID_TABLE");
}

static void test_dispatch_via_active_manager() {
	clear_log();
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;

	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins_compat(mgr.get(), err),
	   "load with a plugin that registers an admin command");
	ok(proxysql_start_configured_plugins(mgr.get(), err),
	   "start publishes the configured plugin command table");

	ProxySQL_PluginCommandContext ctx { proxysql_plugin_get_admindb(),
	                                     proxysql_plugin_get_configdb(),
	                                     proxysql_plugin_get_statsdb() };
	ProxySQL_PluginCommandResult result {99, 0, ""};
	ok(proxysql_dispatch_configured_plugin_admin_command(ctx, "PLUGIN FAKE NOOP", result) &&
	   result.error_code == 0 &&
	   result.rows_affected == 1 &&
	   result.message == "fake command executed",
	   "active dispatch helper routes the command to the plugin");

	ok(proxysql_stop_configured_plugins(mgr, err),
	   "stop helper succeeds");
	ok(!proxysql_dispatch_configured_plugin_admin_command(ctx, "PLUGIN FAKE NOOP", result),
	   "after stop, dispatch helper returns false (no active manager)");
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND");
}

static void test_dispatch_with_no_active_manager() {
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::string err;
	(void)proxysql_stop_configured_plugins(mgr, err); // ensure null
	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };
	ProxySQL_PluginCommandResult result {99, 0, ""};
	ok(!proxysql_dispatch_configured_plugin_admin_command(ctx, "ANYTHING", result),
	   "dispatch helper returns false when no manager is active");
	ok(result.error_code == 99,
	   "dispatch leaves caller's result struct untouched on miss");
}

int main() {
#ifdef PROXYSQL40
	plan(49);  // PROXYSQL40: load succeeds; init fails separately (3 oks)
#else
	plan(47);  // Pre-chassis: load fails with init-side registration error (2 oks)
#endif
	make_log_path();

	test_config_parse_single();
	test_config_parse_multiple();
	test_config_parse_empty_array();
	test_config_no_plugins_directive();
	test_config_parse_skips_non_strings();
	test_load_missing_path_via_helper();
	test_lifecycle_logs_in_order();
	test_multi_lifecycle_logs_in_order();
	test_active_manager_visibility();
	test_reload_replaces_previous_manager();
	test_reload_to_empty();
	test_load_partial_failure();
	test_init_registration_failure_aborts_load();
	test_dispatch_via_active_manager();
	test_dispatch_with_no_active_manager();

	cleanup_log();
	return exit_status();
}
