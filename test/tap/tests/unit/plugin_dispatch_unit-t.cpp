// Focused tests for the global dispatch helpers
// (proxysql_dispatch_configured_plugin_admin_command and friends), exercising
// the active-manager indirection that the admin handler relies on.

#include "ProxySQL_PluginManager.h"
#include "ProxySQL_Plugin.h"
#include "tap.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

namespace {

char g_fake_admin_db = '\0';
char g_fake_config_db = '\0';
char g_fake_stats_db = '\0';

} // namespace

SQLite3DB* proxysql_plugin_get_admindb() { return reinterpret_cast<SQLite3DB*>(&g_fake_admin_db); }
SQLite3DB* proxysql_plugin_get_configdb() { return reinterpret_cast<SQLite3DB*>(&g_fake_config_db); }
SQLite3DB* proxysql_plugin_get_statsdb() { return reinterpret_cast<SQLite3DB*>(&g_fake_stats_db); }

static void test_dispatch_no_active_manager() {
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::string err;
	(void)proxysql_stop_configured_plugins(mgr, err); // ensure cleared

	ok(proxysql_get_plugin_manager() == nullptr,
	   "global manager starts null");

	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };
	ProxySQL_PluginCommandResult res {77, 0, ""};
	ok(!proxysql_dispatch_configured_plugin_admin_command(ctx, "ANY SQL", res),
	   "dispatch returns false when no manager is active");
	ok(res.error_code == 77,
	   "dispatch leaves caller's result struct untouched");
}

static void test_dispatch_after_stop() {
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;

	ok(proxysql_load_configured_plugins(mgr, paths, err),
	   "load helper succeeds");
	ok(proxysql_start_configured_plugins(mgr.get(), err),
	   "start helper succeeds");

	ProxySQL_PluginCommandContext ctx { proxysql_plugin_get_admindb(),
	                                     proxysql_plugin_get_configdb(),
	                                     proxysql_plugin_get_statsdb() };
	ProxySQL_PluginCommandResult res {99, 0, ""};
	ok(proxysql_dispatch_configured_plugin_admin_command(ctx, "PLUGIN FAKE NOOP", res),
	   "dispatch routes to the plugin while manager is active");

	ok(proxysql_stop_configured_plugins(mgr, err),
	   "stop helper succeeds");

	ProxySQL_PluginCommandResult after {99, 0, ""};
	ok(!proxysql_dispatch_configured_plugin_admin_command(ctx, "PLUGIN FAKE NOOP", after),
	   "dispatch returns false after stop (active manager cleared)");
	ok(proxysql_get_plugin_manager() == nullptr,
	   "global manager reports null after stop");

	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND");
}

static void test_dispatch_unknown_command_with_active_manager() {
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err), "load");
	ok(proxysql_start_configured_plugins(mgr.get(), err), "start");

	ProxySQL_PluginCommandContext ctx { proxysql_plugin_get_admindb(),
	                                     proxysql_plugin_get_configdb(),
	                                     proxysql_plugin_get_statsdb() };
	ProxySQL_PluginCommandResult res {88, 0, "unchanged"};
	ok(!proxysql_dispatch_configured_plugin_admin_command(ctx, "TOTALLY UNKNOWN COMMAND", res),
	   "unknown command returns false even with active manager");
	ok(res.error_code == 88 && res.message == "unchanged",
	   "result struct untouched on unknown-command miss");

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND");
}

static void test_dispatch_canonicalises_input() {
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err), "load");
	ok(proxysql_start_configured_plugins(mgr.get(), err), "start");

	ProxySQL_PluginCommandContext ctx { proxysql_plugin_get_admindb(),
	                                     proxysql_plugin_get_configdb(),
	                                     proxysql_plugin_get_statsdb() };

	const char* variants[] = {
		"PLUGIN FAKE NOOP",
		"  PLUGIN FAKE NOOP  ",
		"PLUGIN FAKE NOOP;",
		"PLUGIN  FAKE  NOOP ; ;",
		"plugin fake noop",
		"PluGiN fAkE nOoP",
	};
	for (const char* v : variants) {
		ProxySQL_PluginCommandResult r {99, 0, ""};
		ok(proxysql_dispatch_configured_plugin_admin_command(ctx, v, r) && r.error_code == 0,
		   "dispatch canonicalises: %s", v);
	}

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND");
}

static void test_dispatch_propagates_context() {
	// The fake plugin's command callback ignores its context, but the
	// dispatcher must still pass our context through (verified separately
	// by reaching the plugin and getting a successful result).
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err), "load");
	ok(proxysql_start_configured_plugins(mgr.get(), err), "start");

	// Use a context with all-null DB pointers; dispatch should still work.
	ProxySQL_PluginCommandContext null_ctx { nullptr, nullptr, nullptr };
	ProxySQL_PluginCommandResult r {99, 0, ""};
	ok(proxysql_dispatch_configured_plugin_admin_command(null_ctx, "PLUGIN FAKE NOOP", r) &&
	   r.error_code == 0,
	   "dispatch tolerates a null-handle context (callback chooses what to do with it)");

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND");
}

static void test_dispatch_concurrency() {
	// Smoke test: many concurrent dispatches against a stable active manager
	// must not crash, deadlock, or return false.  We don't make claims about
	// throughput — only correctness.
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err), "load");
	ok(proxysql_start_configured_plugins(mgr.get(), err), "start");

	ProxySQL_PluginCommandContext ctx { proxysql_plugin_get_admindb(),
	                                     proxysql_plugin_get_configdb(),
	                                     proxysql_plugin_get_statsdb() };

	std::atomic<int> succeeded {0};
	std::atomic<int> failed {0};
	const int n_threads = 8;
	const int per_thread = 250;
	std::vector<std::thread> threads;
	threads.reserve(n_threads);
	for (int t = 0; t < n_threads; ++t) {
		threads.emplace_back([&]() {
			for (int i = 0; i < per_thread; ++i) {
				ProxySQL_PluginCommandResult r {99, 0, ""};
				if (proxysql_dispatch_configured_plugin_admin_command(ctx, "PLUGIN FAKE NOOP", r) &&
				    r.error_code == 0) {
					++succeeded;
				} else {
					++failed;
				}
			}
		});
	}
	for (auto& th : threads) th.join();

	ok(succeeded.load() == n_threads * per_thread,
	   "all %d concurrent dispatches succeeded", n_threads * per_thread);
	ok(failed.load() == 0,
	   "no concurrent dispatch reported failure");

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND");
}

static void test_stop_when_not_loaded() {
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::string err;
	ok(proxysql_stop_configured_plugins(mgr, err),
	   "stop helper on a null unique_ptr is a safe no-op");
	ok(err.empty(), "stop helper leaves err empty when there's nothing to stop");
}

static void test_start_when_null_manager() {
	std::string err;
	ok(proxysql_start_configured_plugins(nullptr, err),
	   "start helper on a null manager is a safe no-op");
	ok(err.empty(), "start helper leaves err empty when there's nothing to start");
}

int main() {
	plan(32);

	test_dispatch_no_active_manager();
	test_dispatch_after_stop();
	test_dispatch_unknown_command_with_active_manager();
	test_dispatch_canonicalises_input();
	test_dispatch_propagates_context();
	test_dispatch_concurrency();
	test_stop_when_not_loaded();
	test_start_when_null_manager();

	return exit_status();
}
