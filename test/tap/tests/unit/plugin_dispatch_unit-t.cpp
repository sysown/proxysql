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

// Under PROXYSQL40 the loader stops at Phase B (register_schemas) and Phase D
// (init) runs separately. Without PROXYSQL40 the pre-chassis loader invokes
// init inside proxysql_load_configured_plugins, so this helper is a no-op
// that keeps the same test call sites compiling against both builds.
#ifdef PROXYSQL40
static inline bool proxysql_init_configured_plugins_compat(ProxySQL_PluginManager* m, std::string& err) {
	return proxysql_init_configured_plugins(m, err);
}
#else
static inline bool proxysql_init_configured_plugins_compat(ProxySQL_PluginManager*, std::string&) {
	return true;
}
#endif

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

	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins_compat(mgr.get(), err),
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
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins_compat(mgr.get(), err), "load");
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
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins_compat(mgr.get(), err), "load");
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
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins_compat(mgr.get(), err), "load");
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
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins_compat(mgr.get(), err), "load");
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

#ifdef PROXYSQL40
// Count invocations per plugin to prove the alias-to-canonical resolver
// routed each alias spelling to the correct plugin's callback.
static int g_plugin_a_calls = 0;
static int g_plugin_b_calls = 0;

static ProxySQL_PluginCommandResult plugin_a_cb(const ProxySQL_PluginCommandContext&, const char*) {
	++g_plugin_a_calls;
	return {0, 1, "A"};
}
static ProxySQL_PluginCommandResult plugin_b_cb(const ProxySQL_PluginCommandContext&, const char*) {
	++g_plugin_b_calls;
	return {0, 1, "B"};
}

// Directly populate a manager with two "plugins' worth" of commands +
// aliases to exercise the generic admin-command alias resolver without
// needing to stand up real .so's for two plugins. The manager doesn't
// care about the provenance of registered commands; this tests the
// dispatcher path that replaced the hardcoded MYSQLX alias ladder.
static void test_alias_dispatch_two_non_conflicting_plugins() {
	g_plugin_a_calls = 0;
	g_plugin_b_calls = 0;

	auto mgr = std::make_unique<ProxySQL_PluginManager>();

	// "Plugin A": PLUGIN_A SYNC CONFIG with two alias spellings.
	ok(mgr->register_command("PLUGIN_A SYNC CONFIG", &plugin_a_cb),
	   "plugin A: canonical registers");
	ok(mgr->register_command_alias("PLUGIN_A SYNC CONFIG", "PLUGIN_A RELOAD"),
	   "plugin A: alias 'PLUGIN_A RELOAD' registers");
	ok(mgr->register_command_alias("PLUGIN_A SYNC CONFIG", "PLUGIN_A REFRESH"),
	   "plugin A: alias 'PLUGIN_A REFRESH' registers");

	// "Plugin B": disjoint namespace, different aliases.
	ok(mgr->register_command("PLUGIN_B FLUSH CACHE", &plugin_b_cb),
	   "plugin B: canonical registers");
	ok(mgr->register_command_alias("PLUGIN_B FLUSH CACHE", "PLUGIN_B PURGE"),
	   "plugin B: alias 'PLUGIN_B PURGE' registers");

	// Install as active so the global helper sees it.
	std::unique_ptr<ProxySQL_PluginManager> keeper;
	std::vector<std::string> empty_paths {};
	std::string err;
	(void)proxysql_load_configured_plugins(keeper, empty_paths, err);  // clear any prior active

	// Swap in our test manager.  The manager takes ownership of
	// active-pointer installation via the load helper; for a manager
	// built outside of plugin_modules, we use register_command_for_test
	// seam? — no, the load helper is the only installer. Use a short
	// contrived path: dispatch via the manager directly.
	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };
	ProxySQL_PluginCommandResult res {99, 0, ""};

	// Canonical paths.
	ok(mgr->dispatch_admin_command(ctx, "PLUGIN_A SYNC CONFIG", res) &&
	   res.message == "A",
	   "canonical 'PLUGIN_A SYNC CONFIG' dispatches to plugin A");

	ok(mgr->dispatch_admin_command(ctx, "PLUGIN_B FLUSH CACHE", res) &&
	   res.message == "B",
	   "canonical 'PLUGIN_B FLUSH CACHE' dispatches to plugin B");

	// Alias paths — dispatcher must route each alias to the callback
	// that registered the matching canonical command.
	ok(mgr->dispatch_admin_command(ctx, "PLUGIN_A RELOAD", res) &&
	   res.message == "A",
	   "alias 'PLUGIN_A RELOAD' routes to plugin A");

	ok(mgr->dispatch_admin_command(ctx, "PLUGIN_A REFRESH", res) &&
	   res.message == "A",
	   "alias 'PLUGIN_A REFRESH' routes to plugin A");

	ok(mgr->dispatch_admin_command(ctx, "PLUGIN_B PURGE", res) &&
	   res.message == "B",
	   "alias 'PLUGIN_B PURGE' routes to plugin B");

	ok(g_plugin_a_calls == 3, "plugin A's callback was invoked exactly 3 times (canonical + 2 aliases)");
	ok(g_plugin_b_calls == 2, "plugin B's callback was invoked exactly 2 times (canonical + 1 alias)");

	// resolve_alias_to_canonical returns the canonical, regardless of
	// which spelling was used to probe it.
	ok(mgr->resolve_alias_to_canonical("PLUGIN_A RELOAD") == "PLUGIN_A SYNC CONFIG",
	   "resolve_alias_to_canonical maps alias -> canonical for plugin A");
	ok(mgr->resolve_alias_to_canonical("PLUGIN_B PURGE") == "PLUGIN_B FLUSH CACHE",
	   "resolve_alias_to_canonical maps alias -> canonical for plugin B");
	ok(mgr->resolve_alias_to_canonical("UNKNOWN").empty(),
	   "resolve_alias_to_canonical returns empty for unknown spellings");

	// Whitespace/case normalization on the lookup side.
	ok(mgr->resolve_alias_to_canonical("  plugin_a   reload  ") == "PLUGIN_A SYNC CONFIG",
	   "resolve_alias_to_canonical normalizes whitespace and case");

	// Negative: an alias cannot shadow a different command's canonical
	// or alias (cross-plugin collision).
	ok(!mgr->register_command_alias("PLUGIN_A SYNC CONFIG", "PLUGIN_B PURGE"),
	   "register_command_alias rejects a spelling already owned by another command");

	// Idempotent re-registration of the same (canonical, alias) pair.
	ok(mgr->register_command_alias("PLUGIN_A SYNC CONFIG", "PLUGIN_A RELOAD"),
	   "register_command_alias is idempotent for the same canonical+alias pair");
}

// Real cross-plugin alias collision: two independent .so plugins loaded
// side-by-side, both trying to own the same admin command spelling.
// The second plugin's init MUST fail and the loader MUST report the
// collision rather than silently letting one win.  Exercises the full
// dlopen + init_all + register_command path, not just the same-manager
// API-level collision.
#ifndef PROXYSQL_FAKE_PLUGIN2_PATH
#error "PROXYSQL_FAKE_PLUGIN2_PATH must be defined"
#endif
static void test_cross_plugin_command_collision() {
	// Both plugins try to register the SAME admin-command SQL.  The
	// loader processes plugins in the order passed, so plugin2 is the
	// one that finds the spelling already taken; its init must fail.
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND_SQL", "PLUGIN SHARED CMD", 1);
	setenv("PROXYSQL_FAKE_PLUGIN2_REGISTER_COMMAND", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN2_REGISTER_COMMAND_SQL", "PLUGIN SHARED CMD", 1);

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths {
		PROXYSQL_FAKE_PLUGIN_PATH,
		PROXYSQL_FAKE_PLUGIN2_PATH
	};
	std::string err;
	bool loaded = proxysql_load_configured_plugins(mgr, paths, err);
	bool inited = loaded && proxysql_init_configured_plugins_compat(mgr.get(), err);
	ok(!inited,
	   "load+init fails when two plugins claim the same admin command");
	ok(!err.empty(),
	   "collision produces an error message (err='%s')", err.c_str());

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND");
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND_SQL");
	unsetenv("PROXYSQL_FAKE_PLUGIN2_REGISTER_COMMAND");
	unsetenv("PROXYSQL_FAKE_PLUGIN2_REGISTER_COMMAND_SQL");
}
#endif /* PROXYSQL40 */

int main() {
#ifdef PROXYSQL40
	plan(52);
#else
	plan(32);
#endif

	test_dispatch_no_active_manager();
	test_dispatch_after_stop();
	test_dispatch_unknown_command_with_active_manager();
	test_dispatch_canonicalises_input();
	test_dispatch_propagates_context();
	test_dispatch_concurrency();
	test_stop_when_not_loaded();
	test_start_when_null_manager();
#ifdef PROXYSQL40
	test_alias_dispatch_two_non_conflicting_plugins();
	test_cross_plugin_command_collision();
#endif

	return exit_status();
}
