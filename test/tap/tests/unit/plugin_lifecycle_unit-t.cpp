// Step 2.2 (chassis): four-phase plugin lifecycle test.
//
// Exercises the new register_schemas (Phase B) ABI field and verifies:
//   * both register_schemas and init run when the plugin sets both;
//     register_schemas runs first, init second (ordering contract).
//   * plugins with a null register_schemas field skip Phase B and go
//     straight to init (pre-existing two-phase behavior preserved).
//   * during Phase B, the DB handle getters in services return nullptr.
//     Plugins that call them observe null and must handle it.
//
// The fake_plugin.cpp test helper is the plugin under test; it selects
// between two static ProxySQL_PluginDescriptor layouts based on the
// PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B env var, mirroring the descriptor-
// version-selection pattern a real plugin would use.

#include "ProxySQL_PluginManager.h"
#include "ProxySQL_Plugin.h"
#include "tap.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

namespace {

char g_fake_admin_db  = '\0';
char g_fake_config_db = '\0';
char g_fake_stats_db  = '\0';

std::string g_log_path {};

void make_log_path() {
	char tpl[] = "/tmp/proxysql_plugin_lifecycle_log.XXXXXX";
	int fd = mkstemp(tpl);
	if (fd >= 0) close(fd);
	g_log_path = tpl;
	setenv("PROXYSQL_FAKE_PLUGIN_LOG", g_log_path.c_str(), 1);
}

void clear_log() {
	if (g_log_path.empty()) return;
	std::ofstream(g_log_path, std::ios::trunc);
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
}

bool contains_in_order(const std::string& haystack, const char* first, const char* second) {
	size_t pos_first = haystack.find(first);
	if (pos_first == std::string::npos) return false;
	size_t pos_second = haystack.find(second, pos_first + 1);
	return pos_second != std::string::npos;
}

} // namespace

// Symbols the plugin manager pulls from the core.  In this test harness we
// hand it fake, non-null pointers so init() sees "live" handles -- which
// is what matters for the contrast against Phase B's nullptrs.
SQLite3DB* proxysql_plugin_get_admindb()  { return reinterpret_cast<SQLite3DB*>(&g_fake_admin_db); }
SQLite3DB* proxysql_plugin_get_configdb() { return reinterpret_cast<SQLite3DB*>(&g_fake_config_db); }
SQLite3DB* proxysql_plugin_get_statsdb()  { return reinterpret_cast<SQLite3DB*>(&g_fake_stats_db); }

// Case 1: plugin sets both register_schemas AND init.  Both must fire.
// register_schemas must fire strictly before init (the lifecycle contract
// that lets plugins count on admin module materialization between them).
static void test_phase_b_and_init_both_fire() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins(mgr.get(), err),
	   "load-then-register_schemas-then-init succeeds (err='%s')", err.c_str());

	const std::string log = read_log();
	ok(log.find("fake_plugin:phase_b") != std::string::npos,
	   "register_schemas callback fired (log contains phase_b marker)");
	ok(log.find("fake_plugin:init") != std::string::npos,
	   "init callback fired (log contains init marker)");
	ok(contains_in_order(log, "fake_plugin:phase_b", "fake_plugin:init"),
	   "register_schemas ran strictly before init");

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
}

// Case 2: plugin sets only init (register_schemas field is null).
// Phase B is skipped; init still runs.  This is the compat path for
// plugins built against the pre-2.2 descriptor layout.
static void test_only_init_skips_phase_b() {
	// ENABLE_PHASE_B unset -> descriptor returned omits register_schemas.
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins(mgr.get(), err),
	   "load+init succeeds with no register_schemas set (err='%s')", err.c_str());

	const std::string log = read_log();
	ok(log.find("fake_plugin:phase_b") == std::string::npos,
	   "register_schemas NOT invoked when descriptor field is null");
	ok(log.find("fake_plugin:init") != std::string::npos,
	   "init still fires on the legacy two-phase path");

	(void)proxysql_stop_configured_plugins(mgr, err);
}

// Case 3: register_schemas tries to call DB handle getters.  The loader
// passes a services struct whose DB-handle getters are stubs returning
// nullptr.  The plugin logs which it observed; we assert it saw null.
// This pins down the lifecycle contract that the spec requires plugins
// to respect.
static void test_phase_b_db_handles_are_null() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_TOUCH_HANDLES", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins(mgr.get(), err),
	   "load succeeds even though plugin peeked at DB handles in Phase B");

	const std::string log = read_log();
	ok(log.find("fake_plugin:phase_b_handles_null") != std::string::npos,
	   "DB handle getters returned nullptr during register_schemas (log='%s')",
	   log.c_str());
	ok(log.find("fake_plugin:phase_b_handles_live") == std::string::npos,
	   "DB handles were NOT live during Phase B (contract)");

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_TOUCH_HANDLES");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
}

// Case 4: a failing register_schemas aborts the load and init() is NOT
// called.  Verifies the loader treats Phase-B failure as a hard error.
static void test_phase_b_failure_aborts_init() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_FAIL", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(!proxysql_load_configured_plugins(mgr, paths, err),
	   "load fails when register_schemas returns false");
	ok(!err.empty() && err.find("register_schemas") != std::string::npos,
	   "error message names the failing phase (err='%s')", err.c_str());

	const std::string log = read_log();
	ok(log.find("fake_plugin:phase_b_fail") != std::string::npos,
	   "register_schemas actually ran and logged its failure");
	ok(log.find("fake_plugin:init") == std::string::npos,
	   "init was NOT called after register_schemas failed");

	unsetenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_FAIL");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
}

int main() {
	plan(14);

	make_log_path();

	test_phase_b_and_init_both_fire();
	test_only_init_skips_phase_b();
	test_phase_b_db_handles_are_null();
	test_phase_b_failure_aborts_init();

	cleanup_log();
	return exit_status();
}
