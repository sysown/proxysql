#include "tap.h"
#include "ProxySQL_PluginManager.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <unistd.h>
#include <vector>

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
	char tpl[] = "/tmp/proxysql_plugin_mgr_log.XXXXXX";
	int fd = mkstemp(tpl);
	if (fd >= 0) close(fd);
	g_log_path = tpl;
	setenv("PROXYSQL_FAKE_PLUGIN_LOG", g_log_path.c_str(), 1);
	setenv("PROXYSQL_FAKE_PLUGIN2_LOG", g_log_path.c_str(), 1);
}

void clear_log() {
	if (g_log_path.empty()) return;
	// Truncate via constructor + immediate destructor.  The named local
	// variable is intentional: SonarCloud's "Name this unused temporary
	// object" rule does not recognise the truncate-via-temporary idiom,
	// and the cosmetic name silences the false positive without changing
	// behaviour.
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

static void test_loader_round_trip() {
	ProxySQL_PluginManager mgr;
	std::string err;

	const bool loaded = mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err);
	ok(loaded, "load fake plugin succeeds");
	if (!loaded) {
		diag("load error: %s", err.c_str());
		BAIL_OUT("fake plugin must load before lifecycle assertions");
	}
	ok(mgr.size() == 1, "exactly one plugin is loaded");
	ok(!mgr.start_all(err), "start_all rejects uninitialized plugins");
	ok(!err.empty(), "start_all without init reports an error");
	ok(mgr.init_all(err), "init_all succeeds");
	ok(mgr.start_all(err), "start_all succeeds once DB handle callbacks are available");
	ok(mgr.stop_all(), "stop_all succeeds");
}

static void test_load_error_cases() {
	std::string err;

	{
		ProxySQL_PluginManager mgr;
		ok(!mgr.load("", err) && !err.empty(),
		   "load with empty path returns false with error");
	}

	{
		char tmp_template[] = "/tmp/proxysql_test_text.XXXXXX";
		int fd = mkstemp(tmp_template);
		write(fd, "hello", 5);
		close(fd);
		ProxySQL_PluginManager mgr;
		bool result = mgr.load(std::string(tmp_template), err);
		unlink(tmp_template);
		ok(!result && !err.empty(),
		   "load of non-shared-object file returns false with dlopen error");
	}

	{
		// v3.0 rejects duplicate-path loads.  The rejection message must
		// identify the condition ("already loaded") so operators can tell
		// this apart from other load failures.
		ProxySQL_PluginManager mgr;
		ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err) &&
		   !mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err) &&
		   err.find("already loaded") != std::string::npos &&
		   mgr.size() == 1,
		   "second load of same path is rejected with 'already loaded' (size stays 1)");
	}

	{
		ProxySQL_PluginManager mgr;
		ok(mgr.init_all(err) && err.empty(),
		   "init_all with empty manager returns true with no error");
		ok(mgr.start_all(err),
		   "start_all with empty manager returns true");
		ok(mgr.stop_all(),
		   "stop_all with empty manager returns true");
	}

	{
		ProxySQL_PluginManager mgr;
		ok(!mgr.load("/definitely/does/not/exist/plugin.so", err) && !err.empty(),
		   "load of non-existent path returns false with useful error");
	}
}

static void test_lifecycle_edge_cases() {
	std::string err;

	{
		ProxySQL_PluginManager mgr;
		mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err);
		mgr.init_all(err);
		ok(mgr.stop_all(),
		   "stop_all before start_all returns true (idempotent)");
	}

	{
		ProxySQL_PluginManager mgr;
		mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err);
		mgr.init_all(err);
		ok(mgr.init_all(err),
		   "init_all called twice returns true");
	}

	{
		ProxySQL_PluginManager mgr;
		mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err);
		ok(mgr.init_all(err) && mgr.start_all(err) && mgr.stop_all(),
		   "full init/start/stop lifecycle succeeds with real fake plugin");
	}

	{
		{
			ProxySQL_PluginManager mgr;
			mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err);
			mgr.init_all(err);
			mgr.start_all(err);
		}
		ok(true, "destructor with started plugin does not crash");
	}

	{
		ProxySQL_PluginManager mgr;
		mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err);
		mgr.init_all(err);
		mgr.start_all(err);
		mgr.stop_all();
		ok(mgr.init_all(err),
		   "init_all after stop_all returns true");
	}

	{
		// Two-plugin lifecycle now requires two distinct paths (the loader
		// rejects same-path duplicates).  fake_plugin + fake_plugin2 are
		// built from the same source with different FAKE_PLUGIN_NAME.
		ProxySQL_PluginManager mgr;
		mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err);
		mgr.load(PROXYSQL_FAKE_PLUGIN2_PATH, err);
		ok(mgr.init_all(err) && mgr.start_all(err) && mgr.stop_all() && mgr.size() == 2,
		   "full lifecycle with two plugins succeeds");
	}
}

static void test_init_failure() {
	setenv("PROXYSQL_FAKE_PLUGIN_INIT_FAIL", "1", 1);
	ProxySQL_PluginManager mgr;
	std::string err;

	ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "plugin loads before init failure test");
	ok(!mgr.init_all(err), "init_all returns false when plugin init fails");
	ok(!err.empty(), "init failure reports an error string");
	ok(err.find("fake_plugin") != std::string::npos,
	   "init error message identifies the failing plugin");

	unsetenv("PROXYSQL_FAKE_PLUGIN_INIT_FAIL");
}

static void test_start_failure() {
	setenv("PROXYSQL_FAKE_PLUGIN_START_FAIL", "1", 1);
	ProxySQL_PluginManager mgr;
	std::string err;

	ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "plugin loads before start failure test");
	ok(mgr.init_all(err), "init_all succeeds before start failure test");
	ok(!mgr.start_all(err), "start_all returns false when plugin start fails");
	ok(!err.empty(), "start failure reports an error string");
	ok(err.find("fake_plugin") != std::string::npos,
	   "start error message identifies the failing plugin");

	unsetenv("PROXYSQL_FAKE_PLUGIN_START_FAIL");
}

static void test_stop_failure() {
	setenv("PROXYSQL_FAKE_PLUGIN_STOP_FAIL", "1", 1);
	ProxySQL_PluginManager mgr;
	std::string err;

	ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "plugin loads before stop failure test");
	ok(mgr.init_all(err), "init_all succeeds before stop failure test");
	ok(mgr.start_all(err), "start_all succeeds before stop failure test");
	ok(!mgr.stop_all(), "stop_all returns false when plugin stop fails");

	unsetenv("PROXYSQL_FAKE_PLUGIN_STOP_FAIL");
}

static void test_double_load_rejected() {
	// Two distinct-path loads are the supported multi-plugin path; a
	// second load of the SAME path is rejected and leaves the manager's
	// state unchanged so the original handle is still usable.
	ProxySQL_PluginManager mgr;
	std::string err;

	ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "first load succeeds");
	ok(!mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err),
	   "second load of same path is rejected");
	ok(err.find("already loaded") != std::string::npos,
	   "rejection error mentions 'already loaded'");
	ok(mgr.size() == 1, "size remains 1 after rejected duplicate load");

	err.clear();
	ok(mgr.init_all(err) && mgr.start_all(err),
	   "init_all + start_all succeed on the surviving single handle");
	ok(mgr.stop_all(), "stop_all succeeds on the surviving single handle");
}

static void test_load_missing_path() {
	ProxySQL_PluginManager mgr;
	std::string err;
	ok(!mgr.load("/definitely/missing/plugin.so", err),
	   "load fails for missing path");
	ok(!err.empty(), "missing path failure reports a non-empty error");
	ok(err.find("dlopen") != std::string::npos,
	   "missing path error mentions dlopen");
	ok(mgr.size() == 0, "size remains 0 after failed load");
}

static void test_empty_manager_lifecycle() {
	ProxySQL_PluginManager mgr;
	std::string err;
	ok(mgr.size() == 0, "empty manager has size 0");
	ok(mgr.init_all(err), "init_all on empty manager succeeds");
	ok(err.empty(), "empty init_all leaves err empty");
	ok(mgr.start_all(err), "start_all on empty manager succeeds");
	ok(mgr.stop_all(), "stop_all on empty manager succeeds");
}

static void test_idempotent_init_start_stop() {
	ProxySQL_PluginManager mgr;
	std::string err;
	ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "plugin loads");
	ok(mgr.init_all(err), "first init_all succeeds");
	ok(mgr.init_all(err), "second init_all is a no-op (already initialized)");
	ok(mgr.start_all(err), "first start_all succeeds");
	ok(mgr.start_all(err), "second start_all is a no-op (already started)");
	ok(mgr.stop_all(), "first stop_all succeeds");
	ok(mgr.stop_all(), "second stop_all is a no-op (already stopped)");
}

static void test_destructor_stops_started_plugins() {
	clear_log();
	{
		ProxySQL_PluginManager mgr;
		std::string err;
		ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "plugin loads");
		ok(mgr.init_all(err), "init_all succeeds");
		ok(mgr.start_all(err), "start_all succeeds");
		// no explicit stop_all — destructor must do it
	}
	std::string contents = read_log();
	ok(contents.find("fake_plugin:stop") != std::string::npos,
	   "destructor invokes stop on started plugins");
}

static void test_destructor_skips_unstarted_plugins() {
	clear_log();
	{
		ProxySQL_PluginManager mgr;
		std::string err;
		ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "plugin loads");
		ok(mgr.init_all(err), "init_all succeeds");
		// destruct without start
	}
	std::string contents = read_log();
	// Per the init/stop pairing contract introduced in commit ab9d5a103,
	// stop() runs for every plugin where init() succeeded — irrespective
	// of whether start() ran. Otherwise resources allocated in init()
	// would leak. The previous version of this assertion encoded the
	// older "skip-unstarted" contract and was a leak.
	ok(contents.find("fake_plugin:stop") != std::string::npos,
	   "destructor invokes stop on init-succeeded/never-started plugin (init/stop pairing)");
}

static void test_destructor_no_double_stop() {
	clear_log();
	{
		ProxySQL_PluginManager mgr;
		std::string err;
		ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "plugin loads");
		ok(mgr.init_all(err), "init succeeds");
		ok(mgr.start_all(err), "start succeeds");
		ok(mgr.stop_all(), "explicit stop succeeds");
	}
	std::string contents = read_log();
	int stops = 0;
	size_t pos = 0;
	while ((pos = contents.find("fake_plugin:stop", pos)) != std::string::npos) {
		++stops;
		pos += 1;
	}
	ok(stops == 1, "stop runs exactly once even when destructor follows explicit stop_all (got %d)", stops);
}

static void test_multi_plugin_lifecycle_order() {
	clear_log();
	ProxySQL_PluginManager mgr;
	std::string err;
	ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "load fake_plugin");
	ok(mgr.load(PROXYSQL_FAKE_PLUGIN2_PATH, err), "load fake_plugin2");
	ok(mgr.init_all(err), "init_all succeeds for both plugins");
	ok(mgr.start_all(err), "start_all succeeds for both plugins");
	ok(mgr.stop_all(), "stop_all succeeds for both plugins");

	std::string contents = read_log();
	const std::string expected =
		"fake_plugin:init\n"
		"fake_plugin2:init\n"
		"fake_plugin:start\n"
		"fake_plugin2:start\n"
		"fake_plugin2:stop\n"
		"fake_plugin:stop\n";
	ok(contents == expected,
	   "init/start happen in registration order; stop runs in reverse order (got: '%s')",
	   contents.c_str());
}

static void test_multi_plugin_init_failure_short_circuits() {
	clear_log();
	setenv("PROXYSQL_FAKE_PLUGIN2_INIT_FAIL", "1", 1);
	{
		ProxySQL_PluginManager mgr;
		std::string err;
		ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "load first plugin");
		ok(mgr.load(PROXYSQL_FAKE_PLUGIN2_PATH, err), "load second plugin");
		ok(!mgr.init_all(err), "init_all returns false because the second plugin's init fails");
		ok(err.find("fake_plugin2") != std::string::npos,
		   "init failure error names the failing plugin (second one)");
	}
	std::string contents = read_log();
	ok(contents.find("fake_plugin:init\n") != std::string::npos,
	   "first plugin's init ran before the failure");
	ok(contents.find("fake_plugin2:init_fail\n") != std::string::npos,
	   "second plugin's init ran and reported failure");
	ok(contents.find("fake_plugin:start") == std::string::npos &&
	   contents.find("fake_plugin2:start") == std::string::npos,
	   "no start was attempted after init failure");
	unsetenv("PROXYSQL_FAKE_PLUGIN2_INIT_FAIL");
}

static void test_multi_plugin_start_failure_stops_started() {
	clear_log();
	setenv("PROXYSQL_FAKE_PLUGIN2_START_FAIL", "1", 1);
	{
		ProxySQL_PluginManager mgr;
		std::string err;
		ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "load first plugin");
		ok(mgr.load(PROXYSQL_FAKE_PLUGIN2_PATH, err), "load second plugin");
		ok(mgr.init_all(err), "init_all succeeds");
		ok(!mgr.start_all(err), "start_all fails because second plugin's start fails");
		// destructor runs, must stop only the started plugin (the first one)
	}
	std::string contents = read_log();
	ok(contents.find("fake_plugin:start\n") != std::string::npos,
	   "first plugin started before the failure");
	ok(contents.find("fake_plugin2:start_fail\n") != std::string::npos,
	   "second plugin start reported failure");
	ok(contents.find("fake_plugin:stop\n") != std::string::npos,
	   "destructor stopped the first plugin (which had successfully started)");
	// Per the init/stop pairing contract (ab9d5a103): stop() pairs with
	// init(), NOT with start(). The second plugin's init() succeeded;
	// only its start() failed. Resources acquired in its init() must be
	// released, so destructor MUST call stop on it too.
	ok(contents.find("fake_plugin2:stop") != std::string::npos,
	   "destructor stops the second plugin too — init succeeded, start failed (init/stop pairing)");
	unsetenv("PROXYSQL_FAKE_PLUGIN2_START_FAIL");
}

static void test_register_command_failure_in_init_aborts() {
	// Two DIFFERENT plugins both ask to register "PLUGIN FAKE NOOP"
	// (the default SQL used by the fake helper when REGISTER_COMMAND is
	// set).  The second registration collides → init_all reports error.
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN2_REGISTER_COMMAND", "1", 1);
	ProxySQL_PluginManager mgr;
	std::string err;
	ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "load fake_plugin");
	ok(mgr.load(PROXYSQL_FAKE_PLUGIN2_PATH, err), "load fake_plugin2");
	ok(!mgr.init_all(err),
	   "init_all fails when two plugins register the same command");
	ok(!err.empty(), "registration failure surfaces an error");
	ok(err.find("plugin command registration failed") != std::string::npos,
	   "error message identifies command registration as the failing operation");
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND");
	unsetenv("PROXYSQL_FAKE_PLUGIN2_REGISTER_COMMAND");
}

static void test_register_table_invalid_kind_in_init_aborts() {
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_INVALID_TABLE", "1", 1);
	ProxySQL_PluginManager mgr;
	std::string err;
	ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "load");
	ok(!mgr.init_all(err),
	   "init_all fails when register_table is called with an invalid db_kind");
	ok(err.find("plugin table registration failed") != std::string::npos,
	   "error message identifies table registration as the failing operation");
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_INVALID_TABLE");
}

int main() {
	plan(96);
	make_log_path();

	test_loader_round_trip();
	test_load_error_cases();
	test_lifecycle_edge_cases();
	test_init_failure();
	test_start_failure();
	test_stop_failure();
	test_double_load_rejected();
	test_load_missing_path();
	test_empty_manager_lifecycle();
	test_idempotent_init_start_stop();
	test_destructor_stops_started_plugins();
	test_destructor_skips_unstarted_plugins();
	test_destructor_no_double_stop();
	test_multi_plugin_lifecycle_order();
	test_multi_plugin_init_failure_short_circuits();
	test_multi_plugin_start_failure_stops_started();
	test_register_command_failure_in_init_aborts();
	test_register_table_invalid_kind_in_init_aborts();

	cleanup_log();
	return exit_status();
}
