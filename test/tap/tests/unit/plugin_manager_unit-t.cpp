#include "tap.h"
#include "ProxySQL_PluginManager.h"

#include <string>
#include <unistd.h>

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

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

static void test_loader_round_trip() {
	ProxySQL_PluginManager mgr;
	std::string err;

	const bool loaded = mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err);
	ok(loaded,
	   "load fake plugin succeeds");
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
		ProxySQL_PluginManager mgr;
		ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err) &&
		   mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err) &&
		   mgr.size() == 2,
		   "loading same plugin twice succeeds and size is 2");
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
		ProxySQL_PluginManager mgr;
		mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err);
		mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err);
		ok(mgr.init_all(err) && mgr.start_all(err) && mgr.stop_all() && mgr.size() == 2,
		   "full lifecycle with two plugins succeeds");
	}
}

int main() {
	plan(20);

	test_loader_round_trip();
	test_load_error_cases();
	test_lifecycle_edge_cases();

	return exit_status();
}
