#include "tap.h"
#include "ProxySQL_PluginManager.h"

#include <string>

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

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
	ok(mgr.start_all(err), "start_all succeeds");
	ok(mgr.stop_all(), "stop_all succeeds");
}

int main() {
	plan(7);

	test_loader_round_trip();

	return exit_status();
}
