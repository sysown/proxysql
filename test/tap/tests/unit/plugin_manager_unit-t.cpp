#include "tap.h"
#include "ProxySQL_PluginManager.h"

#include <string>

static void test_loader_round_trip() {
	ProxySQL_PluginManager mgr;
	std::string err;

	ok(mgr.load("../../test_helpers/libproxysql_fake_plugin.so", err),
	   "load fake plugin succeeds");
	ok(mgr.size() == 1, "exactly one plugin is loaded");
	ok(mgr.init_all(err), "init_all succeeds");
	ok(mgr.start_all(err), "start_all succeeds");
	ok(mgr.stop_all(), "stop_all succeeds");
}

int main() {
	plan(5);

	test_loader_round_trip();

	return exit_status();
}
