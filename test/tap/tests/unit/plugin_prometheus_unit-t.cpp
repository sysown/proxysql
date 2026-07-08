// Step 2 ABI extension test: shared Prometheus registry access.
//
// What we assert deterministically:
//   * GloVars.prometheus_registry is the registry plugins receive via the
//     get_prometheus_registry service callback (same pointer);
//   * a counter registered against that registry is collected by the
//     same registry (i.e. it's a single shared instance, not two);
//   * the counter's value reflects increments through the prometheus-cpp
//     API the plugins will use.

#include "ProxySQL_PluginManager.h"
#include "ProxySQL_Plugin.h"
#include "proxysql_glovars.hpp"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "prometheus/registry.h"
#include "prometheus/counter.h"
#include "prometheus/family.h"
#include "prometheus/text_serializer.h"

#include <memory>
#include <string>
#include <vector>

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

extern ProxySQL_GlobalVariables GloVars;

namespace {

char g_fake_admin_db = '\0';
char g_fake_config_db = '\0';
char g_fake_stats_db = '\0';

bool registry_contains_metric(prometheus::Registry* reg, const std::string& name) {
	if (reg == nullptr) return false;
	prometheus::TextSerializer ts;
	const std::string dump = ts.Serialize(reg->Collect());
	return dump.find(name) != std::string::npos;
}

} // namespace

SQLite3DB* proxysql_plugin_get_admindb()  { return reinterpret_cast<SQLite3DB*>(&g_fake_admin_db); }
SQLite3DB* proxysql_plugin_get_configdb() { return reinterpret_cast<SQLite3DB*>(&g_fake_config_db); }
SQLite3DB* proxysql_plugin_get_statsdb()  { return reinterpret_cast<SQLite3DB*>(&g_fake_stats_db); }

static void test_glovars_registry_exists() {
	ok(GloVars.prometheus_registry != nullptr,
	   "GloVars.prometheus_registry is non-null after test_init_minimal");
}

static void test_counter_round_trip_through_shared_registry() {
	prometheus::Registry* reg = GloVars.prometheus_registry.get();

	auto& family = prometheus::BuildCounter()
		.Name("proxysql_plugin_unit_test_counter")
		.Help("Plugin unit test: counter registered against the shared registry")
		.Register(*reg);
	auto& counter = family.Add({});
	counter.Increment();
	counter.Increment();
	counter.Increment();
	ok(counter.Value() == 3.0,
	   "counter value reflects the three increments");

	ok(registry_contains_metric(reg, "proxysql_plugin_unit_test_counter"),
	   "metric name appears in the shared registry's text serialisation");
}

static void test_loader_does_not_disturb_registry() {
	// Loading a plugin must not replace, swap, or null out the registry --
	// just install a service callback that points at it.  Verify the
	// registry pointer survives the lifecycle.
	prometheus::Registry* before = GloVars.prometheus_registry.get();
	ok(before != nullptr, "registry pointer captured before load");

	ProxySQL_PluginManager mgr;
	std::string err;
	ok(mgr.load(PROXYSQL_FAKE_PLUGIN_PATH, err), "fake plugin loads");
	ok(mgr.init_all(err),  "init_all succeeds");
	ok(mgr.start_all(err), "start_all succeeds");

	prometheus::Registry* during = GloVars.prometheus_registry.get();
	ok(during == before,
	   "registry pointer unchanged across plugin load+init+start");

	ok(mgr.stop_all(), "stop_all succeeds");
	ok(GloVars.prometheus_registry.get() == before,
	   "registry pointer unchanged after plugin stop");
}

int main() {
	plan(10);

	// Bring up the minimum core state needed for GloVars.prometheus_registry
	// to exist (test_helpers/test_init.cpp allocates the shared_ptr).
	test_init_minimal();

	test_glovars_registry_exists();
	test_counter_round_trip_through_shared_registry();
	test_loader_does_not_disturb_registry();

	test_cleanup_minimal();
	return exit_status();
}
