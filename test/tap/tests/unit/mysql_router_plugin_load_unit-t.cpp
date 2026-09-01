#include "tap.h"

#include "ProxySQL_Plugin.h"
#include "ProxySQL_PluginManager.h"
#include "proxysql_glovars.hpp"
#include "test_init.h"

#include "prometheus/text_serializer.h"
#include <json.hpp>

#include <dlfcn.h>

#include <memory>
#include <string>

extern ProxySQL_GlobalVariables GloVars;

#ifndef PROXYSQL_MYSQL_ROUTER_PLUGIN_PATH
#error "PROXYSQL_MYSQL_ROUTER_PLUGIN_PATH must be defined"
#endif

int main() {
	plan(26);
	test_init_minimal();

	void* handle = dlopen(PROXYSQL_MYSQL_ROUTER_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
	ok(handle != nullptr, "the real proxysql_mysql_router.so is loadable");
	if (handle == nullptr) {
		diag("dlopen failed: %s", dlerror());
		BAIL_OUT("the real MySQL Router plugin must load");
	}

	auto entry = reinterpret_cast<proxysql_plugin_descriptor_v1_t>(
		dlsym(handle, "proxysql_plugin_descriptor_v1"));
	ok(entry != nullptr, "the plugin exports proxysql_plugin_descriptor_v1");
	const ProxySQL_PluginDescriptor* descriptor = entry ? entry() : nullptr;
	ok(descriptor != nullptr, "the descriptor entry point returns a descriptor");
	ok(descriptor && descriptor->name && std::string(descriptor->name) == "mysql_router",
	   "the plugin identifier is mysql_router");
	ok(descriptor && descriptor->abi_version == 9,
	   "the real Router plugin targets chassis ABI 9");
	ok(descriptor && descriptor->register_schemas && descriptor->register_cli_options &&
	   descriptor->early_action && descriptor->runtime_ready,
	   "the ABI-9 schema, CLI, action, and runtime-ready callbacks are present");
	ok(descriptor && descriptor->init && descriptor->start && descriptor->stop,
	   "the init, start, and stop callbacks are present");
	ok(descriptor && descriptor->status_json,
	   "the plugin exposes its status callback");

	std::string error;
	auto manager = std::make_unique<ProxySQL_PluginManager>();
	ok(manager->load(PROXYSQL_MYSQL_ROUTER_PLUGIN_PATH, error),
	   "ProxySQL_PluginManager loads the real Router plugin: %s", error.c_str());
	ok(manager->invoke_register_schemas_phase(error),
	   "the real Router plugin registers its schema: %s", error.c_str());
	ok(manager->init_all(error), "the real Router plugin initializes: %s", error.c_str());
	ok(manager->start_all(error), "the real Router plugin starts: %s", error.c_str());
	ProxySQL_PluginRuntimeContext runtime_context {nullptr, 1};
	ok(manager->runtime_ready_all(runtime_context, error),
	   "the real Router plugin reaches runtime-ready: %s", error.c_str());
	const std::string status = descriptor && descriptor->status_json
		? descriptor->status_json() : "";
	ok(status.find("mysql_router") != std::string::npos,
	   "the live status JSON identifies the real mysql_router plugin");
	const nlohmann::json status_document = nlohmann::json::parse(status);
	ok(status_document.contains("topology_uuid") &&
	   status_document.contains("metadata_version") &&
	   status_document.contains("advertised_contract") &&
	   status_document.contains("router_id") &&
	   status_document.contains("router_label") &&
	   status_document.contains("managed_hostgroups"),
	   "status exposes Router identity, contract, metadata, and hostgroup mapping");
	ok(status_document.contains("topology_last_success") &&
	   status_document.contains("user_last_success") &&
	   status_document.contains("stale_seconds") &&
	   status_document.contains("user_collisions") &&
	   status_document.contains("unsupported_auth_plugins") &&
	   status_document.contains("unsupported_router_options"),
	   "status exposes refresh age and managed-user diagnostics");

	prometheus::TextSerializer serializer;
	const std::string metrics = serializer.Serialize(GloVars.prometheus_registry->Collect());
	const char* required_metrics[] = {
		"proxysql_mysql_router_metadata_available",
		"proxysql_mysql_router_refresh_total",
		"proxysql_mysql_router_generation",
		"proxysql_mysql_router_managed_servers",
		"proxysql_mysql_router_writer_changes_total",
		"proxysql_mysql_router_drift_corrections_total",
		"proxysql_mysql_router_unresolved_users",
		"proxysql_mysql_router_stale_seconds",
	};
	for (const char* metric : required_metrics) {
		ok(metrics.find(metric) != std::string::npos,
		   "the shared registry exposes %s", metric);
	}
	ok(manager->stop_all(), "the real Router plugin stops cleanly");
	manager.reset();
	ok(dlclose(handle) == 0, "the direct descriptor handle closes cleanly");
	test_cleanup_minimal();

	return exit_status();
}
