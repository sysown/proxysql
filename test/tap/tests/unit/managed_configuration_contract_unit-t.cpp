#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "ezOptionParser.hpp"
#include "ProxySQL_Plugin.h"
#include "ProxySQL_ManagedConfiguration.h"
#include "ProxySQL_ManagedRuntime.h"
#include "ProxySQL_ConfigurationAccess.h"
#include "Web_Interface.hpp"
#include <cstddef>

namespace {
ManagedAuthResult verify(void*, const ManagedSignatureInput&) { return {}; }
ManagedResult invoke(void*, const ManagedRequest&) { return {}; }
ManagedResult bootstrap(void*, const std::string&) { return {}; }
ManagedResult restore(void*) { return {}; }
struct ABI11Descriptor {
 const char* name; uint32_t abi_version;
 proxysql_plugin_init_cb init; proxysql_plugin_start_cb start;
 proxysql_plugin_stop_cb stop; proxysql_plugin_status_json_cb status_json;
 proxysql_plugin_register_schemas_cb register_schemas;
 proxysql_plugin_register_cli_options_cb register_cli_options;
 proxysql_plugin_early_action_cb early_action;
 proxysql_plugin_runtime_ready_cb runtime_ready;
};
}
int main() {
 plan(11); test_init_minimal();
 ok(PROXYSQL_PLUGIN_ABI_LAYOUT_VERSION == 12u, "abi12_debug_prefix_compatible: layout is ABI12");
 ok((PROXYSQL_PLUGIN_ABI_VERSION & ~PROXYSQL_PLUGIN_ABI_DEBUG_BIT) == 12u,
    "ABI12 retains independent DEBUG tagging");
 ok(offsetof(ProxySQL_PluginDescriptor, managed_configuration_service) == sizeof(ABI11Descriptor),
    "ABI11 descriptor prefix remains byte-compatible");
 ok(offsetof(ProxySQL_PluginServices, lock_configuration) ==
    offsetof(ProxySQL_PluginServices, post_server_desired_set) + sizeof(proxysql_plugin_post_server_desired_set_cb),
    "ABI12 service callbacks append after the complete ABI11 prefix");
 ProxySQL_ManagedConfigurationServiceV1 service {PROXYSQL_MANAGED_CONFIGURATION_ABI,
  sizeof(ProxySQL_ManagedConfigurationServiceV1), nullptr, verify, invoke, bootstrap, restore};
 std::string error;
 ok(proxysql_validate_managed_configuration_service(&service, error), "complete V1 service accepted");
 service.abi_version++;
 ok(!proxysql_validate_managed_configuration_service(&service, error), "wrong_binder_version_rejected");
 service.abi_version = PROXYSQL_MANAGED_CONFIGURATION_ABI; service.struct_size--;
 ok(!proxysql_validate_managed_configuration_service(&service, error), "truncated service rejected before tail reads");
 service.struct_size = sizeof(service); service.restore = nullptr;
 ok(!proxysql_validate_managed_configuration_service(&service, error), "managed restore callback required");
 ok(!proxysql_validate_managed_configuration_service(nullptr, error), "missing service rejected");
 const char* args[] = {"unit", "--aws-managed-bootstrap=/tmp/local-manifest.json"};
 GloVars.parse(2, args);
 ok(GloVars.opt->isSet("--aws-managed-bootstrap"), "documented bootstrap equals syntax is parsed");
 std::string manifest;
 GloVars.opt->get("--aws-managed-bootstrap")->getString(manifest);
 ok(manifest == "/tmp/local-manifest.json", "bootstrap manifest path is preserved");
 test_cleanup_minimal(); return exit_status();
}
