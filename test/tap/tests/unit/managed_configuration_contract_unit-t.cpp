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
#include <sys/wait.h>
#include <unistd.h>

namespace {
ManagedAuthResult verify(void*, const ManagedSignatureInput&) { return {}; }
ManagedResult invoke(void*, const ManagedRequest&) { return {}; }
ManagedResult bootstrap(void*, const std::string&) { return {}; }
ManagedResult restore(void*) { return {}; }
bool rejects_retired_command(std::initializer_list<const char*> arguments) {
 int output[2];
 if (pipe(output) != 0) return false;
 fflush(nullptr);
 const auto pid = fork();
 if (pid < 0) { close(output[0]); close(output[1]); return false; }
 if (pid == 0) {
  close(output[0]);
  if (dup2(output[1], STDERR_FILENO) < 0) _exit(127);
  close(output[1]);
  std::vector<const char*> args(arguments);
  GloVars.parse(args.size(), args.data());
  _exit(0); // Returning instead of rejecting is the regression.
 }
 close(output[1]);
 std::string message; char buffer[256]; ssize_t n;
 while ((n = read(output[0], buffer, sizeof(buffer))) > 0) message.append(buffer, n);
 close(output[0]);
 int status = 0;
 return waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
  WEXITSTATUS(status) == EXIT_FAILURE && message.find("removed") != std::string::npos &&
  message.find("aws-deployment.json") != std::string::npos;
}
struct ABI14Descriptor {
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
 plan(17); test_init_minimal();
 ok(PROXYSQL_PLUGIN_ABI_LAYOUT_VERSION == 15u, "abi15_debug_prefix_compatible: layout is ABI15");
 ok((PROXYSQL_PLUGIN_ABI_VERSION & ~PROXYSQL_PLUGIN_ABI_DEBUG_BIT) == 15u,
    "ABI15 retains independent DEBUG tagging");
 ok(offsetof(ProxySQL_PluginDescriptor, managed_configuration_service) == sizeof(ABI14Descriptor),
    "ABI14 descriptor prefix remains byte-compatible");
 ok(offsetof(ProxySQL_PluginServices, lock_configuration) ==
    offsetof(ProxySQL_PluginServices, post_server_desired_set) + sizeof(proxysql_plugin_post_server_desired_set_cb),
    "ABI15 service callbacks append after the complete ABI14 prefix");
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
 const char* args[] = {"unit", "--foreground", "--exit-on-error"};
 GloVars.parse(3, args);
 ok(GloVars.opt->get("--aws-managed-bootstrap") == nullptr, "retired bootstrap option is not registered");
 ok(!GloVars.opt->isSet("--aws-managed-bootstrap"), "retired bootstrap has no parser state");
 GloVars.global.foreground = false;
 glovars.proxy_restart_on_error = true;
 GloVars.process_opts_pre();
 ok(GloVars.opt->isSet("-f"), "ordinary foreground option remains parsed");
 ok(!glovars.proxy_restart_on_error, "ordinary exit-on-error option remains effective");
 ok(rejects_retired_command({"unit", "--aws-managed-bootstrap", "/tmp/manifest.json"}),
    "retired separate-argument command exits with a migration message");
 ok(rejects_retired_command({"unit", "--aws-managed-bootstrap=/tmp/manifest.json"}),
    "retired equals command exits with a migration message");
 ok(rejects_retired_command({"unit", "--aws-managed-bootstrap"}),
    "retired command without a manifest exits with a migration message");
 ok(rejects_retired_command({"unit", "--aws-managed-bootstrap="}),
    "retired command with an empty manifest exits with a migration message");
 test_cleanup_minimal(); return exit_status();
}
