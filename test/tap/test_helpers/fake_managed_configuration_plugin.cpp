// Public fake management provider: no AWS/private implementation dependencies.
#include "ProxySQL_Plugin.h"
#include "Web_Interface.hpp"
#include <cstdlib>
#include <fstream>

#ifndef PROXYSQL_MANAGED_FAKE_NAME
#define PROXYSQL_MANAGED_FAKE_NAME "fake_managed"
#endif
namespace {
bool alive = false;
void event(const char* text) {
 const char* path = std::getenv("PROXYSQL_MANAGED_FAKE_LOG");
 if (path) { std::ofstream out(path, std::ios::app); out << text << '\n'; }
}
bool init(ProxySQL_PluginServices*) { alive = true; event("provider_initialized"); return true; }
bool start() { event("provider_started"); return true; }
bool stop() { alive = false; event("provider_stopped"); return true; }
ManagedAuthResult verify(void*, const ManagedSignatureInput&) { return {}; }
ManagedResult invoke(void*, const ManagedRequest&) {
 event(alive ? "invoke_live" : "invoke_stopped");
 ManagedResult result {}; result.outcome = alive ? ManagedOutcome::ok : ManagedOutcome::internal_error;
 return result;
}
ManagedResult bootstrap(void*, const std::string&) {
 event("bootstrap"); ManagedResult result {};
 result.outcome = std::getenv("PROXYSQL_MANAGED_FAKE_BOOTSTRAP_FAIL") ?
  ManagedOutcome::rejected : ManagedOutcome::ok;
 result.message = "fake bootstrap"; return result;
}
ManagedResult restore(void*) {
 event("restore"); ManagedResult result {};
 result.outcome = std::getenv("PROXYSQL_MANAGED_FAKE_PENDING") ? ManagedOutcome::durable_pending : ManagedOutcome::ok;
 result.message = "fake recovery"; return result;
}
const ProxySQL_ManagedConfigurationServiceV1* service() {
 static ProxySQL_ManagedConfigurationServiceV1 value {PROXYSQL_MANAGED_CONFIGURATION_ABI,
  sizeof(ProxySQL_ManagedConfigurationServiceV1), nullptr, verify, invoke, bootstrap, restore};
 value.abi_version = std::getenv("PROXYSQL_MANAGED_FAKE_BAD_ABI") ? 2 : 1;
 return &value;
}
const ProxySQL_PluginDescriptor descriptor {PROXYSQL_MANAGED_FAKE_NAME, PROXYSQL_PLUGIN_ABI_VERSION,
 init, start, stop, nullptr, nullptr, nullptr, nullptr, nullptr, service};
}
extern "C" const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() { return &descriptor; }

// The same public fixture can stand in for the separate web DSO during
// executable startup probes. It never opens a socket or performs network I/O.
namespace {
class FakeManagedWeb : public Web_Interface {
 public:
 void start(int) override { event("web_started"); }
 void stop() override { event("web_drained"); }
 ~FakeManagedWeb() override { event("web_destroyed"); }
};
}
extern "C" Web_Interface* create_Web_Interface_func() { return new FakeManagedWeb; }
extern "C" bool proxysql_web_bind_managed_configuration_v1(Web_Interface*,
 const ProxySQL_ManagedConfigurationServiceV1*, std::string&) {
 event("web_bound"); return true;
}
