#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "ProxySQL_PluginManager.h"
#include "Web_Interface.hpp"
#include <cstdlib>
#include <condition_variable>
#include <mutex>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>

namespace {
std::string events_path;
const ProxySQL_ManagedConfigurationServiceV1* bound_service = nullptr;
void event(const char* text) { std::ofstream out(events_path, std::ios::app); out << text << '\n'; }
std::string events() { std::ifstream in(events_path); return {std::istreambuf_iterator<char>(in), {}}; }
void clear_events() { std::ofstream out(events_path, std::ios::trunc); }
class FakeWeb : public Web_Interface {
 std::thread handler;
 std::mutex mutex;
 std::condition_variable condition;
 bool accepted{false}, release{false};
 public:
 bool handler_used_live_provider{false};
 void begin_handler() {
  handler = std::thread([this] {
   {
    std::unique_lock<std::mutex> lock(mutex);
    event("handler_accepted"); accepted = true; condition.notify_all();
    condition.wait(lock, [this] { return release; });
   }
   if (bound_service) {
    ManagedRequest request {}; request.kind = ManagedCallKind::status;
    handler_used_live_provider = bound_service->invoke(bound_service->context, request).outcome == ManagedOutcome::ok;
   }
   event("handler_drained");
  });
  std::unique_lock<std::mutex> lock(mutex);
  condition.wait(lock, [this] { return accepted; });
 }
 void stop() override {
  event("web_stop_accepting");
  // The accepted handler calls AWS while stop synchronously joins it.
  // Both plugin objects and the AWS DSO must remain alive until it drains.
  {
   std::lock_guard<std::mutex> lock(mutex); release = true;
  }
  condition.notify_all();
  if (handler.joinable()) handler.join();
  event("web_drained");
 }
 ~FakeWeb() override { event("web_destroyed"); }
};
bool bind(Web_Interface*, const ProxySQL_ManagedConfigurationServiceV1* service, std::string&) {
 bound_service = service; event("web_bound"); return true;
}
bool reject_bind(Web_Interface*, const ProxySQL_ManagedConfigurationServiceV1*, std::string& error) {
 error = "binder rejected"; return false;
}
std::unique_ptr<ProxySQL_PluginManager> provider(std::string& error) {
 auto manager = std::make_unique<ProxySQL_PluginManager>();
 if (!manager->load(PROXYSQL_MANAGED_FAKE_PROVIDER_PATH, error) || !manager->init_all(error)) return nullptr;
 return manager;
}
}
int main() {
 plan(28); test_init_minimal();
 char path[] = "/tmp/proxysql_managed_lifecycle.XXXXXX";
 int fd = mkstemp(path); if (fd >= 0) close(fd);
 events_path = path; setenv("PROXYSQL_MANAGED_FAKE_LOG", path, 1);
 std::string error;
 FakeWeb web;
 ok(!proxysql_start_managed_configuration(nullptr, &web, bind, nullptr, error),
    "required_plugins_checked_at_startup: missing AWS fails before serving");
 auto manager = provider(error);
 ok(manager != nullptr, "fake provider initializes through real plugin loader");
 if (!manager) { diag("%s", error.c_str()); return 1; }
 ok(manager->check_managed_configuration_provider(error), "provider descriptor required at startup");
 ok(!proxysql_start_managed_configuration(manager.get(), nullptr, bind, nullptr, error),
    "required_plugins_checked_at_startup: missing web fails before serving");
 ok(!proxysql_start_managed_configuration(manager.get(), &web, nullptr, nullptr, error),
    "missing v1 binder rejected");
 ok(!proxysql_start_managed_configuration(manager.get(), &web, reject_bind, nullptr, error),
    "binder rejection prevents restore");
 ok(events().find("restore") == std::string::npos, "rejected binder never restores or serves");
 setenv("PROXYSQL_MANAGED_FAKE_BAD_ABI", "1", 1);
 ok(!proxysql_start_managed_configuration(manager.get(), &web, bind, nullptr, error),
    "wrong_binder_version_rejected before invoking binder");
 unsetenv("PROXYSQL_MANAGED_FAKE_BAD_ABI");
 clear_events();
 const bool cluster_sync_interfaces = GloVars.cluster_sync_interfaces;
 GloVars.cluster_sync_interfaces = true;
 ok(proxysql_start_managed_configuration(manager.get(), &web, bind, nullptr, error),
    "restore uses required bound service");
 ok(GloVars.cluster_sync_interfaces, "managed restore does not disable or reconfigure Cluster");
 GloVars.cluster_sync_interfaces = cluster_sync_interfaces;
 const auto restored = events();
 ok(restored.find("web_bound") < restored.find("restore"), "web binds before restoration");
 ok(restored.find("bootstrap") == std::string::npos, "normal startup does not initialize empty deployment");
 clear_events(); const std::string manifest = "{\"installation\":true}";
 ok(proxysql_start_managed_configuration(manager.get(), &web, bind, &manifest, error),
    "local bootstrap goes through same required service");
 ok(events().find("bootstrap") != std::string::npos && events().find("restore") == std::string::npos,
    "bootstrap selected explicitly instead of restore");
 setenv("PROXYSQL_MANAGED_FAKE_PENDING", "1", 1);
 ok(!proxysql_start_managed_configuration(manager.get(), &web, bind, nullptr, error),
    "pending recovery error prevents successful startup");
 unsetenv("PROXYSQL_MANAGED_FAKE_PENDING");
 clear_events();
 Web_Interface* drain_web = new FakeWeb;
 ok(proxysql_start_managed_configuration(manager.get(), drain_web, bind, nullptr, error),
    "web binds before draining test");
 static_cast<FakeWeb*>(drain_web)->begin_handler();
 ok(proxysql_stop_plugins_after_web_drain(drain_web, manager, error), "managed pair stops cleanly");
 const auto stopped = events();
 ok(stopped.find("handler_accepted") < stopped.find("web_stop_accepting"), "request accepted before shutdown starts");
 ok(stopped.find("handler_drained") < stopped.find("provider_stopped"),
    "web_drains_before_aws_destruction: handler completed first");
 ok(stopped.find("provider_stopped") < stopped.find("web_destroyed"), "provider controllers stop before web and AWS destruction");
 ok(stopped.find("invoke_live") != std::string::npos, "inflight handler called live AWS while draining");
 ok(drain_web == nullptr && manager == nullptr, "both plugin objects cleared after drain");
 ProxySQL_PluginManager old;
 ok(old.load(PROXYSQL_MANAGED_OLD_PLUGIN_PATH, error), "ABI13 prefix still loads with matching DEBUG tag");
 ok(!old.check_managed_configuration_provider(error), "ABI13 descriptor never read as an ABI15 provider");
 auto multiple = provider(error);
 ok(multiple && multiple->load(PROXYSQL_MANAGED_FAKE_PROVIDER2_PATH, error), "second distinct fake provider loads");
 ok(multiple && !multiple->check_managed_configuration_provider(error), "multiple managed providers rejected before serving");
 ProxySQL_PluginManager ordinary;
 ok(!ordinary.check_managed_configuration_provider(error), "empty plugin set rejected only for managed profile");
 ok(ordinary.init_all(error) && ordinary.start_all(error), "normal empty plugin lifecycle remains available");
 bound_service = nullptr;
 unsetenv("PROXYSQL_MANAGED_FAKE_LOG"); unlink(path);
 test_cleanup_minimal(); return exit_status();
}
