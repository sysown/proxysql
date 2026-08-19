#include "ProxySQL_Plugin.h"
#include "ProxySQL_PluginManager.h"
#include "ProxySQL_ServerDiscovery.h"
#include "tap.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

SQLite3DB* proxysql_plugin_get_admindb() { return nullptr; }
SQLite3DB* proxysql_plugin_get_configdb() { return nullptr; }
SQLite3DB* proxysql_plugin_get_statsdb() { return nullptr; }

namespace {

std::atomic<unsigned int> g_module_calls {0};
std::atomic<unsigned int> g_module_destroyed {0};
std::atomic<unsigned int> g_controller_calls {0};
std::atomic<unsigned int> g_controller_destroyed {0};
std::mutex g_lease_mutex;
std::condition_variable g_lease_cv;
bool g_callback_entered = false;
bool g_callback_release = false;

void module_installed(void*, ProxySQL_ServerRuntimeSnapshot snapshot) {
	if (snapshot.protocol == ProxySQL_ServerProtocol::mysql && snapshot.generation == 7) {
		++g_module_calls;
	}
	if (snapshot.protocol == ProxySQL_ServerProtocol::pgsql && snapshot.generation == 8) {
		std::unique_lock<std::mutex> lock(g_lease_mutex);
		g_callback_entered = true;
		g_lease_cv.notify_all();
		g_lease_cv.wait(lock, [] { return g_callback_release; });
	}
}

void destroy_module(ProxySQL_ServerModuleTable*) { ++g_module_destroyed; }

class Controller final : public ProxySQL_ServerDiscoveryController {
public:
	void runtime_configuration_installed(ProxySQL_ServerRuntimeSnapshot snapshot) override {
		if (snapshot.generation == 7) ++g_controller_calls;
	}
	void desired_set_applied(uint64_t, bool) override {}
	void shutdown() override {}
};

void destroy_controller(ProxySQL_ServerDiscoveryController* controller) {
	++g_controller_destroyed;
	delete controller;
}

void test_abi_and_registry_contract() {
	static_assert(PROXYSQL_PLUGIN_ABI_VERSION == 9u, "ABI 9 services are public");
	struct Abi8Descriptor {
		const char *name; uint32_t abi_version; proxysql_plugin_init_cb init;
		proxysql_plugin_start_cb start; proxysql_plugin_stop_cb stop;
		proxysql_plugin_status_json_cb status_json; proxysql_plugin_register_schemas_cb register_schemas;
	};
	static_assert(sizeof(Abi8Descriptor) <= sizeof(ProxySQL_PluginDescriptor), "ABI-8 descriptor tail remains readable");

	ProxySQL_PluginManager mgr;
	ProxySQL_ServerModuleTable module {
		ProxySQL_ServerProtocol::mysql, {&module_installed}, nullptr
	};
	ok(mgr.register_server_module(&module, &destroy_module, nullptr), "register one MySQL server module");
	ok(!mgr.register_server_module(&module, &destroy_module, nullptr), "reject duplicate protocol module");
	ok(!mgr.register_server_module(nullptr, &destroy_module, nullptr), "reject null module");

	ProxySQL_ServerRuntimeSnapshot snapshot {ProxySQL_ServerProtocol::mysql, 7, {}};
	mgr.install_server_runtime_snapshot(snapshot);
	ok(g_module_calls == 1, "registered module receives initial runtime configuration");

	ok(mgr.install_server_discovery_controller(ProxySQL_ServerProtocol::mysql,
		new Controller(), &destroy_controller, nullptr), "install one controller per protocol");
	Controller *duplicate = new Controller();
	ok(!mgr.install_server_discovery_controller(ProxySQL_ServerProtocol::mysql,
		duplicate, &destroy_controller, nullptr), "reject second controller for protocol");
	delete duplicate;
	ok(g_controller_calls == 1, "later controller receives latest committed snapshot once");
	ok(mgr.uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql), "uninstall controller");
	ok(g_controller_destroyed == 1, "uninstall destroys controller");
	mgr.unregister_server_module(ProxySQL_ServerProtocol::mysql);
	ok(g_module_destroyed == 1, "unregister drains retained module handle");

	ProxySQL_ServerModuleTable leased_module {
		ProxySQL_ServerProtocol::pgsql, {&module_installed}, nullptr
	};
	ok(mgr.register_server_module(&leased_module, &destroy_module, nullptr),
		"register module whose callback holds a lease");
	std::thread callback([&] {
		mgr.install_server_runtime_snapshot({ProxySQL_ServerProtocol::pgsql, 8, {}});
	});
	{
		std::unique_lock<std::mutex> lock(g_lease_mutex);
		g_lease_cv.wait(lock, [] { return g_callback_entered; });
	}
	std::thread uninstall([&] { mgr.unregister_server_module(ProxySQL_ServerProtocol::pgsql); });
	std::this_thread::yield();
	ok(g_module_destroyed == 1, "uninstall retains module while callback lease is live");
	{
		std::lock_guard<std::mutex> lock(g_lease_mutex);
		g_callback_release = true;
	}
	g_lease_cv.notify_all();
	callback.join();
	uninstall.join();
	ok(g_module_destroyed == 2, "uninstall destroys module after final callback lease exits");
}

} // namespace

int main() {
	plan(13);
	test_abi_and_registry_contract();
	return exit_status();
}
