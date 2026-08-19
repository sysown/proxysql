#include "ProxySQL_Plugin.h"
#include "ProxySQL_PluginManager.h"
#include "ProxySQL_ServerDiscovery.h"
#include "tap.h"

#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <dlfcn.h>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif
#ifndef PROXYSQL_FAKE_PLUGIN2_PATH
#error "PROXYSQL_FAKE_PLUGIN2_PATH must be defined"
#endif
#ifndef PROXYSQL_FAKE_PLUGIN_ABI8_PATH
#error "PROXYSQL_FAKE_PLUGIN_ABI8_PATH must be defined"
#endif

char g_fake_admin_db = '\0';
char g_fake_config_db = '\0';
char g_fake_stats_db = '\0';
SQLite3DB* proxysql_plugin_get_admindb() { return reinterpret_cast<SQLite3DB*>(&g_fake_admin_db); }
SQLite3DB* proxysql_plugin_get_configdb() { return reinterpret_cast<SQLite3DB*>(&g_fake_config_db); }
SQLite3DB* proxysql_plugin_get_statsdb() { return reinterpret_cast<SQLite3DB*>(&g_fake_stats_db); }

namespace {

std::atomic<unsigned int> g_module_calls {0};
std::atomic<unsigned int> g_module_destroyed {0};
std::atomic<unsigned int> g_controller_calls {0};
std::atomic<unsigned int> g_controller_destroyed {0};
std::atomic<bool> g_throw_module_callback {false};
std::atomic<bool> g_throw_module_destroy {false};
std::atomic<bool> g_throw_controller_destroy {false};
std::mutex g_lease_mutex;
std::condition_variable g_lease_cv;
bool g_callback_entered = false;
bool g_callback_release = false;
bool g_uninstall_started = false;
bool g_destroyed_before_callback_release = false;
std::string g_log_path;

void retirement_observer(ProxySQL_ServerProtocol protocol, bool controller, void *) {
	if (protocol != ProxySQL_ServerProtocol::pgsql || controller) return;
	std::lock_guard<std::mutex> lock(g_lease_mutex);
	g_uninstall_started = true;
	g_lease_cv.notify_all();
}

void make_log_path() {
	char path[] = "/tmp/proxysql_server_discovery_abi.XXXXXX";
	int fd = mkstemp(path);
	if (fd >= 0) close(fd);
	g_log_path = path;
	setenv("PROXYSQL_FAKE_PLUGIN_LOG", g_log_path.c_str(), 1);
	setenv("PROXYSQL_FAKE_PLUGIN2_LOG", g_log_path.c_str(), 1);
}

void clear_log() {
	std::ofstream truncator(g_log_path, std::ios::trunc);
	(void)truncator;
}

std::string read_log() {
	std::ifstream log(g_log_path);
	return std::string((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
}

void cleanup_log() {
	if (!g_log_path.empty()) unlink(g_log_path.c_str());
	unsetenv("PROXYSQL_FAKE_PLUGIN_LOG");
	unsetenv("PROXYSQL_FAKE_PLUGIN2_LOG");
}

void *open_retained_module(const char *path) {
	return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}

bool is_module_loaded(const char *path) {
	void *probe = dlopen(path, RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL);
	if (probe == nullptr) return false;
	dlclose(probe);
	return true;
}

void module_installed(void *, ProxySQL_ServerRuntimeSnapshot snapshot) {
	if (g_throw_module_callback.load()) throw std::runtime_error("module callback failure");
	if (snapshot.protocol == ProxySQL_ServerProtocol::mysql && snapshot.generation == 7) {
		++g_module_calls;
	}
	if (snapshot.protocol == ProxySQL_ServerProtocol::pgsql && snapshot.generation == 8) {
		std::unique_lock<std::mutex> lock(g_lease_mutex);
		g_callback_entered = true;
		g_lease_cv.notify_all();
		g_lease_cv.wait(lock, [] { return g_callback_release && g_uninstall_started; });
	}
}

void destroy_module(ProxySQL_ServerModuleHooks *) {
	std::lock_guard<std::mutex> lock(g_lease_mutex);
	if (!g_callback_release) g_destroyed_before_callback_release = true;
	++g_module_destroyed;
	if (g_throw_module_destroy.load()) throw std::runtime_error("module destroy failure");
}

class Controller final : public ProxySQL_ServerDiscoveryController {
public:
	explicit Controller(bool throw_runtime = false, bool throw_desired = false,
	                    bool throw_shutdown = false, bool block_runtime = false)
		: throw_runtime_(throw_runtime), throw_desired_(throw_desired),
		  throw_shutdown_(throw_shutdown), block_runtime_(block_runtime) {}

	void runtime_configuration_installed(ProxySQL_ServerRuntimeSnapshot snapshot) override {
		if (throw_runtime_) throw std::runtime_error("controller runtime failure");
		if (snapshot.generation == 7) ++g_controller_calls;
		if (block_runtime_ && snapshot.generation == 8) {
			std::unique_lock<std::mutex> lock(g_lease_mutex);
			g_callback_entered = true;
			g_lease_cv.notify_all();
			g_lease_cv.wait(lock, [] { return g_callback_release && g_uninstall_started; });
		}
	}
	void desired_set_applied(uint64_t, bool) override {
		if (throw_desired_) throw std::runtime_error("controller desired failure");
	}
	void shutdown() override {
		if (throw_shutdown_) throw std::runtime_error("controller shutdown failure");
	}

private:
	bool throw_runtime_;
	bool throw_desired_;
	bool throw_shutdown_;
	bool block_runtime_;
};

void destroy_controller(ProxySQL_ServerDiscoveryController *controller) {
	++g_controller_destroyed;
	delete controller;
	if (g_throw_controller_destroy.load()) throw std::runtime_error("controller destroy failure");
}

struct SelfUninstallState {
	std::atomic<bool> entered {false};
	std::atomic<bool> uninstall_returned {false};
	std::atomic<bool> uninstall_result {false};
	std::atomic<unsigned int> destroyed {0};
};

struct ConcurrentSelfUninstallState {
	std::mutex mutex;
	std::condition_variable cv;
	bool entered {false};
	bool external_ready {false};
	bool self_retired {false};
	bool external_finished {false};
	bool self_result {false};
	bool external_result {true};
	std::atomic<unsigned int> destroyed {0};
};

class SelfUninstallController final : public ProxySQL_ServerDiscoveryController {
public:
	SelfUninstallController(ProxySQL_PluginManager *manager, ProxySQL_ServerProtocol protocol,
		SelfUninstallState *state, bool from_runtime)
		: manager_(manager), protocol_(protocol), state_(state), from_runtime_(from_runtime) {}

	void runtime_configuration_installed(ProxySQL_ServerRuntimeSnapshot) override {
		if (from_runtime_) uninstall();
	}
	void desired_set_applied(uint64_t, bool) override {
		if (!from_runtime_) uninstall();
	}
	void shutdown() override {}
	SelfUninstallState *state() const { return state_; }

private:
	void uninstall() {
		state_->entered = true;
		state_->uninstall_result = manager_->uninstall_server_discovery_controller(protocol_);
		state_->uninstall_returned = true;
	}

	ProxySQL_PluginManager *manager_;
	ProxySQL_ServerProtocol protocol_;
	SelfUninstallState *state_;
	bool from_runtime_;
};

void destroy_self_uninstall_controller(ProxySQL_ServerDiscoveryController *controller) {
	auto *self = static_cast<SelfUninstallController *>(controller);
	self->state()->destroyed.fetch_add(1);
	delete self;
}

class ConcurrentSelfUninstallController final : public ProxySQL_ServerDiscoveryController {
public:
	ConcurrentSelfUninstallController(ProxySQL_PluginManager *manager, ConcurrentSelfUninstallState *state)
		: manager_(manager), state_(state) {}

	void runtime_configuration_installed(ProxySQL_ServerRuntimeSnapshot) override {}
	void desired_set_applied(uint64_t, bool) override {
		{
			std::unique_lock<std::mutex> lock(state_->mutex);
			state_->entered = true;
			state_->cv.notify_all();
			state_->cv.wait(lock, [this] { return state_->external_ready; });
		}
		const bool result = manager_->uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql);
		{
			std::unique_lock<std::mutex> lock(state_->mutex);
			state_->self_result = result;
			state_->self_retired = true;
			state_->cv.notify_all();
			state_->cv.wait(lock, [this] { return state_->external_finished; });
		}
	}
	void shutdown() override {}
	ConcurrentSelfUninstallState *state() const { return state_; }

private:
	ProxySQL_PluginManager *manager_;
	ConcurrentSelfUninstallState *state_;
};

void destroy_concurrent_self_uninstall_controller(ProxySQL_ServerDiscoveryController *controller) {
	auto *self = static_cast<ConcurrentSelfUninstallController *>(controller);
	self->state()->destroyed.fetch_add(1);
	delete self;
}

void test_abi8_fixture_and_invalid_registration() {
	ProxySQL_PluginManager mgr;
	std::string err;
	void *abi8_fixture = open_retained_module(PROXYSQL_FAKE_PLUGIN_ABI8_PATH);
	using abi8_tail_called_cb = bool (*)();
	auto abi8_tail_called = abi8_fixture == nullptr ? nullptr :
		reinterpret_cast<abi8_tail_called_cb>(dlsym(
			abi8_fixture, "proxysql_fake_plugin_abi8_tail_called"));
	ok(abi8_fixture != nullptr && abi8_tail_called != nullptr &&
		mgr.load(PROXYSQL_FAKE_PLUGIN_ABI8_PATH, err) && mgr.init_all(err) && mgr.start_all(err) &&
		abi8_tail_called(),
		"a frozen ABI-8 DSO calls its ABI-8 tail through ABI-9 loader/init lifecycle");
	ok(mgr.stop_all(), "ABI-8 fixture stops cleanly");
	dlclose(abi8_fixture);
	setenv("PROXYSQL_FAKE_PLUGIN_ABI8_FORCE_ABI10", "1", 1);
	ProxySQL_PluginManager newer_abi_manager;
	ok(!newer_abi_manager.load(PROXYSQL_FAKE_PLUGIN_ABI8_PATH, err),
		"ABI-10 descriptor is rejected by the ABI-9 core");
	ok(err.find("ABI") != std::string::npos && newer_abi_manager.size() == 0,
		"ABI-10 rejection does not retain a plugin handle");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ABI8_FORCE_ABI10");

	ProxySQL_ServerModuleHooks no_hook {ProxySQL_ServerProtocol::mysql, {nullptr}, nullptr};
	ProxySQL_ServerModuleHooks invalid_protocol {
		static_cast<ProxySQL_ServerProtocol>(9), {&module_installed}, nullptr
	};
	void *handle = open_retained_module(PROXYSQL_FAKE_PLUGIN_PATH);
	ok(handle != nullptr, "open a separately retained module DSO reference");
	ok(!mgr.register_server_module(nullptr, &destroy_module, handle), "reject null module hooks");
	ok(!mgr.register_server_module(&no_hook, &destroy_module, handle), "reject null module hook callback");
	ok(!mgr.register_server_module(&invalid_protocol, &destroy_module, handle), "reject invalid module protocol");
	ok(!mgr.register_server_module(&no_hook, nullptr, handle), "reject null module destroy callback");
	ok(!mgr.register_server_module(&no_hook, &destroy_module, nullptr), "reject null retained module handle");
	dlclose(handle);

	void *null_controller_handle = open_retained_module(PROXYSQL_FAKE_PLUGIN2_PATH);
	ok(!mgr.install_server_discovery_controller(ProxySQL_ServerProtocol::mysql, nullptr,
		&destroy_controller, null_controller_handle), "reject null controller");
	dlclose(null_controller_handle);
	Controller *controller = new Controller();
	void *controller_handle = open_retained_module(PROXYSQL_FAKE_PLUGIN2_PATH);
	ok(!mgr.install_server_discovery_controller(static_cast<ProxySQL_ServerProtocol>(9), controller,
		&destroy_controller, controller_handle), "reject invalid controller protocol");
	ok(!mgr.install_server_discovery_controller(ProxySQL_ServerProtocol::mysql, controller,
		nullptr, controller_handle), "reject null controller destroy callback");
	ok(!mgr.install_server_discovery_controller(ProxySQL_ServerProtocol::mysql, controller,
		&destroy_controller, nullptr), "reject null retained controller handle");
	delete controller;
	dlclose(controller_handle);
}

void test_service_phase_availability() {
	make_log_path();
	clear_log();
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_SERVER_DISCOVERY", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_CHECK_SERVER_DISCOVERY_INIT", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string err;
	const std::vector<std::string> plugins {PROXYSQL_FAKE_PLUGIN_PATH};
	ok(proxysql_load_configured_plugins(manager, plugins, err) &&
		proxysql_init_configured_plugins(manager.get(), err),
		"Phase B module registration and normal-init services succeed");
	const std::string phase_log = read_log();
	ok(phase_log.find("phase_b_server_discovery_availability") != std::string::npos &&
		phase_log.find("phase_b_server_module_registered") != std::string::npos,
		"only module registration is live in Phase B");
	ok(phase_log.find("init_server_discovery_live") != std::string::npos,
		"all server discovery services are live in normal init");
	(void)proxysql_stop_configured_plugins(manager, err);
	ok(read_log().find("server_module_destroyed") != std::string::npos,
		"Phase-B registered module is retired through its destroy callback");
	unsetenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_SERVER_DISCOVERY");
	unsetenv("PROXYSQL_FAKE_PLUGIN_CHECK_SERVER_DISCOVERY_INIT");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");

	clear_log();
	setenv("PROXYSQL_FAKE_PLUGIN_START_REGISTER_SERVER_MODULE", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> late_manager;
	ok(proxysql_load_configured_plugins(late_manager, plugins, err) &&
		proxysql_init_configured_plugins(late_manager.get(), err) &&
		proxysql_start_configured_plugins(late_manager.get(), err),
		"plugin can start after normal init");
	ok(read_log().find("start_server_module_rejected") != std::string::npos,
		"registration outside Phase B/init is rejected through the service callback");
	(void)proxysql_stop_configured_plugins(late_manager, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_START_REGISTER_SERVER_MODULE");
	cleanup_log();
}

void test_steady_state_desired_set_service_lifetime() {
	make_log_path();
	clear_log();
	setenv("PROXYSQL_FAKE_PLUGIN_INSTALL_SERVER_DISCOVERY_CONTROLLER", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_START_POST_SERVER_DESIRED_SET", "1", 1);
	void *fixture_handle = open_retained_module(PROXYSQL_FAKE_PLUGIN_PATH);
	using post_after_shutdown_cb = bool (*)();
	auto post_after_shutdown = fixture_handle == nullptr ? nullptr :
		reinterpret_cast<post_after_shutdown_cb>(dlsym(
			fixture_handle, "proxysql_fake_post_server_desired_set_for_test"));
	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string err;
	const std::vector<std::string> plugins {PROXYSQL_FAKE_PLUGIN_PATH};
	ok(fixture_handle != nullptr && post_after_shutdown != nullptr &&
		proxysql_load_configured_plugins(manager, plugins, err) &&
		proxysql_init_configured_plugins(manager.get(), err) &&
		proxysql_start_configured_plugins(manager.get(), err),
		"a plugin can post desired sets from start after init has returned");
	const std::string start_log = read_log();
	ok(start_log.find("init_server_controller_installed") != std::string::npos &&
		start_log.find("start_server_desired_set_posted") != std::string::npos &&
		start_log.find("server_controller_desired_set") != std::string::npos,
		"steady-state desired-set service reaches the installed controller");
	(void)proxysql_stop_configured_plugins(manager, err);
	const std::string stopped_log = read_log();
	const size_t first_ack = stopped_log.find("server_controller_desired_set");
	ok(!post_after_shutdown() &&
		stopped_log.find("server_controller_shutdown") != std::string::npos &&
		stopped_log.find("server_controller_destroyed") != std::string::npos &&
		first_ack != std::string::npos &&
		stopped_log.find("server_controller_desired_set", first_ack + 1) == std::string::npos,
		"post service fails closed after shutdown unpublishes its manager");
	dlclose(fixture_handle);
	unsetenv("PROXYSQL_FAKE_PLUGIN_INSTALL_SERVER_DISCOVERY_CONTROLLER");
	unsetenv("PROXYSQL_FAKE_PLUGIN_START_POST_SERVER_DESIRED_SET");
	cleanup_log();
}

struct RetainedFixtureSymbols {
	using create_module_cb = ProxySQL_ServerModuleHooks *(*)(ProxySQL_ServerProtocol);
	using destroy_module_cb = void (*)(ProxySQL_ServerModuleHooks *);
	using create_controller_cb = ProxySQL_ServerDiscoveryController *(*)();
	using destroy_controller_cb = void (*)(ProxySQL_ServerDiscoveryController *);
	using reset_cb = void (*)();
	using calls_cb = unsigned int (*)();

	void *handle {nullptr};
	create_module_cb create_module {nullptr};
	destroy_module_cb destroy_module {nullptr};
	create_controller_cb create_controller {nullptr};
	destroy_controller_cb destroy_controller {nullptr};
	reset_cb reset {nullptr};
	calls_cb module_calls {nullptr};
	calls_cb controller_calls {nullptr};
};

RetainedFixtureSymbols open_retained_fixture(const char *path) {
	RetainedFixtureSymbols fixture;
	fixture.handle = open_retained_module(path);
	if (fixture.handle == nullptr) return fixture;
	fixture.create_module = reinterpret_cast<RetainedFixtureSymbols::create_module_cb>(dlsym(
		fixture.handle, "proxysql_fake_retained_module_create"));
	fixture.destroy_module = reinterpret_cast<RetainedFixtureSymbols::destroy_module_cb>(dlsym(
		fixture.handle, "proxysql_fake_retained_module_destroy"));
	fixture.create_controller = reinterpret_cast<RetainedFixtureSymbols::create_controller_cb>(dlsym(
		fixture.handle, "proxysql_fake_retained_controller_create"));
	fixture.destroy_controller = reinterpret_cast<RetainedFixtureSymbols::destroy_controller_cb>(dlsym(
		fixture.handle, "proxysql_fake_retained_controller_destroy"));
	fixture.reset = reinterpret_cast<RetainedFixtureSymbols::reset_cb>(dlsym(
		fixture.handle, "proxysql_fake_retained_fixture_reset"));
	fixture.module_calls = reinterpret_cast<RetainedFixtureSymbols::calls_cb>(dlsym(
		fixture.handle, "proxysql_fake_retained_fixture_module_calls"));
	fixture.controller_calls = reinterpret_cast<RetainedFixtureSymbols::calls_cb>(dlsym(
		fixture.handle, "proxysql_fake_retained_fixture_controller_calls"));
	return fixture;
}

bool valid_retained_fixture(const RetainedFixtureSymbols &fixture) {
	return fixture.handle != nullptr && fixture.create_module != nullptr &&
		fixture.destroy_module != nullptr && fixture.create_controller != nullptr &&
		fixture.destroy_controller != nullptr && fixture.reset != nullptr &&
		fixture.module_calls != nullptr && fixture.controller_calls != nullptr;
}

void test_lifecycle_delivery_and_retained_handles() {
	ProxySQL_PluginManager mgr;
	make_log_path();
	clear_log();
	RetainedFixtureSymbols module_fixture = open_retained_fixture(PROXYSQL_FAKE_PLUGIN_PATH);
	ok(valid_retained_fixture(module_fixture), "load module fixture factories from retained DSO");
	module_fixture.reset();
	ProxySQL_ServerModuleHooks *module = module_fixture.create_module(ProxySQL_ServerProtocol::mysql);
	ok(module != nullptr && mgr.register_server_module(module, module_fixture.destroy_module,
		module_fixture.handle), "register DSO-created MySQL module hook with its DSO destroy callback");
	void *duplicate_handle = open_retained_module(PROXYSQL_FAKE_PLUGIN_PATH);
	ProxySQL_ServerModuleHooks *duplicate_module = module_fixture.create_module(ProxySQL_ServerProtocol::mysql);
	ok(!mgr.register_server_module(duplicate_module, module_fixture.destroy_module, duplicate_handle),
		"reject duplicate protocol module hook");
	module_fixture.destroy_module(duplicate_module);
	dlclose(duplicate_handle);

	mgr.install_server_runtime_snapshot({ProxySQL_ServerProtocol::mysql, 7, {}});
	ok(module_fixture.module_calls() == 1, "retained DSO module callback receives runtime configuration");

	RetainedFixtureSymbols controller_fixture = open_retained_fixture(PROXYSQL_FAKE_PLUGIN2_PATH);
	ok(valid_retained_fixture(controller_fixture), "load controller fixture factories from retained DSO");
	controller_fixture.reset();
	ok(mgr.install_server_discovery_controller(ProxySQL_ServerProtocol::mysql,
		controller_fixture.create_controller(), controller_fixture.destroy_controller, controller_fixture.handle),
		"install DSO-created controller with its DSO destroy callback");
	void *duplicate_controller_handle = open_retained_module(PROXYSQL_FAKE_PLUGIN2_PATH);
	ProxySQL_ServerDiscoveryController *duplicate = controller_fixture.create_controller();
	ok(!mgr.install_server_discovery_controller(ProxySQL_ServerProtocol::mysql, duplicate,
		controller_fixture.destroy_controller, duplicate_controller_handle), "reject a second controller for protocol");
	controller_fixture.destroy_controller(duplicate);
	dlclose(duplicate_controller_handle);
	ok(controller_fixture.controller_calls() == 1,
		"retained DSO controller receives latest committed snapshot exactly once");
	ok(mgr.uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql), "uninstall controller");
	ok(read_log().find("retained_fixture_controller_destroyed") != std::string::npos &&
		!is_module_loaded(PROXYSQL_FAKE_PLUGIN2_PATH),
		"DSO controller destroy code runs before final retained handle release");
	ok(mgr.unregister_server_module(ProxySQL_ServerProtocol::mysql), "uninstall module hook");
	ok(read_log().find("retained_fixture_module_destroyed") != std::string::npos &&
		!is_module_loaded(PROXYSQL_FAKE_PLUGIN_PATH),
		"DSO module destroy code runs before final retained handle release");
	cleanup_log();
}

void test_callback_lease_barrier() {
	{
		std::lock_guard<std::mutex> lock(g_lease_mutex);
		g_callback_entered = false;
		g_callback_release = false;
		g_uninstall_started = false;
		g_destroyed_before_callback_release = false;
	}
	const unsigned int destroyed_before = g_module_destroyed.load();
	ProxySQL_PluginManager mgr;
	ProxySQL_ServerModuleHooks module {
		ProxySQL_ServerProtocol::pgsql, {&module_installed}, nullptr
	};
	void *handle = open_retained_module(PROXYSQL_FAKE_PLUGIN_PATH);
	ok(handle != nullptr && mgr.register_server_module(&module, &destroy_module, handle),
		"register module hook for lease-barrier test");
	mgr.set_server_retirement_observer_for_test(&retirement_observer, nullptr);
	std::thread callback([&] {
		mgr.install_server_runtime_snapshot({ProxySQL_ServerProtocol::pgsql, 8, {}});
	});
	{
		std::unique_lock<std::mutex> lock(g_lease_mutex);
		g_lease_cv.wait(lock, [] { return g_callback_entered; });
	}
	std::thread uninstall([&] {
		mgr.unregister_server_module(ProxySQL_ServerProtocol::pgsql);
	});
	{
		std::unique_lock<std::mutex> lock(g_lease_mutex);
		g_lease_cv.wait(lock, [] { return g_uninstall_started; });
		ok(g_module_destroyed == destroyed_before && !g_destroyed_before_callback_release,
			"registry retirement is observable before the held callback lease permits destroy");
		g_callback_release = true;
	}
	g_lease_cv.notify_all();
	callback.join();
	uninstall.join();
	ok(g_module_destroyed == destroyed_before + 1 && !g_destroyed_before_callback_release &&
		!is_module_loaded(PROXYSQL_FAKE_PLUGIN_PATH),
		"lease barrier releases then destroys and unloads deterministically");
}

void test_throwing_callbacks_do_not_leak_leases() {
	{
		ProxySQL_PluginManager mgr;
		ProxySQL_ServerModuleHooks module {ProxySQL_ServerProtocol::mysql, {&module_installed}, nullptr};
		g_throw_module_callback = true;
		void *handle = open_retained_module(PROXYSQL_FAKE_PLUGIN_PATH);
		bool threw = false;
		try { mgr.register_server_module(&module, &destroy_module, handle); mgr.install_server_runtime_snapshot({ProxySQL_ServerProtocol::mysql, 9, {}}); }
		catch (...) { threw = true; }
		g_throw_module_callback = false;
		g_throw_module_destroy = true;
		const bool retired = mgr.unregister_server_module(ProxySQL_ServerProtocol::mysql);
		g_throw_module_destroy = false;
		ok(!threw && retired && !is_module_loaded(PROXYSQL_FAKE_PLUGIN_PATH),
			"throwing module callback/destroy cannot leak its retirement lease or DSO");
	}
	{
		ProxySQL_PluginManager mgr;
		mgr.install_server_runtime_snapshot({ProxySQL_ServerProtocol::mysql, 7, {}});
		void *handle = open_retained_module(PROXYSQL_FAKE_PLUGIN2_PATH);
		bool threw = false;
		try { mgr.install_server_discovery_controller(ProxySQL_ServerProtocol::mysql,
			new Controller(true), &destroy_controller, handle); }
		catch (...) { threw = true; }
		ok(!threw && mgr.uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql),
			"throwing late-controller notification cannot leak its retirement lease");
	}
	{
		ProxySQL_PluginManager mgr;
		void *handle = open_retained_module(PROXYSQL_FAKE_PLUGIN2_PATH);
		mgr.install_server_discovery_controller(ProxySQL_ServerProtocol::mysql,
			new Controller(false, true, true), &destroy_controller, handle);
		bool threw = false;
		try { mgr.post_server_desired_set({ProxySQL_ServerProtocol::mysql, 11, {}, {}, ProxySQL_ServerPersistence::runtime_only}); }
		catch (...) { threw = true; }
		g_throw_controller_destroy = true;
		const bool retired = mgr.uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql);
		g_throw_controller_destroy = false;
		ok(!threw && retired,
			"throwing desired acknowledgement, shutdown, and destroy still retire controller");
	}
	ok(!is_module_loaded(PROXYSQL_FAKE_PLUGIN2_PATH),
		"throwing controller paths release their retained DSO handles");
}

void test_controller_self_uninstall_reentrancy() {
	SelfUninstallState runtime_state;
	{
		ProxySQL_PluginManager mgr;
		void *handle = open_retained_module(PROXYSQL_FAKE_PLUGIN2_PATH);
		auto *controller = new SelfUninstallController(&mgr, ProxySQL_ServerProtocol::mysql,
			&runtime_state, true);
		ok(handle != nullptr && mgr.install_server_discovery_controller(
			ProxySQL_ServerProtocol::mysql, controller, &destroy_self_uninstall_controller, handle),
			"install controller that self-uninstalls from runtime notification");
		mgr.install_server_runtime_snapshot({ProxySQL_ServerProtocol::mysql, 12, {}});
		ok(runtime_state.entered && runtime_state.uninstall_returned && runtime_state.uninstall_result &&
			runtime_state.destroyed == 1 &&
			!mgr.uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql),
			"runtime callback self-uninstall returns without waiting on its own lease");
		ok(!is_module_loaded(PROXYSQL_FAKE_PLUGIN2_PATH),
			"runtime self-uninstall destroys once and releases its retained handle after return");
	}

	SelfUninstallState desired_state;
	{
		ProxySQL_PluginManager mgr;
		void *handle = open_retained_module(PROXYSQL_FAKE_PLUGIN2_PATH);
		auto *controller = new SelfUninstallController(&mgr, ProxySQL_ServerProtocol::pgsql,
			&desired_state, false);
		ok(handle != nullptr && mgr.install_server_discovery_controller(
			ProxySQL_ServerProtocol::pgsql, controller, &destroy_self_uninstall_controller, handle),
			"install controller that self-uninstalls from desired-set acknowledgement");
		ok(mgr.post_server_desired_set({ProxySQL_ServerProtocol::pgsql, 13, {}, {},
			ProxySQL_ServerPersistence::runtime_only}) && desired_state.entered &&
			desired_state.uninstall_returned && desired_state.uninstall_result,
			"desired-set callback self-uninstall returns without waiting on its own lease");
		ok(desired_state.destroyed == 1 &&
			!mgr.uninstall_server_discovery_controller(ProxySQL_ServerProtocol::pgsql) &&
			!is_module_loaded(PROXYSQL_FAKE_PLUGIN2_PATH),
			"self-retired desired-set controller cannot double-destroy or retain the DSO");
	}
}

void test_controller_self_uninstall_concurrent_external_retirement() {
	ConcurrentSelfUninstallState state;
	ProxySQL_PluginManager mgr;
	void *handle = open_retained_module(PROXYSQL_FAKE_PLUGIN2_PATH);
	ok(handle != nullptr && mgr.install_server_discovery_controller(ProxySQL_ServerProtocol::mysql,
		new ConcurrentSelfUninstallController(&mgr, &state),
		&destroy_concurrent_self_uninstall_controller, handle),
		"install controller for concurrent external uninstall race");
	std::thread callback([&] {
		mgr.post_server_desired_set({ProxySQL_ServerProtocol::mysql, 14, {}, {},
			ProxySQL_ServerPersistence::runtime_only});
	});
	std::thread external([&] {
		std::unique_lock<std::mutex> lock(state.mutex);
		state.cv.wait(lock, [&] { return state.entered; });
		state.external_ready = true;
		state.cv.notify_all();
		state.cv.wait(lock, [&] { return state.self_retired; });
		lock.unlock();
		const bool result = mgr.uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql);
		lock.lock();
		state.external_result = result;
		state.external_finished = true;
		state.cv.notify_all();
	});
	callback.join();
	external.join();
	ok(state.self_result && !state.external_result && state.destroyed == 1,
		"self-retirement linearizes against external uninstall without deadlock or double destroy");
	ok(!is_module_loaded(PROXYSQL_FAKE_PLUGIN2_PATH),
		"concurrent retirement releases the controller DSO after the callback returns");
}

void test_controller_callback_lease_barrier() {
	{
		std::lock_guard<std::mutex> lock(g_lease_mutex);
		g_callback_entered = false;
		g_callback_release = false;
		g_uninstall_started = false;
		g_destroyed_before_callback_release = false;
	}
	const unsigned int destroyed_before = g_controller_destroyed.load();
	ProxySQL_PluginManager mgr;
	void *handle = open_retained_module(PROXYSQL_FAKE_PLUGIN2_PATH);
	ok(handle != nullptr && mgr.install_server_discovery_controller(
		ProxySQL_ServerProtocol::pgsql, new Controller(false, false, false, true),
		&destroy_controller, handle), "register controller with retained DSO for callback-lease test");
	std::thread callback([&] {
		mgr.install_server_runtime_snapshot({ProxySQL_ServerProtocol::pgsql, 8, {}});
	});
	{
		std::unique_lock<std::mutex> lock(g_lease_mutex);
		g_lease_cv.wait(lock, [] { return g_callback_entered; });
	}
	std::thread uninstall([&] {
		{
			std::lock_guard<std::mutex> lock(g_lease_mutex);
			g_uninstall_started = true;
		}
		g_lease_cv.notify_all();
		mgr.uninstall_server_discovery_controller(ProxySQL_ServerProtocol::pgsql);
	});
	{
		std::unique_lock<std::mutex> lock(g_lease_mutex);
		g_lease_cv.wait(lock, [] { return g_uninstall_started; });
		ok(g_controller_destroyed == destroyed_before,
			"controller remains retained while its callback lease is held");
		g_callback_release = true;
	}
	g_lease_cv.notify_all();
	callback.join();
	uninstall.join();
	ok(g_controller_destroyed == destroyed_before + 1 && !is_module_loaded(PROXYSQL_FAKE_PLUGIN2_PATH),
		"controller DSO unloads after its final callback lease drains");
}

} // namespace

int main() {
	plan(54);
	test_abi8_fixture_and_invalid_registration();
	test_service_phase_availability();
	test_steady_state_desired_set_service_lifetime();
	test_lifecycle_delivery_and_retained_handles();
	test_callback_lease_barrier();
	test_throwing_callbacks_do_not_leak_leases();
	test_controller_self_uninstall_reentrancy();
	test_controller_self_uninstall_concurrent_external_retirement();
	test_controller_callback_lease_barrier();
	return exit_status();
}
