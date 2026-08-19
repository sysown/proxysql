#include "ProxySQL_Plugin.h"

#include <cstdio>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <string>

// Two builds of this source produce two distinct .so files used together
// in multi-plugin tests:
//   * libproxysql_fake_plugin.so   — plugin name "fake_plugin",  env vars PROXYSQL_FAKE_PLUGIN_*
//   * libproxysql_fake_plugin2.so  — plugin name "fake_plugin2", env vars PROXYSQL_FAKE_PLUGIN2_*
//
// FAKE_PLUGIN_NAME / FAKE_PLUGIN_ENV_PREFIX are -D'd by the Makefile.
#ifndef FAKE_PLUGIN_NAME
#define FAKE_PLUGIN_NAME "fake_plugin"
#endif
#ifndef FAKE_PLUGIN_ENV_PREFIX
#define FAKE_PLUGIN_ENV_PREFIX "PROXYSQL_FAKE_PLUGIN_"
#endif

namespace {

ProxySQL_PluginServices* fake_services = nullptr;
#ifdef PROXYSQL40
proxysql_plugin_post_server_desired_set_cb fake_post_server_desired_set = nullptr;
std::atomic<unsigned int> retained_fixture_module_calls {0};
std::atomic<unsigned int> retained_fixture_controller_calls {0};
#endif

ProxySQL_PluginCommandResult fake_command(const ProxySQL_PluginCommandContext&, const char*) {
	return {0, 1, "fake command executed"};
}

#ifdef PROXYSQL40
ProxySQL_PluginQueryHookResult fake_query_hook(const ProxySQL_PluginQueryHookPayload& payload) {
	// Echo the SQL back through the message field so tests can verify the
	// payload was wired through.  DENY-vs-ALLOW is selected by env var so
	// a test can exercise both paths without rebuilding the plugin.
	std::string msg(payload.query_text, payload.query_len);
	const char* deny_env = std::getenv("PROXYSQL_FAKE_PLUGIN_HOOK_DENY");
	if (deny_env == nullptr) {
		deny_env = std::getenv("PROXYSQL_FAKE_PLUGIN2_HOOK_DENY");
	}
	if (deny_env != nullptr && *deny_env != '\0') {
		return {ProxySQL_PluginQueryHookAction::deny, std::string("denied: ") + msg};
	}
	return {ProxySQL_PluginQueryHookAction::allow, msg};
}
#endif /* PROXYSQL40 */

const char* env(const char* suffix) {
	static char name[128];
	std::snprintf(name, sizeof(name), "%s%s", FAKE_PLUGIN_ENV_PREFIX, suffix);
	return std::getenv(name);
}

void fake_log_event(const char *event) {
	const char *log_path = env("LOG");
	if (log_path == nullptr || *log_path == '\0') {
		return;
	}

	FILE *log_file = std::fopen(log_path, "a");
	if (log_file == nullptr) {
		return;
	}

	std::fprintf(log_file, "%s:%s\n", FAKE_PLUGIN_NAME, event);
	std::fclose(log_file);
}

#ifdef PROXYSQL40
void fake_server_module_installed(void *, ProxySQL_ServerRuntimeSnapshot) {}
bool fake_server_module_prepare(void *, const ProxySQL_ServerModuleSnapshot&,
	std::vector<ProxySQL_ServerHostgroupClaim>& claims, std::string&) {
	if (env("SERVER_MODULE_CONFLICT_CLAIM") != nullptr)
		claims.push_back({17, 18});
	return true;
}
void fake_server_module_commit(void *, uint64_t) {}
SQLite3_result* fake_server_module_table_snapshot(void *, const char *) { return nullptr; }
void fake_server_module_shutdown(void *) {}
void fake_destroy_server_module(ProxySQL_ServerModuleHooks *) {
	fake_log_event("server_module_destroyed");
}

ProxySQL_ServerModuleHooks fake_server_module_hooks {
	ProxySQL_ServerProtocol::mysql, &fake_server_module_installed, nullptr
};
ProxySQL_ServerModuleHooks fake_affiliated_server_module_hooks {
	ProxySQL_ServerProtocol::mysql,
	{{ProxySQL_ServerProtocol::mysql, "mysql_fake_server_module_claims", "runtime_mysql_fake_server_module_claims", "writer"}}
};

void *retain_fake_module() {
	Dl_info info {};
	if (dladdr(reinterpret_cast<void *>(&fake_server_module_installed), &info) == 0 ||
		info.dli_fname == nullptr) {
		return nullptr;
	}
	return dlopen(info.dli_fname, RTLD_NOW | RTLD_LOCAL);
}

bool fake_register_server_module(ProxySQL_PluginServices *services) {
	if (services == nullptr || services->register_server_module == nullptr) return false;
	void *module = retain_fake_module();
	if (module == nullptr) return false;
	ProxySQL_ServerModuleHooks *hooks = &fake_server_module_hooks;
	if (env("AFFILIATED") != nullptr) {
		fake_affiliated_server_module_hooks.prepare_runtime = &fake_server_module_prepare;
		fake_affiliated_server_module_hooks.commit_runtime = &fake_server_module_commit;
		fake_affiliated_server_module_hooks.runtime_table_snapshot = &fake_server_module_table_snapshot;
		fake_affiliated_server_module_hooks.shutdown = &fake_server_module_shutdown;
		hooks = &fake_affiliated_server_module_hooks;
	}
	if (!services->register_server_module(hooks,
		&fake_destroy_server_module, module)) {
		dlclose(module);
		return false;
	}
	return true;
}

class FakeServerDiscoveryController final : public ProxySQL_ServerDiscoveryController {
public:
	void runtime_configuration_installed(ProxySQL_ServerRuntimeSnapshot) override {
		fake_log_event("server_controller_runtime");
	}
	void desired_set_applied(uint64_t, bool) override {
		fake_log_event("server_controller_desired_set");
	}
	void shutdown() override {
		fake_log_event("server_controller_shutdown");
	}
};

void retained_fixture_module_installed(void *, ProxySQL_ServerRuntimeSnapshot) {
	retained_fixture_module_calls.fetch_add(1);
}

void retained_fixture_destroy_module(ProxySQL_ServerModuleHooks *module) {
	fake_log_event("retained_fixture_module_destroyed");
	delete module;
}

class RetainedFixtureController final : public ProxySQL_ServerDiscoveryController {
public:
	void runtime_configuration_installed(ProxySQL_ServerRuntimeSnapshot) override {
		retained_fixture_controller_calls.fetch_add(1);
	}
	void desired_set_applied(uint64_t, bool) override {}
	void shutdown() override { fake_log_event("retained_fixture_controller_shutdown"); }
};

void retained_fixture_destroy_controller(ProxySQL_ServerDiscoveryController *controller) {
	fake_log_event("retained_fixture_controller_destroyed");
	delete controller;
}

void fake_destroy_server_discovery_controller(ProxySQL_ServerDiscoveryController *controller) {
	fake_log_event("server_controller_destroyed");
	delete controller;
}

bool fake_install_server_discovery_controller(ProxySQL_PluginServices *services) {
	if (services == nullptr || services->install_server_discovery_controller == nullptr) return false;
	void *module = retain_fake_module();
	if (module == nullptr) return false;
	auto *controller = new FakeServerDiscoveryController();
	if (!services->install_server_discovery_controller(ProxySQL_ServerProtocol::mysql,
		controller, &fake_destroy_server_discovery_controller, module)) {
		delete controller;
		dlclose(module);
		return false;
	}
	return true;
}
#endif /* PROXYSQL40 */

#ifdef PROXYSQL40
// Phase-B callback (Step 2 chassis ABI extension).  Only wired into the
// descriptor when PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B (or the plugin2
// variant) is set.  Toggles via env vars:
//   _PHASE_B_FAIL         -> return false
//   _PHASE_B_REGISTER_TABLE -> register a per-plugin admin table (Phase B)
//   _PHASE_B_TOUCH_HANDLES  -> try to call DB handle getters; if they come
//                              back null we log "phase_b_handles_null",
//                              otherwise "phase_b_handles_live" (the
//                              lifecycle contract says they must be null).
bool fake_register_schemas(ProxySQL_PluginServices *services) {
	fake_services = services;
	// _PHASE_B_PARTIAL_THEN_FAIL: register a table first, then return
	// false.  Tests that the loader rolls back the registration so a
	// retry doesn't trip on the leftover.
	if (env("PHASE_B_PARTIAL_THEN_FAIL") != nullptr &&
	    services != nullptr &&
	    services->register_table != nullptr) {
		const ProxySQL_PluginTableDef table {
			ProxySQL_PluginDBKind::admin_db,
			FAKE_PLUGIN_NAME "_partial_table",
			"CREATE TABLE " FAKE_PLUGIN_NAME "_partial_table (id INTEGER)"
		};
		services->register_table(table);
		fake_log_event("phase_b_partial_then_fail");
		return false;
	}
	if (env("PHASE_B_FAIL") != nullptr) {
		fake_log_event("phase_b_fail");
		return false;
	}
	if (env("PHASE_B_TOUCH_HANDLES") != nullptr &&
	    services != nullptr) {
		// Contract: during Phase B the getters are non-null stub
		// functions that return nullptr.  A nullptr function pointer
		// would mean plugins can't even call them unconditionally —
		// that breaks the contract just as much as returning a live
		// handle does.  Distinguish the three outcomes so the test can
		// assert the exact one we advertise.
		if (services->get_admindb == nullptr ||
		    services->get_configdb == nullptr ||
		    services->get_statsdb == nullptr) {
			fake_log_event("phase_b_getter_null");
		} else {
			SQLite3DB* a = services->get_admindb();
			SQLite3DB* c = services->get_configdb();
			SQLite3DB* s = services->get_statsdb();
			if (a == nullptr && c == nullptr && s == nullptr) {
				fake_log_event("phase_b_handles_null");
			} else {
				fake_log_event("phase_b_handles_live");
			}
		}
	}
	if (env("PHASE_B_REGISTER_TABLE") != nullptr &&
	    services != nullptr &&
	    services->register_table != nullptr) {
		const ProxySQL_PluginTableDef table {
			ProxySQL_PluginDBKind::admin_db,
			FAKE_PLUGIN_NAME "_phase_b_table",
			"CREATE TABLE " FAKE_PLUGIN_NAME "_phase_b_table (id INTEGER)"
		};
		services->register_table(table);
	}
	if (env("PHASE_B_SERVER_DISCOVERY") != nullptr && services != nullptr) {
		if (services->register_server_module != nullptr &&
			services->install_server_discovery_controller == nullptr &&
			services->uninstall_server_discovery_controller == nullptr &&
			services->post_server_desired_set == nullptr) {
			fake_log_event("phase_b_server_discovery_availability");
		}
		if (fake_register_server_module(services)) {
			fake_log_event("phase_b_server_module_registered");
		} else {
			fake_log_event("phase_b_server_module_rejected");
		}
	}
	fake_log_event("phase_b");
	return true;
}
#endif /* PROXYSQL40 */

bool fake_init(ProxySQL_PluginServices *services) {
	fake_services = services;
	if (env("INIT_FAIL") != nullptr) {
		fake_log_event("init_fail");
		return false;
	}
	if (env("REGISTER_INVALID_TABLE") != nullptr &&
	    services != nullptr &&
	    services->register_table != nullptr) {
		const ProxySQL_PluginTableDef invalid_table {
			static_cast<ProxySQL_PluginDBKind>(255),
			"fake_invalid_table",
			"CREATE TABLE fake_invalid_table (id INTEGER)"
		};
		services->register_table(invalid_table);
	}
	if (env("REGISTER_COMMAND") != nullptr &&
	    services != nullptr &&
	    services->register_command != nullptr) {
		const char* sql = env("REGISTER_COMMAND_SQL");
		services->register_command(sql != nullptr ? sql : "PLUGIN FAKE NOOP", &fake_command);
	}
#ifdef PROXYSQL40
	if (env("CHECK_SERVER_DISCOVERY_INIT") != nullptr && services != nullptr) {
		if (services->register_server_module != nullptr &&
			services->install_server_discovery_controller != nullptr &&
			services->uninstall_server_discovery_controller != nullptr &&
			services->post_server_desired_set != nullptr) {
			fake_log_event("init_server_discovery_live");
		} else {
			fake_log_event("init_server_discovery_unavailable");
		}
	}
	if (services != nullptr) {
		fake_post_server_desired_set = services->post_server_desired_set;
	}
	if (env("INSTALL_SERVER_DISCOVERY_CONTROLLER") != nullptr) {
		if (fake_install_server_discovery_controller(services)) {
			fake_log_event("init_server_controller_installed");
		} else {
			fake_log_event("init_server_controller_rejected");
		}
	}
	if (env("REGISTER_COMMAND_ALIAS") != nullptr &&
	    services != nullptr &&
	    services->register_command_alias != nullptr) {
		const char* canonical = env("REGISTER_COMMAND_ALIAS_CANONICAL");
		const char* alias = env("REGISTER_COMMAND_ALIAS_SQL");
		if (canonical != nullptr && alias != nullptr) {
			services->register_command_alias(canonical, alias);
		}
	}
#endif /* PROXYSQL40 */
	if (env("REGISTER_TABLE") != nullptr &&
	    services != nullptr &&
	    services->register_table != nullptr) {
		const ProxySQL_PluginTableDef table {
			ProxySQL_PluginDBKind::admin_db,
			FAKE_PLUGIN_NAME "_table",
			"CREATE TABLE " FAKE_PLUGIN_NAME "_table (id INTEGER)"
		};
		services->register_table(table);
	}
#ifdef PROXYSQL40
	if (env("REGISTER_QUERY_HOOK") != nullptr &&
	    services != nullptr &&
	    services->register_query_hook != nullptr) {
		const char* proto_env = env("REGISTER_QUERY_HOOK_PROTO");
		ProxySQL_PluginProtocol proto = ProxySQL_PluginProtocol::mysql;
		if (proto_env != nullptr && std::strcmp(proto_env, "pgsql") == 0) {
			proto = ProxySQL_PluginProtocol::pgsql;
		}
		services->register_query_hook(proto, &fake_query_hook);
	}
#endif /* PROXYSQL40 */
	fake_log_event("init");
	return true;
}

bool fake_start() {
	if (env("START_FAIL") != nullptr) {
		fake_log_event("start_fail");
		return false;
	}
	if (fake_services == nullptr ||
	    fake_services->get_admindb == nullptr ||
	    fake_services->get_configdb == nullptr ||
	    fake_services->get_statsdb == nullptr ||
	    fake_services->get_admindb() == nullptr ||
	    fake_services->get_configdb() == nullptr ||
	    fake_services->get_statsdb() == nullptr) {
		return false;
	}
#ifdef PROXYSQL40
	if (env("START_REGISTER_SERVER_MODULE") != nullptr) {
		if (fake_register_server_module(fake_services)) {
			fake_log_event("start_server_module_registered");
		} else {
			fake_log_event("start_server_module_rejected");
		}
	}
	if (env("START_POST_SERVER_DESIRED_SET") != nullptr) {
		const ProxySQL_ServerDesiredSet desired {
			ProxySQL_ServerProtocol::mysql, 42, {}, {}, ProxySQL_ServerPersistence::runtime_only
		};
		if (fake_services != nullptr && fake_services->post_server_desired_set != nullptr &&
			fake_services->post_server_desired_set(desired)) {
			fake_log_event("start_server_desired_set_posted");
		} else {
			fake_log_event("start_server_desired_set_rejected");
		}
	}
#endif /* PROXYSQL40 */
	fake_log_event("start");
	return true;
}

bool fake_stop() {
	if (env("STOP_FAIL") != nullptr) {
		fake_log_event("stop_fail");
		return false;
	}
	fake_log_event("stop");
	return true;
}

const char *fake_status_json() {
	return "{\"name\":\"" FAKE_PLUGIN_NAME "\",\"state\":\"running\"}";
}

// Pre-Step-2.2 descriptor layout (six fields).  Used when the plugin is
// NOT opting into Phase B -- register_schemas is implicitly null because
// the field is absent.  Leaves us testing that plugins built against the
// older descriptor still work under the new loader.  abi_version stays
// at 1 regardless of the compile-time PROXYSQL40 flag so this descriptor
// represents the "legacy plugin" shape the v4 loader has to accept.
const ProxySQL_PluginDescriptor fake_descriptor = {
	FAKE_PLUGIN_NAME,
	1,
	&fake_init,
	&fake_start,
	&fake_stop,
	&fake_status_json,
};

#ifdef PROXYSQL40
// Phase-B-aware descriptor: same as above but wires the register_schemas
// entry.  Selected at plugin-discovery time when the env toggle is set.
// abi_version 2 tells the loader this descriptor has the seventh field.
const ProxySQL_PluginDescriptor fake_descriptor_with_phase_b = {
	FAKE_PLUGIN_NAME,
	2,
	&fake_init,
	&fake_start,
	&fake_stop,
	&fake_status_json,
	&fake_register_schemas,
};
#endif /* PROXYSQL40 */

// Descriptor with a bogus ABI version -- used by lifecycle tests to
// verify the loader's version check rejects unknown ABIs rather than
// reading past the end of the plugin's struct.
const ProxySQL_PluginDescriptor fake_descriptor_bogus_abi = {
	FAKE_PLUGIN_NAME,
	99,
	&fake_init,
	&fake_start,
	&fake_stop,
	&fake_status_json,
};

} // namespace

extern "C" const ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	if (env("FORCE_BOGUS_ABI") != nullptr) {
		return &fake_descriptor_bogus_abi;
	}
#ifdef PROXYSQL40
	if (env("ENABLE_PHASE_B") != nullptr) {
		return &fake_descriptor_with_phase_b;
	}
#endif /* PROXYSQL40 */
	return &fake_descriptor;
}

#ifdef PROXYSQL40
// This intentionally retains only the service function pointer, never the
// transient services table.  Unit tests keep this DSO separately loaded and
// invoke it after manager unpublication to prove the callback fails closed.
extern "C" bool proxysql_fake_post_server_desired_set_for_test() {
	if (fake_post_server_desired_set == nullptr) return false;
	const ProxySQL_ServerDesiredSet desired {
		ProxySQL_ServerProtocol::mysql, 43, {}, {}, ProxySQL_ServerPersistence::runtime_only
	};
	return fake_post_server_desired_set(desired);
}

extern "C" proxysql_plugin_post_server_desired_set_cb
proxysql_fake_post_server_desired_set_callback_for_test() {
	return fake_post_server_desired_set;
}

// These factories, callbacks, and destroy functions are intentionally
// exported from the fixture DSO.  The lease tests pass their addresses into
// the manager, so its retained dlopen reference protects code it really
// invokes (rather than only an unrelated fixture handle).
extern "C" ProxySQL_ServerModuleHooks *proxysql_fake_retained_module_create(
	ProxySQL_ServerProtocol protocol) {
	return new ProxySQL_ServerModuleHooks {protocol, &retained_fixture_module_installed, nullptr};
}

extern "C" void proxysql_fake_retained_module_destroy(ProxySQL_ServerModuleHooks *module) {
	retained_fixture_destroy_module(module);
}

extern "C" ProxySQL_ServerDiscoveryController *proxysql_fake_retained_controller_create() {
	return new RetainedFixtureController();
}

extern "C" void proxysql_fake_retained_controller_destroy(
	ProxySQL_ServerDiscoveryController *controller) {
	retained_fixture_destroy_controller(controller);
}

extern "C" void proxysql_fake_retained_fixture_reset() {
	retained_fixture_module_calls.store(0);
	retained_fixture_controller_calls.store(0);
}

extern "C" unsigned int proxysql_fake_retained_fixture_module_calls() {
	return retained_fixture_module_calls.load();
}

extern "C" unsigned int proxysql_fake_retained_fixture_controller_calls() {
	return retained_fixture_controller_calls.load();
}
#endif /* PROXYSQL40 */
