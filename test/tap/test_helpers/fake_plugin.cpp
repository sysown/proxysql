#include "ProxySQL_Plugin.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

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

void fake_log_event(const char *event);

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

bool fake_register_cli_options(ProxySQL_PluginCLIRegistry* registry) {
	if (registry == nullptr || registry->add == nullptr) return false;
	const ProxySQL_PluginCLIOptionDef option {
		"", "--fake-plugin-action", 1, false, "Fake plugin early action"
	};
	const char* error = nullptr;
	const bool registered = registry->add(registry->opaque, option, &error);
	if (registered) fake_log_event("register_cli");
	return registered;
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
	if (env("PHASE_B_TEST_SECRETS") != nullptr && services != nullptr) {
		std::vector<uint8_t> output { 0x7f };
		const uint8_t byte = 0x42;
		const bool unavailable = services->put_secret != nullptr &&
			services->get_secret != nullptr && services->erase_secret != nullptr &&
			services->put_secret("fake_plugin", "phase_b", &byte, 1) == ProxySQL_PluginSecretResult::not_available &&
			services->get_secret("fake_plugin", "phase_b", output) == ProxySQL_PluginSecretResult::not_available &&
			services->erase_secret("fake_plugin", "phase_b") == ProxySQL_PluginSecretResult::not_available &&
			output.empty();
		fake_log_event(unavailable ? "phase_b_secrets_not_available" : "phase_b_secrets_available");
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
	fake_log_event("phase_b");
	return true;
}

ProxySQL_PluginEarlyActionResult fake_early_action(
	const ProxySQL_PluginEarlyActionContext& context) {
	if (context.services == nullptr || context.services->get_admindb == nullptr ||
		context.services->get_admindb() == nullptr || context.is_set == nullptr ||
		context.get_string == nullptr || !context.is_set(context.option_context,
		"--fake-plugin-action")) {
		return ProxySQL_PluginEarlyActionResult::exit_failure;
	}
	std::string action;
	if (!context.get_string(context.option_context, "--fake-plugin-action", action)) {
		return ProxySQL_PluginEarlyActionResult::exit_failure;
	}
	fake_log_event("early_action");
	if (action == "exit_success") {
		return ProxySQL_PluginEarlyActionResult::exit_success;
	}
	if (action == "exit_failure") {
		return ProxySQL_PluginEarlyActionResult::exit_failure;
	}
	if (action == "throw") throw 1;
	if (action != "continue") return ProxySQL_PluginEarlyActionResult::not_requested;
	return ProxySQL_PluginEarlyActionResult::continue_startup;
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
	fake_log_event("start");
	return true;
}

#ifdef PROXYSQL40
bool fake_runtime_ready(ProxySQL_PluginRuntimeContext* context) {
	if (context == nullptr || context->services == nullptr ||
		context->services->set_listener_gate == nullptr) {
		return false;
	}
	if (env("RUNTIME_READY_MUTATE_CONTEXT") != nullptr) {
		context->services = nullptr;
		context->startup_monotonic_us = 0;
		fake_log_event("runtime_ready_mutated_context");
		return true;
	}
	const ProxySQL_PluginListenerGate listener_gate {
		FAKE_PLUGIN_NAME, "127.0.0.1", 6450,
		env("RUNTIME_READY_INSTALL_READY") != nullptr
			? ProxySQL_PluginListenerState::ready : ProxySQL_PluginListenerState::closed,
		"fake plugin has not reconciled"
	};
	if (!context->services->set_listener_gate(listener_gate)) return false;
	if (env("RUNTIME_READY_THROW") != nullptr) {
		fake_log_event("runtime_ready_throw");
		throw "fake runtime readiness exception";
	}
	if (env("RUNTIME_READY_FAIL") != nullptr) {
		fake_log_event("runtime_ready_fail");
		return false;
	}
	fake_log_event("runtime_ready");
	return true;
}
#endif /* PROXYSQL40 */

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

// ABI 6 descriptor used by the CLI registration tests. The callback is a
// descriptor tail field, so the manager must read it only for ABI >= 6.
const ProxySQL_PluginDescriptor fake_descriptor_with_cli = {
	FAKE_PLUGIN_NAME,
	6,
	&fake_init,
	&fake_start,
	&fake_stop,
	&fake_status_json,
	nullptr,
	&fake_register_cli_options,
	nullptr,
};

const ProxySQL_PluginDescriptor fake_descriptor_with_early_action = {
	FAKE_PLUGIN_NAME,
	6,
	&fake_init,
	&fake_start,
	&fake_stop,
	&fake_status_json,
	&fake_register_schemas,
	&fake_register_cli_options,
	&fake_early_action,
};

const ProxySQL_PluginDescriptor fake_descriptor_with_runtime_ready = {
	FAKE_PLUGIN_NAME,
	8,
	&fake_init,
	&fake_start,
	&fake_stop,
	&fake_status_json,
	nullptr,
	nullptr,
	nullptr,
	&fake_runtime_ready,
};

// This object intentionally uses the ABI-5 descriptor shape. It has no ABI-6
// tail field. Returning it through the current descriptor pointer type models
// a plugin compiled before register_cli_options existed; the manager must not
// inspect beyond register_schemas when abi_version is 5.
struct fake_descriptor_v5_layout {
	const char* name;
	uint32_t abi_version;
	proxysql_plugin_init_cb init;
	proxysql_plugin_start_cb start;
	proxysql_plugin_stop_cb stop;
	proxysql_plugin_status_json_cb status_json;
	proxysql_plugin_register_schemas_cb register_schemas;
};
const fake_descriptor_v5_layout fake_descriptor_abi5 = {
	FAKE_PLUGIN_NAME,
	5,
	&fake_init,
	&fake_start,
	&fake_stop,
	&fake_status_json,
	nullptr,
};

// ABI 7 has the complete pre-runtime-ready descriptor prefix but no ABI-8
// tail. Returning this shorter layout verifies the loader never reads the
// runtime_ready member for secret-service-era plugins.
struct fake_descriptor_v7_layout {
	const char* name;
	uint32_t abi_version;
	proxysql_plugin_init_cb init;
	proxysql_plugin_start_cb start;
	proxysql_plugin_stop_cb stop;
	proxysql_plugin_status_json_cb status_json;
	proxysql_plugin_register_schemas_cb register_schemas;
	proxysql_plugin_register_cli_options_cb register_cli_options;
	proxysql_plugin_early_action_cb early_action;
};
const fake_descriptor_v7_layout fake_descriptor_abi7 = {
	FAKE_PLUGIN_NAME,
	7,
	&fake_init,
	&fake_start,
	&fake_stop,
	&fake_status_json,
	nullptr,
	nullptr,
	nullptr,
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
	if (env("ENABLE_ABI5_TAIL_GUARD") != nullptr) {
		return reinterpret_cast<const ProxySQL_PluginDescriptor*>(&fake_descriptor_abi5);
	}
	if (env("ENABLE_ABI7_TAIL_GUARD") != nullptr) {
		return reinterpret_cast<const ProxySQL_PluginDescriptor*>(&fake_descriptor_abi7);
	}
	if (env("ENABLE_CLI") != nullptr) {
		return &fake_descriptor_with_cli;
	}
	if (env("ENABLE_EARLY_ACTION") != nullptr) {
		return &fake_descriptor_with_early_action;
	}
	if (env("ENABLE_RUNTIME_READY") != nullptr) {
		return &fake_descriptor_with_runtime_ready;
	}
	if (env("ENABLE_PHASE_B") != nullptr) {
		return &fake_descriptor_with_phase_b;
	}
#endif /* PROXYSQL40 */
	return &fake_descriptor;
}
