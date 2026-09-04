#include "ProxySQL_Plugin.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
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
// Phase-B callback (Step 2 chassis ABI extension).  Only wired into the
// descriptor when PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B (or the plugin2
// variant) is set.  Toggles via env vars:
//   _PHASE_B_FAIL         -> return false
//   _PHASE_B_REGISTER_TABLE -> register a per-plugin admin table (Phase B)
//   _PHASE_B_REGISTER_MISMATCHED_TWINS -> register same-name admin/config
//                              tables with incompatible definitions
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
	if (env("PHASE_B_REGISTER_CONFIG_ONLY") != nullptr &&
	    services != nullptr &&
	    services->register_table != nullptr) {
		const ProxySQL_PluginTableDef table {
			ProxySQL_PluginDBKind::config_db,
			FAKE_PLUGIN_NAME "_orphan_config",
			"CREATE TABLE " FAKE_PLUGIN_NAME "_orphan_config (id INTEGER)"
		};
		services->register_table(table);
	}
	if (env("PHASE_B_REGISTER_MISMATCHED_TWINS") != nullptr &&
	    services != nullptr &&
	    services->register_table != nullptr) {
		const ProxySQL_PluginTableDef admin_table {
			ProxySQL_PluginDBKind::admin_db,
			FAKE_PLUGIN_NAME "_mismatched_twins",
			"CREATE TABLE " FAKE_PLUGIN_NAME "_mismatched_twins (id INTEGER)"
		};
		const ProxySQL_PluginTableDef config_table {
			ProxySQL_PluginDBKind::config_db,
			FAKE_PLUGIN_NAME "_mismatched_twins",
			"CREATE TABLE " FAKE_PLUGIN_NAME "_mismatched_twins (id INTEGER, extra TEXT)"
		};
		services->register_table(admin_table);
		services->register_table(config_table);
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
	if (env("REGISTER_CONFIG_TABLE") != nullptr &&
	    services != nullptr &&
	    services->register_table != nullptr) {
		const ProxySQL_PluginTableDef table {
			ProxySQL_PluginDBKind::config_db,
			FAKE_PLUGIN_NAME "_late_config_table",
			"CREATE TABLE " FAKE_PLUGIN_NAME "_late_config_table (id INTEGER)"
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
