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

const ProxySQL_PluginDescriptor fake_descriptor = {
	FAKE_PLUGIN_NAME,
	1,
	&fake_init,
	&fake_start,
	&fake_stop,
	&fake_status_json,
};

} // namespace

extern "C" const ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	return &fake_descriptor;
}
