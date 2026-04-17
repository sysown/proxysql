#include "ProxySQL_Plugin.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

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

void fake_log_event(const char *event) {
	const char *log_path = std::getenv("PROXYSQL_FAKE_PLUGIN_LOG");
	if (log_path == nullptr || *log_path == '\0') {
		return;
	}

	FILE *log_file = std::fopen(log_path, "a");
	if (log_file == nullptr) {
		return;
	}

	std::fprintf(log_file, "%s\n", event);
	std::fclose(log_file);
}

bool fake_init(ProxySQL_PluginServices *services) {
	fake_services = services;
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_INIT_FAIL") != nullptr) {
		fake_log_event("init_fail");
		return false;
	}
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_REGISTER_INVALID_TABLE") != nullptr &&
	    services != nullptr &&
	    services->register_table != nullptr) {
		const ProxySQL_PluginTableDef invalid_table {
			static_cast<ProxySQL_PluginDBKind>(255),
			"fake_invalid_table",
			"CREATE TABLE fake_invalid_table (id INTEGER)"
		};
		services->register_table(invalid_table);
	}
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_REGISTER_COMMAND") != nullptr &&
	    services != nullptr &&
	    services->register_command != nullptr) {
		services->register_command("PLUGIN FAKE NOOP", &fake_command);
	}
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_REGISTER_QUERY_HOOK") != nullptr &&
	    services != nullptr &&
	    services->register_query_hook != nullptr) {
		const char* proto_env = std::getenv("PROXYSQL_FAKE_PLUGIN_REGISTER_QUERY_HOOK_PROTO");
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
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_START_FAIL") != nullptr) {
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
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_STOP_FAIL") != nullptr) {
		fake_log_event("stop_fail");
		return false;
	}
	fake_log_event("stop");
	return true;
}

const char *fake_status_json() {
	return "{\"name\":\"fake_plugin\",\"state\":\"running\"}";
}

const ProxySQL_PluginDescriptor fake_descriptor = {
	"fake_plugin",
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
