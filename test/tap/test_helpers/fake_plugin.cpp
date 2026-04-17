#include "ProxySQL_Plugin.h"

#include <cstdio>
#include <cstdlib>

namespace {

ProxySQL_PluginServices* fake_services = nullptr;

ProxySQL_PluginCommandResult fake_command(const ProxySQL_PluginCommandContext&, const char*) {
	return {0, 1, "fake command executed"};
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
