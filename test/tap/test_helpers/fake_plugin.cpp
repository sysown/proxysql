#include "ProxySQL_Plugin.h"

#include <cstdio>
#include <cstdlib>

namespace {

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

bool fake_init(ProxySQL_PluginServices *) {
	fake_log_event("init");
	return true;
}

bool fake_start() {
	fake_log_event("start");
	return true;
}

bool fake_stop() {
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
