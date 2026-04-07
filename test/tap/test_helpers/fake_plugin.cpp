#include "ProxySQL_Plugin.h"

namespace {

bool fake_init(ProxySQL_PluginServices *) {
	return true;
}

bool fake_start() {
	return true;
}

bool fake_stop() {
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
