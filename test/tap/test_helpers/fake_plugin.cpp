#include "ProxySQL_Plugin.h"

#include <string>

namespace {

bool fake_init(ProxySQL_PluginServices *, std::string &) {
	return true;
}

bool fake_start(std::string &) {
	return true;
}

bool fake_stop() {
	return true;
}

bool fake_status(std::string &) {
	return true;
}

const ProxySQL_PluginDescriptor fake_descriptor = {
	1,
	"fake_plugin",
	&fake_init,
	&fake_start,
	&fake_stop,
	&fake_status,
};

} // namespace

extern "C" const ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	return &fake_descriptor;
}
