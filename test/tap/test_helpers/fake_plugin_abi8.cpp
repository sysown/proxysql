// A descriptor compiled against the pre-ABI-9 service tail. Its descriptor
// layout is unchanged, and it intentionally neither reads nor initializes
// ABI-9 services.
#include "ProxySQL_Plugin.h"

#include <cstdlib>

namespace {

bool init(ProxySQL_PluginServices *) { return true; }
bool start() { return true; }
bool stop() { return true; }
const char *status_json() { return "{\"name\":\"fake_plugin_abi8\"}"; }

const ProxySQL_PluginDescriptor descriptor {
	"fake_plugin_abi8", 8u, &init, &start, &stop, &status_json, nullptr
};

const ProxySQL_PluginDescriptor unsupported_descriptor {
	"fake_plugin_abi10", 10u, &init, &start, &stop, &status_json, nullptr
};

} // namespace

extern "C" const ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_ABI8_FORCE_ABI10") != nullptr) {
		return &unsupported_descriptor;
	}
	return &descriptor;
}
