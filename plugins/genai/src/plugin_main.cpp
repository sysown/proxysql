// Step 1 skeleton: the plugin descriptor exists, the .so loads, init/start/
// stop succeed without doing anything.  Subsequent migration steps (per
// docs/superpowers/specs/2026-04-16-genai-plugin-carveout-design.md) will
// fill these out with the real GenAI/MCP/anomaly-detector lifecycle.

#include "genai_plugin.h"

namespace {

bool genai_init(ProxySQL_PluginServices* services) {
	GenAIPluginContext& ctx = genai_context();
	ctx.services = services;
	ctx.started = false;
	return true;
}

bool genai_start() {
	GenAIPluginContext& ctx = genai_context();
	ctx.started = true;
	return true;
}

bool genai_stop() {
	GenAIPluginContext& ctx = genai_context();
	ctx.started = false;
	return true;
}

const char* genai_status_json() {
	const GenAIPluginContext& ctx = genai_context();
	if (ctx.started) {
		return "{\"name\":\"genai\",\"state\":\"running\"}";
	}
	return "{\"name\":\"genai\",\"state\":\"stopped\"}";
}

const ProxySQL_PluginDescriptor genai_descriptor = {
	"genai",
	1,
	&genai_init,
	&genai_start,
	&genai_stop,
	&genai_status_json,
};

} // namespace

GenAIPluginContext& genai_context() {
	static GenAIPluginContext ctx {};
	return ctx;
}

extern "C" const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
	return &genai_descriptor;
}
