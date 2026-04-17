#ifndef PROXYSQL_GENAI_PLUGIN_H
#define PROXYSQL_GENAI_PLUGIN_H

#include "ProxySQL_Plugin.h"

#include <atomic>

// Plugin-wide context.  Step 1 carries only lifecycle state; subsequent
// steps will accumulate the GenAI/MCP/anomaly-detector subsystem owners
// here as they migrate out of core.
struct GenAIPluginContext {
	ProxySQL_PluginServices* services { nullptr };
	std::atomic<bool> started { false };
};

GenAIPluginContext& genai_context();

#endif /* PROXYSQL_GENAI_PLUGIN_H */
