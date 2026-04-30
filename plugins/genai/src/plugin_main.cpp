/**
 * @file plugin_main.cpp
 * @brief GenAI plugin entry point: descriptor + init/start/stop lifecycle.
 *
 * The plugin manager dlsyms `proxysql_plugin_descriptor_v1` from this
 * shared object at load time.  The returned descriptor wires up:
 *   - `genai_init`    : reserve resources, register Prometheus counters,
 *                       register the query hook for both MySQL and PgSQL,
 *                       construct (but do not yet activate) the
 *                       Anomaly_Detector.
 *   - `genai_start`   : flip the `started` flag — the hook adapter
 *                       starts honoring real analysis from this point.
 *                       (The detector itself has no separate start
 *                       phase today; it is ready immediately after
 *                       construction.)
 *   - `genai_stop`    : tear down the detector and flip `started`
 *                       back off.  Counters remain registered against
 *                       the shared Prometheus registry — there is no
 *                       Unregister API in prometheus-cpp and the cost
 *                       of leaving a stopped counter at its last value
 *                       is negligible.
 *   - `genai_status_json` : tiny JSON status string for SHOW PLUGINS
 *                           equivalents (admin-side query is added in
 *                           a later step).
 *
 * Per the carve-out design, the plugin owns the entire GenAI feature
 * surface.  Step 3 carved out the Anomaly_Detector; later steps move
 * the rest of the GenAI/MCP/LLM stack here.
 *
 * @see docs/superpowers/specs/2026-04-16-genai-plugin-carveout-design.md
 * @see ProxySQL_Plugin.h for the ABI contract.
 */

#include "genai_plugin.h"
#include "Anomaly_Detector.h"
#include "MCP_Thread.h"

#include "prometheus/counter.h"
#include "prometheus/family.h"
#include "prometheus/registry.h"

#include <cstdio>

// Plugin-local definition of the MCP_Threads_Handler global, replacing
// the core-side `GloMCPH` deleted in Step 4.C.  This stays inside the
// .so — the plugin's tool handlers (Query_Tool_Handler etc.) reference
// the symbol locally; core code never sees it.  Lifetime is managed by
// `genai_init` / `genai_stop` below.
MCP_Threads_Handler *GloMCPH = nullptr;

namespace {

/**
 * @brief Register the two GenAI Prometheus counters with the shared registry.
 *
 * Idempotent within a single plugin lifecycle (init() runs once); not
 * safe to call twice — prometheus-cpp will throw on duplicate name in
 * the same registry.  Caller (`genai_init`) guarantees one call.
 *
 * @param ctx  Plugin context; pointers stored in
 *             `metric_detected_anomalies` / `metric_blocked_queries`.
 * @return true on success; false if the Prometheus registry handle was
 *         null (no registry → nothing to register).
 */
bool register_prometheus_counters(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr || ctx.services->get_prometheus_registry == nullptr) {
		return false;
	}
	prometheus::Registry* reg = ctx.services->get_prometheus_registry();
	if (reg == nullptr) {
		return false;
	}

	auto& detected_family = prometheus::BuildCounter()
		.Name("proxysql_genai_detected_anomalies_total")
		.Help("Number of queries the GenAI anomaly detector flagged as anomalous (any risk).")
		.Register(*reg);
	ctx.metric_detected_anomalies = &detected_family.Add({});

	auto& blocked_family = prometheus::BuildCounter()
		.Name("proxysql_genai_blocked_queries_total")
		.Help("Number of queries the GenAI anomaly detector blocked (DENY returned to client).")
		.Register(*reg);
	ctx.metric_blocked_queries = &blocked_family.Add({});
	return true;
}

/**
 * @brief Plugin init callback.  Runs once, on the lifecycle thread,
 *        before any plugin code is hot.
 *
 * Stashes the services pointer, registers Prometheus counters, registers
 * the query hook for both protocols, and constructs the Anomaly_Detector.
 * The detector is instantiated here (not in start()) so any failure
 * surfaces during the gated init phase rather than after admin is up.
 *
 * @param services  Borrowed for the plugin's entire lifetime.  Must not
 *                  be null (the loader has already verified that).
 * @return true on success.  Returning false aborts plugin load and core
 *         startup.
 */
bool genai_init(ProxySQL_PluginServices* services) {
	GenAIPluginContext& ctx = genai_context();
	ctx.services = services;
	ctx.started = false;
	ctx.anomaly_detector = nullptr;
	ctx.mcp = nullptr;

	(void)register_prometheus_counters(ctx);
	// Counter registration failure is non-fatal: it just means metrics
	// won't be exported.  Detector itself still works.

	if (services != nullptr && services->register_query_hook != nullptr) {
		// Register for both MySQL and PgSQL: same callback, same
		// detector instance.  The detector is protocol-agnostic.
		services->register_query_hook(ProxySQL_PluginProtocol::mysql, &genai_query_hook);
		services->register_query_hook(ProxySQL_PluginProtocol::pgsql, &genai_query_hook);
	}

	ctx.anomaly_detector = new Anomaly_Detector();
	if (ctx.anomaly_detector->init() != 0) {
		fprintf(stderr, "genai plugin: Anomaly_Detector::init() failed\n");
		delete ctx.anomaly_detector;
		ctx.anomaly_detector = nullptr;
		return false;
	}

	// Step 4.C: take over MCP_Threads_Handler ownership from former
	// core global GloMCPH.  Construct here; `init()` is called below.
	// `start()` (the listener launch) happens in genai_start().
	//
	// admindb access is not yet available during init() per the chassis
	// ABI (services->get_admindb() returns nullptr until start()), so
	// any plugin-side state that needs it must defer to genai_start.
	ctx.mcp = new MCP_Threads_Handler();
	GloMCPH = ctx.mcp;  // legacy alias used by Query_Tool_Handler etc.
	ctx.mcp->init();
	return true;
}

/**
 * @brief Plugin start callback.  Runs after Admin and the query
 *        processor are up.
 *
 * Flips the `started` flag.  The hook adapter already tolerates a
 * not-yet-started state (returns ALLOW), so this is mostly bookkeeping
 * for the status_json response and any future health-check logic.
 *
 * @return true; this step has no failure mode today.
 */
bool genai_start() {
	GenAIPluginContext& ctx = genai_context();
	ctx.started = true;
	// FIXME(4.F): the MCP listener (ProxySQL_MCP_Server) does not
	// auto-start here.  Pre-4.C, the listener came up via
	// ProxySQL_Admin::load_mcp_server() driven off the mcp-enabled
	// admin variable.  That admin surface is stubbed in core during
	// the 4.C → 4.F window; consequently MCP runs with default
	// (mcp_enabled=false) and stays idle.  4.F restores the admin
	// SQL → plugin path and the listener auto-starts again.
	return true;
}

/**
 * @brief Plugin stop callback.  Runs during shutdown, before unload.
 *
 * Tears down the Anomaly_Detector.  Prometheus counters stay
 * registered (prometheus-cpp has no Unregister API and re-registering
 * on a future load+start of the same plugin would conflict — leaving
 * them registered at their last value is the documented choice).
 *
 * @return true; tear-down has no failure mode today.
 */
bool genai_stop() {
	GenAIPluginContext& ctx = genai_context();
	ctx.started = false;
	if (ctx.mcp != nullptr) {
		// MCP listener teardown.  ~MCP_Threads_Handler stops the
		// embedded ProxySQL_MCP_Server (if running) and joins worker
		// threads.  Mirrors the pre-4.C `delete GloMCPH` in main.cpp.
		delete ctx.mcp;
		ctx.mcp = nullptr;
		GloMCPH = nullptr;
	}
	if (ctx.anomaly_detector != nullptr) {
		ctx.anomaly_detector->close();
		delete ctx.anomaly_detector;
		ctx.anomaly_detector = nullptr;
	}
	return true;
}

/**
 * @brief Status JSON for admin/REST consumers.
 *
 * Returns a string literal — no heap allocation, no caller-owned
 * lifetime.  The ABI contract requires the returned pointer to have
 * static storage duration.
 */
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
