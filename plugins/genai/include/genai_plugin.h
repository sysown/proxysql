/**
 * @file genai_plugin.h
 * @brief GenAI plugin shared context + plugin-wide entry points.
 *
 * Holds the singletons the plugin owns at runtime (services pointer
 * received during init, optional Anomaly_Detector instance, Prometheus
 * counter handles), plus declarations for helper functions defined in
 * sibling translation units (e.g. plugin_hooks.cpp).
 *
 * Lifecycle is documented per-field below.  Plugins MUST NOT touch any
 * field that depends on Admin DBs (none today; Step 4 will add some)
 * before `start()` runs — see ProxySQL_Plugin.h for the full contract.
 *
 * @see plugins/genai/src/plugin_main.cpp for descriptor + lifecycle.
 * @see plugins/genai/src/plugin_hooks.cpp for the query-hook adapter.
 */

#ifndef PROXYSQL_GENAI_PLUGIN_H
#define PROXYSQL_GENAI_PLUGIN_H

#include "ProxySQL_Plugin.h"

#include <atomic>

namespace prometheus { class Counter; }
class Anomaly_Detector;
class MCP_Threads_Handler;

/**
 * @brief Process-wide state shared across the plugin's translation units.
 *
 * Singleton accessed via genai_context().  Populated by `genai_init()`
 * and `genai_start()` in plugin_main.cpp; torn down by `genai_stop()`.
 */
struct GenAIPluginContext {
	/// Services callbacks vended by core during init().  Borrowed; do
	/// not free.  Valid for the plugin's entire lifetime.
	ProxySQL_PluginServices* services { nullptr };

	/// True between successful start() and stop().  Hot-path readers
	/// outside the plugin lifecycle (e.g. the query-hook adapter) read
	/// it relaxed; it is only mutated on the lifecycle thread.
	std::atomic<bool> started { false };

	/// Anomaly detector instance.  Created during init(), deleted
	/// during stop().  nullptr before init() and after stop().
	Anomaly_Detector* anomaly_detector { nullptr };

	/// Prometheus counter for anomalies *detected* (any risk threshold).
	/// Registered against the shared registry during init(); pointer
	/// remains valid for the registry's lifetime (the plugin does not
	/// own the underlying storage).  nullptr if registration failed.
	prometheus::Counter* metric_detected_anomalies { nullptr };

	/// Prometheus counter for anomalies that were *blocked* (DENY
	/// returned to the client).  Same lifetime rules as above.
	prometheus::Counter* metric_blocked_queries { nullptr };

	/// MCP listener handler.  Replaces the former core global
	/// `GloMCPH` as of Step 4.C.  Constructed in `genai_init()`,
	/// started by `genai_start()`, torn down by `genai_stop()`.
	/// See plugins/genai/src/MCP_Thread.cpp for the listener
	/// implementation.
	MCP_Threads_Handler* mcp { nullptr };
};

/**
 * @brief Accessor for the plugin's shared context singleton.
 *
 * Meyers-singleton; thread-safe construction since C++11.  Callers
 * may treat the returned reference as having static storage duration.
 */
GenAIPluginContext& genai_context();

/**
 * @brief Push admin DB's `mcp-*` global_variables values into the
 *        running MCP_Threads_Handler.
 *
 * Defined in plugin_main.cpp.  Called from `genai_start()` (initial
 * read at plugin start) and from the `LOAD MCP VARIABLES TO RUNTIME`
 * admin command (in plugin_commands.cpp) — both go through this one
 * helper to keep behavior consistent.
 *
 * @return true on success; false if admindb is unavailable or the
 *         lookup query errored out.
 */
bool mcp_load_variables_from_admindb(GenAIPluginContext& ctx);

/**
 * @brief Refresh the runtime mcp_auth_profiles / mcp_target_profiles
 *        tables from `main.*`, then rebuild the MCP target_auth_map.
 *
 * Defined in plugin_main.cpp.  Called from `genai_start()` and the
 * `LOAD MCP PROFILES TO RUNTIME` admin command.
 */
bool mcp_load_target_auth_map_from_admindb(GenAIPluginContext& ctx);

/**
 * @brief Bring the MCP listener (`ProxySQL_MCP_Server`) up if
 *        `ctx.mcp->variables.mcp_enabled` is true and no listener is
 *        currently running.
 *
 * Defined in plugin_main.cpp.  Called from `genai_start()` and from
 * the `LOAD MCP VARIABLES TO RUNTIME` admin command (after a
 * variable change might have flipped mcp_enabled to true).
 */
void mcp_start_listener_if_enabled(GenAIPluginContext& ctx);

/**
 * @brief Register the plugin's admin SQL verbs (LOAD/SAVE MCP …)
 *        with the chassis command registry.
 *
 * Defined in plugin_commands.cpp.  Called from `genai_init()`.
 *
 * @param services  The same pointer `genai_init` received.  Must
 *                  expose `register_command` (and ideally
 *                  `register_command_alias`) — both are valid during
 *                  init() per the chassis ABI.
 */
void genai_register_admin_commands(ProxySQL_PluginServices* services);

/**
 * @brief Query-hook adapter: ABI callback that runs the anomaly detector.
 *
 * Defined in plugin_hooks.cpp.  Registered with the plugin manager
 * during init() via services->register_query_hook for both MySQL and
 * PgSQL protocols.
 *
 * Behaviour:
 *   - If `genai_context().anomaly_detector` is null (carve-out
 *     transition window, or init failed) → return ALLOW.
 *   - Otherwise run `Anomaly_Detector::analyze` on the payload.
 *   - On `is_anomaly`, increment `metric_detected_anomalies`.
 *   - On `should_block`, increment `metric_blocked_queries` and return
 *     DENY with the detector's explanation as message.
 *
 * @param payload Borrowed; pointers valid only during this call.
 * @return ALLOW or DENY (with message) per the plugin ABI.
 */
ProxySQL_PluginQueryHookResult genai_query_hook(const ProxySQL_PluginQueryHookPayload& payload);

#endif /* PROXYSQL_GENAI_PLUGIN_H */
