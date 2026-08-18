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
#include <cassert>
#include <mutex>
#include <shared_mutex>
#include <pthread.h>

namespace prometheus { class Counter; }
class Anomaly_Detector;
class MCP_Threads_Handler;
class GenAI_Threads_Handler;

/** BasicLockable wrapper backed by the project's pthread mutex primitive. */
class GenAIMutex {
public:
	GenAIMutex() = default;
	~GenAIMutex() { pthread_mutex_destroy(&mutex_); }

	void lock() noexcept {
		const int rc = pthread_mutex_lock(&mutex_);
		assert(rc == 0);
		(void)rc;
	}
	void unlock() noexcept {
		const int rc = pthread_mutex_unlock(&mutex_);
		assert(rc == 0);
		(void)rc;
	}

	GenAIMutex(const GenAIMutex&) = delete;
	GenAIMutex& operator=(const GenAIMutex&) = delete;

private:
	pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;
};

/** SharedMutex wrapper backed by the project's pthread rwlock primitive. */
class GenAIRWLock {
public:
	GenAIRWLock() = default;
	~GenAIRWLock() { pthread_rwlock_destroy(&rwlock_); }

	void lock() noexcept {
		const int rc = pthread_rwlock_wrlock(&rwlock_);
		assert(rc == 0);
		(void)rc;
	}
	void unlock() noexcept {
		const int rc = pthread_rwlock_unlock(&rwlock_);
		assert(rc == 0);
		(void)rc;
	}
	void lock_shared() noexcept {
		const int rc = pthread_rwlock_rdlock(&rwlock_);
		assert(rc == 0);
		(void)rc;
	}
	void unlock_shared() noexcept { unlock(); }

	GenAIRWLock(const GenAIRWLock&) = delete;
	GenAIRWLock& operator=(const GenAIRWLock&) = delete;

private:
	pthread_rwlock_t rwlock_ = PTHREAD_RWLOCK_INITIALIZER;
};

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

	/// Serializes every GenAI plugin Admin command. Commands normally enter
	/// with Admin's global query mutex held, but runtime reloads must yield that
	/// mutex while draining MCP work. A second plugin command releases Admin
	/// before waiting here, so it cannot mutate plugin runtime state during the
	/// yielded interval and cannot form a command-mutex/Admin lock inversion.
	GenAIMutex admin_command_mutex;

	/// Protects MCP AI/RAG calls while their borrowed GloGATH/GloAI
	/// dependencies are replaced.  Runtime reloads and MCP listener
	/// construction take the exclusive side; endpoint calls take the shared
	/// side.  Admin command callbacks release the Admin global mutex before
	/// waiting for this lock, preventing an Admin/MCP lock inversion.
	GenAIRWLock runtime_dependencies_mutex;
};

/**
 * @brief Reload the GenAI runtime components after genai-* variables change.
 *
 * Defined in plugin_main.cpp.  Tears down and reinitialises the
 * `GloGATH` (GenAI_Threads_Handler) and `GloAI` (AI_Features_Manager)
 * singletons in place — the only way to pick up changes to bootstrap-
 * time values like worker count, embedding endpoint, or LLM-bridge
 * provider configuration.
 *
 * @par Concurrency contract
 * MCP AI/RAG calls share `runtime_dependencies_mutex`; this function takes
 * its exclusive side while replacing runtime resources, then rebinds the
 * persistent endpoint handlers before allowing another call through.  The
 * listener remains alive, so an in-flight Config/Stats handler waiting for
 * the Admin mutex cannot be trapped behind a synchronous listener join.
 * The anomaly-detector query hook, stats runtime view, and MCP AI/RAG calls
 * all hold the shared side while using replaceable runtime objects. Today the
 * function is called from:
 *
 *   1. `genai_start()` — single-threaded plugin lifecycle, no traffic
 *      yet, always safe.
 *   2. `LOAD GENAI VARIABLES TO RUNTIME` admin command — runs on the
 *      admin SQL thread.  The callback releases the Admin mutex before
 *      entering this function so an active MCP request can finish first.
 *   3. `LOAD GENAI VARIABLES FROM CONFIG` — same constraint as (2).
 *
 */
bool genai_refresh_runtime_components(GenAIPluginContext& ctx);

/**
 * @brief Accessor for the plugin's shared context singleton.
 *
 * Meyers-singleton; thread-safe construction since C++11.  Callers
 * may treat the returned reference as having static storage duration.
 */
GenAIPluginContext& genai_context();

/**
 * @brief Format-style log helper that routes through the chassis
 *        services->log_message callback (so messages land in
 *        proxysql.log) and falls back to stderr if the chassis isn't
 *        wired up yet (e.g. very early init or unit-test harness).
 *
 * Severity follows syslog levels: 3=ERROR, 4=WARN, 6=INFO, 7=DEBUG.
 * Messages over ~4 KiB after formatting are silently truncated;
 * they're admin/operator log lines, not data.
 *
 * Defined in plugin_main.cpp.
 */
void genai_log(int level, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

/**
 * @brief Validate and push the complete admin DB `mcp-*` configuration into
 *        the running MCP_Threads_Handler, then atomically publish the
 *        normalized active snapshot to `runtime_global_variables`.
 *
 * Defined in plugin_main.cpp.  Called from `genai_start()` (initial
 * read at plugin start) and from the `LOAD MCP VARIABLES TO RUNTIME`
 * admin command (in plugin_commands.cpp) — both go through this one
 * helper to keep behavior consistent.
 *
 * @return true on success; false if the configuration is incomplete/invalid,
 *         admindb access or publication fails, or the previous handler state
 *         cannot be retained.  A failed load leaves the prior committed
 *         runtime snapshot visible and restores the prior handler values.
 */
bool mcp_load_variables_from_admindb(GenAIPluginContext& ctx);

/**
 * @brief Push admin DB's `genai-*` global_variables values into the
 *        running GenAI_Threads_Handler.
 *
 * Defined in plugin_main.cpp.  Called from the
 * `LOAD GENAI VARIABLES TO RUNTIME` admin command.  Mirrors the
 * pre-Step-5 `flush_genai_variables___database_to_runtime` in core.
 */
bool genai_load_variables_from_admindb(GenAIPluginContext& ctx);

/**
 * @brief Pull runtime `genai-*` values from the running
 *        GenAI_Threads_Handler back into main.global_variables.
 *
 * Defined in plugin_main.cpp.  Called from the
 * `SAVE GENAI VARIABLES TO MEMORY` admin command.  Mirrors the
 * pre-Step-5 `flush_genai_variables___runtime_to_database` in core.
 */
bool genai_save_variables_to_admindb(GenAIPluginContext& ctx);

/**
 * @brief Pull runtime mcp-* values from the running
 *        MCP_Threads_Handler back into main.global_variables.
 *
 * Defined in plugin_main.cpp.  Called from the
 * `SAVE MCP VARIABLES TO MEMORY` / `... FROM RUNTIME` admin command.
 * Mirrors the pre-4.C `flush_mcp_variables___runtime_to_database`
 * with `runtime=false` (write-back to main, not runtime).
 *
 * @return true on success; false on SQL error or if admindb /
 *         ctx.mcp are unavailable.
 */
bool mcp_save_variables_to_admindb(GenAIPluginContext& ctx);

/**
 * @brief Install main.mcp_auth_profiles + main.mcp_target_profiles into
 *        the MCP_Threads_Handler in-memory snapshot, then rebuild the
 *        joined target_auth_map consumed by the listener.
 *
 * Defined in plugin_main.cpp.  Called from `genai_start()` and the
 * `LOAD MCP PROFILES TO RUNTIME` admin command.  Per the ABI-3
 * separation-of-duties contract this MUST NOT touch runtime_mcp_*
 * (those are admin-side projections owned by the chassis).
 */
bool mcp_load_target_auth_map_from_admindb(GenAIPluginContext& ctx);

/**
 * @brief Dump the MCP_Threads_Handler in-memory profile snapshots back
 *        to main.mcp_auth_profiles + main.mcp_target_profiles.
 *
 * Defined in plugin_main.cpp.  Called by the
 * `SAVE MCP PROFILES TO MEMORY` admin command (ABI-3 SAVE side of the
 * triplet).  Never reads runtime_mcp_*.
 */
bool mcp_save_target_auth_map_to_admindb(GenAIPluginContext& ctx);

/**
 * @brief Install main.mcp_query_rules into the MCP_Threads_Handler
 *        in-memory snapshot.  When the MCP listener is running, the
 *        rows are also pushed into Discovery_Schema for the request
 *        hot-path; otherwise the snapshot stays for SAVE / projection.
 *
 * Defined in plugin_main.cpp.  Called by the
 * `LOAD MCP QUERY RULES TO RUNTIME` admin command.
 */
bool mcp_load_query_rules_to_runtime(GenAIPluginContext& ctx);

/**
 * @brief Dump the MCP_Threads_Handler in-memory query-rule snapshot
 *        back to main.mcp_query_rules.
 *
 * Defined in plugin_main.cpp.  Called by the
 * `SAVE MCP QUERY RULES TO MEMORY` admin command.  The legacy second
 * parameter is unused (kept only because callers haven't been
 * regenerated); pass false.
 */
bool mcp_save_query_rules_from_runtime(GenAIPluginContext& ctx, bool runtime);

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
 * @brief Register all MCP-related admin / config / stats tables
 *        with the chassis `register_table` registry.
 *
 * Defined in plugin_tables.cpp.  Called from `genai_init()`.
 *
 * @param services  The same pointer `genai_init` received.  Must
 *                  expose `register_table` — valid during init()
 *                  per the chassis ABI.
 */
void genai_register_admin_tables(ProxySQL_PluginServices* services);

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
