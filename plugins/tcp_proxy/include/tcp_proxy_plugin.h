#ifndef PROXYSQL_TCP_PROXY_PLUGIN_H
#define PROXYSQL_TCP_PROXY_PLUGIN_H

/*
 * Private Admin/lifecycle interface for the native TCP proxy plugin.
 *
 * The data plane itself lives behind the frozen, ProxySQL-independent
 * interface in "tcp_proxy.h".  This header only exposes the pieces that the
 * production plugin, its focused unit tests and the build need to share.
 */

#include "ProxySQL_Plugin.h"

#include "tcp_proxy.h"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

class SQLite3DB;

/* Frozen core ABI-18 service table (include/ProxySQL_PluginRawBackend.h). */
struct ProxySQL_RawBackendServiceV2;

namespace tcp_proxy_plugin {

struct MetricsRuntime;

/*
 * Process-wide plugin state.  The chassis creates exactly one plugin instance
 * per loaded DSO, so a function-local singleton mirrors the established plugin
 * convention and survives the repeated init/start/stop lifecycle exercised by
 * unit tests.
 *
 * Locking contract:
 *   - engine_mutex only protects the shared_ptr publication.  It is never held
 *     while calling into the Engine, while touching SQLite, or while waiting
 *     for Admin to be reacquired.
 *   - status_mutex protects the small textual status fields.
 *   - load_mutex is the dedicated LOAD try-lock required by the design.  It is
 *     acquired non-blocking under Admin before any editable row is copied and
 *     retained until the command response has been built and Admin has been
 *     reacquired.
 */
struct Context {
	ProxySQL_PluginServices* services { nullptr };

	std::mutex engine_mutex;
	std::shared_ptr<tcp_proxy::Engine> engine;

	/* Borrowed core raw-backend adapter.  Immutable after init; outlives the
	 * Engine and every backend handle the Engine created. */
	std::shared_ptr<tcp_proxy::BackendProvider> backend_provider;

	std::mutex status_mutex;
	std::string state { "stopped" };
	std::string last_error {};
	std::string metrics_diagnostic {};
	std::atomic<bool> initialized { false };
	std::atomic<bool> started { false };

	/* status_json() storage.  It lives for the whole module lifetime (not in a
	 * thread_local object whose destructor can run before the chassis stop
	 * callback) and remains valid until the next status_json() call. */
	std::mutex status_json_mutex;
	std::string status_json_buffer {};

	std::mutex load_mutex;

	std::mutex config_mutex;
	tcp_proxy::Config initial_config {};
	bool has_initial_config { false };

	std::shared_ptr<MetricsRuntime> metrics;

	std::thread metrics_thread;
	std::mutex metrics_wait_mutex;
	std::condition_variable metrics_wait_cv;
	std::atomic<bool> metrics_stop_requested { false };

	~Context();
};

Context& context();

/*
 * Backend provider adapter over the frozen core V2 raw-backend service.
 *
 * make_raw_backend_provider() wraps one borrowed V2 service table (version 2);
 * a null/incomplete/foreign-version table yields a provider whose available()
 * is false.  core_backend_provider() resolves the frozen ABI-18 nullable
 * getter. A null getter yields nullptr; a null or incompatible service table
 * yields an unavailable provider. Both are exposed for the focused Admin tests.
 */
std::shared_ptr<tcp_proxy::BackendProvider> make_raw_backend_provider(
	const ProxySQL_RawBackendServiceV2* service);
std::shared_ptr<tcp_proxy::BackendProvider> core_backend_provider(
	ProxySQL_PluginServices* services);

/*
 * Module-owned storage release.  The Context is heap-allocated and never
 * registered with atexit, so its destructor cannot run before the chassis
 * manager's stop callback during a release std::exit().  This helper runs from
 * the DSO finalizer and from tests: it destroys the storage only when the
 * plugin is fully idle (never started/initialized, no Engine, no metrics and no
 * sampler thread).  A daemon that is still running at process exit therefore
 * keeps the Context alive until stop_all() has executed; a normal dlclose after
 * STOP deletes it, so repeated load/unload does not leak.
 */
void context_finalize_if_idle();

/* Phase B: declare tables, runtime/stats views, commands and aliases. */
bool register_schemas(ProxySQL_PluginServices& services);

/* Lifecycle.  init() cleans its own partial state on failure because the
 * chassis only calls stop() for a successful init(). */
bool plugin_init(ProxySQL_PluginServices* services);
bool plugin_start();
bool plugin_stop();
bool runtime_ready(ProxySQL_PluginRuntimeContext* runtime_context);

/* Descriptor status_json() result; static/thread-local ownership. */
const char* status_json();

/*
 * Strict editable-config reader and default seeding.  Exposed for the focused
 * Admin tests; production callers are the lifecycle and command callbacks.
 */
bool seed_settings_defaults(SQLite3DB& db, std::string& error);
bool read_config(SQLite3DB& db, tcp_proxy::Config& config, std::string& error);
/* Refuse legacy tcp_servers/tcp_hostgroup_mappings tables without altering any
 * row.  schema is "main" or "disk"; a missing attached disk is accepted. */
bool reject_legacy_artifacts(SQLite3DB& db, const char* schema,
	std::string& error);

/* Metrics lifecycle.  The ten stable tcp_proxy families are owned by the
 * core process registry for its lifetime; the plugin owns only their samples.
 * Registration/rebinding happens in init(); the sampler starts only after the
 * Engine is running. The sampler never takes Admin's SQL mutex, so teardown
 * can join it during fast SQL exit. Core v4 resets counters after plugin and
 * worker teardown; the manager pins the registry through stop and DSO unload.
 * Unregistration removes only plugin-owned samples after sampler join and
 * Engine/worker shutdown. The fixed component="tcp_proxy" label and this
 * module's serialized lifecycle assume an exclusive tcp_proxy sample writer. */
bool metrics_init(ProxySQL_PluginServices& services, Context& ctx, std::string& error);
bool metrics_start(Context& ctx);
void metrics_stop_sampler(Context& ctx);
void metrics_unregister(Context& ctx);

#ifdef TCP_PROXY_BACKEND_PROVIDER_TESTING
/* Focused adapter test hook: force the next wrapper allocation to fail after
 * the core handle was acquired, proving the acquire/destroy balance.  Only the
 * admin unit target defines this macro; production exports no such symbol. */
void raw_backend_provider_test_fail_wrapper_allocation_once(bool fail);
#endif

#ifdef TCP_PROXY_METRICS_TESTING
/* Focused-test hooks.  The admin unit target defines
 * TCP_PROXY_METRICS_TESTING; production builds contain no implementation and
 * export no symbol. */
void metrics_test_set_failure_stage(int stage);
bool metrics_test_publish_once(Context& ctx, std::string& error);
#endif

/* Shared helpers used by command/projection code. */
std::shared_ptr<tcp_proxy::Engine> copy_engine(Context& ctx);
bool engine_is_running(Context& ctx);
void set_last_error(Context& ctx, const std::string& error);
void clear_last_error(Context& ctx);
void set_state(Context& ctx, const std::string& state);
std::string state_snapshot(Context& ctx, std::string& last_error);

} // namespace tcp_proxy_plugin

#endif // PROXYSQL_TCP_PROXY_PLUGIN_H
