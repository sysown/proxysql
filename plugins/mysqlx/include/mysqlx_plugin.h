#ifndef PROXYSQL_MYSQLX_PLUGIN_H
#define PROXYSQL_MYSQLX_PLUGIN_H

#include "ProxySQL_Plugin.h"
#include "mysqlx_admin_schema.h"
#include "mysqlx_config_store.h"
#include "mysqlx_thread.h"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

class SQLite3DB;

struct MysqlxPluginContext {
	ProxySQL_PluginServices* services { nullptr };
	std::unique_ptr<MysqlxConfigStore> config_store {};
	std::vector<std::unique_ptr<Mysqlx_Thread>> threads {};
	std::atomic<bool> started { false };

	// Source of truth for route-to-thread ownership of listening sockets.
	// Populated (and mutated) exclusively by `mysqlx_reconcile_listeners`
	// during startup and on LOAD MYSQLX ROUTES TO RUNTIME. Keyed by
	// `mysqlx_routes.name`; value is the index into `threads`. Guarded by
	// `route_to_thread_mutex`. `next_rr_index` is the round-robin cursor
	// used to pick a thread for each newly-added route.
	std::map<std::string, int> route_to_thread {};
	std::mutex route_to_thread_mutex {};
	int next_rr_index { 0 };
};

MysqlxPluginContext& mysqlx_context();

/**
 * Desired-state listener reconciliation driven by `MysqlxConfigStore`.
 *
 * Reads the current desired route set from the in-memory store (active
 * routes only, via `MysqlxConfigStore::snapshot_active_routes()`) and
 * adjusts the listener topology to match:
 *   - Routes that are desired but not yet in the plugin-scope
 *     `route_to_thread` map get a freshly-created listener on a thread
 *     chosen round-robin via `next_rr_index`, and the mapping is recorded.
 *   - Routes that are mapped but no longer desired (either deleted or
 *     `active=0`) have their listener removed and the mapping erased.
 *   - Routes present in both sets are left untouched (idempotent).
 *
 * Called from plugin startup and from the admin command
 * `LOAD MYSQLX ROUTES TO RUNTIME`, so both paths converge on the same
 * reconciliation logic. Both call sites run AFTER
 * `install_routes_from_admin` populates the store, so the snapshot here
 * reflects exactly the routes the operator asked for. The reconciler
 * deliberately does NOT read `runtime_mysqlx_routes` — that is an
 * on-demand admin-side projection, not authoritative module state.
 *
 * Declared weak so unit tests that exercise admin_schema.cpp in isolation
 * (without linking mysqlx_plugin.cpp) can link successfully; at runtime
 * inside the shared library the strong definition in mysqlx_plugin.cpp
 * always wins. When weakly unresolved, the function pointer is null and
 * callers must null-check (admin_schema.cpp does).
 */
__attribute__((weak)) void mysqlx_reconcile_listeners(SQLite3DB& admindb);

/**
 * Walks every Mysqlx_Thread in mysqlx_context().threads, snapshots each
 * thread's sessions_ under its sessions_mutex_, and projects one row per
 * active session into stats_mysqlx_processlist. Called from the chassis
 * runtime-view refresh callback before any admin SELECT against the
 * table runs (the callback in mysqlx_admin_schema.cpp).
 *
 * Snapshot work is bounded per thread: a string-copy + a few struct field
 * reads under the mutex, no I/O. Lock ordering: each thread's
 * sessions_mutex_ is acquired in turn; no cross-thread lock is held.
 *
 * Declared __attribute__((weak)) for the same reason
 * mysqlx_reconcile_listeners is — admin_schema.cpp's unit tests don't
 * link mysqlx_plugin.cpp, so the projection registration must tolerate
 * an unresolved hook at test-build link time.
 */
__attribute__((weak)) void mysqlx_populate_stats_processlist(SQLite3DB& statsdb);

// Pure variant of `mysqlx_reconcile_listeners` that takes the plugin state
// as parameters instead of going through `mysqlx_context()`. Exists so unit
// tests can construct a minimal fake context without pulling in the whole
// plugin descriptor / registration surface. Not intended for production
// callers.
//
// `store` is the in-memory route source: the reconciler reads its active
// route set via MysqlxConfigStore::snapshot_active_routes(). admindb is
// retained in the signature only because the weak hook on the public API
// hands it through; this helper does not consult it. May be nullptr in
// tests that pre-populated `store` via install_for_test() and don't care
// about admindb.
void mysqlx_reconcile_listeners_impl(
	const MysqlxConfigStore& store,
	std::vector<std::unique_ptr<Mysqlx_Thread>>& threads,
	std::map<std::string, int>& route_to_thread,
	std::mutex& route_to_thread_mutex,
	int& next_rr_index
);

#endif /* PROXYSQL_MYSQLX_PLUGIN_H */
