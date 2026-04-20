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
 * Desired-state listener reconciliation driven by `runtime_mysqlx_routes`.
 *
 * Reads the current desired route set (rows with `active=1`) from
 * `runtime_mysqlx_routes` and adjusts the listener topology to match:
 *   - Routes that are desired but not yet in the plugin-scope
 *     `route_to_thread` map get a freshly-created listener on a thread
 *     chosen round-robin via `next_rr_index`, and the mapping is recorded.
 *   - Routes that are mapped but no longer desired (either deleted or
 *     `active=0`) have their listener removed and the mapping erased.
 *   - Routes present in both sets are left untouched (idempotent).
 *
 * Called from plugin startup and from the admin command
 * `LOAD MYSQLX ROUTES TO RUNTIME`, so both paths converge on the same
 * reconciliation logic.
 *
 * Declared weak so unit tests that exercise admin_schema.cpp in isolation
 * (without linking mysqlx_plugin.cpp) can link successfully; at runtime
 * inside the shared library the strong definition in mysqlx_plugin.cpp
 * always wins. When weakly unresolved, the function pointer is null and
 * callers must null-check (admin_schema.cpp does).
 */
__attribute__((weak)) void mysqlx_reconcile_listeners(SQLite3DB& admindb);

// Pure variant of `mysqlx_reconcile_listeners` that takes the plugin state
// as parameters instead of going through `mysqlx_context()`. Exists so unit
// tests can construct a minimal fake context without pulling in the whole
// plugin descriptor / registration surface. Not intended for production
// callers.
void mysqlx_reconcile_listeners_impl(
	SQLite3DB& admindb,
	std::vector<std::unique_ptr<Mysqlx_Thread>>& threads,
	std::map<std::string, int>& route_to_thread,
	std::mutex& route_to_thread_mutex,
	int& next_rr_index
);

#endif /* PROXYSQL_MYSQLX_PLUGIN_H */
