#ifndef __DUCKDB_PLUGIN_H
#define __DUCKDB_PLUGIN_H

#include "ProxySQL_Plugin.h"

#include <memory>

class DuckDBConfigStore;

// Process-wide plugin state. The chassis gives callbacks no context
// pointer, so the plugin reaches its own state through this accessor.
// Not thread-safe to mutate; every field is written only during the
// single-threaded lifecycle phases (init / start / stop) and read
// afterwards.
//
// Later tasks add more members here together with the include of each
// member's now-complete type: Task 8 adds engine and listener.
//
// config_store is only forward-declared here; the type must be complete
// wherever the struct's destructor is instantiated (i.e. wherever the
// owning DuckDBPluginContext is defined/destroyed) -- duckdb_plugin.cpp
// includes duckdb_config.h for exactly that reason.
struct DuckDBPluginContext {
	ProxySQL_PluginServices* services { nullptr };
	bool started { false };
	std::unique_ptr<DuckDBConfigStore> config_store;
};

DuckDBPluginContext& duckdb_context();

#endif // __DUCKDB_PLUGIN_H
