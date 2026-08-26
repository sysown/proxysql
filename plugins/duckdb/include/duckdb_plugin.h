#ifndef __DUCKDB_PLUGIN_H
#define __DUCKDB_PLUGIN_H

#include "ProxySQL_Plugin.h"

// Process-wide plugin state. The chassis gives callbacks no context
// pointer, so the plugin reaches its own state through this accessor.
// Not thread-safe to mutate; every field is written only during the
// single-threaded lifecycle phases (init / start / stop) and read
// afterwards.
//
// Later tasks add members here together with the include of each
// member's now-complete type: Task 3 adds config_store, Task 4 adds
// engine, Task 8 adds listener.
struct DuckDBPluginContext {
	ProxySQL_PluginServices* services { nullptr };
	bool started { false };
};

DuckDBPluginContext& duckdb_context();

#endif // __DUCKDB_PLUGIN_H
