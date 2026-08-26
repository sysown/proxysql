#include "duckdb_plugin.h"

namespace {

bool duckdb_register_schemas(ProxySQL_PluginServices* services) {
	if (services == nullptr) return false;
	return true;   // Task 6 registers the schema here.
}

bool duckdb_init(ProxySQL_PluginServices* services) {
	if (services == nullptr) return false;
	DuckDBPluginContext& ctx = duckdb_context();
	ctx.services = services;
	ctx.started = false;
	return true;
}

bool duckdb_start() {
	duckdb_context().started = true;
	return true;   // Task 8 opens the engine and binds listeners here.
}

// Pairs with init(), not start(): the chassis guarantees stop() runs for
// any plugin whose init() returned true, even if start() failed or never
// ran. Every teardown below must tolerate a null / never-started member.
bool duckdb_stop() {
	DuckDBPluginContext& ctx = duckdb_context();
	ctx.started = false;
	return true;
}

const char* duckdb_status_json() {
	return duckdb_context().started
		? "{\"name\":\"duckdb\",\"state\":\"running\"}"
		: "{\"name\":\"duckdb\",\"state\":\"stopped\"}";
}

const ProxySQL_PluginDescriptor duckdb_descriptor = {
	"duckdb",
	PROXYSQL_PLUGIN_ABI_VERSION,
	&duckdb_init,
	&duckdb_start,
	&duckdb_stop,
	&duckdb_status_json,
	&duckdb_register_schemas,
};

} // namespace

DuckDBPluginContext& duckdb_context() {
	static DuckDBPluginContext ctx {};
	return ctx;
}

// Default visibility is required: the .so is built with
// -fvisibility=hidden, and without this the loader fails with
// "undefined symbol: proxysql_plugin_descriptor_v1".
extern "C" __attribute__((visibility("default")))
const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
	return &duckdb_descriptor;
}
