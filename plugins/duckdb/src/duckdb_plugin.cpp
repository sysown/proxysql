#include "duckdb_plugin.h"

#include "duckdb_admin_schema.h"
#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "duckdb_listener.h"

#include <mutex>
#include <string>

namespace {

void log_warn(const std::string& msg) {
	DuckDBPluginContext& ctx = duckdb_context();
	if (ctx.services != nullptr && ctx.services->log_message != nullptr) {
		ctx.services->log_message(2 /* warn */, msg.c_str());
	}
}

void log_error(const std::string& msg) {
	DuckDBPluginContext& ctx = duckdb_context();
	if (ctx.services != nullptr && ctx.services->log_message != nullptr) {
		ctx.services->log_message(3 /* error */, msg.c_str());
	}
}

bool duckdb_register_schemas(ProxySQL_PluginServices* services) {
	if (services == nullptr) return false;
	return duckdb_register_admin_schema(*services);
}

bool duckdb_init(ProxySQL_PluginServices* services) {
	if (services == nullptr) return false;
	DuckDBPluginContext& ctx = duckdb_context();
	ctx.services = services;
	ctx.started = false;
	return true;
}

bool duckdb_start() {
	DuckDBPluginContext& ctx = duckdb_context();

	if (ctx.services != nullptr && ctx.services->get_admindb != nullptr) {
		if (SQLite3DB* admindb = ctx.services->get_admindb()) {
			// disk -> memory, then memory -> module, the canonical order.
			std::string err;
			if (!duckdb_sync_variables_disk_to_memory(*admindb, err)) log_warn(err);
			err.clear();
			if (!duckdb_install_variables_from_admin(*admindb, *ctx.config_store, err) || !err.empty())
				log_warn(err);
		}
	}

	std::string err;
	ctx.engine = std::make_unique<DuckDBEngine>();
	if (!ctx.engine->open(*ctx.config_store, err)) {
		log_error("duckdb: engine open failed: " + err);
		ctx.engine.reset();
		return false;
	}

	ctx.listener = std::make_unique<DuckDBListener>();
	if (!ctx.listener->start(*ctx.config_store, *ctx.engine, err)) {
		log_error("duckdb: listener start failed: " + err);
		ctx.listener.reset();
		ctx.engine->close();
		ctx.engine.reset();
		return false;
	}

	ctx.started = true;
	return true;
}

// Order matters: the listener joins every connection thread, so no thread
// can still hold a duckdb_connection by the time the engine closes.
//
// Pairs with init(), not start(): the chassis guarantees stop() runs for
// any plugin whose init() returned true, even if start() failed or never
// ran. Every teardown step below must tolerate a null / never-started
// member, and stop() itself must tolerate being called twice.
bool duckdb_stop() {
	DuckDBPluginContext& ctx = duckdb_context();
	if (ctx.listener) { ctx.listener->stop(); ctx.listener.reset(); }
	if (ctx.engine)   { ctx.engine->close(); ctx.engine.reset(); }
	ctx.started = false;
	return true;
}

// ABI contract: the returned pointer aliases a shared static buffer, the
// same pattern as strerror() -- it is valid only until the NEXT call to
// duckdb_status_json() on any thread; a caller that needs to keep the
// value must copy it before calling again. The mutex below only makes
// the write itself well-defined under concurrent callers (an
// unsynchronized std::string assigned to from two threads is a data
// race, i.e. UB, regardless of this function's single-threaded callers
// today) -- it cannot and does not extend the pointer's validity past a
// following call, which is a limitation of the const char* ABI itself,
// not something a lock inside this function can fix.
const char* duckdb_status_json() {
	DuckDBPluginContext& ctx = duckdb_context();
	static std::mutex status_mutex;
	static std::string status; // must outlive the call: the ABI returns a raw pointer
	std::lock_guard<std::mutex> lock(status_mutex);
	if (!ctx.started || !ctx.engine) {
		status = "{\"name\":\"duckdb\",\"state\":\"stopped\"}";
		return status.c_str();
	}
	status = "{\"name\":\"duckdb\",\"state\":\"running\",\"database_path\":\"" +
		ctx.config_store->database_path() + "\",\"open_connections\":" +
		std::to_string(ctx.engine->open_connections()) + "}";
	return status.c_str();
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
	static DuckDBPluginContext ctx = [] {
		DuckDBPluginContext c {};
		c.config_store = std::make_unique<DuckDBConfigStore>();
		return c;
	}();
	return ctx;
}

// Default visibility is required: the .so is built with
// -fvisibility=hidden, and without this the loader fails with
// "undefined symbol: proxysql_plugin_descriptor_v1".
extern "C" __attribute__((visibility("default")))
const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
	return &duckdb_descriptor;
}
