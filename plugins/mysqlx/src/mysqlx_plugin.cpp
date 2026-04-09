#include "mysqlx_plugin.h"

namespace {

bool mysqlx_init(ProxySQL_PluginServices* services) {
	if (services == nullptr) {
		return false;
	}

	MysqlxPluginContext& ctx = mysqlx_context();
	ctx.services = services;
	ctx.config_store = std::make_unique<MysqlxConfigStore>();
	ctx.started = false;
	return mysqlx_register_admin_schema(*services);
}

bool mysqlx_start() {
	MysqlxPluginContext& ctx = mysqlx_context();

	// Open listener sockets for active routes if an admin DB is available.
	if (ctx.services != nullptr && ctx.services->get_admindb != nullptr) {
		SQLite3DB* admindb = ctx.services->get_admindb();
		if (admindb != nullptr) {
			std::string err;
			if (!ctx.config_store->load_from_runtime(*admindb, err)) {
				if (ctx.services->log_message != nullptr) {
					ctx.services->log_message(3, err.c_str());
				}
			}
			mysqlx_start_listeners_from_runtime_routes(*admindb);
		}
	}

	ctx.started = true;
	return true;
}

bool mysqlx_stop() {
	mysqlx_stop_listeners();
	MysqlxPluginContext& ctx = mysqlx_context();
	ctx.started = false;
	return true;
}

const char* mysqlx_status_json() {
	const MysqlxPluginContext& ctx = mysqlx_context();
	if (ctx.started) {
		return "{\"name\":\"mysqlx\",\"state\":\"running\"}";
	}
	return "{\"name\":\"mysqlx\",\"state\":\"stopped\"}";
}

const ProxySQL_PluginDescriptor mysqlx_descriptor = {
	"mysqlx",
	1,
	&mysqlx_init,
	&mysqlx_start,
	&mysqlx_stop,
	&mysqlx_status_json,
};

} // namespace

MysqlxPluginContext& mysqlx_context() {
	static MysqlxPluginContext ctx {};
	return ctx;
}

extern "C" const ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	return &mysqlx_descriptor;
}
