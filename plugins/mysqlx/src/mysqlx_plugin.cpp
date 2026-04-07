#include "mysqlx_plugin.h"

class MysqlxConfigStore {
public:
	MysqlxConfigStore() = default;
	MysqlxConfigStore(const MysqlxConfigStore&) = delete;
	MysqlxConfigStore& operator=(const MysqlxConfigStore&) = delete;
	~MysqlxConfigStore() = default;
};

namespace {

bool mysqlx_init(ProxySQL_PluginServices* services) {
	MysqlxPluginContext& ctx = mysqlx_context();
	ctx.services = services;
	ctx.config_store = std::make_unique<MysqlxConfigStore>();
	ctx.started = false;
	if (services == nullptr) {
		return false;
	}
	return mysqlx_register_admin_schema(*services);
}

bool mysqlx_start() {
	MysqlxPluginContext& ctx = mysqlx_context();
	ctx.started = true;
	return true;
}

bool mysqlx_stop() {
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
