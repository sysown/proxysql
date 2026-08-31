#include "mysql_router_admin.h"
#include "mysql_router_bootstrap.h"
#include "mysql_router_plugin.h"

namespace {

bool register_cli_options(ProxySQL_PluginCLIRegistry* registry) {
	return mysql_router_register_cli_options(registry);
}

ProxySQL_PluginEarlyActionResult early_action(
		const ProxySQL_PluginEarlyActionContext& action_context) {
	try {
		const BootstrapOptions options = parse_bootstrap_options(action_context);
		if (!options.requested) return ProxySQL_PluginEarlyActionResult::not_requested;
		MysqlRouterContext& context = mysql_router_context();
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.last_error = "MySQL Router bootstrap engine is not available yet";
		return ProxySQL_PluginEarlyActionResult::exit_failure;
	} catch (const std::exception& exception) {
		MysqlRouterContext& context = mysql_router_context();
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.last_error = exception.what();
		return ProxySQL_PluginEarlyActionResult::exit_failure;
	}
}

bool init(ProxySQL_PluginServices* services) {
	if (services == nullptr) return false;
	MysqlRouterContext& context = mysql_router_context();
	context.services = services;
	if (!mysql_router_register_metrics(*services)) return false;
	context.initialized.store(true);
	{
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.state = "initialized";
		context.status.last_error.clear();
	}
	return true;
}

bool start() {
	MysqlRouterContext& context = mysql_router_context();
	if (!context.initialized.load()) return false;
	context.started.store(true);
	{
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.state = "started";
	}
	return true;
}

bool runtime_ready(ProxySQL_PluginRuntimeContext* runtime_context) {
	if (runtime_context == nullptr) return false;
	MysqlRouterContext& context = mysql_router_context();
	if (!context.started.load()) return false;
	context.runtime_ready.store(true);
	{
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.state = "ready";
	}
	return true;
}

bool stop() {
	MysqlRouterContext& context = mysql_router_context();
	context.runtime_ready.store(false);
	context.started.store(false);
	context.initialized.store(false);
	context.services = nullptr;
	{
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.state = "stopped";
	}
	return true;
}

bool register_schemas(ProxySQL_PluginServices* services) {
	return services != nullptr && mysql_router_register_admin_schema(*services);
}

const ProxySQL_PluginDescriptor descriptor {
	"mysql_router",
	PROXYSQL_PLUGIN_ABI_VERSION,
	&init,
	&start,
	&stop,
	&mysql_router_status_json,
	&register_schemas,
	&register_cli_options,
	&early_action,
	&runtime_ready,
};

} // namespace

MysqlRouterContext& mysql_router_context() {
	static MysqlRouterContext context;
	return context;
}

extern "C" __attribute__((visibility("default")))
const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
	return &descriptor;
}
