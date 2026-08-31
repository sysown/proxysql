#include "mysql_router_plugin.h"

#include "prometheus/counter.h"
#include "prometheus/gauge.h"
#include "prometheus/registry.h"

#include <exception>

bool mysql_router_register_metrics(ProxySQL_PluginServices& services) {
	MysqlRouterContext& context = mysql_router_context();
	if (context.metrics_registered.load()) return true;
	if (services.get_prometheus_registry == nullptr) return false;
	prometheus::Registry* registry = services.get_prometheus_registry();
	if (registry == nullptr) return false;

	try {
		prometheus::BuildGauge()
			.Name("proxysql_mysql_router_metadata_available")
			.Help("Whether MySQL Router metadata is currently available.")
			.Register(*registry).Add({});
		prometheus::BuildCounter()
			.Name("proxysql_mysql_router_refresh_total")
			.Help("MySQL Router refresh attempts by kind and result.")
			.Register(*registry).Add({{"kind", "topology"}, {"result", "success"}});
		prometheus::BuildGauge()
			.Name("proxysql_mysql_router_generation")
			.Help("Active MySQL Router generation by kind.")
			.Register(*registry).Add({{"kind", "topology"}});
		prometheus::BuildGauge()
			.Name("proxysql_mysql_router_managed_servers")
			.Help("Managed MySQL Router servers by role and state.")
			.Register(*registry).Add({{"role", "writer"}, {"state", "online"}});
		prometheus::BuildCounter()
			.Name("proxysql_mysql_router_writer_changes_total")
			.Help("Number of observed MySQL Router writer changes.")
			.Register(*registry).Add({});
		prometheus::BuildCounter()
			.Name("proxysql_mysql_router_drift_corrections_total")
			.Help("Number of MySQL Router managed-state drift corrections.")
			.Register(*registry).Add({});
		prometheus::BuildGauge()
			.Name("proxysql_mysql_router_unresolved_users")
			.Help("Number of MySQL Router users that cannot be materialized.")
			.Register(*registry).Add({});
		prometheus::BuildGauge()
			.Name("proxysql_mysql_router_stale_seconds")
			.Help("Age in seconds of the last validated Router metadata.")
			.Register(*registry).Add({});
		context.metrics_registered.store(true);
		return true;
	} catch (const std::exception& exception) {
		if (services.log_message != nullptr) {
			services.log_message(3, exception.what());
		}
		return false;
	} catch (...) {
		if (services.log_message != nullptr) {
			services.log_message(3, "mysql_router: metric registration failed");
		}
		return false;
	}
}
