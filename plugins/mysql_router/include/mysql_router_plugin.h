#ifndef PROXYSQL_MYSQL_ROUTER_PLUGIN_H
#define PROXYSQL_MYSQL_ROUTER_PLUGIN_H

#include "ProxySQL_Plugin.h"
#include "mysql_router_reconciler.h"
#include "mysql_router_types.h"

#include <atomic>
#include <memory>
#include <mutex>

namespace prometheus {
class Counter;
class Gauge;
}

struct MysqlRouterMetrics {
	prometheus::Gauge* metadata_available {nullptr};
	prometheus::Gauge* topology_generation {nullptr};
	prometheus::Gauge* user_generation {nullptr};
	prometheus::Counter* topology_success {nullptr};
	prometheus::Counter* topology_failure {nullptr};
	prometheus::Counter* user_success {nullptr};
	prometheus::Counter* user_failure {nullptr};
	prometheus::Gauge* managed_writer_online {nullptr};
	prometheus::Gauge* managed_reader_online {nullptr};
	prometheus::Gauge* managed_excluded {nullptr};
	prometheus::Counter* writer_changes {nullptr};
	prometheus::Counter* drift_corrections {nullptr};
	prometheus::Gauge* unresolved_users {nullptr};
	prometheus::Gauge* stale_seconds {nullptr};
};

struct MysqlRouterContext {
	ProxySQL_PluginServices* services {nullptr};
	std::atomic<bool> initialized {false};
	std::atomic<bool> started {false};
	std::atomic<bool> runtime_ready {false};
	std::atomic<bool> metrics_registered {false};
	std::mutex status_mutex;
	std::mutex projection_mutex;
	MysqlRouterStatus status;
	std::vector<MysqlRouterRuntimeTopologyRow> runtime_topology;
	MysqlRouterMetrics metrics;
	std::unique_ptr<IReconcileBackend> reconcile_backend;
	std::unique_ptr<MysqlRouterReconciler> reconciler;
};

MysqlRouterContext& mysql_router_context();
bool mysql_router_register_metrics(ProxySQL_PluginServices& services);
const char* mysql_router_status_json();
ProxySQL_PluginCommandResult mysql_router_reconcile_command(
	const ProxySQL_PluginCommandContext& command_context, const char* command);

#endif
