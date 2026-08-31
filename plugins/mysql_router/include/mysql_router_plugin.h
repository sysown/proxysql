#ifndef PROXYSQL_MYSQL_ROUTER_PLUGIN_H
#define PROXYSQL_MYSQL_ROUTER_PLUGIN_H

#include "ProxySQL_Plugin.h"
#include "mysql_router_types.h"

#include <atomic>
#include <mutex>

struct MysqlRouterContext {
	ProxySQL_PluginServices* services {nullptr};
	std::atomic<bool> initialized {false};
	std::atomic<bool> started {false};
	std::atomic<bool> runtime_ready {false};
	std::atomic<bool> metrics_registered {false};
	std::mutex status_mutex;
	MysqlRouterStatus status;
};

MysqlRouterContext& mysql_router_context();
bool mysql_router_register_metrics(ProxySQL_PluginServices& services);
const char* mysql_router_status_json();

#endif
