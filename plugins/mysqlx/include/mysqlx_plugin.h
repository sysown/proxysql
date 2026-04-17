#ifndef PROXYSQL_MYSQLX_PLUGIN_H
#define PROXYSQL_MYSQLX_PLUGIN_H

#include "ProxySQL_Plugin.h"
#include "mysqlx_admin_schema.h"
#include "mysqlx_config_store.h"
#include "mysqlx_thread.h"

#include <atomic>
#include <memory>
#include <vector>

struct MysqlxPluginContext {
	ProxySQL_PluginServices* services { nullptr };
	std::unique_ptr<MysqlxConfigStore> config_store {};
	std::vector<std::unique_ptr<Mysqlx_Thread>> threads {};
	std::atomic<bool> started { false };
};

MysqlxPluginContext& mysqlx_context();

#endif /* PROXYSQL_MYSQLX_PLUGIN_H */
