#ifndef PROXYSQL_MYSQLX_PLUGIN_H
#define PROXYSQL_MYSQLX_PLUGIN_H

#include "ProxySQL_Plugin.h"
#include "mysqlx_admin_schema.h"

#include <memory>

class MysqlxConfigStore;

struct MysqlxPluginContext {
	ProxySQL_PluginServices* services { nullptr };
	std::unique_ptr<MysqlxConfigStore> config_store {};
	bool started { false };
};

MysqlxPluginContext& mysqlx_context();

#endif /* PROXYSQL_MYSQLX_PLUGIN_H */
