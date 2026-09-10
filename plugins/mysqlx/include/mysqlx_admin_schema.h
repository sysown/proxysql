#ifndef PROXYSQL_MYSQLX_ADMIN_SCHEMA_H
#define PROXYSQL_MYSQLX_ADMIN_SCHEMA_H

#include "ProxySQL_Plugin.h"

class SQLite3DB;

bool mysqlx_register_admin_schema(ProxySQL_PluginServices& services);
void mysqlx_warn_deprecated_disk_variables(SQLite3DB& db, ProxySQL_PluginServices& services);

#endif /* PROXYSQL_MYSQLX_ADMIN_SCHEMA_H */
