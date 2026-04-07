#ifndef PROXYSQL_MYSQLX_ADMIN_SCHEMA_H
#define PROXYSQL_MYSQLX_ADMIN_SCHEMA_H

#include "ProxySQL_Plugin.h"

class MysqlxConfigStore {
public:
	MysqlxConfigStore() = default;
	MysqlxConfigStore(const MysqlxConfigStore&) = delete;
	MysqlxConfigStore& operator=(const MysqlxConfigStore&) = delete;
	~MysqlxConfigStore() = default;
};

#endif /* PROXYSQL_MYSQLX_ADMIN_SCHEMA_H */
