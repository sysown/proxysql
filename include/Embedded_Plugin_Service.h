#pragma once
#include "ProxySQL_EmbeddedExecution.h"
class MySQL_Session;
class PgSQL_Session;
const ProxySQL_Embedded_ServiceV1* proxysql_embedded_execution_service() noexcept;
namespace embedded {
void teardown_plugin_mysql(MySQL_Session&) noexcept;
void teardown_plugin_pgsql(PgSQL_Session&) noexcept;
}
