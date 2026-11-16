#pragma once
#include "Embedded_MySQL_Prepared.h"

namespace embedded {
// Internal Admin/STATS endpoint; no public ABI. SQL is passed unchanged.
// Initial scope: SELECT in main and DML on mysql_servers, mysql_users and
// mysql_query_rules, subject to the native policy's function and schema rules.
bool handle_admin_mysql_prepared(MySQL_Session&, PtrSize_t&);
void unregister_admin_mysql_prepared(MySQL_Session&) noexcept;
}
