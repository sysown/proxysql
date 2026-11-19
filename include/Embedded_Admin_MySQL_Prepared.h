#pragma once
#include "Embedded_MySQL_Prepared.h"

namespace embedded {
// Internal Admin/STATS endpoint; no public ABI. SQL is passed unchanged.
// Native SQLite operations use ordinary Admin and STATS access rules.
bool handle_admin_mysql_prepared(MySQL_Session&, PtrSize_t&, bool& registered);
void unregister_admin_mysql_prepared(MySQL_Session&) noexcept;
}
