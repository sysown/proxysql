#pragma once
#include "Embedded_MySQL_Prepared.h"

namespace embedded {
// Internal Admin/STATS endpoint; no public ABI. SQL is passed unchanged.
// Read-only SELECT in main, subject to the native policy's function and schema rules.
bool handle_admin_mysql_prepared(MySQL_Session&, PtrSize_t&, bool& registered);
void unregister_admin_mysql_prepared(MySQL_Session&) noexcept;
}
