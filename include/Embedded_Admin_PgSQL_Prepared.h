#pragma once
#include "Embedded_PgSQL_Frontend.h"

namespace embedded {
bool handle_admin_pgsql_prepared(PgSQL_Session &, PtrSize_t &, bool &discard_until_sync, bool &registered);
void unregister_admin_pgsql_prepared(PgSQL_Session &) noexcept;
} // namespace embedded
