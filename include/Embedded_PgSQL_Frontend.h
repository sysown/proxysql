#pragma once
#include "Embedded_PgSQL_Prepared.h"

class PgSQL_Session;
typedef struct _PtrSize_t PtrSize_t;
namespace embedded {
// Adapter and policy are borrowed and must outlive unregister.
Status register_pgsql_prepared(PgSQL_Session &, Adapter &, EndpointPolicy &,
                               PgSQLPreparedLimits = {}, GuardFactory = {});
void unregister_pgsql_prepared(PgSQL_Session &) noexcept;
Status reset_pgsql_prepared(PgSQL_Session &);
// A registered session must be handled and unregistered on its owner thread.
// Calls from other threads leave the packet and session unchanged and return false.
bool handle_pgsql_prepared(PgSQL_Session &, PtrSize_t &);
} // namespace embedded
