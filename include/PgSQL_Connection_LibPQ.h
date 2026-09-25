#ifndef PROXYSQL_PGSQL_CONNECTION_LIBPQ_H
#define PROXYSQL_PGSQL_CONNECTION_LIBPQ_H
#include "PgSQL_Connection.h"

// libpq-backed backend connection. Speaks the wire protocol through libpq's
// PGconn handle (pgsql_conn). This is the default transport
// (pgsql_use_native_backend_protocol = false).
class PgSQL_Connection_LibPQ final : public PgSQL_Connection {
public:
	PgSQL_Connection_LibPQ();
};

#endif // PROXYSQL_PGSQL_CONNECTION_LIBPQ_H