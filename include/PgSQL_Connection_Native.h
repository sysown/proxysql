#ifndef PROXYSQL_PGSQL_CONNECTION_NATIVE_H
#define PROXYSQL_PGSQL_CONNECTION_NATIVE_H
#include "PgSQL_Connection.h"

// Native (ProxySQL-implemented) wire-protocol backend connection. Has no libpq
// handle (pgsql_conn stays NULL); all transport state lives in the native_*
// members. Selected when pgsql_use_native_backend_protocol = true.
class PgSQL_Connection_Native final : public PgSQL_Connection {
public:
	PgSQL_Connection_Native();
};

#endif // PROXYSQL_PGSQL_CONNECTION_NATIVE_H