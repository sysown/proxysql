#ifndef PROXYSQL_PGSQL_CLIENT_CONNECTION_H
#define PROXYSQL_PGSQL_CLIENT_CONNECTION_H
#include "PgSQL_Connection.h"

// Connection representing the client side of an accepted session. Distinct from
// the two backend leaves so the transport (and later, the wire protocol
// parser) choice for backend connections cannot accidentally apply to it.
class PgSQL_Client_Connection final : public PgSQL_Connection {
public:
	PgSQL_Client_Connection();
};

#endif // PROXYSQL_PGSQL_CLIENT_CONNECTION_H