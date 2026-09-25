/**
 * @file pgsql_client_connection_unit-t.cpp
 * @brief A client connection must be exactly what `new PgSQL_Connection(true)`
 *   used to be -- nothing more.
 *
 * Step 2 of the connection split introduced PgSQL_Client_Connection as the
 * client-side leaf: constructors only, base transport chosen at construction
 * ((true, false) -> is_client_connection, libpq-class transport). These tests
 * pin the leaf to the old single-class behaviour so that a later step moving
 * transport state into the backend leaves cannot silently change what the
 * client side of a session looks like.
 *
 * As the accessors become virtual (Step 3), this file grows: each accessor
 * must answer for the client leaf exactly as the libpq arm of the old
 * if (native_mode) switch did. Today the accessors are still inline
 * single-arm functions on the base, so the assertions below are the ones that
 * can observe the leaf's identity and its transport class without a backend.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Client_Connection.h"
#include "PgSQL_Connection_Native.h"
#include "PgSQL_Connection_LibPQ.h"

int main() {
	plan(5);

	if (test_init_minimal() != 0)
		BAIL_OUT("test_init_minimal() failed");

	PgSQL_Client_Connection* client = new PgSQL_Client_Connection();
	PgSQL_Connection* conn = client; // what the session actually holds

	ok(dynamic_cast<PgSQL_Client_Connection*>(conn) != nullptr,
	   "client connections are constructed as PgSQL_Client_Connection");

	ok(dynamic_cast<PgSQL_Connection_Native*>(conn) == nullptr &&
	   dynamic_cast<PgSQL_Connection_LibPQ*>(conn) == nullptr,
	   "a client connection is never one of the backend leaves");

	ok(conn->get_pg_connection() == nullptr,
	   "a fresh client connection has no libpq handle (same as before the split)");

	// get_pg_protocol_version() is the sharpest transport-class probe at this
	// stage: the libpq arm returns PQprotocolVersion(NULL) == 0, while the
	// native arm returns 3. A client connection must take the libpq arm,
	// exactly as `new PgSQL_Connection(true)` did with native_mode == false.
	ok(conn->get_pg_protocol_version() == 0,
	   "client connection reports protocol version 0 through the libpq arm");

	// set_is_client() is exercised by the real attach path
	// (Base_Thread.cpp shrinks its myds first), so it is not called on this bare
	// connection: a fresh leaf has no stream attached yet.
	delete client;
	ok(true, "client leaf constructs and destroys cleanly");
}