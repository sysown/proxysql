/**
 * @file pgsql_native_teardown_state_unit-t.cpp
 * @brief A native connection that was torn down must not resume its connect handshake.
 *
 * native_teardown() frees the TLS session and the two memory buffers the TLS code reads and
 * writes through, but used to leave the connection claiming it was still at the step where it
 * died. The session drives a connection it is still holding when the connect timeout expires,
 * and the handshake step then read the freed write buffer through BIO_should_retry(), which
 * has no null check: signal 11. Doing that for real needs a backend, backend TLS and a connect
 * abandoned inside the few milliseconds the handshake lasts; here the step is set by hand.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Connection.h"

// A native connection parked at a connect step. A fresh one has no socket and no TLS
// objects, which is what a torn-down one is left holding.
static PgSQL_Connection* parked_at(PgSQL_Connection::PG_Native_Conn_St st) {
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->native_mode = true;
	c->native_st = st;
	return c;
}

int main(int, char**) {
	plan(3);

	PgSQL_Connection* c = parked_at(PgSQL_Connection::PG_Native_Conn_St::SSL_HANDSHAKE);
	c->native_teardown();
	ok(c->native_st == PgSQL_Connection::PG_Native_Conn_St::FAILED,
	   "teardown leaves the connect state machine at FAILED, not at the step it died in%s",
	   c->native_st == PgSQL_Connection::PG_Native_Conn_St::FAILED
		   ? "" : "  <-- the next connect_cont() replays that step against freed state");

	// The call the session makes when the connect timeout expires. Before the fix this
	// re-entered the TLS handshake and segfaulted instead of returning.
	c->connect_cont(PG_EVENT_NONE);
	ok(c->is_error_present(),
	   "a torn-down connection answers connect_cont() with an error instead of handshaking again");
	ok(c->async_exit_status == PG_EVENT_NONE,
	   "and asks for no further backend events, so the connection is retired");

	delete c;
	return exit_status();
}
