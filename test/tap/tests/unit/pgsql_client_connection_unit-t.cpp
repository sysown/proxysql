/**
 * @file pgsql_client_connection_unit-t.cpp
 * @brief A client connection must be exactly what `new PgSQL_Connection(true)`
 *   used to be -- nothing more.
 *
 * Step 3 of the connection split gave every leaf its own transport-dependent
 * bodies. For the client leaf that means one thing above all: each answer must
 * be the one the old single-class `if (native_mode)` switch already produced for
 * a client connection, which is the answer the libpq arm gave with a NULL
 * PGconn*, or the initial value of a field the libpq transport never writes.
 *
 * So every accessor is checked two ways against a real PgSQL_Connection_LibPQ
 * that has never connected (pgsql_conn == NULL, exactly the state a client
 * connection is in):
 *
 *   1. parity -- client answer == never-connected libpq answer. This is the
 *      behaviour-preservation check, and it fails loudly if an accessor is
 *      moved to the wrong leaf or given a value that was not the old one.
 *   2. pinned value -- the literal the plan records, so the two leaves cannot
 *      drift together into agreeing on something new.
 *
 * The pinned values are the ones libpq produces for a NULL handle; if a future
 * libpq changes one of them, check 1 fails here rather than silently moving the
 * client's reported value.
 */

#include <string.h>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Client_Connection.h"
#include "PgSQL_Connection_Native.h"
#include "PgSQL_Connection_LibPQ.h"

// backend_is_live() is protected: the liveness answers are checked through the
// two public entry points that consult it, is_connected() and
// get_pg_transaction_status(), both of which are on the base and shared.

#define PARITY_INT(EXPR, LIT, NAME) do {                                       \
	const long long c_ = (long long)(client->EXPR);                            \
	const long long l_ = (long long)(pq->EXPR);                                \
	ok(c_ == l_, "client matches never-connected libpq: " NAME);                 \
	ok(c_ == (long long)(LIT), "client pins " NAME);                           \
} while (0)

#define PARITY_STR(EXPR, PIN, NAME) do {                                        \
	const char* c_ = (client->EXPR);                                           \
	const char* l_ = (pq->EXPR);                                               \
	/* through a variable: PIN is a literal nullptr often enough that */        \
	/* strcmp() at the call site would trip -Wnonnull. */                       \
	const char* pin_ = (PIN);                                                  \
	ok(c_ == l_ || (c_ != nullptr && l_ != nullptr && strcmp(c_, l_) == 0),     \
	   "client matches never-connected libpq: " NAME);                         \
	ok(c_ == pin_ ||                                                           \
	   (c_ != nullptr && pin_ != nullptr && strcmp(c_, pin_) == 0),            \
	   "client pins " NAME " to " #PIN);                                       \
} while (0)

int main() {
	plan(66);

	if (test_init_minimal() != 0)
		BAIL_OUT("test_init_minimal() failed");

	PgSQL_Client_Connection* client = new PgSQL_Client_Connection();
	PgSQL_Connection* conn = client; // what the session actually holds
	// The comparison leaf: a backend connection whose libpq connect never ran.
	PgSQL_Connection_LibPQ* pq = new PgSQL_Connection_LibPQ();

	ok(dynamic_cast<PgSQL_Client_Connection*>(conn) != nullptr,
	   "client connections are constructed as PgSQL_Client_Connection");

	ok(dynamic_cast<PgSQL_Connection_Native*>(conn) == nullptr &&
	   dynamic_cast<PgSQL_Connection_LibPQ*>(conn) == nullptr,
	   "a client connection is never one of the backend leaves");

	ok(conn->get_pg_connection() == nullptr,
	   "a fresh client connection has no libpq handle (same as before the split)");

	// --- the accessors the session, poll loop and monitor ask for ---

	PARITY_INT(get_pg_server_version(), 0, "get_pg_server_version()");
	PARITY_INT(get_pg_protocol_version(), 0, "get_pg_protocol_version()");
	PARITY_STR(get_pg_host(), nullptr, "get_pg_host()");
	PARITY_STR(get_pg_hostaddr(), nullptr, "get_pg_hostaddr()");
	PARITY_STR(get_pg_port(), nullptr, "get_pg_port()");
	PARITY_STR(get_pg_dbname(), nullptr, "get_pg_dbname()");
	PARITY_STR(get_pg_user(), nullptr, "get_pg_user()");
	PARITY_STR(get_pg_password(), nullptr, "get_pg_password()");
	PARITY_STR(get_pg_options(), nullptr, "get_pg_options()");
	PARITY_INT(get_pg_socket_fd(), -1, "get_pg_socket_fd()");
	PARITY_INT(get_pg_backend_pid(), 0, "get_pg_backend_pid()");
	PARITY_INT(get_pg_client_encoding(), -1, "get_pg_client_encoding()");
	PARITY_INT(get_pg_ssl_in_use(), 0, "get_pg_ssl_in_use()");
	PARITY_STR(get_pg_parameter_status("client_encoding"), nullptr, "get_pg_parameter_status()");
	PARITY_INT(get_pg_connection_status(), CONNECTION_BAD, "get_pg_connection_status()");
	PARITY_INT(last_ready_for_query_status(), 'I', "last_ready_for_query_status()");
	PARITY_INT(needs_pollout(), 0, "needs_pollout()");
	PARITY_INT(get_pg_is_nonblocking(), 0, "get_pg_is_nonblocking()");
	PARITY_INT(transport_transaction_status(), PQTRANS_UNKNOWN, "transport_transaction_status()");
	PARITY_INT(get_backend_pid(), -1, "get_backend_pid()");
	PARITY_INT(is_pipeline_active(), 0, "is_pipeline_active()");
	// The one accessor with a non-null answer: the state string a connection
	// that never reached CONNECTION_OK reports, which the monitor displays.
	PARITY_STR(get_pg_backend_state(), "disconnected", "get_pg_backend_state()");
	PARITY_INT(transport_blocks_reuse(), 0, "transport_blocks_reuse()");
	PARITY_INT(last_execute_suspended(), 0, "last_execute_suspended()");
	PARITY_INT(result_had_notification(), 0, "result_had_notification()");
	PARITY_INT(relay_async_messages(nullptr), 0, "relay_async_messages()");
	PARITY_INT(IsKnownActiveTransaction(), 0, "IsKnownActiveTransaction()");

	// The liveness answer, through the two public readers of it.
	PARITY_INT(is_connected(), 0, "is_connected() (backend_is_live)");
	PARITY_INT(get_pg_transaction_status(), PQTRANS_UNKNOWN, "get_pg_transaction_status()");

	// The diagnostics string. Not "" -- libpq answers a NULL handle with a
	// string of its own, and the callers append whatever comes back to an
	// error message, so returning an empty one would drop the reason.
	{
		const char* cmsg = client->get_pg_error_message();
		const char* lmsg = pq->get_pg_error_message();
		ok(cmsg != nullptr && lmsg != nullptr && strcmp(cmsg, lmsg) == 0,
		   "client matches never-connected libpq: get_pg_error_message()");
		ok(cmsg != nullptr && cmsg[0] != '\0',
		   "client pins get_pg_error_message() to libpq's own non-empty string");
	}

	// No SSL* to hand out, and no pipeline to be in the middle of.
	ok(client->get_pg_ssl_object() == nullptr && pq->get_pg_ssl_object() == nullptr,
	   "client pins get_pg_ssl_object() to nullptr");

	// Reachable, and a no-op on a client connection both before and after the
	// split: the body guarded on `if (pgsql_conn)`, always false here.
	client->compute_unknown_transaction_status();
	ok(true, "compute_unknown_transaction_status() stays a no-op on a client connection");

	// set_is_client() is exercised by the real attach path
	// (Base_Thread.cpp shrinks its myds first), so it is not called on this bare
	// connection: a fresh leaf has no stream attached yet.
	delete pq;
	delete client;
	ok(true, "client leaf and its comparison leaf construct and destroy cleanly");
}
