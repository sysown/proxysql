/**
 * @file pgsql_native_tls_handover_unit-t.cpp
 * @brief A relay that stopped mid-TLS-record must not hand the connection back for reuse.
 *
 * In fast forward mode the session relays the bytes itself and encrypts them on the way out.
 * Sending is two steps -- encrypt into a buffer, then push that buffer to the socket -- so a
 * socket that cannot take it all leaves encrypted bytes waiting. If the relay ends right then,
 * those bytes sit in a buffer belonging to the data stream, which the connection's own writer
 * knows nothing about, so they are never sent: the backend is left holding half a record, and
 * the next client given that connection fails with a TLS error it did not cause.
 *
 * Only the partial-write half is covered. The other half counts bytes sitting in the write
 * BIO, and a BIO built in this process cannot be read inside libproxysql.so -- each carries
 * its own copy of the vendored OpenSSL. That half needs a real backend.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Connection.h"

#include <openssl/ssl.h>
#include <cstdlib>
#include <cstring>

// A stream holding a native connection whose TLS it has borrowed. Nothing is displaced,
// so backend_tls_adopted stays false and the SSL is only ever tested for NULL here.
static PgSQL_Data_Stream* makeNativeBorrow(PgSQL_Connection* c) {
	c->native_mode = true;
	c->reusable = true;
	c->healthy = true;
	PgSQL_Data_Stream* ds = new PgSQL_Data_Stream();
	ds->attach_connection(c);
	ds->ssl = (SSL*)0x1;
	ds->encrypted = true;
	ds->backend_tls_adopted = false;
	ds->rbio_ssl = NULL;
	ds->wbio_ssl = NULL;
	return ds;
}

// The destructor would SSL_free a borrowed SSL object, and asserts no connection
// is still attached.
static void dropNativeBorrow(PgSQL_Data_Stream* ds) {
	ds->ssl = NULL;
	ds->encrypted = false;
	if (ds->myconn) { ds->myconn->myds = NULL; ds->myconn = NULL; }
	delete ds;
}

int main() {
	plan(3);

	// The relay encrypts into a buffer and then pushes it to the socket. A socket that
	// cannot take it all leaves bytes here that the connection's writer never sends.
	{
		PgSQL_Connection* c = new PgSQL_Connection(false);
		PgSQL_Data_Stream* ds = makeNativeBorrow(c);
		ds->ssl_write_buf = (char*)malloc(13);
		memcpy(ds->ssl_write_buf, "half a record", 13);
		ds->ssl_write_len = 13;

		ds->release_backend_tls();

		ok(c->reusable == false && c->healthy == false,
		   "an unsent partial write gives up the connection%s",
		   c->reusable ? "  <-- it goes back in the pool mid-record" : "");
		ok(ds->ssl_write_len == 0 && ds->ssl_write_buf == NULL,
		   "and the leftover ciphertext is cleared from the stream (%zu bytes left)%s",
		   ds->ssl_write_len,
		   ds->ssl_write_len ? "  <-- it would go out on the next connection's socket" : "");
		dropNativeBorrow(ds);
		delete c;
	}

	// Control: a clean handover must change nothing, or every relayed connection
	// would be thrown away and the pool would churn on each fast forward.
	{
		PgSQL_Connection* c = new PgSQL_Connection(false);
		PgSQL_Data_Stream* ds = makeNativeBorrow(c);
		ds->release_backend_tls();
		ok(c->reusable == true && c->healthy == true,
		   "a clean handover leaves the connection poolable");
		dropNativeBorrow(ds);
		delete c;
	}

	return exit_status();
}
