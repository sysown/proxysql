/**
 * @file pgsql_start_client_tls_unit-t.cpp
 * @brief PgSQL_Data_Stream::start_client_tls() must fail closed when OpenSSL cannot
 * create the TLS objects, instead of dereferencing a NULL SSL pointer.
 *
 * The unit stub of GloVars.get_SSL_new() returns nullptr while no TLS context is set,
 * which stands in for an allocation failure.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Data_Stream.h"

#include <openssl/ssl.h>

int main() {
	plan(7);
	test_init_minimal();

	PgSQL_Data_Stream* ds = new PgSQL_Data_Stream();
	ok(!ds->start_client_tls(), "no TLS context: start_client_tls() fails instead of crashing");
	ok(ds->ssl == nullptr && ds->rbio_ssl == nullptr && ds->wbio_ssl == nullptr,
	   "failure leaves no SSL object or BIOs behind");
	ok(!ds->encrypted, "failure does not mark the stream encrypted");
	// The SSLRequest path marks the stream encrypted before calling start_client_tls().
	ds->encrypted = true;
	ok(!ds->start_client_tls() && !ds->encrypted,
	   "failure after an SSLRequest clears encrypted, so writeout() cannot use the null ssl");

	GloVars.global.ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (GloVars.global.ssl_ctx == nullptr) BAIL_OUT("SSL_CTX_new failed");
	PgSQL_Data_Stream* ds2 = new PgSQL_Data_Stream();
	ok(ds2->start_client_tls(), "with a TLS context: start_client_tls() succeeds");
	ok(ds2->ssl != nullptr && SSL_get_ex_data(ds2->ssl, pgsql_client_ssl_ex_index()) == ds2,
	   "TLS object created and marked as a PgSQL client");
	ok(ds2->encrypted && ds2->DSS == STATE_SSL_INIT, "stream is encrypted and in STATE_SSL_INIT");

	delete ds;
	delete ds2;
	SSL_CTX_free(GloVars.global.ssl_ctx);
	GloVars.global.ssl_ctx = nullptr;
	test_cleanup_minimal();
	return exit_status();
}
