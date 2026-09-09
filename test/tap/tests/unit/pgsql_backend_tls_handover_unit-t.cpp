/**
 * @file pgsql_backend_tls_handover_unit-t.cpp
 * @brief Drives PgSQL_Data_Stream::adopt_backend_tls() / release_backend_tls().
 *
 * A fast forward relay borrows the backend's TLS and must hand it back. The
 * refusal paths matter most: relaying without the backend's TLS would put
 * plaintext on an encrypted socket, and none of them can be reached through the
 * network, so they are driven here against a real libpq connection.
 *
 * Needs a PostgreSQL with ssl=on. Skips when one is not reachable.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Connection.h"

#include <libpq-fe.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <cstdlib>
#include <string>

static const char* envOr(const char* k, const char* dflt) {
	const char* v = getenv(k);
	return (v && *v) ? v : dflt;
}

// A connected libpq handle. sslmode decides whether the backend leg is encrypted.
static PGconn* connectBackend(const char* sslmode) {
	std::string dsn = std::string("host=") + envOr("PGSQL_HOST", "127.0.0.1")
		+ " port=" + envOr("PGSQL_PORT", "5432")
		+ " user=" + envOr("PGSQL_USER", "postgres")
		+ " password=" + envOr("PGSQL_PASSWORD", "postgres")
		+ " dbname=" + envOr("PGSQL_DB", "postgres")
		+ " sslmode=" + sslmode;
	PGconn* c = PQconnectdb(dsn.c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		PQfinish(c);
		return NULL;
	}
	return c;
}

// A backend data stream holding 'c'. Nothing here is polled or session-bound, so
// adopt/release can be driven directly.
static PgSQL_Data_Stream* makeStream(PgSQL_Connection* c) {
	PgSQL_Data_Stream* ds = new PgSQL_Data_Stream();
	ds->myds_type = MYDS_BACKEND;
	ds->myconn = c;
	c->myds = ds;
	return ds;
}

// The destructor asserts no connection is attached, and would SSL_free a
// borrowed SSL object that libpq frees again at PQfinish().
static void dropStream(PgSQL_Data_Stream* ds) {
	ds->release_backend_tls();
	if (ds->myconn) { ds->myconn->myds = NULL; ds->myconn = NULL; }
	delete ds;
}

int main() {
	plan(20);

	PGconn* plain = connectBackend("disable");
	PGconn* tls = connectBackend("require");

	if (tls == NULL) {
		if (plain) PQfinish(plain);
		skip(20, "no PostgreSQL with ssl=on reachable; set PGSQL_HOST/PGSQL_PORT");
		return exit_status();
	}

	// ---- nothing to borrow is not a failure ---------------------------------
	{
		PgSQL_Connection* c = new PgSQL_Connection(false);
		PgSQL_Data_Stream* ds = makeStream(c);
		ds->myconn = NULL;
		ok(ds->adopt_backend_tls() == true, "adopt with no connection succeeds and borrows nothing");
		ds->myconn = c;
		dropStream(ds);
		c->pgsql_conn = NULL;
		delete c;
	}
	if (plain) {
		PgSQL_Connection* c = new PgSQL_Connection(false);
		c->pgsql_conn = plain;
		PgSQL_Data_Stream* ds = makeStream(c);
		ok(ds->adopt_backend_tls() == true, "adopt on a plaintext backend succeeds");
		ok(ds->ssl == NULL && ds->encrypted == false, "plaintext backend leaves the stream unencrypted");
		dropStream(ds);
		c->pgsql_conn = NULL;
		delete c;
	} else {
		ok(1, "SKIP plaintext backend unavailable");
		ok(1, "SKIP plaintext backend unavailable");
	}

	// ---- the round trip ------------------------------------------------------
	{
		PgSQL_Connection* c = new PgSQL_Connection(false);
		c->pgsql_conn = tls;
		PgSQL_Data_Stream* ds = makeStream(c);

		SSL* libpq_ssl = c->get_pg_ssl_object();
		BIO* orig_rbio = SSL_get_rbio(libpq_ssl);
		BIO* orig_wbio = SSL_get_wbio(libpq_ssl);
		ok(libpq_ssl != NULL && orig_rbio != NULL, "libpq exposes an SSL object with a transport");

		ok(ds->adopt_backend_tls() == true, "adopt on a TLS backend succeeds");
		ok(ds->ssl == libpq_ssl && ds->encrypted == true, "the stream took libpq's SSL object");
		ok(c->saved_backend_rbio == orig_rbio && c->saved_backend_wbio == orig_wbio,
			"libpq's transport is held on the connection");
		ok(SSL_get_rbio(libpq_ssl) == ds->rbio_ssl && SSL_get_wbio(libpq_ssl) == ds->wbio_ssl,
			"the SSL object now reads and writes through the memory pair");
		ok(c->healthy == true, "a clean adopt leaves the connection usable");

		ds->release_backend_tls();
		ok(SSL_get_rbio(libpq_ssl) == orig_rbio && SSL_get_wbio(libpq_ssl) == orig_wbio,
			"release puts libpq's own transport back");
		ok(ds->ssl == NULL && ds->encrypted == false, "release clears the stream's TLS fields");
		ok(c->saved_backend_rbio == NULL && c->saved_backend_wbio == NULL,
			"release drops the connection's saved transport");
		ok(c->healthy == true, "a clean release leaves the connection poolable");

		// the borrow must be repeatable, which is what a second COPY does
		ok(ds->adopt_backend_tls() == true, "a second adopt on the same connection succeeds");
		ds->release_backend_tls();
		ok(SSL_get_rbio(libpq_ssl) == orig_rbio, "and the transport survives a second round trip");

		// ---- refusal: a previous borrower never gave the transport back ------
		BIO* stale = BIO_new(BIO_s_mem());
		c->saved_backend_rbio = stale;
		ok(ds->adopt_backend_tls() == false, "adopt refuses when a transport is already held");
		ok(c->healthy == false && c->reusable == false,
			"a refused adopt marks the connection unusable");
		ok(ds->ssl == NULL && ds->encrypted == false,
			"a refused adopt leaves the stream untouched");
		c->saved_backend_rbio = NULL;
		BIO_free(stale);
		c->healthy = true;
		c->reusable = true;

		// ---- ciphertext left behind must not be pooled -----------------------
		ok(ds->adopt_backend_tls() == true, "adopt again for the stranded-data case");
		BIO_write(ds->wbio_ssl, "unsent", 6);
		ds->release_backend_tls();
		ok(c->healthy == false, "release marks the connection unusable when ciphertext is stranded");

		c->healthy = true;
		dropStream(ds);
		c->pgsql_conn = NULL;
		delete c;
	}

	PQfinish(tls);
	if (plain) PQfinish(plain);
	return exit_status();
}
