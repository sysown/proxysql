/**
 * @file pgsql_native_tls_verify_modes_unit-t.cpp
 * @brief The native TLS context must ask for exactly the checking its mode says.
 *
 * use_ssl means encrypt without verifying, the same as sslmode=require to libpq. VERIFY_CA
 * and VERIFY_FULL live in the same function waiting for a config knob, so nothing today
 * builds a verifying context and nothing checks the two things that matter: that the
 * context built is the non-verifying one libpq would have used, and that verification
 * without a CA fails instead of encrypting unchecked. Both are silent when wrong.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Connection.h"
#include "PgSQL_HostGroups_Manager.h"

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

// A connection pointed at a server row, which is all the context the builder reads.
static PgSQL_Connection* conn_for(PgSQL_Connection::PG_Native_SSL_Mode mode) {
	char addr[] = "127.0.0.1";
	char comment[] = "";
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->native_mode = true;
	c->parent = new PgSQL_SrvC(addr, 5432, 1, MYSQL_SERVER_STATUS_ONLINE, 0, 100, 0, 1, 0, comment);
	if (c->userinfo->username == NULL) c->userinfo->username = strdup("tlsuser");
	c->native_ssl_mode = mode;
	return c;
}

// A self-signed certificate on disk for the VERIFY_* path to load. Its contents do not
// matter, only whether the context comes back asking for a peer certificate.
static std::string write_temp_ca() {
	std::string path = "/tmp/pgsql_native_tls_verify_ca_" + std::to_string(getpid()) + ".pem";
	EVP_PKEY* pkey = EVP_RSA_gen(2048);
	if (!pkey) return "";
	X509* x = X509_new();
	if (!x) { EVP_PKEY_free(pkey); return ""; }
	ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
	X509_gmtime_adj(X509_getm_notBefore(x), 0);
	X509_gmtime_adj(X509_getm_notAfter(x), 3600);
	X509_set_pubkey(x, pkey);
	X509_NAME* n = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char*)"unit-test-ca", -1, -1, 0);
	X509_set_issuer_name(x, n);
	std::string out;
	if (X509_sign(x, pkey, EVP_sha256())) {
		FILE* f = fopen(path.c_str(), "w");
		if (f) {
			if (PEM_write_X509(f, x)) out = path;
			fclose(f);
		}
	}
	X509_free(x);
	EVP_PKEY_free(pkey);
	return out;
}

int main(int, char**) {
	plan(3);
	test_init_minimal();
	test_init_hostgroups();   // the builder asks PgHGM for this server's SSL params

	// 1. REQUIRE, the only mode use_ssl can currently produce: encrypt, do not verify.
	{
		PgSQL_Connection* c = conn_for(PgSQL_Connection::PG_Native_SSL_Mode::REQUIRE);
		SSL_CTX* ctx = c->native_create_client_ssl_ctx();
		const int mode = ctx ? SSL_CTX_get_verify_mode(ctx) : -1;
		ok(ctx != NULL && mode == SSL_VERIFY_NONE,
		   "REQUIRE builds an encrypting context that verifies nothing (ctx=%s verify_mode=%d)%s",
		   ctx ? "built" : "null", mode,
		   (ctx && mode == SSL_VERIFY_NONE) ? "" : "  <-- diverges from libpq's sslmode=require");
		delete c;
	}

	// 2. Verification asked for with no CA. Encrypting unchecked looks identical from
	//    the outside, so it has to fail here.
	{
		PgSQL_Connection* c = conn_for(PgSQL_Connection::PG_Native_SSL_Mode::VERIFY_CA);
		SSL_CTX* ctx = c->native_create_client_ssl_ctx();
		ok(ctx == NULL && c->is_error_present(),
		   "VERIFY_CA with no CA fails closed rather than encrypting unverified (ctx=%s error=%s)",
		   ctx ? "BUILT" : "null", c->is_error_present() ? "set" : "MISSING");
		delete c;
	}

	// 3. With a CA available, VERIFY_FULL must actually demand the peer's certificate.
	{
		const std::string ca = write_temp_ca();
		if (ca.empty()) BAIL_OUT("could not write a temporary CA certificate");
		char* saved = pgsql_thread___ssl_p2s_ca;
		pgsql_thread___ssl_p2s_ca = strdup(ca.c_str());

		PgSQL_Connection* c = conn_for(PgSQL_Connection::PG_Native_SSL_Mode::VERIFY_FULL);
		SSL_CTX* ctx = c->native_create_client_ssl_ctx();
		const int mode = ctx ? SSL_CTX_get_verify_mode(ctx) : -1;
		ok(ctx != NULL && (mode & SSL_VERIFY_PEER),
		   "VERIFY_FULL builds a context that requires the peer certificate (ctx=%s verify_mode=%d)",
		   ctx ? "built" : "null", mode);
		delete c;

		free(pgsql_thread___ssl_p2s_ca);
		pgsql_thread___ssl_p2s_ca = saved;
		unlink(ca.c_str());
	}

	test_cleanup_hostgroups();
	test_cleanup_minimal();
	return exit_status();
}
