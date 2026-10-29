/**
 * @file pgsql_native_tls_verify_modes_unit-t.cpp
 * @brief Native backend TLS must honor CA verification and per-server protocol bounds.
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
#include <sys/stat.h>
#include <unistd.h>

// A connection pointed at a server row, which is all the context the builder reads.
static PgSQL_Connection* conn_for(PgSQL_Connection::PG_Native_SSL_Mode mode, int port = 5432) {
	char addr[] = "127.0.0.1";
	char comment[] = "";
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->native_mode = true;
	c->parent = new PgSQL_SrvC(addr, port, 1, MYSQL_SERVER_STATUS_ONLINE, 0, 100, 0, 1, 0, comment);
	if (c->userinfo->username == NULL) c->userinfo->username = strdup("tlsuser");
	c->native_ssl_mode = mode;
	return c;
}

struct TestCertificate {
	EVP_PKEY* key = nullptr;
	X509* cert = nullptr;
	std::string ca_path;

	explicit TestCertificate(const char* name) {
		key = EVP_RSA_gen(2048);
		cert = X509_new();
		if (!key || !cert) return;
		X509_set_version(cert, 2);
		ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
		X509_gmtime_adj(X509_getm_notBefore(cert), -60);
		X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
		X509_set_pubkey(cert, key);
		X509_NAME* subject = X509_get_subject_name(cert);
		X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
			(const unsigned char*)name, -1, -1, 0);
		X509_set_issuer_name(cert, subject);
		if (!X509_sign(cert, key, EVP_sha256())) return;
		char path[] = "/tmp/pgsql_native_tls_XXXXXX";
		const int fd = mkstemp(path);
		if (fd == -1) return;
		ca_path = path;
		FILE* f = fdopen(fd, "w");
		if (!f) { close(fd); unlink(ca_path.c_str()); ca_path.clear(); return; }
		const bool wrote = PEM_write_X509(f, cert) == 1;
		fclose(f);
		if (!wrote) { unlink(ca_path.c_str()); ca_path.clear(); }
	}
	~TestCertificate() {
		if (!ca_path.empty()) unlink(ca_path.c_str());
		X509_free(cert);
		EVP_PKEY_free(key);
	}
	TestCertificate(const TestCertificate&) = delete;
	TestCertificate& operator=(const TestCertificate&) = delete;
	bool valid() const { return key && cert && !ca_path.empty(); }
};

static SSL_CTX* server_ctx_for(const TestCertificate& identity, int version = 0) {
	SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) return nullptr;
	if (SSL_CTX_use_certificate(ctx, identity.cert) != 1 ||
	    SSL_CTX_use_PrivateKey(ctx, identity.key) != 1 ||
	    (version && (SSL_CTX_set_min_proto_version(ctx, version) != 1 ||
	                 SSL_CTX_set_max_proto_version(ctx, version) != 1))) {
		SSL_CTX_free(ctx);
		return nullptr;
	}
	return ctx;
}

// Drive both real OpenSSL state machines through memory BIOs. The returned version
// is meaningful only when both peers complete the handshake.
static int handshake_version(SSL_CTX* client_ctx, SSL_CTX* server_ctx) {
	SSL* client = SSL_new(client_ctx);
	SSL* server = SSL_new(server_ctx);
	if (!client || !server) {
		SSL_free(client);
		SSL_free(server);
		return 0;
	}
	BIO* client_in = BIO_new(BIO_s_mem());
	BIO* client_out = BIO_new(BIO_s_mem());
	BIO* server_in = BIO_new(BIO_s_mem());
	BIO* server_out = BIO_new(BIO_s_mem());
	if (!client_in || !client_out || !server_in || !server_out) {
		BIO_free(client_in); BIO_free(client_out);
		BIO_free(server_in); BIO_free(server_out);
		SSL_free(client); SSL_free(server);
		return 0;
	}
	SSL_set_bio(client, client_in, client_out);
	SSL_set_bio(server, server_in, server_out);
	SSL_set_connect_state(client);
	SSL_set_accept_state(server);
	bool client_done = false, server_done = false;
	int negotiated = 0;
	for (int round = 0; round < 100 && !(client_done && server_done); ++round) {
		if (!client_done) {
			int rc = SSL_do_handshake(client);
			if (rc == 1) client_done = true;
			else {
				int err = SSL_get_error(client, rc);
				if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) break;
			}
		}
		char bytes[16384];
		int n;
		while ((n = BIO_read(client_out, bytes, sizeof(bytes))) > 0)
			if (BIO_write(server_in, bytes, n) != n) goto done;
		if (!server_done) {
			int rc = SSL_do_handshake(server);
			if (rc == 1) server_done = true;
			else {
				int err = SSL_get_error(server, rc);
				if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) break;
			}
		}
		while ((n = BIO_read(server_out, bytes, sizeof(bytes))) > 0)
			if (BIO_write(client_in, bytes, n) != n) goto done;
	}
	if (client_done && server_done) negotiated = SSL_version(client);
done:
	SSL_free(client);
	SSL_free(server);
	return negotiated;
}

static void populate_server_params(const std::string& ca) {
	SQLite3_result* rows = new SQLite3_result(10);
	struct Row { int port; const char* range; const char* ca; };
	const Row input[] = {
		{6432, "", ""},
		{6433, "TLSv1.3-", ""},
		{6434, "-TLSv1.2", ""},
		{6435, "TLSv1.2", ""},
		{6436, "", ca.c_str()},
		{6437, "TLSv1.3-TLSv1.2", ""},
		{6438, "TLSv1.4", ""},
		{6439, "tlsv1.3-", ""},
		{6440, "TLSv1.0", ""},
	};
	for (const Row& item : input) {
		std::string port = std::to_string(item.port);
		char* fields[] = {
			(char*)"127.0.0.1", (char*)port.c_str(), (char*)"tlsuser",
			(char*)item.ca, (char*)"", (char*)"", (char*)"", (char*)"",
			(char*)item.range, (char*)"TLS unit test"
		};
		rows->add_row(fields);
	}
	PgHGM->save_incoming_pgsql_table(rows, "pgsql_servers_ssl_params");
	PgHGM->commit({}, {}, false, false);
}

int main(int, char**) {
	plan(28);
	std::string first_path, second_path;
	{
		TestCertificate first("tempfile-probe"), second("tempfile-probe");
		if (!first.valid() || !second.valid()) BAIL_OUT("could not create TLS temporary-file fixtures");
		first_path = first.ca_path;
		second_path = second.ca_path;
		ok(first_path != second_path, "certificate fixtures with the same name have independent files");
		struct stat info {};
		ok(stat(first_path.c_str(), &info) == 0 && (info.st_mode & 0777) == 0600,
		   "certificate fixture files are accessible only by their owner");
	}
	ok(access(first_path.c_str(), F_OK) == -1 && access(second_path.c_str(), F_OK) == -1,
	   "certificate fixture destruction removes both temporary files");
	test_init_minimal();
	test_init_query_processor();
	test_init_hostgroups();   // the builder asks PgHGM for this server's SSL params
	TestCertificate trusted("trusted");
	TestCertificate untrusted("untrusted");
	if (!trusted.valid() || !untrusted.valid()) BAIL_OUT("could not create TLS test certificates");

	// Without a CA, REQUIRE remains an encrypt-only mode.
	{
		PgSQL_Connection* c = conn_for(PgSQL_Connection::PG_Native_SSL_Mode::REQUIRE);
		SSL_CTX* ctx = c->native_create_client_ssl_ctx();
		const int mode = ctx ? SSL_CTX_get_verify_mode(ctx) : -1;
		ok(ctx != NULL && mode == SSL_VERIFY_NONE,
		   "REQUIRE without a CA does not verify (ctx=%s verify_mode=%d)",
		   ctx ? "built" : "null", mode);
		delete c;
	}

	// Explicit verification without a CA must fail closed.
	{
		PgSQL_Connection* c = conn_for(PgSQL_Connection::PG_Native_SSL_Mode::VERIFY_CA);
		SSL_CTX* ctx = c->native_create_client_ssl_ctx();
		ok(ctx == NULL && c->is_error_present(),
		   "VERIFY_CA with no CA fails closed rather than encrypting unverified (ctx=%s error=%s)",
		   ctx ? "BUILT" : "null", c->is_error_present() ? "set" : "MISSING");
		delete c;
	}

	// A configured root CA makes REQUIRE verify the chain, as libpq does.
	{
		char* saved = pgsql_thread___ssl_p2s_ca;
		pgsql_thread___ssl_p2s_ca = strdup(trusted.ca_path.c_str());
		if (!pgsql_thread___ssl_p2s_ca) BAIL_OUT("could not set TLS root CA");

		PgSQL_Connection* require = conn_for(PgSQL_Connection::PG_Native_SSL_Mode::REQUIRE);
		SSL_CTX* require_ctx = require->native_create_client_ssl_ctx();
		const int require_mode = require_ctx ? SSL_CTX_get_verify_mode(require_ctx) : -1;
		ok(require_ctx != NULL && (require_mode & SSL_VERIFY_PEER),
		   "REQUIRE with a root CA enables peer verification (verify_mode=%d)", require_mode);
		SSL_CTX* trusted_server = server_ctx_for(trusted);
		SSL_CTX* untrusted_server = server_ctx_for(untrusted);
		if (!trusted_server || !untrusted_server) BAIL_OUT("could not create TLS server contexts");
		ok(require_ctx && handshake_version(require_ctx, trusted_server) != 0,
		   "REQUIRE with a root CA accepts the trusted server");
		ok(require_ctx && handshake_version(require_ctx, untrusted_server) == 0,
		   "REQUIRE with a root CA rejects the untrusted server");
		SSL_CTX_free(trusted_server);
		SSL_CTX_free(untrusted_server);
		delete require;

		PgSQL_Connection* c = conn_for(PgSQL_Connection::PG_Native_SSL_Mode::VERIFY_FULL);
		SSL_CTX* ctx = c->native_create_client_ssl_ctx();
		const int mode = ctx ? SSL_CTX_get_verify_mode(ctx) : -1;
		ok(ctx != NULL && (mode & SSL_VERIFY_PEER),
		   "VERIFY_FULL builds a context that requires the peer certificate (ctx=%s verify_mode=%d)",
		   ctx ? "built" : "null", mode);
		delete c;

		free(pgsql_thread___ssl_p2s_ca);
		pgsql_thread___ssl_p2s_ca = saved;
	}

	populate_server_params(trusted.ca_path);
	// A server row takes precedence over the global CA setting.
	{
		char* saved = pgsql_thread___ssl_p2s_ca;
		pgsql_thread___ssl_p2s_ca = strdup(untrusted.ca_path.c_str());
		if (!pgsql_thread___ssl_p2s_ca) BAIL_OUT("could not set alternate TLS root CA");
		PgSQL_Connection* c = conn_for(PgSQL_Connection::PG_Native_SSL_Mode::REQUIRE, 6436);
		SSL_CTX* ctx = c->native_create_client_ssl_ctx();
		SSL_CTX* server = server_ctx_for(trusted);
		if (!server) BAIL_OUT("could not create TLS server context");
		ok(ctx && handshake_version(ctx, server) != 0,
		   "per-server root CA wins over the global root CA");
		SSL_CTX_free(server);
		delete c;
		free(pgsql_thread___ssl_p2s_ca);
		pgsql_thread___ssl_p2s_ca = saved;
	}

	// The parsed per-server range must govern both context bounds and real negotiation.
	struct ProtocolCase {
		const char* name;
		int port;
		int min;
		int max;
		bool accepts_12;
		bool accepts_13;
	};
	const ProtocolCase cases[] = {
		{"unset range", 6432, TLS1_2_VERSION, 0, true, true},
		{"TLSv1.3 minimum", 6433, TLS1_3_VERSION, 0, false, true},
		{"TLSv1.2 maximum", 6434, TLS1_2_VERSION, TLS1_2_VERSION, true, false},
		{"TLSv1.2 pin", 6435, TLS1_2_VERSION, TLS1_2_VERSION, true, false},
		{"lowercase TLSv1.3 minimum", 6439, TLS1_3_VERSION, 0, false, true},
	};
	SSL_CTX* server_12 = server_ctx_for(trusted, TLS1_2_VERSION);
	SSL_CTX* server_13 = server_ctx_for(trusted, TLS1_3_VERSION);
	if (!server_12 || !server_13) BAIL_OUT("could not create version-pinned TLS servers");
	for (const ProtocolCase& tc : cases) {
		PgSQL_Connection* c = conn_for(PgSQL_Connection::PG_Native_SSL_Mode::REQUIRE, tc.port);
		SSL_CTX* ctx = c->native_create_client_ssl_ctx();
		ok(ctx && SSL_CTX_get_min_proto_version(ctx) == tc.min &&
		   SSL_CTX_get_max_proto_version(ctx) == tc.max,
		   "%s context bounds: min=%ld max=%ld", tc.name,
		   ctx ? (long)SSL_CTX_get_min_proto_version(ctx) : -1L,
		   ctx ? (long)SSL_CTX_get_max_proto_version(ctx) : -1L);
		const int negotiated_12 = ctx ? handshake_version(ctx, server_12) : 0;
		const int negotiated_13 = ctx ? handshake_version(ctx, server_13) : 0;
		ok((negotiated_12 == TLS1_2_VERSION) == tc.accepts_12,
		   "%s %s a TLSv1.2-only peer (negotiated=%d)", tc.name,
		   tc.accepts_12 ? "accepts" : "rejects", negotiated_12);
		ok((negotiated_13 == TLS1_3_VERSION) == tc.accepts_13,
		   "%s %s a TLSv1.3-only peer (negotiated=%d)", tc.name,
		   tc.accepts_13 ? "accepts" : "rejects", negotiated_13);
		delete c;
	}
	SSL_CTX_free(server_12);
	SSL_CTX_free(server_13);
	const int invalid_ports[] = {6437, 6438, 6440};
	for (int port : invalid_ports) {
		PgSQL_Connection* c = conn_for(PgSQL_Connection::PG_Native_SSL_Mode::REQUIRE, port);
		SSL_CTX* ctx = c->native_create_client_ssl_ctx();
		ok(ctx == nullptr && c->is_error_present(),
		   "invalid protocol range on port %d fails before handshake", port);
		delete c;
	}

	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
