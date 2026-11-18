/** ALPN selection: PgSQL-marked TLS objects negotiate "postgresql"; any other (MySQL) gets NOACK. */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Data_Stream.h"

#include <cstring>
#include <string>
#include <vector>
#include <openssl/ssl.h>

static const unsigned char* out = nullptr;
static unsigned char outlen = 0;

static int cb(SSL* ssl, const std::vector<std::string>& protos) {
	std::string wire;
	for (const std::string& p : protos) { wire += (char)p.size(); wire += p; }
	out = nullptr;
	outlen = 0;
	return pgsql_alpn_select_cb(ssl, &out, &outlen, (const unsigned char*)wire.data(), wire.size(), nullptr);
}

int main() {
	plan(7);
	if (test_init_minimal() != 0) BAIL_OUT("test_init_minimal failed");

	SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) BAIL_OUT("SSL_CTX_new failed");
	SSL* marked = SSL_new(ctx);
	SSL* unmarked = SSL_new(ctx);
	if (!marked || !unmarked) BAIL_OUT("SSL_new failed");
	SSL_set_ex_data(marked, pgsql_client_ssl_ex_index(), marked);
	pgsql_install_alpn(nullptr); // a null context must be ignored

	const std::string pg = "postgresql", foo = "foo";
	ok(cb(unmarked, {pg}) == SSL_TLSEXT_ERR_NOACK, "unmarked TLS object (MySQL) gets NOACK even when postgresql is offered");
	ok(cb(unmarked, {foo}) == SSL_TLSEXT_ERR_NOACK, "unmarked TLS object gets NOACK for a foreign protocol");
	ok(cb(marked, {pg}) == SSL_TLSEXT_ERR_OK, "marked: postgresql selected");
	ok(outlen == 10 && memcmp(out, "postgresql", 10) == 0, "marked: selected protocol is exactly postgresql");
	ok(cb(marked, {foo, pg}) == SSL_TLSEXT_ERR_OK, "marked: postgresql selected from a list");
	ok(outlen == 10 && memcmp(out, "postgresql", 10) == 0, "marked: list case selects exactly postgresql");
	ok(cb(marked, {foo}) == SSL_TLSEXT_ERR_ALERT_FATAL, "marked: foreign-only list refused with a fatal alert");

	SSL_free(marked);
	SSL_free(unmarked);
	SSL_CTX_free(ctx);
	test_cleanup_minimal();
	return exit_status();
}
