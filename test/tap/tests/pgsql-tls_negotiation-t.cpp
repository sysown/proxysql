/**
 * @file pgsql-tls_negotiation-t.cpp
 * @brief Checks that ProxySQL honours one SSLRequest and one GSSENCRequest per connection, as
 *        PostgreSQL does (ProcessStartupPacket() ssl_done / gss_done), and refuses a repeat.
 *        Also checks ALPN and direct TLS (a ClientHello as the first bytes, ProcessSSLStartup()).
 */

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "pgsql_raw_client.h"

CommandLine cl;

constexpr uint32_t PG_SSL_REQUEST_CODE = 80877103;
constexpr uint32_t PG_GSS_ENCRYPT_CODE = 80877104;
constexpr uint32_t PG_PROTOCOL_30 = 0x00030000;
static const std::string ALPN_PG = std::string("\x0a" "postgresql", 11);
static const std::string ALPN_FOO = std::string("\x03" "foo", 4);
static const std::string ALPN_FOO_PG = ALPN_FOO + ALPN_PG;

static std::string frontend_user;

/** The 8-byte negotiation packet (SSLRequest or GSSENCRequest). */
static bool send_request(int sock, uint32_t code, SSL* tls = nullptr) {
	std::vector<uint8_t> pkt;
	put_uint32(pkt, 8);
	put_uint32(pkt, code);
	return send_exact(sock, pkt.data(), pkt.size(), tls);
}

static bool read_reply_byte(int sock, char& reply, SSL* tls = nullptr) {
	reply = '?';
	return recv_exact(sock, &reply, 1, tls);
}

/** SSL_connect on a socket already switched to TLS (or a fresh one for direct TLS). */
static SSL* tls_handshake(int sock, const std::string& alpn_wire, SSL_CTX** out_ctx, int max_version = 0, int* fail_reason = nullptr) {
	SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == nullptr) return nullptr;
	if (max_version > 0) SSL_CTX_set_max_proto_version(ctx, max_version);
	if (!alpn_wire.empty()) SSL_CTX_set_alpn_protos(ctx, (const unsigned char*)alpn_wire.data(), alpn_wire.size());
	SSL* tls = SSL_new(ctx);
	if (tls == nullptr) { SSL_CTX_free(ctx); return nullptr; }
	SSL_set_fd(tls, sock);
	ERR_clear_error();
	if (SSL_connect(tls) != 1) {
		if (fail_reason) *fail_reason = ERR_GET_REASON(ERR_peek_last_error());
		SSL_free(tls);
		SSL_CTX_free(ctx);
		return nullptr;
	}
	*out_ctx = ctx;
	return tls;
}

static std::string alpn_selected(SSL* tls) {
	const unsigned char* data = nullptr;
	unsigned int len = 0;
	SSL_get0_alpn_selected(tls, &data, &len);
	return data ? std::string((const char*)data, len) : "";
}

struct DirectTls { int sock = -1; SSL_CTX* ctx = nullptr; SSL* tls = nullptr; int reason = 0; };

/** A fresh socket whose first bytes are a ClientHello. sock is kept open even when the handshake fails. */
static DirectTls direct_tls_connect(const std::string& host, int port, const std::string& alpn_wire, int max_version = 0) {
	DirectTls d;
	d.sock = create_raw_connection(host, port);
	if (d.sock >= 0) d.tls = tls_handshake(d.sock, alpn_wire, &d.ctx, max_version, &d.reason);
	return d;
}

/** True if the peer closed the TLS connection; a receive timeout (WANT_READ) is not a close. */
static bool tls_closed_by_peer(SSL* tls) {
	char c;
	const int n = SSL_read(tls, &c, 1);
	return n <= 0 && SSL_get_error(tls, n) != SSL_ERROR_WANT_READ;
}

/** Memory-BIO client I/O: send everything tls has queued in wbio. */
static bool flush_wbio(int sock, BIO* wbio) {
	char buf[4096];
	int n;
	while ((n = BIO_read(wbio, buf, sizeof(buf))) > 0)
		if (!send_exact(sock, buf, n)) return false;
	return true;
}

/** Memory-BIO client I/O: feed one socket read into rbio. False on EOF or receive timeout. */
static bool feed_rbio(int sock, BIO* rbio) {
	char buf[4096];
	const ssize_t n = recv(sock, buf, sizeof(buf), 0);
	return n > 0 && BIO_write(rbio, buf, n) == n;
}

static MYSQL* admin_connect() {
	MYSQL* conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, cl.admin_host, cl.admin_username, cl.admin_password,
							NULL, cl.admin_port, NULL, 0)) {
		diag("admin connect failed: %s", mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}
	return conn;
}

static bool admin_run(MYSQL* admin, const std::string& sql) {
	if (mysql_query(admin, sql.c_str())) {
		diag("admin query '%s' failed: %s", sql.c_str(), mysql_error(admin));
		return false;
	}
	return true;
}

static bool set_pgsql_var(MYSQL* admin, const std::string& name, const std::string& value) {
	return admin_run(admin, "SET pgsql-" + name + "=" + value) &&
		   admin_run(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

static void close_all(int sock, SSL* tls, SSL_CTX* ctx) {
	if (tls) { SSL_shutdown(tls); SSL_free(tls); }
	if (ctx) SSL_CTX_free(ctx);
	if (sock >= 0) close(sock);
}

static bool send_startup_pkt(int sock, SSL* tls = nullptr, const std::string& user = frontend_user) {
	const std::vector<uint8_t> s = startup_packet(PG_PROTOCOL_30, user);
	return send_exact(sock, s.data(), s.size(), tls);
}

static uint32_t auth_type(const std::vector<uint8_t>& body) {
	if (body.size() < 4) return UINT32_MAX;
	return ((uint32_t)body[0] << 24) | ((uint32_t)body[1] << 16) | ((uint32_t)body[2] << 8) | body[3];
}

/** Startup, expect R type 3, send the password, read to Z. True when R type 0 was seen and no E. */
static bool login_cleartext(int sock, SSL* tls, const std::string& user, const std::string& password) {
	char type = '?';
	std::vector<uint8_t> body;
	if (!send_startup_pkt(sock, tls, user) || !read_message(sock, type, body, tls) || type != 'R' || auth_type(body) != 3) {
		diag("login_cleartext: expected R type 3, got '%c' type %u", type, auth_type(body));
		return false;
	}
	std::vector<uint8_t> pkt{ 'p' };
	put_uint32(pkt, 4 + password.size() + 1);
	pkt.insert(pkt.end(), password.begin(), password.end());
	pkt.push_back(0);
	if (!send_exact(sock, pkt.data(), pkt.size(), tls)) return false;
	bool auth_ok = false, error = false;
	while (read_message(sock, type, body, tls) && type != 'Z') {
		if (type == 'R' && auth_type(body) == 0) auth_ok = true;
		if (type == 'E') { error = true; diag("login_cleartext: error '%s'", error_field(body, 'M').c_str()); }
	}
	return type == 'Z' && auth_ok && !error;
}

/** Q, read to Z. True when a D arrived and no E. */
static bool simple_query_ok(int sock, SSL* tls, const std::string& sql) {
	std::vector<uint8_t> pkt{ 'Q' };
	put_uint32(pkt, 4 + sql.size() + 1);
	pkt.insert(pkt.end(), sql.begin(), sql.end());
	pkt.push_back(0);
	if (!send_exact(sock, pkt.data(), pkt.size(), tls)) return false;
	char type = '?';
	std::vector<uint8_t> body;
	bool row = false, error = false;
	while (read_message(sock, type, body, tls) && type != 'Z') {
		if (type == 'D') row = true;
		if (type == 'E') { error = true; diag("simple_query_ok: error '%s'", error_field(body, 'M').c_str()); }
	}
	return type == 'Z' && row && !error;
}

int main(int argc, char** argv) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(32);

	frontend_user = cl.pgsql_username;
	const std::string host = cl.pgsql_host;
	const int port = cl.pgsql_port;

	char type = 0;
	std::vector<uint8_t> body;

	MYSQL* admin = admin_connect();
	if (!admin) BAIL_OUT("cannot connect to admin");

	// A: SSLRequest, 'S', TLS, SSLRequest inside TLS
	{
		SSL_CTX* ctx = nullptr;
		SSL* tls = nullptr;
		int sock = create_raw_connection(host, port);
		char reply = '?';
		if (sock >= 0 && send_request(sock, PG_SSL_REQUEST_CODE) && read_reply_byte(sock, reply) && reply == 'S')
			tls = tls_handshake(sock, "", &ctx);
		type = '?';
		if (tls && send_request(sock, PG_SSL_REQUEST_CODE, tls)) read_message(sock, type, body, tls);
		ok(type == 'E' && error_field(body, 'C') == "0A000",
		   "second SSLRequest inside TLS: refused with 0A000 (got '%c', '%s')", type, error_field(body, 'C').c_str());
		ok(error_field(body, 'M').find("unsupported frontend protocol 1234.5679") == 0,
		   "second SSLRequest: message names 1234.5679 (got '%s')", error_field(body, 'M').c_str());
		close_all(sock, tls, ctx);
	}

	// B: SSLRequest, 'S', TLS, GSSENCRequest inside TLS
	{
		SSL_CTX* ctx = nullptr;
		SSL* tls = nullptr;
		int sock = create_raw_connection(host, port);
		char reply = '?';
		if (sock >= 0 && send_request(sock, PG_SSL_REQUEST_CODE) && read_reply_byte(sock, reply) && reply == 'S')
			tls = tls_handshake(sock, "", &ctx);
		type = '?';
		body.clear();
		if (tls && send_request(sock, PG_GSS_ENCRYPT_CODE, tls)) read_message(sock, type, body, tls);
		ok(type == 'E' && error_field(body, 'C') == "0A000" && error_field(body, 'M').find("1234.5680") != std::string::npos,
		   "GSSENCRequest after TLS: refused (got '%c', '%s')", type, error_field(body, 'M').c_str());
		close_all(sock, tls, ctx);
	}

	// C: GSSENCRequest -> 'N', then SSLRequest on the same socket
	{
		SSL_CTX* ctx = nullptr;
		SSL* tls = nullptr;
		int sock = create_raw_connection(host, port);
		char reply1 = '?', reply2 = '?';
		if (sock >= 0 && send_request(sock, PG_GSS_ENCRYPT_CODE) && read_reply_byte(sock, reply1) &&
			send_request(sock, PG_SSL_REQUEST_CODE) && read_reply_byte(sock, reply2) && reply2 == 'S')
			tls = tls_handshake(sock, "", &ctx);
		ok(reply1 == 'N' && reply2 == 'S', "GSSENCRequest then SSLRequest: 'N' then 'S' (got '%c','%c')", reply1, reply2);
		type = '?';
		if (tls && send_startup_pkt(sock, tls)) read_message(sock, type, body, tls);
		ok(tls != nullptr && type == 'R', "GSSENCRequest then SSLRequest: TLS and startup work (got '%c')", type);
		close_all(sock, tls, ctx);
	}

	// D: GSSENCRequest -> 'N', GSSENCRequest again (plaintext)
	{
		int sock = create_raw_connection(host, port);
		char reply = '?';
		type = '?';
		if (sock >= 0 && send_request(sock, PG_GSS_ENCRYPT_CODE) && read_reply_byte(sock, reply) &&
			send_request(sock, PG_GSS_ENCRYPT_CODE))
			read_message(sock, type, body);
		ok(type == 'E' && error_field(body, 'C') == "0A000", "second GSSENCRequest: refused (got '%c')", type);
		close_all(sock, nullptr, nullptr);
	}

	// E/F need have_ssl=false; it is restored below before exit.
	if (!set_pgsql_var(admin, "have_ssl", "false")) {
		// The SET may have succeeded and the LOAD failed: do not leave false staged for the next LOAD.
		admin_run(admin, "SET pgsql-have_ssl=true");
		BAIL_OUT("cannot set pgsql-have_ssl=false");
	}
	{
		int sock = create_raw_connection(host, port);
		char reply = '?';
		type = '?';
		if (sock >= 0 && send_request(sock, PG_SSL_REQUEST_CODE) && read_reply_byte(sock, reply) &&
			reply == 'N' && send_request(sock, PG_SSL_REQUEST_CODE))
			read_message(sock, type, body);
		ok(reply == 'N', "have_ssl=false: SSLRequest answered 'N' (got '%c')", reply);
		ok(type == 'E' && error_field(body, 'C') == "0A000", "have_ssl=false: second SSLRequest refused (got '%c')", type);
		close_all(sock, nullptr, nullptr);
	}
	{
		int sock = create_raw_connection(host, port);
		char reply1 = '?', reply2 = '?';
		type = '?';
		if (sock >= 0 && send_request(sock, PG_SSL_REQUEST_CODE) && read_reply_byte(sock, reply1) &&
			send_request(sock, PG_GSS_ENCRYPT_CODE) && read_reply_byte(sock, reply2) &&
			send_startup_pkt(sock))
			read_message(sock, type, body);
		ok(reply1 == 'N' && reply2 == 'N' && type == 'R', "have_ssl=false: SSL 'N', GSS 'N', startup 'R' (got '%c','%c','%c')", reply1, reply2, type);
		close_all(sock, nullptr, nullptr);
	}
	const bool restored = set_pgsql_var(admin, "have_ssl", "true");
	ok(restored, "pgsql-have_ssl restored to true");
	if (!restored) BAIL_OUT("cannot restore pgsql-have_ssl");

	// G: sanity
	{
		int sock = create_raw_connection(host, port);
		type = '?';
		if (sock >= 0 && send_startup_pkt(sock)) read_message(sock, type, body);
		ok(type == 'R', "ProxySQL still accepts a plaintext startup (got '%c')", type);
		close_all(sock, nullptr, nullptr);
	}

	// H: ALPN after SSLRequest. Returns the TLS object (or null) and reads the first reply when startup is sent.
	auto alpn_case = [&](const std::string& alpn, std::string& selected, bool startup) {
		SSL_CTX* ctx = nullptr;
		SSL* tls = nullptr;
		int sock = create_raw_connection(host, port);
		char reply = '?';
		type = '?';
		selected = "";
		if (sock >= 0 && send_request(sock, PG_SSL_REQUEST_CODE) && read_reply_byte(sock, reply) && reply == 'S')
			tls = tls_handshake(sock, alpn, &ctx);
		if (tls) selected = alpn_selected(tls);
		if (tls && startup && send_startup_pkt(sock, tls)) read_message(sock, type, body, tls);
		const bool connected = tls != nullptr;
		close_all(sock, tls, ctx);
		return connected;
	};
	std::string sel;
	bool tls_ok = alpn_case("", sel, true);
	ok(tls_ok && sel == "" && type == 'R', "SSLRequest, no ALPN: accepted, nothing selected (got '%s','%c')", sel.c_str(), type);
	tls_ok = alpn_case(ALPN_PG, sel, true);
	ok(tls_ok && sel == "postgresql" && type == 'R', "SSLRequest, ALPN postgresql: selected (got '%s','%c')", sel.c_str(), type);
	tls_ok = alpn_case(ALPN_FOO_PG, sel, false);
	ok(tls_ok && sel == "postgresql", "SSLRequest, ALPN foo,postgresql: postgresql selected (got '%s')", sel.c_str());
	{
		// The server must send alert 120 (no_application_protocol) before closing.
		SSL_CTX* ctx = nullptr;
		SSL* tls = nullptr;
		int reason = 0;
		char reply = '?';
		int sock = create_raw_connection(host, port);
		const bool got_s = sock >= 0 && send_request(sock, PG_SSL_REQUEST_CODE) && read_reply_byte(sock, reply) && reply == 'S';
		if (got_s) tls = tls_handshake(sock, ALPN_FOO, &ctx, 0, &reason);
		ok(got_s && tls == nullptr && reason == SSL_R_TLSV1_ALERT_NO_APPLICATION_PROTOCOL,
			"SSLRequest, ALPN foo: refused with alert 120 (got_s %d, reason %d)", (int)got_s, reason);
		close_all(sock, tls, ctx);
	}
	ok(admin_run(admin, "PROXYSQL RELOAD TLS"), "PROXYSQL RELOAD TLS succeeds");
	tls_ok = alpn_case(ALPN_PG, sel, false);
	ok(tls_ok && sel == "postgresql", "after RELOAD TLS: postgresql still selected (got '%s')", sel.c_str());

	// I: direct TLS (PostgreSQL 17+ sslnegotiation=direct): the ClientHello is the first thing sent.
	auto still_serving = [&]() {
		int sock = create_raw_connection(host, port);
		char t = '?';
		std::vector<uint8_t> b;
		if (sock >= 0 && send_startup_pkt(sock)) read_message(sock, t, b);
		close_all(sock, nullptr, nullptr);
		return t == 'R';
	};
	{
		DirectTls d = direct_tls_connect(host, port, ALPN_PG);
		sel = d.tls ? alpn_selected(d.tls) : "";
		type = '?';
		if (d.tls && send_startup_pkt(d.sock, d.tls)) read_message(d.sock, type, body, d.tls);
		ok(d.tls && sel == "postgresql" && type == 'R', "direct TLS, ALPN postgresql: startup answered (got '%s','%c')", sel.c_str(), type);
		close_all(d.sock, d.tls, d.ctx);
	}
	{
		DirectTls d = direct_tls_connect(host, port, ALPN_FOO_PG);
		sel = d.tls ? alpn_selected(d.tls) : "";
		ok(d.tls && sel == "postgresql", "direct TLS, ALPN foo,postgresql: postgresql selected (got '%s')", sel.c_str());
		close_all(d.sock, d.tls, d.ctx);
	}
	{
		// As PostgreSQL: the handshake completes, then the connection is closed without a reply.
		DirectTls d = direct_tls_connect(host, port, "");
		type = '?';
		if (d.tls && send_startup_pkt(d.sock, d.tls)) read_message(d.sock, type, body, d.tls);
		ok(d.tls != nullptr && type != 'R' && tls_closed_by_peer(d.tls), "direct TLS, no ALPN: handshake completes, then closed with no authentication request");
		close_all(d.sock, d.tls, d.ctx);
	}
	{
		// TLS 1.2: the client finishes only after the server's flight, so the server-side flush before closing is what lets it complete.
		DirectTls d = direct_tls_connect(host, port, "", TLS1_2_VERSION);
		type = '?';
		if (d.tls && send_startup_pkt(d.sock, d.tls)) read_message(d.sock, type, body, d.tls);
		ok(d.tls != nullptr && type != 'R' && tls_closed_by_peer(d.tls), "direct TLS 1.2, no ALPN: handshake completes, then closed with no authentication request");
		close_all(d.sock, d.tls, d.ctx);
	}
	{
		DirectTls d = direct_tls_connect(host, port, ALPN_FOO);
		ok(d.tls == nullptr && d.reason == SSL_R_TLSV1_ALERT_NO_APPLICATION_PROTOCOL, "direct TLS, ALPN foo: alert 120 (reason %d)", d.reason);
		close_all(d.sock, d.tls, d.ctx);
	}
	{
		DirectTls d = direct_tls_connect(host, port, ALPN_PG);
		char reply = '?';
		type = '?';
		if (d.tls && send_request(d.sock, PG_SSL_REQUEST_CODE, d.tls) && read_reply_byte(d.sock, reply, d.tls) &&
			reply == 'N' && send_startup_pkt(d.sock, d.tls))
			read_message(d.sock, type, body, d.tls);
		ok(reply == 'N' && type == 'R', "direct TLS, then SSLRequest: 'N', then startup works (got '%c','%c')", reply, type);
		close_all(d.sock, d.tls, d.ctx);
	}
	bool auth_restored = false;
	{
		// Cleartext, so the password check runs inside the direct TLS session. Restored right after.
		bool logged_in = false, queried = false;
		if (set_pgsql_var(admin, "authentication_method", "1")) {
			DirectTls d = direct_tls_connect(host, port, ALPN_PG);
			logged_in = d.tls && login_cleartext(d.sock, d.tls, cl.pgsql_username, cl.pgsql_password);
			queried = logged_in && simple_query_ok(d.sock, d.tls, "SELECT 1");
			close_all(d.sock, d.tls, d.ctx);
		}
		auth_restored = set_pgsql_var(admin, "authentication_method", "3");
		ok(logged_in && queried, "direct TLS: cleartext login and SELECT 1 succeed");
	}
	{
		// TLS 1.2 carries ALPN in the ServerHello, not in EncryptedExtensions.
		DirectTls d = direct_tls_connect(host, port, ALPN_PG, TLS1_2_VERSION);
		sel = d.tls ? alpn_selected(d.tls) : "";
		type = '?';
		if (d.tls && send_startup_pkt(d.sock, d.tls)) read_message(d.sock, type, body, d.tls);
		ok(d.tls && sel == "postgresql" && type == 'R', "direct TLS 1.2: ALPN selected, startup answered (got '%s','%c')", sel.c_str(), type);
		close_all(d.sock, d.tls, d.ctx);
	}
	{
		DirectTls d = direct_tls_connect(host, port, ALPN_PG);
		std::vector<uint8_t> cancel;
		for (uint32_t v : {16u, 80877102u, 0u, 0u}) put_uint32(cancel, v);
		const bool closed = d.tls && send_exact(d.sock, cancel.data(), cancel.size(), d.tls) && tls_closed_by_peer(d.tls);
		close_all(d.sock, d.tls, d.ctx);
		ok(d.tls != nullptr && closed && still_serving(), "cancel over direct TLS: connection closed, ProxySQL keeps serving");
	}
	{
		DirectTls d = direct_tls_connect(cl.pgsql_admin_host, cl.pgsql_admin_port, ALPN_PG);
		sel = d.tls ? alpn_selected(d.tls) : "";
		type = '?';
		if (d.tls && send_startup_pkt(d.sock, d.tls, cl.admin_username)) read_message(d.sock, type, body, d.tls);
		ok(d.tls && sel == "postgresql" && type == 'R', "direct TLS on the PgSQL admin port (%d) (got '%c')", cl.pgsql_admin_port, type);
		close_all(d.sock, d.tls, d.ctx);
	}
	bool ssl_restored = false;
	{
		bool refused = false;
		if (set_pgsql_var(admin, "have_ssl", "false")) {
			DirectTls d = direct_tls_connect(host, port, ALPN_PG);
			refused = d.tls == nullptr;
			close_all(d.sock, d.tls, d.ctx);
		}
		ssl_restored = set_pgsql_var(admin, "have_ssl", "true");
		ok(refused, "pgsql-have_ssl=false: direct TLS refused");
	}
	{
		int sock = create_raw_connection(host, port);
		if (sock >= 0) close(sock);
		usleep(100000); // let ProxySQL see the EOF before the next connection
		ok(still_serving(), "connect and close without a byte: ProxySQL keeps serving");
	}
	{
		// The peek must neither consume nor misread a lone 0x00 (the first length byte).
		int sock = create_raw_connection(host, port);
		const std::vector<uint8_t> s = startup_packet(PG_PROTOCOL_30, frontend_user);
		type = '?';
		if (sock >= 0 && send_exact(sock, s.data(), 1)) {
			usleep(100000);
			if (send_exact(sock, s.data() + 1, s.size() - 1)) read_message(sock, type, body);
		}
		ok(type == 'R', "split plaintext startup (first segment 1 byte, 100 ms pause): answered (got '%c')", type);
		close_all(sock, nullptr, nullptr);
	}
	{
		// The first TCP segment holds only 2 bytes of the ClientHello: the first read sees a partial
		// record header. Memory BIOs let the test choose where the ClientHello is cut.
		int sock = create_raw_connection(host, port);
		SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
		SSL* tls = ctx ? SSL_new(ctx) : nullptr;
		bool done = false;
		std::string alpn;
		type = '?';
		if (tls) SSL_set_bio(tls, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem())); // tls owns both
		BIO* rbio = tls ? SSL_get_rbio(tls) : nullptr;
		BIO* wbio = tls ? SSL_get_wbio(tls) : nullptr;
		if (sock >= 0 && rbio && wbio) {
			SSL_set_alpn_protos(tls, (const unsigned char*)ALPN_PG.data(), ALPN_PG.size());
			SSL_set_connect_state(tls);
			SSL_do_handshake(tls); // queues the ClientHello in wbio
			std::string hello(BIO_ctrl_pending(wbio), '\0');
			const bool hello_ok = hello.size() > 2 && BIO_read(wbio, &hello[0], hello.size()) == (int)hello.size();
			if (hello_ok && send_exact(sock, hello.data(), 2)) {
				usleep(100000);
				if (send_exact(sock, hello.data() + 2, hello.size() - 2)) {
					for (const time_t deadline = time(nullptr) + 5; time(nullptr) < deadline;) {
						const int rc = SSL_do_handshake(tls);
						if (rc == 1) { done = true; break; }
						if (SSL_get_error(tls, rc) != SSL_ERROR_WANT_READ || !flush_wbio(sock, wbio) || !feed_rbio(sock, rbio)) break;
					}
				}
			}
			alpn = alpn_selected(tls);
			const std::vector<uint8_t> s = startup_packet(PG_PROTOCOL_30, frontend_user);
			if (done && SSL_write(tls, s.data(), s.size()) == (int)s.size() && flush_wbio(sock, wbio)) {
				int rc;
				while ((rc = SSL_read(tls, &type, 1)) <= 0 && SSL_get_error(tls, rc) == SSL_ERROR_WANT_READ && feed_rbio(sock, rbio)) {}
			}
		}
		ok(done && alpn == "postgresql" && type == 'R', "direct TLS, ClientHello split (first segment 2 bytes): handshake and startup (got '%s','%c')", alpn.c_str(), type);
		close_all(sock, tls, ctx);
	}
	ok(ssl_restored && auth_restored, "pgsql-have_ssl and pgsql-authentication_method restored");

	mysql_close(admin);
	return exit_status();
}
