/**
 * @file pgsql-tls_negotiation-t.cpp
 * @brief Checks that ProxySQL honours one SSLRequest and one GSSENCRequest per connection, as
 *        PostgreSQL does (ProcessStartupPacket() ssl_done / gss_done), and refuses a repeat.
 */

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

constexpr int TIMEOUT_SEC = 5;
constexpr uint32_t PG_SSL_REQUEST_CODE = 80877103;
constexpr uint32_t PG_GSS_ENCRYPT_CODE = 80877104;
constexpr uint32_t PG_PROTOCOL_30 = 0x00030000;
static const std::string ALPN_PG = std::string("\x0a" "postgresql", 11);
static const std::string ALPN_FOO = std::string("\x03" "foo", 4);
static const std::string ALPN_FOO_PG = ALPN_FOO + ALPN_PG;

static std::string frontend_user;

static int create_raw_connection(const std::string& host, int port) {
	struct addrinfo hints {};
	struct addrinfo* result = nullptr;
	int sock = -1;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0) {
		return -1;
	}

	for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock < 0) continue;

		struct timeval timeout { TIMEOUT_SEC, 0 };
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		int flag = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

		if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
		close(sock);
		sock = -1;
	}

	freeaddrinfo(result);
	return sock;
}

static void put_uint32(std::vector<uint8_t>& pkt, uint32_t val) {
	pkt.push_back((val >> 24) & 0xFF);
	pkt.push_back((val >> 16) & 0xFF);
	pkt.push_back((val >> 8) & 0xFF);
	pkt.push_back(val & 0xFF);
}

static bool send_exact(int sock, const void* buf, size_t len, SSL* tls = nullptr) {
	const char* p = (const char*)buf;
	while (len) {
		ssize_t n = tls ? SSL_write(tls, p, len) : send(sock, p, len, MSG_NOSIGNAL);
		if (n <= 0) return false;
		p += n;
		len -= n;
	}
	return true;
}

static bool recv_exact(int sock, void* buf, size_t len, SSL* tls = nullptr) {
	char* p = (char*)buf;
	while (len) {
		ssize_t n = tls ? SSL_read(tls, p, len) : recv(sock, p, len, 0);
		if (n <= 0) return false;
		p += n;
		len -= n;
	}
	return true;
}

/** Reads one message. Returns false when the peer closed instead of answering. */
static bool read_message(int sock, char& type, std::vector<uint8_t>& body, SSL* tls = nullptr) {
	// '?' means nothing came back, so a failed read cannot leave the previous message's type
	// behind and report a reply that never arrived.
	type = '?';
	if (!recv_exact(sock, &type, 1, tls)) return false;

	uint8_t len_buf[4];
	if (!recv_exact(sock, len_buf, 4, tls)) return false;
	int32_t len = ((int32_t)len_buf[0] << 24) | ((int32_t)len_buf[1] << 16) |
				  ((int32_t)len_buf[2] << 8) | (int32_t)len_buf[3];
	if (len < 4) return false;

	body.resize(len - 4);
	return body.empty() || recv_exact(sock, body.data(), body.size(), tls);
}

/** The startup packet bytes for a given version. */
static std::vector<uint8_t> startup_packet(uint32_t version) {
	std::vector<uint8_t> pkt(4);
	put_uint32(pkt, version);
	for (const std::string& p : {std::string("user"), frontend_user, std::string("database"), std::string("postgres")}) {
		pkt.insert(pkt.end(), p.begin(), p.end());
		pkt.push_back(0);
	}
	pkt.push_back(0);
	const uint32_t len = pkt.size();
	pkt[0] = (len >> 24) & 0xFF;
	pkt[1] = (len >> 16) & 0xFF;
	pkt[2] = (len >> 8) & 0xFF;
	pkt[3] = len & 0xFF;
	return pkt;
}

/** The value of one ErrorResponse field, or "" when absent. */
static std::string error_field(const std::vector<uint8_t>& body, char field) {
	for (size_t i = 0; i + 1 < body.size() && body[i] != 0;) {
		const char f = body[i];
		const void* nul = memchr(&body[i + 1], 0, body.size() - (i + 1));
		if (nul == nullptr) break;
		const std::string value((const char*)&body[i + 1]);
		if (f == field) return value;
		i += 1 + value.size() + 1;
	}
	return "";
}

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

static bool send_startup_pkt(int sock, SSL* tls = nullptr) {
	const std::vector<uint8_t> s = startup_packet(PG_PROTOCOL_30);
	return send_exact(sock, s.data(), s.size(), tls);
}

int main(int argc, char** argv) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(17);

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
	if (!set_pgsql_var(admin, "have_ssl", "false")) BAIL_OUT("cannot set pgsql-have_ssl=false");
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
	tls_ok = alpn_case(ALPN_FOO, sel, false);
	ok(!tls_ok, "SSLRequest, ALPN foo: handshake refused");
	ok(admin_run(admin, "PROXYSQL RELOAD TLS"), "PROXYSQL RELOAD TLS succeeds");
	tls_ok = alpn_case(ALPN_PG, sel, false);
	ok(tls_ok && sel == "postgresql", "after RELOAD TLS: postgresql still selected (got '%s')", sel.c_str());

	mysql_close(admin);
	return exit_status();
}
